"""End-to-end check that one identity fronts several upstreams, each at its path.

The proxy runs through :func:`authsome_mcp_proxy.mcp_proxy.run_async` exactly as
in production, with only the edges replaced: uvicorn hands the built app to the
test instead of binding a port, the upstream URLs resolve to in-process FastMCP
servers, and -- in the first half -- the inbound provider is FastMCP's
``InMemoryOAuthProvider``, a real authorization server that needs no IdP, so a
token can be obtained over HTTP the way a client would.

The second half swaps in a real ``OIDCProxy``, the provider family whose
resource binding made sharing one authorization server across endpoints need a
correction (see :mod:`authsome_mcp_proxy.path_router`).
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from base64 import urlsafe_b64encode
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import fastmcp
import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.http import create_streamable_http_app
from mcp.server.auth.settings import ClientRegistrationOptions

from authsome_mcp_proxy import mcp_proxy
from authsome_mcp_proxy.config import UpstreamRoute, WebConfig
from authsome_mcp_proxy.inbound_auth import build_inbound_auth

BASE = "https://mcp.example.com"
ALIAS = "https://mcp.example.io"
ISSUER = "https://idp.example.com"
REDIRECT_URI = "http://localhost:3000/callback"

SECURE_URL = "http://secure.internal/mcp"
EMB3D_URL = "http://emb3d.internal/mcp"
DOWN_URL = "http://down.internal/mcp"

# ---------------------------------------------------------------------------
# In-process upstreams
# ---------------------------------------------------------------------------

# Headers each upstream reports back, so a test can see exactly what arrived.
REPORTED_HEADERS = ("authorization", "mcp-protocol-version", "x-request-id")


def _upstream_app(name: str):
    upstream = FastMCP(name=f"{name}-upstream")

    @upstream.tool()
    def whoami() -> str:
        return name

    @upstream.tool()
    def request_headers() -> dict[str, str]:
        headers = get_http_headers(include_all=True)
        return {h: headers[h] for h in REPORTED_HEADERS if h in headers}

    return create_streamable_http_app(server=upstream, streamable_http_path="/mcp")


class _Unreachable(httpx2.AsyncBaseTransport):
    """An upstream that is down: every connection attempt is refused."""

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("connection refused", request=request)


def _transport(
    target: httpx2.AsyncBaseTransport,
    url: str,
    *,
    auth=None,
    headers: dict[str, str] | None = None,
) -> StreamableHttpTransport:
    """A streamable-HTTP transport that reaches ``url`` through ``target``."""

    def client_factory(headers=None, timeout=None, auth=None, **kwargs):
        if timeout is not None:
            kwargs["timeout"] = timeout
        return httpx2.AsyncClient(
            transport=target, headers=headers, auth=auth, **kwargs
        )

    return StreamableHttpTransport(
        url, headers=headers, auth=auth, httpx_client_factory=client_factory
    )


def _upstream_client_factory(upstreams: Mapping[str, httpx2.AsyncBaseTransport]):
    """Stand in for ``mcp_proxy.Client``: upstream URLs resolve in-process."""
    real_client = fastmcp.Client

    def client(transport, **kwargs):
        if isinstance(transport, str) and transport in upstreams:
            transport = _transport(upstreams[transport], transport)
        return real_client(transport=transport, **kwargs)

    return client


# ---------------------------------------------------------------------------
# Running the proxy
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app):
    """Drive the ASGI lifespan protocol, as uvicorn would."""
    inbox: asyncio.Queue = asyncio.Queue()
    started, finished = asyncio.Event(), asyncio.Event()

    async def send(message):
        if message["type"] == "lifespan.startup.complete":
            started.set()
        elif message["type"] == "lifespan.shutdown.complete":
            finished.set()
        elif message["type"].endswith(".failed"):
            raise AssertionError(f"lifespan failed: {message}")

    task = asyncio.create_task(app({"type": "lifespan"}, inbox.get, send))
    await inbox.put({"type": "lifespan.startup"})
    await asyncio.wait_for(started.wait(), timeout=10)
    try:
        yield
    finally:
        await inbox.put({"type": "lifespan.shutdown"})
        await asyncio.wait_for(finished.wait(), timeout=10)
        await task


@asynccontextmanager
async def serving(config: WebConfig, build_auth):
    """Run the proxy through ``run_async``; yield its ASGI app while it serves.

    uvicorn is replaced by a server whose ``serve()`` hands the app to the test
    and returns once the test is done, so everything around it -- route
    servers, providers, apps, lifespans -- is the production path.
    """
    upstreams = {
        SECURE_URL: httpx2.ASGITransport(app=_upstream_app("secure")),
        EMB3D_URL: httpx2.ASGITransport(app=_upstream_app("emb3d")),
        DOWN_URL: _Unreachable(),
    }
    upstream_apps = [
        t.app for t in upstreams.values() if isinstance(t, httpx2.ASGITransport)
    ]
    served: asyncio.Queue = asyncio.Queue()
    done = asyncio.Event()

    with (
        patch(
            "authsome_mcp_proxy.mcp_proxy.build_inbound_auth", side_effect=build_auth
        ),
        patch(
            "authsome_mcp_proxy.mcp_proxy.Client",
            side_effect=_upstream_client_factory(upstreams),
        ),
        patch("authsome_mcp_proxy.mcp_proxy.uvicorn") as uvicorn_mod,
    ):

        async def serve():
            app = uvicorn_mod.Config.call_args.args[0]
            async with _lifespan(app):
                await served.put(app)
                await done.wait()

        uvicorn_mod.Server.return_value.serve = serve
        async with _lifespan(upstream_apps[0]), _lifespan(upstream_apps[1]):
            proxy = asyncio.create_task(
                mcp_proxy.run_async(None, config, show_banner=False)
            )
            getter = asyncio.create_task(served.get())
            await asyncio.wait({proxy, getter}, return_when=asyncio.FIRST_COMPLETED)
            if not getter.done():
                getter.cancel()
                await proxy  # raises whatever stopped the proxy from serving
            try:
                yield getter.result()
            finally:
                done.set()
                await asyncio.wait_for(proxy, timeout=10)


def _web_config(**overrides) -> WebConfig:
    kwargs: dict[str, Any] = {
        "inbound_auth_provider": "keycloak",  # replaced by build_auth
        "proxy_base_url": BASE,
        "issuer_url": "https://kc.example.com/realms/r",
        "upstreams": [
            UpstreamRoute(name="secure", mcp_url=SECURE_URL),
            UpstreamRoute(name="emb3d", mcp_url=EMB3D_URL, outbound_auth="none"),
            UpstreamRoute(name="down", mcp_url=DOWN_URL),
        ],
        "default_upstream": "secure",
    }
    kwargs.update(overrides)
    return WebConfig(**kwargs)


def _in_memory_auth(config, base_url):
    return InMemoryOAuthProvider(
        base_url=base_url,
        client_registration_options=ClientRegistrationOptions(enabled=True),
    )


def _http(app, base: str = BASE) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=base)


def _mcp_client(
    app, path: str, token: str | None, base: str = BASE, **headers: str
) -> fastmcp.Client:
    url = f"{base}{path}"
    transport = _transport(
        httpx2.ASGITransport(app=app), url, auth=token, headers=headers or None
    )
    return fastmcp.Client(transport)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, urlsafe_b64encode(digest).decode().rstrip("=")


async def _register(http: httpx2.AsyncClient) -> str:
    response = await http.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "test client",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


async def _authorize(
    http: httpx2.AsyncClient, client_id: str, resource: str, challenge: str
):
    return await http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "resource": resource,
        },
    )


async def _obtain_token(app, resource: str, base: str = BASE) -> str:
    """Run DCR, authorization code + PKCE and the token exchange over HTTP."""
    async with _http(app, base) as http:
        client_id = await _register(http)
        verifier, challenge = _pkce()
        response = await _authorize(http, client_id, resource, challenge)
        assert response.status_code == 302, response.text
        code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
        response = await http.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]


# ---------------------------------------------------------------------------
# One identity, several upstreams
# ---------------------------------------------------------------------------


async def test_one_token_opens_every_route():
    """The point of sharing the authorization server: a token obtained while
    connecting to one route is accepted by every other route of the identity,
    and each route reaches its own upstream."""
    async with serving(_web_config(), _in_memory_auth) as app:
        token = await _obtain_token(app, f"{BASE}/secure/mcp")

        reached = {}
        for path in ("/secure/mcp", "/emb3d/mcp", "/mcp"):
            async with _mcp_client(app, path, token) as client:
                reached[path] = (await client.call_tool("whoami", {})).data

    assert reached == {"/secure/mcp": "secure", "/emb3d/mcp": "emb3d", "/mcp": "secure"}


async def test_each_route_advertises_its_own_resource():
    """RFC 9728 path-scoped metadata at the origin root, one document per
    route, all pointing at the one shared authorization server."""
    async with serving(_web_config(), _in_memory_auth) as app, _http(app) as http:
        documents = {
            path: (
                await http.get(f"/.well-known/oauth-protected-resource{path}")
            ).json()
            for path in ("/secure/mcp", "/emb3d/mcp", "/mcp")
        }
        # Not under the route prefix: that is not where clients look.
        misplaced = await http.get("/secure/.well-known/oauth-protected-resource/mcp")

    for path, document in documents.items():
        assert document["resource"] == f"{BASE}{path}"
        assert document["authorization_servers"] == [f"{BASE}/"]
    assert misplaced.status_code == 404


async def test_authorization_server_is_served_once_at_the_root():
    async with serving(_web_config(), _in_memory_auth) as app, _http(app) as http:
        metadata = (await http.get("/.well-known/oauth-authorization-server")).json()
        under_route = await http.get("/secure/.well-known/oauth-authorization-server")
        authorize_under_route = await http.get("/emb3d/authorize")

    assert metadata["issuer"].rstrip("/") == BASE
    assert metadata["authorization_endpoint"] == f"{BASE}/authorize"
    assert metadata["token_endpoint"] == f"{BASE}/token"
    assert metadata["registration_endpoint"] == f"{BASE}/register"
    assert under_route.status_code == 404
    assert authorize_under_route.status_code == 404


async def test_unauthenticated_requests_are_challenged_with_their_routes_metadata():
    """The 401 bootstraps discovery, so it must point at the metadata of the
    route the client contacted -- otherwise the client checks the wrong
    resource and gives up."""
    async with serving(_web_config(), _in_memory_auth) as app, _http(app) as http:
        challenges = {}
        for path in ("/secure/mcp", "/emb3d/mcp", "/mcp"):
            response = await http.post(
                path,
                headers={"Accept": "application/json, text/event-stream"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            assert response.status_code == 401, path
            challenges[path] = response.headers["www-authenticate"]

    for path, challenge in challenges.items():
        assert f'{BASE}/.well-known/oauth-protected-resource{path}"' in challenge


async def test_outbound_auth_is_chosen_per_route():
    """``forward`` hands the user's token to its upstream; ``none`` must not let
    it through at all, even though FastMCP forwards inbound headers by default.
    Everything else arrives as sent, and each upstream connection carries the
    protocol version it negotiated."""
    async with serving(_web_config(), _in_memory_auth) as app:
        token = await _obtain_token(app, f"{BASE}/secure/mcp")
        seen = {}
        for path in ("/secure/mcp", "/emb3d/mcp"):
            async with _mcp_client(
                app, path, token, **{"X-Request-Id": "req-42"}
            ) as client:
                seen[path] = (await client.call_tool("request_headers", {})).data

    assert seen["/secure/mcp"]["authorization"] == f"Bearer {token}"
    assert "authorization" not in seen["/emb3d/mcp"]
    for headers in seen.values():
        assert headers["x-request-id"] == "req-42"
        assert headers["mcp-protocol-version"]


async def test_a_session_from_one_route_does_not_resolve_on_another():
    async with serving(_web_config(), _in_memory_auth) as app:
        token = await _obtain_token(app, f"{BASE}/secure/mcp")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        }
        async with _http(app) as http:
            opened = await http.post(
                "/secure/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"},
                    },
                },
            )
            session_id = opened.headers["mcp-session-id"]
            crossed = await http.post(
                "/emb3d/mcp",
                headers={**headers, "Mcp-Session-Id": session_id},
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )

    assert opened.status_code == 200, opened.text
    assert crossed.status_code == 404


async def test_an_unreachable_upstream_fails_only_its_own_requests():
    """The proxy started although ``down`` was unreachable from the outset;
    a request there fails, and the other routes keep working."""
    async with serving(_web_config(), _in_memory_auth) as app:
        token = await _obtain_token(app, f"{BASE}/secure/mcp")

        async with _mcp_client(app, "/down/mcp", token) as client:
            with pytest.raises(Exception):  # noqa: B017 -- any failure will do
                await client.call_tool("whoami", {})

        async with _mcp_client(app, "/emb3d/mcp", token) as client:
            assert (await client.call_tool("whoami", {})).data == "emb3d"


async def test_without_a_default_upstream_mcp_is_not_served():
    async with (
        serving(_web_config(default_upstream=None), _in_memory_auth) as app,
        _http(app) as http,
    ):
        metadata = await http.get("/.well-known/oauth-protected-resource/mcp")
        endpoint = await http.post("/mcp", json={})
        # The authorization server is still there, served by the first route.
        as_metadata = await http.get("/.well-known/oauth-authorization-server")

    assert metadata.status_code == 404
    assert endpoint.status_code == 404
    assert as_metadata.status_code == 200


async def test_routes_compose_with_several_hostnames():
    """Both dimensions at once: every hostname is its own identity, and each
    one serves every route under its own name."""
    config = _web_config(additional_proxy_base_urls=[ALIAS])
    async with serving(config, _in_memory_auth) as app:
        async with _http(app, ALIAS) as http:
            document = (
                await http.get("/.well-known/oauth-protected-resource/emb3d/mcp")
            ).json()
        token = await _obtain_token(app, f"{ALIAS}/secure/mcp", ALIAS)
        async with _mcp_client(app, "/emb3d/mcp", token, ALIAS) as client:
            reached = (await client.call_tool("whoami", {})).data
        # The hostnames stay separate identities: the alias's token means
        # nothing to the primary hostname's authorization server.
        async with _http(app) as http:
            foreign = await http.post(
                "/emb3d/mcp",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json, text/event-stream",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )

    assert document["resource"] == f"{ALIAS}/emb3d/mcp"
    assert document["authorization_servers"] == [f"{ALIAS}/"]
    assert reached == "emb3d"
    assert foreign.status_code == 401


# ---------------------------------------------------------------------------
# A real OIDCProxy as the shared authorization server
# ---------------------------------------------------------------------------


def _oidc_configuration() -> OIDCConfiguration:
    """A discovery document, so constructing OIDCProxy reaches no network."""
    return OIDCConfiguration(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/jwks",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
    )


@pytest.fixture
def oidc(tmp_path, monkeypatch):
    """An ``oidc`` deployment's config, plus the providers it builds.

    OAuthProxy persists clients and transactions under FastMCP's home; point
    that at a temporary directory rather than the developer's own.
    """
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path)
    providers: list[OIDCProxy] = []

    def build_auth(config, base_url):
        with patch.object(
            OIDCProxy, "get_oidc_configuration", return_value=_oidc_configuration()
        ):
            provider = build_inbound_auth(config, base_url=base_url)
        assert isinstance(provider, OIDCProxy)
        providers.append(provider)
        return provider

    config = _web_config(
        inbound_auth_provider="oidc",
        issuer_url=ISSUER,
        client_id="cid",
        client_secret="csec",
        scopes="openid",
    )
    return config, build_auth, providers


@pytest.mark.parametrize("path", ["/secure/mcp", "/emb3d/mcp", "/mcp"])
async def test_oidc_proxy_authorizes_for_every_route(oidc, path):
    """FastMCP's OAuthProxy accepts exactly one RFC 8707 ``resource`` -- the
    endpoint it was last bound to. Shared across routes, it has to accept each
    of them, or a client connecting to any but the last is turned away."""
    config, build_auth, _ = oidc
    async with serving(config, build_auth) as app, _http(app) as http:
        client_id = await _register(http)
        response = await _authorize(http, client_id, f"{BASE}{path}", _pkce()[1])

    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert "error" not in parse_qs(urlsplit(location).query), location


async def test_oidc_proxy_still_refuses_a_foreign_resource(oidc):
    """Widening the check must not drop it: a token for another server is
    exactly what RFC 8707 exists to refuse."""
    config, build_auth, _ = oidc
    async with serving(config, build_auth) as app, _http(app) as http:
        client_id = await _register(http)
        response = await _authorize(
            http, client_id, "https://elsewhere.example.com/mcp", _pkce()[1]
        )

    assert response.status_code == 302, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["error"] == ["invalid_target"]


async def test_oidc_proxy_binds_tokens_to_the_shared_identity(oidc):
    """One audience for all routes, so a token minted while connecting to one
    route validates on every other; the base URL is what they have in common."""
    config, build_auth, providers = oidc
    async with serving(config, build_auth):
        (provider,) = providers
        audience = provider.jwt_issuer.audience

    assert audience == f"{BASE}/"


async def test_oidc_proxy_tokens_stay_with_their_hostname(oidc):
    """Each hostname is its own identity, even though both providers derive
    the same signing key from the one IdP client secret: a token minted by
    one is refused by the other's issuer, on issuer and audience."""
    from joserfc.errors import JoseError

    _, build_auth, providers = oidc
    config = _web_config(
        inbound_auth_provider="oidc",
        issuer_url=ISSUER,
        client_id="cid",
        client_secret="csec",
        scopes="openid",
        additional_proxy_base_urls=[ALIAS],
    )
    async with serving(config, build_auth):
        primary, alias = providers
        token = primary.jwt_issuer.issue_access_token(
            client_id="client", scopes=[], jti="jti-1"
        )

        assert primary.jwt_issuer.verify_token(token)["aud"] == f"{BASE}/"
        with pytest.raises(JoseError):
            alias.jwt_issuer.verify_token(token)


async def test_oidc_proxy_serves_one_authorization_server_and_per_route_metadata(oidc):
    config, build_auth, _ = oidc
    async with serving(config, build_auth) as app, _http(app) as http:
        metadata = (await http.get("/.well-known/oauth-authorization-server")).json()
        documents = {
            path: (
                await http.get(f"/.well-known/oauth-protected-resource{path}")
            ).json()
            for path in ("/secure/mcp", "/emb3d/mcp", "/mcp")
        }

    assert metadata["issuer"].rstrip("/") == BASE
    assert metadata["authorization_endpoint"] == f"{BASE}/authorize"
    for path, document in documents.items():
        assert document["resource"] == f"{BASE}{path}"
        assert document["authorization_servers"] == [f"{BASE}/"]
