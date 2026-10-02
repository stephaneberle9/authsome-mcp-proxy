"""Tests for authsome_mcp_proxy.outbound_auth — outbound auth mode factory.

These tests exercise the httpx2.Auth classes directly without spinning up a
FastMCP server, by:

- Mocking ``get_access_token`` for forward mode
- Using ``respx`` is overkill here; instead we patch ``httpx2.AsyncClient.post``
  for the client_credentials refresh path
- For static mode, just inspecting the resulting request headers
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx2
import pytest

from authsome_mcp_proxy.config import WebConfig
from authsome_mcp_proxy.outbound_auth import (
    ForwardSessionTokenAuth,
    NoCredentialAuth,
    OAuthClientCredentialsAuth,
    StaticHeaderAuth,
    build_outbound_auth,
)


def _base_keycloak_kwargs() -> dict:
    return {
        "inbound_auth_provider": "keycloak",
        "proxy_base_url": "https://mcp.example.com",
        "issuer_url": "https://kc.example.com/realms/r",
    }


class TestBuildOutboundAuthDispatch:
    """The factory should pick the right httpx2.Auth shape for each mode."""

    def test_forward_returns_forward_auth(self):
        config = WebConfig(**_base_keycloak_kwargs())
        auth = build_outbound_auth(config)
        assert isinstance(auth, ForwardSessionTokenAuth)

    def test_static_returns_static_auth_with_default_header_name(self):
        config = WebConfig(
            **_base_keycloak_kwargs(),
            outbound_auth="static",
            outbound_header_value="Bearer abc123",
        )
        auth = build_outbound_auth(config)
        assert isinstance(auth, StaticHeaderAuth)
        assert auth.header_name == "Authorization"
        assert auth.header_value == "Bearer abc123"

    def test_static_returns_static_auth_with_custom_header_name(self):
        config = WebConfig(
            **_base_keycloak_kwargs(),
            outbound_auth="static",
            outbound_header_name="X-API-Key",
            outbound_header_value="abc123",
        )
        auth = build_outbound_auth(config)
        assert isinstance(auth, StaticHeaderAuth)
        assert auth.header_name == "X-API-Key"
        assert auth.header_value == "abc123"

    def test_oauth_cc_returns_cc_auth(self):
        config = WebConfig(
            **_base_keycloak_kwargs(),
            outbound_auth="oauth-client-credentials",
            outbound_client_id="ocid",
            outbound_client_secret="osec",
            outbound_token_url="https://idp.example.com/token",
        )
        auth = build_outbound_auth(config)
        assert isinstance(auth, OAuthClientCredentialsAuth)
        assert auth.token_url == "https://idp.example.com/token"
        assert auth.client_id == "ocid"
        assert auth.client_secret == "osec"

    def test_none_returns_no_credential_auth(self):
        config = WebConfig(**_base_keycloak_kwargs(), outbound_auth="none")
        assert isinstance(build_outbound_auth(config), NoCredentialAuth)

    def test_unknown_outbound_auth_raises(self):
        config = WebConfig(**_base_keycloak_kwargs())
        config.outbound_auth = "made-up-mode"  # type: ignore[assignment]  # ty: ignore[invalid-assignment]
        with pytest.raises(ValueError, match="Unknown outbound_auth"):
            build_outbound_auth(config)


class TestForwardSessionTokenAuth:
    """Forward mode reads from FastMCP's per-session access token accessor."""

    @pytest.mark.asyncio
    async def test_injects_bearer_token_when_session_token_present(self):
        mock_token = MagicMock(token="session-token-xyz")
        with patch(
            "authsome_mcp_proxy.outbound_auth.get_access_token",
            return_value=mock_token,
        ):
            auth = ForwardSessionTokenAuth()
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            yielded = await flow.__anext__()

        assert yielded.headers["Authorization"] == "Bearer session-token-xyz"

    @pytest.mark.asyncio
    async def test_raises_when_no_session_token(self):
        with patch(
            "authsome_mcp_proxy.outbound_auth.get_access_token", return_value=None
        ):
            auth = ForwardSessionTokenAuth()
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            with pytest.raises(RuntimeError, match="No inbound session access token"):
                await flow.__anext__()

    @pytest.mark.asyncio
    async def test_raises_when_session_token_has_empty_value(self):
        mock_token = MagicMock(token="")
        with patch(
            "authsome_mcp_proxy.outbound_auth.get_access_token",
            return_value=mock_token,
        ):
            auth = ForwardSessionTokenAuth()
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            with pytest.raises(RuntimeError):
                await flow.__anext__()


class TestStaticHeaderAuth:
    """Static mode unconditionally injects the configured header value."""

    def test_injects_authorization_bearer_header(self):
        auth = StaticHeaderAuth(
            header_name="Authorization", header_value="Bearer abc123"
        )
        request = httpx2.Request("GET", "https://upstream.example.com/")
        # auth_flow is a sync generator; iterate once
        flow = auth.auth_flow(request)
        yielded = next(flow)
        assert yielded.headers["Authorization"] == "Bearer abc123"

    def test_injects_custom_header_name(self):
        auth = StaticHeaderAuth(header_name="X-API-Key", header_value="abc123")
        request = httpx2.Request("GET", "https://upstream.example.com/")
        flow = auth.auth_flow(request)
        yielded = next(flow)
        assert yielded.headers["X-API-Key"] == "abc123"
        assert "Authorization" not in yielded.headers

    def test_overwrites_existing_header(self):
        auth = StaticHeaderAuth(
            header_name="Authorization", header_value="Bearer fresh"
        )
        request = httpx2.Request(
            "GET",
            "https://upstream.example.com/",
            headers={"Authorization": "Bearer stale"},
        )
        flow = auth.auth_flow(request)
        yielded = next(flow)
        assert yielded.headers["Authorization"] == "Bearer fresh"


class TestOAuthClientCredentialsAuth:
    """oauth-client-credentials obtains, caches, and refreshes a service-account
    token via the OAuth client_credentials grant."""

    @pytest.mark.asyncio
    async def test_initial_request_fetches_and_injects_token(self):
        auth = OAuthClientCredentialsAuth(
            token_url="https://idp.example.com/token",
            client_id="cid",
            client_secret="csec",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "access_token": "fresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.post.return_value = mock_response

        with patch(
            "authsome_mcp_proxy.outbound_auth.httpx2.AsyncClient",
            return_value=mock_client,
        ):
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            yielded = await flow.__anext__()

        assert yielded.headers["Authorization"] == "Bearer fresh-token"
        # POST was made to the configured token URL with the right form data.
        mock_client.post.assert_called_once()
        call = mock_client.post.call_args
        assert call.args[0] == "https://idp.example.com/token"
        assert call.kwargs["data"]["grant_type"] == "client_credentials"
        assert call.kwargs["data"]["client_id"] == "cid"
        assert call.kwargs["data"]["client_secret"] == "csec"

    @pytest.mark.asyncio
    async def test_second_request_within_validity_reuses_cached_token(self):
        auth = OAuthClientCredentialsAuth(
            token_url="https://idp.example.com/token",
            client_id="cid",
            client_secret="csec",
        )
        # Prime the cache as if a successful refresh already happened.
        auth._access_token = "cached-token"
        auth._expires_at = time.time() + 3600

        with patch(
            "authsome_mcp_proxy.outbound_auth.httpx2.AsyncClient"
        ) as mock_client_class:
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            yielded = await flow.__anext__()

        assert yielded.headers["Authorization"] == "Bearer cached-token"
        mock_client_class.assert_not_called()

    @pytest.mark.asyncio
    async def test_expired_token_triggers_refresh(self):
        auth = OAuthClientCredentialsAuth(
            token_url="https://idp.example.com/token",
            client_id="cid",
            client_secret="csec",
        )
        # Prime the cache with a token that's "expired" considering the skew.
        auth._access_token = "stale-token"
        auth._expires_at = time.time() + 30  # less than _expiry_skew_seconds

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "access_token": "fresh-token",
            "expires_in": 3600,
        }

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.post.return_value = mock_response

        with patch(
            "authsome_mcp_proxy.outbound_auth.httpx2.AsyncClient",
            return_value=mock_client,
        ):
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            yielded = await flow.__anext__()

        assert yielded.headers["Authorization"] == "Bearer fresh-token"
        assert auth._access_token == "fresh-token"

    @pytest.mark.asyncio
    async def test_response_without_expires_in_treated_as_long_lived(self):
        auth = OAuthClientCredentialsAuth(
            token_url="https://idp.example.com/token",
            client_id="cid",
            client_secret="csec",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"access_token": "long-lived"}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.post.return_value = mock_response

        with patch(
            "authsome_mcp_proxy.outbound_auth.httpx2.AsyncClient",
            return_value=mock_client,
        ):
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            await flow.__anext__()

        assert auth._expires_at is None
        assert auth._is_token_valid()

    @pytest.mark.asyncio
    async def test_scope_is_included_when_set(self):
        auth = OAuthClientCredentialsAuth(
            token_url="https://idp.example.com/token",
            client_id="cid",
            client_secret="csec",
            scope="upstream:read upstream:write",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"access_token": "t", "expires_in": 3600}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.post.return_value = mock_response

        with patch(
            "authsome_mcp_proxy.outbound_auth.httpx2.AsyncClient",
            return_value=mock_client,
        ):
            request = httpx2.Request("GET", "https://upstream.example.com/")
            flow = auth.async_auth_flow(request)
            await flow.__anext__()

        assert (
            mock_client.post.call_args.kwargs["data"]["scope"]
            == "upstream:read upstream:write"
        )


class TestNoCredentialAuth:
    """none: the upstream receives no credential, not even a forwarded one."""

    def test_strips_a_forwarded_authorization_header(self):
        """FastMCP's proxy copies the downstream Authorization header onto the
        upstream connection; adding nothing would let it through."""
        request = httpx2.Request(
            "POST",
            "https://kb.example.com/mcp",
            headers={"Authorization": "Bearer user-token", "X-Request-Id": "r1"},
        )
        sent = next(NoCredentialAuth().auth_flow(request))

        assert "authorization" not in sent.headers
        assert sent.headers["x-request-id"] == "r1"

    def test_leaves_a_request_without_credential_alone(self):
        request = httpx2.Request("GET", "https://kb.example.com/mcp")
        assert (
            "authorization" not in next(NoCredentialAuth().auth_flow(request)).headers
        )


class TestNoCredentialThroughTheProxy:
    """What ``none`` is for, end to end through FastMCP's proxy."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "outbound_auth,expected",
        [
            # The control: FastMCP's proxy forwards the client's token on its own.
            pytest.param(None, {"authorization": "Bearer user-token"}, id="no-auth"),
            pytest.param(NoCredentialAuth(), {}, id="none"),
        ],
    )
    async def test_the_users_token_does_not_reach_the_upstream(
        self, outbound_auth, expected
    ):
        from contextlib import AsyncExitStack

        from fastmcp import Client, FastMCP
        from fastmcp.client.transports import StreamableHttpTransport
        from fastmcp.server import create_proxy
        from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
        from fastmcp.server.dependencies import get_http_headers
        from fastmcp.server.http import create_streamable_http_app

        upstream = FastMCP(name="upstream")

        @upstream.tool()
        def seen_headers() -> dict[str, str]:
            headers = get_http_headers(include_all=True)
            return {
                h: headers[h] for h in ("authorization", "x-request-id") if h in headers
            }

        def transport_to(app, headers=None):
            def client_factory(headers=None, timeout=None, auth=None, **kwargs):
                if timeout is not None:
                    kwargs["timeout"] = timeout
                return httpx2.AsyncClient(
                    transport=httpx2.ASGITransport(app=app),
                    headers=headers,
                    auth=auth,
                    **kwargs,
                )

            return StreamableHttpTransport(
                "http://testserver/mcp",
                headers=headers,
                httpx_client_factory=client_factory,
            )

        upstream_app = create_streamable_http_app(
            server=upstream, streamable_http_path="/mcp"
        )
        proxy = create_proxy(Client(transport_to(upstream_app), auth=outbound_auth))
        proxy_app = create_streamable_http_app(
            server=proxy,
            streamable_http_path="/mcp",
            auth=StaticTokenVerifier(
                tokens={"user-token": {"client_id": "user", "scopes": []}}
            ),
        )

        async with AsyncExitStack() as stack:
            for app in (upstream_app, proxy_app):
                await stack.enter_async_context(app.router.lifespan_context(app))
            client = await stack.enter_async_context(
                Client(
                    transport_to(proxy_app, headers={"X-Request-Id": "r1"}),
                    auth="user-token",
                )
            )
            seen = (await client.call_tool("seen_headers", {})).data

        # Every other header the client sent still arrives.
        assert seen == {"x-request-id": "r1", **expected}


class TestAcceptedByFastMCPClient:
    """The auth objects must be usable by the HTTP stack fastmcp actually runs.

    The unit tests above drive ``auth_flow`` by hand, so they pass whatever
    library the classes subclass. fastmcp hands ``auth`` to its own HTTP client,
    which rejects anything that is not an instance of *its* ``Auth`` base class
    with ``TypeError: Invalid "auth" argument`` -- at connect time, not at
    construction. This happened when fastmcp 4 moved from ``httpx`` to
    ``httpx2`` while these classes still subclassed ``httpx.Auth``. Only a real
    ``Client`` round trip catches it.
    """

    @pytest.mark.asyncio
    async def test_static_header_reaches_upstream_through_fastmcp_client(self):
        from fastmcp import Client, FastMCP
        from fastmcp.client.transports import StreamableHttpTransport
        from fastmcp.server.dependencies import get_http_headers
        from fastmcp.server.http import create_streamable_http_app

        upstream = FastMCP(name="upstream")

        @upstream.tool()
        def echo_header() -> str:
            return get_http_headers(include_all=True).get("x-api-key", "<missing>")

        app = create_streamable_http_app(server=upstream, streamable_http_path="/mcp")

        def client_factory(
            headers: dict[str, str] | None = None,
            timeout: httpx2.Timeout | None = None,
            auth: httpx2.Auth | None = None,
            **kwargs,
        ) -> httpx2.AsyncClient:
            if timeout is not None:
                kwargs["timeout"] = timeout
            return httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                headers=headers,
                auth=auth,
                **kwargs,
            )

        transport = StreamableHttpTransport(
            "http://testserver/mcp",
            auth=StaticHeaderAuth("X-API-Key", "abc123"),
            httpx_client_factory=client_factory,
        )
        async with app.router.lifespan_context(app), Client(transport) as client:
            result = await client.call_tool("echo_header", {})

        assert result.data == "abc123"
