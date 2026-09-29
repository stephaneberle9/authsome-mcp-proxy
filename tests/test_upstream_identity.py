"""Tests for relaying the upstream's identity through web-mode handshakes."""

import logging

import mcp.types as mt
import pytest
from fastmcp import Client, FastMCP
from fastmcp.server import create_proxy

from authsome_mcp_proxy import mcp_proxy
from authsome_mcp_proxy.upstream_identity import UpstreamIdentityMiddleware

UPSTREAM_ICON = mt.Icon(
    src="https://upstream.example.com/icon.png", mime_type="image/png"
)


def _upstream():
    return FastMCP(
        name="upstream-name",
        version="9.9.9",
        instructions="use the upstream's tools wisely",
        website_url="https://upstream.example.com",
        icons=[UPSTREAM_ICON],
    )


def _proxy(upstream, **proxy_kwargs):
    """A proxy wired like web mode: identity from config, relay via middleware."""
    proxy = create_proxy(Client(upstream), **proxy_kwargs)
    middleware = UpstreamIdentityMiddleware(
        lambda: mcp_proxy._relay_upstream_identity(upstream, None),
        configured_fields=proxy_kwargs.keys(),
    )
    proxy.add_middleware(middleware)
    return proxy


class _CountingFetch:
    """A fetch_identity stand-in that records calls and can be made to fail."""

    def __init__(self, identity=None, error=None):
        self.identity = identity or {
            "instructions": "relayed",
            "website_url": "https://relayed.example.com",
        }
        self.error = error
        self.calls = 0

    async def __call__(self):
        self.calls += 1
        if self.error:
            raise self.error
        return self.identity


# "auto" negotiates the modern protocol through server/discover, where serverInfo
# is a `_meta` stamp; "legacy" pins the initialize handshake, where it is a result
# field. (Pinning a modern version instead would skip discover altogether.)
PROTOCOL_ERAS = pytest.mark.parametrize("mode", ["auto", "legacy"])


@PROTOCOL_ERAS
async def test_downstream_sees_the_upstreams_identity(mode):
    proxy = _proxy(_upstream(), name="itemis ANALYZE MCP", version="1.0.0")

    async with Client(proxy, mode=mode) as client:
        info = client.server_info
        instructions = client.instructions
        # Guards the parametrization: each era must take its own code path.
        assert (client.initialize_result is None) == (mode == "auto")

    assert info.name == "itemis ANALYZE MCP"
    assert info.version == "1.0.0"
    assert info.website_url == "https://upstream.example.com"
    assert info.icons == [UPSTREAM_ICON]
    assert instructions == "use the upstream's tools wisely"


@PROTOCOL_ERAS
async def test_operator_configured_fields_win(mode):
    proxy = _proxy(
        _upstream(),
        name="itemis ANALYZE MCP",
        instructions="the operator's instructions",
        website_url="https://operator.example.com",
    )

    async with Client(proxy, mode=mode) as client:
        info = client.server_info
        instructions = client.instructions

    assert instructions == "the operator's instructions"
    assert info.website_url == "https://operator.example.com"
    # Not configured, so still relayed.
    assert info.icons == [UPSTREAM_ICON]


async def test_identity_is_fetched_once_and_reused():
    fetch = _CountingFetch()
    proxy = create_proxy(Client(_upstream()), name="proxy")
    proxy.add_middleware(UpstreamIdentityMiddleware(fetch))

    for _ in range(3):
        async with Client(proxy) as client:
            assert client.instructions == "relayed"

    assert fetch.calls == 1


async def test_identity_is_refetched_after_the_ttl():
    fetch = _CountingFetch()
    proxy = create_proxy(Client(_upstream()), name="proxy")
    proxy.add_middleware(UpstreamIdentityMiddleware(fetch, ttl_seconds=0))

    for _ in range(2):
        async with Client(proxy):
            pass

    assert fetch.calls == 2


async def test_a_failed_fetch_leaves_the_handshake_intact(caplog):
    """The identity is cosmetic: the client must connect regardless, and see
    the proxy's own values rather than an error."""
    fetch = _CountingFetch(error=RuntimeError("upstream unreachable"))
    proxy = create_proxy(Client(_upstream()), name="proxy", instructions="fallback")
    proxy.add_middleware(UpstreamIdentityMiddleware(fetch))

    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            async with Client(proxy) as client:
                assert client.server_info.name == "proxy"
                assert client.instructions == "fallback"

    # Backed off rather than retried on every handshake.
    assert fetch.calls == 1
    assert "upstream unreachable" in caplog.text


async def test_a_failed_refresh_keeps_serving_the_last_identity():
    fetch = _CountingFetch()
    proxy = create_proxy(Client(_upstream()), name="proxy")
    proxy.add_middleware(
        UpstreamIdentityMiddleware(fetch, ttl_seconds=0, retry_after_seconds=0)
    )

    async with Client(proxy) as client:
        assert client.instructions == "relayed"

    fetch.error = RuntimeError("upstream redeploying")
    async with Client(proxy) as client:
        assert client.instructions == "relayed"
    assert fetch.calls == 2


async def test_a_slow_fetch_is_cut_off():
    import anyio

    async def hang():
        await anyio.sleep(60)

    proxy = create_proxy(Client(_upstream()), name="proxy")
    proxy.add_middleware(UpstreamIdentityMiddleware(hang, timeout_seconds=0.1))

    with anyio.fail_after(10):
        async with Client(proxy) as client:
            assert client.server_info.name == "proxy"


async def test_nothing_is_fetched_when_the_operator_configured_everything():
    fetch = _CountingFetch()
    proxy = create_proxy(Client(_upstream()), name="proxy")
    proxy.add_middleware(
        UpstreamIdentityMiddleware(
            fetch, configured_fields=("instructions", "website_url", "icons")
        )
    )

    async with Client(proxy):
        pass

    assert fetch.calls == 0


def _asgi_transport(app, auth=None):
    """A streamable-HTTP transport that talks to *app* in-process."""
    import httpx2
    from fastmcp.client.transports import StreamableHttpTransport

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
        "http://testserver/mcp", httpx_client_factory=client_factory, auth=auth
    )


@PROTOCOL_ERAS
async def test_forward_mode_fetches_with_the_downstream_users_token(mode):
    """The case the middleware exists for: an upstream that only accepts the
    user's own token, so the identity cannot be read before a user connects.
    The fetch must run inside the downstream request to see that token."""
    from contextlib import AsyncExitStack

    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
    from fastmcp.server.http import create_streamable_http_app

    from authsome_mcp_proxy.outbound_auth import ForwardSessionTokenAuth

    def verifier():
        return StaticTokenVerifier(
            tokens={"user-token": {"client_id": "user", "scopes": []}}
        )

    upstream = _upstream()
    upstream_app = create_streamable_http_app(
        server=upstream, streamable_http_path="/mcp", auth=verifier()
    )

    outbound_auth = ForwardSessionTokenAuth()
    proxy = create_proxy(
        Client(_asgi_transport(upstream_app), auth=outbound_auth), name="proxy"
    )
    proxy.add_middleware(
        UpstreamIdentityMiddleware(
            lambda: mcp_proxy._relay_upstream_identity(
                _asgi_transport(upstream_app), outbound_auth
            )
        )
    )
    proxy_app = create_streamable_http_app(
        server=proxy, streamable_http_path="/mcp", auth=verifier()
    )

    async with AsyncExitStack() as stack:
        await stack.enter_async_context(
            upstream_app.router.lifespan_context(upstream_app)
        )
        await stack.enter_async_context(proxy_app.router.lifespan_context(proxy_app))
        client = await stack.enter_async_context(
            Client(_asgi_transport(proxy_app), auth="user-token", mode=mode)
        )
        info = client.server_info
        instructions = client.instructions

    assert info.name == "proxy"
    assert info.website_url == "https://upstream.example.com"
    assert instructions == "use the upstream's tools wisely"
