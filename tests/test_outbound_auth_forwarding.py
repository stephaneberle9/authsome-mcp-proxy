"""End-to-end check of which inbound credentials reach the upstream MCP server.

The proxy that ``create_proxy`` builds runs its upstream ``Client`` with
fastmcp's ``forward_incoming_headers`` transport option, so the transport
copies the downstream request's headers -- ``Authorization`` included -- onto
every upstream request before the outbound auth flow runs. Only what the auth
flow overwrites or removes is kept from the upstream.

The unit tests in ``test_outbound_auth.py`` drive ``auth_flow`` on hand-built
requests, which proves what the flow does to headers that are already there but
not that the forwarded headers *are* already there when it runs. These tests
send a request with a bearer token and a cookie through a real proxy app into an
in-process upstream, and look at the headers the upstream actually received.

fastmcp's forwarding withholds ``Cookie`` on its own today, so the cookie
assertions here pin the combined behavior and would catch fastmcp starting to
forward it; the auth flows' own cookie stripping is pinned by the unit tests.
"""

from __future__ import annotations

import json
import time

import httpx2
import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.http import create_streamable_http_app

from authsome_mcp_proxy.outbound_auth import (
    ForwardSessionTokenAuth,
    OAuthClientCredentialsAuth,
    StaticHeaderAuth,
)

INBOUND_TOKEN = "inbound-token-for-the-proxy"
INBOUND_COOKIE = "session=inbound-cookie-for-the-proxy"


def _asgi_client_factory(app):
    """An httpx client factory that routes a fastmcp transport into ``app``."""

    def factory(
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

    return factory


async def _upstream_headers_seen_through_proxy(
    outbound_auth: httpx2.Auth,
) -> dict[str, str]:
    """Call an upstream tool through the proxy and return the upstream's headers.

    The downstream client authenticates to the proxy with ``INBOUND_TOKEN`` and
    also sends ``INBOUND_COOKIE``, as a browser-adjacent client might. The proxy
    accepts the token through a static verifier so that ``forward`` mode finds
    an authenticated session, the same way inbound OAuth would provide one.
    """
    upstream = FastMCP(name="upstream")

    @upstream.tool()
    def received_headers() -> str:
        return json.dumps(get_http_headers(include_all=True))

    upstream_app = create_streamable_http_app(
        server=upstream, streamable_http_path="/mcp"
    )

    proxy_client = Client(
        StreamableHttpTransport(
            "http://upstream/mcp",
            auth=outbound_auth,
            httpx_client_factory=_asgi_client_factory(upstream_app),
        )
    )
    proxy = create_proxy(proxy_client, name="proxy")
    proxy_app = create_streamable_http_app(
        server=proxy,
        streamable_http_path="/mcp",
        auth=StaticTokenVerifier(
            tokens={INBOUND_TOKEN: {"client_id": "downstream", "scopes": []}}
        ),
    )

    downstream = Client(
        StreamableHttpTransport(
            "http://proxy/mcp",
            headers={
                "Authorization": f"Bearer {INBOUND_TOKEN}",
                "Cookie": INBOUND_COOKIE,
            },
            httpx_client_factory=_asgi_client_factory(proxy_app),
        )
    )
    async with (
        upstream_app.router.lifespan_context(upstream_app),
        proxy_app.router.lifespan_context(proxy_app),
        downstream,
    ):
        result = await downstream.call_tool("received_headers", {})

    return json.loads(result.data)


def _client_credentials_auth_with_cached_token() -> OAuthClientCredentialsAuth:
    auth = OAuthClientCredentialsAuth(
        token_url="https://idp.example.com/token",
        client_id="cid",
        client_secret="csec",
    )
    # A primed cache keeps the token endpoint out of the test.
    auth._access_token = "service-account-token"
    auth._expires_at = time.time() + 3600
    return auth


@pytest.mark.asyncio
async def test_static_custom_header_does_not_forward_inbound_bearer_token():
    headers = await _upstream_headers_seen_through_proxy(
        StaticHeaderAuth("X-API-Key", "upstream-api-key")
    )

    assert headers["x-api-key"] == "upstream-api-key"
    # The inbound token was issued for the proxy, not for the upstream.
    assert "authorization" not in headers
    assert "cookie" not in headers


@pytest.mark.asyncio
async def test_static_authorization_header_replaces_inbound_bearer_token():
    headers = await _upstream_headers_seen_through_proxy(
        StaticHeaderAuth("Authorization", "Bearer upstream-api-key")
    )

    assert headers["authorization"] == "Bearer upstream-api-key"
    assert "cookie" not in headers


@pytest.mark.asyncio
async def test_forward_mode_sends_session_token_and_no_cookie():
    headers = await _upstream_headers_seen_through_proxy(ForwardSessionTokenAuth())

    assert headers["authorization"] == f"Bearer {INBOUND_TOKEN}"
    assert "cookie" not in headers


@pytest.mark.asyncio
async def test_client_credentials_mode_sends_service_token_and_no_cookie():
    headers = await _upstream_headers_seen_through_proxy(
        _client_credentials_auth_with_cached_token()
    )

    assert headers["authorization"] == "Bearer service-account-token"
    assert "cookie" not in headers
