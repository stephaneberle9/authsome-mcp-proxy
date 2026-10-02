"""Outbound auth mode factory for the web (HTTP) transport.

The proxy authenticates outbound calls to the upstream MCP server using
one of four mechanisms -- see ``WebConfig.outbound_auth``:

- ``forward``: reuse the downstream session's bearer token. The current
  session's access token is read from FastMCP's per-request auth context
  via :func:`fastmcp.server.dependencies.get_access_token` and copied into
  the outbound ``Authorization: Bearer <token>`` header. Pattern C (and
  Pattern A passthrough by the same shape).
- ``none``: send no credential. FastMCP's proxy copies the downstream
  request's ``Authorization`` header onto the upstream connection by default,
  so "no outbound auth" has to strip it rather than merely add nothing --
  otherwise the user's token reaches an upstream that never asked for it.
- ``oauth-client-credentials``: proxy obtains its own access token via the
  OAuth 2.0 client_credentials grant against an outbound token endpoint
  that is *independent* of the inbound IdP -- in Pattern B the upstream's
  auth mechanism is by definition disconnected from the IdP that fronts
  the proxy. The token is cached and refreshed on expiry.
- ``static``: proxy injects a configured literal header value (e.g.
  ``Authorization: Bearer <api-key>`` or ``X-API-Key: <api-key>``). Covers
  API keys, API tokens, and PATs uniformly -- same wire shape, different
  upstream vocabularies. The *pattern* (B.1 vs B.2) is determined by the
  *scope* of the credential the operator configures (tenant-scoped vs
  per-user), not by the mechanism.
"""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator, Generator
from typing import TYPE_CHECKING

import anyio
import httpx2
from fastmcp.server.dependencies import get_access_token

if TYPE_CHECKING:
    from .config import UpstreamRoute, WebConfig


class ForwardSessionTokenAuth(httpx2.Auth):
    """Forward the downstream session's bearer token to the upstream MCP.

    Reads the current FastMCP session's access token via
    :func:`fastmcp.server.dependencies.get_access_token` and injects it as
    the outbound ``Authorization`` header. The accessor is ContextVar-backed
    and propagates through the per-session ``Client`` clone that FastMCP's
    ``create_proxy`` produces, so the value resolves to *this* request's
    token rather than any other concurrent session's.

    Fails closed: if no inbound token is available (e.g. the inbound auth
    middleware didn't authenticate the request), raises rather than sending
    unauthenticated outbound traffic.
    """

    requires_request_body = False
    requires_response_body = False

    async def async_auth_flow(
        self, request: httpx2.Request
    ) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        token = get_access_token()
        if token is None or not token.token:
            raise RuntimeError(
                "No inbound session access token available for outbound_auth='forward'. "
                "The inbound request must be authenticated before the proxy can forward "
                "the user's token to the upstream MCP server."
            )
        request.headers["Authorization"] = f"Bearer {token.token}"
        yield request


class NoCredentialAuth(httpx2.Auth):
    """Send the upstream no credential at all.

    For an upstream that authenticates nobody, such as a read-only knowledge
    server. Adding nothing would not be enough: FastMCP's proxy forwards the
    downstream request's headers to the upstream, ``Authorization`` included,
    and the auth flow is the last point before the request leaves the proxy.
    Removing the header here keeps the user's token -- a credential that
    opens the proxy itself -- away from a server that has no use for it.
    """

    requires_request_body = False
    requires_response_body = False

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response]:
        request.headers.pop("Authorization", None)
        yield request


class StaticHeaderAuth(httpx2.Auth):
    """Inject a configured literal header value on every outbound request.

    Single-tenant Pattern B.1 (tenant-scoped credential) and single-tenant
    single-user Pattern B.2 (per-user credential -- known as API key, API
    token, or PAT depending on the upstream's vocabulary) share this same
    code path. The pattern is purely a property of the *scope* of the
    configured value, not of the mechanism.
    """

    requires_request_body = False
    requires_response_body = False

    def __init__(self, header_name: str, header_value: str) -> None:
        self.header_name = header_name
        self.header_value = header_value

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response]:
        request.headers[self.header_name] = self.header_value
        yield request


class OAuthClientCredentialsAuth(httpx2.Auth):
    """OAuth 2.0 client_credentials grant for outbound calls.

    Obtains a service-account access token from a separately configured
    outbound token endpoint, caches it with expiry tracking, and refreshes
    on demand. The outbound IdP / token endpoint is independent of the
    inbound IdP -- Pattern B's defining property.

    A small skew is subtracted from the response's ``expires_in`` so the
    cached token is treated as expired slightly before the IdP would
    actually reject it, avoiding races where the upstream sees the token
    just as it expires.
    """

    requires_request_body = False
    requires_response_body = False
    _expiry_skew_seconds: float = 60.0

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
    ) -> None:
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self._access_token: str | None = None
        self._expires_at: float | None = None
        self._lock = anyio.Lock()

    async def async_auth_flow(
        self, request: httpx2.Request
    ) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        token = await self._get_token()
        request.headers["Authorization"] = f"Bearer {token}"
        yield request

    def _is_token_valid(self) -> bool:
        if self._access_token is None:
            return False
        if self._expires_at is None:
            # Token endpoint didn't return expires_in -- treat as long-lived.
            return True
        return time.time() < self._expires_at - self._expiry_skew_seconds

    async def _get_token(self) -> str:
        if self._is_token_valid():
            assert self._access_token is not None
            return self._access_token

        async with self._lock:
            # Re-check inside the lock to coalesce concurrent refreshes.
            if self._is_token_valid():
                assert self._access_token is not None
                return self._access_token

            await self._refresh_token()
            assert self._access_token is not None
            return self._access_token

    async def _refresh_token(self) -> None:
        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            data["scope"] = self.scope

        async with httpx2.AsyncClient() as client:
            response = await client.post(self.token_url, data=data, timeout=10.0)
            response.raise_for_status()
            payload = response.json()

        self._access_token = payload["access_token"]
        expires_in = payload.get("expires_in")
        self._expires_at = (
            time.time() + float(expires_in) if expires_in is not None else None
        )


def build_outbound_auth(config: WebConfig | UpstreamRoute) -> httpx2.Auth:
    """Build an ``httpx2.Auth`` matching ``config.outbound_auth``.

    The returned auth instance is attached to the per-session ``Client``
    that FastMCP's ``create_proxy`` produces, so its hooks run within the
    inbound MCP request's async task. That matters for ``forward`` mode,
    where the auth reads ContextVar-backed per-session state.

    Args:
        config: Web-mode configuration, or one route of a multi-upstream
            configuration. Its ``__post_init__`` has already validated that
            all required per-mode fields are populated.

    Returns:
        An ``httpx2.Auth`` instance ready to plug into a per-session Client.

    Raises:
        ValueError: If ``config.outbound_auth`` is unknown.
    """
    if config.outbound_auth == "forward":
        return ForwardSessionTokenAuth()

    if config.outbound_auth == "none":
        return NoCredentialAuth()

    if config.outbound_auth == "oauth-client-credentials":
        assert config.outbound_token_url is not None
        assert config.outbound_client_id is not None
        assert config.outbound_client_secret is not None
        return OAuthClientCredentialsAuth(
            token_url=config.outbound_token_url,
            client_id=config.outbound_client_id,
            client_secret=config.outbound_client_secret,
        )

    if config.outbound_auth == "static":
        assert config.outbound_header_value is not None
        return StaticHeaderAuth(
            header_name=config.outbound_header_name,
            header_value=config.outbound_header_value,
        )

    raise ValueError(
        f"Unknown outbound_auth {config.outbound_auth!r}; supported: "
        "forward, none, oauth-client-credentials, static"
    )
