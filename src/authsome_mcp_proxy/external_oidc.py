"""
OIDC Auth client provider for external OpenID Connect (OIDC) providers.

This module provides an OAuth client for external OIDC providers (Keycloak, Auth0,
Okta, etc.) that handles the complete OAuth 2.0 authorization code flow with PKCE
using static client credentials. Key features include:

- Automatic provider configuration discovery via /.well-known/openid-configuration
- Browser-based user authentication with automatic OAuth callback handling
- Secure token exchange using PKCE (Proof Key for Code Exchange)
- Local token caching to eliminate repeated browser authentication
- Automatic access token refresh using refresh tokens
- Support for custom scopes and redirect URLs

Unlike dynamic client registration, this uses pre-configured client credentials
(client_id/client_secret) that must be set up in the OIDC provider beforehand.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
import webbrowser
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode, urlparse

import anyio
import httpx2
from exceptiongroup import BaseExceptionGroup
from fastmcp.client.auth.oauth import TokenStorageAdapter
from fastmcp.client.oauth_callback import (
    OAuthCallbackResult,
    create_oauth_callback_server,
)
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration
from key_value.aio.stores.disk import DiskStore
from mcp.client.auth import PKCEParameters, TokenStorage
from mcp.shared.auth import OAuthToken
from pydantic import AnyHttpUrl
from uvicorn.server import Server

from . import __version__

__all__ = ["ExternalOIDCAuth"]

# Use 'logging' instead of 'fastmcp.utilities.logging' to avoid mixin of FastMCP-formatted log message
logger = logging.getLogger(__name__)

# Add file handler for token refresh logging
# Log file will be created in the cache directory (e.g., ~/.cache/authsome-mcp-proxy-dev/)
# Note: Cache directory is determined later during auth initialization, so we'll set this up there
_token_refresh_log_handler = None


def _setup_token_refresh_logging(cache_dir: Path):
    """Set up file logging for token refresh events."""
    global _token_refresh_log_handler
    if _token_refresh_log_handler:
        return  # Already set up

    token_refresh_log = cache_dir / "token_refresh.log"
    _token_refresh_log_handler = logging.FileHandler(
        token_refresh_log, mode="a", encoding="utf-8"
    )
    _token_refresh_log_handler.setLevel(logging.DEBUG)
    _token_refresh_log_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
    )
    logger.addHandler(_token_refresh_log_handler)


HTTPX_REQUEST_TIMEOUT_SECONDS = 5
BROWSER_LOGIN_TIMEOUT_SECONDS = 30


class _ExternalOIDCConfiguration(OIDCConfiguration):
    """fastmcp's discovery model, extended with the RFC 9207 metadata flag.

    fastmcp's `OIDCConfiguration` ignores undeclared fields, so without this
    declaration the provider's `authorization_response_iss_parameter_supported`
    would be dropped during parsing and the callback could never require `iss`.
    Subclassing keeps fastmcp's fetching, strict validation and caching, which
    `get_oidc_configuration` applies to whichever class it is called on.
    """

    # RFC 9207, section 3: advertises that every authorization response carries `iss`
    authorization_response_iss_parameter_supported: bool | None = None


@dataclass
class OIDCContext:
    """OIDC OAuth flow context - similar to OAuthContext but for external OIDC providers."""

    issuer_url: str
    client_id: str
    client_secret: str | None
    scopes: list[str]
    redirect_uri: str
    storage: TokenStorage

    # Discovered metadata
    oidc_config: _ExternalOIDCConfiguration

    # Token management
    current_tokens: OAuthToken | None = None
    token_expiry_time: float | None = None

    # State
    lock: anyio.Lock = field(default_factory=anyio.Lock)

    def get_redirect_port(self) -> int:
        """Extract the port number from the redirect URI."""
        parsed = urlparse(self.redirect_uri)
        return parsed.port or 80

    def get_redirect_path(self) -> str:
        """Extract the path from the redirect URI."""
        parsed = urlparse(self.redirect_uri)
        return parsed.path or "/callback"

    def get_authorization_url(self, state: str, pkce: PKCEParameters) -> str:
        """Build the authorization URL with PKCE parameters."""
        auth_params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
            "code_challenge": pkce.code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.oidc_config.authorization_endpoint}?{urlencode(auth_params)}"

    def get_token_exchange_data(
        self, auth_code: str, pkce: PKCEParameters
    ) -> dict[str, str]:
        """Build token exchange request data."""
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": pkce.code_verifier,
        }
        if self.client_secret:
            token_data["client_secret"] = self.client_secret
        return token_data

    def get_token_refresh_data(self) -> dict[str, str]:
        """Build token refresh request data.

        Note: Callers should check can_refresh_token() before calling this method.
        """
        if not self.current_tokens or not self.current_tokens.refresh_token:
            raise RuntimeError("No refresh token available")
        token_data: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": self.current_tokens.refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            token_data["client_secret"] = self.client_secret
        return token_data

    def set_tokens(self, tokens: OAuthToken | None) -> None:
        """Set current tokens and update expiry time."""
        self.current_tokens = tokens
        if tokens and tokens.expires_in:
            self.token_expiry_time = time.time() + tokens.expires_in
        else:
            self.token_expiry_time = None

    def is_token_valid(self) -> bool:
        """Check if current token is valid and not expired."""
        return bool(
            self.current_tokens
            and self.current_tokens.access_token
            and (
                not self.token_expiry_time or time.time() < self.token_expiry_time - 60
            )
        )

    def can_refresh_token(self) -> bool:
        """Check if token can be refreshed."""
        return bool(self.current_tokens and self.current_tokens.refresh_token)

    def get_access_token(self) -> str:
        """Get the current access token.

        Raises:
            RuntimeError: If no valid access token is available.
        """
        if not self.current_tokens or not self.current_tokens.access_token:
            raise RuntimeError("No access token available")
        return self.current_tokens.access_token

    def clear_tokens(self) -> None:
        """Clear current tokens."""
        self.current_tokens = None
        self.token_expiry_time = None


class ExternalOIDCAuth(httpx2.Auth):
    """
    OAuth client provider that authenticates against external OIDC providers.

    This client fetches OAuth configuration from an external OIDC provider's
    /.well-known/openid-configuration endpoint and uses static client credentials
    (client_id and client_secret) instead of dynamic client registration.

    Key differences from standard OAuth client:
    - Fetches config from issuer's /.well-known/openid-configuration (not MCP server)
    - Uses static client_id/client_secret (no dynamic registration)
    - Works with any OIDC-compliant provider (Keycloak, Auth0, Okta, etc.)

    Example:
        ```python
        from fastmcp.client import Client
        from fastmcp.client.auth import OIDCAuth

        auth = OIDCAuth(
            issuer_url="https://your-keycloak.example.com/realms/myrealm",
            client_id="your-client-id",
            client_secret="your-client-secret",
            scopes=["openid", "profile", "email"],
            redirect_url="http://localhost:8080/auth/callback"
        )

        async with Client("http://localhost:8000/mcp", auth=auth) as client:
            # Use authenticated client
            result = await client.call_tool("my_tool", {"arg": "value"})
        ```
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str | None = None,
        scopes: str | list[str] | None = None,
        token_storage_cache_dir: Path | None = None,
        redirect_url: str | None = None,
    ):
        """
        Initialize OIDC Auth client provider.

        Args:
            issuer_url: OIDC issuer URL (e.g., "https://keycloak.example.com/realms/myrealm")
            client_id: Static OAuth client ID
            client_secret: Static OAuth client secret (optional for public OIDC clients that don't require any such)
            scopes: OAuth scopes to request (default: ["openid"]). Can be a
            space-separated string or a list of strings.
            token_storage_cache_dir: Directory for token storage cache (default: ~/.cache/authsome-mcp-proxy-<version>/)
            redirect_url: Localhost URL for OAuth redirect (default: http://localhost:8080/auth/callback)
        """
        # Validate required parameters
        if not issuer_url:
            raise ValueError("Missing required issuer URL")
        if not client_id:
            raise ValueError("Missing required client id")

        # Parse and validate scopes
        if isinstance(scopes, list):
            scopes_list = scopes
        elif scopes is not None:
            scopes_list = scopes.split()
        else:
            scopes_list = ["openid"]

        # Ensure openid scope is always included
        if "openid" not in scopes_list:
            scopes_list.insert(0, "openid")

        # Setup redirect port and redirect URI
        redirect_uri = redirect_url or "http://localhost:8080/auth/callback"

        # Initialize token storage using DiskStore and TokenStorageAdapter
        # DiskStore provides persistent disk-based storage for OAuth tokens
        # Use a default cache directory if none is provided
        # For development versions (with git hash), use stable 'dev' directory
        # to avoid creating new cache for each commit
        version_suffix = (
            "dev" if "+g" in __version__ or ".dev" in __version__ else __version__
        )
        cache_dir = (
            token_storage_cache_dir
            or Path.home() / ".cache" / f"authsome-mcp-proxy-{version_suffix}"
        )
        disk_store = DiskStore(directory=cache_dir)
        storage = TokenStorageAdapter(async_key_value=disk_store, server_url=issuer_url)

        # Set up token refresh logging to file in cache directory
        _setup_token_refresh_logging(cache_dir)

        # Fetch OIDC configuration
        config_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
        oidc_config = _ExternalOIDCConfiguration.get_oidc_configuration(
            AnyHttpUrl(config_url),
            strict=True,
            timeout_seconds=HTTPX_REQUEST_TIMEOUT_SECONDS,
        )

        # Validate required endpoints
        if not oidc_config.authorization_endpoint:
            raise ValueError("OIDC configuration missing authorization_endpoint")
        if not oidc_config.token_endpoint:
            raise ValueError("OIDC configuration missing token_endpoint")

        # OpenID Connect Discovery 1.0, section 4.3 (and RFC 8414, section 3.3)
        # forbids using a discovery document whose `issuer` is not identical to
        # the issuer URL it was fetched for. The document's `issuer` is the
        # reference value of the RFC 9207 `iss` check on the callback, so
        # without this check that security check would be anchored to whatever
        # the discovery response claims rather than to the configuration.
        # The comparison is exact except for a trailing slash on either side.
        # The discovery URL above strips that slash, so both spellings fetch
        # the same document, and tolerating it anchors the `issuer` no less
        # while keeping configurations working that copied the issuer URL with
        # or without the slash the provider publishes. Any other difference is
        # a mismatch, and the error names both values. `oidc_config.issuer` is
        # the literal string the provider published, since fastmcp's model
        # prefers `str` over `AnyHttpUrl` for a string input and so never adds
        # a trailing slash; the `iss` check compares against it exactly. The
        # `str(...)` matches that check and only narrows the declared type.
        if str(oidc_config.issuer).rstrip("/") != issuer_url.rstrip("/"):
            raise ValueError(
                f"OIDC configuration issuer {oidc_config.issuer} does not match "
                f"the configured issuer URL {issuer_url}"
            )

        # Create context with all configuration and state
        self.context = OIDCContext(
            issuer_url=issuer_url,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes_list,
            redirect_uri=redirect_uri,
            oidc_config=oidc_config,
            storage=storage,
        )

        self._initialized = False

    async def _initialize(self) -> None:
        """Load stored tokens if available."""
        if self._initialized:
            return

        stored_tokens = await self.context.storage.get_tokens()
        self.context.set_tokens(stored_tokens)
        has_access = (
            bool(stored_tokens and stored_tokens.access_token)
            if stored_tokens
            else False
        )
        has_refresh = (
            bool(stored_tokens and stored_tokens.refresh_token)
            if stored_tokens
            else False
        )
        logger.info(
            f"[INIT] OIDC Auth initialized: access_token={has_access}, refresh_token={has_refresh}"
        )
        self._initialized = True

    async def _run_callback_server(self) -> tuple[str, str, str | None]:
        """Handle OAuth callback and return (auth_code, state, iss).

        `iss` is the RFC 9207 issuer identifier, or None when the provider did
        not send one.
        """
        # Create result container and event for async coordination
        result_container = OAuthCallbackResult()
        result_ready = anyio.Event()

        # Create server with result container and event
        server: Server = create_oauth_callback_server(
            port=self.context.get_redirect_port(),
            callback_path=self.context.get_redirect_path(),
            server_url=self.context.issuer_url,
            result_container=result_container,
            result_ready=result_ready,
        )

        # Run server until response is received with timeout logic
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            logger.info(
                f"OIDC Auth callback server started on {self.context.redirect_uri}"
            )

            try:
                with anyio.fail_after(BROWSER_LOGIN_TIMEOUT_SECONDS):
                    await result_ready.wait()

                    # Check for errors
                    if result_container.error:
                        raise result_container.error

                    # Validate that we received code and state
                    if not result_container.code or not result_container.state:
                        raise RuntimeError(
                            "OAuth callback did not return code or state"
                        )

                    return (
                        result_container.code,
                        result_container.state,
                        result_container.iss,
                    )
            except TimeoutError:
                raise TimeoutError(
                    f"OIDC Auth callback timed out after {BROWSER_LOGIN_TIMEOUT_SECONDS} seconds, "
                    f"check browser for errors"
                )
            finally:
                server.should_exit = True
                await asyncio.sleep(0.1)  # Allow server to shut down gracefully
                tg.cancel_scope.cancel()

        raise RuntimeError("OIDC Auth callback handler could not be started")

    def _validate_iss(self, returned_iss: str | None) -> None:
        """Validate the RFC 9207 `iss` parameter of the authorization callback.

        Defends against the mix-up attack: an attacker who gets the client to
        start a flow at one authorization server can make the authorization code
        of another server arrive at this callback, and the client would then
        redeem it at the wrong token endpoint. The authorization server names
        itself in `iss`, so a callback from any other server is rejected here,
        before the code reaches the token endpoint.

        Raises:
            RuntimeError: If `iss` does not match the provider's issuer, or is
                absent although the provider advertised that it always sends it.
        """
        # RFC 9207, section 2.4 prescribes comparing against the issuer
        # identifier of the authorization server the request was sent to. That
        # is the discovery document's `issuer`, which `__init__` has checked to
        # match the configured issuer URL; mcp's OAuth client
        # compares against the metadata issuer too. Plain string comparison,
        # without URL normalization, is what section 2.4 requires.
        expected_iss = str(self.context.oidc_config.issuer)

        if returned_iss is not None:
            if returned_iss != expected_iss:
                raise RuntimeError(
                    f"OAuth iss mismatch: {returned_iss} != {expected_iss} - possible mix-up attack"
                )
            return

        # A provider that does not advertise support may legitimately omit
        # `iss`; one that does advertise it always sends it, so its absence
        # means the callback did not come from that provider.
        if self.context.oidc_config.authorization_response_iss_parameter_supported:
            raise RuntimeError(
                f"OAuth iss missing: expected {expected_iss} - possible mix-up attack"
            )

    async def _perform_auth_flow(self) -> OAuthToken:
        """Perform the OAuth authorization code flow with PKCE."""
        async with self.context.lock:
            # Generate PKCE parameters and state
            pkce = PKCEParameters.generate()
            state = secrets.token_urlsafe(32)

            # Build authorization URL using context method
            authorization_url = self.context.get_authorization_url(state, pkce)

            # Open browser for authorization
            logger.info(f"Opening browser for OIDC authorization: {authorization_url}")
            webbrowser.open(authorization_url)

            # Wait for callback
            auth_code, returned_state, returned_iss = await self._run_callback_server()

            # Validate state
            if returned_state is None or not secrets.compare_digest(
                returned_state, state
            ):
                raise RuntimeError(
                    f"OAuth state mismatch: {returned_state} != {state} - possible CSRF attack"
                )

            self._validate_iss(returned_iss)

            # Validate auth code
            if not auth_code:
                raise RuntimeError("No authorization code received")

            # Build token data using context method
            token_data = self.context.get_token_exchange_data(auth_code, pkce)

            # Exchange authorization code for tokens
            async with httpx2.AsyncClient() as client:
                response = await client.post(
                    str(self.context.oidc_config.token_endpoint),
                    data=token_data,
                    timeout=float(HTTPX_REQUEST_TIMEOUT_SECONDS),
                )
                response.raise_for_status()
                token_response = response.json()

            # Parse and store tokens
            tokens = OAuthToken.model_validate(token_response)
            await self.context.storage.set_tokens(tokens)
            self.context.set_tokens(tokens)

            logger.info("OIDC Auth flow completed successfully")
            return tokens

    async def _refresh_tokens(self) -> OAuthToken:
        """Refresh access token using refresh token."""
        async with self.context.lock:
            if not self.context.can_refresh_token():
                raise RuntimeError("No refresh token available")

            token_data = self.context.get_token_refresh_data()

            async with httpx2.AsyncClient() as client:
                response = await client.post(
                    str(self.context.oidc_config.token_endpoint),
                    data=token_data,
                    timeout=float(HTTPX_REQUEST_TIMEOUT_SECONDS),
                )
                response.raise_for_status()
                token_response = response.json()

            # Parse and store new tokens
            tokens = OAuthToken.model_validate(token_response)

            # Preserve existing refresh token if response doesn't include a new one
            # Per OAuth 2.0 spec, refresh token is optional in refresh responses
            if not tokens.refresh_token and self.context.current_tokens:
                tokens.refresh_token = self.context.current_tokens.refresh_token
                logger.debug(
                    "[REFRESH] Preserved existing refresh token (not in response)"
                )

            await self.context.storage.set_tokens(tokens)
            self.context.set_tokens(tokens)

            logger.debug("OIDC Auth tokens refreshed")
            return tokens

    async def _get_token(self) -> str:
        """
        Get a valid access token, renewing it if necessary.

        Returns:
            A valid access token, either from cache or after renewal.
        """
        await self._initialize()

        # If token is valid, return it
        if self.context.is_token_valid():
            logger.debug("[TOKEN] Using cached valid token")
            return self.context.get_access_token()

        # Token expired or missing - refresh or re-auth
        logger.info("[TOKEN] Token expired/missing, attempting renewal")
        return await self._renew_token()

    async def _renew_token(self) -> str:
        """Handle authentication errors by refreshing or re-authenticating."""
        if self.context.can_refresh_token():
            try:
                logger.info("[REFRESH] Attempting silent token refresh...")
                await self._refresh_tokens()
                logger.info(
                    "[REFRESH] Token refreshed successfully (no browser needed)"
                )
            except Exception as e:
                logger.warning(f"[REFRESH] Token refresh failed: {e}")
                logger.warning("[AUTH] Opening browser for full re-authentication")
                await self._perform_auth_flow()
        else:
            logger.warning("[AUTH] No refresh token available")
            logger.warning("[AUTH] Opening browser for full re-authentication")
            await self._perform_auth_flow()

        return self.context.get_access_token()

    async def async_auth_flow(
        self, request: httpx2.Request
    ) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        """
        HTTPX auth flow implementation.

        This method is compatible with httpx2.Auth interface and automatically
        adds the Bearer token to requests.
        """
        # Get current access token or a new one if it has expired
        access_token = await self._get_token()

        # Add authorization header
        request.headers["Authorization"] = f"Bearer {access_token}"

        # Yield request and handle response
        response = yield request

        # If we get 401, handle auth error and retry
        if response.status_code == 401:
            logger.debug("Received 401, attempting token refresh")
            try:
                # Token invalid or missing - refresh or re-auth
                access_token = await self._renew_token()

                # Update request with new token
                request.headers["Authorization"] = f"Bearer {access_token}"

                # Retry request
                response = yield request
            except Exception as e:
                # Extract root cause from exception groups to avoid
                # "unhandled errors in a TaskGroup (1 sub-exception)" messages
                cause: BaseException = e
                while (
                    isinstance(cause, BaseExceptionGroup) and len(cause.exceptions) == 1
                ):
                    cause = cause.exceptions[0]
                logger.error(f"Token refresh and retry failed: {cause}")
                # Return original 401 response
                pass
