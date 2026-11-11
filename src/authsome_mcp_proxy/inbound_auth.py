"""Inbound auth provider factory for web mode (http transport).

This module dispatches ``WebConfig.inbound_auth_provider`` to the matching FastMCP
auth provider class. The proxy itself stays IdP-agnostic -- per-IdP quirks
(Cognito's ``client_id`` claim validation, Azure's scope prefixing, Google's
opaque-token handling, Keycloak's native DCR support, etc.) live inside
the FastMCP provider classes -- or, for ZITADEL, in the provider vendored from
FastMCP in :mod:`authsome_mcp_proxy.zitadel_provider` until a FastMCP release
ships it.

The provider decides which of two roles the proxy takes:

- **IdP as authorization server**: ``keycloak`` uses
  ``KeycloakAuthProvider`` (a ``RemoteAuthProvider``). Keycloak lets MCP
  clients register with it directly, so the proxy holds no IdP credentials
  and downstream MCP clients register and sign in at Keycloak. Lean, but
  requires Keycloak >= 26.6.0.
- **Proxy as authorization server**: ``oidc`` / ``aws-cognito`` /
  ``google`` / ``azure`` / ``zitadel`` use ``OIDCProxy`` (or one of its
  IdP-specific subclasses). The proxy holds a pre-registered static client
  with the IdP and is itself the authorization server for downstream MCP
  clients, which identify themselves to it by Client ID Metadata Document
  or Dynamic Client Registration. Use ``oidc`` as the generic fallback for
  any OIDC IdP that MCP clients cannot register with themselves (including
  older Keycloak).

``WebConfig.enable_cimd`` rides along on the ``OIDCProxy`` branches: FastMCP's
``OAuthProxy`` implements CIMD (Client ID Metadata Documents) itself, so the
proxy only has to forward the switch. It is inert for ``keycloak`` -- there
Keycloak is the authorization server, so whether a downstream client may
identify itself by URL is Keycloak's decision, not this proxy's.

``WebConfig.jwt_signing_key`` and the store backend ride along the same way:
the ``OIDCProxy`` branches keep their OAuth state (client registrations, the
upstream IdP's tokens, the mapping from the proxy's own tokens to them) in a
key-value store. ``WebConfig.oauth_state`` turns the settings into
fastmcp-seaworthy's ``OAuthStateSettings``; its ``build_client_storage`` builds
the store and ``provider_kwargs`` hands both to the provider.

The ``google`` and ``zitadel`` branches also take a shared HTTP client. Both
IdPs issue opaque access tokens (ZITADEL by default), so every inbound request
is verified with a call to the IdP -- Google's token info endpoint, ZITADEL's
token introspection endpoint. Without a shared client, each of those calls
opens and closes its own connection. The caller owns the client and closes it
when serving stops.

To add a new IdP:

1. Add a literal to ``AuthProvider`` in :mod:`authsome_mcp_proxy.config`.
2. Add the per-provider required fields to ``WebConfig`` and its
   ``__post_init__`` validation.
3. Add a branch to :func:`build_inbound_auth`.
4. Document required params and add a working example to the README.

The client allowlist (``WebConfig.client_allowlist``) is not applied here but
by the caller, :func:`authsome_mcp_proxy.mcp_proxy._serve_http`, on each
provider this function returns: it wraps a built provider rather than
configuring its construction.

Store backends live in fastmcp-seaworthy. Exposing a new one here takes its
``--store-*`` flags in :mod:`authsome_mcp_proxy.__main__`, its fields on
``WebConfig`` and their mapping in ``WebConfig.oauth_state``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx2
from fastmcp.server.auth.auth import AuthProvider as FastMCPAuthProvider
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.aws import AWSCognitoProvider
from fastmcp.server.auth.providers.azure import AzureProvider
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.auth.providers.keycloak import KeycloakAuthProvider

from .zitadel_provider import ZitadelProvider

if TYPE_CHECKING:
    from fastmcp_seaworthy import ClientStorage

    from .config import WebConfig


def _parse_scopes(scopes: str | None) -> list[str] | None:
    if not scopes:
        return None
    return scopes.split()


def build_inbound_auth(
    config: WebConfig,
    base_url: str | None = None,
    client_storage: ClientStorage | None = None,
    http_client: httpx2.AsyncClient | None = None,
) -> FastMCPAuthProvider:
    """Instantiate the FastMCP auth provider matching ``config.inbound_auth_provider``.

    The returned provider is passed to FastMCP via the ``auth=`` argument
    on the server. For ``oidc``/``aws-cognito``/``google``/``azure``/
    ``zitadel`` it is the authorization server downstream MCP clients register
    and sign in at, backed by the proxy's one static client at the IdP. For
    ``keycloak`` it sets up token verification + protected-resource-metadata
    advertising and leaves registration and sign-in to Keycloak.

    Args:
        config: Web-mode configuration. ``WebConfig.__post_init__`` has
            already validated that all required per-provider fields are
            populated.
        base_url: Which of the configured public base URLs this provider
            should advertise as. Defaults to ``config.proxy_base_url``.
            Multi-hostname deployments call this once per entry in
            ``config.all_proxy_base_urls``, because a provider's base URL is
            baked in at construction and reaches everything the provider
            advertises -- see :mod:`fastmcp_seaworthy.host_router`.
        client_storage: The store from fastmcp-seaworthy's
            ``build_client_storage(config.oauth_state)``, or
            ``None`` for FastMCP's default file store. Multi-hostname
            deployments pass the same instance for every base URL. Ignored for
            ``keycloak``.
        http_client: A shared client for the per-request token verification
            calls to the IdP, so they reuse connections, or ``None`` for a new
            client per call. The caller closes it. Used only by ``google`` and
            ``zitadel``.

    Returns:
        A FastMCP ``AuthProvider`` subclass instance.

    Raises:
        ValueError: If ``config.inbound_auth_provider`` is unknown.
    """
    scopes = _parse_scopes(config.scopes)
    base_url = base_url if base_url is not None else config.proxy_base_url
    # Empty for keycloak, which takes neither keyword: config.oauth_state is
    # None there, as the proxy issues no tokens and keeps no OAuth state.
    settings = config.oauth_state
    oauth_state: dict[str, Any] = (
        settings.provider_kwargs(client_storage) if settings is not None else {}
    )

    if config.inbound_auth_provider == "keycloak":
        # RemoteAuthProvider: no client_id/secret; MCP clients register with Keycloak.
        assert config.issuer_url is not None
        return KeycloakAuthProvider(
            realm_url=config.issuer_url,
            base_url=base_url,
            required_scopes=scopes,
            audience=config.audience,
        )

    if config.inbound_auth_provider == "oidc":
        # Generic OIDC: derive the discovery URL from the issuer. Use this
        # for older Keycloak versions and any OIDC IdP that MCP clients cannot
        # register with themselves.
        assert config.issuer_url is not None
        assert config.client_id is not None
        config_url = f"{config.issuer_url.rstrip('/')}/.well-known/openid-configuration"
        return OIDCProxy(
            config_url=config_url,
            client_id=config.client_id,
            client_secret=config.client_secret,
            audience=config.audience,
            required_scopes=scopes,
            base_url=base_url,
            enable_cimd=config.enable_cimd,
            **oauth_state,
        )

    if config.inbound_auth_provider == "aws-cognito":
        assert config.client_id is not None
        assert config.client_secret is not None
        assert config.cognito_user_pool_id is not None
        assert config.cognito_aws_region is not None
        return AWSCognitoProvider(
            user_pool_id=config.cognito_user_pool_id,
            aws_region=config.cognito_aws_region,
            client_id=config.client_id,
            client_secret=config.client_secret,
            required_scopes=scopes,
            base_url=base_url,
            enable_cimd=config.enable_cimd,
            **oauth_state,
        )

    if config.inbound_auth_provider == "google":
        assert config.client_id is not None
        return GoogleProvider(
            client_id=config.client_id,
            client_secret=config.client_secret,
            required_scopes=scopes,
            base_url=base_url,
            enable_cimd=config.enable_cimd,
            http_client=http_client,
            **oauth_state,
        )

    if config.inbound_auth_provider == "azure":
        assert config.client_id is not None
        assert config.azure_tenant_id is not None
        assert scopes is not None
        return AzureProvider(
            client_id=config.client_id,
            client_secret=config.client_secret,
            tenant_id=config.azure_tenant_id,
            identifier_uri=config.azure_identifier_uri,
            required_scopes=scopes,
            base_url=base_url,
            enable_cimd=config.enable_cimd,
            **oauth_state,
        )

    if config.inbound_auth_provider == "zitadel":
        assert config.zitadel_domain is not None
        assert config.client_id is not None
        assert config.client_secret is not None
        return ZitadelProvider(
            domain=config.zitadel_domain,
            client_id=config.client_id,
            client_secret=config.client_secret,
            required_scopes=scopes,
            base_url=base_url,
            enable_cimd=config.enable_cimd,
            http_client=http_client,
            **oauth_state,
        )

    raise ValueError(
        f"Unknown inbound_auth_provider {config.inbound_auth_provider!r}; supported: "
        "oidc, keycloak, aws-cognito, google, azure, zitadel"
    )
