"""Inbound auth provider factory for the web (HTTP) transport.

This module dispatches ``WebConfig.inbound_auth_provider`` to the matching FastMCP
auth provider class. The proxy itself stays IdP-agnostic -- per-IdP quirks
(Cognito's ``client_id`` claim validation, Azure's scope prefixing, Google's
opaque-token handling, Keycloak's native DCR support, etc.) live inside
the FastMCP provider classes.

Two patterns are dispatched here:

- ``keycloak`` uses ``KeycloakAuthProvider`` (a ``RemoteAuthProvider``):
  modern Keycloak supports MCP-compatible DCR natively, so the proxy holds
  no IdP credentials and downstream MCP clients register directly with
  Keycloak. Lean, but requires Keycloak >= 26.6.0.
- ``oidc`` / ``aws-cognito`` / ``google`` / ``azure`` use ``OIDCProxy`` (or
  one of its IdP-specific subclasses) in DCR-bridge mode: the proxy holds a
  pre-registered static client with the IdP and bridges downstream MCP
  clients' DCR requests to that IdP's static-client model. Use ``oidc`` as
  the generic fallback for any OIDC IdP that doesn't support DCR natively
  (including older Keycloak).

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

To add a new IdP:

1. Add a literal to ``AuthProvider`` in :mod:`authsome_mcp_proxy.config`.
2. Add the per-provider required fields to ``WebConfig`` and its
   ``__post_init__`` validation.
3. Add a branch to :func:`build_inbound_auth`.
4. Document required params and add a working example to the README.

Store backends live in fastmcp-seaworthy. Exposing a new one here takes its
``--store-*`` flags in :mod:`authsome_mcp_proxy.__main__`, its fields on
``WebConfig`` and their mapping in ``WebConfig.oauth_state``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastmcp.server.auth.auth import AuthProvider as FastMCPAuthProvider
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.aws import AWSCognitoProvider
from fastmcp.server.auth.providers.azure import AzureProvider
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.auth.providers.keycloak import KeycloakAuthProvider

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
) -> FastMCPAuthProvider:
    """Instantiate the FastMCP auth provider matching ``config.inbound_auth_provider``.

    The returned provider is passed to FastMCP via the ``auth=`` argument
    on the server. For DCR-bridge providers (``oidc``/``aws-cognito``/
    ``google``/``azure``) it bridges downstream MCP clients' DCR requests
    to the IdP's static-client model. For ``keycloak`` it sets up token
    verification + protected-resource-metadata advertising and relies on
    Keycloak's own DCR.

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
        # RemoteAuthProvider: no client_id/secret; MCP client DCRs with Keycloak.
        assert config.issuer_url is not None
        return KeycloakAuthProvider(
            realm_url=config.issuer_url,
            base_url=base_url,
            required_scopes=scopes,
            audience=config.audience,
        )

    if config.inbound_auth_provider == "oidc":
        # DCR-bridge generic OIDC: derive the discovery URL from the issuer.
        # Use this for older Keycloak versions and any non-DCR OIDC IdP.
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

    raise ValueError(
        f"Unknown inbound_auth_provider {config.inbound_auth_provider!r}; supported: "
        "oidc, keycloak, aws-cognito, google, azure"
    )
