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
key-value store, and :func:`build_client_storage` builds the one handed to them
when the operator selects something other than FastMCP's default file store.

To add a new IdP:

1. Add a literal to ``AuthProvider`` in :mod:`authsome_mcp_proxy.config`.
2. Add the per-provider required fields to ``WebConfig`` and its
   ``__post_init__`` validation.
3. Add a branch to :func:`build_inbound_auth`.
4. Document required params and add a working example to the README.

To add a new store backend:

1. Add a literal to ``StoreBackend`` in :mod:`authsome_mcp_proxy.config`, its
   settings to ``WebConfig`` and their validation to ``_validate_store``.
2. Add an extra for its dependencies to ``pyproject.toml``.
3. Add a factory to ``_STORE_BACKENDS`` that imports the store class lazily.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import version
from typing import TYPE_CHECKING, Any

from cryptography.fernet import Fernet
from fastmcp.server.auth.auth import AuthProvider as FastMCPAuthProvider
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.aws import AWSCognitoProvider
from fastmcp.server.auth.providers.azure import AzureProvider
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.auth.providers.keycloak import KeycloakAuthProvider
from key_value.aio.errors import StoreSetupError
from key_value.aio.protocols.key_value import AsyncKeyValue
from key_value.aio.stores.base import BaseContextManagerStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

if TYPE_CHECKING:
    from .config import WebConfig


@dataclass
class ClientStorage:
    """An external store backend for the OAuth proxy's state, encrypted.

    Attributes:
        store: What the providers are handed as ``client_storage`` -- the
            backend behind the encryption wrapper.
        backend: The backend itself, kept for its lifecycle: the wrapper
            forwards reads and writes but not ``setup()`` or ``close()``.
        description: Names the backend's location in startup errors, e.g. the
            DynamoDB table and the setting that selects it.
    """

    store: AsyncKeyValue
    backend: BaseContextManagerStore
    description: str

    async def open(self) -> None:
        """Connect to the backend, so a backend the proxy cannot use fails at startup.

        Every store connects lazily on first use, which would be the first
        user's sign-in. A missing DynamoDB table, a wrong region or missing
        credentials would then surface as a failed request long after the
        deployment looked healthy.

        Raises:
            ValueError: Naming the backend's location, when setup fails.
        """
        try:
            await self.backend.setup()
        except StoreSetupError as e:
            await self.backend.close()
            cause = e.__cause__ or e
            raise ValueError(f"Cannot use {self.description}: {cause}") from e

    async def close(self) -> None:
        await self.backend.close()


def _dynamodb_backend(config: WebConfig) -> tuple[BaseContextManagerStore, str]:
    # Imported here, not at module level: the extra is optional, and a
    # deployment on the default file store must not need -- or load -- the AWS
    # SDK.
    try:
        from key_value.aio.stores.dynamodb import DynamoDBStore
    except ImportError as e:
        raise RuntimeError(
            "store_backend='dynamodb' needs the 'dynamodb' extra: install "
            "authsome-mcp-proxy[dynamodb]"
        ) from e

    assert config.store_dynamodb_table is not None
    with warnings.catch_warnings():
        # py-key-value-aio warns on every construction that the store's Python
        # API may still change. That is addressed to whoever calls the
        # constructor -- this function, whose range fastmcp's own <0.5 pin
        # bounds -- not to the operator reading the startup log.
        warnings.filterwarnings(
            "ignore", message="A configured store is unstable", category=UserWarning
        )
        store = DynamoDBStore(
            table_name=config.store_dynamodb_table,
            region_name=config.store_dynamodb_region,
            auto_create=config.store_dynamodb_auto_create,
        )
    return (
        store,
        f"DynamoDB table {config.store_dynamodb_table!r} (STORE_DYNAMODB_TABLE)",
    )


_STORE_BACKENDS: dict[
    str, Callable[[WebConfig], tuple[BaseContextManagerStore, str]]
] = {
    "dynamodb": _dynamodb_backend,
}
"""Store backend name -> factory returning the store and where it lives.

The stores themselves are py-key-value-aio's; a backend here is only the
mapping from this proxy's settings to a store class's constructor.
"""


def _storage_encryption_key(jwt_signing_key: str) -> bytes:
    """Derive the store's Fernet key from the signing key, exactly as FastMCP does.

    ``OAuthProxy`` stretches a string signing key with PBKDF2 and then derives
    its default file store's key from the result with HKDF under this salt.
    Repeating both steps keeps an operator-chosen, possibly low-entropy key as
    hard to brute-force from a leaked store as from a leaked token.
    """
    signing_key = derive_jwt_key(
        low_entropy_material=jwt_signing_key, salt="fastmcp-jwt-signing-key"
    )
    return derive_jwt_key(
        high_entropy_material=signing_key.decode(),
        salt="fastmcp-storage-encryption-key",
    )


def build_client_storage(config: WebConfig) -> ClientStorage | None:
    """Build the store selected by ``config.store_backend``, or ``None`` for the default.

    ``None`` leaves FastMCP's own encrypted file store in place and imports no
    backend dependency. It is also what ``keycloak`` gets, whatever is set:
    there Keycloak is the authorization server and the proxy keeps no OAuth
    state.

    The caller builds this once and hands the same instance to the provider of
    every hostname, then calls :meth:`ClientStorage.open` before serving.

    Raises:
        ValueError: If ``config.store_backend`` is unknown.
        RuntimeError: If the backend's extra is not installed.
    """
    if config.inbound_auth_provider == "keycloak" or config.store_backend == "file":
        return None
    factory = _STORE_BACKENDS.get(config.store_backend)
    if factory is None:
        raise ValueError(
            f"Unknown store_backend {config.store_backend!r}; supported: file, "
            f"{', '.join(_STORE_BACKENDS)}"
        )
    backend, description = factory(config)
    assert config.jwt_signing_key is not None  # WebConfig._validate_store
    # FastMCP encrypts only the file store it builds itself; a store passed in
    # as client_storage is used as given. That store holds the upstream IdP's
    # access and refresh tokens, so an external one is wrapped the same way the
    # default is. raise_on_decryption_error=False matches FastMCP too: an entry
    # written under another key reads as missing -- the client re-registers or
    # the user signs in again -- instead of failing every request that touches
    # it.
    store = FernetEncryptionWrapper(
        key_value=backend,
        fernet=Fernet(key=_storage_encryption_key(config.jwt_signing_key)),
        raise_on_decryption_error=False,
    )
    return ClientStorage(store=store, backend=backend, description=description)


def _oauth_state_kwargs(
    config: WebConfig, client_storage: ClientStorage | None
) -> dict[str, Any]:
    """Keyword arguments carrying the signing key and store to an ``OIDCProxy``.

    Only what is set is passed, so a deployment that configures neither builds
    its provider exactly as before and FastMCP's defaults apply.
    """
    kwargs: dict[str, Any] = {}
    if config.jwt_signing_key:
        kwargs["jwt_signing_key"] = config.jwt_signing_key
    if client_storage is not None:
        kwargs["client_storage"] = client_storage.store
    return kwargs


def _parse_scopes(scopes: str | None) -> list[str] | None:
    if not scopes:
        return None
    return scopes.split()


def _disable_cimd(provider: FastMCPAuthProvider) -> None:
    """Turn CIMD off on an already-constructed provider.

    Every other ``OIDCProxy`` subclass takes an ``enable_cimd`` keyword and
    forwards it; ``AWSCognitoProvider`` is the one that doesn't in any stable
    release up to 3.4.7, so for Cognito the manager has to be dropped after
    construction instead. ``OAuthProxy`` gates both CIMD client lookup and the
    ``client_id_metadata_document_supported`` advertisement on
    ``self._cimd_manager is not None``, and ``get_routes()`` runs later -- when
    the ASGI app is built -- so clearing it here is enough.

    Interim measure with a known end date: upstream added the passthrough in
    PrefectHQ/fastmcp#4719, which ships in 4.0 (present in 4.0.0b3, absent from
    every 3.x). When this project's floor reaches a stable 4.0, delete this
    helper and pass ``enable_cimd=`` to ``AWSCognitoProvider`` like the other
    three providers. Until then it stays correct on both lines: 4.0 keeps
    ``_cimd_manager`` where it is.
    """
    if not hasattr(provider, "_cimd_manager"):
        raise RuntimeError(
            f"Cannot disable CIMD on {type(provider).__name__}: fastmcp "
            f"{version('fastmcp')} no longer exposes _cimd_manager. Pass "
            "enable_cimd to the provider constructor instead and delete this "
            "workaround."
        )
    provider._cimd_manager = None  # ty: ignore[invalid-assignment]


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
            advertises -- see :mod:`authsome_mcp_proxy.host_router`.
        client_storage: The store from :func:`build_client_storage`, or
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
    # Not for keycloak, which takes neither keyword: there the proxy issues no
    # tokens and keeps no OAuth state.
    oauth_state = _oauth_state_kwargs(config, client_storage)

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
        provider = AWSCognitoProvider(
            user_pool_id=config.cognito_user_pool_id,
            aws_region=config.cognito_aws_region,
            client_id=config.client_id,
            client_secret=config.client_secret,
            required_scopes=scopes,
            base_url=base_url,
            **oauth_state,
        )
        # No enable_cimd keyword on this one -- see _disable_cimd. Enabled is
        # the inherited default, so only the off switch needs applying.
        if not config.enable_cimd:
            _disable_cimd(provider)
        return provider

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
