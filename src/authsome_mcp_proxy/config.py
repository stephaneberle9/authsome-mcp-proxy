"""Configuration models for the MCP proxy.

Two transports, two config shapes:

- ``DesktopConfig`` -- stdio mode. The proxy runs as a local process launched
  by the MCP client, performs the OAuth Authorization Code + PKCE flow
  against an external OIDC provider on behalf of the local user, caches
  tokens on disk, and forwards them as Bearer tokens to the upstream MCP
  server. No inbound auth (local trust between MCP client and proxy).

- ``WebConfig`` -- http mode. The proxy runs as a standalone HTTP server.
  Downstream MCP clients (Claude.ai, MCP Inspector, etc.) authenticate
  against the proxy; the proxy bridges that to a configured upstream IdP.
  Outbound auth to the upstream MCP server is independently configurable
  via ``outbound_auth``.

The pattern this proxy serves in web mode depends on what credential the
operator plugs in for outbound auth -- see the *MCP Server Auth Architecture
Patterns* write-up. Primary target is Pattern C (``outbound_auth='forward'``).
Pattern B.1 (tenant-scoped outbound credential) and Pattern B.2 (per-user
outbound credential) are partially supported via ``oauth-client-credentials``
and ``static`` outbound modes; mechanism is orthogonal to pattern (B.1 vs
B.2 is determined by the scope of the configured credential, not by which
mechanism is used).
"""

from dataclasses import dataclass, field
from typing import Literal, TypeAlias

AuthProvider: TypeAlias = Literal["oidc", "keycloak", "aws-cognito", "google", "azure"]
"""Inbound auth provider type for web mode.

Two distinct patterns are dispatched:

- ``keycloak`` -> FastMCP's ``KeycloakAuthProvider`` (a ``RemoteAuthProvider``).
  Modern Keycloak (>= 26.6.0) supports MCP-compatible Dynamic Client
  Registration natively, so the proxy holds no IdP credentials of its own;
  downstream MCP clients DCR directly against Keycloak. The proxy's job
  reduces to JWT verification + advertising Keycloak as the authorization
  server via OAuth 2.0 protected-resource metadata.
- ``oidc`` / ``aws-cognito`` / ``google`` / ``azure`` -> DCR-bridge style
  (``OIDCProxy`` or one of its IdP-specific subclasses). The proxy holds a
  pre-registered static ``client_id`` / ``client_secret`` with the IdP and
  bridges downstream MCP clients' DCR requests to the IdP's static-client
  model. Use ``oidc`` as a fallback for older Keycloak or any generic OIDC
  IdP.
"""

OutboundAuthMode: TypeAlias = Literal["forward", "oauth-client-credentials", "static"]
"""Outbound auth mechanism the proxy uses when calling the upstream MCP.

- ``forward`` -- reuse the downstream session's bearer token (Pattern C).
- ``oauth-client-credentials`` -- proxy obtains its own token via OAuth
  client-credentials grant against an outbound token endpoint independent
  of the inbound IdP.
- ``static`` -- proxy injects a configured literal header value. Covers API
  keys, API tokens, and personal access tokens (PATs) uniformly -- same wire
  shape under different upstream vocabularies.
"""

StoreBackend: TypeAlias = Literal["file", "dynamodb"]
"""Where the OAuth proxy keeps its state in web mode.

- ``file`` -- FastMCP's own encrypted file store under ``${FASTMCP_HOME}``.
  Durable on a VM disk or a mounted volume, lost with a container filesystem.
- ``dynamodb`` -- an AWS DynamoDB table, shared by every replica and surviving
  any restart. Needs the ``dynamodb`` extra.
"""


@dataclass
class DesktopConfig:
    """Configuration for stdio (desktop) transport.

    Attributes:
        issuer_url: OIDC issuer URL (e.g.
            ``https://keycloak.example.com/realms/myrealm``).
        client_id: OAuth client identifier.
        client_secret: OAuth client secret. Optional for public OIDC clients
            that don't require one.
        scopes: Space-separated OAuth scopes (e.g. ``"openid profile email"``).
        redirect_url: Localhost callback URL for the OAuth redirect.
    """

    issuer_url: str
    client_id: str
    client_secret: str | None = None
    scopes: str | None = None
    redirect_url: str | None = None


@dataclass
class WebConfig:
    """Configuration for http (web connector) transport.

    Inbound (downstream MCP client -> proxy):
        inbound_auth_provider: Which inbound auth provider to use.
        proxy_base_url: Publicly reachable URL of the proxy (e.g.
            ``https://mcp.example.com``). Used by every provider to advertise
            its authorization/token/JWKS endpoints to downstream MCP clients
            via the OAuth 2.0 protected-resource metadata document. This is the
            canonical identity: it also answers requests that carry no ``Host``
            header or an unrecognized one, such as Kubernetes probes hitting
            the pod IP.
        additional_proxy_base_urls: Further public URLs the same proxy answers
            under, each as its own OAuth identity. A provider's ``base_url``
            reaches into the advertised resource, the authorization-server
            metadata, the IdP ``redirect_uri`` and the minted tokens' ``iss``/
            ``aud``, and FastMCP never derives it from the request -- so a
            second hostname needs a second provider, not merely a second entry
            on the load balancer. One app is built per base URL and requests
            are dispatched between them on the ``Host`` header (see
            :mod:`authsome_mcp_proxy.host_router`). Every entry's
            ``{base_url}/auth/callback`` must be registered as a redirect URI
            with the IdP. Empty by default -- single-hostname deployments are
            unaffected.
        client_id: OAuth client ID. Required for ``oidc``, ``aws-cognito``,
            ``google``, ``azure``. Unused for ``keycloak`` (DCR-direct).
        client_secret: OAuth client secret. Required for ``aws-cognito``;
            optional for ``oidc`` / ``google`` / ``azure``; unused for
            ``keycloak``.
        scopes: Space-separated OAuth scopes for the inbound flow. Required
            for ``azure`` (FastMCP's ``AzureProvider`` requires
            ``required_scopes``).
        enable_cimd: Accept OAuth Client ID Metadata Documents from downstream
            MCP clients (``draft-ietf-oauth-client-id-metadata-document``,
            adopted into MCP as SEP-991). A CIMD client uses an HTTPS URL as
            its ``client_id``; the proxy fetches the client's metadata from
            that URL instead of the client registering via DCR, which gives
            the client one durable identity that also survives a proxy
            restart. Purely additive: DCR stays enabled either way, so
            existing clients are unaffected. Defaults to ``True``, matching
            FastMCP's own default. Two caveats: the proxy must be able to
            reach arbitrary client domains over HTTPS for the document fetch
            (a restrictive egress policy breaks CIMD), and the setting is
            inert for ``keycloak``, where Keycloak -- not the proxy -- is the
            authorization server that would have to support CIMD.
        issuer_url: For ``oidc`` and ``keycloak``: the issuer URL of the
            IdP / Keycloak realm (e.g.
            ``https://keycloak.example.com/realms/myrealm``). For ``oidc``,
            the OIDC discovery URL is derived as
            ``{issuer_url}/.well-known/openid-configuration``. Required for
            both ``oidc`` and ``keycloak``.
        audience: Optional JWT ``aud`` claim to require. Used by ``oidc``
            and ``keycloak``. Recommended for production deployments.
        cognito_user_pool_id: AWS Cognito user pool ID -- required for ``aws-cognito``.
        cognito_aws_region: AWS region for the Cognito user pool -- required
            for ``aws-cognito``.
        azure_tenant_id: Azure AD tenant ID -- required for ``azure``.
        azure_identifier_uri: Azure Application ID URI used for scope
            prefixing. Optional for ``azure``.

    OAuth proxy state (``oidc`` / ``aws-cognito`` / ``google`` / ``azure``;
    inert for ``keycloak``, where Keycloak is the authorization server and the
    proxy keeps no OAuth state):
        jwt_signing_key: Secret the proxy signs the tokens it issues to MCP
            clients with, and from which the store's encryption key is
            derived. Unset, FastMCP derives both from ``client_secret``, so a
            rotation of the upstream client secret invalidates every issued
            token and makes the stored state unreadable. Required with any
            ``store_backend`` other than ``file``.
        store_backend: Where the proxy keeps client registrations, the upstream
            IdP's tokens and the mapping from its own tokens to them. See
            :data:`StoreBackend`.
        store_dynamodb_table: DynamoDB table name -- required for
            ``store_backend='dynamodb'``.
        store_dynamodb_region: AWS region of the table. Optional; unset, the
            AWS SDK's default resolution (``AWS_REGION``, profile, instance
            metadata) applies.
        store_dynamodb_auto_create: Create the table at startup when it is
            missing. Off by default, so the proxy needs no
            ``dynamodb:CreateTable`` permission and a missing table fails at
            startup instead of being created with defaults nobody chose.

    Outbound (proxy -> upstream MCP server):
        outbound_auth: Outbound auth mechanism.
        outbound_client_id: OAuth client ID -- required for
            ``oauth-client-credentials``.
        outbound_client_secret: OAuth client secret -- required for
            ``oauth-client-credentials``.
        outbound_token_url: Token endpoint for the client-credentials grant
            -- required for ``oauth-client-credentials``. Independent of the
            inbound IdP: in Pattern B the upstream's auth mechanism is by
            definition disconnected from the IdP that fronts the proxy.
        outbound_header_name: Header name for ``static`` mode. Defaults to
            ``Authorization``.
        outbound_header_value: Literal header value for ``static`` mode
            -- required for ``static``. E.g. ``"Bearer eyJ..."`` for a bearer
            token, or a bare API key paired with
            ``outbound_header_name="X-API-Key"``.

    Server identity (advertised to downstream MCP clients):
        In stdio mode the proxy connects once at startup and relays the
        upstream's ``serverInfo`` so the proxy appears transparent. In web
        mode that startup relay isn't always possible (``outbound_auth=
        'forward'`` has no inbound session yet) so these fields let the
        operator hard-code what downstream clients should see. Each maps
        directly to the matching ``create_proxy()`` kwarg.

        proxy_name: Display name (e.g. ``"ANALYZE"``). Without this, the
            proxy falls back to FastMCP's auto-generated ``FastMCPProxy-xxxx``.
        proxy_version: Display version string.
        proxy_instructions: Instructions the LLM sees alongside the
            tool catalog -- influences tool selection.
        proxy_website_url: Project URL shown in client UIs.
    """

    inbound_auth_provider: AuthProvider
    proxy_base_url: str
    additional_proxy_base_urls: list[str] = field(default_factory=list)
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = None
    enable_cimd: bool = True

    # oidc / keycloak
    issuer_url: str | None = None
    audience: str | None = None

    # aws-cognito
    cognito_user_pool_id: str | None = None
    cognito_aws_region: str | None = None

    # azure
    azure_tenant_id: str | None = None
    azure_identifier_uri: str | None = None

    # OAuth proxy state
    jwt_signing_key: str | None = None
    store_backend: StoreBackend = "file"
    store_dynamodb_table: str | None = None
    store_dynamodb_region: str | None = None
    store_dynamodb_auto_create: bool = False

    # outbound
    outbound_auth: OutboundAuthMode = "forward"
    outbound_client_id: str | None = None
    outbound_client_secret: str | None = None
    outbound_token_url: str | None = None
    outbound_header_name: str = "Authorization"
    outbound_header_value: str | None = None

    # server identity advertised to downstream MCP clients
    proxy_name: str | None = None
    proxy_version: str | None = None
    proxy_instructions: str | None = None
    proxy_website_url: str | None = None

    def __post_init__(self) -> None:
        self._validate_base_urls()
        self._validate_inbound()
        self._validate_store()
        self._validate_outbound()

    @property
    def all_proxy_base_urls(self) -> list[str]:
        """Every public base URL this proxy answers under, canonical first."""
        return [self.proxy_base_url, *self.additional_proxy_base_urls]

    def _validate_base_urls(self) -> None:
        """Reject base URL sets the ``Host`` header could not tell apart.

        Duplicate hostnames are caught here rather than at startup so the
        failure names the config that caused it. ``host_of`` also rejects a
        value that isn't a URL at all (e.g. a bare hostname), which would
        otherwise surface much later as an unroutable identity.
        """
        from .host_router import host_of

        seen: dict[str, str] = {}
        for base_url in self.all_proxy_base_urls:
            host = host_of(base_url)
            if host in seen:
                raise ValueError(
                    f"base URLs {seen[host]!r} and {base_url!r} share the hostname "
                    f"{host!r}; the Host header cannot distinguish them"
                )
            seen[host] = base_url

    def _validate_inbound(self) -> None:
        if self.inbound_auth_provider == "keycloak":
            if not self.issuer_url:
                raise ValueError("inbound_auth_provider='keycloak' requires issuer_url")
            # KeycloakAuthProvider is a RemoteAuthProvider: no client_id /
            # client_secret needed (the MCP client DCRs directly with Keycloak).
        elif self.inbound_auth_provider == "oidc":
            if not self.issuer_url:
                raise ValueError("inbound_auth_provider='oidc' requires issuer_url")
            if not self.client_id:
                raise ValueError("inbound_auth_provider='oidc' requires client_id")
        elif self.inbound_auth_provider == "aws-cognito":
            missing = [
                name
                for name, value in (
                    ("client_id", self.client_id),
                    ("client_secret", self.client_secret),
                    ("cognito_user_pool_id", self.cognito_user_pool_id),
                    ("cognito_aws_region", self.cognito_aws_region),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    f"inbound_auth_provider='aws-cognito' requires {', '.join(missing)}"
                )
        elif self.inbound_auth_provider == "google":
            if not self.client_id:
                raise ValueError("inbound_auth_provider='google' requires client_id")
        elif self.inbound_auth_provider == "azure":
            if not self.client_id:
                raise ValueError("inbound_auth_provider='azure' requires client_id")
            if not self.azure_tenant_id:
                raise ValueError(
                    "inbound_auth_provider='azure' requires azure_tenant_id"
                )
            if not self.scopes:
                # AzureProvider's required_scopes is a mandatory list[str].
                raise ValueError("inbound_auth_provider='azure' requires scopes")

    def _validate_store(self) -> None:
        """Refuse a store backend the proxy could not keep readable.

        Skipped for ``keycloak``, where the settings are inert, and for the
        default ``file`` store, where startup stays exactly as it was.

        The signing key is mandatory with any other backend because without it
        FastMCP derives the store's encryption key from the upstream client
        secret: the first rotation of that secret would silently turn a store
        shared by every replica into undecryptable data and sign every user out.
        Failing here surfaces that at the first deployment instead.
        """
        if self.inbound_auth_provider == "keycloak" or self.store_backend == "file":
            return
        if not self.jwt_signing_key:
            raise ValueError(
                f"store_backend={self.store_backend!r} requires jwt_signing_key "
                "(JWT_SIGNING_KEY / --jwt-signing-key): without it the store's "
                "encryption key is derived from the upstream client secret, and "
                "rotating that secret would make the stored state unreadable"
            )
        if self.store_backend == "dynamodb" and not self.store_dynamodb_table:
            raise ValueError(
                "store_backend='dynamodb' requires store_dynamodb_table "
                "(STORE_DYNAMODB_TABLE / --store-dynamodb-table)"
            )

    def _validate_outbound(self) -> None:
        if self.outbound_auth == "oauth-client-credentials":
            missing = [
                name
                for name, value in (
                    ("outbound_client_id", self.outbound_client_id),
                    ("outbound_client_secret", self.outbound_client_secret),
                    ("outbound_token_url", self.outbound_token_url),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    f"outbound_auth='oauth-client-credentials' requires {', '.join(missing)}"
                )
        elif self.outbound_auth == "static":
            if not self.outbound_header_value:
                raise ValueError(
                    "outbound_auth='static' requires outbound_header_value"
                )


ProxyConfig: TypeAlias = DesktopConfig | WebConfig
"""Discriminated union of the two transport-specific config shapes.

Call sites should narrow with ``isinstance(config, DesktopConfig)`` /
``isinstance(config, WebConfig)`` before reading transport-specific fields.
"""
