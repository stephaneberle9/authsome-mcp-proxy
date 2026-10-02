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

A ``WebConfig`` fronts either one upstream MCP server, served at ``/mcp``, or
several, each described by an ``UpstreamRoute`` and served at ``/<name>/mcp``
behind one shared OAuth identity (see :mod:`authsome_mcp_proxy.path_router`).

The pattern this proxy serves in web mode depends on what credential the
operator plugs in for outbound auth -- see the *MCP Server Auth Architecture
Patterns* write-up. Primary target is Pattern C (``outbound_auth='forward'``).
Pattern B.1 (tenant-scoped outbound credential) and Pattern B.2 (per-user
outbound credential) are partially supported via ``oauth-client-credentials``
and ``static`` outbound modes; mechanism is orthogonal to pattern (B.1 vs
B.2 is determined by the scope of the configured credential, not by which
mechanism is used).
"""

import re
from dataclasses import dataclass, field
from typing import Literal, TypeAlias, get_args

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

OutboundAuthMode: TypeAlias = Literal[
    "forward", "none", "oauth-client-credentials", "static"
]
"""Outbound auth mechanism the proxy uses when calling the upstream MCP.

- ``forward`` -- reuse the downstream session's bearer token (Pattern C).
- ``none`` -- send no credential at all, for an upstream that validates none,
  such as a read-only knowledge server. The user's token is withheld rather
  than handed to a server that has no use for it.
- ``oauth-client-credentials`` -- proxy obtains its own token via OAuth
  client-credentials grant against an outbound token endpoint independent
  of the inbound IdP.
- ``static`` -- proxy injects a configured literal header value. Covers API
  keys, API tokens, and personal access tokens (PATs) uniformly -- same wire
  shape under different upstream vocabularies.
"""

OUTBOUND_AUTH_MODES: tuple[OutboundAuthMode, ...] = get_args(OutboundAuthMode)

_ROUTE_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")


def _validate_outbound_settings(
    outbound_auth: str,
    *,
    client_id: str | None,
    client_secret: str | None,
    token_url: str | None,
    header_value: str | None,
    context: str = "",
) -> None:
    """Check that an outbound mode is known and has the fields it needs.

    Shared by ``WebConfig`` and ``UpstreamRoute``; ``context`` prefixes the
    message so that a route's error names the route.
    """
    if outbound_auth not in OUTBOUND_AUTH_MODES:
        raise ValueError(
            f"{context}outbound_auth must be one of {', '.join(OUTBOUND_AUTH_MODES)}"
            f" -- got {outbound_auth!r}"
        )
    if outbound_auth == "oauth-client-credentials":
        missing = [
            name
            for name, value in (
                ("outbound_client_id", client_id),
                ("outbound_client_secret", client_secret),
                ("outbound_token_url", token_url),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"{context}outbound_auth='oauth-client-credentials' requires "
                f"{', '.join(missing)}"
            )
    elif outbound_auth == "static":
        if not header_value:
            raise ValueError(
                f"{context}outbound_auth='static' requires outbound_header_value"
            )


@dataclass
class UpstreamRoute:
    """One of several upstream MCP servers a web-mode proxy fronts.

    The route is served at ``/<name>/mcp`` with its own protected-resource
    metadata at ``/.well-known/oauth-protected-resource/<name>/mcp``, and
    shares the proxy's OAuth identity with every other route: one sign-in
    covers them all.

    Every field after ``mcp_url`` means the same as its namesake on
    ``WebConfig`` but applies to this route only. The values are final:
    falling back to the global setting for whatever was left unset is the job
    of whoever builds the route -- the CLI does it for the
    ``UPSTREAM_<NAME>_*`` environment variables.

    Attributes:
        name: Route name, also the first path segment. Lower-case letters,
            digits and ``-``, starting with a letter or digit.
        mcp_url: URL of the upstream MCP server.
    """

    name: str
    mcp_url: str
    outbound_auth: OutboundAuthMode = "forward"
    outbound_client_id: str | None = None
    outbound_client_secret: str | None = None
    outbound_token_url: str | None = None
    outbound_header_name: str = "Authorization"
    outbound_header_value: str | None = None

    proxy_name: str | None = None
    proxy_version: str | None = None
    proxy_instructions: str | None = None
    proxy_website_url: str | None = None

    def __post_init__(self) -> None:
        if not _ROUTE_NAME.fullmatch(self.name):
            raise ValueError(
                f"upstream name {self.name!r} must match {_ROUTE_NAME.pattern!r}: "
                "it becomes a path segment and part of environment variable names"
            )
        if not self.mcp_url:
            raise ValueError(f"upstream {self.name!r} requires mcp_url")
        _validate_outbound_settings(
            self.outbound_auth,
            client_id=self.outbound_client_id,
            client_secret=self.outbound_client_secret,
            token_url=self.outbound_token_url,
            header_value=self.outbound_header_value,
            context=f"upstream {self.name!r}: ",
        )

    @property
    def path(self) -> str:
        """The path this route's MCP endpoint is served at."""
        return f"/{self.name}/mcp"


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

    Several upstreams (web mode only):
        upstreams: Upstream MCP servers to serve side by side, each at
            ``/<name>/mcp`` and each with its own outbound auth and advertised
            identity. Empty by default: the proxy then fronts the single
            upstream URL it is started with, at ``/mcp``, using the outbound
            and identity fields above. When set, those fields are not used
            directly -- every route carries its own -- and no single upstream
            URL may be given. All routes share one OAuth identity per public
            hostname; see :mod:`authsome_mcp_proxy.path_router`.
        default_upstream: Name of the route that is additionally served at
            ``/mcp`` with its protected-resource metadata at
            ``/.well-known/oauth-protected-resource/mcp``, so clients of a
            former single-upstream deployment keep working. Optional.
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

    upstreams: list[UpstreamRoute] = field(default_factory=list)
    default_upstream: str | None = None

    def __post_init__(self) -> None:
        self._validate_base_urls()
        self._validate_inbound()
        self._validate_upstreams()
        if not self.upstreams:
            # With several upstreams each route validates its own settings;
            # the top-level ones are unused and may be incomplete.
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

    def _validate_upstreams(self) -> None:
        names = [route.name for route in self.upstreams]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(
                f"upstream names must be unique; duplicated: {', '.join(duplicates)}"
            )
        if self.default_upstream is not None and self.default_upstream not in names:
            if not names:
                raise ValueError(
                    "default_upstream requires upstreams: it names the one of "
                    "several upstreams that is also served at /mcp"
                )
            raise ValueError(
                f"default_upstream {self.default_upstream!r} is not among the "
                f"upstreams {names!r}"
            )

    def _validate_outbound(self) -> None:
        _validate_outbound_settings(
            self.outbound_auth,
            client_id=self.outbound_client_id,
            client_secret=self.outbound_client_secret,
            token_url=self.outbound_token_url,
            header_value=self.outbound_header_value,
        )


ProxyConfig: TypeAlias = DesktopConfig | WebConfig
"""Discriminated union of the two transport-specific config shapes.

Call sites should narrow with ``isinstance(config, DesktopConfig)`` /
``isinstance(config, WebConfig)`` before reading transport-specific fields.
"""
