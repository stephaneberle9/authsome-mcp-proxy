"""
Authsome MCP Proxy - Command-line interface.

This module provides the CLI entry point for running the MCP proxy server. It:

- Parses command-line arguments and environment variables
- Builds either a ``DesktopConfig`` (stdio transport) or a ``WebConfig``
  (http transport) based on ``--transport``
- Launches the proxy server with appropriate settings
- Handles graceful shutdown and error reporting

CLI flags fall back to matching environment variables (CLI arguments take
precedence). For stdio mode the ``OIDC_*`` env vars apply; for http mode
the inbound provider params (``OIDC_*``, ``COGNITO_*``, ``AZURE_*``,
``--audience``, ``--proxy-base-url``, ``ENABLE_CIMD``) and the outbound mode
params (``OUTBOUND_*``) apply.

Several upstreams (http mode only) are named by ``UPSTREAMS`` or repeated
``--upstream NAME=URL`` flags. Their per-route settings are environment-only,
``UPSTREAM_<NAME>_<SETTING>`` with ``<NAME>`` upper-cased and ``-`` turned into
``_``; each one falls back to the matching global setting.
"""

import argparse
import asyncio
import logging
import os
import sys

import httpx2
from exceptiongroup import BaseExceptionGroup
from mcp.shared.exceptions import MCPError

from . import __version__, mcp_proxy
from .config import (
    OUTBOUND_AUTH_MODES,
    DesktopConfig,
    ProxyConfig,
    UpstreamRoute,
    WebConfig,
)

logger = logging.getLogger(__name__)


_INBOUND_AUTH_PROVIDERS = ("oidc", "keycloak", "aws-cognito", "google", "azure")

# Per-route settings of a multi-upstream deployment, as (field, suffix, global):
# read from UPSTREAM_<NAME>_<suffix>, falling back to the global setting --
# the args attribute of the same field name, set from the `global` variable or
# its flag. The field is also the UpstreamRoute field.
_ROUTE_SETTINGS = (
    ("outbound_auth", "OUTBOUND_AUTH", "OUTBOUND_AUTH"),
    ("outbound_client_id", "OUTBOUND_CLIENT_ID", "OUTBOUND_CLIENT_ID"),
    ("outbound_client_secret", "OUTBOUND_CLIENT_SECRET", "OUTBOUND_CLIENT_SECRET"),
    ("outbound_token_url", "OUTBOUND_TOKEN_URL", "OUTBOUND_TOKEN_URL"),
    ("outbound_header_name", "OUTBOUND_HEADER_NAME", "OUTBOUND_HEADER_NAME"),
    ("outbound_header_value", "OUTBOUND_HEADER_VALUE", "OUTBOUND_HEADER_VALUE"),
    ("proxy_name", "PROXY_NAME", "MCP_PROXY_NAME"),
    ("proxy_version", "PROXY_VERSION", "MCP_PROXY_VERSION"),
    ("proxy_instructions", "PROXY_INSTRUCTIONS", "MCP_PROXY_INSTRUCTIONS"),
    ("proxy_website_url", "PROXY_WEBSITE_URL", "MCP_PROXY_WEBSITE_URL"),
)

_TRUTHY = ("1", "true", "yes", "on")
_FALSY = ("0", "false", "no", "off")


def _env_flag(name: str, *, default: bool) -> bool:
    """Read a boolean environment variable, or ``default`` when it is unset.

    Unlike the plain fallback table in :func:`_apply_env_fallbacks`, this can
    tell "unset" from "set to false", which a flag defaulting to true needs.
    An unrecognized value is an error rather than a silent default: a typo, or
    a plausible-looking ``ENABLE_CIMD=enabled``, should not quietly resolve to
    whichever state the operator was trying to leave.
    """
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    raise ValueError(
        f"{name} must be one of {', '.join((*_TRUTHY, *_FALSY))} -- got {raw!r}"
    )


_ROUTE_SETTINGS_EPILOG = (
    "Several upstreams (--upstream / UPSTREAMS) take their per-upstream settings "
    "from the environment only, as UPSTREAM_<NAME>_<SETTING> with <NAME> "
    "upper-cased and '-' turned into '_'. Each is optional and falls back to the "
    "global setting named in brackets: "
    + ", ".join(
        f"UPSTREAM_<NAME>_{suffix} ({global_name})"
        for _, suffix, global_name in _ROUTE_SETTINGS
    )
    + "."
)


def _upstream_arg(raw: str) -> tuple[str, str]:
    """Parse one ``--upstream NAME=URL`` value.

    Only the shape is checked here; the name's syntax is validated with the
    rest of the configuration, so the message is the same however the route
    was configured.
    """
    name, sep, url = raw.partition("=")
    if not sep or not name.strip() or not url.strip():
        raise argparse.ArgumentTypeError(f"expected NAME=URL, got {raw!r}")
    return name.strip(), url.strip()


def _route_env_prefix(name: str) -> str:
    """The environment variable prefix of a route: ``emb3d-kb`` -> ``UPSTREAM_EMB3D_KB_``."""
    return f"UPSTREAM_{name.upper().replace('-', '_')}_"


def cli() -> argparse.Namespace:
    """
    Parse command line arguments and merge with environment variables.

    Parses CLI arguments for OIDC configuration, upstream URL, and logging options.
    Falls back to environment variables when CLI arguments are not provided, with
    CLI arguments taking precedence.

    Returns:
        Namespace: Parsed arguments with all configuration options.
    """
    parser = argparse.ArgumentParser(
        description=(
            f"Authsome MCP Proxy -- bridges upstream MCP servers protected "
            f"by token validation or static credentials to MCP clients such as "
            f"Claude Desktop, Claude Code, Cursor, Codex, MCP Inspector, "
            f"and Claude.ai (version {__version__})"
        ),
        epilog=_ROUTE_SETTINGS_EPILOG,
    )

    # Proxy server arguments
    parser.add_argument(
        "upstream_mcp_url",
        metavar="UPSTREAM_MCP_URL",
        nargs="?",
        help="URL of the upstream MCP server to be proxied "
        "(can also be set via UPSTREAM_MCP_URL env var)",
    )
    parser.add_argument(
        "--upstream",
        dest="upstreams",
        metavar="NAME=URL",
        action="append",
        type=_upstream_arg,
        default=None,
        help="Serve the upstream MCP server at URL under /NAME/mcp; repeat for "
        "several upstreams behind one OAuth identity -- http mode only. Replaces "
        "the positional UPSTREAM_MCP_URL. NAME: lower-case letters, digits and "
        "'-'. Can also be set via UPSTREAMS=NAME,NAME,... with each URL in "
        "UPSTREAM_<NAME>_MCP_URL. Per-upstream settings: see below.",
    )
    parser.add_argument(
        "--default-upstream",
        metavar="NAME",
        default=None,
        help="Also serve upstream NAME at /mcp, the path of a single-upstream "
        "deployment, so its existing clients keep working "
        "(can also be set via DEFAULT_UPSTREAM env var)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't show the proxy server banner",
    )

    # Transport options
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=None,
        help="Transport to serve on. "
        "'stdio' (default): proxy is launched as a local process by the MCP "
        "client (Claude Desktop, Claude Code via 'claude mcp add --transport stdio', "
        "Cursor, Codex, etc.). "
        "'http': proxy runs as a standalone HTTP server that clients connect to by URL "
        "(e.g. Claude Code via 'claude mcp add --transport http <name> <url>'). "
        "Can also be set via MCP_PROXY_TRANSPORT env var.",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Host address to bind to when using HTTP transport "
        "(can also be set via MCP_PROXY_HOST env var, default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to listen on when using HTTP transport "
        "(can also be set via MCP_PROXY_PORT env var, default: 8000)",
    )

    # Inbound OIDC options -- used by:
    # - stdio: the desktop OAuth client (issuer/client/scopes/redirect)
    # - http: the FastMCP inbound provider when --inbound-auth-provider is
    #   'oidc'/'keycloak' (issuer_url), or as the OAuth client_id/secret
    #   common across 'oidc'/'aws-cognito'/'google'/'azure' (unused for
    #   'keycloak' which is a RemoteAuthProvider).
    parser.add_argument(
        "--oidc-issuer-url",
        help="OIDC issuer / Keycloak realm URL "
        "(can also be set via OIDC_ISSUER_URL env var)",
    )
    parser.add_argument(
        "--oidc-client-id",
        help="OAuth client ID (can also be set via OIDC_CLIENT_ID env var)",
    )
    parser.add_argument(
        "--oidc-client-secret",
        help="OAuth client secret (can also be set via OIDC_CLIENT_SECRET env var, "
        "optional for public OIDC clients that don't require any such)",
    )
    parser.add_argument(
        "--oidc-scopes",
        help="Space-separated OAuth scopes "
        "(can also be set via OIDC_SCOPES env var, default for stdio: 'openid profile email')",
    )
    parser.add_argument(
        "--oidc-redirect-url",
        help="Localhost URL for OAuth redirect -- stdio mode only "
        "(can also be set via OIDC_REDIRECT_URL env var, "
        "default: http://localhost:8080/auth/callback)",
    )

    # Web-mode-only inbound options
    parser.add_argument(
        "--inbound-auth-provider",
        choices=list(_INBOUND_AUTH_PROVIDERS),
        default=None,
        help="Inbound auth provider for http mode. 'keycloak' uses FastMCP's "
        "KeycloakAuthProvider (RemoteAuthProvider -- Keycloak >= 26.6.0 with "
        "native DCR). 'oidc' uses OIDCProxy in DCR-bridge mode for any "
        "generic OIDC IdP (including older Keycloak). 'aws-cognito', "
        "'google', 'azure' use the matching IdP-specific FastMCP providers. "
        "Can also be set via INBOUND_AUTH_PROVIDER env var.",
    )
    parser.add_argument(
        "--proxy-base-url",
        default=None,
        help="Publicly reachable URL of the proxy -- required for http mode "
        "(can also be set via MCP_PROXY_BASE_URL env var). Used by inbound providers to "
        "advertise their authorization/token/JWKS endpoints to downstream MCP "
        "clients via OAuth 2.0 protected-resource metadata. Accepts a "
        "comma-separated list to serve several public hostnames from one "
        "process, each as its own OAuth identity, dispatched on the request's "
        "Host header; the first entry is canonical and also answers requests "
        "with no or an unrecognized Host (e.g. container health probes). Every "
        "entry's '{base_url}/auth/callback' must be registered as a redirect "
        "URI with the IdP.",
    )
    parser.add_argument(
        "--audience",
        default=None,
        help="JWT 'aud' claim to require on incoming tokens -- used by oidc and "
        "keycloak inbound providers "
        "(can also be set via AUDIENCE env var, recommended for production)",
    )
    parser.add_argument(
        "--cognito-user-pool-id",
        default=None,
        help="AWS Cognito user pool ID -- required for --inbound-auth-provider aws-cognito "
        "(can also be set via COGNITO_USER_POOL_ID env var)",
    )
    parser.add_argument(
        "--cognito-aws-region",
        default=None,
        help="AWS region for the Cognito user pool -- required for --inbound-auth-provider aws-cognito "
        "(can also be set via COGNITO_AWS_REGION env var)",
    )
    parser.add_argument(
        "--azure-tenant-id",
        default=None,
        help="Azure AD tenant ID -- required for --inbound-auth-provider azure "
        "(can also be set via AZURE_TENANT_ID env var)",
    )
    parser.add_argument(
        "--azure-identifier-uri",
        default=None,
        help="Azure Application ID URI used for scope prefixing -- optional for "
        "--inbound-auth-provider azure (can also be set via AZURE_IDENTIFIER_URI env var)",
    )
    parser.add_argument(
        "--enable-cimd",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Accept OAuth Client ID Metadata Documents (CIMD) from downstream "
        "MCP clients, i.e. an HTTPS URL as client_id whose metadata the proxy "
        "fetches, as an alternative to Dynamic Client Registration. Enabled by "
        "default; --no-enable-cimd turns it off. Additive -- DCR keeps working "
        "either way. Inert for --inbound-auth-provider keycloak, where Keycloak "
        "is the authorization server. Can also be set via ENABLE_CIMD env var.",
    )

    # Web-mode-only outbound options
    parser.add_argument(
        "--outbound-auth",
        choices=list(OUTBOUND_AUTH_MODES),
        default=None,
        help="How the proxy authenticates outbound calls to the upstream MCP "
        "server. 'forward' (default): reuse the downstream session's bearer "
        "token (Pattern C). 'none': send no credential, not even the user's "
        "token, to an upstream that validates none. "
        "'oauth-client-credentials': proxy obtains its own "
        "token via OAuth client_credentials grant against an outbound IdP "
        "independent of the inbound IdP (Pattern B with a tenant- or user-"
        "scoped OAuth credential). 'static': proxy injects a fixed header "
        "value such as an API key, API token, or PAT (Pattern B with a "
        "tenant- or user-scoped static credential). "
        "Can also be set via OUTBOUND_AUTH env var.",
    )
    parser.add_argument(
        "--outbound-client-id",
        default=None,
        help="OAuth client ID for outbound oauth-client-credentials mode "
        "(can also be set via OUTBOUND_CLIENT_ID env var)",
    )
    parser.add_argument(
        "--outbound-client-secret",
        default=None,
        help="OAuth client secret for outbound oauth-client-credentials mode "
        "(can also be set via OUTBOUND_CLIENT_SECRET env var)",
    )
    parser.add_argument(
        "--outbound-token-url",
        default=None,
        help="Token endpoint URL for outbound oauth-client-credentials mode "
        "(can also be set via OUTBOUND_TOKEN_URL env var; independent of the "
        "inbound IdP -- in Pattern B the upstream's auth mechanism is by "
        "definition disconnected from the IdP that fronts the proxy)",
    )
    parser.add_argument(
        "--outbound-header-name",
        default=None,
        help="Header name for outbound static mode "
        "(can also be set via OUTBOUND_HEADER_NAME env var, default: Authorization)",
    )
    parser.add_argument(
        "--outbound-header-value",
        default=None,
        help="Literal header value for outbound static mode "
        "(can also be set via OUTBOUND_HEADER_VALUE env var; e.g. 'Bearer eyJ...' "
        "for a bearer token, or a bare API key paired with "
        "--outbound-header-name X-API-Key)",
    )

    # Web-mode-only server-identity options
    parser.add_argument(
        "--proxy-name",
        default=None,
        help="Display name advertised to downstream MCP clients (e.g. 'ANALYZE'). "
        "Without this, FastMCP auto-generates 'FastMCPProxy-xxxx'. "
        "Can also be set via MCP_PROXY_NAME env var.",
    )
    parser.add_argument(
        "--proxy-version",
        default=None,
        help="Display version string advertised to downstream MCP clients "
        "(can also be set via MCP_PROXY_VERSION env var)",
    )
    parser.add_argument(
        "--proxy-instructions",
        default=None,
        help="Instructions advertised alongside the tool catalog -- influences "
        "how the LLM selects and uses the upstream's tools "
        "(can also be set via MCP_PROXY_INSTRUCTIONS env var)",
    )
    parser.add_argument(
        "--proxy-website-url",
        default=None,
        help="Project URL shown in downstream MCP client UIs "
        "(can also be set via MCP_PROXY_WEBSITE_URL env var)",
    )

    # Logging options
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--silent", action="store_true", help="Show only error messages")
    group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (can also be set through 'MCP_PROXY_DEBUG' environment variable)",
    )

    args = parser.parse_args()

    # Env var fallbacks (CLI args win when present)
    _apply_env_fallbacks(args)

    return args


def _apply_env_fallbacks(args: argparse.Namespace) -> None:
    """Apply environment-variable fallbacks for any CLI args left unset.

    Walks a table of (attr, env_var) pairs and sets each unset attribute
    from its matching env var. Mode-specific defaulting (default transport,
    int-conversion for port, boolean parsing for MCP_PROXY_DEBUG) is
    handled separately below.
    """
    env_fallbacks = (
        ("upstream_mcp_url", "UPSTREAM_MCP_URL"),
        ("host", "MCP_PROXY_HOST"),
        ("oidc_issuer_url", "OIDC_ISSUER_URL"),
        ("oidc_client_id", "OIDC_CLIENT_ID"),
        ("oidc_client_secret", "OIDC_CLIENT_SECRET"),
        ("oidc_scopes", "OIDC_SCOPES"),
        ("oidc_redirect_url", "OIDC_REDIRECT_URL"),
        ("inbound_auth_provider", "INBOUND_AUTH_PROVIDER"),
        ("proxy_base_url", "MCP_PROXY_BASE_URL"),
        ("audience", "AUDIENCE"),
        ("cognito_user_pool_id", "COGNITO_USER_POOL_ID"),
        ("cognito_aws_region", "COGNITO_AWS_REGION"),
        ("azure_tenant_id", "AZURE_TENANT_ID"),
        ("azure_identifier_uri", "AZURE_IDENTIFIER_URI"),
        ("outbound_auth", "OUTBOUND_AUTH"),
        ("outbound_client_id", "OUTBOUND_CLIENT_ID"),
        ("outbound_client_secret", "OUTBOUND_CLIENT_SECRET"),
        ("outbound_token_url", "OUTBOUND_TOKEN_URL"),
        ("outbound_header_name", "OUTBOUND_HEADER_NAME"),
        ("outbound_header_value", "OUTBOUND_HEADER_VALUE"),
        ("proxy_name", "MCP_PROXY_NAME"),
        ("proxy_version", "MCP_PROXY_VERSION"),
        ("proxy_instructions", "MCP_PROXY_INSTRUCTIONS"),
        ("proxy_website_url", "MCP_PROXY_WEBSITE_URL"),
        ("default_upstream", "DEFAULT_UPSTREAM"),
    )
    for attr, env_name in env_fallbacks:
        if not getattr(args, attr):
            setattr(args, attr, os.getenv(env_name))

    if not args.upstreams:
        # Unlike the flag, the list carries names only; each URL has a variable
        # of its own. A missing one is reported by build_proxy_config.
        args.upstreams = [
            (name, os.getenv(f"{_route_env_prefix(name)}MCP_URL"))
            for name in _split_list(os.getenv("UPSTREAMS") or "")
        ]
    # Per-route settings are environment-only. Read now, while the environment
    # is the one cli() runs against; the fallback to the global settings is
    # applied when the routes are built.
    args.upstream_settings = {
        name: {
            field: os.getenv(f"{_route_env_prefix(name)}{suffix}") or None
            for field, suffix, _ in _ROUTE_SETTINGS
        }
        for name, _ in args.upstreams
    }

    if not args.transport:
        args.transport = os.getenv("MCP_PROXY_TRANSPORT") or "stdio"
    if not args.port:
        port_env = os.getenv("MCP_PROXY_PORT")
        args.port = int(port_env) if port_env else None
    if not args.debug:
        args.debug = os.getenv("MCP_PROXY_DEBUG", "").lower() in _TRUTHY
    if args.enable_cimd is None:
        # Tri-state on purpose: --no-enable-cimd has to beat ENABLE_CIMD=true,
        # which it cannot if "off" and "unset" both look like False here.
        args.enable_cimd = _env_flag("ENABLE_CIMD", default=True)


def _split_list(raw: str) -> list[str]:
    """Split a comma-separated value into its non-blank, stripped entries.

    Blank entries are dropped so a trailing comma, or the line continuations
    that creep into Kubernetes manifests and .env files, don't produce an
    empty entry.
    """
    return [entry for entry in (part.strip() for part in raw.split(",")) if entry]


def _split_base_urls(raw: str) -> list[str]:
    """Split a comma-separated ``--proxy-base-url`` value into its entries.

    Blank entries are dropped (see :func:`_split_list`), so none becomes an
    identity with an empty hostname.

    Raises:
        ValueError: If nothing usable remains.
    """
    base_urls = _split_list(raw)
    if not base_urls:
        raise ValueError(
            "--proxy-base-url (or MCP_PROXY_BASE_URL env var) contains no usable URL"
        )
    return base_urls


def build_proxy_config(args: argparse.Namespace) -> ProxyConfig:
    """Build the appropriate ProxyConfig from parsed CLI args.

    Branches on ``args.transport``:

    - ``stdio`` -> ``DesktopConfig`` using the ``--oidc-*`` flags.
    - ``http`` -> ``WebConfig`` using ``--inbound-auth-provider`` plus the relevant
      per-provider and outbound flags. Per-provider required-field
      validation lives in ``WebConfig.__post_init__``; missing transport-
      level fields (e.g. ``--proxy-base-url``) are caught here.

    Raises:
        ValueError: If required transport-level fields are missing, or if
            several upstreams are configured for stdio mode or alongside a
            single upstream URL.
    """
    if args.transport == "stdio":
        if args.upstreams or args.default_upstream:
            raise ValueError(
                "UPSTREAMS / --upstream and DEFAULT_UPSTREAM / --default-upstream "
                "require --transport http: only web mode serves several upstreams"
            )
        return DesktopConfig(
            issuer_url=args.oidc_issuer_url,
            client_id=args.oidc_client_id,
            client_secret=args.oidc_client_secret,
            scopes=args.oidc_scopes,
            redirect_url=args.oidc_redirect_url,
        )

    # http
    if not args.proxy_base_url:
        raise ValueError(
            "--proxy-base-url (or MCP_PROXY_BASE_URL env var) is required for --transport http"
        )
    if not args.inbound_auth_provider:
        raise ValueError(
            "--inbound-auth-provider (or INBOUND_AUTH_PROVIDER env var) is required for "
            "--transport http"
        )

    if args.upstreams and args.upstream_mcp_url:
        raise ValueError(
            "UPSTREAMS (or --upstream) and UPSTREAM_MCP_URL (or the positional URL) "
            "are mutually exclusive: name every upstream in UPSTREAMS, and give the "
            "one existing clients use DEFAULT_UPSTREAM to keep it at /mcp"
        )

    canonical_base_url, *additional_base_urls = _split_base_urls(args.proxy_base_url)

    return WebConfig(
        inbound_auth_provider=args.inbound_auth_provider,
        proxy_base_url=canonical_base_url,
        additional_proxy_base_urls=additional_base_urls,
        client_id=args.oidc_client_id,
        client_secret=args.oidc_client_secret,
        scopes=args.oidc_scopes,
        enable_cimd=args.enable_cimd,
        issuer_url=args.oidc_issuer_url,
        audience=args.audience,
        cognito_user_pool_id=args.cognito_user_pool_id,
        cognito_aws_region=args.cognito_aws_region,
        azure_tenant_id=args.azure_tenant_id,
        azure_identifier_uri=args.azure_identifier_uri,
        outbound_auth=args.outbound_auth or "forward",
        outbound_client_id=args.outbound_client_id,
        outbound_client_secret=args.outbound_client_secret,
        outbound_token_url=args.outbound_token_url,
        outbound_header_name=args.outbound_header_name or "Authorization",
        outbound_header_value=args.outbound_header_value,
        proxy_name=args.proxy_name,
        proxy_version=args.proxy_version,
        proxy_instructions=args.proxy_instructions,
        proxy_website_url=args.proxy_website_url,
        upstreams=_build_upstream_routes(args),
        default_upstream=args.default_upstream,
    )


def _build_upstream_routes(args: argparse.Namespace) -> list[UpstreamRoute]:
    """Build the routes of a multi-upstream deployment from parsed args.

    Each setting comes from the route's own ``UPSTREAM_<NAME>_*`` variable,
    else from the global flag or variable, else from the global default.

    Raises:
        ValueError: If a route has no URL, or a route fails validation.
    """
    routes = []
    for name, url in args.upstreams:
        if not url:
            raise ValueError(
                f"{_route_env_prefix(name)}MCP_URL is required for upstream {name!r} "
                "listed in UPSTREAMS"
            )
        own = args.upstream_settings[name]
        settings = {
            field: own[field] or getattr(args, field) for field, _, _ in _ROUTE_SETTINGS
        }
        settings["outbound_auth"] = settings["outbound_auth"] or "forward"
        settings["outbound_header_name"] = (
            settings["outbound_header_name"] or "Authorization"
        )
        routes.append(UpstreamRoute(name=name, mcp_url=url, **settings))
    return routes


class _LowercaseLevelFormatter(logging.Formatter):
    """Formatter that lowercases the level name to match Claude Desktop log style."""

    def format(self, record):
        record.levelname = record.levelname.lower()
        return super().format(record)


def configure_logging(args):
    """Configure logging based on command line arguments.

    In stdio mode, stdout is reserved for MCP JSON-RPC traffic so logs are
    forced to stderr. In http mode, stdout is free; logs go to stdout there
    (more conventional for HTTP server output, especially in containers).
    """
    if args.silent:
        log_level = logging.ERROR
    elif args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    stream = sys.stderr if args.transport == "stdio" else sys.stdout
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        _LowercaseLevelFormatter(
            fmt="%(asctime)s.%(msecs)03dZ [%(name)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logging.root.addHandler(handler)
    logging.root.setLevel(log_level)


def get_log_level_name(args) -> str:
    """
    Determine the appropriate log level based on command line arguments.

    Args:
        args: Parsed command line arguments containing silent/debug flags.

    Returns:
        str: Log level name ('ERROR', 'DEBUG', or 'INFO').
    """
    if args.silent:
        return logging.getLevelName(logging.ERROR)
    elif args.debug:
        return logging.getLevelName(logging.DEBUG)
    else:
        return logging.getLevelName(logging.INFO)


def extract_root_cause(eg: BaseExceptionGroup) -> BaseException:
    """Extract the root cause from singly-nested exception groups.

    Exceptions from anyio task groups and asyncio often get wrapped in multiple
    layers of BaseExceptionGroup. This recursively unwraps to find the actual cause.
    """
    exceptions = eg.exceptions
    while len(exceptions) == 1 and isinstance(exceptions[0], BaseExceptionGroup):
        exceptions = exceptions[0].exceptions
    if len(exceptions) == 1:
        return exceptions[0]
    return eg


def log_error_and_exit(exc: BaseException) -> None:
    """Log an exception appropriately and exit with status 1.

    Provides clean error messages without stack traces for expected error types,
    and full tracebacks for unexpected internal errors. Recursively handles
    BaseExceptionGroup by extracting and processing the root cause.

    Args:
        exc: The exception to log and handle.
    """
    if isinstance(exc, KeyboardInterrupt):
        # Graceful shutdown - exit without logging
        return

    # Handle BaseExceptionGroup recursively
    if isinstance(exc, BaseExceptionGroup):
        cause = extract_root_cause(exc)
        if isinstance(cause, SystemExit):
            # SystemExit from uvicorn loses the original error message;
            # check __context__ for the real cause (e.g., OSError from port binding)
            context = getattr(cause, "__context__", None)
            log_error_and_exit(context if context else cause)
        else:
            log_error_and_exit(cause)
        return

    # Log based on exception type
    if isinstance(exc, httpx2.HTTPStatusError | MCPError):
        logger.error(f"Backend error: {exc}")
    elif isinstance(
        exc,
        httpx2.ConnectError
        | httpx2.ConnectTimeout
        | httpx2.ReadTimeout
        | httpx2.TimeoutException,
    ):
        logger.error(f"Network error: {exc}")
    elif isinstance(exc, OSError):
        logger.error(f"System error: {exc}")
    elif isinstance(exc, ValueError):
        logger.error(f"Configuration error: {exc}")
    elif isinstance(exc, RuntimeError):
        logger.error(f"Runtime error: {exc}")
    elif isinstance(exc, SystemExit):
        # Unexpected system exit without proper context
        logger.error(f"Unexpected system exit: {exc}")
        sys.exit(exc.code if exc.code is not None else 1)
    else:
        # Unexpected internal error - include full traceback for debugging
        logger.error(f"Internal error: {exc}", exc_info=exc)

    sys.exit(1)


def main():
    """
    Main entry point for the Authsome MCP Proxy application.

    Parses configuration, builds the appropriate ProxyConfig (DesktopConfig for
    stdio mode, WebConfig for http mode), and launches the proxy server. Handles
    graceful shutdown and provides appropriate error messages for different
    exception types.

    Exits with status code 1 on errors, 0 on successful completion.
    """
    args = cli()
    configure_logging(args)

    try:
        config = build_proxy_config(args)

        # Build transport kwargs forwarded to FastMCP's run_async.
        # log_level applies to both transports; host/port apply to http only.
        transport_kwargs: dict = {"log_level": get_log_level_name(args)}
        if args.transport == "http":
            if args.host:
                transport_kwargs["host"] = args.host
            if args.port:
                transport_kwargs["port"] = args.port

        # Start the MCP proxy
        asyncio.run(
            mcp_proxy.run_async(
                upstream_url=args.upstream_mcp_url,
                config=config,
                show_banner=not args.no_banner,
                **transport_kwargs,
            )
        )
    except Exception as e:
        # Catch-all for any exceptions (BaseExceptionGroup, KeyboardInterrupt, etc.)
        # All exception handling logic is in log_error_and_exit
        log_error_and_exit(e)
    finally:
        logging.shutdown()


if __name__ == "__main__":
    main()
