"""
MCP proxy with two operating modes selected by config type.

- :class:`DesktopConfig` -> stdio transport. The proxy is launched as a
  local process by the MCP client (Claude Desktop, Claude Code via
  ``claude mcp add --transport stdio``, Cursor, Codex, etc.). The
  proxy itself runs the OAuth Authorization Code + PKCE flow against an
  external OIDC IdP via :class:`ExternalOIDCAuth`, caches tokens on
  disk, and forwards them as Bearer tokens to the upstream MCP server.
  No inbound auth (local trust).
- :class:`WebConfig` -> http transport. The proxy runs as a standalone
  HTTP server that MCP clients connect to by URL (e.g. Claude Code via
  ``claude mcp add --transport http <name> <url>``). The proxy is an
  OAuth server in front of an external IdP (built by
  :func:`build_inbound_auth`); downstream MCP clients authenticate
  against the proxy and the proxy authenticates outbound to the upstream
  MCP server using the mechanism returned by
  :func:`build_outbound_auth`.

Both paths converge on FastMCP's ``create_proxy`` + per-session
``client.new()`` model so each downstream session gets an isolated
upstream connection.
"""

import logging
from typing import Any

import httpx2
from fastmcp import Client
from fastmcp.server import create_proxy
from fastmcp.server.auth.auth import AuthProvider
from fastmcp_seaworthy import build_client_storage, serve_http

from .config import DesktopConfig, ProxyConfig, WebConfig
from .external_oidc import ExternalOIDCAuth
from .inbound_auth import build_inbound_auth
from .outbound_auth import build_outbound_auth
from .upstream_identity import UpstreamIdentityMiddleware

logger = logging.getLogger(__name__)


async def run_async(
    upstream_url: str,
    config: ProxyConfig,
    show_banner: bool = True,
    **transport_kwargs: Any,
) -> None:
    """Run the MCP proxy server.

    The transport (stdio vs http) is derived from the config type -- there
    is no separate transport argument. ``DesktopConfig`` always runs over
    stdio; ``WebConfig`` always runs over http.

    Args:
        upstream_url: URL of the upstream MCP server to proxy.
        config: Either a ``DesktopConfig`` (stdio mode) or a ``WebConfig``
            (http mode). Selects the auth strategy and transport.
        show_banner: Whether to display the server startup banner.
        **transport_kwargs: Additional keyword arguments passed to the
            transport layer. For stdio: ``log_level``. For http: ``host``,
            ``port``, ``log_level``, ``path``, ``uvicorn_config``,
            ``json_response``, ``stateless_http`` / ``stateless``,
            ``middleware``, ``host_origin_protection``, ``allowed_hosts``,
            ``allowed_origins`` and ``session_idle_timeout`` -- see
            ``fastmcp_seaworthy.serve_http``. Unrecognized keywords raise at
            startup rather than being ignored.

    Raises:
        TypeError: If ``config`` is not a recognized ``ProxyConfig`` type.
        ValueError: If ``transport`` is passed. It is derived from the config
            type, so there is nothing to choose -- and both branches splat
            ``transport_kwargs`` onto a call that already fixes it, which
            would otherwise surface as a "got multiple values for keyword
            argument 'transport'" naming a function the caller never called.
    """
    if "transport" in transport_kwargs:
        raise ValueError(
            "transport is not configurable: it is derived from the config type "
            "(DesktopConfig -> stdio, WebConfig -> http). Pass the config you "
            "want rather than a transport."
        )

    if isinstance(config, DesktopConfig):
        await _run_desktop(upstream_url, config, show_banner, **transport_kwargs)
    elif isinstance(config, WebConfig):
        await _run_web(upstream_url, config, show_banner, **transport_kwargs)
    else:
        raise TypeError(
            f"Unsupported config type: {type(config).__name__}. "
            "Expected DesktopConfig or WebConfig."
        )


async def _run_desktop(
    upstream_url: str,
    config: DesktopConfig,
    show_banner: bool,
    **transport_kwargs: Any,
) -> None:
    """Run the proxy in stdio mode against an external OIDC IdP."""
    auth = ExternalOIDCAuth(
        issuer_url=config.issuer_url,
        client_id=config.client_id,
        client_secret=config.client_secret,
        scopes=config.scopes,
        redirect_url=config.redirect_url,
    )

    # Connect once to relay upstream server identity (name/version/icons/etc.)
    # so the proxy appears transparent to the MCP client.
    proxy_kwargs = await _relay_upstream_identity(upstream_url, auth)

    # Disconnected client; FastMCP calls client.new() per session.
    proxy_client = Client(transport=upstream_url, auth=auth)
    mcp_proxy = create_proxy(proxy_client, **proxy_kwargs)

    await mcp_proxy.run_async(
        transport="stdio", show_banner=show_banner, **transport_kwargs
    )


async def _run_web(
    upstream_url: str,
    config: WebConfig,
    show_banner: bool,
    **transport_kwargs: Any,
) -> None:
    """Run the proxy in http mode with FastMCP inbound auth + configurable outbound.

    One ASGI app is built per entry in ``config.all_proxy_base_urls``, each with
    its own inbound auth provider, and a :class:`~fastmcp_seaworthy.HostRouter`
    picks between them on the request's ``Host``. A FastMCP auth provider bakes
    its ``base_url`` in at construction and advertises it everywhere -- resource
    metadata, authorization-server metadata, the IdP ``redirect_uri``, minted
    token claims -- so answering as a second hostname genuinely needs a second
    provider. The upstream client, the tool catalog and the server lifespan stay
    shared: this duplicates the front door, not the backend.

    The single-hostname case runs the same way with one child app, which is why
    there is no second code path to keep in step.
    """
    outbound_auth = build_outbound_auth(config)

    # The stdio path's pre-flight relay cannot run here: with
    # outbound_auth='forward' there is no inbound session yet to borrow a
    # credential from. The name comes from the operator's config -- without it
    # FastMCP falls back to its auto-generated FastMCPProxy-xxxx name -- and the
    # upstream's instructions, version, website URL and icons are relayed per
    # handshake by UpstreamIdentityMiddleware instead, unless the operator
    # configured them.
    proxy_kwargs = _server_identity_kwargs(config)
    proxy_client = Client(transport=upstream_url, auth=outbound_auth)

    # No auth= here: it is supplied per app below. The server is never served
    # through its own http_app(), which would be unauthenticated.
    mcp_proxy = create_proxy(proxy_client, **proxy_kwargs)
    mcp_proxy.add_middleware(
        UpstreamIdentityMiddleware(
            lambda: _relay_upstream_identity(upstream_url, outbound_auth),
            configured_fields=proxy_kwargs.keys(),
        )
    )

    await _serve_http(mcp_proxy, config, show_banner, **transport_kwargs)


async def _serve_http(
    mcp_proxy: Any,
    config: WebConfig,
    /,
    show_banner: bool = True,
    **transport_kwargs: Any,
) -> None:
    """Serve one ASGI app per configured base URL behind a host router.

    fastmcp-seaworthy's ``serve_http`` does the serving -- it mirrors
    ``FastMCP.run_http_async`` but builds one app per base URL, routed on
    ``Host`` -- so this function only supplies what is the proxy's own: the
    base URLs, the inbound auth provider for each, and the OAuth state store.
    ``transport_kwargs`` are forwarded as they are; ``serve_http`` spells out
    its keywords, so anything unrecognized fails at startup instead of being
    silently dropped.

    ``mcp_proxy`` and ``config`` are positional-only because they would
    otherwise be shadowable by a caller's ``**transport_kwargs``.

    One store serves every hostname: the providers of different hostnames are
    separate OAuth identities but one proxy, and ``serve_http`` opens the store
    before building any of them, so a backend the proxy cannot reach fails at
    startup rather than at the first sign-in.
    """
    oauth_state = config.oauth_state
    client_storage = (
        build_client_storage(oauth_state) if oauth_state is not None else None
    )

    def auth_for(base_url: str) -> AuthProvider:
        return build_inbound_auth(
            config, base_url=base_url, client_storage=client_storage
        )

    await serve_http(
        mcp_proxy,
        config.all_proxy_base_urls,
        auth_for,
        client_storage=client_storage,
        show_banner=show_banner,
        **transport_kwargs,
    )


def _server_identity_kwargs(config: WebConfig) -> dict[str, Any]:
    """Collect operator-configured server-identity fields as create_proxy kwargs.

    Only includes fields the operator actually set. Unset fields are omitted so
    FastMCP's defaults apply.
    """
    kwargs: dict[str, Any] = {}
    if config.proxy_name:
        kwargs["name"] = config.proxy_name
    if config.proxy_version:
        kwargs["version"] = config.proxy_version
    if config.proxy_instructions:
        kwargs["instructions"] = config.proxy_instructions
    if config.proxy_website_url:
        kwargs["website_url"] = config.proxy_website_url
    return kwargs


async def _relay_upstream_identity(
    upstream_url: str, auth: httpx2.Auth | None
) -> dict[str, Any]:
    """Connect to the upstream and collect the identity the proxy should relay.

    On the modern protocol the server's name and version are only an optional
    ``_meta`` stamp on the ``server/discover`` result, and some servers do not
    send it: Quarkus MCP Server 2.0.0 puts ``serverInfo`` at the top level of
    the result instead, where the MCP SDK drops it as an unknown field. The
    proxy would then show up under FastMCP's generated name. When the first
    connection yields no name, a second one pinned to the initialize handshake
    reads it from ``InitializeResult.serverInfo``, which every server fills in.
    Values from the first connection win where both are present.
    """
    async with Client(transport=upstream_url, auth=auth) as client:
        proxy_kwargs = _relay_server_info(client)
    if "name" in proxy_kwargs:
        return proxy_kwargs

    try:
        async with Client(
            transport=upstream_url, auth=auth, mode="legacy"
        ) as legacy_client:
            legacy_kwargs = _relay_server_info(legacy_client)
    except Exception as e:
        # The identity is cosmetic; an upstream that only speaks the modern
        # protocol must not be kept from starting over it.
        logger.warning(
            "Upstream did not identify itself and the initialize handshake "
            "failed (%s); advertising FastMCP's generated server name",
            e,
        )
        return proxy_kwargs
    return {**legacy_kwargs, **proxy_kwargs}


def _relay_server_info(client: Client) -> dict[str, Any]:
    """Extract the upstream MCP server's identity so the proxy appears transparent.

    Reads name/version/website_url/icons from the server info (shown in the
    Claude Desktop connector list) and ``instructions`` (influences how the
    LLM selects and uses the server's tools).

    Uses the protocol-era-neutral ``Client.server_info`` / ``Client.instructions``
    rather than ``Client.initialize_result``: fastmcp 4 negotiates the modern
    protocol when the upstream supports it, and on such a connection there is
    no initialize handshake, so ``initialize_result`` is ``None`` and the relay
    would silently come back empty.
    """
    proxy_kwargs: dict[str, Any] = {}

    if info := client.server_info:
        if name := info.name:
            proxy_kwargs["name"] = name
        if version := info.version:
            proxy_kwargs["version"] = version
        if website_url := info.website_url:
            proxy_kwargs["website_url"] = website_url
        if icons := info.icons:
            proxy_kwargs["icons"] = icons
    if instructions := client.instructions:
        proxy_kwargs["instructions"] = instructions

    return proxy_kwargs
