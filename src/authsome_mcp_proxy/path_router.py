"""Path-based ASGI dispatch, so one OAuth identity can front several upstreams.

Why this exists
---------------
A deployment that fronts several upstream MCP servers -- a repository server and
a read-only knowledge base, say -- wants them under one hostname, each at its own
path (``/secure/mcp``, ``/emb3d/mcp``), with the user signing in once. That
means one authorization server: one IdP client and redirect URI, one DCR store,
one set of pending authorizations and minted tokens, so that a token obtained
while connecting to ``/secure/mcp`` is also accepted at ``/emb3d/mcp``.

FastMCP builds its HTTP app around a single MCP endpoint.
``create_streamable_http_app`` mounts exactly one ``streamable_http_path`` and
derives everything resource-specific from it: the RFC 9728 protected-resource
metadata at ``/.well-known/oauth-protected-resource/<path>`` and its
``resource``, and the metadata URL in the 401 challenge. Several routes
therefore need several apps -- one per route, each over its upstream's proxy
server and with its own MCP session manager, so a session opened on one route
can never be resumed on another.

The authorization server is the part that must *not* multiply. Building a
second auth provider per route would split it: OAuthProxy-style providers bind
the tokens they mint to their own resource URL, so a token from one route's
provider fails audience validation on the next, and every provider would have
to be reachable at the same ``/authorize``, ``/token`` and ``/auth/callback``.
Instead, one provider instance per public hostname is passed to every route's
``create_streamable_http_app``. Each app then carries the full set of
authorization-server routes, all bound to that one instance, and this router
sends every request that is neither a route nor a route's resource metadata to a
single designated child. The authorization server is served once, at the
origin root, with all of its state in one place.

Sharing the instance needs one correction. ``get_routes`` re-binds the
provider's resource URL on every call, so after N apps have been built the last
route would be the only resource the authorization server accepts in an RFC 8707
``resource`` parameter, and its URL would be the audience of every token.
:func:`authsome_mcp_proxy.inbound_auth.share_authorization_server` widens the
check to the identity's own routes -- a foreign resource is still refused -- and
binds tokens to the base URL every route shares.

A legacy ``/mcp`` alias for one route is a separate child app over that route's
server rather than a path rewrite: its metadata has to name ``<base>/mcp`` as
the resource, because MCP clients reject metadata whose ``resource`` differs
from the URL they connected to.

The router nests inside :class:`~authsome_mcp_proxy.host_router.HostRouter`:
hostnames select an identity, paths select an upstream within it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.types import Receive, Scope, Send

from .host_router import LifespanApp, enter_lifespans, serve_lifespan

if TYPE_CHECKING:
    from collections.abc import Mapping
    from contextlib import AbstractAsyncContextManager

#: RFC 9728 §3.1: metadata lives at this prefix plus the resource's path.
PROTECTED_RESOURCE_METADATA_PREFIX = "/.well-known/oauth-protected-resource"


def protected_resource_metadata_path(route_path: str) -> str:
    """The path of the protected-resource metadata for a route.

    ``/secure/mcp`` -> ``/.well-known/oauth-protected-resource/secure/mcp``,
    at the origin root -- not ``/secure/.well-known/...``.
    """
    return f"{PROTECTED_RESOURCE_METADATA_PREFIX}{route_path}"


def _route_path(scope: Scope) -> str:
    """The request path relative to the app's ``root_path``, as Starlette sees it."""
    path: str = scope.get("path", "")
    root_path: str = scope.get("root_path", "")
    if root_path and path.startswith(f"{root_path}/"):
        return path[len(root_path) :]
    return path


class PathRouter:
    """ASGI app dispatching each route, and its metadata, to the route's own child.

    Args:
        apps: Child apps keyed by the path of the route each one serves, e.g.
            ``/secure/mcp``. Insertion order fixes the lifespan startup order.
        fallback: The route path whose app answers every other request: the
            shared authorization server's endpoints, health checks, and paths
            that match nothing.

    Raises:
        ValueError: If ``apps`` is empty, if a path is not absolute or ends in
            ``/``, or if ``fallback`` is not among ``apps``.
    """

    def __init__(self, apps: Mapping[str, LifespanApp], *, fallback: str) -> None:
        if not apps:
            raise ValueError("PathRouter requires at least one app")
        if fallback not in apps:
            raise ValueError(
                f"fallback path {fallback!r} is not among the routed paths {list(apps)!r}"
            )

        self._children: tuple[LifespanApp, ...] = tuple(apps.values())
        self._by_path: dict[str, LifespanApp] = {}
        for route_path, app in apps.items():
            if not route_path.startswith("/") or route_path.endswith("/"):
                raise ValueError(
                    f"route path {route_path!r} must start with '/' and not end with it"
                )
            self._by_path[route_path] = app
            self._by_path[protected_resource_metadata_path(route_path)] = app
        self._fallback = apps[fallback]

    def lifespan(self, app: Any, /) -> AbstractAsyncContextManager[None]:
        """Enter every child's lifespan; see :func:`enter_lifespans`."""
        return enter_lifespans(self._children)

    def app_for_path(self, path: str) -> LifespanApp:
        """Resolve a request path to its app, falling back to the designated one.

        A trailing slash is ignored, so ``/secure/mcp/`` still reaches the route
        whose app answers it with Starlette's usual redirect.
        """
        return self._by_path.get(path.rstrip("/"), self._fallback)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await serve_lifespan(self.lifespan(self), receive, send)
            return
        # The scope travels on untouched -- headers included -- since each child
        # mounts its route at the full path.
        await self.app_for_path(_route_path(scope))(scope, receive, send)
