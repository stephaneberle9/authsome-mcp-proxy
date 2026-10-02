"""Host-based ASGI dispatch, so one process can serve several public identities.

Why this exists
---------------
Every FastMCP inbound auth provider is built around a single ``base_url``. That
one value is not cosmetic: it becomes the OAuth 2.0 protected-resource
``resource``, the advertised ``authorization_servers`` entry, every endpoint in
the authorization-server metadata, the ``redirect_uri`` sent to the upstream IdP
at ``/authorize`` *and again* at the callback token exchange, the consent URL,
and the ``iss``/``aud`` of the tokens the proxy mints. FastMCP never derives it
from the request, so a provider instance can only ever answer as one hostname.

Deployments that must be reachable under more than one public hostname -- an
alias domain for customers whose networks block the primary TLD, a vanity host,
a migration where old and new names run side by side -- therefore cannot be
solved at the ingress. Adding a second host to a load balancer fixes TLS and
routing, but the proxy still answers OAuth discovery with the *first* hostname,
so the client is sent to a host it may not be able to reach. Rewriting the
hostname in responses at the edge does not work either: it survives the metadata
documents and the redirect, then fails at the server-to-server token exchange,
where the ``redirect_uri`` must byte-match what the IdP saw earlier.

The fix is to stop sharing one identity. FastMCP's ``_lifespan_manager`` is
reference-counted and re-entrant by design, so a single FastMCP server can back
several ASGI apps at once. This module builds one app per public base URL, each
with its own auth provider, and routes requests between them on the ``Host``
header. One process, one upstream client, N fully correct identities.

Only hostnames derived from configured base URLs are ever matched -- the ``Host``
header selects among them but never defines one, so a forged header can at worst
reach an identity the operator already published.

The lifespan helpers at the bottom are module-level so that a router nested
inside this one can enter its own children the same way.
"""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack, asynccontextmanager
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

from starlette.types import Receive, Scope, Send

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable, Mapping
    from contextlib import AbstractAsyncContextManager

logger = logging.getLogger(__name__)


class LifespanApp(Protocol):
    """An ASGI app whose lifespan this router is responsible for entering.

    Deliberately structural rather than ``StarletteWithLifespan``: the router
    needs exactly two things from a child -- that it can be called as an ASGI
    app, and that its lifespan can be entered on the child's behalf. Naming a
    FastMCP-internal Starlette subclass here would couple the router to that
    type for no gain and make it untestable without one.
    """

    # `app` is positional-only: Starlette's Lifespan callables take it that way,
    # and the router calls child.lifespan(child) positionally.
    def lifespan(self, app: Any, /) -> AbstractAsyncContextManager[Any]: ...

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None: ...


def host_of(base_url: str) -> str:
    """Return the lower-cased, port-less hostname of ``base_url``.

    ``https://Mcp.Example.com:443/`` -> ``mcp.example.com``. Used both to key
    the routing table and to normalize the inbound ``Host`` header, so the two
    are compared on the same footing.
    """
    hostname = urlsplit(base_url).hostname
    if not hostname:
        raise ValueError(f"base URL has no hostname: {base_url!r}")
    return hostname.lower()


def _request_host(scope: Scope) -> str | None:
    """Extract the port-less hostname a request was addressed to.

    Reads the ``Host`` header, which uvicorn also populates from HTTP/2's
    ``:authority``. Returns ``None`` when the header is absent -- a bare-IP
    request such as a Kubernetes probe, which the caller resolves to the
    canonical app.
    """
    for name, value in scope.get("headers", ()):
        if name == b"host":
            host = value.decode("latin-1").strip().lower()
            if not host:
                return None
            # IPv6 literals are bracketed ("[::1]:8000"); everything else
            # splits on the first colon.
            if host.startswith("["):
                return host.partition("]")[0].lstrip("[")
            return host.partition(":")[0]
    return None


class HostRouter:
    """ASGI app dispatching to per-hostname child apps.

    Args:
        apps: Child apps keyed by public base URL. Insertion order fixes the
            lifespan startup order.
        canonical_base_url: The base URL whose app answers requests carrying an
            unknown or absent ``Host`` -- Kubernetes probes hitting the pod IP,
            health checkers, and anything else addressing the server directly.

    Raises:
        ValueError: If ``apps`` is empty, if two base URLs share a hostname
            (the ``Host`` header could not tell them apart), or if
            ``canonical_base_url`` is not among ``apps``.
    """

    def __init__(
        self, apps: Mapping[str, LifespanApp], canonical_base_url: str
    ) -> None:
        if not apps:
            raise ValueError("HostRouter requires at least one app")
        if canonical_base_url not in apps:
            raise ValueError(
                f"canonical base URL {canonical_base_url!r} is not among the "
                f"routed base URLs {list(apps)!r}"
            )

        self._children: tuple[LifespanApp, ...] = tuple(apps.values())
        self._by_host: dict[str, LifespanApp] = {}
        for base_url, app in apps.items():
            host = host_of(base_url)
            if host in self._by_host:
                raise ValueError(
                    f"two base URLs resolve to the same hostname {host!r}; "
                    "the Host header cannot distinguish them"
                )
            self._by_host[host] = app

        self._canonical = apps[canonical_base_url]
        self._canonical_host = host_of(canonical_base_url)

    def lifespan(self, app: Any, /) -> AbstractAsyncContextManager[None]:
        """Enter every child's lifespan; see :func:`enter_lifespans`."""
        return enter_lifespans(self._children)

    def app_for_host(self, host: str | None) -> LifespanApp:
        """Resolve a hostname to its app, falling back to the canonical one."""
        if host is None:
            return self._canonical
        return self._by_host.get(host, self._canonical)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await serve_lifespan(self.lifespan(self), receive, send)
            return

        host = _request_host(scope)
        if host is not None and host not in self._by_host:
            # Not an error: probes, load-balancer health checks and scanners all
            # arrive this way. Serving them from the canonical identity keeps
            # health routes working on the pod IP.
            logger.debug(
                "unrouted Host %r; serving from canonical identity %r",
                host,
                self._canonical_host,
            )
        await self.app_for_host(host)(scope, receive, send)


@asynccontextmanager
async def enter_lifespans(children: Iterable[LifespanApp]) -> AsyncIterator[None]:
    """Run every child's lifespan under one parent lifespan.

    Starlette propagates lifespan only into apps reached through routing, so a
    router enters its children explicitly. They share a single
    ``AsyncExitStack``, which unwinds in reverse on shutdown and on a failed
    startup alike.
    """
    async with AsyncExitStack() as stack:
        for child in children:
            await stack.enter_async_context(child.lifespan(child))
        yield


async def serve_lifespan(
    lifespan: AbstractAsyncContextManager[None], receive: Receive, send: Send
) -> None:
    """Speak the ASGI lifespan protocol for a router around ``lifespan``.

    A failure in either phase is reported to the server before it propagates,
    so a half-started router never reports itself ready.
    """
    started = False
    try:
        message = await receive()
        assert message["type"] == "lifespan.startup"
        async with lifespan:
            await send({"type": "lifespan.startup.complete"})
            started = True

            message = await receive()
            assert message["type"] == "lifespan.shutdown"
    except BaseException as exc:
        phase = "shutdown" if started else "startup"
        await send({"type": f"lifespan.{phase}.failed", "message": str(exc)})
        raise
    await send({"type": "lifespan.shutdown.complete"})
