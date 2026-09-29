"""Relay the upstream MCP server's identity to downstream clients in web mode.

Desktop mode connects to the upstream once at startup and bakes what it reads
into the proxy (see :func:`authsome_mcp_proxy.mcp_proxy._relay_upstream_identity`).
Web mode cannot: with ``outbound_auth='forward'`` the only credential the
upstream accepts is a user's, and at startup there is no user yet. Without a
relay, a client connecting through the proxy is shown FastMCP's defaults instead
of the upstream's instructions, website URL and icons -- and the instructions
are what tell the model how to use the upstream's tools.

:class:`UpstreamIdentityMiddleware` closes that gap at the one point where a
credential exists: the downstream client's own ``initialize`` (handshake-era
protocol) or ``server/discover`` (modern protocol). The first one fetches the
upstream's identity using that request's credential and caches it; every one
patches the relayed fields into the result it returns.

Name and version are deliberately not relayed. They are the operator's to set
(``proxy_name`` / ``proxy_version``), because FastMCP also uses the server name
outside the wire result -- as the audience of sealed request state and in
tracing spans -- where a per-request rewrite would not reach it.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Collection
from typing import Any

import anyio
import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

logger = logging.getLogger(__name__)

#: Identity fields relayed from the upstream, keyed as ``create_proxy`` kwargs.
RELAYED_FIELDS = ("instructions", "website_url", "icons")


class UpstreamIdentityMiddleware(Middleware):
    """Patch the upstream's identity into ``initialize`` and ``server/discover`` results.

    Args:
        fetch_identity: Coroutine returning the upstream's identity as
            ``create_proxy`` kwargs. Called inside a downstream request, so
            outbound auth that reads the request's credential works.
        configured_fields: Fields the operator set explicitly. They win over
            the upstream's values and are never overwritten.
        ttl_seconds: How long a fetched identity is reused. The upstream can be
            redeployed with new instructions while the proxy keeps running.
        retry_after_seconds: How long to wait after a failed fetch before
            trying again, so an unreachable upstream does not slow down every
            connection. A previously fetched identity keeps being served
            meanwhile.
        timeout_seconds: Upper bound on one fetch. It runs inside a client's
            connection handshake, which must not hang on it.
    """

    def __init__(
        self,
        fetch_identity: Callable[[], Awaitable[dict[str, Any]]],
        *,
        configured_fields: Collection[str] = (),
        ttl_seconds: float = 600.0,
        retry_after_seconds: float = 60.0,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._fetch_identity = fetch_identity
        self._relayed_fields = tuple(
            f for f in RELAYED_FIELDS if f not in configured_fields
        )
        self._ttl_seconds = ttl_seconds
        self._retry_after_seconds = retry_after_seconds
        self._timeout_seconds = timeout_seconds
        self._identity: dict[str, Any] = {}
        self._next_fetch_at = 0.0
        self._lock = anyio.Lock()

    async def on_initialize(
        self,
        context: MiddlewareContext[mt.InitializeRequest],
        call_next: CallNext[mt.InitializeRequest, mt.InitializeResult | None],
    ) -> mt.InitializeResult | None:
        result = await call_next(context)
        if result is None or not self._relayed_fields:
            return result
        identity = await self._current_identity()
        if not identity:
            return result
        return result.model_copy(
            update={
                "server_info": _patched_server_info(result.server_info, identity),
                "instructions": identity.get("instructions", result.instructions),
            }
        )

    async def on_discover(
        self,
        context: MiddlewareContext[mt.DiscoverRequest],
        call_next: CallNext[mt.DiscoverRequest, mt.DiscoverResult | dict[str, Any]],
    ) -> mt.DiscoverResult | dict[str, Any]:
        result = await call_next(context)
        if not isinstance(result, mt.DiscoverResult) or not self._relayed_fields:
            return result
        identity = await self._current_identity()
        if not identity:
            return result

        # On the modern protocol, serverInfo is a `_meta` stamp rather than a
        # result field. The SDK only stamps a result that carries none, so
        # writing it here also works if the stamp is added after this runs.
        meta = dict(result.meta or {})
        stamp = meta.get(mt.SERVER_INFO_META_KEY)
        if stamp is not None:
            server_info = mt.Implementation.model_validate(stamp)
            meta[mt.SERVER_INFO_META_KEY] = _patched_server_info(
                server_info, identity
            ).model_dump(by_alias=True, mode="json", exclude_none=True)
        return result.model_copy(
            update={
                "meta": meta,
                "instructions": identity.get("instructions", result.instructions),
            }
        )

    async def _current_identity(self) -> dict[str, Any]:
        """The cached identity, refreshed when due; only the relayed fields."""
        if time.monotonic() < self._next_fetch_at:
            return self._identity
        async with self._lock:
            # Re-check inside the lock so concurrent handshakes fetch once.
            if time.monotonic() < self._next_fetch_at:
                return self._identity
            try:
                with anyio.fail_after(self._timeout_seconds):
                    fetched = await self._fetch_identity()
            except Exception as e:
                # The identity is cosmetic; a client must still connect.
                logger.warning(
                    "Could not fetch the upstream's identity (%s); retrying in %ss",
                    e,
                    self._retry_after_seconds,
                )
                self._next_fetch_at = time.monotonic() + self._retry_after_seconds
                return self._identity
            self._identity = {
                f: fetched[f] for f in self._relayed_fields if fetched.get(f)
            }
            self._next_fetch_at = time.monotonic() + self._ttl_seconds
            return self._identity


def _patched_server_info(
    server_info: mt.Implementation, identity: dict[str, Any]
) -> mt.Implementation:
    update = {f: identity[f] for f in ("website_url", "icons") if f in identity}
    return server_info.model_copy(update=update) if update else server_info
