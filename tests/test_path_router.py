from contextlib import asynccontextmanager

import pytest

from authsome_mcp_proxy.host_router import HostRouter
from authsome_mcp_proxy.path_router import PathRouter, protected_resource_metadata_path

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeApp:
    """Minimal stand-in for a StarletteWithLifespan child app."""

    def __init__(self, name):
        self.name = name
        self.calls = []
        self.events = []

    async def __call__(self, scope, receive, send):
        self.calls.append(scope)

    def lifespan(self, app):
        assert app is self, "child lifespan must be passed its own app"

        @asynccontextmanager
        async def _cm():
            self.events.append("startup")
            try:
                yield
            finally:
                self.events.append("shutdown")

        return _cm()


async def noop_receive():
    raise AssertionError("routing tests never read the request body")


async def noop_send(message):
    raise AssertionError("routing tests never send a response")


def http_scope(path, root_path=""):
    return {
        "type": "http",
        "path": path,
        "root_path": root_path,
        "headers": [(b"host", b"mcp.example.com"), (b"mcp-protocol-version", b"x")],
    }


def _router():
    alias, secure, emb3d = FakeApp("alias"), FakeApp("secure"), FakeApp("emb3d")
    router = PathRouter(
        {"/mcp": alias, "/secure/mcp": secure, "/emb3d/mcp": emb3d}, fallback="/mcp"
    )
    return router, alias, secure, emb3d


class LifespanDriver:
    def __init__(self):
        self.incoming = ["lifespan.startup", "lifespan.shutdown"]
        self.sent = []

    async def receive(self):
        return {"type": self.incoming.pop(0)}

    async def send(self, message):
        self.sent.append(message)


# ---------------------------------------------------------------------------
# protected_resource_metadata_path
# ---------------------------------------------------------------------------


def test_metadata_path_is_path_scoped_at_the_origin_root():
    """RFC 9728 §3.1: the well-known prefix comes first, the resource's path
    after it -- not the other way round."""
    assert (
        protected_resource_metadata_path("/secure/mcp")
        == "/.well-known/oauth-protected-resource/secure/mcp"
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_rejects_empty_app_map():
    with pytest.raises(ValueError, match="at least one app"):
        PathRouter({}, fallback="/mcp")


def test_rejects_fallback_not_among_apps():
    with pytest.raises(ValueError, match="not among the routed paths"):
        PathRouter({"/secure/mcp": FakeApp("s")}, fallback="/mcp")


@pytest.mark.parametrize("bad", ["secure/mcp", "/secure/mcp/", ""])
def test_rejects_paths_that_could_never_match(bad):
    with pytest.raises(ValueError, match="must start with '/'"):
        PathRouter({bad: FakeApp("s")}, fallback=bad)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,expected",
    [
        ("/secure/mcp", "secure"),
        ("/emb3d/mcp", "emb3d"),
        ("/mcp", "alias"),
        ("/.well-known/oauth-protected-resource/secure/mcp", "secure"),
        ("/.well-known/oauth-protected-resource/emb3d/mcp", "emb3d"),
        ("/.well-known/oauth-protected-resource/mcp", "alias"),
    ],
)
async def test_route_and_its_metadata_reach_the_same_child(path, expected):
    """The metadata has to come from the app that serves the route: it is the
    one whose provider was bound to that route's resource URL."""
    router, *apps = _router()
    await router(http_scope(path), noop_receive, noop_send)
    assert [app.name for app in apps if app.calls] == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/.well-known/oauth-authorization-server",
        "/authorize",
        "/token",
        "/register",
        "/auth/callback",
        "/consent",
        "/healthz",
        "/secure",
        "/secure/mcp/extra",
        "/",
    ],
)
async def test_everything_else_reaches_the_fallback(path):
    """The shared authorization server lives in every child, but only the
    fallback's copy is ever reached -- one authorization server per identity."""
    router, alias, secure, emb3d = _router()
    await router(http_scope(path), noop_receive, noop_send)
    assert len(alias.calls) == 1
    assert secure.calls == emb3d.calls == []


@pytest.mark.asyncio
async def test_trailing_slash_reaches_the_routes_child():
    """So Starlette in that child can redirect it, as it would without a router."""
    router, _, secure, _ = _router()
    await router(http_scope("/secure/mcp/"), noop_receive, noop_send)
    assert len(secure.calls) == 1


@pytest.mark.asyncio
async def test_root_path_is_not_part_of_the_match():
    router, _, secure, _ = _router()
    await router(
        http_scope("/prefix/secure/mcp", root_path="/prefix"), noop_receive, noop_send
    )
    assert len(secure.calls) == 1


@pytest.mark.asyncio
async def test_scope_is_passed_on_untouched():
    """Headers -- MCP-Protocol-Version among them -- and the path must reach the
    child exactly as they arrived."""
    router, _, secure, _ = _router()
    scope = http_scope("/secure/mcp")
    original = dict(scope)
    await router(scope, noop_receive, noop_send)
    assert secure.calls == [original]


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_every_child():
    router, *apps = _router()
    driver = LifespanDriver()

    await router({"type": "lifespan"}, driver.receive, driver.send)

    assert [m["type"] for m in driver.sent] == [
        "lifespan.startup.complete",
        "lifespan.shutdown.complete",
    ]
    for app in apps:
        assert app.events == ["startup", "shutdown"]


@pytest.mark.asyncio
async def test_nested_in_a_host_router_every_grandchild_starts():
    """Per hostname a path router, per path an app: the host router's lifespan
    has to reach all the way down, or a route's session manager never runs."""
    primary, *primary_apps = _router()
    alias, *alias_apps = _router()
    host_router = HostRouter(
        {"https://mcp.example.com": primary, "https://mcp.example.io": alias},
        canonical_base_url="https://mcp.example.com",
    )
    driver = LifespanDriver()

    await host_router({"type": "lifespan"}, driver.receive, driver.send)

    assert driver.sent[-1]["type"] == "lifespan.shutdown.complete"
    for app in [*primary_apps, *alias_apps]:
        assert app.events == ["startup", "shutdown"]


@pytest.mark.asyncio
async def test_failing_child_startup_reports_failure_and_unwinds():
    class ExplodingApp(FakeApp):
        def lifespan(self, app):
            @asynccontextmanager
            async def _cm():
                raise RuntimeError("session manager unavailable")
                yield  # pragma: no cover - unreachable, satisfies the CM shape

            return _cm()

    healthy = FakeApp("healthy")
    router = PathRouter({"/mcp": healthy, "/x/mcp": ExplodingApp("x")}, fallback="/mcp")
    driver = LifespanDriver()

    with pytest.raises(RuntimeError, match="session manager unavailable"):
        await router({"type": "lifespan"}, driver.receive, driver.send)

    assert driver.sent[-1]["type"] == "lifespan.startup.failed"
    assert healthy.events == ["startup", "shutdown"]
