"""End-to-end check that two hostnames really do advertise two identities.

The unit tests verify the wiring with mocks. This one exercises the actual
FastMCP stack: two live ASGI apps built over one server, routed by ``Host``, and
asked for their OAuth 2.0 protected-resource metadata. If FastMCP's ``base_url``
were request-derived, or if the router leaked one app's identity into the other,
these documents would come back identical -- which is exactly the failure the
whole design exists to prevent.
"""

import asyncio
from contextlib import asynccontextmanager

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from fastmcp.server.http import create_streamable_http_app

from authsome_mcp_proxy.host_router import HostRouter

PRIMARY = "https://mcp.example.io"
ALIAS = "https://mcp.example.com"

PRM_PATH = "/.well-known/oauth-protected-resource/mcp"


def _auth(base_url: str) -> InMemoryOAuthProvider:
    """A real ``OAuthProvider`` that reaches no IdP at construction.

    The identity plumbing under test -- protected-resource metadata,
    authorization-server metadata, the challenge on a protected route -- lives
    in the ``OAuthProvider`` base class, so this exercises the same code path as
    the Cognito provider the ANALYZE deployment uses, without a live user pool.
    """
    return InMemoryOAuthProvider(base_url=base_url)


@pytest.fixture
def router():
    server = FastMCP(name="test-proxy")

    @server.tool()
    def ping() -> str:
        return "pong"

    apps = {
        base_url: create_streamable_http_app(
            server=server,
            streamable_http_path="/mcp",
            auth=_auth(base_url),
        )
        for base_url in (PRIMARY, ALIAS)
    }
    return HostRouter(apps, canonical_base_url=PRIMARY)


async def _get(router, path, host=None):
    headers = {"Host": host} if host else {}
    transport = httpx2.ASGITransport(app=router)
    async with httpx2.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        return await client.get(path, headers=headers)


@pytest.mark.asyncio
async def test_each_host_advertises_itself_as_the_resource(router):
    """The decisive property: a client that reached the alias hostname is never
    handed the primary hostname to continue its OAuth flow with."""
    primary = (await _get(router, PRM_PATH, "mcp.example.io")).json()
    alias = (await _get(router, PRM_PATH, "mcp.example.com")).json()

    assert primary["resource"] == f"{PRIMARY}/mcp"
    assert primary["authorization_servers"] == [f"{PRIMARY}/"]

    assert alias["resource"] == f"{ALIAS}/mcp"
    assert alias["authorization_servers"] == [f"{ALIAS}/"]

    # Nothing from the primary identity bleeds into the alias document.
    assert "example.io" not in str(alias)


@pytest.mark.asyncio
async def test_authorization_server_metadata_is_per_host(router):
    """Discovery continues on whichever host the client arrived at, so the
    authorize/token endpoints must be on that host too -- otherwise a client
    blocked from the primary domain still cannot complete the flow."""
    primary = (
        await _get(router, "/.well-known/oauth-authorization-server", "mcp.example.io")
    ).json()
    alias = (
        await _get(router, "/.well-known/oauth-authorization-server", "mcp.example.com")
    ).json()

    assert primary["issuer"].rstrip("/") == PRIMARY
    assert primary["authorization_endpoint"].startswith(PRIMARY)
    assert primary["token_endpoint"].startswith(PRIMARY)

    assert alias["issuer"].rstrip("/") == ALIAS
    assert alias["authorization_endpoint"].startswith(ALIAS)
    assert alias["token_endpoint"].startswith(ALIAS)


@pytest.mark.asyncio
async def test_unknown_host_gets_the_canonical_identity(router):
    """Health probes address the pod IP. They must reach a working app, and the
    one they reach is the canonical identity rather than an arbitrary one."""
    body = (await _get(router, PRM_PATH, "10.0.1.7")).json()
    assert body["resource"] == f"{PRIMARY}/mcp"


@pytest.mark.asyncio
async def test_protected_endpoint_challenges_with_its_own_metadata_url(router):
    """The 401 is what bootstraps discovery: it points the client at the
    resource metadata of the host it actually contacted."""
    transport = httpx2.ASGITransport(app=router)
    async with httpx2.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/mcp",
            headers={"Host": "mcp.example.com", "Accept": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert f"{ALIAS}{PRM_PATH}" in challenge
    assert "example.io" not in challenge


# ---------------------------------------------------------------------------
# Lifespan reaches the session manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def running(app):
    """Drive the ASGI lifespan protocol for real, in a background task.

    ``httpx2.ASGITransport`` never sends lifespan events, so the tests above
    exercise routing and metadata only — they would still pass if the router
    started no child at all. A request that gets past auth needs the child's
    StreamableHTTPSessionManager, which exists only if its lifespan ran.
    """
    inbox: asyncio.Queue = asyncio.Queue()
    started, finished = asyncio.Event(), asyncio.Event()

    async def send(message):
        if message["type"] == "lifespan.startup.complete":
            started.set()
        elif message["type"] == "lifespan.shutdown.complete":
            finished.set()
        elif message["type"].endswith(".failed"):
            raise AssertionError(f"lifespan failed: {message}")

    task = asyncio.create_task(app({"type": "lifespan"}, inbox.get, send))
    await inbox.put({"type": "lifespan.startup"})
    await asyncio.wait_for(started.wait(), timeout=10)
    try:
        yield
    finally:
        await inbox.put({"type": "lifespan.shutdown"})
        await asyncio.wait_for(finished.wait(), timeout=10)
        await task


@pytest.mark.asyncio
async def test_every_host_serves_a_live_mcp_session():
    """Each child app must have its own started session manager, on every
    hostname -- not just the canonical one whose lifespan might have run by
    accident."""
    server = FastMCP(name="test-proxy")

    @server.tool()
    def ping() -> str:
        return "pong"

    # No auth here: this test is about the transport being live, and the 401
    # test above already covers the auth boundary.
    apps = {
        base_url: create_streamable_http_app(server=server, streamable_http_path="/mcp")
        for base_url in (PRIMARY, ALIAS)
    }
    router = HostRouter(apps, canonical_base_url=PRIMARY)

    async with running(router):
        for host in ("mcp.example.io", "mcp.example.com"):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=router),
                base_url="http://testserver",
            ) as client:
                response = await client.post(
                    "/mcp",
                    headers={
                        "Host": host,
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1"},
                        },
                    },
                )

            assert response.status_code == 200, (host, response.text)
            assert response.headers.get("mcp-session-id"), host
