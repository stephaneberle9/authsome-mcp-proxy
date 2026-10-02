from contextlib import asynccontextmanager, contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.middleware import Middleware

from authsome_mcp_proxy import mcp_proxy
from authsome_mcp_proxy.config import DesktopConfig, UpstreamRoute, WebConfig
from authsome_mcp_proxy.upstream_identity import UpstreamIdentityMiddleware

# ---------------------------------------------------------------------------
# Desktop (stdio) mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_async_desktop_relays_server_info():
    """Desktop mode connects once to relay upstream name/version/etc., then
    creates a fresh disconnected client for create_proxy. Transport is stdio."""
    upstream_url = "http://upstream:8080"
    desktop_config = DesktopConfig(
        issuer_url="https://auth.example.com", client_id="test-client"
    )

    with patch("authsome_mcp_proxy.mcp_proxy.ExternalOIDCAuth"):
        with patch("authsome_mcp_proxy.mcp_proxy.Client") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client

            # Shaped like mcp 2's Implementation: snake_case attributes, plus
            # fields create_proxy does not accept, which must not leak through.
            mock_client.server_info = SimpleNamespace(
                name="BackendServer",
                version="1.2.3",
                website_url="https://example.com",
                icons=[{"uri": "https://example.com/icon.png", "type": "image/png"}],
                title="Some Title",
                custom_info_prop="info-value",
            )
            mock_client.instructions = "Test instructions"
            mock_client_cls.return_value = mock_client

            with patch(
                "authsome_mcp_proxy.mcp_proxy.create_proxy"
            ) as mock_create_proxy:
                mock_proxy_server = AsyncMock()
                mock_create_proxy.return_value = mock_proxy_server

                await mcp_proxy.run_async(
                    upstream_url, desktop_config, show_banner=False
                )

                # create_proxy was called with the relayed (filtered) properties
                mock_create_proxy.assert_called_once()
                call_args = mock_create_proxy.call_args
                assert call_args.args[0] == mock_client
                call_kwargs = call_args.kwargs
                assert call_kwargs["name"] == "BackendServer"
                assert call_kwargs["version"] == "1.2.3"
                assert call_kwargs["instructions"] == "Test instructions"
                assert call_kwargs["website_url"] == "https://example.com"
                assert call_kwargs["icons"] == [
                    {"uri": "https://example.com/icon.png", "type": "image/png"}
                ]

                # Unknown props are filtered out so create_proxy doesn't TypeError
                assert "title" not in call_kwargs
                assert "custom_info_prop" not in call_kwargs
                # Desktop mode never passes auth= to the FastMCP proxy server
                assert "auth" not in call_kwargs

                # run_async on the proxy is called with transport="stdio"
                mock_proxy_server.run_async.assert_called_once_with(
                    transport="stdio",
                    show_banner=False,
                )


@pytest.mark.asyncio
async def test_run_async_desktop_uses_fresh_proxy_client():
    """create_proxy receives a fresh disconnected client (not the connected info
    client), so each incoming MCP session gets an isolated upstream connection."""
    upstream_url = "http://upstream:8080"
    desktop_config = DesktopConfig(
        issuer_url="https://auth.example.com", client_id="test-client"
    )

    with patch("authsome_mcp_proxy.mcp_proxy.ExternalOIDCAuth"):
        with patch("authsome_mcp_proxy.mcp_proxy.Client") as mock_client_cls:
            info_client = AsyncMock()
            info_client.__aenter__.return_value = info_client
            # Named, so no second relay connection falls back to the handshake.
            info_client.server_info = SimpleNamespace(
                name="BackendServer", version=None, website_url=None, icons=None
            )
            info_client.instructions = None

            proxy_client = AsyncMock()

            # First Client(...) call → info connection; second → disconnected proxy client.
            mock_client_cls.side_effect = [info_client, proxy_client]

            with patch(
                "authsome_mcp_proxy.mcp_proxy.create_proxy"
            ) as mock_create_proxy:
                mock_proxy_server = AsyncMock()
                mock_create_proxy.return_value = mock_proxy_server

                await mcp_proxy.run_async(
                    upstream_url, desktop_config, show_banner=False
                )

                assert mock_client_cls.call_count == 2
                received_client = mock_create_proxy.call_args.args[0]
                assert received_client is proxy_client
                assert received_client is not info_client


def _connected_client(server_info, instructions):
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.server_info = server_info
    client.instructions = instructions
    return client


@pytest.mark.asyncio
async def test_relay_falls_back_to_the_handshake_when_discover_has_no_name():
    """Quarkus MCP Server 2.0.0 answers server/discover with serverInfo at the
    top level instead of in _meta, so the MCP SDK sees no identity on the
    modern protocol. A second connection pinned to the initialize handshake
    must supply name and version, while the modern connection's instructions
    stay."""
    modern = _connected_client(None, "modern instructions")
    legacy = _connected_client(
        SimpleNamespace(
            name="secure-repository-mcp",
            version="1.0.0",
            website_url=None,
            icons=None,
        ),
        "legacy instructions",
    )

    with patch(
        "authsome_mcp_proxy.mcp_proxy.Client", side_effect=[modern, legacy]
    ) as mock_client_cls:
        relayed = await mcp_proxy._relay_upstream_identity(
            "http://upstream", MagicMock()
        )

    assert mock_client_cls.call_args_list[1].kwargs["mode"] == "legacy"
    assert relayed == {
        "name": "secure-repository-mcp",
        "version": "1.0.0",
        "instructions": "modern instructions",
    }


@pytest.mark.asyncio
async def test_relay_keeps_what_it_has_when_the_handshake_fails(caplog):
    """An upstream that only speaks the modern protocol rejects initialize. The
    identity is cosmetic, so the proxy must still start, and say why it runs
    under a generated name."""
    modern = _connected_client(None, "modern instructions")
    failing = AsyncMock()
    failing.__aenter__.side_effect = RuntimeError("Client failed to connect")

    with patch("authsome_mcp_proxy.mcp_proxy.Client", side_effect=[modern, failing]):
        relayed = await mcp_proxy._relay_upstream_identity(
            "http://upstream", MagicMock()
        )

    assert relayed == {"instructions": "modern instructions"}
    assert "generated server name" in caplog.text


# ---------------------------------------------------------------------------
# Web (http) mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_async_web_wires_outbound_auth_and_defers_serving():
    """Web mode skips the info-relay step and attaches outbound auth to the
    per-session Client. Inbound auth is deliberately *not* passed to
    create_proxy: it is per-hostname and built inside _serve_http, so the
    shared server must not carry one identity of its own."""
    upstream_url = "http://upstream:8080"
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
    )

    sentinel_outbound = MagicMock(name="outbound_auth")

    with (
        patch(
            "authsome_mcp_proxy.mcp_proxy.build_outbound_auth",
            return_value=sentinel_outbound,
        ) as mock_build_outbound,
        patch("authsome_mcp_proxy.mcp_proxy.Client") as mock_client_cls,
        patch("authsome_mcp_proxy.mcp_proxy.create_proxy") as mock_create_proxy,
        patch(
            "authsome_mcp_proxy.mcp_proxy._serve_http", new_callable=AsyncMock
        ) as mock_serve,
    ):
        proxy_client = AsyncMock()
        mock_client_cls.return_value = proxy_client

        mock_proxy_server = MagicMock()
        mock_create_proxy.return_value = mock_proxy_server

        await mcp_proxy.run_async(upstream_url, web_config, show_banner=False)

        mock_build_outbound.assert_called_once_with(web_config)

        # The (single) Client was built with auth=outbound_auth (no info-relay
        # connection in web mode).
        assert mock_client_cls.call_count == 1
        client_kwargs = mock_client_cls.call_args.kwargs
        assert client_kwargs["auth"] is sentinel_outbound

        # create_proxy received that client and no inbound auth.
        mock_create_proxy.assert_called_once()
        cp_args = mock_create_proxy.call_args
        assert cp_args.args[0] is proxy_client
        assert "auth" not in cp_args.kwargs
        # No server-identity kwargs leak through when none were configured;
        # FastMCP's defaults apply.
        assert "name" not in cp_args.kwargs
        assert "version" not in cp_args.kwargs
        assert "instructions" not in cp_args.kwargs
        assert "website_url" not in cp_args.kwargs

        # The upstream's identity is relayed per handshake instead, by a
        # middleware that only fills the fields the operator left unset.
        mock_proxy_server.add_middleware.assert_called_once()
        middleware = mock_proxy_server.add_middleware.call_args.args[0]
        assert isinstance(middleware, UpstreamIdentityMiddleware)
        assert middleware._relayed_fields == ("instructions", "website_url", "icons")

        mock_serve.assert_called_once_with(mock_proxy_server, web_config, False)


@pytest.mark.asyncio
async def test_run_async_web_forwards_server_identity_kwargs():
    """Operator-configured proxy_name/version/instructions/website_url land on
    create_proxy as the matching kwargs, so the proxy advertises them to
    downstream MCP clients instead of FastMCP's auto-generated name."""
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
        proxy_name="ANALYZE",
        proxy_version="2.3.0",
        proxy_instructions="Use these tools for traceability analysis.",
        proxy_website_url="https://analyze.example.com",
    )

    with (
        patch(
            "authsome_mcp_proxy.mcp_proxy.build_outbound_auth", return_value=MagicMock()
        ),
        patch("authsome_mcp_proxy.mcp_proxy.Client"),
        patch("authsome_mcp_proxy.mcp_proxy.create_proxy") as mock_create_proxy,
        patch("authsome_mcp_proxy.mcp_proxy._serve_http", new_callable=AsyncMock),
    ):
        mock_proxy_server = MagicMock()
        mock_create_proxy.return_value = mock_proxy_server

        await mcp_proxy.run_async("http://upstream:8080", web_config, show_banner=False)

        cp_kwargs = mock_create_proxy.call_args.kwargs
        assert cp_kwargs["name"] == "ANALYZE"
        assert cp_kwargs["version"] == "2.3.0"
        assert cp_kwargs["instructions"] == "Use these tools for traceability analysis."
        assert cp_kwargs["website_url"] == "https://analyze.example.com"


@pytest.mark.asyncio
async def test_run_async_web_omits_unset_server_identity_kwargs():
    """When only some server-identity fields are set, only those are passed."""
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
        proxy_name="ANALYZE",  # only this one set
    )

    with (
        patch(
            "authsome_mcp_proxy.mcp_proxy.build_outbound_auth", return_value=MagicMock()
        ),
        patch("authsome_mcp_proxy.mcp_proxy.Client"),
        patch("authsome_mcp_proxy.mcp_proxy.create_proxy") as mock_create_proxy,
        patch("authsome_mcp_proxy.mcp_proxy._serve_http", new_callable=AsyncMock),
    ):
        mock_proxy_server = MagicMock()
        mock_create_proxy.return_value = mock_proxy_server

        await mcp_proxy.run_async("http://upstream:8080", web_config, show_banner=False)

        cp_kwargs = mock_create_proxy.call_args.kwargs
        assert cp_kwargs["name"] == "ANALYZE"
        assert "version" not in cp_kwargs
        assert "instructions" not in cp_kwargs
        assert "website_url" not in cp_kwargs


@pytest.mark.asyncio
async def test_run_async_web_forwards_transport_kwargs():
    """host/port/log_level transport_kwargs reach the serving layer verbatim."""
    upstream_url = "http://upstream:8080"
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
    )

    with (
        patch(
            "authsome_mcp_proxy.mcp_proxy.build_outbound_auth", return_value=MagicMock()
        ),
        patch("authsome_mcp_proxy.mcp_proxy.Client"),
        patch("authsome_mcp_proxy.mcp_proxy.create_proxy") as mock_create_proxy,
        patch(
            "authsome_mcp_proxy.mcp_proxy._serve_http", new_callable=AsyncMock
        ) as mock_serve,
    ):
        mock_proxy_server = MagicMock()
        mock_create_proxy.return_value = mock_proxy_server

        await mcp_proxy.run_async(
            upstream_url,
            web_config,
            show_banner=False,
            host="0.0.0.0",
            port=8000,
            log_level="DEBUG",
        )

        mock_serve.assert_called_once_with(
            mock_proxy_server,
            web_config,
            False,
            host="0.0.0.0",
            port=8000,
            log_level="DEBUG",
        )


# ---------------------------------------------------------------------------
# Unrecognised config type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_async_rejects_unknown_config_type():
    """Anything that's neither DesktopConfig nor WebConfig is a TypeError."""

    class NotAConfig:
        pass

    with pytest.raises(TypeError, match="Unsupported config type"):
        await mcp_proxy.run_async(
            "http://upstream:8080",
            NotAConfig(),  # ty: ignore[invalid-argument-type]
            show_banner=False,
        )


# ---------------------------------------------------------------------------
# Multi-hostname serving
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _noop_lifespan():
    yield


def _fake_server():
    """A stand-in FastMCP server whose reference-counted lifespan is a no-op."""
    server = MagicMock(name="mcp_proxy")
    server._lifespan_manager.side_effect = lambda: _noop_lifespan()
    return server


@contextmanager
def _serve_patches():
    """Patch the serving layer's collaborators: app factory, auth factory,
    host router and uvicorn. Yields them as a SimpleNamespace."""
    with (
        patch("authsome_mcp_proxy.mcp_proxy.create_streamable_http_app") as create_app,
        patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth") as build_inbound,
        patch("authsome_mcp_proxy.mcp_proxy.HostRouter") as host_router,
        patch("authsome_mcp_proxy.mcp_proxy.uvicorn") as uvicorn_mod,
    ):
        uvicorn_mod.Server.return_value.serve = AsyncMock()
        yield SimpleNamespace(
            create_app=create_app,
            build_inbound=build_inbound,
            host_router=host_router,
            uvicorn=uvicorn_mod,
        )


@pytest.mark.asyncio
async def test_serve_http_builds_one_identity_per_base_url():
    """Each configured hostname gets its own auth provider bound to its own base
    URL -- that is the whole reason a second hostname needs more than an extra
    ingress rule."""
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.io",
        additional_proxy_base_urls=["https://mcp.example.com"],
        issuer_url="https://kc.example.com/realms/r",
    )
    app_io, app_com = MagicMock(name="app_io"), MagicMock(name="app_com")
    auth_io, auth_com = MagicMock(name="auth_io"), MagicMock(name="auth_com")

    with _serve_patches() as mocks:
        mocks.create_app.side_effect = [app_io, app_com]
        mocks.build_inbound.side_effect = [auth_io, auth_com]

        await mcp_proxy._serve_http(_fake_server(), web_config, show_banner=False)

        assert [c.kwargs["base_url"] for c in mocks.build_inbound.call_args_list] == [
            "https://mcp.example.io",
            "https://mcp.example.com",
        ]
        assert [c.kwargs["auth"] for c in mocks.create_app.call_args_list] == [
            auth_io,
            auth_com,
        ]

        # Routing table is keyed by base URL, canonical first.
        router_args = mocks.host_router.call_args
        assert router_args.args[0] == {
            "https://mcp.example.io": app_io,
            "https://mcp.example.com": app_com,
        }
        assert router_args.kwargs["canonical_base_url"] == "https://mcp.example.io"


@pytest.mark.asyncio
async def test_serve_http_shares_one_server_across_identities():
    """The duplicated part is the front door only: every app is backed by the
    same FastMCP server, so the upstream client and tool catalog are not
    duplicated along with the identity."""
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.io",
        additional_proxy_base_urls=["https://mcp.example.com"],
        issuer_url="https://kc.example.com/realms/r",
    )
    server = _fake_server()

    with _serve_patches() as mocks:
        await mcp_proxy._serve_http(server, web_config, show_banner=False)

    assert mocks.create_app.call_count == 2
    assert {id(c.kwargs["server"]) for c in mocks.create_app.call_args_list} == {
        id(server)
    }


@pytest.mark.asyncio
async def test_serve_http_single_host_builds_exactly_one_app():
    """No additional base URLs means one app and one identity -- the previous
    single-hostname behaviour, reached through the same code path."""
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
    )

    with _serve_patches() as mocks:
        await mcp_proxy._serve_http(_fake_server(), web_config, show_banner=False)

    assert mocks.create_app.call_count == 1
    assert mocks.build_inbound.call_args.kwargs["base_url"] == "https://mcp.example.com"
    assert list(mocks.host_router.call_args.args[0]) == ["https://mcp.example.com"]


@pytest.mark.asyncio
async def test_serve_http_passes_host_and_port_to_uvicorn():
    web_config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
    )

    with _serve_patches() as mocks:
        await mcp_proxy._serve_http(
            _fake_server(),
            web_config,
            show_banner=False,
            host="0.0.0.0",
            port=8000,
        )

    config_kwargs = mocks.uvicorn.Config.call_args.kwargs
    assert config_kwargs["host"] == "0.0.0.0"
    assert config_kwargs["port"] == 8000
    assert mocks.uvicorn.Config.call_args.args[0] is mocks.host_router.return_value
    mocks.uvicorn.Server.return_value.serve.assert_awaited_once()


# ---------------------------------------------------------------------------
# Several upstreams
# ---------------------------------------------------------------------------


def _multi_config(**overrides) -> WebConfig:
    kwargs: dict[str, Any] = {
        "inbound_auth_provider": "keycloak",
        "proxy_base_url": "https://mcp.example.com",
        "issuer_url": "https://kc.example.com/realms/r",
        "upstreams": [
            UpstreamRoute(name="secure", mcp_url="http://secure/mcp"),
            UpstreamRoute(
                name="emb3d",
                mcp_url="http://emb3d/mcp",
                outbound_auth="none",
                proxy_name="EMB3D",
                proxy_instructions="Look up threats here.",
            ),
        ],
        "default_upstream": "secure",
    }
    kwargs.update(overrides)
    return WebConfig(**kwargs)


@pytest.mark.asyncio
async def test_run_async_web_builds_one_proxy_per_upstream():
    """Each route gets its own upstream client, outbound auth and identity --
    nothing of one route's backend is shared with another's."""
    config = _multi_config()
    secure_auth, emb3d_auth = MagicMock(name="secure_auth"), MagicMock(name="emb3d")
    secure_server, emb3d_server = MagicMock(name="secure"), MagicMock(name="emb3d")

    with (
        patch(
            "authsome_mcp_proxy.mcp_proxy.build_outbound_auth",
            side_effect=[secure_auth, emb3d_auth],
        ) as mock_build_outbound,
        patch("authsome_mcp_proxy.mcp_proxy.Client") as mock_client_cls,
        patch(
            "authsome_mcp_proxy.mcp_proxy.create_proxy",
            side_effect=[secure_server, emb3d_server],
        ) as mock_create_proxy,
        patch(
            "authsome_mcp_proxy.mcp_proxy._serve_http", new_callable=AsyncMock
        ) as mock_serve,
    ):
        await mcp_proxy.run_async(None, config, show_banner=False)

    assert [c.args[0] for c in mock_build_outbound.call_args_list] == config.upstreams
    assert [
        (c.kwargs["transport"], c.kwargs["auth"])
        for c in mock_client_cls.call_args_list
    ] == [("http://secure/mcp", secure_auth), ("http://emb3d/mcp", emb3d_auth)]
    assert [c.kwargs for c in mock_create_proxy.call_args_list] == [
        {},
        {"name": "EMB3D", "instructions": "Look up threats here."},
    ]
    for server in (secure_server, emb3d_server):
        server.add_middleware.assert_called_once()
    mock_serve.assert_called_once_with(
        {"secure": secure_server, "emb3d": emb3d_server}, config, False
    )


@pytest.mark.asyncio
async def test_run_async_rejects_a_single_url_alongside_upstreams():
    with pytest.raises(ValueError, match="mutually exclusive"):
        await mcp_proxy.run_async("http://single/mcp", _multi_config(), False)


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [None, ""])
async def test_run_async_requires_an_upstream(url):
    with pytest.raises(ValueError, match="upstream_url is required"):
        await mcp_proxy.run_async(url, _web_config(), False)


@contextmanager
def _multi_serve_patches():
    """_serve_patches plus the two multi-upstream collaborators."""
    with (
        _serve_patches() as mocks,
        patch("authsome_mcp_proxy.mcp_proxy.PathRouter") as path_router,
        patch("authsome_mcp_proxy.mcp_proxy.share_authorization_server") as share,
    ):
        mocks.path_router = path_router
        mocks.share = share
        yield mocks


def _route_servers():
    return {"secure": _fake_server(), "emb3d": _fake_server()}


@pytest.mark.asyncio
async def test_serve_http_shares_one_provider_across_an_identitys_routes():
    """One authorization server per identity: every route's app is built over
    the same provider, which is then widened to all of their resources."""
    servers = _route_servers()

    with _multi_serve_patches() as mocks:
        await mcp_proxy._serve_http(servers, _multi_config(), show_banner=False)

    mocks.build_inbound.assert_called_once()
    provider = mocks.build_inbound.return_value
    calls = mocks.create_app.call_args_list
    assert [c.kwargs["streamable_http_path"] for c in calls] == [
        "/mcp",
        "/secure/mcp",
        "/emb3d/mcp",
    ]
    assert [c.kwargs["server"] for c in calls] == [
        servers["secure"],
        servers["secure"],
        servers["emb3d"],
    ]
    assert {id(c.kwargs["auth"]) for c in calls} == {id(provider)}

    mocks.share.assert_called_once_with(
        provider,
        [
            "https://mcp.example.com/mcp",
            "https://mcp.example.com/secure/mcp",
            "https://mcp.example.com/emb3d/mcp",
        ],
    )
    router_args = mocks.path_router.call_args
    assert list(router_args.args[0]) == ["/mcp", "/secure/mcp", "/emb3d/mcp"]
    assert router_args.kwargs["fallback"] == "/mcp"
    assert mocks.host_router.call_args.args[0] == {
        "https://mcp.example.com": mocks.path_router.return_value
    }


@pytest.mark.asyncio
async def test_serve_http_without_default_upstream_serves_routes_only():
    """No /mcp alias; the first upstream's route answers everything else."""
    with _multi_serve_patches() as mocks:
        await mcp_proxy._serve_http(
            _route_servers(), _multi_config(default_upstream=None), show_banner=False
        )

    assert [
        c.kwargs["streamable_http_path"] for c in mocks.create_app.call_args_list
    ] == ["/secure/mcp", "/emb3d/mcp"]
    assert mocks.path_router.call_args.kwargs["fallback"] == "/secure/mcp"


@pytest.mark.asyncio
async def test_serve_http_builds_one_identity_per_hostname_over_all_routes():
    config = _multi_config(additional_proxy_base_urls=["https://mcp.example.io"])
    auth_com, auth_io = MagicMock(name="auth_com"), MagicMock(name="auth_io")

    with _multi_serve_patches() as mocks:
        mocks.build_inbound.side_effect = [auth_com, auth_io]
        await mcp_proxy._serve_http(_route_servers(), config, show_banner=False)

    auths = [c.kwargs["auth"] for c in mocks.create_app.call_args_list]
    assert auths == [auth_com] * 3 + [auth_io] * 3
    assert [c.args for c in mocks.share.call_args_list] == [
        (
            auth_com,
            [
                f"https://mcp.example.com{p}"
                for p in ("/mcp", "/secure/mcp", "/emb3d/mcp")
            ],
        ),
        (
            auth_io,
            [
                f"https://mcp.example.io{p}"
                for p in ("/mcp", "/secure/mcp", "/emb3d/mcp")
            ],
        ),
    ]
    assert list(mocks.host_router.call_args.args[0]) == [
        "https://mcp.example.com",
        "https://mcp.example.io",
    ]


@pytest.mark.asyncio
async def test_serve_http_path_moves_the_default_upstreams_alias():
    with _multi_serve_patches() as mocks:
        await mcp_proxy._serve_http(
            _route_servers(), _multi_config(), False, path="/legacy"
        )

    assert mocks.create_app.call_args_list[0].kwargs["streamable_http_path"] == (
        "/legacy"
    )


@pytest.mark.asyncio
async def test_serve_http_rejects_an_alias_colliding_with_a_route():
    with _multi_serve_patches():
        with pytest.raises(ValueError, match="already the route"):
            await mcp_proxy._serve_http(
                _route_servers(), _multi_config(), False, path="/emb3d/mcp"
            )


@pytest.mark.asyncio
async def test_serve_http_enters_every_route_servers_lifespan_once():
    """The default upstream backs two routes but is still one server."""
    servers = _route_servers()

    with _multi_serve_patches():
        await mcp_proxy._serve_http(servers, _multi_config(), show_banner=False)

    for server in servers.values():
        server._lifespan_manager.assert_called_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("several", [False, True])
async def test_serve_http_shows_the_banner_only_for_one_server(several):
    """The banner names a single server; with several it would name one of
    them as if it were the whole proxy."""
    single_config = _multi_config(
        upstreams=[UpstreamRoute(name="secure", mcp_url="http://secure/mcp")]
    )
    servers = _route_servers() if several else {"secure": _fake_server()}
    config = _multi_config() if several else single_config

    with (
        _multi_serve_patches(),
        patch("fastmcp.utilities.cli.log_server_banner") as banner,
    ):
        await mcp_proxy._serve_http(servers, config, show_banner=True)

    assert banner.called is not several


@pytest.mark.asyncio
async def test_serve_http_with_one_route_needs_no_path_router():
    """One upstream without the /mcp alias is a single route, served as before."""
    config = _multi_config(
        upstreams=[UpstreamRoute(name="secure", mcp_url="http://secure/mcp")],
        default_upstream=None,
    )
    with _multi_serve_patches() as mocks:
        await mcp_proxy._serve_http(
            {"secure": _fake_server()}, config, show_banner=False
        )

    mocks.path_router.assert_not_called()
    mocks.share.assert_not_called()
    assert mocks.host_router.call_args.args[0] == {
        "https://mcp.example.com": mocks.create_app.return_value
    }


# ---------------------------------------------------------------------------
# The transport_kwargs passthrough contract
# ---------------------------------------------------------------------------


class _NoopMiddleware:
    """Minimal ASGI middleware, used only as an identity sentinel."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)


SENTINEL_MIDDLEWARE = [Middleware(_NoopMiddleware)]


def _web_config(**overrides):
    return WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
        **overrides,
    )


@pytest.mark.asyncio
async def test_serve_http_honours_the_full_fastmcp_keyword_surface():
    """These reached FastMCP's run_http_async before the host router existed;
    dropping them would have quietly ignored an operator's explicit setting."""
    with _serve_patches() as mocks:
        await mcp_proxy._serve_http(
            _fake_server(),
            _web_config(),
            False,
            path="/custom",
            json_response=True,
            stateless_http=True,
            middleware=SENTINEL_MIDDLEWARE,
        )

    kwargs = mocks.create_app.call_args.kwargs
    assert kwargs["streamable_http_path"] == "/custom"
    assert kwargs["json_response"] is True
    assert kwargs["stateless_http"] is True
    assert kwargs["middleware"] is SENTINEL_MIDDLEWARE


@pytest.mark.asyncio
async def test_stateless_is_an_alias_for_stateless_http():
    """FastMCP's CLI spells it `stateless`; accept both rather than silently
    ignoring one of them."""
    with _serve_patches() as mocks:
        await mcp_proxy._serve_http(
            _fake_server(), _web_config(), False, stateless=True
        )

    assert mocks.create_app.call_args.kwargs["stateless_http"] is True


@pytest.mark.asyncio
async def test_explicit_stateless_http_wins_over_the_alias():
    with _serve_patches() as mocks:
        await mcp_proxy._serve_http(
            _fake_server(), _web_config(), False, stateless=True, stateless_http=False
        )

    assert mocks.create_app.call_args.kwargs["stateless_http"] is False


@pytest.mark.asyncio
async def test_uvicorn_config_merges_over_the_defaults():
    with _serve_patches() as mocks:
        await mcp_proxy._serve_http(
            _fake_server(),
            _web_config(),
            False,
            uvicorn_config={"timeout_graceful_shutdown": 30, "proxy_headers": True},
        )

    kwargs = mocks.uvicorn.Config.call_args.kwargs
    assert kwargs["timeout_graceful_shutdown"] == 30
    assert kwargs["proxy_headers"] is True
    assert kwargs["lifespan"] == "on"


@pytest.mark.asyncio
async def test_unknown_transport_kwarg_fails_at_startup():
    """An unrecognized keyword must not be swallowed: it would look like the
    setting took effect while the server ran with the default."""
    with _serve_patches():
        with pytest.raises(TypeError, match="not_a_real_option"):
            await mcp_proxy._serve_http(
                _fake_server(),
                _web_config(),
                False,
                not_a_real_option=True,  # ty: ignore[unknown-argument]
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config",
    [
        pytest.param(
            WebConfig(
                inbound_auth_provider="keycloak",
                proxy_base_url="https://mcp.example.com",
                issuer_url="https://kc.example.com/realms/r",
            ),
            id="web",
        ),
        pytest.param(
            DesktopConfig(
                issuer_url="https://auth.example.com", client_id="test-client"
            ),
            id="desktop",
        ),
    ],
)
async def test_transport_kwarg_is_rejected_in_both_modes(config):
    """The transport follows from the config type, so there is nothing to choose
    in either mode. Both branches splat transport_kwargs onto a call that already
    fixes the transport, so without this guard the caller gets "got multiple
    values for keyword argument 'transport'" naming a FastMCP function they never
    called."""
    with pytest.raises(ValueError, match="transport is not configurable"):
        await mcp_proxy.run_async(
            "http://upstream:8080", config, show_banner=False, transport="sse"
        )


@pytest.mark.asyncio
async def test_transport_is_rejected_before_any_connection_is_attempted():
    """Desktop mode dials the upstream to relay its serverInfo before it would
    ever reach the transport. The guard has to run first, or a plainly invalid
    call blocks on a network round trip before failing."""
    desktop_config = DesktopConfig(
        issuer_url="https://auth.example.com", client_id="test-client"
    )

    with (
        patch("authsome_mcp_proxy.mcp_proxy.ExternalOIDCAuth") as mock_auth,
        patch("authsome_mcp_proxy.mcp_proxy.Client") as mock_client_cls,
    ):
        with pytest.raises(ValueError, match="transport is not configurable"):
            await mcp_proxy.run_async(
                "http://upstream:8080",
                desktop_config,
                show_banner=False,
                transport="http",
            )

    mock_auth.assert_not_called()
    mock_client_cls.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["mcp_proxy", "config"])
async def test_serve_http_internals_cannot_be_shadowed_by_transport_kwargs(name):
    """mcp_proxy and config are positional-only, so a caller's **transport_kwargs
    can neither rebind them nor collide with them. Without the marker this would
    raise the far more puzzling "got multiple values for argument"."""
    with _serve_patches():
        with pytest.raises(TypeError, match="positional-only"):
            await mcp_proxy._serve_http(
                _fake_server(),
                _web_config(),
                False,
                **{name: "hijacked"},  # ty: ignore[invalid-argument-type]
            )


@pytest.mark.asyncio
async def test_relay_server_info_reads_a_modern_protocol_upstream():
    """Against a real FastMCP upstream, not a mock shaped like the old API.

    fastmcp 4 negotiates the modern protocol when the upstream supports it, and
    such a connection has no initialize handshake: ``initialize_result`` stays
    ``None``. Reading identity from there made the relay come back empty without
    any error, so the proxy showed up under FastMCP's generated name.
    """
    import httpx2
    from fastmcp import Client, FastMCP
    from fastmcp.client.transports import StreamableHttpTransport
    from fastmcp.server.http import create_streamable_http_app

    upstream = FastMCP(
        name="upstream-name", version="9.9.9", instructions="use me wisely"
    )
    app = create_streamable_http_app(server=upstream, streamable_http_path="/mcp")

    def client_factory(
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
        **kwargs,
    ) -> httpx2.AsyncClient:
        if timeout is not None:
            kwargs["timeout"] = timeout
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            headers=headers,
            auth=auth,
            **kwargs,
        )

    transport = StreamableHttpTransport(
        "http://testserver/mcp", httpx_client_factory=client_factory
    )
    async with app.router.lifespan_context(app), Client(transport) as client:
        relayed = mcp_proxy._relay_server_info(client)

    assert relayed == {
        "name": "upstream-name",
        "version": "9.9.9",
        "instructions": "use me wisely",
    }
