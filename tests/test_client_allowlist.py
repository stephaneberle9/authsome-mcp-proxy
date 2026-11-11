"""Tests for how the proxy configures and applies the client allowlist.

The allowlist itself -- entry syntax, prefix matching, the upstream
``client_id``'s redirect URIs -- is fastmcp-seaworthy's and tested there. What
remains here is the proxy's part: the CLI and env settings, carrying the list
on ``WebConfig``, applying it to the provider of every hostname, and saying at
startup what is in effect.

The serving tests go through :func:`authsome_mcp_proxy.mcp_proxy._serve_http`
with real ``OIDCProxy`` providers and talk to the resulting router over ASGI,
because what a client is told on the wire is the only thing that decides
whether it gets in.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fastmcp
import httpx2
import pytest
from fastmcp.server.auth.cimd import CIMDClientManager
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from fastmcp_seaworthy import ClientAllowlist

from authsome_mcp_proxy import __main__ as cli_main
from authsome_mcp_proxy import mcp_proxy
from authsome_mcp_proxy.config import WebConfig

ISSUER = "https://idp.example.com"
HOSTS = ("https://mcp.example.io", "https://mcp.example.com")

CLAUDE_PREFIX = "https://claude.ai/"
LISTED_CLIENT = "https://claude.ai/oauth/mcp-oauth-client-metadata"
UNLISTED_CLIENT = "https://client.example.net/oauth/client.json"

AS_METADATA_PATH = "/.well-known/oauth-authorization-server"

_HTTP_ARGS = [
    "http://upstream.example.com/mcp",
    "--transport",
    "http",
    "--proxy-base-url",
    "https://mcp.example.com",
    "--inbound-auth-provider",
    "oidc",
    "--oidc-issuer-url",
    ISSUER,
    "--oidc-client-id",
    "cid",
]

_ALLOWLIST_ENV = ("ALLOWED_CLIENT_IDS", "ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS")


def _config_from_cli(args: list[str]) -> WebConfig:
    with patch("sys.argv", ["authsome-mcp-proxy", *_HTTP_ARGS, *args]):
        config = cli_main.build_proxy_config(cli_main.cli())
    assert isinstance(config, WebConfig)
    return config


class TestCLI:
    """Each setting is an env var plus a CLI flag, the flag winning."""

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch: pytest.MonkeyPatch):
        for name in _ALLOWLIST_ENV:
            monkeypatch.delenv(name, raising=False)

    def test_default_is_no_allowlist(self):
        config = _config_from_cli([])
        assert config.client_allowlist == ClientAllowlist()
        assert config.client_allowlist.enabled is False

    def test_flags(self):
        config = _config_from_cli(
            [
                "--allowed-client-ids",
                f"{CLAUDE_PREFIX}, cid",
                "--allowed-upstream-client-redirect-uris",
                "http://localhost:* http://127.0.0.1:*",
            ]
        )
        assert config.client_allowlist == ClientAllowlist(
            client_ids=(CLAUDE_PREFIX, "cid"),
            upstream_client_redirect_uris=(
                "http://localhost:*",
                "http://127.0.0.1:*",
            ),
        )

    def test_env_vars(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ALLOWED_CLIENT_IDS", f"{CLAUDE_PREFIX}\ncid")
        monkeypatch.setenv(
            "ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS", "http://localhost:*"
        )

        config = _config_from_cli([])

        assert config.client_allowlist == ClientAllowlist(
            client_ids=(CLAUDE_PREFIX, "cid"),
            upstream_client_redirect_uris=("http://localhost:*",),
        )

    def test_flags_override_env_vars(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ALLOWED_CLIENT_IDS", "https://client.example.net/")

        config = _config_from_cli(["--allowed-client-ids", CLAUDE_PREFIX])

        assert config.client_allowlist.client_ids == (CLAUDE_PREFIX,)

    def test_a_malformed_entry_is_refused_at_startup(self):
        """A glob would also match a host anyone can register."""
        with pytest.raises(ValueError, match="ALLOWED_CLIENT_IDS entry 1"):
            _config_from_cli(["--allowed-client-ids", "https://claude.ai*"])


def _oidc_configuration() -> OIDCConfiguration:
    return OIDCConfiguration(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/jwks",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
    )


def _oidc_config(allowlist: ClientAllowlist | None = None) -> WebConfig:
    return WebConfig(
        inbound_auth_provider="oidc",
        proxy_base_url=HOSTS[0],
        additional_proxy_base_urls=list(HOSTS[1:]),
        issuer_url=ISSUER,
        client_id="cid",
        client_secret="csec",
        scopes="openid",
        client_allowlist=allowlist if allowlist is not None else ClientAllowlist(),
    )


@asynccontextmanager
async def _noop_lifespan():
    yield


def _fake_server():
    server = MagicMock(name="mcp_proxy")
    server._lifespan_manager.side_effect = lambda: _noop_lifespan()
    return server


Exercise = Callable[[Any], Awaitable[None]]


async def _serve(config: WebConfig, exercise: Exercise) -> None:
    """Run ``_serve_http`` and hand the router it would serve to ``exercise``.

    Everything is real except uvicorn: the providers are built by
    ``build_inbound_auth`` and wrapped by ``_serve_http``'s ``auth_for``, and
    fastmcp-seaworthy puts their apps behind its ``HostRouter``. In place of
    binding a port, ``exercise`` gets the ASGI app uvicorn was configured with.
    """

    with (
        patch.object(
            OIDCProxy, "get_oidc_configuration", return_value=_oidc_configuration()
        ),
        patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
    ):

        async def serve() -> None:
            await exercise(uvicorn_mod.Config.call_args.args[0])

        uvicorn_mod.Server.return_value.serve = AsyncMock(side_effect=serve)
        await mcp_proxy._serve_http(_fake_server(), config, show_banner=False)

    uvicorn_mod.Server.return_value.serve.assert_awaited_once()


def _client(app: Any, base_url: str) -> httpx2.AsyncClient:
    """A client whose ``Host`` header selects ``base_url``'s identity."""
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=base_url
    )


def _authorize_params(client_id: str) -> dict[str, str]:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        "code_challenge": "c" * 43,
        "code_challenge_method": "S256",
        "state": "state",
    }


_REGISTRATION = {
    "client_name": "A DCR client",
    "redirect_uris": ["http://localhost:8123/callback"],
}


@pytest.fixture(autouse=True)
def _isolated_fastmcp_home(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Keep the file store the real providers create out of the user's own."""
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path)


class TestAllowlistSet:
    """``ALLOWED_CLIENT_IDS=https://claude.ai/`` on a two-hostname proxy."""

    CONFIG_ALLOWLIST = ClientAllowlist(client_ids=(CLAUDE_PREFIX,))

    @pytest.mark.parametrize("base_url", HOSTS)
    async def test_unlisted_cimd_client_gets_invalid_client(self, base_url):
        """At the token endpoint, where OAuth has an ``invalid_client`` to give:
        the client can neither redeem a code nor refresh a token."""

        async def exercise(app: Any) -> None:
            async with _client(app, base_url) as client:
                response = await client.post(
                    "/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": "a-refresh-token",
                        "client_id": UNLISTED_CLIENT,
                    },
                )
            assert response.status_code == 401
            assert response.json()["error"] == "invalid_client"

        with patch.object(CIMDClientManager, "get_client", AsyncMock()) as fetch:
            await _serve(_oidc_config(self.CONFIG_ALLOWLIST), exercise)

        fetch.assert_not_awaited()

    @pytest.mark.parametrize("base_url", HOSTS)
    async def test_unlisted_cimd_client_cannot_start_a_sign_in(self, base_url):
        """``/authorize`` refuses it before its metadata document is fetched.

        FastMCP answers an unknown client there with ``invalid_request`` rather
        than ``invalid_client``; what matters is that no sign-in starts and the
        proxy makes no outbound request for a client that is not on the list.
        """

        async def exercise(app: Any) -> None:
            async with _client(app, base_url) as client:
                response = await client.get(
                    "/authorize", params=_authorize_params(UNLISTED_CLIENT)
                )
            assert response.status_code == 400
            assert "location" not in response.headers
            assert response.json()["error"] == "invalid_request"

        with patch.object(CIMDClientManager, "get_client", AsyncMock()) as fetch:
            await _serve(_oidc_config(self.CONFIG_ALLOWLIST), exercise)

        fetch.assert_not_awaited()

    @pytest.mark.parametrize("base_url", HOSTS)
    async def test_listed_cimd_client_is_looked_up(self, base_url):
        """The control for the two tests above: a client under the allowed
        prefix does reach the CIMD lookup they assert never happens."""

        async def exercise(app: Any) -> None:
            async with _client(app, base_url) as client:
                await client.get("/authorize", params=_authorize_params(LISTED_CLIENT))

        with patch.object(
            CIMDClientManager, "get_client", AsyncMock(return_value=None)
        ) as fetch:
            await _serve(_oidc_config(self.CONFIG_ALLOWLIST), exercise)

        fetch.assert_awaited_once_with(LISTED_CLIENT)

    @pytest.mark.parametrize("base_url", HOSTS)
    async def test_dcr_is_refused(self, base_url):
        """A DCR ``client_id`` is random, so it could never be on the list: the
        endpoint is gone and no longer advertised, on every hostname."""

        async def exercise(app: Any) -> None:
            async with _client(app, base_url) as client:
                metadata = (await client.get(AS_METADATA_PATH)).json()
                registration = await client.post("/register", json=_REGISTRATION)
            assert "registration_endpoint" not in metadata
            assert metadata["client_id_metadata_document_supported"] is True
            assert registration.status_code == 404

        await _serve(_oidc_config(self.CONFIG_ALLOWLIST), exercise)


class TestAllowlistUnset:
    """Nothing changes for a deployment that sets no allowlist."""

    @pytest.mark.parametrize("base_url", HOSTS)
    async def test_dcr_stays_open(self, base_url):
        async def exercise(app: Any) -> None:
            async with _client(app, base_url) as client:
                metadata = (await client.get(AS_METADATA_PATH)).json()
                registration = await client.post("/register", json=_REGISTRATION)
            assert metadata["registration_endpoint"] == f"{base_url}/register"
            assert registration.status_code == 201
            assert registration.json()["client_id"]

        await _serve(_oidc_config(), exercise)

    async def test_any_cimd_client_is_looked_up(self):
        async def exercise(app: Any) -> None:
            async with _client(app, HOSTS[0]) as client:
                await client.get(
                    "/authorize", params=_authorize_params(UNLISTED_CLIENT)
                )

        with patch.object(
            CIMDClientManager, "get_client", AsyncMock(return_value=None)
        ) as fetch:
            await _serve(_oidc_config(), exercise)

        fetch.assert_awaited_once_with(UNLISTED_CLIENT)

    async def test_providers_are_left_untouched(self):
        """``apply`` shadows ``get_client`` on the instance; unset, it must not."""
        providers = []

        async def exercise(app: Any) -> None:
            pass

        real = mcp_proxy.build_inbound_auth

        def build(*args: Any, **kwargs: Any):
            providers.append(real(*args, **kwargs))
            return providers[-1]

        with patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth", build):
            await _serve(_oidc_config(), exercise)

        assert len(providers) == len(HOSTS)
        for provider in providers:
            assert "get_client" not in vars(provider)
            assert "register_client" not in vars(provider)


class TestStartupLog:
    async def _log(self, caplog: pytest.LogCaptureFixture, config: WebConfig) -> str:
        async def exercise(app: Any) -> None:
            pass

        with caplog.at_level("INFO", logger="authsome_mcp_proxy.mcp_proxy"):
            await _serve(config, exercise)
        return caplog.text

    async def test_the_allowlist_is_named_once_for_all_hostnames(
        self, caplog: pytest.LogCaptureFixture
    ):
        text = await self._log(
            caplog, _oidc_config(ClientAllowlist(client_ids=(CLAUDE_PREFIX,)))
        )

        line = (
            f"OAuth clients limited to {CLAUDE_PREFIX}; "
            "dynamic client registration disabled"
        )
        assert text.count(line) == 1
        assert text.count("OAuth state in ") == 1

    async def test_an_unset_allowlist_is_named_too(
        self, caplog: pytest.LogCaptureFixture
    ):
        """Otherwise an allowlist that never reached the process -- a typo in
        the variable's name -- looks the same as one that did."""
        text = await self._log(caplog, _oidc_config())

        assert text.count("Every OAuth client accepted") == 1


class TestKeycloak:
    """There Keycloak is the authorization server: the proxy never sees a
    ``client_id`` to check, so the setting is inert, like the store settings."""

    def _config(self, allowlist: ClientAllowlist) -> WebConfig:
        return WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url=HOSTS[0],
            issuer_url="https://kc.example.com/realms/r",
            client_allowlist=allowlist,
        )

    async def _serve_keycloak(self, config: WebConfig) -> MagicMock:
        provider = MagicMock(name="KeycloakAuthProvider")
        with (
            patch(
                "authsome_mcp_proxy.mcp_proxy.build_inbound_auth",
                return_value=provider,
            ),
            patch("fastmcp_seaworthy.serve.create_streamable_http_app") as create_app,
            patch("fastmcp_seaworthy.serve.HostRouter"),
            patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock()
            await mcp_proxy._serve_http(_fake_server(), config, show_banner=False)
        assert create_app.call_args.kwargs["auth"] is provider
        return provider

    async def test_allowlist_is_not_applied_and_says_so(
        self, caplog: pytest.LogCaptureFixture
    ):
        config = self._config(ClientAllowlist(client_ids=(CLAUDE_PREFIX,)))

        with caplog.at_level("INFO", logger="authsome_mcp_proxy.mcp_proxy"):
            provider = await self._serve_keycloak(config)

        assert "get_client" not in vars(provider)
        assert "ALLOWED_CLIENT_IDS is not applied" in caplog.text
        assert "OAuth clients limited to" not in caplog.text

    async def test_nothing_is_logged_without_an_allowlist(
        self, caplog: pytest.LogCaptureFixture
    ):
        with caplog.at_level("INFO", logger="authsome_mcp_proxy.mcp_proxy"):
            await self._serve_keycloak(self._config(ClientAllowlist()))

        assert "ALLOWED_CLIENT_IDS" not in caplog.text
        assert "OAuth client" not in caplog.text
