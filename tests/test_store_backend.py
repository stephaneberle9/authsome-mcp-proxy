"""Tests for how the proxy configures and wires the OAuth proxy's state store.

The store itself -- encryption, key derivation, DynamoDB, what survives a
restart -- is fastmcp-seaworthy's and tested there. What remains here is the
proxy's part: the CLI and env settings, ``WebConfig.oauth_state``, and handing
signing key and store to every provider and hostname.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp_seaworthy import OAuthStateSettings, build_client_storage

from authsome_mcp_proxy import __main__ as cli_main
from authsome_mcp_proxy import mcp_proxy
from authsome_mcp_proxy.config import WebConfig
from authsome_mcp_proxy.inbound_auth import build_inbound_auth

SIGNING_KEY = "a-signing-key-shared-by-every-replica"


def _oidc_config(**overrides: Any) -> WebConfig:
    values: dict[str, Any] = {
        "inbound_auth_provider": "oidc",
        "proxy_base_url": "https://mcp.example.com",
        "issuer_url": "https://idp.example.com",
        "client_id": "cid",
        "client_secret": "csec",
    }
    values.update(overrides)
    return WebConfig(**values)


def _dynamodb_config(table: str = "oauth-state", **overrides) -> WebConfig:
    return _oidc_config(
        jwt_signing_key=SIGNING_KEY,
        store_backend="dynamodb",
        store_dynamodb_table=table,
        **overrides,
    )


class TestOAuthState:
    """``WebConfig.oauth_state`` is what reaches fastmcp-seaworthy."""

    def test_default_is_fastmcps_file_store(self):
        """No store is built, so FastMCP keeps its own encrypted file store."""
        settings = _oidc_config().oauth_state
        assert settings is not None
        assert settings == OAuthStateSettings()
        assert build_client_storage(settings) is None

    def test_every_setting_is_carried_over(self):
        settings = _dynamodb_config(
            store_dynamodb_region="eu-west-1", store_dynamodb_auto_create=True
        ).oauth_state
        assert settings == OAuthStateSettings(
            jwt_signing_key=SIGNING_KEY,
            store_backend="dynamodb",
            store_dynamodb_table="oauth-state",
            store_dynamodb_region="eu-west-1",
            store_dynamodb_auto_create=True,
        )

    def test_keycloak_has_none(self):
        """Keycloak is the authorization server there; the proxy keeps no OAuth
        state, so a selected backend is inert rather than connected to."""
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            store_backend="dynamodb",
        )
        assert config.oauth_state is None


class TestProviderWiring:
    """The signing key and store reach every OIDCProxy-based provider -- and
    only when set, so an unconfigured deployment builds them exactly as
    before."""

    @pytest.mark.parametrize(
        ("provider", "patched", "extra"),
        [
            (
                "oidc",
                "OIDCProxy",
                {"issuer_url": "https://idp.example.com", "client_id": "cid"},
            ),
            (
                "aws-cognito",
                "AWSCognitoProvider",
                {
                    "client_id": "cid",
                    "client_secret": "csec",
                    "cognito_user_pool_id": "eu-central-1_abc",
                    "cognito_aws_region": "eu-central-1",
                },
            ),
            ("google", "GoogleProvider", {"client_id": "cid"}),
            (
                "azure",
                "AzureProvider",
                {"client_id": "cid", "azure_tenant_id": "tid", "scopes": "user.read"},
            ),
        ],
    )
    def test_signing_key_and_store_are_forwarded(self, provider, patched, extra):
        config = WebConfig(
            inbound_auth_provider=provider,
            proxy_base_url="https://mcp.example.com",
            jwt_signing_key=SIGNING_KEY,
            store_backend="dynamodb",
            store_dynamodb_table="oauth-state",
            **extra,
        )
        assert config.oauth_state is not None
        storage = build_client_storage(config.oauth_state)
        assert storage is not None
        with patch(f"authsome_mcp_proxy.inbound_auth.{patched}") as mock_class:
            build_inbound_auth(config, client_storage=storage)

        kwargs = mock_class.call_args.kwargs
        assert kwargs["jwt_signing_key"] == SIGNING_KEY
        assert kwargs["client_storage"] is storage.store

    def test_nothing_is_forwarded_when_nothing_is_set(self):
        with patch("authsome_mcp_proxy.inbound_auth.OIDCProxy") as mock_class:
            build_inbound_auth(_oidc_config())

        kwargs = mock_class.call_args.kwargs
        assert "jwt_signing_key" not in kwargs
        assert "client_storage" not in kwargs

    def test_keycloak_receives_neither(self):
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            jwt_signing_key=SIGNING_KEY,
        )
        with patch(
            "authsome_mcp_proxy.inbound_auth.KeycloakAuthProvider"
        ) as mock_class:
            build_inbound_auth(config, client_storage=MagicMock())

        kwargs = mock_class.call_args.kwargs
        assert "jwt_signing_key" not in kwargs
        assert "client_storage" not in kwargs


def test_nothing_configured_imports_no_backend_dependency(tmp_path):
    """Acceptance: a deployment that selects no backend loads no cloud SDK.

    Run in a fresh interpreter, because this test session itself has imported
    them for the DynamoDB tests. Goes through the CLI's config building and the
    serving path's store and provider construction, i.e. everything a web-mode
    startup runs before it binds the port.
    """
    script = textwrap.dedent(
        """
        import sys
        from unittest.mock import patch

        from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy

        from fastmcp_seaworthy import build_client_storage

        from authsome_mcp_proxy import __main__
        from authsome_mcp_proxy.inbound_auth import build_inbound_auth

        with patch("sys.argv", [
            "authsome-mcp-proxy", "http://upstream.example.com/mcp",
            "--transport", "http",
            "--proxy-base-url", "https://mcp.example.com",
            "--inbound-auth-provider", "oidc",
            "--oidc-issuer-url", "https://idp.example.com",
            "--oidc-client-id", "cid",
            "--oidc-client-secret", "csec",
        ]):
            config = __main__.build_proxy_config(__main__.cli())

        storage = build_client_storage(config.oauth_state)
        assert storage is None, storage
        discovery = OIDCConfiguration(
            issuer="https://idp.example.com",
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
            jwks_uri="https://idp.example.com/jwks",
            response_types_supported=["code"],
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        with patch.object(OIDCProxy, "get_oidc_configuration", return_value=discovery):
            build_inbound_auth(config, client_storage=storage)

        loaded = sorted(
            name for name in sys.modules
            if name.split(".")[0] in {"aioboto3", "aiobotocore", "boto3", "botocore"}
            or name.startswith("key_value.aio.stores.dynamodb")
        )
        print(",".join(loaded))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        # FASTMCP_HOME keeps the default file store FastMCP creates out of the
        # developer's real data directory.
        env={**os.environ, "FASTMCP_HOME": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""


_HTTP_ARGS = [
    "http://upstream.example.com/mcp",
    "--transport",
    "http",
    "--proxy-base-url",
    "https://mcp.example.com",
    "--inbound-auth-provider",
    "oidc",
    "--oidc-issuer-url",
    "https://idp.example.com",
    "--oidc-client-id",
    "cid",
]

_STORE_ENV = (
    "JWT_SIGNING_KEY",
    "STORE_BACKEND",
    "STORE_DYNAMODB_TABLE",
    "STORE_DYNAMODB_REGION",
    "STORE_DYNAMODB_AUTO_CREATE",
)


def _config_from_cli(args: list[str]) -> WebConfig:
    with patch("sys.argv", ["authsome-mcp-proxy", *_HTTP_ARGS, *args]):
        config = cli_main.build_proxy_config(cli_main.cli())
    assert isinstance(config, WebConfig)
    return config


class TestCLI:
    """Each setting is an env var plus a CLI flag, the flag winning."""

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch: pytest.MonkeyPatch):
        for name in _STORE_ENV:
            monkeypatch.delenv(name, raising=False)

    def test_defaults(self):
        config = _config_from_cli([])
        assert config.jwt_signing_key is None
        assert config.store_backend == "file"
        assert config.store_dynamodb_table is None
        assert config.store_dynamodb_region is None
        assert config.store_dynamodb_auto_create is False

    def test_flags(self):
        config = _config_from_cli(
            [
                "--jwt-signing-key",
                SIGNING_KEY,
                "--store-backend",
                "dynamodb",
                "--store-dynamodb-table",
                "oauth-state",
                "--store-dynamodb-region",
                "eu-west-1",
                "--store-dynamodb-auto-create",
            ]
        )
        assert config.jwt_signing_key == SIGNING_KEY
        assert config.store_backend == "dynamodb"
        assert config.store_dynamodb_table == "oauth-state"
        assert config.store_dynamodb_region == "eu-west-1"
        assert config.store_dynamodb_auto_create is True

    def test_env_vars(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("JWT_SIGNING_KEY", SIGNING_KEY)
        monkeypatch.setenv("STORE_BACKEND", "dynamodb")
        monkeypatch.setenv("STORE_DYNAMODB_TABLE", "oauth-state")
        monkeypatch.setenv("STORE_DYNAMODB_REGION", "eu-west-1")
        monkeypatch.setenv("STORE_DYNAMODB_AUTO_CREATE", "true")

        config = _config_from_cli([])

        assert config.jwt_signing_key == SIGNING_KEY
        assert config.store_backend == "dynamodb"
        assert config.store_dynamodb_table == "oauth-state"
        assert config.store_dynamodb_region == "eu-west-1"
        assert config.store_dynamodb_auto_create is True

    def test_flags_override_env_vars(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("JWT_SIGNING_KEY", "from-the-environment")
        monkeypatch.setenv("STORE_BACKEND", "dynamodb")
        monkeypatch.setenv("STORE_DYNAMODB_TABLE", "from-the-environment")
        monkeypatch.setenv("STORE_DYNAMODB_AUTO_CREATE", "true")

        config = _config_from_cli(
            [
                "--jwt-signing-key",
                SIGNING_KEY,
                "--store-backend",
                "file",
                "--store-dynamodb-table",
                "oauth-state",
                "--no-store-dynamodb-auto-create",
            ]
        )

        assert config.jwt_signing_key == SIGNING_KEY
        assert config.store_backend == "file"
        assert config.store_dynamodb_table == "oauth-state"
        assert config.store_dynamodb_auto_create is False

    def test_unknown_backend_in_env_is_rejected(self, monkeypatch: pytest.MonkeyPatch):
        """A typo must not quietly fall back to the restart-fragile file store."""
        monkeypatch.setenv("STORE_BACKEND", "dynamo")
        with pytest.raises(ValueError, match="STORE_BACKEND must be one of"):
            _config_from_cli([])

    def test_missing_signing_key_is_refused_naming_the_setting(self):
        with pytest.raises(ValueError, match="JWT_SIGNING_KEY"):
            _config_from_cli(
                ["--store-backend", "dynamodb", "--store-dynamodb-table", "t"]
            )


@asynccontextmanager
async def _noop_lifespan():
    yield


def _fake_server():
    server = MagicMock(name="mcp_proxy")
    server._lifespan_manager.side_effect = lambda: _noop_lifespan()
    return server


class TestServeHttp:
    """The store is built once per process and shared by every hostname."""

    async def test_one_store_is_opened_and_shared_by_every_hostname(self):
        config = _dynamodb_config(
            proxy_base_url="https://mcp.example.io",
            additional_proxy_base_urls=["https://mcp.example.com"],
        )
        storage = MagicMock(name="storage")
        storage.open = AsyncMock()
        storage.close = AsyncMock()
        events: list[str] = []
        storage.open.side_effect = lambda: events.append("open")
        storage.close.side_effect = lambda: events.append("close")

        with (
            patch(
                "authsome_mcp_proxy.mcp_proxy.build_client_storage",
                return_value=storage,
            ) as build_storage,
            patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth") as build_inbound,
            patch("fastmcp_seaworthy.serve.create_streamable_http_app"),
            patch("fastmcp_seaworthy.serve.HostRouter"),
            patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock(
                side_effect=lambda: events.append("serve")
            )
            await mcp_proxy._serve_http(_fake_server(), config, show_banner=False)

        build_storage.assert_called_once_with(config.oauth_state)
        assert [c.kwargs["client_storage"] for c in build_inbound.call_args_list] == [
            storage,
            storage,
        ]
        assert events == ["open", "serve", "close"]

    async def test_the_oauth_state_in_use_is_logged(
        self, caplog: pytest.LogCaptureFixture
    ):
        with (
            patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth"),
            patch("fastmcp_seaworthy.serve.create_streamable_http_app"),
            patch("fastmcp_seaworthy.serve.HostRouter"),
            patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
            caplog.at_level("INFO", logger="authsome_mcp_proxy.mcp_proxy"),
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock()
            await mcp_proxy._serve_http(
                _fake_server(),
                _oidc_config(jwt_signing_key=SIGNING_KEY),
                show_banner=False,
            )

        assert (
            "OAuth state in FastMCP's file store under FASTMCP_HOME, "
            "tokens signed with JWT_SIGNING_KEY"
        ) in caplog.text
        assert SIGNING_KEY not in caplog.text

    async def test_default_store_passes_none(self):
        with (
            patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth") as build_inbound,
            patch("fastmcp_seaworthy.serve.create_streamable_http_app"),
            patch("fastmcp_seaworthy.serve.HostRouter"),
            patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock()
            await mcp_proxy._serve_http(
                _fake_server(), _oidc_config(), show_banner=False
            )

        assert build_inbound.call_args.kwargs["client_storage"] is None

    async def test_a_store_that_cannot_open_stops_startup_before_serving(self):
        storage = MagicMock(name="storage")
        storage.open = AsyncMock(side_effect=ValueError("Cannot use DynamoDB table"))
        with (
            patch(
                "authsome_mcp_proxy.mcp_proxy.build_client_storage",
                return_value=storage,
            ),
            patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth"),
            patch("fastmcp_seaworthy.serve.create_streamable_http_app"),
            patch("fastmcp_seaworthy.serve.HostRouter"),
            patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
            pytest.raises(ValueError, match="Cannot use DynamoDB table"),
        ):
            await mcp_proxy._serve_http(
                _fake_server(), _dynamodb_config(), show_banner=False
            )

        uvicorn_mod.Server.assert_not_called()
