"""Tests for how the proxy configures and wires the OAuth proxy's state store.

The store itself -- encryption, key derivation, DynamoDB, PostgreSQL, what
survives a restart -- is fastmcp-seaworthy's and tested there. What remains here is the
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

POSTGRES_PASSWORD = "p4ss-w0rd-never-shown"
POSTGRES_URL = f"postgresql://pguser:{POSTGRES_PASSWORD}@db.example.com:5432/appdb"


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


def _postgres_config(**overrides) -> WebConfig:
    values: dict[str, Any] = {
        "jwt_signing_key": SIGNING_KEY,
        "store_backend": "postgres",
        "store_postgres_url": POSTGRES_URL,
    }
    values.update(overrides)
    return _oidc_config(**values)


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

    def test_every_postgres_setting_is_carried_over(self):
        settings = _postgres_config(
            store_postgres_table="oauth.proxy_state", store_postgres_auto_create=True
        ).oauth_state
        assert settings == OAuthStateSettings(
            jwt_signing_key=SIGNING_KEY,
            store_backend="postgres",
            store_postgres_url=POSTGRES_URL,
            store_postgres_table="oauth.proxy_state",
            store_postgres_auto_create=True,
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
            (
                "zitadel",
                "ZitadelProvider",
                {
                    "client_id": "cid",
                    "client_secret": "csec",
                    "zitadel_domain": "my-instance-abc123.zitadel.cloud",
                },
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

    def test_postgres_store_is_forwarded(self):
        """Building the store connects to nothing: the pool is opened by
        ``serve_http``, so this needs no database."""
        config = _postgres_config()
        assert config.oauth_state is not None
        storage = build_client_storage(config.oauth_state)
        assert storage is not None
        with patch("authsome_mcp_proxy.inbound_auth.OIDCProxy") as mock_class:
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
            if name.split(".")[0]
            in {"aioboto3", "aiobotocore", "boto3", "botocore", "asyncpg"}
            or name.startswith("key_value.aio.stores.dynamodb")
            or name.startswith("key_value.aio.stores.postgresql")
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
    "STORE_POSTGRES_URL",
    "STORE_POSTGRES_TABLE",
    "STORE_POSTGRES_AUTO_CREATE",
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
        assert config.store_postgres_url is None
        assert config.store_postgres_table is None
        assert config.store_postgres_auto_create is False

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


class TestPostgresCLI:
    """The PostgreSQL settings follow the DynamoDB ones: env var plus flag."""

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch: pytest.MonkeyPatch):
        for name in _STORE_ENV:
            monkeypatch.delenv(name, raising=False)

    def test_env_vars(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("JWT_SIGNING_KEY", SIGNING_KEY)
        monkeypatch.setenv("STORE_BACKEND", "postgres")
        monkeypatch.setenv("STORE_POSTGRES_URL", POSTGRES_URL)
        monkeypatch.setenv("STORE_POSTGRES_TABLE", "oauth.proxy_state")
        monkeypatch.setenv("STORE_POSTGRES_AUTO_CREATE", "true")

        config = _config_from_cli([])

        assert config.store_backend == "postgres"
        assert config.store_postgres_url == POSTGRES_URL
        assert config.store_postgres_table == "oauth.proxy_state"
        assert config.store_postgres_auto_create is True

    def test_flags(self):
        config = _config_from_cli(
            [
                "--jwt-signing-key",
                SIGNING_KEY,
                "--store-backend",
                "postgres",
                "--store-postgres-url",
                POSTGRES_URL,
                "--store-postgres-table",
                "proxy_state",
                "--store-postgres-auto-create",
            ]
        )
        assert config.store_backend == "postgres"
        assert config.store_postgres_url == POSTGRES_URL
        assert config.store_postgres_table == "proxy_state"
        assert config.store_postgres_auto_create is True

    def test_flags_override_env_vars(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("JWT_SIGNING_KEY", SIGNING_KEY)
        monkeypatch.setenv("STORE_BACKEND", "postgres")
        monkeypatch.setenv("STORE_POSTGRES_URL", POSTGRES_URL)
        monkeypatch.setenv("STORE_POSTGRES_TABLE", "from_the_environment")
        monkeypatch.setenv("STORE_POSTGRES_AUTO_CREATE", "true")

        config = _config_from_cli(
            [
                "--store-postgres-table",
                "proxy_state",
                "--no-store-postgres-auto-create",
            ]
        )

        assert config.store_postgres_table == "proxy_state"
        assert config.store_postgres_auto_create is False

    def test_unparsable_auto_create_is_rejected(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STORE_POSTGRES_AUTO_CREATE", "enabled")
        with pytest.raises(ValueError, match="STORE_POSTGRES_AUTO_CREATE must be"):
            _config_from_cli([])

    def test_missing_url_is_refused_naming_the_setting(self):
        with pytest.raises(ValueError, match="STORE_POSTGRES_URL"):
            _config_from_cli(
                ["--jwt-signing-key", SIGNING_KEY, "--store-backend", "postgres"]
            )

    def test_table_name_is_checked_at_startup(self):
        with pytest.raises(ValueError, match="STORE_POSTGRES_TABLE"):
            _postgres_config(store_postgres_table="Not-A-Table")

    @pytest.mark.parametrize(
        "url",
        [
            # Not a PostgreSQL URL at all.
            f"mysql://pguser:{POSTGRES_PASSWORD}@db.example.com/appdb",
            # An unencoded '@' in the password, which asyncpg and urllib split
            # differently -- part of the password would be read as the host.
            f"postgresql://pguser:{POSTGRES_PASSWORD}@x@db.example.com/appdb",
        ],
    )
    def test_a_refused_url_is_never_quoted(self, url):
        """The refusal reaches the log through ``log_error_and_exit``."""
        with pytest.raises(ValueError, match="STORE_POSTGRES_URL") as excinfo:
            _postgres_config(store_postgres_url=url)

        assert POSTGRES_PASSWORD not in str(excinfo.value)
        assert url not in str(excinfo.value)

    def test_url_is_kept_out_of_the_config_repr(self):
        """A dataclass repr ends up in tracebacks and debug logs."""
        config = _postgres_config()

        assert POSTGRES_PASSWORD not in repr(config)
        assert POSTGRES_URL not in repr(config)
        assert POSTGRES_PASSWORD not in repr(config.oauth_state)

    def test_settings_are_inert_for_keycloak(self):
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            store_backend="postgres",
        )
        assert config.oauth_state is None


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

    async def test_postgres_store_is_logged_once_without_credentials(
        self, caplog: pytest.LogCaptureFixture
    ):
        """One line for the process, however many hostnames it serves, naming
        the table, database, host and port -- never the user or password."""
        config = _postgres_config(
            proxy_base_url="https://mcp.example.io",
            additional_proxy_base_urls=["https://mcp.example.com"],
        )
        storage = MagicMock(name="storage")
        storage.open = AsyncMock()
        storage.close = AsyncMock()
        with (
            patch(
                "authsome_mcp_proxy.mcp_proxy.build_client_storage",
                return_value=storage,
            ),
            patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth") as build_inbound,
            patch("fastmcp_seaworthy.serve.create_streamable_http_app"),
            patch("fastmcp_seaworthy.serve.HostRouter"),
            patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
            caplog.at_level("DEBUG"),
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock()
            await mcp_proxy._serve_http(_fake_server(), config, show_banner=False)

        assert build_inbound.call_count == 2
        line = (
            "OAuth state in PostgreSQL table 'fastmcp_oauth_state' in database "
            "'appdb' on db.example.com:5432, tokens signed with JWT_SIGNING_KEY"
        )
        assert caplog.text.count(line) == 1
        assert caplog.text.count("OAuth state in ") == 1
        assert POSTGRES_PASSWORD not in caplog.text
        assert "pguser" not in caplog.text
        assert SIGNING_KEY not in caplog.text
        storage.open.assert_awaited_once()
        storage.close.assert_awaited_once()

    async def test_an_unreachable_postgres_names_the_server_not_the_url(self):
        """Opening a real store against a port nothing listens on: the startup
        error names the table and server, and never the password."""
        url = f"postgresql://pguser:{POSTGRES_PASSWORD}@127.0.0.1:1/appdb"
        with (
            patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth"),
            patch("fastmcp_seaworthy.serve.create_streamable_http_app"),
            patch("fastmcp_seaworthy.serve.HostRouter"),
            patch("fastmcp_seaworthy.serve.uvicorn") as uvicorn_mod,
            pytest.raises(ValueError, match="Cannot use PostgreSQL table") as excinfo,
        ):
            await mcp_proxy._serve_http(
                _fake_server(),
                _postgres_config(store_postgres_url=url),
                show_banner=False,
            )

        uvicorn_mod.Server.assert_not_called()
        assert "127.0.0.1:1" in str(excinfo.value)
        assert POSTGRES_PASSWORD not in str(excinfo.value)
        assert url not in str(excinfo.value)

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
