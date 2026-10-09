"""Tests for the selectable store backend behind the OAuth proxy's state."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from authsome_mcp_proxy import __main__ as cli_main
from authsome_mcp_proxy import mcp_proxy
from authsome_mcp_proxy.config import WebConfig
from authsome_mcp_proxy.inbound_auth import build_client_storage, build_inbound_auth

from .conftest import dynamodb_client

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


class TestSelection:
    def test_default_is_fastmcps_file_store(self):
        """None leaves FastMCP to build its own encrypted file store."""
        assert build_client_storage(_oidc_config()) is None

    def test_a_signing_key_alone_keeps_the_file_store(self):
        assert build_client_storage(_oidc_config(jwt_signing_key=SIGNING_KEY)) is None

    def test_keycloak_ignores_the_store_settings(self):
        """Keycloak is the authorization server there; the proxy keeps no OAuth
        state, so a selected backend is inert rather than connected to."""
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            store_backend="dynamodb",
        )
        assert build_client_storage(config) is None

    def test_dynamodb_is_wrapped_in_fernet_encryption(self):
        storage = build_client_storage(
            _dynamodb_config(store_dynamodb_region="eu-west-1")
        )

        assert storage is not None
        assert isinstance(storage.store, FernetEncryptionWrapper)
        assert storage.store.raise_on_decryption_error is False
        assert storage.backend._table_name == "oauth-state"  # ty: ignore[unresolved-attribute]
        assert storage.backend._auto_create is False  # ty: ignore[unresolved-attribute]
        assert "'oauth-state'" in storage.description

    def test_unknown_backend_raises(self):
        config = _dynamodb_config()
        config.store_backend = "redis"  # type: ignore[assignment]  # ty: ignore[invalid-assignment]
        with pytest.raises(ValueError, match="Unknown store_backend 'redis'"):
            build_client_storage(config)

    def test_missing_extra_names_it(self):
        """Without the extra the store class cannot be imported; the error says
        which extra to install rather than surfacing a bare ImportError."""
        with (
            patch.dict(sys.modules, {"key_value.aio.stores.dynamodb": None}),
            pytest.raises(RuntimeError, match=r"authsome-mcp-proxy\[dynamodb\]"),
        ):
            build_client_storage(_dynamodb_config())


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
        storage = build_client_storage(config)
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

        from authsome_mcp_proxy import __main__, mcp_proxy
        from authsome_mcp_proxy.inbound_auth import (
            build_client_storage, build_inbound_auth,
        )

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

        storage = build_client_storage(config)
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


class TestDynamoDBStorage:
    async def test_values_at_rest_are_encrypted(self, dynamodb_table: str, aws_env):
        """FastMCP encrypts only the store it builds itself. What reaches the
        table must carry no plaintext -- it holds the upstream IdP's tokens."""
        storage = build_client_storage(_dynamodb_config(dynamodb_table))
        assert storage is not None
        await storage.open()
        try:
            await storage.store.put(
                key="upstream-token-id",
                value={"access_token": "plaintext-upstream-access-token"},
                collection="mcp-upstream-tokens",
            )
            assert await storage.store.get(
                key="upstream-token-id", collection="mcp-upstream-tokens"
            ) == {"access_token": "plaintext-upstream-access-token"}
        finally:
            await storage.close()

        items = dynamodb_client(aws_env).scan(TableName=dynamodb_table)["Items"]
        assert len(items) == 1
        raw = items[0]["value"]["S"]
        assert "plaintext-upstream-access-token" not in raw
        assert "access_token" not in raw

    async def test_missing_table_fails_at_startup_naming_it(self, aws_env):
        """Infrastructure creates the table; with auto_create off a missing one
        is a deployment error, reported at startup with the table's name."""
        storage = build_client_storage(_dynamodb_config("no-such-table"))
        assert storage is not None

        with pytest.raises(ValueError, match="'no-such-table'") as excinfo:
            await storage.open()

        assert "STORE_DYNAMODB_TABLE" in str(excinfo.value)

    async def test_auto_create_creates_a_missing_table(self, aws_env):
        table = "created-by-the-proxy"
        storage = build_client_storage(
            _dynamodb_config(table, store_dynamodb_auto_create=True)
        )
        assert storage is not None

        await storage.open()
        await storage.close()

        description = dynamodb_client(aws_env).describe_table(TableName=table)
        assert {
            k["AttributeName"]: k["KeyType"] for k in description["Table"]["KeySchema"]
        } == {
            "collection": "HASH",
            "key": "RANGE",
        }


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
            patch("authsome_mcp_proxy.mcp_proxy.create_streamable_http_app"),
            patch("authsome_mcp_proxy.mcp_proxy.HostRouter"),
            patch("authsome_mcp_proxy.mcp_proxy.uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock(
                side_effect=lambda: events.append("serve")
            )
            await mcp_proxy._serve_http(_fake_server(), config, show_banner=False)

        build_storage.assert_called_once_with(config)
        assert [c.kwargs["client_storage"] for c in build_inbound.call_args_list] == [
            storage,
            storage,
        ]
        assert events == ["open", "serve", "close"]

    async def test_default_store_passes_none(self):
        with (
            patch("authsome_mcp_proxy.mcp_proxy.build_inbound_auth") as build_inbound,
            patch("authsome_mcp_proxy.mcp_proxy.create_streamable_http_app"),
            patch("authsome_mcp_proxy.mcp_proxy.HostRouter"),
            patch("authsome_mcp_proxy.mcp_proxy.uvicorn") as uvicorn_mod,
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
            patch("authsome_mcp_proxy.mcp_proxy.create_streamable_http_app"),
            patch("authsome_mcp_proxy.mcp_proxy.HostRouter"),
            patch("authsome_mcp_proxy.mcp_proxy.uvicorn") as uvicorn_mod,
            pytest.raises(ValueError, match="Cannot use DynamoDB table"),
        ):
            await mcp_proxy._serve_http(
                _fake_server(), _dynamodb_config(), show_banner=False
            )

        uvicorn_mod.Server.assert_not_called()
