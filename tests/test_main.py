"""Tests for authsome_mcp_proxy.__main__ module."""

import logging
import os
from unittest.mock import patch

import pytest

from authsome_mcp_proxy.__main__ import build_proxy_config, cli, get_log_level_name
from authsome_mcp_proxy.config import DesktopConfig, WebConfig


class TestCLI:
    """Test CLI argument parsing."""

    def test_cli_with_all_args(self):
        """Test CLI parsing with all arguments provided."""
        test_args = [
            "http://upstream.example.com/mcp",
            "--oidc-issuer-url",
            "https://auth.example.com",
            "--oidc-client-id",
            "test-client",
            "--oidc-client-secret",
            "test-secret",
            "--oidc-scopes",
            "openid profile",
            "--oidc-redirect-url",
            "http://localhost:8080/callback",
            "--debug",
        ]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.upstream_mcp_url == "http://upstream.example.com/mcp"
        assert args.oidc_issuer_url == "https://auth.example.com"
        assert args.oidc_client_id == "test-client"
        assert args.oidc_client_secret == "test-secret"
        assert args.oidc_scopes == "openid profile"
        assert args.oidc_redirect_url == "http://localhost:8080/callback"
        assert args.debug is True
        assert args.silent is False

    def test_cli_with_minimal_args(self):
        """Test CLI parsing with minimal arguments."""
        test_args = ["http://upstream.example.com/mcp"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.upstream_mcp_url == "http://upstream.example.com/mcp"
        assert args.debug is False
        assert args.silent is False

    def test_cli_with_no_upstream_url(self):
        """Test CLI parsing when upstream URL is not provided."""
        with patch("sys.argv", ["authsome-mcp-proxy"]):
            with patch.dict(os.environ, {}, clear=True):
                args = cli()

        assert args.upstream_mcp_url is None

    def test_cli_env_var_fallback(self):
        """Test that CLI falls back to environment variables."""
        env_vars = {
            "UPSTREAM_MCP_URL": "http://env-upstream.example.com/mcp",
            "OIDC_ISSUER_URL": "https://env-auth.example.com",
            "OIDC_CLIENT_ID": "env-client",
            "OIDC_CLIENT_SECRET": "env-secret",
            "OIDC_SCOPES": "openid email",
            "OIDC_REDIRECT_URL": "http://localhost:9090/callback",
        }

        with patch("sys.argv", ["authsome-mcp-proxy"]):
            with patch.dict(os.environ, env_vars):
                args = cli()

        assert args.upstream_mcp_url == "http://env-upstream.example.com/mcp"
        assert args.oidc_issuer_url == "https://env-auth.example.com"
        assert args.oidc_client_id == "env-client"
        assert args.oidc_client_secret == "env-secret"
        assert args.oidc_scopes == "openid email"
        assert args.oidc_redirect_url == "http://localhost:9090/callback"

    def test_cli_args_override_env_vars(self):
        """Test that CLI arguments take precedence over environment variables."""
        env_vars = {
            "UPSTREAM_MCP_URL": "http://env-upstream.example.com/mcp",
            "OIDC_ISSUER_URL": "https://env-auth.example.com",
        }

        test_args = [
            "http://cli-upstream.example.com/mcp",
            "--oidc-issuer-url",
            "https://cli-auth.example.com",
        ]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            with patch.dict(os.environ, env_vars):
                args = cli()

        assert args.upstream_mcp_url == "http://cli-upstream.example.com/mcp"
        assert args.oidc_issuer_url == "https://cli-auth.example.com"

    def test_cli_debug_flag(self):
        """Test debug flag sets debug to True."""
        test_args = ["http://upstream.example.com/mcp", "--debug"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.debug is True
        assert args.silent is False

    def test_cli_silent_flag(self):
        """Test silent flag sets silent to True."""
        test_args = ["http://upstream.example.com/mcp", "--silent"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.silent is True
        assert args.debug is False

    def test_cli_debug_env_var(self):
        """Test MCP_PROXY_DEBUG environment variable."""
        test_args = ["http://upstream.example.com/mcp"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            with patch.dict(os.environ, {"MCP_PROXY_DEBUG": "true"}):
                args = cli()

        assert args.debug is True

    def test_cli_no_banner_flag(self):
        """Test --no-banner flag."""
        test_args = ["http://upstream.example.com/mcp", "--no-banner"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.no_banner is True

    def test_cli_transport_default_is_stdio(self):
        """Test that transport defaults to stdio when not specified."""
        with patch(
            "sys.argv", ["authsome-mcp-proxy", "http://upstream.example.com/mcp"]
        ):
            args = cli()

        assert args.transport == "stdio"

    def test_cli_transport_stdio_explicit(self):
        """Test explicit --transport stdio."""
        test_args = ["http://upstream.example.com/mcp", "--transport", "stdio"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.transport == "stdio"

    def test_cli_transport_http(self):
        """Test --transport http."""
        test_args = ["http://upstream.example.com/mcp", "--transport", "http"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.transport == "http"

    def test_cli_transport_env_var(self):
        """Test MCP_PROXY_TRANSPORT environment variable fallback."""
        with patch(
            "sys.argv", ["authsome-mcp-proxy", "http://upstream.example.com/mcp"]
        ):
            with patch.dict(os.environ, {"MCP_PROXY_TRANSPORT": "http"}):
                args = cli()

        assert args.transport == "http"

    def test_cli_transport_cli_overrides_env_var(self):
        """Test that --transport takes precedence over MCP_PROXY_TRANSPORT env var."""
        test_args = ["http://upstream.example.com/mcp", "--transport", "stdio"]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            with patch.dict(os.environ, {"MCP_PROXY_TRANSPORT": "http"}):
                args = cli()

        assert args.transport == "stdio"

    def test_cli_host_arg(self):
        """Test --host argument."""
        test_args = [
            "http://upstream.example.com/mcp",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
        ]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.host == "127.0.0.1"

    def test_cli_port_arg(self):
        """Test --port argument is parsed as integer."""
        test_args = [
            "http://upstream.example.com/mcp",
            "--transport",
            "http",
            "--port",
            "9000",
        ]

        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()

        assert args.port == 9000

    def test_cli_host_env_var(self):
        """Test MCP_PROXY_HOST environment variable fallback."""
        with patch(
            "sys.argv", ["authsome-mcp-proxy", "http://upstream.example.com/mcp"]
        ):
            with patch.dict(os.environ, {"MCP_PROXY_HOST": "192.168.1.1"}):
                args = cli()

        assert args.host == "192.168.1.1"

    def test_cli_port_env_var(self):
        """Test MCP_PROXY_PORT environment variable fallback is converted to int."""
        with patch(
            "sys.argv", ["authsome-mcp-proxy", "http://upstream.example.com/mcp"]
        ):
            with patch.dict(os.environ, {"MCP_PROXY_PORT": "9000"}):
                args = cli()

        assert args.port == 9000

    def test_cli_host_port_none_by_default(self):
        """Test that host and port are None when not provided (FastMCP uses its own defaults)."""
        with patch(
            "sys.argv", ["authsome-mcp-proxy", "http://upstream.example.com/mcp"]
        ):
            with patch.dict(os.environ, {}, clear=True):
                args = cli()

        assert args.host is None
        assert args.port is None


class TestCLIWebModeFlags:
    """Test parsing of the http-mode-only CLI flags + env-var fallbacks."""

    def test_inbound_auth_provider_flag(self):
        test_args = [
            "http://upstream",
            "--transport",
            "http",
            "--inbound-auth-provider",
            "aws-cognito",
        ]
        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()
        assert args.inbound_auth_provider == "aws-cognito"

    def test_inbound_auth_provider_env_var(self):
        with patch("sys.argv", ["authsome-mcp-proxy", "http://upstream"]):
            with patch.dict(
                os.environ, {"INBOUND_AUTH_PROVIDER": "keycloak"}, clear=True
            ):
                args = cli()
        assert args.inbound_auth_provider == "keycloak"

    def test_proxy_base_url_flag_and_env(self):
        test_args = ["http://upstream", "--proxy-base-url", "https://mcp.example.com"]
        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()
        assert args.proxy_base_url == "https://mcp.example.com"

        with patch("sys.argv", ["authsome-mcp-proxy", "http://upstream"]):
            with patch.dict(
                os.environ,
                {"MCP_PROXY_BASE_URL": "https://env.example.com"},
                clear=True,
            ):
                args = cli()
        assert args.proxy_base_url == "https://env.example.com"

    def test_provider_specific_flags(self):
        test_args = [
            "http://upstream",
            "--cognito-user-pool-id",
            "us-east-1_abc",
            "--cognito-aws-region",
            "us-east-1",
            "--azure-tenant-id",
            "tid",
            "--azure-identifier-uri",
            "api://example",
            "--audience",
            "mcp-server",
        ]
        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()
        assert args.cognito_user_pool_id == "us-east-1_abc"
        assert args.cognito_aws_region == "us-east-1"
        assert args.azure_tenant_id == "tid"
        assert args.azure_identifier_uri == "api://example"
        assert args.audience == "mcp-server"

    def test_provider_specific_env_vars(self):
        with patch("sys.argv", ["authsome-mcp-proxy", "http://upstream"]):
            with patch.dict(
                os.environ,
                {
                    "COGNITO_USER_POOL_ID": "eu-central-1_xyz",
                    "COGNITO_AWS_REGION": "eu-central-1",
                    "AZURE_TENANT_ID": "env-tid",
                    "AZURE_IDENTIFIER_URI": "api://env",
                    "AUDIENCE": "env-aud",
                },
                clear=True,
            ):
                args = cli()
        assert args.cognito_user_pool_id == "eu-central-1_xyz"
        assert args.cognito_aws_region == "eu-central-1"
        assert args.azure_tenant_id == "env-tid"
        assert args.azure_identifier_uri == "api://env"
        assert args.audience == "env-aud"

    def test_enable_cimd_defaults_to_true(self):
        """Nothing set anywhere: CIMD stays on, matching FastMCP's default."""
        args = _parse(["http://upstream"])
        assert args.enable_cimd is True

    def test_enable_cimd_flags(self):
        assert _parse(["http://upstream", "--enable-cimd"]).enable_cimd is True
        assert _parse(["http://upstream", "--no-enable-cimd"]).enable_cimd is False

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("1", True),
            ("true", True),
            ("TRUE", True),
            ("yes", True),
            ("on", True),
            ("0", False),
            ("false", False),
            ("False", False),
            ("no", False),
            ("off", False),
            ("", True),
        ],
    )
    def test_enable_cimd_env_var(self, raw, expected):
        with patch("sys.argv", ["authsome-mcp-proxy", "http://upstream"]):
            with patch.dict(os.environ, {"ENABLE_CIMD": raw}, clear=True):
                args = cli()
        assert args.enable_cimd is expected

    def test_enable_cimd_flag_overrides_env_var(self):
        """The tri-state default exists for exactly this: --no-enable-cimd has
        to beat ENABLE_CIMD=true, and vice versa."""
        with patch(
            "sys.argv", ["authsome-mcp-proxy", "http://upstream", "--no-enable-cimd"]
        ):
            with patch.dict(os.environ, {"ENABLE_CIMD": "true"}, clear=True):
                assert cli().enable_cimd is False

        with patch(
            "sys.argv", ["authsome-mcp-proxy", "http://upstream", "--enable-cimd"]
        ):
            with patch.dict(os.environ, {"ENABLE_CIMD": "false"}, clear=True):
                assert cli().enable_cimd is True

    @pytest.mark.parametrize("raw", ["enabled", "disabled", "y", "maybe"])
    def test_enable_cimd_env_var_rejects_unrecognized_values(self, raw):
        """Plausible-looking values and typos alike have to fail loudly --
        resolving them to the default would silently ignore the operator."""
        with patch("sys.argv", ["authsome-mcp-proxy", "http://upstream"]):
            with patch.dict(os.environ, {"ENABLE_CIMD": raw}, clear=True):
                with pytest.raises(ValueError, match="ENABLE_CIMD"):
                    cli()

    def test_outbound_auth_flags(self):
        test_args = [
            "http://upstream",
            "--outbound-auth",
            "oauth-client-credentials",
            "--outbound-client-id",
            "ocid",
            "--outbound-client-secret",
            "osec",
            "--outbound-token-url",
            "https://idp.example.com/token",
        ]
        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()
        assert args.outbound_auth == "oauth-client-credentials"
        assert args.outbound_client_id == "ocid"
        assert args.outbound_client_secret == "osec"
        assert args.outbound_token_url == "https://idp.example.com/token"

    def test_outbound_static_flags(self):
        test_args = [
            "http://upstream",
            "--outbound-auth",
            "static",
            "--outbound-header-name",
            "X-API-Key",
            "--outbound-header-value",
            "abc123",
        ]
        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()
        assert args.outbound_auth == "static"
        assert args.outbound_header_name == "X-API-Key"
        assert args.outbound_header_value == "abc123"

    def test_server_identity_flags(self):
        test_args = [
            "http://upstream",
            "--proxy-name",
            "ANALYZE",
            "--proxy-version",
            "2.3.0",
            "--proxy-instructions",
            "Use these tools for traceability analysis.",
            "--proxy-website-url",
            "https://analyze.example.com",
        ]
        with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
            args = cli()
        assert args.proxy_name == "ANALYZE"
        assert args.proxy_version == "2.3.0"
        assert args.proxy_instructions == "Use these tools for traceability analysis."
        assert args.proxy_website_url == "https://analyze.example.com"

    def test_server_identity_env_vars(self):
        with patch("sys.argv", ["authsome-mcp-proxy", "http://upstream"]):
            with patch.dict(
                os.environ,
                {
                    "MCP_PROXY_NAME": "ANALYZE",
                    "MCP_PROXY_VERSION": "2.3.0",
                    "MCP_PROXY_INSTRUCTIONS": "Env-supplied instructions.",
                    "MCP_PROXY_WEBSITE_URL": "https://analyze.example.com",
                },
                clear=True,
            ):
                args = cli()
        assert args.proxy_name == "ANALYZE"
        assert args.proxy_version == "2.3.0"
        assert args.proxy_instructions == "Env-supplied instructions."
        assert args.proxy_website_url == "https://analyze.example.com"

    def test_outbound_env_vars(self):
        with patch("sys.argv", ["authsome-mcp-proxy", "http://upstream"]):
            with patch.dict(
                os.environ,
                {
                    "OUTBOUND_AUTH": "static",
                    "OUTBOUND_HEADER_NAME": "X-Auth",
                    "OUTBOUND_HEADER_VALUE": "secret",
                    "OUTBOUND_CLIENT_ID": "x",
                    "OUTBOUND_CLIENT_SECRET": "y",
                    "OUTBOUND_TOKEN_URL": "https://t",
                },
                clear=True,
            ):
                args = cli()
        assert args.outbound_auth == "static"
        assert args.outbound_header_name == "X-Auth"
        assert args.outbound_header_value == "secret"
        assert args.outbound_client_id == "x"
        assert args.outbound_client_secret == "y"
        assert args.outbound_token_url == "https://t"


def _parse(test_args: list[str]):
    with patch("sys.argv", ["authsome-mcp-proxy"] + test_args):
        with patch.dict(os.environ, {}, clear=True):
            return cli()


class TestBuildProxyConfig:
    """build_proxy_config picks DesktopConfig vs WebConfig based on transport."""

    def test_stdio_builds_desktop_config(self):
        args = _parse(
            [
                "http://upstream",
                "--oidc-issuer-url",
                "https://auth.example.com",
                "--oidc-client-id",
                "cid",
                "--oidc-client-secret",
                "csec",
                "--oidc-scopes",
                "openid",
                "--oidc-redirect-url",
                "http://localhost:8080/callback",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, DesktopConfig)
        assert config.issuer_url == "https://auth.example.com"
        assert config.client_id == "cid"
        assert config.client_secret == "csec"
        assert config.scopes == "openid"
        assert config.redirect_url == "http://localhost:8080/callback"

    def test_http_requires_proxy_base_url(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--inbound-auth-provider",
                "keycloak",
                "--oidc-issuer-url",
                "https://kc/realms/r",
            ]
        )
        with pytest.raises(ValueError, match="--proxy-base-url"):
            build_proxy_config(args)

    def test_http_requires_inbound_auth_provider(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
            ]
        )
        with pytest.raises(ValueError, match="--inbound-auth-provider"):
            build_proxy_config(args)

    def test_http_builds_web_config_for_keycloak(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "keycloak",
                "--oidc-issuer-url",
                "https://kc/realms/r",
                "--audience",
                "mcp-server",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.inbound_auth_provider == "keycloak"
        assert config.proxy_base_url == "https://mcp.example.com"
        assert config.issuer_url == "https://kc/realms/r"
        assert config.audience == "mcp-server"
        # Defaults for outbound when nothing else is set
        assert config.outbound_auth == "forward"
        assert config.outbound_header_name == "Authorization"

    def test_http_builds_web_config_for_aws_cognito(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "aws-cognito",
                "--oidc-client-id",
                "cid",
                "--oidc-client-secret",
                "csec",
                "--cognito-user-pool-id",
                "us-east-1_abc",
                "--cognito-aws-region",
                "us-east-1",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.inbound_auth_provider == "aws-cognito"
        assert config.client_id == "cid"
        assert config.cognito_user_pool_id == "us-east-1_abc"
        assert config.cognito_aws_region == "us-east-1"

    def test_http_builds_web_config_with_oauth_cc_outbound(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "keycloak",
                "--oidc-issuer-url",
                "https://kc/realms/r",
                "--outbound-auth",
                "oauth-client-credentials",
                "--outbound-client-id",
                "ocid",
                "--outbound-client-secret",
                "osec",
                "--outbound-token-url",
                "https://idp/token",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.outbound_auth == "oauth-client-credentials"
        assert config.outbound_token_url == "https://idp/token"

    def test_http_builds_web_config_with_none_outbound(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "keycloak",
                "--oidc-issuer-url",
                "https://kc/realms/r",
                "--outbound-auth",
                "none",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.outbound_auth == "none"

    def test_http_builds_web_config_with_static_outbound(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "keycloak",
                "--oidc-issuer-url",
                "https://kc/realms/r",
                "--outbound-auth",
                "static",
                "--outbound-header-name",
                "X-API-Key",
                "--outbound-header-value",
                "abc123",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.outbound_auth == "static"
        assert config.outbound_header_name == "X-API-Key"
        assert config.outbound_header_value == "abc123"

    def test_http_propagates_server_identity_fields(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "keycloak",
                "--oidc-issuer-url",
                "https://kc/realms/r",
                "--proxy-name",
                "ANALYZE",
                "--proxy-version",
                "2.3.0",
                "--proxy-instructions",
                "Use these tools for traceability analysis.",
                "--proxy-website-url",
                "https://analyze.example.com",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.proxy_name == "ANALYZE"
        assert config.proxy_version == "2.3.0"
        assert config.proxy_instructions == "Use these tools for traceability analysis."
        assert config.proxy_website_url == "https://analyze.example.com"

    def test_http_server_identity_fields_default_to_none(self):
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "keycloak",
                "--oidc-issuer-url",
                "https://kc/realms/r",
            ]
        )
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.proxy_name is None
        assert config.proxy_version is None
        assert config.proxy_instructions is None
        assert config.proxy_website_url is None

    def test_http_propagates_post_init_validation_errors(self):
        """Per-provider field validation lives in WebConfig.__post_init__ —
        build_proxy_config surfaces those ValueErrors transparently."""
        args = _parse(
            [
                "http://upstream",
                "--transport",
                "http",
                "--proxy-base-url",
                "https://mcp.example.com",
                "--inbound-auth-provider",
                "aws-cognito",
                # missing client_id, client_secret, user-pool-id, region
            ]
        )
        with pytest.raises(ValueError, match="aws-cognito"):
            build_proxy_config(args)


class TestGetLogLevelName:
    """Test get_log_level_name function."""

    def test_silent_mode(self):
        """Test that silent mode returns ERROR level."""

        class Args:
            silent = True
            debug = False

        level = get_log_level_name(Args())
        assert level == logging.getLevelName(logging.ERROR)

    def test_debug_mode(self):
        """Test that debug mode returns DEBUG level."""

        class Args:
            silent = False
            debug = True

        level = get_log_level_name(Args())
        assert level == logging.getLevelName(logging.DEBUG)

    def test_normal_mode(self):
        """Test that normal mode returns INFO level."""

        class Args:
            silent = False
            debug = False

        level = get_log_level_name(Args())
        assert level == logging.getLevelName(logging.INFO)


class TestMultipleProxyBaseUrls:
    """--proxy-base-url / MCP_PROXY_BASE_URL accept a comma-separated list so a
    deployment can serve several public hostnames from one process."""

    @staticmethod
    def _config(base_urls) -> WebConfig:
        config = build_proxy_config(
            _parse(
                [
                    "http://upstream",
                    "--transport",
                    "http",
                    "--proxy-base-url",
                    base_urls,
                    "--inbound-auth-provider",
                    "keycloak",
                    "--oidc-issuer-url",
                    "https://kc/realms/r",
                ]
            )
        )
        # build_proxy_config returns the ProxyConfig union; --transport http
        # always yields the web half.
        assert isinstance(config, WebConfig)
        return config

    def test_single_url_leaves_no_additional_identities(self):
        """The pre-existing single-hostname form must keep behaving exactly as
        it did, since every current deployment passes it."""
        config = self._config("https://mcp.example.com")
        assert config.proxy_base_url == "https://mcp.example.com"
        assert config.additional_proxy_base_urls == []

    def test_first_entry_becomes_canonical_and_the_rest_additional(self):
        config = self._config(
            "https://mcp.example.io,https://mcp.example.com,https://mcp.example.de"
        )
        assert config.proxy_base_url == "https://mcp.example.io"
        assert config.additional_proxy_base_urls == [
            "https://mcp.example.com",
            "https://mcp.example.de",
        ]

    def test_surrounding_whitespace_and_trailing_commas_are_ignored(self):
        """Kubernetes manifests and .env files routinely introduce both; an
        empty entry would otherwise become an identity with no hostname."""
        config = self._config(" https://mcp.example.io , https://mcp.example.com ,, ")
        assert config.proxy_base_url == "https://mcp.example.io"
        assert config.additional_proxy_base_urls == ["https://mcp.example.com"]

    def test_only_separators_is_rejected(self):
        with pytest.raises(ValueError, match="no usable URL"):
            self._config(" , , ")

    def test_reads_a_list_from_the_environment(self):
        argv = [
            "authsome-mcp-proxy",
            "http://upstream",
            "--transport",
            "http",
            "--inbound-auth-provider",
            "keycloak",
            "--oidc-issuer-url",
            "https://kc/realms/r",
        ]
        with patch("sys.argv", argv):
            with patch.dict(
                os.environ,
                {
                    "MCP_PROXY_BASE_URL": "https://mcp.example.io,https://mcp.example.com"
                },
                clear=True,
            ):
                args = cli()
        config = build_proxy_config(args)
        assert isinstance(config, WebConfig)
        assert config.proxy_base_url == "https://mcp.example.io"
        assert config.additional_proxy_base_urls == ["https://mcp.example.com"]

    def test_duplicate_hostnames_are_rejected(self):
        with pytest.raises(ValueError, match="share the hostname"):
            self._config("https://mcp.example.com,https://mcp.example.com/other")


# ---------------------------------------------------------------------------
# Several upstreams
# ---------------------------------------------------------------------------

_HTTP_ARGS = [
    "--transport",
    "http",
    "--proxy-base-url",
    "https://mcp.example.com",
    "--inbound-auth-provider",
    "keycloak",
    "--oidc-issuer-url",
    "https://kc/realms/r",
]


def _web_config_from(argv: list[str], env: dict[str, str]) -> WebConfig:
    with patch("sys.argv", ["authsome-mcp-proxy", *argv]):
        with patch.dict(os.environ, env, clear=True):
            args = cli()
    config = build_proxy_config(args)
    assert isinstance(config, WebConfig)
    return config


class TestSeveralUpstreams:
    """UPSTREAMS / --upstream: one proxy, several upstreams, one identity."""

    def test_reads_routes_from_the_environment(self):
        config = _web_config_from(
            _HTTP_ARGS,
            {
                "UPSTREAMS": "secure, emb3d,",
                "UPSTREAM_SECURE_MCP_URL": "http://secure:8080/mcp",
                "UPSTREAM_EMB3D_MCP_URL": "http://emb3d:8080/mcp",
                "DEFAULT_UPSTREAM": "secure",
            },
        )
        assert [(r.name, r.mcp_url) for r in config.upstreams] == [
            ("secure", "http://secure:8080/mcp"),
            ("emb3d", "http://emb3d:8080/mcp"),
        ]
        assert config.default_upstream == "secure"

    def test_route_settings_fall_back_to_the_global_ones(self):
        """Each UPSTREAM_<NAME>_* variable is optional and defaults to its
        global counterpart, which defaults as in single-upstream mode."""
        config = _web_config_from(
            _HTTP_ARGS,
            {
                "UPSTREAMS": "secure,emb3d,repo",
                "UPSTREAM_SECURE_MCP_URL": "http://secure/mcp",
                "UPSTREAM_EMB3D_MCP_URL": "http://emb3d/mcp",
                "UPSTREAM_REPO_MCP_URL": "http://repo/mcp",
                "OUTBOUND_AUTH": "static",
                "OUTBOUND_HEADER_NAME": "X-API-Key",
                "OUTBOUND_HEADER_VALUE": "global-key",
                "UPSTREAM_SECURE_OUTBOUND_AUTH": "forward",
                "UPSTREAM_EMB3D_OUTBOUND_AUTH": "none",
                "UPSTREAM_REPO_OUTBOUND_HEADER_VALUE": "repo-key",
                "MCP_PROXY_NAME": "itemis",
                "MCP_PROXY_VERSION": "1.0.0",
                "UPSTREAM_EMB3D_PROXY_NAME": "EMB3D",
                "UPSTREAM_EMB3D_PROXY_INSTRUCTIONS": "Look up threats here.",
                "UPSTREAM_EMB3D_PROXY_WEBSITE_URL": "https://emb3d.example.com",
                "UPSTREAM_EMB3D_PROXY_VERSION": "2.0.0",
            },
        )
        secure, emb3d, repo = config.upstreams

        assert secure.outbound_auth == "forward"
        assert emb3d.outbound_auth == "none"
        assert repo.outbound_auth == "static"
        assert repo.outbound_header_name == "X-API-Key"
        assert repo.outbound_header_value == "repo-key"
        assert secure.outbound_header_value == "global-key"

        assert (secure.proxy_name, secure.proxy_version) == ("itemis", "1.0.0")
        assert (emb3d.proxy_name, emb3d.proxy_version) == ("EMB3D", "2.0.0")
        assert emb3d.proxy_instructions == "Look up threats here."
        assert emb3d.proxy_website_url == "https://emb3d.example.com"
        assert secure.proxy_instructions is None

    def test_route_defaults_without_any_global_setting(self):
        config = _web_config_from(
            _HTTP_ARGS,
            {"UPSTREAMS": "secure", "UPSTREAM_SECURE_MCP_URL": "http://secure/mcp"},
        )
        (route,) = config.upstreams
        assert route.outbound_auth == "forward"
        assert route.outbound_header_name == "Authorization"

    def test_client_credentials_settings_are_per_route_too(self):
        config = _web_config_from(
            _HTTP_ARGS,
            {
                "UPSTREAMS": "svc",
                "UPSTREAM_SVC_MCP_URL": "http://svc/mcp",
                "UPSTREAM_SVC_OUTBOUND_AUTH": "oauth-client-credentials",
                "UPSTREAM_SVC_OUTBOUND_CLIENT_ID": "svc-id",
                "UPSTREAM_SVC_OUTBOUND_CLIENT_SECRET": "svc-secret",
                "OUTBOUND_TOKEN_URL": "https://idp/token",
            },
        )
        (route,) = config.upstreams
        assert route.outbound_client_id == "svc-id"
        assert route.outbound_client_secret == "svc-secret"
        assert route.outbound_token_url == "https://idp/token"

    def test_dashes_in_names_become_underscores_in_variables(self):
        config = _web_config_from(
            _HTTP_ARGS,
            {
                "UPSTREAMS": "knowledge-base",
                "UPSTREAM_KNOWLEDGE_BASE_MCP_URL": "http://kb/mcp",
                "UPSTREAM_KNOWLEDGE_BASE_OUTBOUND_AUTH": "none",
            },
        )
        (route,) = config.upstreams
        assert route.path == "/knowledge-base/mcp"
        assert route.outbound_auth == "none"

    def test_reads_routes_from_repeated_flags(self):
        config = _web_config_from(
            [
                *_HTTP_ARGS,
                "--upstream",
                "secure=http://secure/mcp",
                "--upstream",
                "emb3d=http://emb3d/mcp?x=1",
                "--default-upstream",
                "emb3d",
            ],
            {"UPSTREAM_EMB3D_OUTBOUND_AUTH": "none"},
        )
        assert [(r.name, r.mcp_url) for r in config.upstreams] == [
            ("secure", "http://secure/mcp"),
            # Only the first '=' separates; the URL may contain more.
            ("emb3d", "http://emb3d/mcp?x=1"),
        ]
        assert config.upstreams[1].outbound_auth == "none"
        assert config.default_upstream == "emb3d"

    def test_flags_win_over_the_environment(self):
        config = _web_config_from(
            [*_HTTP_ARGS, "--upstream", "secure=http://from-flag/mcp"],
            {
                "UPSTREAMS": "emb3d",
                "UPSTREAM_EMB3D_MCP_URL": "http://emb3d/mcp",
                "UPSTREAM_SECURE_MCP_URL": "http://from-env/mcp",
            },
        )
        assert [(r.name, r.mcp_url) for r in config.upstreams] == [
            ("secure", "http://from-flag/mcp")
        ]

    @pytest.mark.parametrize("raw", ["secure", "=http://u/mcp", "secure="])
    def test_malformed_flag_is_a_usage_error(self, raw):
        with patch("sys.argv", ["authsome-mcp-proxy", *_HTTP_ARGS, "--upstream", raw]):
            with patch.dict(os.environ, {}, clear=True):
                with pytest.raises(SystemExit):
                    cli()

    def test_missing_route_url_names_the_variable(self):
        with pytest.raises(ValueError, match="UPSTREAM_EMB3D_MCP_URL is required"):
            _web_config_from(
                _HTTP_ARGS,
                {
                    "UPSTREAMS": "secure,emb3d",
                    "UPSTREAM_SECURE_MCP_URL": "http://s/mcp",
                },
            )

    def test_invalid_route_name_is_rejected(self):
        with pytest.raises(ValueError, match="'Secure' must match"):
            _web_config_from(
                _HTTP_ARGS,
                {"UPSTREAMS": "Secure", "UPSTREAM_SECURE_MCP_URL": "http://s/mcp"},
            )

    @pytest.mark.parametrize(
        "argv,env",
        [
            pytest.param(
                ["http://single/mcp"],
                {"UPSTREAMS": "secure", "UPSTREAM_SECURE_MCP_URL": "http://s/mcp"},
                id="positional",
            ),
            pytest.param(
                [],
                {
                    "UPSTREAM_MCP_URL": "http://single/mcp",
                    "UPSTREAMS": "secure",
                    "UPSTREAM_SECURE_MCP_URL": "http://s/mcp",
                },
                id="env",
            ),
            pytest.param(
                ["--upstream", "secure=http://s/mcp"],
                {"UPSTREAM_MCP_URL": "http://single/mcp"},
                id="flag",
            ),
        ],
    )
    def test_cannot_be_combined_with_a_single_upstream_url(self, argv, env):
        """Which of the two the operator meant is not guessable -- and silently
        preferring one would leave the other's clients pointed at nothing."""
        with pytest.raises(ValueError, match="UPSTREAMS.*UPSTREAM_MCP_URL"):
            _web_config_from([*argv, *_HTTP_ARGS], env)

    @pytest.mark.parametrize(
        "env",
        [
            {"UPSTREAMS": "secure", "UPSTREAM_SECURE_MCP_URL": "http://s/mcp"},
            {"DEFAULT_UPSTREAM": "secure"},
        ],
    )
    def test_stdio_mode_rejects_several_upstreams(self, env):
        with patch("sys.argv", ["authsome-mcp-proxy"]):
            with patch.dict(os.environ, env, clear=True):
                args = cli()
        with pytest.raises(ValueError, match="require --transport http"):
            build_proxy_config(args)

    def test_single_upstream_mode_is_unchanged(self):
        config = _web_config_from(["http://single/mcp", *_HTTP_ARGS], {})
        assert config.upstreams == []
        assert config.default_upstream is None
