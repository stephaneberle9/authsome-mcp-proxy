"""Tests for authsome_mcp_proxy.inbound_auth — provider factory dispatch."""

from unittest.mock import patch

import pytest

from authsome_mcp_proxy.config import WebConfig
from authsome_mcp_proxy.inbound_auth import build_inbound_auth


def _cognito_config(**overrides) -> WebConfig:
    return WebConfig(
        inbound_auth_provider="aws-cognito",
        proxy_base_url="https://mcp.example.com",
        client_id="cid",
        client_secret="csec",
        cognito_user_pool_id="eu-central-1_abc",
        cognito_aws_region="eu-central-1",
        scopes="openid",
        **overrides,
    )


class TestInboundAuthDispatch:
    """Each WebConfig.inbound_auth_provider value should instantiate the matching
    FastMCP provider class with the right per-IdP kwargs.

    The provider classes are patched at the inbound_auth module so we don't
    hit the network for OIDC discovery / JWKS during unit tests.
    """

    def test_keycloak_dispatches_to_KeycloakAuthProvider(self):
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            scopes="openid email",
            audience="mcp-server",
        )
        with patch(
            "authsome_mcp_proxy.inbound_auth.KeycloakAuthProvider"
        ) as mock_class:
            build_inbound_auth(config)

        mock_class.assert_called_once_with(
            realm_url="https://kc.example.com/realms/r",
            base_url="https://mcp.example.com",
            required_scopes=["openid", "email"],
            audience="mcp-server",
        )

    def test_oidc_dispatches_to_OIDCProxy_with_derived_config_url(self):
        config = WebConfig(
            inbound_auth_provider="oidc",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://idp.example.com",
            client_id="cid",
            client_secret="csec",
            scopes="openid",
        )
        with patch("authsome_mcp_proxy.inbound_auth.OIDCProxy") as mock_class:
            build_inbound_auth(config)

        mock_class.assert_called_once_with(
            config_url="https://idp.example.com/.well-known/openid-configuration",
            client_id="cid",
            client_secret="csec",
            audience=None,
            required_scopes=["openid"],
            base_url="https://mcp.example.com",
            enable_cimd=True,
        )

    def test_oidc_strips_trailing_slash_from_issuer(self):
        config = WebConfig(
            inbound_auth_provider="oidc",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://idp.example.com/",
            client_id="cid",
        )
        with patch("authsome_mcp_proxy.inbound_auth.OIDCProxy") as mock_class:
            build_inbound_auth(config)

        kwargs = mock_class.call_args.kwargs
        assert (
            kwargs["config_url"]
            == "https://idp.example.com/.well-known/openid-configuration"
        )

    def test_aws_cognito_dispatches_to_AWSCognitoProvider(self):
        config = WebConfig(
            inbound_auth_provider="aws-cognito",
            proxy_base_url="https://mcp.example.com",
            client_id="cid",
            client_secret="csec",
            cognito_user_pool_id="eu-central-1_abc",
            cognito_aws_region="eu-central-1",
            scopes="openid",
        )
        with patch("authsome_mcp_proxy.inbound_auth.AWSCognitoProvider") as mock_class:
            build_inbound_auth(config)

        mock_class.assert_called_once_with(
            user_pool_id="eu-central-1_abc",
            aws_region="eu-central-1",
            client_id="cid",
            client_secret="csec",
            required_scopes=["openid"],
            base_url="https://mcp.example.com",
            enable_cimd=True,
        )

    def test_google_dispatches_to_GoogleProvider(self):
        config = WebConfig(
            inbound_auth_provider="google",
            proxy_base_url="https://mcp.example.com",
            client_id="cid",
            client_secret="csec",
        )
        with patch("authsome_mcp_proxy.inbound_auth.GoogleProvider") as mock_class:
            build_inbound_auth(config)

        mock_class.assert_called_once_with(
            client_id="cid",
            client_secret="csec",
            required_scopes=None,
            base_url="https://mcp.example.com",
            enable_cimd=True,
        )

    def test_azure_dispatches_to_AzureProvider(self):
        config = WebConfig(
            inbound_auth_provider="azure",
            proxy_base_url="https://mcp.example.com",
            client_id="cid",
            client_secret="csec",
            azure_tenant_id="tid",
            azure_identifier_uri="api://example",
            scopes="user.read profile",
        )
        with patch("authsome_mcp_proxy.inbound_auth.AzureProvider") as mock_class:
            build_inbound_auth(config)

        mock_class.assert_called_once_with(
            client_id="cid",
            client_secret="csec",
            tenant_id="tid",
            identifier_uri="api://example",
            required_scopes=["user.read", "profile"],
            base_url="https://mcp.example.com",
            enable_cimd=True,
        )

    def test_unknown_provider_raises(self):
        # Bypass dataclass-level Literal validation by mutating after construction.
        config = WebConfig(
            inbound_auth_provider="oidc",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://idp.example.com",
            client_id="cid",
        )
        config.inbound_auth_provider = "made-up-provider"  # type: ignore[assignment]  # ty: ignore[invalid-assignment]
        with pytest.raises(ValueError, match="Unknown inbound_auth_provider"):
            build_inbound_auth(config)


class TestCimdToggle:
    """``WebConfig.enable_cimd`` has to reach every provider that can act on it,
    and must not reach Keycloak, which can't.

    FastMCP implements CIMD inside ``OAuthProxy`` and defaults it on, so the
    only thing this proxy owns is forwarding the operator's choice. The tests
    that matter are the negative ones: an operator who turned CIMD off must
    actually get it off.
    """

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
                {
                    "client_id": "cid",
                    "azure_tenant_id": "tid",
                    "scopes": "user.read",
                },
            ),
        ],
    )
    @pytest.mark.parametrize("enable_cimd", [True, False])
    def test_flag_is_forwarded_to_providers_that_accept_it(
        self, provider, patched, extra, enable_cimd
    ):
        config = WebConfig(
            inbound_auth_provider=provider,
            proxy_base_url="https://mcp.example.com",
            enable_cimd=enable_cimd,
            **extra,
        )
        with patch(f"authsome_mcp_proxy.inbound_auth.{patched}") as mock_class:
            build_inbound_auth(config)

        assert mock_class.call_args.kwargs["enable_cimd"] is enable_cimd

    @pytest.mark.parametrize("enable_cimd", [True, False])
    def test_keycloak_is_unaffected(self, enable_cimd):
        """Keycloak is the authorization server there, so the proxy has nothing
        to forward."""
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            enable_cimd=enable_cimd,
        )
        with patch(
            "authsome_mcp_proxy.inbound_auth.KeycloakAuthProvider"
        ) as mock_class:
            build_inbound_auth(config)

        assert "enable_cimd" not in mock_class.call_args.kwargs
