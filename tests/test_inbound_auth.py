"""Tests for authsome_mcp_proxy.inbound_auth — provider factory dispatch."""

from unittest.mock import Mock, patch

import pytest

from authsome_mcp_proxy.config import WebConfig
from authsome_mcp_proxy.inbound_auth import (
    _disable_cimd,
    build_inbound_auth,
    share_authorization_server,
)


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

    def test_cognito_does_not_receive_an_enable_cimd_kwarg(self):
        """AWSCognitoProvider has no such keyword in any stable release up to
        3.4.7 (upstream added it for 4.0). Passing one would be a TypeError at
        construction, so the CIMD default has to be left alone here."""
        config = _cognito_config()
        with patch("authsome_mcp_proxy.inbound_auth.AWSCognitoProvider") as mock_class:
            build_inbound_auth(config)

        assert "enable_cimd" not in mock_class.call_args.kwargs

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
    and must not reach the two that can't.

    FastMCP implements CIMD inside ``OAuthProxy`` and defaults it on, so the
    only thing this proxy owns is forwarding the operator's choice. The tests
    that matter are the negative ones: an operator who turned CIMD off must
    actually get it off, including on the Cognito path where the keyword
    doesn't exist.
    """

    @pytest.mark.parametrize(
        ("provider", "patched", "extra"),
        [
            (
                "oidc",
                "OIDCProxy",
                {"issuer_url": "https://idp.example.com", "client_id": "cid"},
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
    def test_cognito_is_switched_after_construction(self, enable_cimd):
        """Enabled is what OIDCProxy's default already gives us, so only the
        off case may touch the provider."""
        config = _cognito_config(enable_cimd=enable_cimd)
        with (
            patch("authsome_mcp_proxy.inbound_auth.AWSCognitoProvider") as mock_class,
            patch("authsome_mcp_proxy.inbound_auth._disable_cimd") as mock_disable,
        ):
            provider = build_inbound_auth(config)

        assert provider is mock_class.return_value
        if enable_cimd:
            mock_disable.assert_not_called()
        else:
            mock_disable.assert_called_once_with(mock_class.return_value)

    def test_disable_cimd_clears_the_manager(self):
        """The switch itself, unmocked: what build_inbound_auth delegates to has
        to leave the attribute FastMCP gates CIMD on set to None."""

        class _FakeProxy:
            _cimd_manager = object()

        provider = _FakeProxy()
        _disable_cimd(provider)  # ty: ignore[invalid-argument-type]

        assert provider._cimd_manager is None

    def test_disable_cimd_raises_when_fastmcp_drops_the_attribute(self):
        """If a future FastMCP renames or removes ``_cimd_manager``, the switch
        must fail loudly rather than silently leave CIMD on."""
        with pytest.raises(RuntimeError, match="_cimd_manager"):
            _disable_cimd(Mock(spec=[]))

    @pytest.mark.parametrize("enable_cimd", [True, False])
    def test_keycloak_is_unaffected(self, enable_cimd):
        """Keycloak is the authorization server there, so the proxy has nothing
        to forward -- and nothing to reach into either."""
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            enable_cimd=enable_cimd,
        )
        with (
            patch("authsome_mcp_proxy.inbound_auth.KeycloakAuthProvider") as mock_class,
            patch("authsome_mcp_proxy.inbound_auth._disable_cimd") as mock_disable,
        ):
            build_inbound_auth(config)

        assert "enable_cimd" not in mock_class.call_args.kwargs
        mock_disable.assert_not_called()


# ---------------------------------------------------------------------------
# One authorization server for several MCP endpoints
# ---------------------------------------------------------------------------


class TestShareAuthorizationServer:
    """share_authorization_server widens an OAuthProxy from one endpoint to all
    the endpoints of an identity. The end-to-end effect is covered in
    test_path_router_integration; these pin down the mechanism."""

    BASE = "https://mcp.example.com"
    RESOURCES = (f"{BASE}/a/mcp", f"{BASE}/b/mcp", f"{BASE}/mcp")

    @pytest.fixture
    def provider(self, tmp_path, monkeypatch):
        """A real OIDCProxy, bound to two endpoints the way two apps bind it."""
        import fastmcp
        from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy

        monkeypatch.setattr(fastmcp.settings, "home", tmp_path)
        discovery = OIDCConfiguration(
            issuer="https://idp.example.com",
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
            jwks_uri="https://idp.example.com/jwks",
            response_types_supported=["code"],
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        config = WebConfig(
            inbound_auth_provider="oidc",
            proxy_base_url=self.BASE,
            issuer_url="https://idp.example.com",
            client_id="cid",
            client_secret="csec",
        )
        with patch.object(OIDCProxy, "get_oidc_configuration", return_value=discovery):
            provider = build_inbound_auth(config)
        provider.get_routes(mcp_path="/a/mcp")
        provider.get_routes(mcp_path="/b/mcp")
        return provider

    @staticmethod
    def _params(resource):
        from mcp.server.auth.provider import AuthorizationParams
        from pydantic import AnyUrl

        return AuthorizationParams(
            state="s",
            scopes=None,
            code_challenge="challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
            resource=resource,
        )

    def test_without_it_the_last_endpoint_wins(self, provider):
        """The problem being solved, pinned so a FastMCP change shows up here:
        every get_routes call rebinds the one provider."""
        assert str(provider._resource_url) == f"{self.BASE}/b/mcp"
        assert provider.jwt_issuer.audience == f"{self.BASE}/b/mcp"

    def test_binds_tokens_to_the_base_url(self, provider):
        share_authorization_server(provider, self.RESOURCES)
        assert provider.jwt_issuer.audience == f"{self.BASE}/"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "resource",
        [
            f"{BASE}/a/mcp",
            f"{BASE}/b/mcp",
            f"{BASE}/mcp",
            f"{BASE}/a/mcp/",
            # ChatGPT appends query parameters; FastMCP ignores them too.
            f"{BASE}/a/mcp?kb_name=x",
            None,
        ],
    )
    async def test_passes_every_served_resource_on_unchanged(self, provider, resource):
        """Unchanged, so the IdP is forwarded the same resource as in a
        single-endpoint deployment."""
        from unittest.mock import AsyncMock

        provider.authorize = AsyncMock(return_value="https://next")
        original = provider.authorize
        share_authorization_server(provider, self.RESOURCES)
        client, params = Mock(), self._params(resource)

        assert await provider.authorize(client, params) == "https://next"
        original.assert_awaited_once_with(client, params)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "resource",
        ["https://elsewhere.example.com/a/mcp", f"{BASE}/c/mcp", f"{BASE}/"],
    )
    async def test_refuses_any_other_resource(self, provider, resource):
        from unittest.mock import AsyncMock

        from mcp.server.auth.provider import AuthorizeError

        provider.authorize = AsyncMock()
        original = provider.authorize
        share_authorization_server(provider, self.RESOURCES)

        with pytest.raises(AuthorizeError) as raised:
            await provider.authorize(Mock(), self._params(resource))
        assert raised.value.error == "invalid_target"
        original.assert_not_awaited()

    def test_leaves_a_remote_auth_provider_alone(self):
        """keycloak: Keycloak is the authorization server, and nothing on the
        proxy side is bound to one endpoint."""
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url=self.BASE,
            issuer_url="https://kc.example.com/realms/r",
        )
        provider = build_inbound_auth(config)
        provider.get_routes(mcp_path="/a/mcp")

        share_authorization_server(provider, self.RESOURCES)

        assert str(provider._resource_url) == f"{self.BASE}/a/mcp"
        assert "authorize" not in vars(provider)

    def test_fails_loudly_when_tokens_are_not_bound_to_the_base_url(
        self, provider, monkeypatch
    ):
        """If FastMCP stops deriving the audience from the resource URL, one
        sign-in would silently stop covering every route."""
        monkeypatch.setattr(type(provider), "set_mcp_path", lambda self, path: None)
        with pytest.raises(RuntimeError, match="rather than the base URL"):
            share_authorization_server(provider, self.RESOURCES)

    def test_refuses_a_provider_with_identity_assertion(self, provider):
        """The jwt-bearer grant checks its resource against the same single URL;
        clearing it would switch that check off without replacing it."""
        provider._identity_assertion = Mock()
        with pytest.raises(RuntimeError, match="identity assertion"):
            share_authorization_server(provider, self.RESOURCES)
