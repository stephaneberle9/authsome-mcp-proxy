"""Tests for authsome_mcp_proxy.config module."""

from typing import Any

import pytest

from authsome_mcp_proxy.config import DesktopConfig, UpstreamRoute, WebConfig


class TestDesktopConfig:
    """Tests for the stdio-mode DesktopConfig dataclass."""

    def test_minimal_required_fields(self):
        config = DesktopConfig(
            issuer_url="https://auth.example.com", client_id="test-client"
        )

        assert config.issuer_url == "https://auth.example.com"
        assert config.client_id == "test-client"
        assert config.client_secret is None
        assert config.scopes is None
        assert config.redirect_url is None

    def test_full_initialization(self):
        config = DesktopConfig(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            scopes="openid profile email",
            redirect_url="http://localhost:8080/callback",
        )

        assert config.client_secret == "test-secret"
        assert config.scopes == "openid profile email"
        assert config.redirect_url == "http://localhost:8080/callback"

    def test_equality(self):
        a = DesktopConfig(issuer_url="https://x", client_id="c")
        b = DesktopConfig(issuer_url="https://x", client_id="c")
        assert a == b

    def test_inequality(self):
        a = DesktopConfig(issuer_url="https://x", client_id="c")
        b = DesktopConfig(issuer_url="https://y", client_id="c")
        assert a != b


class TestWebConfigInbound:
    """Per-provider inbound validation in WebConfig.__post_init__."""

    def test_keycloak_requires_issuer_url(self):
        with pytest.raises(ValueError, match="keycloak.*issuer_url"):
            WebConfig(
                inbound_auth_provider="keycloak",
                proxy_base_url="https://mcp.example.com",
            )

    def test_keycloak_does_not_require_client_id(self):
        # RemoteAuthProvider mode: no client credentials needed on the proxy.
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
        )
        assert config.client_id is None
        assert config.client_secret is None

    def test_oidc_requires_issuer_and_client_id(self):
        with pytest.raises(ValueError, match="oidc.*issuer_url"):
            WebConfig(
                inbound_auth_provider="oidc", proxy_base_url="https://mcp.example.com"
            )
        with pytest.raises(ValueError, match="oidc.*client_id"):
            WebConfig(
                inbound_auth_provider="oidc",
                proxy_base_url="https://mcp.example.com",
                issuer_url="https://idp.example.com",
            )

    def test_aws_cognito_requires_full_set(self):
        with pytest.raises(
            ValueError,
            match="aws-cognito.*client_id.*client_secret.*cognito_user_pool_id.*cognito_aws_region",
        ):
            WebConfig(
                inbound_auth_provider="aws-cognito",
                proxy_base_url="https://mcp.example.com",
            )

    def test_aws_cognito_happy_path(self):
        config = WebConfig(
            inbound_auth_provider="aws-cognito",
            proxy_base_url="https://mcp.example.com",
            client_id="cid",
            client_secret="csec",
            cognito_user_pool_id="eu-central-1_abc",
            cognito_aws_region="eu-central-1",
        )
        assert config.cognito_user_pool_id == "eu-central-1_abc"

    def test_cimd_defaults_to_enabled(self):
        """Matches FastMCP's own enable_cimd default, so an operator who
        configures nothing keeps accepting CIMD client IDs."""
        config = WebConfig(
            inbound_auth_provider="oidc",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://idp.example.com",
            client_id="cid",
        )
        assert config.enable_cimd is True

    def test_cimd_can_be_disabled_for_any_provider(self):
        """No __post_init__ rule guards this: off is legal everywhere, even
        where it is inert (keycloak)."""
        keycloak = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
            enable_cimd=False,
        )
        oidc = WebConfig(
            inbound_auth_provider="oidc",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://idp.example.com",
            client_id="cid",
            enable_cimd=False,
        )

        assert keycloak.enable_cimd is False
        assert oidc.enable_cimd is False

    def test_google_requires_client_id(self):
        with pytest.raises(ValueError, match="google.*client_id"):
            WebConfig(
                inbound_auth_provider="google", proxy_base_url="https://mcp.example.com"
            )

    def test_azure_requires_tenant_and_scopes(self):
        with pytest.raises(ValueError, match="azure.*azure_tenant_id"):
            WebConfig(
                inbound_auth_provider="azure",
                proxy_base_url="https://mcp.example.com",
                client_id="cid",
            )
        with pytest.raises(ValueError, match="azure.*scopes"):
            WebConfig(
                inbound_auth_provider="azure",
                proxy_base_url="https://mcp.example.com",
                client_id="cid",
                azure_tenant_id="tid",
            )

    def test_azure_happy_path(self):
        config = WebConfig(
            inbound_auth_provider="azure",
            proxy_base_url="https://mcp.example.com",
            client_id="cid",
            azure_tenant_id="tid",
            scopes="user.read",
        )
        assert config.azure_tenant_id == "tid"


class TestWebConfigOutbound:
    """Per-mode outbound validation in WebConfig.__post_init__."""

    def _base_keycloak_kwargs(self) -> dict:
        return {
            "inbound_auth_provider": "keycloak",
            "proxy_base_url": "https://mcp.example.com",
            "issuer_url": "https://kc.example.com/realms/r",
        }

    def test_default_outbound_is_forward(self):
        config = WebConfig(**self._base_keycloak_kwargs())
        assert config.outbound_auth == "forward"

    def test_oauth_client_credentials_requires_all_fields(self):
        with pytest.raises(
            ValueError,
            match="oauth-client-credentials.*outbound_client_id.*outbound_client_secret.*outbound_token_url",
        ):
            WebConfig(
                **self._base_keycloak_kwargs(),
                outbound_auth="oauth-client-credentials",
            )

    def test_oauth_client_credentials_happy_path(self):
        config = WebConfig(
            **self._base_keycloak_kwargs(),
            outbound_auth="oauth-client-credentials",
            outbound_client_id="ocid",
            outbound_client_secret="osec",
            outbound_token_url="https://idp.example.com/token",
        )
        assert config.outbound_auth == "oauth-client-credentials"

    def test_none_needs_no_further_fields(self):
        config = WebConfig(**self._base_keycloak_kwargs(), outbound_auth="none")
        assert config.outbound_auth == "none"

    def test_static_requires_header_value(self):
        with pytest.raises(ValueError, match="static.*outbound_header_value"):
            WebConfig(**self._base_keycloak_kwargs(), outbound_auth="static")

    def test_static_happy_path_with_default_header_name(self):
        config = WebConfig(
            **self._base_keycloak_kwargs(),
            outbound_auth="static",
            outbound_header_value="Bearer abc123",
        )
        assert config.outbound_header_name == "Authorization"

    def test_static_happy_path_with_custom_header_name(self):
        config = WebConfig(
            **self._base_keycloak_kwargs(),
            outbound_auth="static",
            outbound_header_name="X-API-Key",
            outbound_header_value="abc123",
        )
        assert config.outbound_header_name == "X-API-Key"


# ---------------------------------------------------------------------------
# Multiple public base URLs
# ---------------------------------------------------------------------------


def test_all_proxy_base_urls_puts_canonical_first():
    """Order is load-bearing: the first entry is the identity that answers
    requests with no or an unrecognized Host."""
    config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.io",
        additional_proxy_base_urls=[
            "https://mcp.example.com",
            "https://mcp.example.de",
        ],
        issuer_url="https://kc.example.com/realms/r",
    )
    assert config.all_proxy_base_urls == [
        "https://mcp.example.io",
        "https://mcp.example.com",
        "https://mcp.example.de",
    ]


def test_all_proxy_base_urls_defaults_to_the_canonical_alone():
    config = WebConfig(
        inbound_auth_provider="keycloak",
        proxy_base_url="https://mcp.example.com",
        issuer_url="https://kc.example.com/realms/r",
    )
    assert config.all_proxy_base_urls == ["https://mcp.example.com"]


def test_rejects_additional_base_url_duplicating_the_canonical_hostname():
    """Scheme or port differences don't make two identities distinguishable --
    the Host header carries neither."""
    with pytest.raises(ValueError, match="share the hostname"):
        WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            additional_proxy_base_urls=["http://mcp.example.com:8000"],
            issuer_url="https://kc.example.com/realms/r",
        )


def test_rejects_base_url_without_a_hostname():
    with pytest.raises(ValueError, match="no hostname"):
        WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            additional_proxy_base_urls=["mcp.example.com"],
            issuer_url="https://kc.example.com/realms/r",
        )


# ---------------------------------------------------------------------------
# Several upstreams
# ---------------------------------------------------------------------------


def _multi(**overrides) -> WebConfig:
    kwargs: dict[str, Any] = {
        "inbound_auth_provider": "keycloak",
        "proxy_base_url": "https://mcp.example.com",
        "issuer_url": "https://kc.example.com/realms/r",
        "upstreams": [
            UpstreamRoute(name="secure", mcp_url="http://secure:8080/mcp"),
            UpstreamRoute(name="emb3d", mcp_url="http://emb3d:8080/mcp"),
        ],
    }
    kwargs.update(overrides)
    return WebConfig(**kwargs)


class TestUpstreamRoute:
    @pytest.mark.parametrize("name", ["secure", "emb3d", "knowledge-base", "0day", "a"])
    def test_accepts_path_and_env_safe_names(self, name):
        assert UpstreamRoute(name=name, mcp_url="http://u/mcp").path == f"/{name}/mcp"

    @pytest.mark.parametrize(
        "name", ["", "Secure", "-secure", "emb_3d", "a/b", "a.b", "mcp ", "ümlaut"]
    )
    def test_rejects_names_that_are_not_path_and_env_safe(self, name):
        """The name becomes both a path segment and part of an environment
        variable name; underscores would make two names map to one variable."""
        with pytest.raises(ValueError, match="must match"):
            UpstreamRoute(name=name, mcp_url="http://u/mcp")

    def test_requires_a_url(self):
        with pytest.raises(ValueError, match="'secure' requires mcp_url"):
            UpstreamRoute(name="secure", mcp_url="")

    def test_defaults_match_the_single_upstream_defaults(self):
        route = UpstreamRoute(name="secure", mcp_url="http://u/mcp")
        assert route.outbound_auth == "forward"
        assert route.outbound_header_name == "Authorization"
        assert route.proxy_name is None

    def test_outbound_validation_names_the_route(self):
        with pytest.raises(
            ValueError, match="upstream 'emb3d': outbound_auth='static' requires"
        ):
            UpstreamRoute(name="emb3d", mcp_url="http://u/mcp", outbound_auth="static")
        with pytest.raises(
            ValueError,
            match="upstream 'emb3d': outbound_auth='oauth-client-credentials' "
            "requires outbound_client_id",
        ):
            UpstreamRoute(
                name="emb3d",
                mcp_url="http://u/mcp",
                outbound_auth="oauth-client-credentials",
            )

    def test_none_needs_no_further_fields(self):
        route = UpstreamRoute(
            name="emb3d", mcp_url="http://u/mcp", outbound_auth="none"
        )
        assert route.outbound_auth == "none"

    def test_rejects_an_unknown_outbound_mode(self):
        """Env values bypass argparse's choices, so a typo has to be caught here
        -- and name the route it was meant for."""
        with pytest.raises(ValueError, match="upstream 'emb3d': outbound_auth must be"):
            UpstreamRoute(
                name="emb3d",
                mcp_url="http://u/mcp",
                outbound_auth="nope",  # ty: ignore[invalid-argument-type]
            )


class TestWebConfigUpstreams:
    def test_single_upstream_by_default(self):
        """Every existing deployment: no routes, no default."""
        config = WebConfig(
            inbound_auth_provider="keycloak",
            proxy_base_url="https://mcp.example.com",
            issuer_url="https://kc.example.com/realms/r",
        )
        assert config.upstreams == []
        assert config.default_upstream is None

    def test_default_upstream_must_be_a_route(self):
        assert _multi(default_upstream="secure").default_upstream == "secure"
        with pytest.raises(ValueError, match="'other' is not among the upstreams"):
            _multi(default_upstream="other")

    def test_default_upstream_requires_upstreams(self):
        with pytest.raises(ValueError, match="default_upstream requires upstreams"):
            _multi(upstreams=[], default_upstream="secure")

    def test_route_names_must_be_unique(self):
        """Two routes with one name would share a path; the second would never
        be reachable."""
        route = UpstreamRoute(name="secure", mcp_url="http://a/mcp")
        twin = UpstreamRoute(name="secure", mcp_url="http://b/mcp")
        with pytest.raises(ValueError, match="duplicated: secure"):
            _multi(upstreams=[route, twin])

    def test_top_level_outbound_is_not_validated_with_upstreams(self):
        """With routes, the top-level outbound settings are unused -- each route
        validates its own -- so an incomplete one must not block startup."""
        config = _multi(outbound_auth="static")
        assert config.outbound_header_value is None
