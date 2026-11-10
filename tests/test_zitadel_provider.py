"""Unit tests for the vendored ZITADEL OAuth provider.

Ported from FastMCP's ``tests/server/auth/providers/test_zitadel.py``
(PrefectHQ/fastmcp#6392), so the vendored copy stays covered against the
fastmcp release this project resolves. FastMCP's HTTP mocking fixture is not
available here; the introspection tests hand the provider a shared client on an
``httpx2.MockTransport`` instead. Delete this file together with
:mod:`authsome_mcp_proxy.zitadel_provider`.
"""

import base64
import time
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager, contextmanager
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from fastmcp.server.auth.oidc_proxy import _clear_oidc_configuration_cache
from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier

from authsome_mcp_proxy.zitadel_provider import ZitadelProvider

ZITADEL_DOMAIN = "https://my-instance-abc123.zitadel.cloud"
INTROSPECTION_URL = f"{ZITADEL_DOMAIN}/oauth/v2/introspect"
CLIENT_ID = "123456789012345678"
CLIENT_SECRET = "zitadel-secret"
PROJECT_ID = "987654321098765432"


@pytest.fixture(autouse=True)
def clear_oidc_discovery_cache():
    """fastmcp caches OIDC discovery per process; without a reset, a document
    fetched by one test answers the next one's discovery and the mock is never
    called. FastMCP's own suite does the same in its auth conftest."""
    _clear_oidc_configuration_cache()
    yield
    _clear_oidc_configuration_cache()


def _discovery_document(domain: str = ZITADEL_DOMAIN) -> dict[str, Any]:
    return {
        "issuer": domain,
        "authorization_endpoint": f"{domain}/oauth/v2/authorize",
        "token_endpoint": f"{domain}/oauth/v2/token",
        "introspection_endpoint": f"{domain}/oauth/v2/introspect",
        "userinfo_endpoint": f"{domain}/oidc/v1/userinfo",
        "revocation_endpoint": f"{domain}/oauth/v2/revoke",
        "end_session_endpoint": f"{domain}/oidc/v1/end_session",
        "jwks_uri": f"{domain}/oauth/v2/keys",
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "private_key_jwt",
        ],
    }


@contextmanager
def mock_zitadel_discovery(
    document: dict[str, Any] | None = None,
) -> Generator[Any]:
    """Mock ZITADEL's OIDC discovery endpoint."""
    with patch("httpx2.get") as mock_get:
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = document or _discovery_document()
        yield mock_get


@asynccontextmanager
async def introspection_client(
    payload: dict[str, Any],
) -> AsyncIterator[tuple[httpx2.AsyncClient, list[httpx2.Request]]]:
    """A client whose every request gets ``payload``, recording the requests."""
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, json=payload)

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        yield client, requests


def _make_provider(**overrides: Any) -> ZitadelProvider:
    kwargs: dict[str, Any] = {
        "domain": ZITADEL_DOMAIN,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "base_url": "https://mcp.example.com",
        "jwt_signing_key": "test-signing-key",
    }
    kwargs.update(overrides)
    return ZitadelProvider(**kwargs)


class TestZitadelProviderInit:
    def test_discovers_endpoints(self):
        with mock_zitadel_discovery() as mock_get:
            provider = _make_provider()

        mock_get.assert_called_once()
        assert (
            str(mock_get.call_args.args[0])
            == f"{ZITADEL_DOMAIN}/.well-known/openid-configuration"
        )
        assert (
            provider._upstream_authorization_endpoint
            == f"{ZITADEL_DOMAIN}/oauth/v2/authorize"
        )
        assert provider._upstream_token_endpoint == f"{ZITADEL_DOMAIN}/oauth/v2/token"
        assert provider._upstream_client_id == CLIENT_ID
        assert provider._upstream_client_secret is not None
        assert provider._upstream_client_secret.get_secret_value() == CLIENT_SECRET

    def test_defaults(self):
        with mock_zitadel_discovery():
            provider = _make_provider()

        assert provider.domain == ZITADEL_DOMAIN
        assert provider._redirect_path == "/auth/callback"
        assert provider._token_endpoint_auth_method == "client_secret_basic"
        assert provider.required_scopes == ["openid"]

    @pytest.mark.parametrize(
        ("domain", "expected"),
        [
            ("my-instance-abc123.zitadel.cloud", ZITADEL_DOMAIN),
            (f"{ZITADEL_DOMAIN}/", ZITADEL_DOMAIN),
            ("http://localhost:8080", "http://localhost:8080"),
        ],
    )
    def test_normalizes_domain(self, domain: str, expected: str):
        with mock_zitadel_discovery(_discovery_document(expected)) as mock_get:
            provider = _make_provider(domain=domain)

        assert provider.domain == expected
        assert (
            str(mock_get.call_args.args[0])
            == f"{expected}/.well-known/openid-configuration"
        )

    def test_custom_scopes_and_auth_method(self):
        with mock_zitadel_discovery():
            provider = _make_provider(
                required_scopes="openid offline_access",
                valid_scopes=["openid", "offline_access", "profile", "email"],
                token_endpoint_auth_method="client_secret_post",
            )

        assert provider.required_scopes == ["openid", "offline_access"]
        assert provider._token_endpoint_auth_method == "client_secret_post"
        # Introspection still uses HTTP Basic: ZITADEL rejects POST there
        verifier = provider._token_validator
        assert isinstance(verifier, IntrospectionTokenVerifier)
        assert verifier.client_auth_method == "client_secret_basic"
        assert verifier.required_scopes == ["openid", "offline_access"]

    def test_requires_client_secret(self):
        with pytest.raises(ValueError, match="client secret"):
            _make_provider(client_secret="")

    def test_requires_domain(self):
        with pytest.raises(ValueError, match="domain"):
            _make_provider(domain="")

    def test_requires_introspection_endpoint(self):
        document = _discovery_document()
        del document["introspection_endpoint"]
        with mock_zitadel_discovery(document):
            with pytest.raises(ValueError, match="introspection_endpoint"):
                _make_provider()


class TestZitadelTokenVerifier:
    def test_uses_introspection(self):
        with mock_zitadel_discovery():
            provider = _make_provider(introspection_cache_ttl_seconds=60)

        verifier = provider._token_validator
        assert isinstance(verifier, IntrospectionTokenVerifier)
        assert verifier.introspection_url == INTROSPECTION_URL
        assert verifier.client_id == CLIENT_ID
        assert verifier.client_secret == CLIENT_SECRET
        assert verifier.audience == CLIENT_ID
        assert verifier.required_scopes == ["openid"]
        assert verifier._cache._ttl == 60
        assert verifier._http_client is None

    async def test_reuses_shared_http_client(self):
        async with httpx2.AsyncClient() as http_client:
            with mock_zitadel_discovery():
                provider = _make_provider(http_client=http_client)

            verifier = provider._token_validator
            assert isinstance(verifier, IntrospectionTokenVerifier)
            assert verifier._http_client is http_client

    async def test_verifies_active_token(self):
        async with introspection_client(
            {
                "active": True,
                "scope": "openid profile email",
                "client_id": CLIENT_ID,
                "token_type": "Bearer",
                "exp": int(time.time()) + 3600,
                "aud": [CLIENT_ID, PROJECT_ID],
                "sub": "user-1",
                "email": "jane@example.com",
            }
        ) as (client, requests):
            with mock_zitadel_discovery():
                provider = _make_provider(http_client=client)

            token = await provider._token_validator.verify_token("opaque-token")

            assert token is not None
            assert token.subject == "user-1"
            assert token.scopes == ["openid", "profile", "email"]
            assert token.claims["email"] == "jane@example.com"

            assert len(requests) == 1
            request = requests[0]
            assert str(request.url) == INTROSPECTION_URL
            expected_auth = base64.b64encode(
                f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
            ).decode()
            assert request.headers["Authorization"] == f"Basic {expected_auth}"
            assert parse_qs(request.content.decode())["token"] == ["opaque-token"]

    async def test_rejects_token_for_sibling_application(self):
        """A token issued to another app of the same project lacks our client ID."""
        async with introspection_client(
            {
                "active": True,
                "scope": "openid",
                "exp": int(time.time()) + 3600,
                "aud": ["other-client-id", PROJECT_ID],
                "sub": "user-1",
            }
        ) as (client, requests):
            with mock_zitadel_discovery():
                provider = _make_provider(http_client=client)

            assert await provider._token_validator.verify_token("opaque-token") is None

    async def test_rejects_token_missing_required_scope(self):
        async with introspection_client(
            {
                "active": True,
                "scope": "openid",
                "exp": int(time.time()) + 3600,
                "aud": [CLIENT_ID, PROJECT_ID],
                "sub": "user-1",
            }
        ) as (client, requests):
            with mock_zitadel_discovery():
                provider = _make_provider(
                    required_scopes=["openid", "offline_access"], http_client=client
                )

            assert await provider._token_validator.verify_token("opaque-token") is None


class TestZitadelAuthorizeUrl:
    def test_does_not_send_audience_parameter(self):
        with mock_zitadel_discovery():
            provider = _make_provider()

        url = provider._build_upstream_authorize_url(
            "txn-1", {"scopes": ["openid", "offline_access"]}
        )
        params = parse_qs(urlparse(url).query)

        assert url.startswith(f"{ZITADEL_DOMAIN}/oauth/v2/authorize?")
        assert "audience" not in params
        assert params["client_id"] == [CLIENT_ID]
        assert params["scope"] == ["openid offline_access"]
        assert params["redirect_uri"] == ["https://mcp.example.com/auth/callback"]
