"""Integration tests for authsome_mcp_proxy.external_oidc module."""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from mcp.shared.auth import OAuthToken

from authsome_mcp_proxy.external_oidc import ExternalOIDCAuth


class TestExternalOIDCAuthIntegration:
    """Integration tests for ExternalOIDCAuth with mocked OIDC server."""

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    def test_initialization_fetches_oidc_config(self, mock_get):
        """Test that initialization fetches OIDC configuration from well-known endpoint."""
        # Mock the OIDC configuration endpoint response
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            scopes="openid profile email",
        )

        # Verify the OIDC config was fetched
        mock_get.assert_called_once()
        call_args = mock_get.call_args[0][0]
        assert "https://auth.example.com/.well-known/openid-configuration" in str(
            call_args
        )

        # Verify the context was initialized correctly
        assert auth.context.issuer_url == "https://auth.example.com"
        assert auth.context.client_id == "test-client"
        assert auth.context.client_secret == "test-secret"
        assert auth.context.scopes == ["openid", "profile", "email"]

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    def test_initialization_with_list_scopes(self, mock_get):
        """Test initialization with scopes as a list."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            scopes=["openid", "profile", "email", "custom_scope"],
        )

        assert auth.context.scopes == ["openid", "profile", "email", "custom_scope"]

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    def test_initialization_with_custom_redirect_url(self, mock_get):
        """Test initialization with custom redirect URL."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            redirect_url="http://localhost:9999/custom/callback",
        )

        assert auth.context.redirect_uri == "http://localhost:9999/custom/callback"

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    async def test_initialize_loads_cached_tokens(self, mock_get):
        """Test that _initialize loads tokens from storage."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com", client_id="test-client"
        )

        # Mock the storage to return a token
        mock_token = OAuthToken(
            access_token="cached-access-token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="cached-refresh-token",
        )

        with patch.object(
            auth.context.storage, "get_tokens", new=AsyncMock(return_value=mock_token)
        ):
            # Initialize
            await auth._initialize()

            # Verify tokens were loaded
            assert auth.context.current_tokens == mock_token
            assert auth.context.token_expiry_time is not None

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    async def test_initialize_handles_no_cached_tokens(self, mock_get):
        """Test that _initialize handles missing cached tokens."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com", client_id="test-client"
        )

        # Mock the storage to return None
        with patch.object(
            auth.context.storage, "get_tokens", new=AsyncMock(return_value=None)
        ):
            # Initialize
            await auth._initialize()

            # Verify no tokens are set
            assert auth.context.current_tokens is None

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    @patch("authsome_mcp_proxy.external_oidc.httpx2.AsyncClient")
    async def test_refresh_tokens_success(self, mock_async_client, mock_get):
        """Test successful token refresh."""
        # Mock OIDC config
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
        )

        # Set current tokens with refresh token
        old_token = OAuthToken(
            access_token="old-access-token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh-token-123",
        )
        auth.context.current_tokens = old_token

        # Mock the refresh token response
        mock_http_response = Mock()
        mock_http_response.json.return_value = {
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token",
        }
        mock_http_response.raise_for_status = Mock()

        mock_client_instance = AsyncMock()
        mock_client_instance.post = AsyncMock(return_value=mock_http_response)
        mock_async_client.return_value.__aenter__.return_value = mock_client_instance

        # Mock storage
        with patch.object(
            auth.context.storage, "set_tokens", new=AsyncMock()
        ) as mock_set_tokens:
            # Refresh tokens
            new_tokens = await auth._refresh_tokens()

            # Verify new tokens were set
            assert new_tokens.access_token == "new-access-token"
            assert new_tokens.refresh_token == "new-refresh-token"
            assert auth.context.current_tokens.access_token == "new-access-token"

            # Verify storage was updated
            mock_set_tokens.assert_called_once()

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    async def test_refresh_tokens_raises_without_refresh_token(self, mock_get):
        """Test that _refresh_tokens raises error when no refresh token available."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com", client_id="test-client"
        )

        # Set tokens without refresh token
        auth.context.current_tokens = OAuthToken(
            access_token="access-token", token_type="Bearer"
        )

        # Try to refresh - should raise error
        with pytest.raises(RuntimeError, match="No refresh token available"):
            await auth._refresh_tokens()

    @patch("authsome_mcp_proxy.external_oidc.httpx2.get")
    async def test_get_token_returns_cached_valid_token(self, mock_get):
        """Test that _get_token returns cached token if still valid."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_get.return_value = mock_response

        auth = ExternalOIDCAuth(
            issuer_url="https://auth.example.com", client_id="test-client"
        )

        # Mock storage to return valid token
        valid_token = OAuthToken(
            access_token="valid-token", token_type="Bearer", expires_in=3600
        )

        with patch.object(
            auth.context.storage, "get_tokens", new=AsyncMock(return_value=valid_token)
        ):
            # Get token
            token = await auth._get_token()

            # Should return the cached token
            assert token == "valid-token"
