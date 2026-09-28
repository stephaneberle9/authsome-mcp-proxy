"""Tests for authsome_mcp_proxy.external_oidc module."""

import logging
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from authsome_mcp_proxy.external_oidc import (
    ExternalOIDCAuth,
    OIDCContext,
    _setup_token_refresh_logging,
)


class TestOIDCContext:
    """Test OIDCContext dataclass and methods."""

    def test_get_redirect_port_with_port(self):
        """Test extracting port from redirect URI."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        assert context.get_redirect_port() == 8080

    def test_get_redirect_port_default(self):
        """Test default port when not specified."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        assert context.get_redirect_port() == 80

    def test_get_redirect_path_with_port(self):
        """Test extracting path from redirect URI."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:80/auth/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        assert context.get_redirect_path() == "/auth/callback"

    def test_is_token_valid_no_tokens(self):
        """Test is_token_valid returns False when no tokens."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        assert context.is_token_valid() is False

    def test_can_refresh_token_no_tokens(self):
        """Test can_refresh_token returns False when no tokens."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        assert context.can_refresh_token() is False

    def test_clear_tokens(self):
        """Test clear_tokens sets current_tokens to None."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )
        context.current_tokens = Mock()

        context.clear_tokens()

        assert context.current_tokens is None

    def test_get_token_exchange_data_with_secret(self):
        """Test token exchange data includes client secret when provided."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        pkce = Mock(code_verifier="test-verifier")
        data = context.get_token_exchange_data("auth-code", pkce)

        assert data["grant_type"] == "authorization_code"
        assert data["code"] == "auth-code"
        assert data["client_id"] == "test-client"
        assert data["client_secret"] == "test-secret"
        assert data["code_verifier"] == "test-verifier"
        assert data["redirect_uri"] == "http://localhost:8080/callback"

    def test_get_token_exchange_data_without_secret(self):
        """Test token exchange data excludes client secret when not provided."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        pkce = Mock(code_verifier="test-verifier")
        data = context.get_token_exchange_data("auth-code", pkce)

        assert "client_secret" not in data

    def test_get_authorization_url(self):
        """Test building authorization URL with PKCE parameters."""
        oidc_config = Mock()
        oidc_config.authorization_endpoint = "https://auth.example.com/authorize"

        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid", "profile"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=oidc_config,
            storage=Mock(),
        )

        pkce = Mock(code_challenge="test-challenge")
        url = context.get_authorization_url("test-state", pkce)

        assert "https://auth.example.com/authorize?" in url
        assert "client_id=test-client" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback" in url
        assert "scope=openid+profile" in url
        assert "state=test-state" in url
        assert "code_challenge=test-challenge" in url
        assert "code_challenge_method=S256" in url

    def test_get_token_refresh_data_with_secret(self):
        """Test token refresh data includes client secret when provided."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        mock_token = Mock()
        mock_token.refresh_token = "refresh-token-123"
        context.current_tokens = mock_token

        data = context.get_token_refresh_data()

        assert data["grant_type"] == "refresh_token"
        assert data["refresh_token"] == "refresh-token-123"
        assert data["client_id"] == "test-client"
        assert data["client_secret"] == "test-secret"

    def test_get_token_refresh_data_without_secret(self):
        """Test token refresh data excludes client secret when not provided."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        mock_token = Mock()
        mock_token.refresh_token = "refresh-token-123"
        context.current_tokens = mock_token

        data = context.get_token_refresh_data()

        assert "client_secret" not in data

    def test_set_tokens_with_expires_in(self):
        """Test setting tokens updates expiry time when expires_in is provided."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        mock_token = Mock()
        mock_token.expires_in = 3600  # 1 hour

        context.set_tokens(mock_token)

        assert context.current_tokens is mock_token
        assert context.token_expiry_time is not None
        assert context.token_expiry_time > 0

    def test_set_tokens_without_expires_in(self):
        """Test setting tokens when expires_in is not provided."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        mock_token = Mock()
        mock_token.expires_in = None

        context.set_tokens(mock_token)

        assert context.current_tokens is mock_token
        assert context.token_expiry_time is None

    def test_is_token_valid_with_valid_token(self):
        """Test is_token_valid returns True for valid non-expired token."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        mock_token = Mock()
        mock_token.access_token = "valid-token"
        mock_token.expires_in = 3600
        context.set_tokens(mock_token)

        assert context.is_token_valid() is True

    def test_can_refresh_token_with_refresh_token(self):
        """Test can_refresh_token returns True when refresh token exists."""
        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=Mock(),
            storage=Mock(),
        )

        mock_token = Mock()
        mock_token.refresh_token = "refresh-token-123"
        context.current_tokens = mock_token

        assert context.can_refresh_token() is True


class TestExternalOIDCAuth:
    """Test ExternalOIDCAuth initialization and validation."""

    def test_init_raises_on_missing_issuer_url(self):
        """Test that __init__ raises ValueError when issuer_url is empty."""
        with pytest.raises(ValueError, match="Missing required issuer URL"):
            ExternalOIDCAuth(issuer_url="", client_id="test-client")

    def test_init_raises_on_missing_client_id(self):
        """Test that __init__ raises ValueError when client_id is empty."""
        with pytest.raises(ValueError, match="Missing required client id"):
            ExternalOIDCAuth(issuer_url="https://auth.example.com", client_id="")


class TestTokenRefreshLogging:
    """Test token refresh logging setup and functionality."""

    def test_setup_token_refresh_logging_creates_file_handler(self, tmp_path):
        """Test that _setup_token_refresh_logging creates a file handler in the cache directory."""
        from authsome_mcp_proxy import external_oidc

        # Reset global state
        external_oidc._token_refresh_log_handler = None

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        _setup_token_refresh_logging(cache_dir)

        # Verify log file was created
        log_file = cache_dir / "token_refresh.log"
        assert log_file.exists()

        # Verify handler was created and attached
        assert external_oidc._token_refresh_log_handler is not None
        assert isinstance(external_oidc._token_refresh_log_handler, logging.FileHandler)

        # Clean up
        logger = logging.getLogger("authsome_mcp_proxy.external_oidc")
        if external_oidc._token_refresh_log_handler:
            logger.removeHandler(external_oidc._token_refresh_log_handler)
        external_oidc._token_refresh_log_handler = None

    def test_setup_token_refresh_logging_only_runs_once(self, tmp_path):
        """Test that _setup_token_refresh_logging only sets up logging once."""
        from authsome_mcp_proxy import external_oidc

        # Reset global state
        external_oidc._token_refresh_log_handler = None

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Call setup twice
        _setup_token_refresh_logging(cache_dir)
        first_handler = external_oidc._token_refresh_log_handler

        _setup_token_refresh_logging(cache_dir)
        second_handler = external_oidc._token_refresh_log_handler

        # Should be the same handler instance
        assert first_handler is second_handler

        # Clean up
        logger = logging.getLogger("authsome_mcp_proxy.external_oidc")
        if external_oidc._token_refresh_log_handler:
            logger.removeHandler(external_oidc._token_refresh_log_handler)
        external_oidc._token_refresh_log_handler = None

    def test_setup_token_refresh_logging_creates_log_file(self, tmp_path):
        """Test that log file is created at the correct path."""
        from authsome_mcp_proxy import external_oidc

        # Reset global state
        external_oidc._token_refresh_log_handler = None

        cache_dir = tmp_path / "test_cache"
        cache_dir.mkdir()

        _setup_token_refresh_logging(cache_dir)

        log_file = cache_dir / "token_refresh.log"
        assert log_file.exists()
        assert log_file.is_file()

        # Clean up
        logger = logging.getLogger("authsome_mcp_proxy.external_oidc")
        if external_oidc._token_refresh_log_handler:
            logger.removeHandler(external_oidc._token_refresh_log_handler)
        external_oidc._token_refresh_log_handler = None

    def test_setup_token_refresh_logging_handler_config(self, tmp_path):
        """Test that the file handler is configured correctly."""
        from authsome_mcp_proxy import external_oidc

        # Reset global state
        external_oidc._token_refresh_log_handler = None

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        _setup_token_refresh_logging(cache_dir)

        handler = external_oidc._token_refresh_log_handler
        assert handler is not None

        # Verify handler configuration
        assert handler.level == logging.DEBUG
        assert isinstance(handler.formatter, logging.Formatter)

        # Verify formatter format
        formatter = handler.formatter
        assert formatter._fmt == "%(asctime)s [%(levelname)s] %(message)s"
        assert formatter.datefmt == "%Y-%m-%d %H:%M:%S"

        # Clean up
        logger = logging.getLogger("authsome_mcp_proxy.external_oidc")
        if external_oidc._token_refresh_log_handler:
            logger.removeHandler(external_oidc._token_refresh_log_handler)
        external_oidc._token_refresh_log_handler = None

    def test_logging_writes_to_file(self, tmp_path):
        """Test that log messages are actually written to the file."""
        from authsome_mcp_proxy import external_oidc

        # Reset global state
        external_oidc._token_refresh_log_handler = None

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        _setup_token_refresh_logging(cache_dir)

        # Write a log message
        logger = logging.getLogger("authsome_mcp_proxy.external_oidc")
        # Ensure logger level allows DEBUG messages
        original_level = logger.level
        logger.setLevel(logging.DEBUG)

        test_message = "[REFRESH] Test refresh token message"
        logger.info(test_message)

        # Force flush and close to ensure write
        if external_oidc._token_refresh_log_handler:
            external_oidc._token_refresh_log_handler.flush()
            external_oidc._token_refresh_log_handler.close()

        # Verify message was written
        log_file = cache_dir / "token_refresh.log"
        log_content = log_file.read_text(encoding="utf-8")
        assert test_message in log_content

        # Clean up
        if external_oidc._token_refresh_log_handler:
            logger.removeHandler(external_oidc._token_refresh_log_handler)
        logger.setLevel(original_level)
        external_oidc._token_refresh_log_handler = None

    def test_external_oidc_auth_calls_setup_logging(self, tmp_path):
        """Test that ExternalOIDCAuth calls _setup_token_refresh_logging during init."""
        from authsome_mcp_proxy import external_oidc

        # Reset global state
        external_oidc._token_refresh_log_handler = None

        # Mock both the OIDC config fetch and the setup_logging call
        with (
            patch(
                "authsome_mcp_proxy.external_oidc._setup_token_refresh_logging"
            ) as mock_setup,
            patch(
                "authsome_mcp_proxy.external_oidc.OIDCConfiguration.get_oidc_configuration"
            ) as mock_get_config,
        ):
            # Mock the OIDC config response
            mock_oidc_config = Mock()
            mock_oidc_config.authorization_endpoint = (
                "https://auth.example.com/authorize"
            )
            mock_oidc_config.token_endpoint = "https://auth.example.com/token"
            mock_get_config.return_value = mock_oidc_config

            # Create ExternalOIDCAuth instance with custom cache dir
            ExternalOIDCAuth(
                issuer_url="https://auth.example.com",
                client_id="test-client",
                token_storage_cache_dir=tmp_path / "cache",
            )

            # Verify setup was called
            mock_setup.assert_called_once()
            # Get the actual call args
            call_args = mock_setup.call_args[0][0]
            assert isinstance(call_args, Path)
            assert "cache" in str(call_args)


class TestTokenRefresh:
    """Test token refresh logic, especially the critical bug fix for preserving refresh tokens."""

    @pytest.mark.asyncio
    async def test_refresh_preserves_existing_refresh_token_when_not_in_response(self):
        """Test that refresh token is preserved when not included in refresh response.

        This is the critical bug fix - OAuth 2.0 spec allows omitting refresh_token
        from refresh responses, expecting clients to reuse the existing one.
        """
        # Create a mock OIDC context with existing tokens
        mock_storage = AsyncMock()
        mock_oidc_config = Mock()
        mock_oidc_config.token_endpoint = "https://auth.example.com/token"

        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=mock_oidc_config,
            storage=mock_storage,
        )

        # Set existing tokens with a refresh token
        from authsome_mcp_proxy.external_oidc import OAuthToken

        existing_tokens = OAuthToken(
            access_token="old-access-token",
            refresh_token="existing-refresh-token",
            expires_in=3600,
            token_type="Bearer",
        )
        context.set_tokens(existing_tokens)

        # Mock httpx2 post response - refresh response WITHOUT refresh_token (common with Cognito, etc.)
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            # NOTE: No refresh_token in response
        }
        mock_response.raise_for_status = Mock()

        # Create ExternalOIDCAuth and test _refresh_tokens
        with (
            patch(
                "authsome_mcp_proxy.external_oidc.OIDCConfiguration.get_oidc_configuration"
            ) as mock_get_config,
            patch("httpx2.AsyncClient.post", return_value=mock_response),
        ):
            mock_get_config.return_value = mock_oidc_config

            auth = ExternalOIDCAuth(
                issuer_url="https://auth.example.com",
                client_id="test-client",
            )
            auth.context = context

            # Call _refresh_tokens
            await auth._refresh_tokens()

            # Verify that the refresh token was preserved
            assert auth.context.current_tokens is not None
            assert auth.context.current_tokens.access_token == "new-access-token"
            assert (
                auth.context.current_tokens.refresh_token == "existing-refresh-token"
            )  # PRESERVED!

            # Verify storage was updated with preserved refresh token
            mock_storage.set_tokens.assert_called_once()
            saved_tokens = mock_storage.set_tokens.call_args[0][0]
            assert saved_tokens.access_token == "new-access-token"
            assert saved_tokens.refresh_token == "existing-refresh-token"

    @pytest.mark.asyncio
    async def test_refresh_updates_refresh_token_when_in_response(self):
        """Test that refresh token is updated when included in refresh response."""
        # Create a mock OIDC context with existing tokens
        mock_storage = AsyncMock()
        mock_oidc_config = Mock()
        mock_oidc_config.token_endpoint = "https://auth.example.com/token"

        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=mock_oidc_config,
            storage=mock_storage,
        )

        # Set existing tokens
        from authsome_mcp_proxy.external_oidc import OAuthToken

        existing_tokens = OAuthToken(
            access_token="old-access-token",
            refresh_token="old-refresh-token",
            expires_in=3600,
            token_type="Bearer",
        )
        context.set_tokens(existing_tokens)

        # Mock httpx2 post response - refresh response WITH new refresh_token
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",  # New refresh token provided
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = Mock()

        # Create ExternalOIDCAuth and test _refresh_tokens
        with (
            patch(
                "authsome_mcp_proxy.external_oidc.OIDCConfiguration.get_oidc_configuration"
            ) as mock_get_config,
            patch("httpx2.AsyncClient.post", return_value=mock_response),
        ):
            mock_get_config.return_value = mock_oidc_config

            auth = ExternalOIDCAuth(
                issuer_url="https://auth.example.com",
                client_id="test-client",
            )
            auth.context = context

            # Call _refresh_tokens
            await auth._refresh_tokens()

            # Verify that both tokens were updated
            assert auth.context.current_tokens is not None
            assert auth.context.current_tokens.access_token == "new-access-token"
            assert (
                auth.context.current_tokens.refresh_token == "new-refresh-token"
            )  # UPDATED!

            # Verify storage was updated with new refresh token
            mock_storage.set_tokens.assert_called_once()
            saved_tokens = mock_storage.set_tokens.call_args[0][0]
            assert saved_tokens.access_token == "new-access-token"
            assert saved_tokens.refresh_token == "new-refresh-token"

    @pytest.mark.asyncio
    async def test_refresh_updates_token_expiry_time(self):
        """Test that token refresh updates the expiry time correctly."""
        # Create a mock OIDC context
        mock_storage = AsyncMock()
        mock_oidc_config = Mock()
        mock_oidc_config.token_endpoint = "https://auth.example.com/token"

        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=mock_oidc_config,
            storage=mock_storage,
        )

        # Set existing tokens
        from authsome_mcp_proxy.external_oidc import OAuthToken

        existing_tokens = OAuthToken(
            access_token="old-access-token",
            refresh_token="existing-refresh-token",
            expires_in=300,  # 5 minutes
            token_type="Bearer",
        )
        context.set_tokens(existing_tokens)
        old_expiry = context.token_expiry_time
        assert old_expiry is not None

        # Mock httpx2 post response with different expires_in
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 7200,  # 2 hours
        }
        mock_response.raise_for_status = Mock()

        # Create ExternalOIDCAuth and test _refresh_tokens
        with (
            patch(
                "authsome_mcp_proxy.external_oidc.OIDCConfiguration.get_oidc_configuration"
            ) as mock_get_config,
            patch("httpx2.AsyncClient.post", return_value=mock_response),
        ):
            mock_get_config.return_value = mock_oidc_config

            auth = ExternalOIDCAuth(
                issuer_url="https://auth.example.com",
                client_id="test-client",
            )
            auth.context = context

            # Call _refresh_tokens
            await auth._refresh_tokens()

            # Verify that expiry time was updated
            assert auth.context.token_expiry_time is not None
            assert auth.context.token_expiry_time > old_expiry
            assert auth.context.current_tokens is not None
            assert auth.context.current_tokens.expires_in == 7200

    @pytest.mark.asyncio
    async def test_refresh_fails_when_no_refresh_token_available(self):
        """Test that refresh fails gracefully when no refresh token is available."""
        # Create a mock OIDC context without tokens
        mock_storage = AsyncMock()
        mock_oidc_config = Mock()
        mock_oidc_config.token_endpoint = "https://auth.example.com/token"

        context = OIDCContext(
            issuer_url="https://auth.example.com",
            client_id="test-client",
            client_secret=None,
            scopes=["openid"],
            redirect_uri="http://localhost:8080/callback",
            oidc_config=mock_oidc_config,
            storage=mock_storage,
        )

        # No tokens set - context.current_tokens is None

        # Create ExternalOIDCAuth
        with patch(
            "authsome_mcp_proxy.external_oidc.OIDCConfiguration.get_oidc_configuration"
        ) as mock_get_config:
            mock_get_config.return_value = mock_oidc_config

            auth = ExternalOIDCAuth(
                issuer_url="https://auth.example.com",
                client_id="test-client",
            )
            auth.context = context

            # Attempt to refresh should raise RuntimeError
            with pytest.raises(RuntimeError, match="No refresh token available"):
                await auth._refresh_tokens()
