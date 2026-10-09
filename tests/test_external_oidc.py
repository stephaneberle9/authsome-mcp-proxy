"""Tests for authsome_mcp_proxy.external_oidc module."""

import logging
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from authsome_mcp_proxy.external_oidc import (
    ExternalOIDCAuth,
    OIDCContext,
    _ExternalOIDCConfiguration,
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


class TestDiscoveryIssuerValidation:
    """Test that the discovery document's `issuer` must equal the configured
    issuer URL.

    The document's `issuer` is the reference value of the RFC 9207 `iss` check
    on the authorization callback, so it must be anchored to the
    configuration rather than taken on the discovery response's word.
    """

    @staticmethod
    def _make_auth(
        tmp_path: Path, configured_issuer_url: str, published_issuer: str
    ) -> ExternalOIDCAuth:
        """Construct the auth against a discovery response publishing
        `published_issuer`.

        The response goes through fastmcp's real discovery parsing, so the
        tests also pin that the published `issuer` is compared as the literal
        string, not as a URL normalized by pydantic.
        """
        response = Mock()
        response.json.return_value = {
            "issuer": published_issuer,
            "authorization_endpoint": f"{published_issuer.rstrip('/')}/authorize",
            "token_endpoint": f"{published_issuer.rstrip('/')}/token",
            "jwks_uri": f"{published_issuer.rstrip('/')}/certs",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        with (
            patch("authsome_mcp_proxy.external_oidc._setup_token_refresh_logging"),
            patch("authsome_mcp_proxy.external_oidc.httpx2.get", return_value=response),
        ):
            return ExternalOIDCAuth(
                issuer_url=configured_issuer_url,
                client_id="test-client",
                token_storage_cache_dir=tmp_path / "cache",
            )

    @staticmethod
    def _unique_issuer() -> str:
        # fastmcp caches discovery documents by discovery URL, which is the
        # same with and without a trailing slash on the issuer URL; a host of
        # its own keeps every test from being served another test's document.
        return f"https://{uuid.uuid4().hex}.example.com/realms/test"

    def test_matching_issuer_is_accepted(self, tmp_path):
        """A document whose `issuer` is identical to the configured issuer URL
        may be used (OpenID Connect Discovery 1.0, section 4.3)."""
        issuer = self._unique_issuer()

        auth = self._make_auth(tmp_path, issuer, issuer)

        assert auth.context.oidc_config.issuer == issuer

    def test_mismatching_issuer_is_rejected(self, tmp_path):
        """A document naming another issuer must not be used (OpenID Connect
        Discovery 1.0, section 4.3); otherwise the `iss` check on the callback
        would compare against an issuer the configuration never named."""
        issuer = self._unique_issuer()

        with pytest.raises(ValueError) as excinfo:
            self._make_auth(tmp_path, issuer, ATTACKER_ISSUER)

        assert str(excinfo.value) == (
            f"OIDC configuration issuer {ATTACKER_ISSUER} does not match "
            f"the configured issuer URL {issuer}"
        )

    def test_trailing_slash_on_configured_issuer_url_only_is_rejected(self, tmp_path):
        """OpenID Connect Discovery 1.0, section 4.3 requires the two values to
        be identical, so a trailing slash on the configured issuer URL only is a
        mismatch, not normalized away; the error names both values so the user
        can correct the configured URL."""
        issuer = self._unique_issuer()

        with pytest.raises(ValueError) as excinfo:
            self._make_auth(tmp_path, f"{issuer}/", issuer)

        assert str(excinfo.value) == (
            f"OIDC configuration issuer {issuer} does not match "
            f"the configured issuer URL {issuer}/"
        )

    def test_trailing_slash_on_published_issuer_only_is_rejected(self, tmp_path):
        """OpenID Connect Discovery 1.0, section 4.3 requires the two values to
        be identical, so a trailing slash on the published `issuer` only is a
        mismatch too; the configured URL must then carry the slash as well."""
        issuer = self._unique_issuer()

        with pytest.raises(ValueError) as excinfo:
            self._make_auth(tmp_path, issuer, f"{issuer}/")

        assert str(excinfo.value) == (
            f"OIDC configuration issuer {issuer}/ does not match "
            f"the configured issuer URL {issuer}"
        )


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
            mock_oidc_config.issuer = "https://auth.example.com"
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
        mock_oidc_config.issuer = "https://auth.example.com"
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
        mock_oidc_config.issuer = "https://auth.example.com"
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
        mock_oidc_config.issuer = "https://auth.example.com"
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
        mock_oidc_config.issuer = "https://auth.example.com"
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


ISSUER = "https://auth.example.com/realms/test"
ATTACKER_ISSUER = "https://attacker.example.com"


class TestIssValidation:
    """Test RFC 9207 `iss` validation on the authorization callback.

    `iss` defends against mix-up attacks: a callback carrying another
    authorization server's code must be rejected before that code is redeemed
    at this provider's token endpoint.
    """

    @staticmethod
    def _make_auth(tmp_path: Path, iss_supported: bool | None) -> ExternalOIDCAuth:
        oidc_config = _ExternalOIDCConfiguration(
            strict=False,
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            authorization_response_iss_parameter_supported=iss_supported,
        )
        with (
            patch("authsome_mcp_proxy.external_oidc._setup_token_refresh_logging"),
            patch(
                "authsome_mcp_proxy.external_oidc.OIDCConfiguration.get_oidc_configuration",
                return_value=oidc_config,
            ),
        ):
            auth = ExternalOIDCAuth(
                issuer_url=ISSUER,
                client_id="test-client",
                token_storage_cache_dir=tmp_path / "cache",
            )
        auth.context.storage = AsyncMock()
        return auth

    @staticmethod
    async def _run_flow(
        auth: ExternalOIDCAuth, returned_iss: str | None
    ) -> tuple[RuntimeError | None, Mock]:
        """Run the auth flow with a callback carrying `returned_iss`.

        Returns the flow's RuntimeError (None on success) and the token
        endpoint mock, so callers can assert whether the authorization code
        was redeemed.
        """
        opened_urls: list[str] = []

        async def callback() -> tuple[str, str, str | None]:
            # Echo the flow's own state, so only `iss` decides the outcome
            state = parse_qs(urlparse(opened_urls[0]).query)["state"][0]
            return "auth-code", state, returned_iss

        token_response = Mock()
        token_response.json.return_value = {
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        token_response.raise_for_status = Mock()

        with (
            patch(
                "authsome_mcp_proxy.external_oidc.webbrowser.open",
                side_effect=opened_urls.append,
            ),
            patch.object(auth, "_run_callback_server", side_effect=callback),
            patch("httpx2.AsyncClient.post", return_value=token_response) as token_post,
        ):
            try:
                await auth._perform_auth_flow()
            except RuntimeError as e:
                return e, token_post
        return None, token_post

    def test_discovery_keeps_iss_parameter_supported_flag(self):
        """The RFC 9207 flag survives discovery parsing.

        fastmcp's OIDCConfiguration drops undeclared fields; without the
        subclass the flag would be lost and `iss` could never be required.
        """
        config = _ExternalOIDCConfiguration.model_validate(
            {
                "strict": False,
                "issuer": ISSUER,
                "authorization_response_iss_parameter_supported": True,
            }
        )

        assert config.authorization_response_iss_parameter_supported is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("iss_supported", [True, False])
    async def test_matching_iss_is_accepted(self, tmp_path, iss_supported):
        """A callback naming this provider proceeds to the token exchange,
        whether or not the provider advertised `iss` support."""
        auth = self._make_auth(tmp_path, iss_supported)

        error, token_post = await self._run_flow(auth, ISSUER)

        assert error is None
        token_post.assert_called_once()
        assert auth.context.get_access_token() == "access-token"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("iss_supported", [True, False])
    async def test_mismatching_iss_is_rejected(self, tmp_path, iss_supported):
        """A callback naming another server is a mix-up; it is rejected before
        the code reaches the token endpoint, even without advertised support,
        because a present `iss` identifies its sender either way."""
        auth = self._make_auth(tmp_path, iss_supported)

        error, token_post = await self._run_flow(auth, ATTACKER_ISSUER)

        assert error is not None
        assert str(error) == (
            f"OAuth iss mismatch: {ATTACKER_ISSUER} != {ISSUER} - possible mix-up attack"
        )
        token_post.assert_not_called()

    @pytest.mark.asyncio
    async def test_iss_with_added_trailing_slash_is_rejected(self, tmp_path):
        """`iss` is compared with the discovery `issuer` by plain string
        comparison (RFC 9207, section 2.4), so an `iss` that differs only by a
        trailing slash does not match."""
        auth = self._make_auth(tmp_path, True)

        error, token_post = await self._run_flow(auth, f"{ISSUER}/")

        assert error is not None
        assert str(error).startswith("OAuth iss mismatch")
        token_post.assert_not_called()

    @pytest.mark.asyncio
    async def test_absent_iss_is_rejected_when_support_is_advertised(self, tmp_path):
        """A provider advertising `iss` support always sends it, so a callback
        without `iss` did not come from that provider."""
        auth = self._make_auth(tmp_path, True)

        error, token_post = await self._run_flow(auth, None)

        assert error is not None
        assert str(error) == (
            f"OAuth iss missing: expected {ISSUER} - possible mix-up attack"
        )
        token_post.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("iss_supported", [False, None])
    async def test_absent_iss_is_accepted_without_advertised_support(
        self, tmp_path, iss_supported
    ):
        """Providers that do not implement RFC 9207 omit `iss`; requiring it
        would lock their users out. An explicit `false` and an absent flag
        mean the same."""
        auth = self._make_auth(tmp_path, iss_supported)

        error, token_post = await self._run_flow(auth, None)

        assert error is None
        token_post.assert_called_once()
        assert auth.context.get_access_token() == "access-token"
