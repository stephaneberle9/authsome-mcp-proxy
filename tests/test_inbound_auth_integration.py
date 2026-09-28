"""End-to-end check that the CIMD switch reaches the advertised OAuth metadata.

The unit tests verify that ``enable_cimd`` is forwarded to the FastMCP provider
classes. This one goes the rest of the way: it builds a real ``OIDCProxy``
through :func:`build_inbound_auth`, mounts it exactly as the proxy does, and
reads ``/.well-known/oauth-authorization-server`` back over ASGI. What clients
discover there is the only thing that actually decides whether they may present
an HTTPS URL as their ``client_id`` -- and it is set deep inside FastMCP's
``OAuthProxy.get_routes()``, well below anything this repo mocks.

That also makes this the tripwire for FastMCP changing its own CIMD default or
moving the flag: CIMD is in beta upstream.
"""

from unittest.mock import patch

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from fastmcp.server.http import create_streamable_http_app

from authsome_mcp_proxy.config import WebConfig
from authsome_mcp_proxy.inbound_auth import build_inbound_auth

BASE_URL = "https://mcp.example.com"
ISSUER = "https://idp.example.com"

AS_METADATA_PATH = "/.well-known/oauth-authorization-server"


def _oidc_configuration() -> OIDCConfiguration:
    """A discovery document, so constructing OIDCProxy reaches no network.

    ``OIDCProxy.__init__`` fetches ``config_url`` eagerly and refuses anything
    without an authorization and token endpoint; the JWKS behind ``jwks_uri``
    is only fetched when a token is actually verified, which these tests never
    do.
    """
    return OIDCConfiguration(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/jwks",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
    )


def _oidc_config(*, enable_cimd: bool) -> WebConfig:
    return WebConfig(
        inbound_auth_provider="oidc",
        proxy_base_url=BASE_URL,
        issuer_url=ISSUER,
        client_id="cid",
        client_secret="csec",
        scopes="openid",
        enable_cimd=enable_cimd,
    )


def _cognito_config(*, enable_cimd: bool) -> WebConfig:
    return WebConfig(
        inbound_auth_provider="aws-cognito",
        proxy_base_url=BASE_URL,
        client_id="cid",
        client_secret="csec",
        cognito_user_pool_id="eu-central-1_abc",
        cognito_aws_region="eu-central-1",
        scopes="openid",
        enable_cimd=enable_cimd,
    )


def _app(*, enable_cimd: bool, config: WebConfig | None = None):
    config = config if config is not None else _oidc_config(enable_cimd=enable_cimd)
    server = FastMCP(name="test-proxy")
    with patch.object(
        OIDCProxy, "get_oidc_configuration", return_value=_oidc_configuration()
    ):
        auth = build_inbound_auth(config)
    return create_streamable_http_app(
        server=server, streamable_http_path="/mcp", auth=auth
    )


async def _metadata(app) -> dict:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE_URL
    ) as client:
        response = await client.get(AS_METADATA_PATH)
    response.raise_for_status()
    return response.json()


@pytest.mark.asyncio
async def test_cimd_is_advertised_by_default():
    """The decisive property: a client reading discovery is told it may use a
    CIMD URL as its client_id."""
    metadata = await _metadata(_app(enable_cimd=True))

    assert metadata["client_id_metadata_document_supported"] is True


@pytest.mark.asyncio
async def test_cimd_is_not_advertised_when_disabled():
    """``--no-enable-cimd`` has to reach the wire, not just the constructor."""
    metadata = await _metadata(_app(enable_cimd=False))

    assert not metadata.get("client_id_metadata_document_supported")


@pytest.mark.asyncio
@pytest.mark.parametrize("enable_cimd", [True, False])
async def test_cognito_switch_reaches_the_metadata_too(enable_cimd):
    """The Cognito path can't take an ``enable_cimd`` keyword, so it is switched
    by clearing ``_cimd_manager`` after construction. That workaround is only
    worth anything if it changes what clients actually discover -- assert it
    here rather than trusting the private attribute."""
    metadata = await _metadata(
        _app(enable_cimd=enable_cimd, config=_cognito_config(enable_cimd=enable_cimd))
    )

    assert metadata.get("client_id_metadata_document_supported") is (
        True if enable_cimd else None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("enable_cimd", [True, False])
async def test_dcr_stays_available_either_way(enable_cimd):
    """CIMD is additive. Whichever way the switch is thrown, clients that
    register dynamically must still find a registration endpoint."""
    metadata = await _metadata(_app(enable_cimd=enable_cimd))

    assert metadata["registration_endpoint"] == f"{BASE_URL}/register"


@pytest.mark.asyncio
@pytest.mark.parametrize("build_config", [_oidc_config, _cognito_config])
async def test_cimd_advertises_public_client_token_auth(build_config):
    """Advertising CIMD is not on its own enough to get a client to use it.

    Claude selects CIMD only when the metadata *also* offers ``none`` in
    ``token_endpoint_auth_methods_supported`` -- its CIMD client authenticates as
    a public client -- and falls back to DCR when that is missing. FastMCP adds
    ``none`` and ``private_key_jwt`` on the CIMD branch of ``get_routes()``
    since 3.4.3 (every 4.x has it too): on 3.3.1 the proxy advertised CIMD
    that no Claude client would ever select.

    Asserted over ASGI rather than against the floor, because the floor is the
    means and this is the end. Only the positive is asserted: with CIMD off,
    which methods a public-client proxy ought to advertise is upstream's call,
    and fastmcp 4.0 narrows the set to ``none`` unconditionally.
    """
    metadata = await _metadata(
        _app(enable_cimd=True, config=build_config(enable_cimd=True))
    )

    assert "none" in metadata["token_endpoint_auth_methods_supported"]
