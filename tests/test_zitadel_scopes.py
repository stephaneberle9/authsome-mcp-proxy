"""``--oidc-scopes`` with ZITADEL project-audience scopes, end to end.

``--oidc-scopes`` does two jobs for the ``zitadel`` provider: the scopes are
sent to ZITADEL's ``/authorize``, and they become the verifier's
``required_scopes``, checked on every request against the ``scope`` field of
ZITADEL's introspection response. A forwarding deployment whose upstream calls
other ZITADEL projects needs reserved scopes of the form
``urn:zitadel:iam:org:project:id:<id>:aud`` there. Were introspection to leave
those out of ``scope``, requesting one would reject every token.

It does not: ZITADEL echoes the requested scopes verbatim, reserved ones
included (observed on ZITADEL Cloud with an opaque access token from the
authorization code flow). The introspection payload below has the shape of
that response; the test pins that the proxy's wiring accepts it, so the two
jobs can stay on one setting.

Kept apart from ``test_zitadel_provider.py``, which mirrors FastMCP's own test
module for the vendored provider.
"""

import time
from urllib.parse import parse_qs, urlparse

from authsome_mcp_proxy.config import WebConfig
from authsome_mcp_proxy.inbound_auth import build_inbound_auth
from authsome_mcp_proxy.zitadel_provider import ZitadelProvider

from .test_zitadel_provider import (
    CLIENT_ID,
    CLIENT_SECRET,
    PROJECT_ID,
    ZITADEL_DOMAIN,
    clear_oidc_discovery_cache,  # noqa: F401  (autouse fixture)
    introspection_client,
    mock_zitadel_discovery,
)

OTHER_PROJECT_ID = "111111111111111111"
AUDIENCE_SCOPE = f"urn:zitadel:iam:org:project:id:{OTHER_PROJECT_ID}:aud"
SCOPES = f"openid profile email {AUDIENCE_SCOPE}"


def _config() -> WebConfig:
    return WebConfig(
        inbound_auth_provider="zitadel",
        proxy_base_url="https://mcp.example.com",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        zitadel_domain=ZITADEL_DOMAIN,
        scopes=SCOPES,
        jwt_signing_key="a-signing-key-shared-by-every-replica",
    )


def _introspection(scope: str) -> dict:
    return {
        "active": True,
        "scope": scope,
        "client_id": CLIENT_ID,
        "token_type": "Bearer",
        "exp": int(time.time()) + 3600,
        # The application's own project arrives without being asked for; the
        # other project is there because its scope was requested.
        "aud": [CLIENT_ID, PROJECT_ID, OTHER_PROJECT_ID],
        "sub": "user-1",
    }


async def test_project_audience_scope_is_requested_and_accepted():
    async with introspection_client(_introspection(SCOPES)) as (client, _):
        with mock_zitadel_discovery():
            provider = build_inbound_auth(_config(), http_client=client)
        assert isinstance(provider, ZitadelProvider)

        url = provider._build_upstream_authorize_url(
            "txn-1", {"scopes": SCOPES.split()}
        )
        token = await provider._token_validator.verify_token("opaque-token")

    assert parse_qs(urlparse(url).query)["scope"] == [SCOPES]
    assert token is not None
    assert AUDIENCE_SCOPE in token.scopes


async def test_token_without_the_project_audience_scope_is_rejected():
    """The other half of the same check: a token obtained without the scope --
    which therefore lacks the upstream's audience -- does not get through."""
    async with introspection_client(_introspection("openid profile email")) as (
        client,
        _,
    ):
        with mock_zitadel_discovery():
            provider = build_inbound_auth(_config(), http_client=client)
        assert isinstance(provider, ZitadelProvider)

        token = await provider._token_validator.verify_token("opaque-token")

    assert token is None
