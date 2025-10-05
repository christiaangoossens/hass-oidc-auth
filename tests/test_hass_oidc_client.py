"""Tests for the YAML config setup of OIDC"""

import logging
from urllib.parse import urlparse, parse_qs
import pytest
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from auth_oidc import DOMAIN
from auth_oidc.tools.oidc_client import OIDCDiscoveryClient, OIDCDiscoveryInvalid
from auth_oidc.config.const import (
    DISCOVERY_URL,
    CLIENT_ID,
)

from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses

_LOGGER = logging.getLogger(__name__)
EXAMPLE_CLIENT_ID = "dummyclient"


async def setup(hass: HomeAssistant):
    """Set up the integration within Home Assistant"""
    mock_config = {
        DOMAIN: {
            CLIENT_ID: EXAMPLE_CLIENT_ID,
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
        }
    }

    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result


@pytest.mark.asyncio
async def test_full_oidc_flow(hass: HomeAssistant, hass_client):
    """Test that one full OIDC flow works if OIDC is mocked."""

    await setup(hass)

    with mock_oidc_responses():
        # Start by going to /auth/oidc/redirect
        client = await hass_client()
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
        assert resp.status == 302
        assert resp.headers["Location"].startswith(MockOIDCServer.get_authorize_url())

        # Parse the location header and test the query params for correctness
        location = resp.headers["Location"]
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)

        assert "response_type" in query_params and query_params.get(
            "response_type"
        ) == ["code"]
        assert "client_id" in query_params and query_params.get("client_id") == [
            EXAMPLE_CLIENT_ID
        ]
        assert "scope" in query_params and query_params.get("scope") == [
            "openid profile groups"
        ]
        assert "state" in query_params and query_params["state"]
        state = query_params["state"][0]
        assert len(state) >= 16  # Ensure state is sufficiently long
        assert (
            "redirect_uri" in query_params
            and query_params["redirect_uri"]
            and query_params["redirect_uri"][0].endswith("/auth/oidc/callback")
        )  # TODO: Also test that the URL itself is correct
        assert "nonce" in query_params and query_params["nonce"]
        assert "code_challenge_method" in query_params and query_params.get(
            "code_challenge_method"
        ) == ["S256"]
        assert "code_challenge" in query_params and query_params["code_challenge"]

        session = async_get_clientsession(hass)
        resp = session.get(location, allow_redirects=False)
        assert resp.status == 200

        json_parsed = await resp.json()
        assert "code" in json_parsed and json_parsed["code"]

        # Now go back to the callback with a sample code
        code = json_parsed["code"]
        client = await hass_client()
        resp = await client.get(
            f"/auth/oidc/callback?code={code}&state={state}", allow_redirects=False
        )

        text = await resp.text()
        # TODO: Test if logged text contains our login
        # TODO: Test if the code actually works
        _LOGGER.debug("Callback response text: %s", text)
        assert resp.status == 302
        assert "/auth/oidc/finish?code=" in resp.headers["Location"]


async def discovery_test_through_redirect(
    hass_client, caplog, scenario: str, match_log_line: str
):
    """Test that discovery document retrieval fails gracefully through redirect endpoint."""
    with mock_oidc_responses(scenario):
        # Start by going to /auth/oidc/redirect
        client = await hass_client()
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)

        # Find matching log line
        assert match_log_line in caplog.text

        # Assert that we get a 200 response with an error message
        assert resp.status == 200
        text = await resp.text()
        assert "Integration is misconfigured, discovery could not be obtained." in text


async def direct_discovery_test(
    hass: HomeAssistant,
    scenario: str,
    match_type: str,
    match_log_line: str | None = None,
):
    """Test that discovery document retrieval fails with nice error directly."""
    with mock_oidc_responses(scenario):
        session = async_get_clientsession(hass)
        client = OIDCDiscoveryClient(
            MockOIDCServer.get_discovery_url(),
            session,
            {
                "id_token_signing_alg": "RS256",
            },
        )

        with pytest.raises(OIDCDiscoveryInvalid) as exc_info:
            await client.fetch_discovery_document()

        assert exc_info.value.type == match_type
        assert exc_info.value.get_detail_string().startswith("type: " + match_type)

        if match_log_line:
            assert match_log_line in exc_info.value.get_detail_string()


@pytest.mark.asyncio
async def test_discovery_failures(hass: HomeAssistant, hass_client, caplog):
    """Test that discovery document retrieval fails gracefully."""

    await setup(hass)

    # Empty scenario
    await discovery_test_through_redirect(
        hass_client, caplog, "empty", "is missing required endpoint: issuer"
    )
    await direct_discovery_test(hass, "empty", "missing_endpoint", "endpoint: issuer")

    # Missing authorization_endpoint
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "only_issuer",
        "is missing required endpoint: authorization_endpoint",
    )
    await direct_discovery_test(
        hass, "only_issuer", "missing_endpoint", "endpoint: authorization_endpoint"
    )

    # Missing token_endpoint
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "missing_token",
        "is missing required endpoint: token_endpoint",
    )
    await direct_discovery_test(
        hass, "missing_token", "missing_endpoint", "endpoint: token_endpoint"
    )

    # Missing jwks_uri
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "missing_jwks",
        "is missing required endpoint: jwks_uri",
    )
    await direct_discovery_test(
        hass, "missing_jwks", "missing_endpoint", "endpoint: jwks_uri"
    )

    # Invalid response_modes_supported
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "invalid_response_modes",
        "does not support required 'query' response mode, only supports: ['post']",
    )
    await direct_discovery_test(
        hass, "invalid_response_modes", "does_not_support_response_mode", "post"
    )

    # Invalid grant_types supported
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "invalid_grant_types",
        "does not support required 'authorization_code' grant type, only supports: ['refresh_token']",
    )
    await direct_discovery_test(
        hass, "invalid_grant_types", "does_not_support_grant_type", "refresh_token"
    )

    # Invalid response types
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "invalid_response_types",
        "does not support required 'code' response type, only supports: ['token']",
    )
    await direct_discovery_test(
        hass, "invalid_response_types", "does_not_support_response_type", "token"
    )

    # Invalid code_challenge types
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "invalid_code_challenge_types",
        "does not support required 'S256' code challenge method, only supports: ['plain']",
    )
    await direct_discovery_test(
        hass,
        "invalid_code_challenge_types",
        "does_not_support_required_code_challenge_method",
        "plain",
    )

    # Invalid id_token_signing alg
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "invalid_id_token_signing_alg",
        "does not have 'id_token_signing_alg_values_supported' field",
    )
    await direct_discovery_test(
        hass, "invalid_id_token_signing_alg", "missing_id_token_signing_alg_values"
    )

    # Not matching id_token_signing alg
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "wrong_id_token_signing_alg",
        "does not support requested id_token_signing_alg 'RS256', only supports: ['HS256']",
    )
    await direct_discovery_test(
        hass,
        "wrong_id_token_signing_alg",
        "does_not_support_id_token_signing_alg",
        "requested: RS256, supported: ['HS256']",
    )

    # Invalid URL
    await discovery_test_through_redirect(
        hass_client,
        caplog,
        "invalid_url",
        "has invalid URL in endpoint: jwks_uri (/jwks)",
    )
    await direct_discovery_test(
        hass,
        "invalid_url",
        "invalid_endpoint",
        "endpoint: jwks_uri, url: /jwks",
    )


@pytest.mark.asyncio
async def test_direct_jwks_fetch(hass: HomeAssistant):
    """Test direct fetch of JWKS."""
    with mock_oidc_responses():
        session = async_get_clientsession(hass)
        client = OIDCDiscoveryClient(
            MockOIDCServer.get_discovery_url(),
            session,
            {
                "id_token_signing_alg": "RS256",
            },
        )

        await client.fetch_discovery_document()
        jwks = await client.fetch_jwks()
        assert "keys" in jwks
