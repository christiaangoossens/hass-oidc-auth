"""Tests for the YAML config setup of OIDC"""

from contextlib import contextmanager
import logging
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse, parse_qs
import pytest
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from auth_oidc import DOMAIN
from auth_oidc.config.const import (
    DISCOVERY_URL,
    CLIENT_ID,
)

from .mocks.oidc_server import MockOIDCServer

_LOGGER = logging.getLogger(__name__)
mockOIDCServer = MockOIDCServer()
EXAMPLE_CLIENT_ID = "dummyclient"


async def setup(hass: HomeAssistant):
    """Set up the integration within Home Assistant"""
    mock_config = {
        DOMAIN: {
            CLIENT_ID: EXAMPLE_CLIENT_ID,
            DISCOVERY_URL: mockOIDCServer.get_discovery_url(),
        }
    }

    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result


@contextmanager
def mock_oidc_responses():
    """Mock OIDC responses for testing."""

    def make_mock_response(json_data, status):
        mock_response = AsyncMock()
        mock_response.__aenter__.return_value = mock_response
        mock_response.__aexit__.return_value = None
        mock_response.json = AsyncMock(return_value=json_data)
        mock_response.status = status
        return mock_response

    def default_handler(method, url, *args, **kwargs):
        _LOGGER.debug("Mocked %s request to %s", method, url)
        body = kwargs.get("data") or kwargs.get("json") or None
        response = mockOIDCServer.process_request(url, method, body)
        return make_mock_response(response[0], response[1])

    def get_side_effect(url, *args, **kwargs):
        return default_handler("GET", url, *args, **kwargs)

    def post_side_effect(url, *args, **kwargs):
        return default_handler("POST", url, *args, **kwargs)

    with (
        patch("aiohttp.ClientSession.get", side_effect=get_side_effect) as get_patch,
        patch("aiohttp.ClientSession.post", side_effect=post_side_effect) as post_patch,
    ):
        yield (get_patch, post_patch, default_handler)


@pytest.mark.asyncio
async def test_full_oidc_flow(hass: HomeAssistant, hass_client):
    """Test that one full OIDC flow works if OIDC is mocked."""

    await setup(hass)

    with mock_oidc_responses():
        # Start by going to /auth/oidc/redirect
        client = await hass_client()
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
        assert resp.status == 302
        assert resp.headers["Location"].startswith(mockOIDCServer.get_authorize_url())

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
