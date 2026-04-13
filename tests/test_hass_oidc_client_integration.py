"""Tests for the OIDC client"""

import base64
import asyncio
import re
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, unquote, urlparse, urlencode
import pytest
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.tools.oidc_client import (
    OIDCDiscoveryClient,
    OIDCDiscoveryInvalid,
)
from custom_components.auth_oidc.config.const import (
    DISCOVERY_URL,
    CLIENT_ID,
)

from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses

EXAMPLE_CLIENT_ID = "http://example.com/"
WEB_CLIENT_ID = "https://example.com"
MOBILE_CLIENT_ID = "https://home-assistant.io/Android"

# Helper functions


def encode_redirect_uri(redirect_uri: str) -> str:
    """Helper to encode redirect URI for welcome page."""
    return base64.b64encode(redirect_uri.encode("utf-8")).decode("utf-8")


def create_redirect_uri(client_id: str) -> str:
    """Create a redirect URI for Home Assistant Android app."""
    params = {
        "response_type": "code",
        "redirect_uri": client_id,
        "client_id": client_id,
        "state": "example",
    }

    return f"http://example.com/auth/authorize?{urlencode(params)}"


async def get_welcome_for_client(client, redirect_uri: str) -> tuple[str, str, int]:
    """Go to welcome page and return state cookie, HTML content, and status.

    Returns:
        Tuple of (state_id, html_content, status_code)
    """
    encoded_uri = encode_redirect_uri(redirect_uri)
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded_uri}",
        allow_redirects=False,
    )

    state = resp.cookies["auth_oidc_state"].value
    html = await resp.text() if resp.status == 200 else ""
    return state, html, resp.status


async def get_redirect_auth_url(client) -> str:
    """Go to redirect page and extract the authorization URL.

    Returns:
        The full authorization URL to send to the OIDC provider
    """
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 200
    html = await resp.text()

    match = re.search(r'decodeURIComponent\("([^"]+)"\)', html)
    assert match is not None, "Authorization URL not found in redirect page"
    return unquote(match.group(1))


async def complete_callback_and_finish(client, code: str, state: str):
    """Complete the callback and finish flow.

    Returns:
        The state_id cookie value after completion
    """
    resp = await client.get(
        f"/auth/oidc/callback?code={code}&state={state}",
        allow_redirects=False,
    )
    assert resp.status == 302
    assert resp.headers["Location"].endswith("/auth/oidc/finish")

    resp_finish = await client.get("/auth/oidc/finish", allow_redirects=False)
    assert resp_finish.status == 200
    finish_html = await resp_finish.text()
    assert 'id="continue-on-this-device"' in finish_html
    assert 'id="device-code-input"' in finish_html
    assert 'id="approve-login-button"' in finish_html


async def verify_back_redirect(client, expected_redirect_uri: str):
    """Verify that POST to finish without body redirects back to the original redirect_uri."""
    resp_finish_post = await client.post("/auth/oidc/finish", allow_redirects=False)
    assert resp_finish_post.status == 302
    assert (
        resp_finish_post.headers["Location"]
        == unquote(expected_redirect_uri) + "&storeToken=true&skip_oidc_redirect=true"
    )


async def listen_for_sse_events(
    resp_sse,
    expected_event: str,
    timeout_seconds: int = 5,
) -> list[str]:
    """Listen for SSE events and return once the expected event is received.

    Args:
        resp_sse: The SSE response stream
        expected_event: The event type to listen for (e.g., "waiting" or "ready")
        timeout_seconds: Maximum time to wait for the event

    Returns:
        List of received event lines
    """

    if resp_sse is None:
        raise ValueError("resp_sse cannot be None")

    received_events = []

    async def stream_reader():
        try:
            async for line in resp_sse.content:
                decoded_line = line.decode("utf-8").strip()
                if not decoded_line:
                    continue

                received_events.append(decoded_line)

                # Check if this is an event line
                if decoded_line.startswith("event:"):
                    event_type = decoded_line.split(":", 1)[1].strip()
                    if event_type == expected_event:
                        # Found the expected event, return successfully.
                        return True

                    # Device SSE may emit multiple waiting events before ready.
                    if expected_event == "ready" and event_type == "waiting":
                        continue

                    raise AssertionError(
                        f"Unexpected event type '{event_type}'. Expected: {expected_event}"
                    )
        except asyncio.CancelledError:
            pass
        return False

    try:
        result = await asyncio.wait_for(stream_reader(), timeout=timeout_seconds)
        if result:
            return received_events
    except asyncio.TimeoutError as exc:
        raise AssertionError(
            f"Timeout after {timeout_seconds}s waiting for '{expected_event}' event"
        ) from exc

    raise AssertionError(f"Failed to receive '{expected_event}' event")


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


# Actual tests


@pytest.mark.asyncio
async def test_full_oidc_flow(hass: HomeAssistant, hass_client):
    """Test that one full OIDC flow works if OIDC is mocked."""

    await setup(hass)

    with mock_oidc_responses():
        client = await hass_client()
        redirect_uri = create_redirect_uri(WEB_CLIENT_ID)

        # Go to welcome and get state cookie
        state, _, status = await get_welcome_for_client(client, redirect_uri)
        assert status == 200
        assert state is not None

        # Get authorization URL from redirect page
        authorization_url = await get_redirect_auth_url(client)
        assert authorization_url.startswith(MockOIDCServer.get_authorize_url())

        # Parse the rendered redirect URL and test the query params for correctness
        parsed_url = urlparse(authorization_url)
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
        assert query_params["state"][0] == state
        assert len(query_params["state"][0]) >= 16  # Ensure state is sufficiently long
        assert (
            "redirect_uri" in query_params
            and query_params["redirect_uri"]
            and query_params["redirect_uri"][0].endswith("/auth/oidc/callback")
        )
        assert "nonce" in query_params and query_params["nonce"]
        assert "code_challenge_method" in query_params and query_params.get(
            "code_challenge_method"
        ) == ["S256"]
        assert "code_challenge" in query_params and query_params["code_challenge"]

        session = async_get_clientsession(hass)
        resp = session.get(authorization_url, allow_redirects=False)
        assert resp.status == 200

        # JSON response from mock server, normally would be interactive
        json_parsed = await resp.json()
        assert "code" in json_parsed and json_parsed["code"]

        # Now go back to the callback with a sample code
        code = json_parsed["code"]

        await complete_callback_and_finish(client, code, state)

        # POST to finish without any POST body should result in 302 back to the original redirect_uri
        await verify_back_redirect(client, redirect_uri)


async def discovery_test_through_redirect(
    hass_client, caplog, scenario: str, match_log_line: str
):
    """Test that discovery document retrieval fails gracefully through redirect endpoint."""
    with mock_oidc_responses(scenario):
        client = await hass_client()
        redirect_uri = create_redirect_uri(WEB_CLIENT_ID)

        await client.get(
            f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
            allow_redirects=False,
        )
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)

        # Find matching log line
        assert match_log_line in caplog.text

        # Assert that we get an error response with an error message
        assert resp.status == 500
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


@pytest.mark.asyncio
async def test_device_login_flow_two_browsers(hass: HomeAssistant, hass_client):
    """Test device login flow with two separate browser sessions.

    This simulates:
    - Mobile device (Device 1) generating a device code and waiting via SSE
    - Desktop browser (Device 2) completing full OAuth flow and linking the code
    - Mobile device receiving ready event after code is linked
    """
    await setup(hass)

    with mock_oidc_responses():
        # ==================== DEVICE 1: Mobile ====================
        # Mobile client starts the login flow
        mobile_client = await hass_client()
        mobile_redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID)

        mobile_state, mobile_html, status = await get_welcome_for_client(
            mobile_client, mobile_redirect_uri
        )
        assert status == 200
        assert mobile_state is not None
        assert 'id="device-instructions"' in mobile_html
        assert 'id="device-code"' in mobile_html

        # Extract device code from the welcome page.
        # The code is rendered in a div with id="device-code".
        device_code_match = re.search(
            r'id=["\']device-code["\'][^>]*>\s*([^<\s]+)\s*<',
            mobile_html,
        )
        assert device_code_match is not None, (
            "Device code should be generated for mobile client"
        )
        mobile_device_code = device_code_match.group(1)
        assert len(mobile_device_code) > 0

        # ==================== DEVICE 2: Desktop ====================
        # Desktop client in a separate session
        desktop_client = await hass_client()
        desktop_redirect_uri = create_redirect_uri(WEB_CLIENT_ID)

        desktop_state, _, status = await get_welcome_for_client(
            desktop_client, desktop_redirect_uri
        )
        assert status in [200, 302]
        assert desktop_state is not None

        # Desktop goes through redirect to get the authorization URL
        authorization_url = await get_redirect_auth_url(desktop_client)
        assert authorization_url.startswith(MockOIDCServer.get_authorize_url())

        # Desktop gets the authorization code from OIDC provider
        session = async_get_clientsession(hass)
        resp_auth = session.get(authorization_url, allow_redirects=False)
        assert resp_auth.status == 200
        json_auth = await resp_auth.json()
        assert "code" in json_auth
        desktop_code = json_auth["code"]

        await complete_callback_and_finish(desktop_client, desktop_code, desktop_state)

        # ==================== Mobile Device Finalizes Flow ====================
        # Mobile device polls SSE and keeps the connection open throughout
        resp_sse = await mobile_client.get(
            "/auth/oidc/device-sse", allow_redirects=False
        )
        assert resp_sse.status == 200

        # Listen for waiting events for up to 5 seconds
        await listen_for_sse_events(resp_sse, "waiting", timeout_seconds=5)

        # Actually submit the mobile code using POST
        resp_code = await desktop_client.post(
            "/auth/oidc/finish",
            data={"device_code": mobile_device_code},
            allow_redirects=False,
        )
        assert resp_code.status == 200
        assert resp_code.headers.get("Content-Type", "").startswith("text/html")
        html_code = await resp_code.text()
        assert 'id="mobile-success-message"' in html_code
        assert 'id="restart-login-button"' in html_code

        # ==================== Mobile Device Receives Ready Event ====================
        # After desktop flow is completed, mobile SSE should receive a ready event on same connection
        await listen_for_sse_events(resp_sse, "ready", timeout_seconds=5)

        # POST to finish without any POST body should result in 302 back to the original redirect_uri
        await verify_back_redirect(mobile_client, mobile_redirect_uri)


@pytest.mark.asyncio
async def test_finish_rejects_device_code_when_state_not_ready(
    hass: HomeAssistant, hass_client
):
    """Submitting a device code must fail if callback did not complete for this browser."""
    await setup(hass)

    with mock_oidc_responses():
        # Device session that owns the device code.
        mobile_client = await hass_client()
        mobile_redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID)
        _, mobile_html, status = await get_welcome_for_client(
            mobile_client, mobile_redirect_uri
        )
        assert status == 200

        device_code_match = re.search(
            r'id=["\']device-code["\'][^>]*>\s*([^<\s]+)\s*<',
            mobile_html,
        )
        assert device_code_match is not None
        mobile_device_code = device_code_match.group(1)

        # Separate browser starts but does not complete callback flow.
        desktop_client = await hass_client()
        desktop_redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
        _, _, desktop_status = await get_welcome_for_client(
            desktop_client, desktop_redirect_uri
        )
        assert desktop_status in [200, 302]

        # Negative branch: try to finalize before desktop state has user info.
        resp = await desktop_client.post(
            "/auth/oidc/finish",
            data={"device_code": mobile_device_code},
            allow_redirects=False,
        )
        assert resp.status == 400
        text = await resp.text()
        assert "Failed to link state to device code" in text


@pytest.mark.asyncio
async def test_callback_shows_error_if_userinfo_save_fails(
    hass: HomeAssistant, hass_client
):
    """Callback should return error page when state save fails after successful token flow."""
    await setup(hass)

    with (
        mock_oidc_responses(),
        patch(
            "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_save_user_info",
            new=AsyncMock(return_value=False),
        ),
    ):
        client = await hass_client()
        redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
        state, _, status = await get_welcome_for_client(client, redirect_uri)
        assert status == 200

        authorization_url = await get_redirect_auth_url(client)
        session = async_get_clientsession(hass)
        resp_auth = session.get(authorization_url, allow_redirects=False)
        json_auth = await resp_auth.json()

        resp = await client.get(
            f"/auth/oidc/callback?code={json_auth['code']}&state={state}",
            allow_redirects=False,
        )
        assert resp.status == 500
        text = await resp.text()
        assert "Failed to save user information, session probably expired." in text


@pytest.mark.asyncio
async def test_callback_rejects_nonce_mismatch(hass: HomeAssistant, hass_client):
    """Callback should fail closed when the returned nonce does not match the stored flow nonce."""
    await setup(hass)

    with (
        mock_oidc_responses(),
        patch(
            "custom_components.auth_oidc.tools.oidc_client.OIDCClient._parse_id_token",
            new=AsyncMock(
                return_value={
                    "sub": "test-user",
                    "nonce": "mismatched-nonce",
                    "name": "Test Name",
                    "preferred_username": "testuser",
                    "groups": [],
                }
            ),
        ),
    ):
        client = await hass_client()
        redirect_uri = create_redirect_uri(WEB_CLIENT_ID)

        state, _, status = await get_welcome_for_client(client, redirect_uri)
        assert status == 200

        authorization_url = await get_redirect_auth_url(client)
        session = async_get_clientsession(hass)
        resp_auth = session.get(authorization_url, allow_redirects=False)
        json_auth = await resp_auth.json()

        resp = await client.get(
            f"/auth/oidc/callback?code={json_auth['code']}&state={state}",
            allow_redirects=False,
        )
        assert resp.status == 500
        text = await resp.text()
        assert "Failed to get user details" in text


@pytest.mark.asyncio
async def test_callback_replay_is_rejected(hass: HomeAssistant, hass_client):
    """A callback replay with the same state should be rejected after first successful use."""
    await setup(hass)

    with mock_oidc_responses():
        client = await hass_client()
        redirect_uri = create_redirect_uri(WEB_CLIENT_ID)

        state, _, status = await get_welcome_for_client(client, redirect_uri)
        assert status == 200

        authorization_url = await get_redirect_auth_url(client)
        session = async_get_clientsession(hass)
        resp_auth = session.get(authorization_url, allow_redirects=False)
        json_auth = await resp_auth.json()
        code = json_auth["code"]

        # First callback should succeed.
        first = await client.get(
            f"/auth/oidc/callback?code={code}&state={state}",
            allow_redirects=False,
        )
        assert first.status == 302

        # Replay should fail because the state flow has already been consumed.
        replay = await client.get(
            f"/auth/oidc/callback?code={code}&state={state}",
            allow_redirects=False,
        )
        assert replay.status == 500
        replay_text = await replay.text()
        assert "Failed to get user details" in replay_text
