"""Tests for the Auth Provider registration in HA"""

import base64
import re
from collections import OrderedDict
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlparse
from unittest.mock import patch
import pytest

from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.components.person import DOMAIN as PERSON_DOMAIN

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.config.const import (
    DISCOVERY_URL,
    CLIENT_ID,
    FEATURES,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    FEATURES_AUTOMATIC_USER_LINKING,
)
from custom_components.auth_oidc.provider import InvalidAuthError
from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses

FAKE_REDIR_URL = "http://example.com/auth/authorize?response_type=code&redirect_uri=http%3A%2F%2Fexample.com%3A8123%2F%3Fauth_callback%3D1&client_id=http%3A%2F%2Fexample.com%3A8123%2F&state=example"


async def setup(hass: HomeAssistant, config: dict, expect_success: bool) -> bool:
    """Set up the auth_oidc component."""
    result = await async_setup_component(hass, DOMAIN, {DOMAIN: config})

    if expect_success:
        assert result
        assert DOMAIN in hass.data


@pytest.mark.asyncio
async def test_setup_success_auth_provider_registration(hass: HomeAssistant):
    """Test successful setup"""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
        },
        True,
    )

    # Ensure the auth provider is registered
    auth_providers = hass.auth.get_auth_providers(DOMAIN)
    assert len(auth_providers) == 1

    # Public auth-provider contract: OIDC provider does not support HA MFA
    assert auth_providers[0].support_mfa is False


@pytest.mark.asyncio
async def test_provider_ip_fallback_fails_closed_without_request_context(
    hass: HomeAssistant,
):
    """Provider should not invent a shared IP when request context is missing."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]

    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = None
        assert provider._resolve_ip() is None


@pytest.mark.asyncio
async def test_provider_cookie_header_sets_secure_when_requested(hass: HomeAssistant):
    """Cookie header should include Secure when HTTPS is in use."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    cookie_header = provider.get_cookie_header("state-id", secure=True)["set-cookie"]

    assert "SameSite=Lax" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header


@pytest.mark.asyncio
async def test_provider_is_trusted_network_host_true_for_allowed_ip(
    hass: HomeAssistant,
):
    """Provider should detect trusted network host when trusted provider allows the IP."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]

    class TrustedNetworksAllowProvider:
        def async_validate_access(self, _ip_addr):
            return None

    # pylint: disable=protected-access
    hass.auth._providers = OrderedDict(
        [
            (("trusted_networks", None), TrustedNetworksAllowProvider()),
            ((provider.type, provider.id), provider),
        ]
    )
    # pylint: enable=protected-access

    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = SimpleNamespace(remote="127.0.0.1")
        assert provider.is_trusted_network_host() is True


@pytest.mark.asyncio
async def test_provider_is_trusted_network_host_false_for_disallowed_ip(
    hass: HomeAssistant,
):
    """Provider should return False when trusted provider denies the current IP."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]

    class TrustedNetworksDenyProvider:
        def async_validate_access(self, _ip_addr):
            raise InvalidAuthError("Not in trusted_networks")

    # pylint: disable=protected-access
    hass.auth._providers = OrderedDict(
        [
            (("trusted_networks", None), TrustedNetworksDenyProvider()),
            ((provider.type, provider.id), provider),
        ]
    )
    # pylint: enable=protected-access

    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = SimpleNamespace(remote="127.0.0.1")
        assert provider.is_trusted_network_host() is False


@pytest.mark.asyncio
async def test_provider_is_trusted_network_host_false_without_trusted_provider(
    hass: HomeAssistant,
):
    """Provider should return False when trusted_networks auth provider is absent."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]

    # Without actually getting the IP, should also be false
    assert provider.is_trusted_network_host() is False

    # With the IP, should be false
    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = SimpleNamespace(remote="127.0.0.1")
        assert provider.is_trusted_network_host() is False


async def login_user(hass: HomeAssistant, state_id: str):
    """Helper to login a user from the stored OIDC state."""

    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    # This helper runs outside an HTTP request, so pass the known local test IP.
    sub = await provider.async_get_subject(state_id, "127.0.0.1")
    assert sub == MockOIDCServer.get_final_subject()

    # Get credentials
    credentials = await provider.async_get_or_create_credentials({"sub": sub})
    assert credentials is not None
    assert credentials.data["sub"] == sub

    user = await hass.auth.async_get_or_create_user(credentials)
    assert user.is_active
    return user


async def get_login_state(hass: HomeAssistant, hass_client):
    """Helper to complete the browser login flow and return the OIDC state id."""
    client = await hass_client()

    redirect_uri = FAKE_REDIR_URL
    encoded_redirect_uri = base64.b64encode(redirect_uri.encode("utf-8")).decode(
        "utf-8"
    )
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded_redirect_uri}",
        allow_redirects=False,
    )
    assert resp.status == 200
    state_id = resp.cookies["auth_oidc_state"].value

    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 200
    html = await resp.text()
    match = re.search(r'decodeURIComponent\("([^"]+)"\)', html)
    assert match is not None
    auth_url = unquote(match.group(1))

    parsed_url = urlparse(auth_url)
    query_params = parse_qs(parsed_url.query)
    assert query_params["state"][0] == state_id

    session = async_get_clientsession(hass)
    resp = session.get(auth_url, allow_redirects=False)
    assert resp.status == 200

    # Mock OIDC returns JSON
    json_parsed = await resp.json()
    assert "code" in json_parsed and json_parsed["code"]

    code = json_parsed["code"]
    resp = await client.get(
        f"/auth/oidc/callback?code={code}&state={state_id}", allow_redirects=False
    )

    assert resp.status == 302
    assert resp.headers["Location"].endswith("/auth/oidc/finish")

    return state_id


@pytest.mark.asyncio
async def test_full_login(hass: HomeAssistant, hass_client):
    """Test a full login flow."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    with mock_oidc_responses():
        # Actually start the login and get a code
        state_id = await get_login_state(hass, hass_client)

        # Use the stored state to login directly with the registered auth provider
        # Inspired by tests for the built-in providers
        user = await login_user(hass, state_id)
        assert user.name == "Test Name"

        # Login again to see if we trigger the re-use path
        state_id2 = await get_login_state(hass, hass_client)
        user2 = await login_user(hass, state_id2)
        assert user2.id == user.id


@pytest.mark.asyncio
async def test_login_with_linking(hass: HomeAssistant, hass_client):
    """Test a linking login."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: True,
            },
        },
        True,
    )

    with mock_oidc_responses("username"):
        # Create a user first with username 'foobar'
        user = await hass.auth.async_create_user("Foo Bar")
        assert user.is_active

        hass_provider = hass.auth.get_auth_providers("homeassistant")[0]
        credential = await hass_provider.async_get_or_create_credentials(
            {"username": "foobar"}
        )
        await hass.auth.async_link_user(user, credential)

        # Actually start the login and get a code
        state_id = await get_login_state(hass, hass_client)

        # Use the stored state to login directly with the registered auth provider
        user2 = await login_user(hass, state_id)
        assert user2.id == user.id  # Assert that the user was linked


@pytest.mark.asyncio
async def test_login_with_person_create(hass: HomeAssistant, hass_client):
    """Test a person create."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: True,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    await async_setup_component(hass, PERSON_DOMAIN, {})

    with mock_oidc_responses():
        state_id = await get_login_state(hass, hass_client)
        user = await login_user(hass, state_id)
        assert user.is_active

        # Find the person associated to this user using the PersonRegistry API
        person_store = hass.data[PERSON_DOMAIN][1]
        persons = person_store.async_items()
        assert len(persons) == 1

        person = persons[0]
        assert person["user_id"] == user.id


@pytest.mark.asyncio
async def test_login_without_person_create_does_not_create_person(
    hass: HomeAssistant, hass_client
):
    """Test that person creation can be disabled."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    await async_setup_component(hass, PERSON_DOMAIN, {})

    with mock_oidc_responses():
        state_id = await get_login_state(hass, hass_client)
        user = await login_user(hass, state_id)
        assert user.is_active

        person_store = hass.data[PERSON_DOMAIN][1]
        persons = person_store.async_items()
        assert len(persons) == 0


@pytest.mark.asyncio
async def test_login_shows_form(hass: HomeAssistant):
    """Test a login"""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    flow = await provider.async_login_flow({})

    result = await flow.async_step_init({})
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "no_oidc_cookie_found"


@pytest.mark.asyncio
async def test_login_with_invalid_cookie_aborts(hass: HomeAssistant):
    """A cookie that does not map to a valid state should fail closed."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    flow = await provider.async_login_flow({})

    fake_request = SimpleNamespace(
        cookies={"auth_oidc_state": "missing-state"}, remote="127.0.0.1"
    )
    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = fake_request

        result = await flow.async_step_init({})

    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "oidc_cookie_invalid"


@pytest.mark.asyncio
async def test_login_with_no_cookie_aborts(hass: HomeAssistant):
    """Missing cookie should fail closed."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    flow = await provider.async_login_flow({})

    fake_request = SimpleNamespace(cookies={}, remote="127.0.0.1")
    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = fake_request

        result = await flow.async_step_init({})

    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "no_oidc_cookie_found"
