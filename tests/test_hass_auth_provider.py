"""Tests for the Auth Provider registration in HA"""

import base64
import re
from collections import OrderedDict
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from homeassistant.auth import InvalidAuthError
from homeassistant.auth.models import AuthFlowContext
from homeassistant.components.person import DOMAIN as PERSON_DOMAIN
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.config.const import (
    CLIENT_ID,
    DEFAULT_TITLE,
    DISCOVERY_URL,
    DISPLAY_NAME,
    FEATURES,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    FEATURES_AUTOMATIC_USER_LINKING,
    FEATURES_REQUIRE_EXISTING_USER,
)
from custom_components.auth_oidc.provider import OpenIDAuthProvider
from custom_components.auth_oidc.tools.helpers import STATE_COOKIE_NAME

from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses

DEFAULT_CONFIG = {
    CLIENT_ID: "dummy",
    DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
}


def make_fake_redirect_url(client) -> str:
    """Build a same-origin redirect URI for the current HA test client."""
    origin = str(client.make_url("/")).rstrip("/")
    return (
        f"{origin}/auth/authorize?response_type=code"
        f"&redirect_uri={origin}%2F%3Fauth_callback%3D1"
        f"&client_id={origin}%2F&state=example"
    )


async def setup(hass: HomeAssistant, config: dict, expect_success: bool) -> None:
    """Set up the auth_oidc component."""
    result = await async_setup_component(hass, DOMAIN, {DOMAIN: config})

    if expect_success:
        assert result
        assert DOMAIN in hass.data


def get_oidc_provider(hass: HomeAssistant) -> OpenIDAuthProvider:
    """Return the registered OIDC provider."""
    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    assert isinstance(provider, OpenIDAuthProvider)
    return provider


def set_auth_providers(hass: HomeAssistant, providers: list[tuple]) -> None:
    """Replace Home Assistant's registered providers, stand-ins included."""
    hass.auth._providers = OrderedDict(providers)


async def get_auth_store_ids(hass: HomeAssistant) -> tuple[set[str], set[str]]:
    """Return all user and credential IDs currently stored by Home Assistant."""
    users = await hass.auth.async_get_users()
    return (
        {user.id for user in users},
        {credential.id for user in users for credential in user.credentials},
    )


async def async_get_person_states(hass: HomeAssistant) -> list:
    """Return the person entity states, which carry the linked user_id."""
    await hass.async_block_till_done()
    return hass.states.async_all(PERSON_DOMAIN)


@pytest.mark.asyncio
async def test_setup_success_auth_provider_registration(hass: HomeAssistant):
    """Test successful setup"""
    await setup(
        hass,
        DEFAULT_CONFIG,
        True,
    )

    # Ensure the auth provider is registered
    assert len(hass.auth.get_auth_providers(DOMAIN)) == 1

    # Public auth-provider contract: OIDC provider does not support HA MFA
    assert get_oidc_provider(hass).support_mfa is False


@pytest.mark.asyncio
async def test_provider_name_is_stable_regardless_of_display_name(hass: HomeAssistant):
    """The provider picker shows DEFAULT_TITLE, whatever the configured display_name."""
    await setup(
        hass,
        {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
            DISPLAY_NAME: "Custom / Branded IdP",
        },
        True,
    )

    provider = get_oidc_provider(hass)
    assert provider.name == DEFAULT_TITLE


@pytest.mark.asyncio
async def test_provider_hides_login_from_another_ip(hass: HomeAssistant):
    """A finished OIDC login is only offered to the client that finished it."""
    await setup(hass, DEFAULT_CONFIG, True)
    provider = get_oidc_provider(hass)

    state_id = await provider.async_create_state("https://example.com/", "127.0.0.1")
    await provider.async_save_user_info(
        state_id,
        {"sub": "sub", "display_name": None, "username": None, "role": "system-users"},
    )

    request = SimpleNamespace(remote="10.0.0.1", cookies={STATE_COOKIE_NAME: state_id})

    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = request
        assert provider.async_can_start_login(AuthFlowContext()) is False


@pytest.mark.asyncio
async def test_provider_hides_login_when_the_check_fails(hass: HomeAssistant, caplog):
    """An error while checking hides OIDC and is logged, instead of failing the page."""
    await setup(hass, DEFAULT_CONFIG, True)
    provider = get_oidc_provider(hass)

    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.side_effect = RuntimeError("boom")
        assert provider.async_can_start_login(AuthFlowContext()) is False

    assert "Could not check if the OIDC login is ready" in caplog.text


@pytest.mark.asyncio
async def test_provider_ip_fallback_fails_closed_without_request_context(
    hass: HomeAssistant,
):
    """Provider should not invent a shared IP when request context is missing."""
    await setup(
        hass,
        DEFAULT_CONFIG,
        True,
    )

    provider = get_oidc_provider(hass)

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
        DEFAULT_CONFIG,
        True,
    )

    provider = get_oidc_provider(hass)
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
        DEFAULT_CONFIG,
        True,
    )

    provider = get_oidc_provider(hass)

    class TrustedNetworksAllowProvider:
        def async_validate_access(self, _ip_addr):
            return None

    set_auth_providers(
        hass,
        [
            (("trusted_networks", None), TrustedNetworksAllowProvider()),
            ((provider.type, provider.id), provider),
        ],
    )

    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = SimpleNamespace(remote="127.0.0.1")
        assert provider.is_trusted_network_host() is True


@pytest.mark.asyncio
async def test_provider_is_trusted_network_host_false_for_disallowed_ip(
    hass: HomeAssistant, caplog
):
    """Provider should return False when trusted provider denies the current IP."""
    await setup(
        hass,
        DEFAULT_CONFIG,
        True,
    )

    provider = get_oidc_provider(hass)

    class TrustedNetworksDenyProvider:
        def async_validate_access(self, _ip_addr):
            raise InvalidAuthError("Not in trusted_networks")

    set_auth_providers(
        hass,
        [
            (("trusted_networks", None), TrustedNetworksDenyProvider()),
            ((provider.type, provider.id), provider),
        ],
    )

    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = SimpleNamespace(remote="127.0.0.1")
        assert provider.is_trusted_network_host() is False
        assert any(
            level >= 0
            and "is not in a trusted network, proceeding with OIDC flow" in message
            for _, level, message in caplog.record_tuples
        )
        assert not any(
            level >= 0 and "Error while validating trusted network for IP" in message
            for _, level, message in caplog.record_tuples
        )


@pytest.mark.asyncio
async def test_provider_is_trusted_network_host_false_without_trusted_provider(
    hass: HomeAssistant,
):
    """Provider should return False when trusted_networks auth provider is absent."""
    await setup(
        hass,
        DEFAULT_CONFIG,
        True,
    )

    provider = get_oidc_provider(hass)

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

    provider = get_oidc_provider(hass)
    # This helper runs outside an HTTP request, so pass the known local test IP.
    sub = await provider.async_get_subject(state_id, "127.0.0.1")
    assert sub is not None and sub == MockOIDCServer.get_final_subject()

    # Get credentials
    credentials = await provider.async_get_or_create_credentials({"sub": sub})
    assert credentials is not None
    assert credentials.data["sub"] == sub

    user = await hass.auth.async_get_or_create_user(credentials)
    assert user.is_active
    return user


async def get_login_state(hass: HomeAssistant, hass_client):
    """Helper to complete the browser login flow and return the OIDC state id."""
    state_id, resp = await get_callback_response(hass, hass_client)

    assert resp.status == 302
    assert resp.headers["Location"].endswith("/auth/oidc/finish")

    return state_id


async def get_callback_response(hass: HomeAssistant, hass_client) -> tuple[str, Any]:
    """Helper to log in at the OIDC provider and return the state id and callback."""
    client = await hass_client()

    redirect_uri = make_fake_redirect_url(client)
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
    # The OIDC mock returns the response itself, without awaiting
    resp: Any = session.get(auth_url, allow_redirects=False)
    assert resp.status == 200

    # Mock OIDC returns JSON
    json_parsed = await resp.json()
    assert json_parsed.get("code")

    code = json_parsed["code"]
    resp = await client.get(
        f"/auth/oidc/callback?code={code}&state={state_id}", allow_redirects=False
    )

    return state_id, resp


@pytest.mark.asyncio
async def test_full_login(hass: HomeAssistant, hass_client):
    """Test a full login flow."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
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
            **DEFAULT_CONFIG,
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


@pytest.mark.parametrize("automatic_user_linking", [False, True])
@pytest.mark.asyncio
async def test_require_existing_user_denies_new_oidc_identity(
    hass: HomeAssistant, hass_client, automatic_user_linking: bool
):
    """New OIDC identities are denied without provisioning a HA user."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: automatic_user_linking,
                FEATURES_REQUIRE_EXISTING_USER: True,
            },
        },
        True,
    )

    with mock_oidc_responses("username"):
        users_before, credentials_before = await get_auth_store_ids(hass)

        state_id, resp = await get_callback_response(hass, hass_client)

        await assert_login_not_allowed(hass, state_id, resp)
        assert await get_auth_store_ids(hass) == (users_before, credentials_before)


async def assert_login_not_allowed(hass: HomeAssistant, state_id: str, resp) -> None:
    """Assert the callback showed the not allowed page and OIDC is not offered."""
    assert resp.status == 403
    assert "not allowed to log in" in await resp.text()

    provider = get_oidc_provider(hass)
    assert not await provider.async_is_state_ready(state_id, "127.0.0.1")


@pytest.mark.asyncio
async def test_require_existing_user_aborts_login_flow_cleanly(
    hass: HomeAssistant, hass_client
):
    """If a user is removed after the callback, the login flow aborts without a user."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: True,
                FEATURES_REQUIRE_EXISTING_USER: True,
            },
        },
        True,
    )

    with mock_oidc_responses("username"):
        user = await hass.auth.async_create_user("Foo Bar")
        hass_provider = hass.auth.get_auth_providers("homeassistant")[0]
        local_credential = await hass_provider.async_get_or_create_credentials(
            {"username": "foobar"}
        )
        await hass.auth.async_link_user(user, local_credential)

        state_id = await get_login_state(hass, hass_client)
        await hass.auth.async_remove_user(user)

        provider = get_oidc_provider(hass)
        flow = await provider.async_login_flow({})
        users_before, credentials_before = await get_auth_store_ids(hass)

        fake_request = SimpleNamespace(
            cookies={"auth_oidc_state": state_id}, remote="127.0.0.1"
        )
        with patch(
            "custom_components.auth_oidc.provider.http.current_request"
        ) as current_request:
            current_request.get.return_value = fake_request
            result = await flow.async_step_init({})

        assert result.get("type") == FlowResultType.ABORT
        assert result.get("reason") == "invalid_auth"
        assert await get_auth_store_ids(hass) == (users_before, credentials_before)


@pytest.mark.asyncio
async def test_require_existing_user_does_not_link_when_linking_is_disabled(
    hass: HomeAssistant, hass_client
):
    """A matching local username is still denied when linking is disabled."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
                FEATURES_REQUIRE_EXISTING_USER: True,
            },
        },
        True,
    )

    with mock_oidc_responses("username"):
        user = await hass.auth.async_create_user("Foo Bar")
        hass_provider = hass.auth.get_auth_providers("homeassistant")[0]
        local_credential = await hass_provider.async_get_or_create_credentials(
            {"username": "foobar"}
        )
        await hass.auth.async_link_user(user, local_credential)
        users_before, credentials_before = await get_auth_store_ids(hass)

        state_id, resp = await get_callback_response(hass, hass_client)

        await assert_login_not_allowed(hass, state_id, resp)
        assert await get_auth_store_ids(hass) == (users_before, credentials_before)


@pytest.mark.asyncio
async def test_require_existing_user_allows_automatic_linking(
    hass: HomeAssistant, hass_client
):
    """A matching local user is linked instead of provisioning a new user."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: True,
                FEATURES_REQUIRE_EXISTING_USER: True,
            },
        },
        True,
    )

    with mock_oidc_responses("username"):
        user = await hass.auth.async_create_user("Foo Bar")
        hass_provider = hass.auth.get_auth_providers("homeassistant")[0]
        credential = await hass_provider.async_get_or_create_credentials(
            {"username": "foobar"}
        )
        await hass.auth.async_link_user(user, credential)
        users_before = {existing.id for existing in await hass.auth.async_get_users()}

        state_id = await get_login_state(hass, hass_client)
        linked_user = await login_user(hass, state_id)

        assert linked_user.id == user.id
        assert {
            existing.id for existing in await hass.auth.async_get_users()
        } == users_before


@pytest.mark.asyncio
async def test_require_existing_user_allows_existing_oidc_credential(
    hass: HomeAssistant, hass_client
):
    """Already-linked OIDC credentials work when automatic linking is disabled."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
                FEATURES_REQUIRE_EXISTING_USER: False,
            },
        },
        True,
    )

    with mock_oidc_responses():
        first_state = await get_login_state(hass, hass_client)
        user = await login_user(hass, first_state)

        provider = get_oidc_provider(hass)
        provider.require_existing_user = True

        second_state = await get_login_state(hass, hass_client)
        existing_user = await login_user(hass, second_state)

        assert existing_user.id == user.id


@pytest.mark.asyncio
async def test_login_with_person_create(hass: HomeAssistant, hass_client):
    """Test a person create."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
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

        persons = await async_get_person_states(hass)
        assert len(persons) == 1
        assert persons[0].attributes["user_id"] == user.id


@pytest.mark.asyncio
async def test_login_without_person_create_does_not_create_person(
    hass: HomeAssistant, hass_client
):
    """Test that person creation can be disabled."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
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

        assert await async_get_person_states(hass) == []


@pytest.mark.asyncio
async def test_login_shows_form(hass: HomeAssistant):
    """Test a login"""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    provider = get_oidc_provider(hass)
    flow = await provider.async_login_flow({})

    result = await flow.async_step_init({})
    assert result.get("type") == FlowResultType.ABORT
    assert result.get("reason") == "no_oidc_cookie_found"


@pytest.mark.asyncio
async def test_login_with_invalid_cookie_aborts(hass: HomeAssistant):
    """A cookie that does not map to a valid state should fail closed."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    provider = get_oidc_provider(hass)
    flow = await provider.async_login_flow({})

    fake_request = SimpleNamespace(
        cookies={"auth_oidc_state": "missing-state"}, remote="127.0.0.1"
    )
    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = fake_request

        result = await flow.async_step_init({})

    assert result.get("type") == FlowResultType.ABORT
    assert result.get("reason") == "oidc_cookie_invalid"


@pytest.mark.asyncio
async def test_login_with_no_cookie_aborts(hass: HomeAssistant):
    """Missing cookie should fail closed."""
    await setup(
        hass,
        {
            **DEFAULT_CONFIG,
            FEATURES: {
                FEATURES_AUTOMATIC_PERSON_CREATION: False,
                FEATURES_AUTOMATIC_USER_LINKING: False,
            },
        },
        True,
    )

    provider = get_oidc_provider(hass)
    flow = await provider.async_login_flow({})

    fake_request = SimpleNamespace(cookies={}, remote="127.0.0.1")
    with patch(
        "custom_components.auth_oidc.provider.http.current_request"
    ) as current_request:
        current_request.get.return_value = fake_request

        result = await flow.async_step_init({})

    assert result.get("type") == FlowResultType.ABORT
    assert result.get("reason") == "no_oidc_cookie_found"
