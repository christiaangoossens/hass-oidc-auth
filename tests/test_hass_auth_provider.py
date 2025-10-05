"""Tests for the Auth Provider registration in HA"""

from urllib.parse import urlparse, parse_qs
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
from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses


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


async def login_user(hass: HomeAssistant, code: str):
    """Helper to login a user."""

    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    flow = await provider.async_login_flow({})

    result = await flow.async_step_init({"code": code})
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"] is not None

    data = result["data"]
    sub = data["sub"]
    assert sub == MockOIDCServer.get_final_subject()

    # Get credentials
    credentials = await provider.async_get_or_create_credentials(data)
    assert credentials is not None
    assert credentials.data["sub"] == sub

    user = await hass.auth.async_get_or_create_user(credentials)
    assert user.is_active
    return user


async def get_login_code(hass: HomeAssistant, hass_client):
    """Helper to get a login code."""
    client = await hass_client()
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 302
    location = resp.headers["Location"]
    parsed_url = urlparse(location)
    query_params = parse_qs(parsed_url.query)
    state = query_params["state"][0]

    session = async_get_clientsession(hass)
    resp = session.get(location, allow_redirects=False)
    assert resp.status == 200

    json_parsed = await resp.json()
    assert "code" in json_parsed and json_parsed["code"]

    code = json_parsed["code"]
    client = await hass_client()
    resp = await client.get(
        f"/auth/oidc/callback?code={code}&state={state}", allow_redirects=False
    )

    assert resp.status == 302
    location = resp.headers["Location"]
    assert "/auth/oidc/finish?code=" in location

    # Get the code from the finish URL
    code = location.split("code=")[1]
    return code


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
        code = await get_login_code(hass, hass_client)

        # Use the code to login directly with the registered auth provider
        # Inspired by tests for the built-in providers
        user = await login_user(hass, code)
        assert user.name == "Test Name"

        # Login again to see if we trigger the re-use path
        code2 = await get_login_code(hass, hass_client)
        user2 = await login_user(hass, code2)
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
        code = await get_login_code(hass, hass_client)

        # Use the code to login directly with the registered auth provider
        user2 = await login_user(hass, code)
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
        code = await get_login_code(hass, hass_client)
        user = await login_user(hass, code)
        assert user.is_active

        # Find the person associated to this user using the PersonRegistry API
        person_store = hass.data[PERSON_DOMAIN][1]
        persons = person_store.async_items()
        assert len(persons) == 1

        person = persons[0]
        assert person["user_id"] == user.id


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
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "mfa"

    # Attempt an invalid code
    result = await flow.async_step_init({"code": "invalid"})
    assert result["type"] == FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
