"""Login scenarios with Home Assistant's own auth providers next to OIDC.

These tests use the HTTP endpoints exactly like the Home Assistant frontend does:
the frontend fetches /auth/providers and starts the login flow of the first provider.
"""

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse

import pytest
from homeassistant.auth.providers import auth_provider_from_config
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.config.const import (
    CLIENT_ID,
    DISCOVERY_URL,
    FEATURES,
    FEATURES_DEFAULT_REDIRECT,
)

from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses
from .test_hass_oidc_client_integration import (
    WEB_CLIENT_ID,
    complete_callback_and_finish,
    create_redirect_uri,
    get_redirect_auth_url,
    get_test_origin,
    get_welcome_for_client,
)
from .test_hass_webserver import setup_mock_authorize_route

PASSWORD = {"type": "homeassistant"}
TRUSTED = {"type": "trusted_networks", "trusted_networks": ["127.0.0.1"]}
UNTRUSTED = {"type": "trusted_networks", "trusted_networks": ["10.0.0.0/8"]}


@dataclass(frozen=True)
class Scenario:
    """A Home Assistant auth configuration and the login behaviour it should give."""

    other_providers: list[dict]
    authorize_redirects: bool
    welcome_continues: bool
    providers: list[str]
    first_login_without_cookie: str
    first_login_after_oidc: str
    features: dict = field(default_factory=dict)


SCENARIOS = [
    pytest.param(
        Scenario(
            other_providers=[],
            authorize_redirects=True,
            welcome_continues=True,
            providers=["auth_oidc"],
            first_login_without_cookie="abort:no_oidc_cookie_found",
            first_login_after_oidc="create_entry",
        ),
        id="oidc_only",
    ),
    pytest.param(
        Scenario(
            other_providers=[PASSWORD],
            authorize_redirects=True,
            welcome_continues=False,
            providers=["auth_oidc", "homeassistant"],
            first_login_without_cookie="abort:no_oidc_cookie_found",
            first_login_after_oidc="create_entry",
        ),
        id="password",
    ),
    pytest.param(
        Scenario(
            other_providers=[TRUSTED, PASSWORD],
            authorize_redirects=False,
            welcome_continues=False,
            providers=["trusted_networks", "auth_oidc", "homeassistant"],
            first_login_without_cookie="form:init",
            first_login_after_oidc="form:init",
        ),
        id="trusted_network",
    ),
    pytest.param(
        Scenario(
            other_providers=[UNTRUSTED, PASSWORD],
            authorize_redirects=True,
            welcome_continues=False,
            providers=["auth_oidc", "homeassistant"],
            first_login_without_cookie="abort:no_oidc_cookie_found",
            first_login_after_oidc="create_entry",
        ),
        id="untrusted_network",
    ),
    pytest.param(
        Scenario(
            other_providers=[PASSWORD],
            features={FEATURES_DEFAULT_REDIRECT: True},
            authorize_redirects=True,
            welcome_continues=True,
            providers=["auth_oidc", "homeassistant"],
            first_login_without_cookie="abort:no_oidc_cookie_found",
            first_login_after_oidc="create_entry",
        ),
        id="default_redirect",
    ),
]


async def setup_scenario(hass: HomeAssistant, scenario: Scenario) -> None:
    """Set up Home Assistant's providers first, like at startup, then OIDC."""
    await setup_mock_authorize_route(hass)

    for config in scenario.other_providers:
        # pylint: disable=protected-access
        provider = await auth_provider_from_config(hass, hass.auth._store, config)
        assert provider is not None
        hass.auth._providers[(provider.type, provider.id)] = provider

    assert await async_setup_component(hass, "auth", {})
    assert await async_setup_component(
        hass,
        DOMAIN,
        {
            DOMAIN: {
                CLIENT_ID: "http://example.com/",
                DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
                FEATURES: scenario.features,
            }
        },
    )


def describe(result: dict[str, Any]) -> str:
    """Summarize a login flow result, e.g. 'abort:<reason>' or 'form:<step>'."""
    detail = result.get("reason") or result.get("step_id")
    return f"{result['type']}:{detail}" if detail else result["type"]


async def get_providers(client) -> list[dict[str, Any]]:
    """Return the providers that the frontend would show."""
    resp = await client.get("/auth/providers")
    assert resp.status == 200

    return (await resp.json())["providers"]


async def start_first_login(client) -> str:
    """Start the login flow of the first provider, as the frontend does."""
    first = (await get_providers(client))[0]
    origin = get_test_origin(client)

    resp = await client.post(
        "/auth/login_flow",
        json={
            "client_id": f"{origin}/",
            "handler": [first["type"], first["id"]],
            "redirect_uri": f"{origin}/?auth_callback=1",
        },
    )
    assert resp.status == 200

    return describe(await resp.json())


async def login_with_oidc(hass: HomeAssistant, client) -> None:
    """Complete an OIDC login, which leaves a ready state cookie in the client."""
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID, get_test_origin(client))
    state, _, _ = await get_welcome_for_client(client, redirect_uri)

    authorization_url = await get_redirect_auth_url(client)
    async with async_get_clientsession(hass).get(authorization_url) as resp:
        code = (await resp.json())["code"]

    await complete_callback_and_finish(client, code, state)


@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_authorize_page(
    hass: HomeAssistant, hass_client_no_auth, scenario: Scenario
):
    """The login page sends the browser to OIDC or shows Home Assistant's page."""
    await setup_scenario(hass, scenario)
    client = await hass_client_no_auth()
    origin = get_test_origin(client)

    query = urlencode(
        {"client_id": f"{origin}/", "redirect_uri": f"{origin}/?auth_callback=1"}
    )
    resp = await client.get(f"/auth/authorize?{query}", allow_redirects=False)

    if scenario.authorize_redirects:
        assert resp.status == 302
        assert urlparse(resp.headers["Location"]).path == "/auth/oidc/welcome"
    else:
        assert resp.status == 200

    with mock_oidc_responses():
        redirect_uri = create_redirect_uri(WEB_CLIENT_ID, origin)
        _, _, status = await get_welcome_for_client(client, redirect_uri)

    assert status == (302 if scenario.welcome_continues else 200)


@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_login_without_cookie(
    hass: HomeAssistant, hass_client_no_auth, scenario: Scenario
):
    """Without an OIDC login, the frontend starts the first listed provider."""
    await setup_scenario(hass, scenario)
    client = await hass_client_no_auth()

    providers = await get_providers(client)

    assert [provider["type"] for provider in providers] == scenario.providers
    assert await start_first_login(client) == scenario.first_login_without_cookie


@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_login_after_oidc(
    hass: HomeAssistant, hass_client_no_auth, scenario: Scenario
):
    """After an OIDC login, the frontend starts the first listed provider."""
    await setup_scenario(hass, scenario)
    client = await hass_client_no_auth()

    with mock_oidc_responses():
        await login_with_oidc(hass, client)

    assert await start_first_login(client) == scenario.first_login_after_oidc
