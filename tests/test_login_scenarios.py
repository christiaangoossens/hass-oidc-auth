"""Login scenarios with Home Assistant's own auth providers next to OIDC.

These tests use the HTTP endpoints exactly like the Home Assistant frontend does:
the frontend fetches /auth/providers and starts the login flow of the first provider.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import patch
from urllib.parse import urlencode, urlparse

import pytest
from homeassistant.auth.providers import auth_provider_from_config
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.config.const import (
    CLIENT_ID,
    DISCOVERY_URL,
    FEATURES,
    FEATURES_DEFAULT_REDIRECT,
)
from custom_components.auth_oidc.provider import OpenIDAuthProvider, has_login_hook

from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses
from .test_hass_oidc_client_integration import (
    MOBILE_CLIENT_ID,
    WEB_CLIENT_ID,
    create_redirect_uri,
    get_test_origin,
    get_welcome_for_client,
    login_with_oidc,
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


PASSWORD_SCENARIO = Scenario(
    other_providers=[PASSWORD],
    authorize_redirects=True,
    welcome_continues=False,
    providers=["homeassistant"],
    first_login_without_cookie="form:init",
    first_login_after_oidc="create_entry",
)

SCENARIOS = [
    pytest.param(
        Scenario(
            other_providers=[],
            authorize_redirects=True,
            welcome_continues=True,
            providers=[],
            first_login_without_cookie="no_providers",
            first_login_after_oidc="create_entry",
        ),
        id="oidc_only",
    ),
    pytest.param(PASSWORD_SCENARIO, id="password"),
    pytest.param(
        Scenario(
            other_providers=[TRUSTED, PASSWORD],
            authorize_redirects=False,
            welcome_continues=False,
            providers=["trusted_networks", "homeassistant"],
            first_login_without_cookie="form:init",
            first_login_after_oidc="form:init",
        ),
        id="trusted_network",
    ),
    pytest.param(
        Scenario(
            other_providers=[PASSWORD, TRUSTED],
            authorize_redirects=True,
            welcome_continues=False,
            providers=["homeassistant", "trusted_networks"],
            first_login_without_cookie="form:init",
            first_login_after_oidc="create_entry",
        ),
        id="trusted_network_not_first",
    ),
    pytest.param(
        Scenario(
            other_providers=[UNTRUSTED, PASSWORD],
            authorize_redirects=True,
            welcome_continues=False,
            providers=["homeassistant"],
            first_login_without_cookie="form:init",
            first_login_after_oidc="create_entry",
        ),
        id="untrusted_network",
    ),
    pytest.param(
        Scenario(
            other_providers=[UNTRUSTED],
            authorize_redirects=True,
            welcome_continues=True,
            providers=[],
            first_login_without_cookie="no_providers",
            first_login_after_oidc="create_entry",
        ),
        id="untrusted_network_only",
    ),
    pytest.param(
        Scenario(
            other_providers=[PASSWORD],
            features={FEATURES_DEFAULT_REDIRECT: True},
            authorize_redirects=True,
            welcome_continues=True,
            providers=["homeassistant"],
            first_login_without_cookie="form:init",
            first_login_after_oidc="create_entry",
        ),
        id="default_redirect",
    ),
]


@pytest.fixture(
    params=[
        pytest.param(
            "hook",
            marks=pytest.mark.skipif(
                not has_login_hook(), reason="Home Assistant < 2026.11 has no hook"
            ),
        ),
        "route_filter",
    ]
)
def oidc_hiding(request: pytest.FixtureRequest) -> Iterator[str]:
    """Run each test with HA's provider hook and with the /auth/providers filter.

    The filter also runs on 2026.11+, with our hook switched off like on older versions.
    """
    if request.param == "hook":
        yield "hook"
        return

    with (
        patch("custom_components.auth_oidc.has_login_hook", return_value=False),
        patch.object(OpenIDAuthProvider, "async_can_start_login", return_value=True),
    ):
        yield "route_filter"


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
    """Start the login flow of the first provider, as the frontend does.

    Without providers, the frontend shows an error instead: 'no_providers'.
    """
    providers = await get_providers(client)
    if not providers:
        return "no_providers"

    first = providers[0]
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
async def test_phone_offers_default_login_only_when_available(
    hass: HomeAssistant, hass_client_no_auth, scenario: Scenario
):
    """The code page on a phone links to Home Assistant's login only if it offers one."""
    await setup_scenario(hass, scenario)
    client = await hass_client_no_auth()

    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
    _, page, _ = await get_welcome_for_client(client, redirect_uri)

    assert ('id="alternative-sign-in-link"' in page) == bool(scenario.providers)


@pytest.mark.usefixtures("oidc_hiding")
@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_login_without_cookie(
    hass: HomeAssistant, hass_client_no_auth, scenario: Scenario
):
    """Without an OIDC login, OIDC is hidden, like any provider that cannot start."""
    await setup_scenario(hass, scenario)
    client = await hass_client_no_auth()

    providers = await get_providers(client)

    assert [provider["type"] for provider in providers] == scenario.providers
    assert await start_first_login(client) == scenario.first_login_without_cookie


@pytest.mark.usefixtures("oidc_hiding")
@pytest.mark.parametrize("scenario", SCENARIOS)
async def test_login_after_oidc(
    hass: HomeAssistant, hass_client_no_auth, scenario: Scenario
):
    """After an OIDC login, OIDC is listed in its usual place and finishes the login."""
    await setup_scenario(hass, scenario)
    client = await hass_client_no_auth()

    with mock_oidc_responses():
        await login_with_oidc(hass, client)

    providers = await get_providers(client)

    assert "auth_oidc" in [provider["type"] for provider in providers]
    assert await start_first_login(client) == scenario.first_login_after_oidc


@pytest.mark.usefixtures("oidc_hiding")
@pytest.mark.parametrize("oidc_hiding", ["route_filter"], indirect=True)
async def test_filtered_provider_list_is_not_cached(
    hass: HomeAssistant, hass_client_no_auth
):
    """On older Home Assistant, the list depends on the login cookie, so it isn't cached."""
    await setup_scenario(hass, PASSWORD_SCENARIO)
    client = await hass_client_no_auth()

    for logged_in in (False, True):
        if logged_in:
            with mock_oidc_responses():
                await login_with_oidc(hass, client)

        resp = await client.get("/auth/providers")
        assert resp.headers["Cache-Control"] == "no-store"


@pytest.mark.skipif(not has_login_hook(), reason="Home Assistant < 2026.11 has no hook")
async def test_oidc_login_cannot_start_without_cookie(
    hass: HomeAssistant, hass_client_no_auth
):
    """Home Assistant refuses to start a hidden OIDC login, like any unknown provider."""
    await setup_scenario(hass, PASSWORD_SCENARIO)
    client = await hass_client_no_auth()
    origin = get_test_origin(client)

    resp = await client.post(
        "/auth/login_flow",
        json={
            "client_id": f"{origin}/",
            "handler": ["auth_oidc", "default"],
            "redirect_uri": f"{origin}/?auth_callback=1",
        },
    )

    assert resp.status == 404
