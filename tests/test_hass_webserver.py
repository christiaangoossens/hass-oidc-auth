"""Tests for the registered webpages"""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING
from unittest.mock import ANY, AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import pytest
from aiohttp import web
from auth_oidc.config.const import (
    CLIENT_ID,
    DISCOVERY_URL,
    FEATURES,
    FEATURES_DEFAULT_REDIRECT,
    FEATURES_FORCE_HTTPS,
    SOURCE_STATIC_FILES,
)
from homeassistant.components.http import DOMAIN as HTTP_DOMAIN
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.endpoints import device_sse
from custom_components.auth_oidc.tools.http_route_takeover import take_over_get_route
from custom_components.auth_oidc.tools.types import OIDCFlow

from .integration import get_state_store

if TYPE_CHECKING:
    # Annotation only, so the tests also run with the older
    # pytest-homeassistant-custom-component harness (HA < 2026.11)
    from pytest_homeassistant.typing import ClientSessionGenerator

MOBILE_CLIENT_ID = "https://home-assistant.io/Android"
STATE_STORE = "custom_components.auth_oidc.stores.state_store.StateStore"
TEST_FLOW: OIDCFlow = {"code_verifier": "verifier", "nonce": "nonce"}
WELCOME_PATH = "/auth/oidc/welcome"


def assert_redirects_to_welcome(resp) -> None:
    """Assert a response redirects to the OIDC welcome endpoint."""
    assert resp.status == 302
    location = resp.headers["Location"]
    parsed_location = urlparse(location)
    assert parsed_location.path == WELCOME_PATH


async def assert_home_assistant_login_page(resp) -> None:
    """Assert Home Assistant's own login page was served, unchanged."""
    assert resp.status == 200
    assert "Test page" in await resp.text()


def create_redirect_uri(client_id: str, origin: str) -> str:
    """Build a redirect URI that includes a client_id query parameter."""
    params = {
        "response_type": "code",
        "redirect_uri": client_id,
        "client_id": client_id,
        "state": "example",
    }

    return f"{origin.rstrip('/')}/auth/authorize?{urlencode(params)}"


def get_test_origin(client) -> str:
    """Return the actual HTTP origin for the current test client session."""
    return str(client.make_url("/")).rstrip("/")


def get_test_client_id(client) -> str:
    """Return the test client's own URL, used as the OAuth client_id."""
    return str(client.make_url("/"))


def encode_redirect_uri(redirect_uri: str) -> str:
    """Encode redirect_uri in the same way as frontend btoa()."""
    return base64.b64encode(redirect_uri.encode("utf-8")).decode("utf-8")


async def setup(
    hass: HomeAssistant,
):
    mock_config = {
        DOMAIN: {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
        }
    }

    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result


async def setup_mock_authorize_route(hass: HomeAssistant) -> None:
    """Register a mock /auth/authorize page, like Home Assistant's frontend does."""
    await async_setup_component(hass, HTTP_DOMAIN, {})

    mock_html_path = os.path.join(os.path.dirname(__file__), "mocks", "auth_page.html")
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/auth/authorize",
                mock_html_path,
                cache_headers=False,
            )
        ]
    )


@pytest.mark.asyncio
async def test_welcome_page_registration(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Test that welcome page is present."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/welcome", allow_redirects=False)
    assert resp.status == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("url", list(SOURCE_STATIC_FILES))
async def test_static_files_are_served(
    hass: HomeAssistant, hass_client: ClientSessionGenerator, url: str
):
    """The static files the pages link to are served from the integration's folder."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get(url)
    assert resp.status == 200


@pytest.mark.asyncio
async def test_redirect_page_registration(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Test that redirect page can be reached."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 302

    resp2 = await client.post("/auth/oidc/redirect", allow_redirects=False)
    assert resp2.status == 302


@pytest.mark.asyncio
async def test_welcome_page_default_redirect(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Test that the welcome page returns a redirect when default_redirect is preferred."""

    mock_config = {
        DOMAIN: {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
            FEATURES: {FEATURES_DEFAULT_REDIRECT: True},
        }
    }

    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result

    client = await hass_client()
    resp = await client.get("/auth/oidc/welcome", allow_redirects=False)
    assert resp.status == 302


@pytest.mark.asyncio
async def test_welcome_rejects_invalid_encoded_redirect_uri(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should reject malformed base64 redirect_uri values."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get(
        "/auth/oidc/welcome?redirect_uri=%25%25%25",
        allow_redirects=False,
    )
    assert resp.status == 400
    assert "Invalid redirect_uri, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_welcome_page_translated(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome page should render in German when the browser prefers it."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get(
        "/auth/oidc/welcome",
        headers={"Accept-Language": "de-DE,de;q=0.9,en;q=0.8"},
        allow_redirects=False,
    )
    assert resp.status == 200
    assert resp.headers["Vary"] == "Accept-Language"

    body = await resp.text()
    assert 'lang="de"' in body
    assert "anmelden" in body


@pytest.mark.asyncio
async def test_error_page_translated(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Error pages should render in German when the browser prefers it."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get(
        "/auth/oidc/welcome?redirect_uri=%25%25%25",
        headers={"Accept-Language": "de-DE,de;q=0.9,en;q=0.8"},
        allow_redirects=False,
    )
    assert resp.status == 400

    body = await resp.text()
    assert 'lang="de"' in body
    assert "Ungültige redirect_uri, bitte starte die Anmeldung neu." in body


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://example.com/auth/authorize?client_id=https://example.com",
        "http://example.com/auth/authorize?redirect_uri=https://example.com",
    ],
)
async def test_welcome_rejects_redirect_uris_missing_required_query_params(
    hass: HomeAssistant, hass_client: ClientSessionGenerator, redirect_uri: str
):
    """Welcome should reject redirect URIs that decode but are incomplete."""
    await setup(hass)

    client = await hass_client()
    encoded = encode_redirect_uri(redirect_uri)
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )

    assert resp.status == 400
    assert "Invalid redirect_uri, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_welcome_rejects_evil_redirect_uri(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should reject well-formed but evil values."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get(
        "/auth/oidc/welcome?redirect_uri=amF2YXNjcmlwdDphbGVydChkb2N1bWVudC5kb21haW4p",
        allow_redirects=False,
    )
    assert resp.status == 400
    assert "Invalid redirect_uri, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_welcome_rejects_weird_origin_redirect_uri(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should reject well-formed but bad-origin values."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri("random_client_id", "https://evil.com")
    encoded = encode_redirect_uri(redirect_uri)
    resp = await client.get(
        "/auth/oidc/welcome?redirect_uri=" + encoded,
        allow_redirects=False,
    )
    assert resp.status == 400
    assert "Invalid redirect_uri, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_welcome_accepts_host_starting_with_auth(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """A Home Assistant on a host like auth.example.com passes the same-origin check."""
    await setup(hass)

    client = await hass_client()
    origin = "http://auth.example.com:8123"
    redirect_uri = create_redirect_uri(f"{origin}/", origin)
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        headers={"Host": "auth.example.com:8123"},
        allow_redirects=False,
    )
    assert resp.status in (200, 302)


@pytest.mark.asyncio
async def test_welcome_rejects_non_ha_oauth2_path_redirect_uri(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should reject redirect URIs that have the right origin but the wrong HA path."""
    await setup(hass)

    client = await hass_client()
    origin = get_test_origin(client)
    redirect_uri = (
        f"{origin}/auth/not-ha-authorize?response_type=code"
        f"&redirect_uri={origin}%2F%3Fauth_callback%3D1"
        f"&client_id={origin}%2F&state=example"
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp = await client.get(
        "/auth/oidc/welcome?redirect_uri=" + encoded,
        allow_redirects=False,
    )
    assert resp.status == 400
    assert "Invalid redirect_uri, please restart login." in await resp.text()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client_id", "should_store_token", "is_mobile"),
    [
        ("", True, False),
        (MOBILE_CLIENT_ID, False, True),
        ("https://random.example", False, False),
    ],
)
async def test_welcome_only_adds_store_token_for_web_clients(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    client_id: str,
    should_store_token: bool,
    is_mobile: bool,
):
    """Welcome should only append storeToken for clients aligned with the base URL."""
    await setup(hass)

    captured_redirect_uri = {}

    def fake_create_state(state_redirect_uri: str, *_args):
        captured_redirect_uri["value"] = state_redirect_uri
        return "state-id"

    with (
        patch(
            f"{STATE_STORE}.create_state",
            new=MagicMock(side_effect=fake_create_state),
        ),
        patch(
            f"{STATE_STORE}.create_device_code",
            new=MagicMock(return_value="123456"),
        ),
    ):
        client = await hass_client()

        if client_id == "":
            # If not present, set it to the root URL to
            # emulate the normal website/Lovelace/dashboard
            client_id = str(client.make_url("/?test=true"))

        redirect_uri = create_redirect_uri(client_id, get_test_origin(client))
        encoded = encode_redirect_uri(redirect_uri)
        resp = await client.get(
            f"/auth/oidc/welcome?redirect_uri={encoded}",
            allow_redirects=False,
        )

    assert resp.status in (200, 302)
    assert "value" in captured_redirect_uri

    parsed_state_redirect = urlparse(captured_redirect_uri["value"])
    state_redirect_query = parse_qs(parsed_state_redirect.query)
    nested_redirect_uri = unquote(state_redirect_query["redirect_uri"][0])

    if should_store_token:
        assert "storeToken=true" in nested_redirect_uri
    else:
        assert "storeToken=true" not in nested_redirect_uri

    if is_mobile:
        assert "https://home-assistant.io/" in nested_redirect_uri


@pytest.mark.asyncio
async def test_welcome_sets_secure_state_cookie_flags(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should set secure cookie flags for the OIDC state cookie."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)

    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )

    assert resp.status in (200, 302)
    assert "auth_oidc_state" in resp.cookies

    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "Path=/auth/" in set_cookie
    assert "SameSite=Lax" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Max-Age=300" in set_cookie


@pytest.mark.asyncio
async def test_welcome_mobile_device_code_generation_failure(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should error if device code generation fails for mobile clients."""
    await setup(hass)

    with patch(
        f"{STATE_STORE}.create_device_code",
        new=MagicMock(return_value=None),
    ):
        client = await hass_client()
        redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
        encoded = encode_redirect_uri(redirect_uri)

        resp = await client.get(
            f"/auth/oidc/welcome?redirect_uri={encoded}",
            allow_redirects=False,
        )
        assert resp.status == 500
        assert (
            "Failed to generate device code, please restart login." in await resp.text()
        )


@pytest.mark.asyncio
async def test_welcome_shows_alternative_sign_in_link_when_other_providers_exist(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should render fallback auth link when other providers are present."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp.status == 200
    text = await resp.text()
    assert 'id="login-button"' in text
    assert 'id="alternative-sign-in-link"' in text
    assert "skip_oidc_redirect=true" in text


@pytest.mark.asyncio
async def test_welcome_desktop_auto_redirects_without_other_providers(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Welcome should auto-redirect desktop clients when no other providers exist."""

    hass.auth._providers = {}  # Clear initial providers out

    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp.status == 302
    assert "/auth/oidc/redirect" in resp.headers["Location"]


@pytest.mark.asyncio
async def test_redirect_without_cookie_goes_to_welcome(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Redirect endpoint should bounce to welcome when no state cookie exists."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 302
    assert_redirects_to_welcome(resp)


@pytest.mark.asyncio
async def test_redirect_shows_error_on_oidc_runtime_error(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Redirect should show a configuration error when OIDC URL generation raises."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status in (200, 302)

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.OIDCClient.async_get_authorization_url",
        new=AsyncMock(side_effect=RuntimeError("broken discovery")),
    ):
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
        assert resp.status == 500
        assert (
            "Integration is misconfigured, discovery could not be obtained."
            in await resp.text()
        )


@pytest.mark.asyncio
async def test_redirect_shows_error_when_auth_url_empty(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Redirect should show error page if OIDC returns no authorization URL."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status in (200, 302)

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.OIDCClient.async_get_authorization_url",
        new=AsyncMock(return_value=None),
    ):
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
        assert resp.status == 500
        assert (
            "Integration is misconfigured, discovery could not be obtained."
            in await resp.text()
        )


@pytest.mark.asyncio
async def test_login_pages_reject_a_state_from_another_ip(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """A state cookie used from another IP than it was created on is not accepted."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        allow_redirects=False,
    )
    state = resp_welcome.cookies["auth_oidc_state"].value

    # As if the cookie was taken to another network
    get_state_store(hass).get_data()[state]["ip_address"] = "10.0.0.1"

    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 302
    assert resp.headers["Location"].endswith(WELCOME_PATH)

    for resp in (
        await client.get("/auth/oidc/finish"),
        await client.post("/auth/oidc/finish", data={"device_code": "123456"}),
        await client.get(f"/auth/oidc/callback?code=code&state={state}"),
    ):
        assert resp.status == 400
        assert "Missing state cookie" in await resp.text()

    resp = await client.get("/auth/oidc/device-sse")
    assert await resp.text() == "event: expired\ndata: false\n\n"


@pytest.mark.asyncio
async def test_redirect_rejects_state_removed_during_discovery(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """A state that is gone once the discovery document loaded can't store its flow."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        allow_redirects=False,
    )
    state = resp_welcome.cookies["auth_oidc_state"].value

    async def remove_state_during_discovery(*_args):
        # Like an expiry or eviction would
        get_state_store(hass).get_data().pop(state)
        return "https://issuer/authorize", TEST_FLOW

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.OIDCClient.async_get_authorization_url",
        new=remove_state_during_discovery,
    ):
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)

    assert resp.status == 400
    assert "Invalid state, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_callback_registration(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Test that callback page is reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/callback", allow_redirects=False)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_callback_rejects_missing_state(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Callback must reject requests missing state."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )

    resp_missing_state = await client.get(
        "/auth/oidc/callback?code=testcode",
        allow_redirects=False,
    )
    assert resp_missing_state.status == 400
    assert "Missing code or state parameter." in await resp_missing_state.text()


@pytest.mark.asyncio
async def test_callback_rejects_missing_code(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Callback must reject requests missing code."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    state = resp_welcome.cookies["auth_oidc_state"].value

    resp_missing_code = await client.get(
        f"/auth/oidc/callback?state={state}",
        allow_redirects=False,
    )
    assert resp_missing_code.status == 400
    assert "Missing code or state parameter." in await resp_missing_code.text()


async def open_welcome_page(client) -> str:
    """Open the welcome page like a browser, and return the state cookie."""
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        allow_redirects=False,
    )
    return resp.cookies["auth_oidc_state"].value


@pytest.mark.parametrize(
    ("error_params", "language", "shown"),
    [
        (
            {"error": "access_denied", "error_description": "The user denied access"},
            "en",
            "The OIDC provider returned an error: The user denied access",
        ),
        (
            {"error": "access_denied"},
            "en",
            "The OIDC provider returned an error: access_denied",
        ),
        (
            # Home Assistant itself already blocks queries with <...script...>
            {"error": "access_denied", "error_description": "<b>{code}</b>"},
            "en",
            "The OIDC provider returned an error: &lt;b&gt;{code}&lt;/b&gt;",
        ),
        (
            {"error": "access_denied", "error_description": "The user denied access"},
            "de",
            "Der OIDC-Anbieter hat einen Fehler zurückgegeben: The user denied access",
        ),
    ],
    ids=["description", "code-only", "escaped", "german"],
)
async def test_callback_shows_provider_error(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    error_params: dict[str, str],
    language: str,
    shown: str,
):
    """An OAuth error from the identity provider, with our state, shows its
    description, or its code, escaped and after a translated lead-in."""
    await setup(hass)

    client = await hass_client()
    state = await open_welcome_page(client)

    resp = await client.get(
        f"/auth/oidc/callback?{urlencode({**error_params, 'state': state})}",
        headers={"Accept-Language": language},
        allow_redirects=False,
    )
    text = await resp.text()

    assert resp.status == 400
    assert shown in text
    assert "<b>" not in text


@pytest.mark.parametrize(
    ("query", "shown_error"),
    [
        ("error=access_denied&state=other", "State parameter does not match"),
        ("error=access_denied", "Missing code or state parameter."),
    ],
    ids=["wrong-state", "no-state"],
)
async def test_callback_hides_provider_text_without_matching_state(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    caplog: pytest.LogCaptureFixture,
    query: str,
    shown_error: str,
):
    """A crafted callback link can't show its own text on the error page,
    because an error without our state is rejected like a code would be.
    The error is still logged."""
    await setup(hass)

    client = await hass_client()
    await open_welcome_page(client)

    resp = await client.get(
        f"/auth/oidc/callback?{query}&error_description=Call+support+now",
        allow_redirects=False,
    )
    text = await resp.text()

    assert resp.status == 400
    assert shown_error in text
    assert "Call support now" not in text
    assert (
        "Identity provider returned error 'access_denied': 'Call support now'"
        in caplog.text
    )


@pytest.mark.asyncio
async def test_callback_rejects_state_mismatch(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Callback must reject state mismatch to protect against CSRF."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    state = resp_welcome.cookies["auth_oidc_state"].value

    resp = await client.get(
        f"/auth/oidc/callback?code=testcode&state={state}-other",
        allow_redirects=False,
    )
    assert resp.status == 400
    assert "State parameter does not match, possible CSRF attack." in await resp.text()


async def start_login_at_provider(client) -> str:
    """Visit the welcome and redirect pages like a browser, and return the state."""
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        allow_redirects=False,
    )

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.OIDCClient.async_get_authorization_url",
        new=AsyncMock(return_value=("https://issuer/authorize", TEST_FLOW)),
    ):
        resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
        assert resp.status == 200

    return resp_welcome.cookies["auth_oidc_state"].value


@pytest.mark.asyncio
async def test_redirect_hands_flow_to_callback(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """The PKCE verifier and nonce from the redirect reach the token request."""
    await setup(hass)

    client = await hass_client()
    state = await start_login_at_provider(client)

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.OIDCClient.async_complete_token_flow",
        new=AsyncMock(return_value=None),
    ) as complete_token_flow:
        await client.get(
            f"/auth/oidc/callback?code=testcode&state={state}",
            allow_redirects=False,
        )

    complete_token_flow.assert_awaited_once_with(ANY, "testcode", TEST_FLOW)


@pytest.mark.asyncio
async def test_callback_rejects_state_that_was_not_redirected(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """A callback for a state that never went to the identity provider is rejected."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        allow_redirects=False,
    )
    state = resp_welcome.cookies["auth_oidc_state"].value

    resp = await client.get(
        f"/auth/oidc/callback?code=testcode&state={state}",
        allow_redirects=False,
    )
    assert resp.status == 400
    assert "Invalid state, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_callback_rejects_when_user_details_fetch_fails(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Callback should error when token exchange/userinfo retrieval fails."""
    await setup(hass)

    client = await hass_client()
    state = await start_login_at_provider(client)

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.OIDCClient.async_complete_token_flow",
        new=AsyncMock(return_value=None),
    ):
        resp = await client.get(
            f"/auth/oidc/callback?code=testcode&state={state}",
            allow_redirects=False,
        )
        assert resp.status == 500
        assert (
            "Failed to get user details, see Home Assistant logs for more information."
            in await resp.text()
        )


@pytest.mark.asyncio
async def test_callback_rejects_invalid_role(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Callback should reject users marked with invalid role."""
    await setup(hass)

    client = await hass_client()
    state = await start_login_at_provider(client)

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.OIDCClient.async_complete_token_flow",
        new=AsyncMock(return_value={"sub": "abc", "role": "invalid"}),
    ):
        resp = await client.get(
            f"/auth/oidc/callback?code=testcode&state={state}",
            allow_redirects=False,
        )
        assert resp.status == 403
        assert (
            "User is not in the correct group to access Home Assistant"
            in await resp.text()
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "data"),
    [
        ("get", None),
        ("post", {}),
        ("post", {"device_code": "456888"}),
    ],
)
async def test_finish_requires_state_cookie(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    method: str,
    data: dict | None,
):
    """Finish endpoint should require the OIDC state cookie for both GET and POST."""
    await setup(hass)

    client = await hass_client()
    request = getattr(client, method)
    if data is None:
        resp = await request("/auth/oidc/finish", allow_redirects=False)
    else:
        resp = await request("/auth/oidc/finish", data=data, allow_redirects=False)

    assert resp.status == 400
    assert "Missing state cookie" in await resp.text()


@pytest.mark.asyncio
async def test_finish_post_rejects_invalid_state(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Finish POST should error when the state cookie does not resolve to redirect_uri."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(
        get_test_client_id(client), get_test_origin(client)
    )
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status in (200, 302)

    with patch(
        f"{STATE_STORE}.get_redirect_uri_for_state",
        new=MagicMock(return_value=None),
    ):
        resp = await client.post("/auth/oidc/finish", allow_redirects=False)
        assert resp.status == 400
        assert "Invalid state, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_device_sse_without_state_reports_expired(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """Without a valid state the stream says expired, so the page offers a new code."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)

    assert resp.status == 200
    assert await resp.text() == "event: expired\ndata: false\n\n"


@pytest.mark.asyncio
async def test_device_sse_emits_expired_for_unknown_state(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """SSE should emit expired when the state can no longer be resolved."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status == 200

    # Valid when the stream opens, expired at the first poll
    with patch(
        f"{STATE_STORE}.is_state_valid",
        new=MagicMock(side_effect=[True, False]),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        assert resp.status == 200
        payload = await resp.text()
        assert "event: expired" in payload


@pytest.mark.asyncio
async def test_device_sse_ready_wins_over_expired(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """An approved login finishes even when its state expires at the same poll."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
    await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        allow_redirects=False,
    )

    with (
        patch(
            f"{STATE_STORE}.is_state_valid",
            new=MagicMock(side_effect=[True, False]),
        ),
        patch(
            f"{STATE_STORE}.is_state_ready",
            new=MagicMock(return_value=True),
        ),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        payload = await resp.text()

    assert payload.endswith("event: ready\ndata: true\n\n")
    assert "event: expired" not in payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("keepalive_seconds", "keepalives"),
    [(0, 2), (15, 0)],
)
async def test_device_sse_sends_keepalive_while_waiting(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    monkeypatch: pytest.MonkeyPatch,
    keepalive_seconds: int,
    keepalives: int,
):
    """A waiting stream says so once, then only sends a keepalive after a quiet period."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
    await client.get(
        f"/auth/oidc/welcome?redirect_uri={encode_redirect_uri(redirect_uri)}",
        allow_redirects=False,
    )

    monkeypatch.setattr(device_sse, "POLL_SECONDS", 0)
    monkeypatch.setattr(device_sse, "KEEPALIVE_SECONDS", keepalive_seconds)

    # Valid when the stream opens and for two polls, expired at the third
    with patch(
        f"{STATE_STORE}.is_state_valid",
        new=MagicMock(side_effect=[True, True, True, False]),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        payload = await resp.text()

    assert resp.headers["Content-Type"] == "text/event-stream"
    assert resp.headers["X-Accel-Buffering"] == "no"
    assert payload.count("event: waiting") == 1
    assert payload.count(": keepalive") == keepalives
    assert payload.endswith("event: expired\ndata: false\n\n")


@pytest.mark.asyncio
async def test_device_sse_handles_runtime_error_and_returns_cleanly(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """SSE should swallow runtime errors from stream loop and finish response."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status == 200

    with patch(
        f"{STATE_STORE}.is_state_ready",
        new=MagicMock(side_effect=RuntimeError("disconnect")),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        assert resp.status == 200


@pytest.mark.asyncio
async def test_device_sse_ignores_write_eof_connection_reset(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """SSE should ignore ConnectionResetError while closing the stream."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID, get_test_origin(client))
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status == 200

    with (
        patch(
            f"{STATE_STORE}.is_state_valid",
            new=MagicMock(side_effect=[True, False]),
        ),
        patch(
            "custom_components.auth_oidc.endpoints.device_sse.web.StreamResponse.write_eof",
            new=AsyncMock(side_effect=ConnectionResetError),
        ),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        assert resp.status == 200


# Test the login page at /auth/authorize
@pytest.mark.asyncio
async def test_authorize_page_serves_home_assistant_page_without_redirect_uri(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """A login page not started by a client is Home Assistant's own page."""

    # Because there is no frontend in the test setup,
    # we'll have to fake /auth/authorize for the takeover to find it.
    await setup_mock_authorize_route(hass)

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/authorize", allow_redirects=False)
    await assert_home_assistant_login_page(resp)


@pytest.mark.asyncio
async def test_authorize_page_logs_error_when_route_is_missing(
    hass: HomeAssistant, caplog
):
    """Without the login page there is nothing to redirect, the log says what to open."""
    await async_setup_component(hass, HTTP_DOMAIN, {})

    await setup(hass)

    assert any(
        record.levelname == "ERROR"
        and "Could not find /auth/authorize" in record.message
        and WELCOME_PATH in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_authorize_page_takeover_failure_keeps_home_assistant_page(
    hass: HomeAssistant, hass_client: ClientSessionGenerator, caplog
):
    """A failing takeover leaves Home Assistant's login page untouched."""
    await setup_mock_authorize_route(hass)

    with patch(
        "custom_components.auth_oidc.endpoints.authorize.take_over_get_route",
        side_effect=RuntimeError("boom"),
    ):
        await setup(hass)

    assert "Failed to redirect /auth/authorize to OIDC" in caplog.text

    client = await hass_client()
    encoded_redirect_uri = quote(
        create_redirect_uri(get_test_client_id(client), get_test_origin(client)),
        safe="",
    )
    resp = await client.get(
        f"/auth/authorize?redirect_uri={encoded_redirect_uri}", allow_redirects=False
    )
    await assert_home_assistant_login_page(resp)


@pytest.mark.asyncio
async def test_authorize_page_redirects_to_welcome_when_not_skipped(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """The login page redirects into OIDC when skip flags are absent."""

    await setup_mock_authorize_route(hass)
    await setup(hass)

    client = await hass_client()
    encoded_redirect_uri = quote(
        create_redirect_uri(get_test_client_id(client), get_test_origin(client)),
        safe="",
    )

    resp = await client.get(
        f"/auth/authorize?redirect_uri={encoded_redirect_uri}",
        allow_redirects=False,
    )
    assert resp.status == 302

    location = resp.headers["Location"]
    parsed_location = urlparse(location)
    assert parsed_location.path == "/auth/oidc/welcome"

    query = parse_qs(parsed_location.query)
    assert "redirect_uri" in query

    original_url = base64.b64decode(unquote(query["redirect_uri"][0]), validate=True)
    original_url = original_url.decode("utf-8")
    assert "/auth/authorize?redirect_uri=" in original_url


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "request_target",
    [
        "/auth/authorize?skip_oidc_redirect=true",
        "/auth/authorize?redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fauthorize%3Fskip_oidc_redirect%3Dtrue",
    ],
)
async def test_authorize_page_serves_home_assistant_page_when_skipped(
    hass: HomeAssistant,
    hass_client,
    request_target: str,
):
    """The login page is Home Assistant's own when redirect suppression is requested."""

    await setup_mock_authorize_route(hass)
    await setup(hass)

    client = await hass_client()
    response = await client.get(request_target, allow_redirects=False)

    await assert_home_assistant_login_page(response)


@pytest.mark.parametrize("path", ["/test/post-only", "/test/missing"])
async def test_route_takeover_needs_an_existing_get_route(
    hass: HomeAssistant, path: str
):
    """A path without a GET route, or without any route, is not taken over."""
    await async_setup_component(hass, HTTP_DOMAIN, {})

    async def handler(_request: web.Request) -> web.Response:
        return web.Response(text="post")

    hass.http.app.router.add_post("/test/post-only", handler)
    wrap = MagicMock()

    assert take_over_get_route(hass, path, wrap) is False
    wrap.assert_not_called()


@pytest.mark.asyncio
async def test_authorize_redirect_uses_https_when_forced(
    hass: HomeAssistant, hass_client: ClientSessionGenerator
):
    """With force_https, the login page redirects to https and returns to https,
    without changing the client's own redirect_uri."""
    await setup_mock_authorize_route(hass)
    assert await async_setup_component(
        hass,
        DOMAIN,
        {
            DOMAIN: {
                CLIENT_ID: "dummy",
                DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
                FEATURES: {FEATURES_FORCE_HTTPS: True},
            }
        },
    )

    client = await hass_client()
    encoded_redirect_uri = quote(
        create_redirect_uri(get_test_client_id(client), get_test_origin(client)),
        safe="",
    )
    resp = await client.get(
        f"/auth/authorize?redirect_uri={encoded_redirect_uri}", allow_redirects=False
    )

    location = resp.headers["Location"]
    return_url = base64.b64decode(
        unquote(parse_qs(urlparse(location).query)["redirect_uri"][0])
    ).decode()
    assert location.startswith("https://")
    assert return_url.startswith("https://")

    client_redirect_uri = parse_qs(urlparse(return_url).query)["redirect_uri"][0]
    assert client_redirect_uri == unquote(encoded_redirect_uri)
