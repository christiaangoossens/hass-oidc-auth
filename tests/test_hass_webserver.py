"""Tests for the registered webpages"""

import base64
import os
from unittest.mock import AsyncMock, MagicMock, patch
from auth_oidc.config.const import DISCOVERY_URL, CLIENT_ID
import pytest

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from homeassistant.components.http import StaticPathConfig, DOMAIN as HTTP_DOMAIN

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.endpoints.injected_auth_page import (
    OIDCInjectedAuthPage,
    frontend_injection,
)


WEB_CLIENT_ID = "https://example.com"
MOBILE_CLIENT_ID = "https://home-assistant.io/Android"


def create_redirect_uri(client_id: str) -> str:
    """Build a redirect URI that includes a client_id query parameter."""
    return f"http://example.com/auth/authorize?client_id={client_id}"


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


@pytest.mark.asyncio
async def test_welcome_page_registration(hass: HomeAssistant, hass_client):
    """Test that welcome page is present."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/welcome", allow_redirects=False)
    assert resp.status == 200


@pytest.mark.asyncio
async def test_redirect_page_registration(hass: HomeAssistant, hass_client):
    """Test that redirect page can be reached."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 302

    resp2 = await client.post("/auth/oidc/redirect", allow_redirects=False)
    assert resp2.status == 302


@pytest.mark.asyncio
async def test_welcome_rejects_invalid_encoded_redirect_uri(
    hass: HomeAssistant, hass_client
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
async def test_welcome_sets_secure_state_cookie_flags(hass: HomeAssistant, hass_client):
    """Welcome should set secure cookie flags for the OIDC state cookie."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
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
    hass: HomeAssistant, hass_client
):
    """Welcome should error if device code generation fails for mobile clients."""
    await setup(hass)

    with patch(
        "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_generate_device_code",
        new=AsyncMock(return_value=None),
    ):
        client = await hass_client()
        redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID)
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
    hass: HomeAssistant, hass_client
):
    """Welcome should render fallback auth link when other providers are present."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
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
    hass: HomeAssistant, hass_client
):
    """Welcome should auto-redirect desktop clients when no other providers exist."""

    # pylint: disable=protected-access
    hass.auth._providers = []  # Clear initial providers out
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
    encoded = encode_redirect_uri(redirect_uri)
    resp = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp.status == 302
    assert "/auth/oidc/redirect" in resp.headers["Location"]


@pytest.mark.asyncio
async def test_redirect_without_cookie_goes_to_welcome(
    hass: HomeAssistant, hass_client
):
    """Redirect endpoint should bounce to welcome when no state cookie exists."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 302
    assert "/auth/oidc/welcome" in resp.headers["Location"]


@pytest.mark.asyncio
async def test_redirect_shows_error_on_oidc_runtime_error(
    hass: HomeAssistant, hass_client
):
    """Redirect should show a configuration error when OIDC URL generation raises."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
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
    hass: HomeAssistant, hass_client
):
    """Redirect should show error page if OIDC returns no authorization URL."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
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
async def test_callback_registration(hass: HomeAssistant, hass_client):
    """Test that callback page is reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/callback", allow_redirects=False)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_callback_rejects_missing_code_or_state(hass: HomeAssistant, hass_client):
    """Callback must reject requests missing either code or state."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
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

    resp_missing_state = await client.get(
        "/auth/oidc/callback?code=testcode",
        allow_redirects=False,
    )
    assert resp_missing_state.status == 400
    assert "Missing code or state parameter." in await resp_missing_state.text()


@pytest.mark.asyncio
async def test_callback_rejects_state_mismatch(hass: HomeAssistant, hass_client):
    """Callback must reject state mismatch to protect against CSRF."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
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


@pytest.mark.asyncio
async def test_callback_rejects_when_user_details_fetch_fails(
    hass: HomeAssistant, hass_client
):
    """Callback should error when token exchange/userinfo retrieval fails."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    state = resp_welcome.cookies["auth_oidc_state"].value

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
async def test_callback_rejects_invalid_role(hass: HomeAssistant, hass_client):
    """Callback should reject users marked with invalid role."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    state = resp_welcome.cookies["auth_oidc_state"].value

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
    hass: HomeAssistant, hass_client, method: str, data: dict | None
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
async def test_finish_post_rejects_invalid_state(hass: HomeAssistant, hass_client):
    """Finish POST should error when the state cookie does not resolve to redirect_uri."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(WEB_CLIENT_ID)
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status in (200, 302)

    with patch(
        "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_get_redirect_uri_for_state",
        new=AsyncMock(return_value=None),
    ):
        resp = await client.post("/auth/oidc/finish", allow_redirects=False)
        assert resp.status == 400
        assert "Invalid state, please restart login." in await resp.text()


@pytest.mark.asyncio
async def test_device_sse_requires_state_cookie(hass: HomeAssistant, hass_client):
    """SSE endpoint should reject requests without state cookie."""
    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
    assert resp.status == 400
    assert "Missing session cookie" in await resp.text()


@pytest.mark.asyncio
async def test_device_sse_emits_expired_for_unknown_state(
    hass: HomeAssistant, hass_client
):
    """SSE should emit expired when the state can no longer be resolved."""
    await setup(hass)

    with patch(
        "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_get_redirect_uri_for_state",
        new=AsyncMock(return_value=None),
    ):
        client = await hass_client()
        redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID)
        encoded = encode_redirect_uri(redirect_uri)
        resp_welcome = await client.get(
            f"/auth/oidc/welcome?redirect_uri={encoded}",
            allow_redirects=False,
        )
        assert resp_welcome.status == 200

        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        assert resp.status == 200
        payload = await resp.text()
        assert "event: expired" in payload


@pytest.mark.asyncio
async def test_device_sse_emits_timeout(hass: HomeAssistant, hass_client):
    """SSE should emit timeout if the polling window is exceeded."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID)
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status == 200

    fake_loop = MagicMock()
    fake_loop.time.side_effect = [0, 301]

    with (
        patch(
            "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_get_redirect_uri_for_state",
            new=AsyncMock(return_value=redirect_uri),
        ),
        patch(
            "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_is_state_ready",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "custom_components.auth_oidc.endpoints.device_sse.asyncio.get_running_loop",
            return_value=fake_loop,
        ),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        assert resp.status == 200
        payload = await resp.text()
        assert "event: timeout" in payload


@pytest.mark.asyncio
async def test_device_sse_handles_runtime_error_and_returns_cleanly(
    hass: HomeAssistant, hass_client
):
    """SSE should swallow runtime errors from stream loop and finish response."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID)
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status == 200

    with (
        patch(
            "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_get_redirect_uri_for_state",
            new=AsyncMock(return_value=redirect_uri),
        ),
        patch(
            "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_is_state_ready",
            new=AsyncMock(side_effect=RuntimeError("disconnect")),
        ),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        assert resp.status == 200


@pytest.mark.asyncio
async def test_device_sse_ignores_write_eof_connection_reset(
    hass: HomeAssistant, hass_client
):
    """SSE should ignore ConnectionResetError while closing the stream."""
    await setup(hass)

    client = await hass_client()
    redirect_uri = create_redirect_uri(MOBILE_CLIENT_ID)
    encoded = encode_redirect_uri(redirect_uri)
    resp_welcome = await client.get(
        f"/auth/oidc/welcome?redirect_uri={encoded}",
        allow_redirects=False,
    )
    assert resp_welcome.status == 200

    with (
        patch(
            "custom_components.auth_oidc.provider.OpenIDAuthProvider.async_get_redirect_uri_for_state",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "custom_components.auth_oidc.endpoints.device_sse.web.StreamResponse.write_eof",
            new=AsyncMock(side_effect=ConnectionResetError),
        ),
    ):
        resp = await client.get("/auth/oidc/device-sse", allow_redirects=False)
        assert resp.status == 200


# Test the frontend injection
@pytest.mark.asyncio
async def test_frontend_injection(hass: HomeAssistant, hass_client):
    """Test that frontend injection works."""

    # Because there is no frontend in the test setup,
    # we'll have to fake /auth/authorize for the changes to register
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

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/authorize", allow_redirects=False)
    assert resp.status == 200
    text = await resp.text()

    assert "<script src='/auth/oidc/static/injection.js" in text


@pytest.mark.asyncio
async def test_frontend_injection_logs_and_returns_when_route_handler_is_unexpected(
    hass: HomeAssistant, caplog
):
    """frontend_injection should log and return if the GET handler shape is unexpected."""

    await async_setup_component(hass, HTTP_DOMAIN, {})

    class FakeRoute:
        method = "GET"
        handler = object()

    class FakeResource:
        canonical = "/auth/authorize"

        def __init__(self):
            self.prefix = None

        def add_prefix(self, prefix):
            self.prefix = prefix

        def __iter__(self):
            return iter([FakeRoute()])

    with patch.object(hass.http.app.router, "resources", return_value=[FakeResource()]):
        await frontend_injection(hass)

    assert "Unexpected route handler type" in caplog.text
    assert (
        "Failed to find GET route for /auth/authorize, cannot inject OIDC frontend code"
        in caplog.text
    )


@pytest.mark.asyncio
async def test_injected_auth_page_inject_logs_errors(hass: HomeAssistant, caplog):
    """OIDCInjectedAuthPage.inject should swallow unexpected injection errors."""

    await async_setup_component(hass, HTTP_DOMAIN, {})

    with patch(
        "custom_components.auth_oidc.endpoints.injected_auth_page.frontend_injection",
        side_effect=RuntimeError("boom"),
    ):
        await OIDCInjectedAuthPage.inject(hass)

    assert "Failed to inject OIDC auth page: boom" in caplog.text
