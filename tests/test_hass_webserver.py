"""Tests for the YAML config setup of OIDC"""

import logging
from auth_oidc.config.const import (
    DISCOVERY_URL,
    CLIENT_ID,
    FEATURES,
    FEATURES_DISABLE_FRONTEND_INJECTION,
)
import pytest

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def setup(hass: HomeAssistant, enable_frontend_changes: bool = None):
    mock_config = {
        DOMAIN: {
            CLIENT_ID: "dummy",
            DISCOVERY_URL: "https://example.com/.well-known/openid-configuration",
            FEATURES: {
                FEATURES_DISABLE_FRONTEND_INJECTION: not enable_frontend_changes
            },
        }
    }

    if enable_frontend_changes is None:
        del mock_config[DOMAIN][FEATURES][FEATURES_DISABLE_FRONTEND_INJECTION]

    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result


@pytest.mark.asyncio
async def test_welcome_page_registration(hass: HomeAssistant, hass_client):
    """Test that welcome page is present if frontend changes are disabled."""

    await setup(hass, enable_frontend_changes=False)

    client = await hass_client()
    resp = await client.get("/auth/oidc/welcome", allow_redirects=False)
    assert resp.status == 200


@pytest.mark.asyncio
async def test_welcome_page_registration_with_changes(hass: HomeAssistant, hass_client):
    """Test that welcome page is redirect if frontend changes are enabled."""

    await setup(hass, enable_frontend_changes=True)

    client = await hass_client()
    resp = await client.get("/auth/oidc/welcome", allow_redirects=False)
    assert resp.status == 307


@pytest.mark.asyncio
async def test_redirect_page_registration(hass: HomeAssistant, hass_client):
    """Test that redirect page shows OIDC misconfiguration error if OIDC server is not reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/redirect", allow_redirects=False)
    assert resp.status == 200
    text = await resp.text()
    assert "Integration is misconfigured" in text

    resp2 = await client.post("/auth/oidc/redirect", allow_redirects=False)
    assert resp2.status == 200


@pytest.mark.asyncio
async def test_callback_registration(hass: HomeAssistant, hass_client):
    """Test that callback page is reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/callback", allow_redirects=False)
    assert resp.status == 200


@pytest.mark.asyncio
async def test_finish_registration(hass: HomeAssistant, hass_client):
    """Test that finish page is reachable."""

    await setup(hass)

    client = await hass_client()
    resp = await client.get("/auth/oidc/finish", allow_redirects=False)
    assert resp.status == 200
    text = await resp.text()

    # Should miss the code parameter if called without it
    assert "Missing code" in text

    resp2 = await client.get("/auth/oidc/finish?code=123456", allow_redirects=False)
    assert resp2.status == 200
    text2 = await resp2.text()
    assert "Missing code" not in text2
    assert "123456" in text2


@pytest.mark.asyncio
async def test_finish_post(hass: HomeAssistant, hass_client):
    """Test that finish page works with POST."""

    await setup(hass)
    client = await hass_client()
    resp = await client.post("/auth/oidc/finish", data={}, allow_redirects=False)
    assert resp.status == 500

    resp2 = await client.post(
        "/auth/oidc/finish", data={"code": "456888"}, allow_redirects=False
    )
    assert resp2.status == 302
    assert resp2.headers["Location"] == "/?storeToken=true"
    assert resp2.cookies["auth_oidc_code"].value == "456888"
