"""Tests for the YAML config setup of OIDC"""

import pytest

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.config.const import ADDITIONAL_SCOPES


async def setup(hass: HomeAssistant, config: dict, expect_success: bool) -> bool:
    """Set up the auth_oidc component."""
    result = await async_setup_component(hass, DOMAIN, {DOMAIN: config})

    if expect_success:
        assert result
        assert DOMAIN in hass.data


@pytest.mark.asyncio
async def test_setup_success_yaml(hass: HomeAssistant):
    """Test successful setup of a YAML configuration."""
    await setup(
        hass,
        {
            "client_id": "dummy",
            "discovery_url": "https://example.com/.well-known/openid-configuration",
        },
        True,
    )


@pytest.mark.asyncio
async def test_setup_success_yaml_with_optional(hass: HomeAssistant):
    """Test successful setup of a YAML configuration with optional parameters."""
    await setup(
        hass,
        {
            "client_id": "dummy",
            "discovery_url": "https://example.com/.well-known/openid-configuration",
            ADDITIONAL_SCOPES: "email phone",
        },
        True,
    )


@pytest.mark.asyncio
async def test_setup_failure_empty_yaml(hass: HomeAssistant, caplog):
    """Test failure setup of an empty YAML configuration."""
    await setup(hass, {}, False)

    assert "required key 'client_id' not provided" in caplog.text
    assert "required key 'discovery_url' not provided" in caplog.text
    assert (
        "Setup failed for custom integration 'auth_oidc': Invalid config."
        in caplog.text
    )


@pytest.mark.asyncio
async def test_setup_failure_partial_empty_yaml_discovery(hass: HomeAssistant, caplog):
    """Test failure setup of an partial YAML configuration."""
    await setup(
        hass,
        {"discovery_url": "https://example.com/.well-known/openid-configuration"},
        False,
    )

    assert "required key 'client_id' not provided" in caplog.text
    assert "required key 'discovery_url' not provided" not in caplog.text
    assert (
        "Setup failed for custom integration 'auth_oidc': Invalid config."
        in caplog.text
    )


@pytest.mark.asyncio
async def test_setup_failure_partial_empty_yaml_client(hass: HomeAssistant, caplog):
    """Test failure setup of an partial YAML configuration."""

    await setup(
        hass,
        {"client_id": "test"},
        False,
    )

    assert "required key 'client_id' not provided" not in caplog.text
    assert "required key 'discovery_url' not provided" in caplog.text
    assert (
        "Setup failed for custom integration 'auth_oidc': Invalid config."
        in caplog.text
    )
