"""Tests for the YAML config setup of OIDC"""

import logging
import pytest

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import DOMAIN

_LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_setup_success_yaml(hass: HomeAssistant):
    """Test successful setup of a YAML configuration."""
    mock_config = {
        DOMAIN: {
            "client_id": "dummy",
            "discovery_url": "https://example.com/.well-known/openid-configuration",
        }
    }
    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert result
    assert DOMAIN in hass.data


@pytest.mark.asyncio
async def test_setup_failure_empty_yaml(hass: HomeAssistant, caplog):
    """Test failure setup of an empty YAML configuration."""
    mock_config = {DOMAIN: {}}
    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert not result

    assert "required key 'client_id' not provided" in caplog.text
    assert "required key 'discovery_url' not provided" in caplog.text
    assert (
        "Setup failed for custom integration 'auth_oidc': Invalid config."
        in caplog.text
    )


@pytest.mark.asyncio
async def test_setup_failure_partial_empty_yaml_discovery(hass: HomeAssistant, caplog):
    """Test failure setup of an partial YAML configuration."""
    mock_config = {
        DOMAIN: {
            "discovery_url": "https://example.com/.well-known/openid-configuration"
        }
    }
    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert not result

    assert "required key 'client_id' not provided" in caplog.text
    assert not "required key 'discovery_url' not provided" in caplog.text
    assert (
        "Setup failed for custom integration 'auth_oidc': Invalid config."
        in caplog.text
    )


@pytest.mark.asyncio
async def test_setup_failure_partial_empty_yaml_client(hass: HomeAssistant, caplog):
    """Test failure setup of an partial YAML configuration."""
    mock_config = {DOMAIN: {"client_id": "test"}}
    result = await async_setup_component(hass, DOMAIN, mock_config)
    assert not result

    assert not "required key 'client_id' not provided" in caplog.text
    assert "required key 'discovery_url' not provided" in caplog.text
    assert (
        "Setup failed for custom integration 'auth_oidc': Invalid config."
        in caplog.text
    )
