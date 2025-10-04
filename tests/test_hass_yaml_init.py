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
