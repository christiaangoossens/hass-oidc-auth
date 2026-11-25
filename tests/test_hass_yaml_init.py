"""Tests for the YAML config setup of OIDC"""

from unittest.mock import patch

import pytest
from homeassistant.const import EVENT_HOMEASSISTANT_CLOSE
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.auth_oidc import CONFIG_SCHEMA, DOMAIN
from custom_components.auth_oidc.config.const import ADDITIONAL_SCOPES
from custom_components.auth_oidc.tools.oidc_client import OIDCClient


async def setup(hass: HomeAssistant, config: dict, expect_success: bool) -> None:
    """Set up the auth_oidc component."""
    result = await async_setup_component(hass, DOMAIN, {DOMAIN: config})

    if expect_success:
        assert result
        assert DOMAIN in hass.data


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config",
    [
        {
            "client_id": "dummy",
            "discovery_url": "https://example.com/.well-known/openid-configuration",
        },
        {
            "client_id": "dummy",
            "discovery_url": "https://example.com/.well-known/openid-configuration",
            ADDITIONAL_SCOPES: "email phone",
        },
    ],
)
async def test_setup_success_yaml(hass: HomeAssistant, config: dict):
    """YAML setup should succeed for minimal and optional-scope configurations."""
    await setup(
        hass,
        config,
        True,
    )


@pytest.mark.parametrize(
    ("additional_scopes", "expected"),
    [
        ("email", ["email"]),
        (["email", "phone"], ["email", "phone"]),
        ([], []),
    ],
)
def test_additional_scopes_accepts_a_single_string(
    additional_scopes: str | list[str], expected: list[str]
):
    """A single scope given as a string is one scope, not a list of characters."""
    config = CONFIG_SCHEMA(
        {
            DOMAIN: {
                "client_id": "dummy",
                "discovery_url": "https://example.com/.well-known/openid-configuration",
                ADDITIONAL_SCOPES: additional_scopes,
            }
        }
    )

    assert isinstance(config, dict)
    assert config[DOMAIN][ADDITIONAL_SCOPES] == expected


async def test_http_session_closes_when_home_assistant_stops(hass: HomeAssistant):
    """The OIDC client's HTTP session is closed on shutdown."""
    with patch.object(OIDCClient, "async_close") as async_close:
        await setup(
            hass,
            {
                "client_id": "dummy",
                "discovery_url": "https://example.com/.well-known/openid-configuration",
            },
            True,
        )

        hass.bus.async_fire(EVENT_HOMEASSISTANT_CLOSE)
        await hass.async_block_till_done()

    async_close.assert_awaited_once()


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
