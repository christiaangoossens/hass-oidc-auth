import logging
from typing import OrderedDict

import voluptuous as vol
from homeassistant.core import HomeAssistant

DOMAIN = "auth_oidc"
_LOGGER = logging.getLogger(__name__)

from .provider import OpenIDAuthProvider

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
               
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

async def async_setup(hass: HomeAssistant, config):
    """Add the OIDC Auth Provider to the providers in Home Assistant"""
    providers = OrderedDict()

    provider = OpenIDAuthProvider(
        hass,
        hass.auth._store,
        config[DOMAIN],
    )

    providers[(provider.type, provider.id)] = provider
    providers.update(hass.auth._providers)
    hass.auth._providers = providers

    _LOGGER.debug("Added OIDC provider")
    return True
