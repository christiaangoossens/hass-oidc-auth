import logging
from typing import OrderedDict

import voluptuous as vol
from homeassistant.core import HomeAssistant

from .example import ExampleAuthProvider

DOMAIN = "auth_oidc"
_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = vol.Schema(
    {
        
    },
    extra=vol.ALLOW_EXTRA,
)

async def async_setup(hass: HomeAssistant, config):
    """TODO"""
    # Inject Auth-Header provider.
    providers = OrderedDict()
    provider = ExampleAuthProvider(
        hass,
        hass.auth._store,
        config[DOMAIN],
    )
    providers[(provider.type, provider.id)] = provider
    providers.update(hass.auth._providers)
    hass.auth._providers = providers
    _LOGGER.debug("Injected example provider")
    return True