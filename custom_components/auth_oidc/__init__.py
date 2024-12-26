import logging
from typing import OrderedDict

import voluptuous as vol
from homeassistant.core import HomeAssistant

from .endpoints.welcome import OIDCWelcomeView
from .endpoints.redirect import OIDCRedirectView
from .endpoints.finish import OIDCFinishView
from .endpoints.callback import OIDCCallbackView

from .oidc_client import OIDCClient
from .provider import OpenIDAuthProvider

DOMAIN = "auth_oidc"
_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required("client_id"): vol.Coerce(str),
                vol.Optional("client_secret"): vol.Coerce(str),
                vol.Required("discovery_url"): vol.Url(),
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

    _LOGGER.debug("Added OIDC provider for Home Assistant")

    # Define some fields
    discovery_url = config[DOMAIN]["discovery_url"]
    client_id = config[DOMAIN]["client_id"]
    scope = "openid profile email"

    oidc_client = oidc_client = OIDCClient(discovery_url, client_id, scope)

    hass.http.register_view(OIDCWelcomeView())
    hass.http.register_view(OIDCRedirectView(oidc_client))
    hass.http.register_view(OIDCCallbackView(oidc_client, provider))
    hass.http.register_view(OIDCFinishView())

    return True
