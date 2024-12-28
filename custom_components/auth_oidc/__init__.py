"""OIDC Integration for Home Assistant."""

import logging
from typing import OrderedDict

from homeassistant.core import HomeAssistant

# Import and re-export config schema explictly
# pylint: disable=useless-import-alias
from .config import CONFIG_SCHEMA as CONFIG_SCHEMA, DOMAIN

from .endpoints.welcome import OIDCWelcomeView
from .endpoints.redirect import OIDCRedirectView
from .endpoints.finish import OIDCFinishView
from .endpoints.callback import OIDCCallbackView

from .oidc_client import OIDCClient
from .provider import OpenIDAuthProvider

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config):
    """Add the OIDC Auth Provider to the providers in Home Assistant"""
    providers = OrderedDict()

    # Use private APIs until there is a real auth platform
    # pylint: disable=protected-access
    provider = OpenIDAuthProvider(hass, hass.auth._store, config[DOMAIN])

    providers[(provider.type, provider.id)] = provider
    providers.update(hass.auth._providers)
    hass.auth._providers = providers
    # pylint: enable=protected-access

    _LOGGER.info("Registered OIDC provider")

    # Define some fields
    discovery_url: str = config[DOMAIN]["discovery_url"]
    client_id: str = config[DOMAIN]["client_id"]

    # We only use openid & profile, never email
    scope: str = "openid profile"

    # TODO: Allow setting the options
    oidc_client = oidc_client = OIDCClient(discovery_url, client_id, scope)

    hass.http.register_view(OIDCWelcomeView())
    hass.http.register_view(OIDCRedirectView(oidc_client))
    hass.http.register_view(OIDCCallbackView(oidc_client, provider))
    hass.http.register_view(OIDCFinishView())

    _LOGGER.info("Registered OIDC views")

    return True
