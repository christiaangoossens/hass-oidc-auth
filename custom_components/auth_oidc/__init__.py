"""OIDC Integration for Home Assistant."""

import logging
from typing import OrderedDict

from homeassistant.core import HomeAssistant

# Import and re-export config schema explictly
# pylint: disable=useless-import-alias
from .config import (
    CONFIG_SCHEMA as CONFIG_SCHEMA,
    DOMAIN,
    DEFAULT_TITLE,
    CLIENT_ID,
    CLIENT_SECRET,
    DISCOVERY_URL,
    DISPLAY_NAME,
    ID_TOKEN_SIGNING_ALGORITHM,
    GROUPS_SCOPE,
    FEATURES,
    CLAIMS,
    ROLES,
    NETWORK,
    FEATURES_INCLUDE_GROUPS_SCOPE,
    FEATURES_WELCOME_PATH,
    FEATURES_REDIRECT_PATH,
    )

# pylint: enable=useless-import-alias

from .endpoints.welcome import OIDCWelcomeView
from .endpoints.redirect import OIDCRedirectView
from .endpoints.finish import OIDCFinishView
from .endpoints.callback import OIDCCallbackView

from .oidc_client import OIDCClient
from .provider import OpenIDAuthProvider

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config):
    """Add the OIDC Auth Provider to the providers in Home Assistant"""
    my_config = config[DOMAIN]

    providers = OrderedDict()

    # Read the welcome and redirect paths from the configuration
    welcome_path = my_config.get(FEATURES_WELCOME_PATH, "/auth/oidc/welcome")
    redirect_path = my_config.get(FEATURES_REDIRECT_PATH, "/auth/oidc/redirect")

    # Use private APIs until there is a real auth platform
    # pylint: disable=protected-access
    provider = OpenIDAuthProvider(hass, hass.auth._store, my_config)

    providers[(provider.type, provider.id)] = provider
    providers.update(hass.auth._providers)
    hass.auth._providers = providers
    # pylint: enable=protected-access

    _LOGGER.info("Registered OIDC provider")

    # Set the correct scopes
    # Always use 'openid' & 'profile' as they are specified in the OIDC spec
    # All servers should support this
    scope = "openid profile"

    # Include groups if requested (default is to include 'groups'
    # as a scope for Authelia & Authentik)
    features_config = my_config.get(FEATURES, {})
    include_groups_scope = features_config.get(FEATURES_INCLUDE_GROUPS_SCOPE, True)
    groups_scope = my_config.get(GROUPS_SCOPE, "groups")
    if include_groups_scope:
        scope += " " + groups_scope

    # Create the OIDC client
    oidc_client = OIDCClient(
        hass=hass,
        discovery_url=my_config.get(DISCOVERY_URL),
        client_id=my_config.get(CLIENT_ID),
        scope=scope,
        client_secret=my_config.get(CLIENT_SECRET),
        id_token_signing_alg=my_config.get(ID_TOKEN_SIGNING_ALGORITHM),
        features=my_config.get(FEATURES, {}),
        claims=my_config.get(CLAIMS, {}),
        roles=my_config.get(ROLES, {}),
        network=my_config.get(NETWORK, {}),
    )

    # Register the views with the custom paths
    name = config[DOMAIN].get(DISPLAY_NAME, DEFAULT_TITLE)

    hass.http.register_view(OIDCWelcomeView(name, welcome_path))
    hass.http.register_view(OIDCRedirectView(oidc_client, redirect_path))
    hass.http.register_view(OIDCCallbackView(oidc_client, provider))
    hass.http.register_view(OIDCFinishView())

    _LOGGER.info("Registered OIDC views")

    return True
