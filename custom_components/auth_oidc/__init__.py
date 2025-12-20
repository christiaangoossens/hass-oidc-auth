"""OIDC Integration for Home Assistant."""

import logging
import re
from typing import OrderedDict

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

# Import and re-export config schema explictly
# pylint: disable=useless-import-alias
from .config import CONFIG_SCHEMA as CONFIG_SCHEMA

# Get all the constants for the config
from .config import (
    DOMAIN,
    DEFAULT_TITLE,
    CLIENT_ID,
    CLIENT_SECRET,
    DISCOVERY_URL,
    DISPLAY_NAME,
    ID_TOKEN_SIGNING_ALGORITHM,
    GROUPS_SCOPE,
    ADDITIONAL_SCOPES,
    FEATURES,
    CLAIMS,
    ROLES,
    NETWORK,
    FEATURES_INCLUDE_GROUPS_SCOPE,
    FEATURES_DISABLE_FRONTEND_INJECTION,
    FEATURES_FORCE_HTTPS,
    REQUIRED_SCOPES,
    VERBOSE_DEBUG_MODE,
)

from .config import convert_ui_config_entry_to_internal_format

from .endpoints import (
    OIDCWelcomeView,
    OIDCRedirectView,
    OIDCFinishView,
    OIDCCallbackView,
    OIDCInjectedAuthPage,
)
from .tools.oidc_client import OIDCClient
from .provider import OpenIDAuthProvider

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config):
    """Add the OIDC Auth Provider to the providers in Home Assistant (YAML config)."""
    if DOMAIN not in config:
        return True

    my_config = config[DOMAIN]

    # Store YAML config for later access by config flow
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    hass.data[DOMAIN]["yaml_config"] = my_config

    await _setup_oidc_provider(
        hass, my_config, config[DOMAIN].get(DISPLAY_NAME, DEFAULT_TITLE)
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up OIDC Authentication from a config entry (UI config)."""
    # Convert config entry data to the format expected by the existing setup
    config_data = entry.data.copy()

    # Convert config entry format to internal format
    my_config = convert_ui_config_entry_to_internal_format(config_data)

    # Get display name from config entry
    display_name = config_data.get("display_name", DEFAULT_TITLE)

    await _setup_oidc_provider(hass, my_config, display_name)
    return True


async def async_unload_entry(_hass: HomeAssistant, _entry: ConfigEntry):
    """Unload a config entry."""
    # OIDC auth providers cannot be easily unloaded as they are integrated
    # into Home Assistant's auth system. A restart is required.
    return False


async def _setup_oidc_provider(hass: HomeAssistant, my_config: dict, display_name: str):
    """Set up the OIDC provider with the given configuration."""
    providers = OrderedDict()

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
    scope = REQUIRED_SCOPES

    # Include groups if requested (default is to include 'groups'
    # as a scope for Authelia & Authentik)
    features_config = my_config.get(FEATURES, {})
    include_groups_scope = features_config.get(FEATURES_INCLUDE_GROUPS_SCOPE, True)
    groups_scope = my_config.get(GROUPS_SCOPE, "groups")
    if include_groups_scope:
        scope += " " + groups_scope
    # Add additional scopes if configured
    additional_scopes = my_config.get(ADDITIONAL_SCOPES, [])
    if additional_scopes:
        # Ensure we have a space before adding additional scopes
        if scope:
            scope += " "
        scope += " ".join(additional_scopes)

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
        enable_verbose_debug_mode=my_config.get(VERBOSE_DEBUG_MODE, False),
    )

    # Register the views
    is_frontend_injection_enabled = (
        features_config.get(FEATURES_DISABLE_FRONTEND_INJECTION, False) is False
    )
    name = display_name
    name = re.sub(r"[^A-Za-z0-9 _\-\(\)]", "", name)

    force_https = features_config.get(FEATURES_FORCE_HTTPS, False)

    hass.http.register_view(
        OIDCWelcomeView(
            name,
            # Welcome view is not enabled if frontend injection is enabled
            not is_frontend_injection_enabled,
            force_https,
        )
    )
    hass.http.register_view(OIDCRedirectView(oidc_client, force_https))
    hass.http.register_view(OIDCCallbackView(oidc_client, provider, force_https))
    hass.http.register_view(OIDCFinishView())

    _LOGGER.info("Registered OIDC views")

    # Inject OIDC code into the frontend for /auth/authorize if the user has the
    # frontend injection feature enabled
    if is_frontend_injection_enabled:
        await OIDCInjectedAuthPage.inject(hass, name)
    else:
        _LOGGER.info("OIDC frontend changes are disabled, skipping injection")

    return True
