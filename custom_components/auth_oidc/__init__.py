"""OIDC Integration for Home Assistant."""

import logging
from typing import OrderedDict

from functools import partial
from aiofiles import open as async_open
from homeassistant.core import HomeAssistant
from homeassistant.components.http import StaticPathConfig

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
    ADDITIONAL_SCOPES,
    FEATURES,
    CLAIMS,
    ROLES,
    NETWORK,
    FEATURES_INCLUDE_GROUPS_SCOPE,
)

# pylint: enable=useless-import-alias

from .endpoints.welcome import OIDCWelcomeView
from .endpoints.redirect import OIDCRedirectView
from .endpoints.finish import OIDCFinishView
from .endpoints.callback import OIDCCallbackView

from .oidc_client import OIDCClient
from .provider import OpenIDAuthProvider

_LOGGER = logging.getLogger(__name__)


async def read_file(path: str) -> str:
    """Read a file from the static path."""
    async with async_open(path, mode="r") as f:
        return await f.read()


async def frontend_injection(hass: HomeAssistant) -> None:
    """Inject new frontend code into /auth/authorize."""
    router = hass.http.app.router
    frontend_path = None

    for resource in router.resources():
        if resource.canonical != "/auth/authorize":
            continue

        # This path doesn't actually work, gives 404, effectively disabling the old matcher
        resource.add_prefix("/auth/oidc/unused")

        # Now get the original frontend path from this resource to obtain the GET route
        routes = iter(resource)
        route = next(
            (r for r in routes if r.method == "GET"),
            None,
        )

        if route is not None:
            if not route.handler or not isinstance(route.handler, partial):
                _LOGGER.warning(
                    "Unexpected route handler type %s for /auth/authorize",
                    type(route.handler),
                )
                continue

            frontend_path = route.handler.args[0]
            break

    # Get the path to the original frontend resource
    if frontend_path is None:
        _LOGGER.info(
            "Failed to find GET route for /auth/authorize, cannot inject OIDC frontend code"
        )
        return

    # Inject our new script into the existing frontend code
    # First fetch the frontend path into memory
    frontend_code = await read_file(frontend_path)

    # Inject JS
    frontend_code = frontend_code.replace(
        "</body>", "<script src='/auth/oidc/static/injection.js'></script></body>"
    )
    _LOGGER.debug(frontend_code)

    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/auth/oidc/static/injection.js",
                ,
                cache_headers=False,
            )
        ]
    )

    await hass.http.async_register_static_paths(
        [
            # Mimic the old code from HASS core:
            # StaticPathConfig("/auth/authorize", str(root_path / "authorize.html"), False)
            StaticPathConfig(
                "/auth/authorize",
                frontend_path,
                cache_headers=False,
            )
        ]
    )
    _LOGGER.info("Registered OIDC frontend injection")


async def async_setup(hass: HomeAssistant, config):
    """Add the OIDC Auth Provider to the providers in Home Assistant"""
    my_config = config[DOMAIN]

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
    scope = "openid profile"

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
    oidc_client = oidc_client = OIDCClient(
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

    # Register the views
    name = config[DOMAIN].get(DISPLAY_NAME, DEFAULT_TITLE)

    hass.http.register_view(OIDCWelcomeView(name))
    hass.http.register_view(OIDCRedirectView(oidc_client))
    hass.http.register_view(OIDCCallbackView(oidc_client, provider))
    hass.http.register_view(OIDCFinishView())

    _LOGGER.info("Registered OIDC views")

    # Inject OIDC code into the frontend for /auth/authorize if the user has the
    # frontend injection feature enabled
    if features_config.get("disable_frontend_changes", False) is False:
        await frontend_injection(hass)

    return True
