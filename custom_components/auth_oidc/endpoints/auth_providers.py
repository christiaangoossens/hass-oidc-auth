"""Hide the OIDC provider on /auth/providers until its login is ready.

Only for Home Assistant before 2026.11. Newer versions ask the provider itself through
OpenIDAuthProvider.async_can_start_login. Delete this file once hacs.json requires 2026.11.
"""

import json
import logging
from typing import cast

from aiohttp import web
from homeassistant.core import HomeAssistant

from ..provider import OpenIDAuthProvider
from ..tools.http_route_takeover import Handler, take_over_get_route

PATH = "/auth/providers"

_LOGGER = logging.getLogger(__name__)


def filter_providers(
    response: web.StreamResponse, provider: OpenIDAuthProvider
) -> web.StreamResponse:
    """Drop OIDC from the providers unless its login is ready.

    Error responses, like onboarding not being finished, are passed on unchanged.
    """
    if not isinstance(response, web.Response) or response.status != 200:
        return response

    if not provider.is_login_ready():
        data = json.loads(cast(bytes, response.body))
        others = [p for p in data["providers"] if p["type"] != provider.type]
        response = web.json_response({**data, "providers": others})

    # The list depends on the login cookie, so it must not be cached
    response.headers["Cache-Control"] = "no-store"
    return response


def take_over_auth_providers(hass: HomeAssistant, provider: OpenIDAuthProvider) -> None:
    """Filter /auth/providers through filter_providers."""

    def wrap(original_handler: Handler) -> Handler:
        async def get(req: web.Request) -> web.StreamResponse:
            return filter_providers(await original_handler(req), provider)

        return get

    try:
        if take_over_get_route(hass, PATH, wrap):
            return

        _LOGGER.error(
            "Could not find %s, so the login page may offer OIDC before its "
            "login can finish",
            PATH,
        )
    # pylint: disable-next=broad-except
    except Exception:
        _LOGGER.exception(
            "Failed to filter %s, so the login page may offer OIDC before its "
            "login can finish",
            PATH,
        )
