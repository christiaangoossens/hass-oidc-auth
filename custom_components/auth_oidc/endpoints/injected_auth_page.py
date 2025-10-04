"""Injected authorization page, replacing the original"""

import logging
from functools import partial
from homeassistant.components.http import HomeAssistantView, StaticPathConfig
from homeassistant.core import HomeAssistant
from aiohttp import web
from aiofiles import open as async_open

PATH = "/auth/authorize"

_LOGGER = logging.getLogger(__name__)


async def read_file(path: str) -> str:
    """Read a file from the static path."""
    async with async_open(path, mode="r") as f:
        return await f.read()


async def frontend_injection(hass: HomeAssistant, sso_name: str) -> None:
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

            # The original frontend path is the first argument of the handler
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

    # Inject JS and register that route
    frontend_code = frontend_code.replace(
        "</body>",
        "<script src='/auth/oidc/static/injection.js?v=3'></script><script>window.sso_name = '"
        + sso_name
        + "';</script></body>",
    )

    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/auth/oidc/static/injection.js",
                hass.config.path("custom_components/auth_oidc/static/injection.js"),
                cache_headers=False,
            )
        ]
    )

    # If everything is succesful, register a fake view that just returns the modified HTML
    hass.http.register_view(OIDCInjectedAuthPage(frontend_code))
    _LOGGER.info("Performed OIDC frontend injection")


class OIDCInjectedAuthPage(HomeAssistantView):
    """OIDC Plugin Injected Auth Page."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:authorize_page"

    def __init__(self, html: str) -> None:
        """Initialize the injected auth page."""
        self.html = html

    @staticmethod
    async def inject(hass: HomeAssistant, sso_name: str) -> None:
        """Inject the OIDC auth page into the frontend."""
        try:
            await frontend_injection(hass, sso_name)
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error("Failed to inject OIDC auth page: %s", e)

    async def get(self, _) -> web.Response:
        """Return the screen"""
        return web.Response(text=self.html, content_type="text/html")
