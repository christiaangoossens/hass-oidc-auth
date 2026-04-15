"""Injected authorization page, replacing the original"""

import base64
import logging
from functools import partial
from urllib.parse import quote, unquote
from aiohttp import web
from aiofiles import open as async_open

from homeassistant.components.http import HomeAssistantView, StaticPathConfig
from homeassistant.core import HomeAssistant

from .welcome import PATH as WELCOME_PATH
from ..tools.helpers import get_url

PATH = "/auth/authorize"

_LOGGER = logging.getLogger(__name__)


async def read_file(path: str) -> str:
    """Read a file from the static path."""
    async with async_open(path, mode="r") as f:
        return await f.read()


async def frontend_injection(hass: HomeAssistant, force_https: bool) -> None:
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
    injection_js = "<script src='/auth/oidc/static/injection.js?v=6'></script>"
    frontend_code = frontend_code.replace("</body>", f"{injection_js}</body>")

    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/auth/oidc/static/injection.js",
                hass.config.path("custom_components/auth_oidc/static/injection.js"),
                cache_headers=False,
            ),
            StaticPathConfig(
                "/auth/oidc/static/style.css",
                hass.config.path("custom_components/auth_oidc/static/style.css"),
                cache_headers=False,
            ),
        ]
    )

    # If everything is succesful, register a fake view that just returns the modified HTML
    hass.http.register_view(OIDCInjectedAuthPage(frontend_code, force_https))
    _LOGGER.info("Performed OIDC frontend injection")


class OIDCInjectedAuthPage(HomeAssistantView):
    """OIDC Plugin Injected Auth Page."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:authorize_page"

    def __init__(self, html: str, force_https: bool) -> None:
        """Initialize the injected auth page."""
        self.html = html
        self.force_https = force_https

    @staticmethod
    async def inject(hass: HomeAssistant, force_https: bool) -> None:
        """Inject the OIDC auth page into the frontend."""
        try:
            await frontend_injection(hass, force_https)
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.error("Failed to inject OIDC auth page: %s", e)

    @staticmethod
    def _should_do_oidc_redirect(req: web.Request) -> bool:
        """Check if we should redirect to the OIDC flow."""
        # Set when we return from finish
        if req.query.get("skip_oidc_redirect") == "true":
            return False

        # Set whenever you directly do /?skip_oidc_redirect=true,
        # for example when you click the "other" button on the welcome screen
        redirect_uri = req.query.get("redirect_uri")
        if not redirect_uri:
            return False

        # Handle both encoded and plain redirect_uri values.
        decoded_redirect_uri = unquote(redirect_uri)
        return "skip_oidc_redirect=true" not in decoded_redirect_uri

    def _get_welcome_redirect_location(self, req: web.Request) -> str:
        """Build the welcome URL for the injected auth page redirect."""
        encoded_current_url = quote(
            base64.b64encode(str(req.url).encode("utf-8")).decode("ascii")
        )
        return get_url(
            f"{WELCOME_PATH}?redirect_uri={encoded_current_url}",
            self.force_https,
        )

    async def get(self, req: web.Request) -> web.Response:
        """Return the original page or redirect into the OIDC flow."""
        if self._should_do_oidc_redirect(req):
            raise web.HTTPFound(location=self._get_welcome_redirect_location(req))

        return web.Response(text=self.html, content_type="text/html")
