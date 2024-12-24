from aiohttp import web
from homeassistant.components.http import HomeAssistantView
import logging

PATH = "/auth/oidc/redirect"

_LOGGER = logging.getLogger(__name__)

class OIDCRedirectView(HomeAssistantView):
    """OIDC Plugin Redirect View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:redirect"

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        _LOGGER.debug("Redirect view accessed")

        return web.Response(
            headers={"content-type": "text/html"},
            text="<h1>Redirect</h1>",
        )

    async def post(self, request: web.Request) -> web.Response:
        """POST"""

        _LOGGER.debug("Redirect POST view accessed")

        return self.json_message("POST received")