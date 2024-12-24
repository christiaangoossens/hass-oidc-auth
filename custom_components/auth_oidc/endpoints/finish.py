from aiohttp import web
from homeassistant.components.http import HomeAssistantView
import logging

PATH = "/auth/oidc/finish"

_LOGGER = logging.getLogger(__name__)

class OIDCFinishView(HomeAssistantView):
    """OIDC Plugin Finish View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:finish"

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        _LOGGER.debug("Finish view accessed")

        return web.Response(
            headers={"content-type": "text/html"},
            text="<h1>Finish</h1>",
        )