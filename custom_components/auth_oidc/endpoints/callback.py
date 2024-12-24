from aiohttp import web
from homeassistant.components.http import HomeAssistantView
import logging

PATH = "/auth/oidc/callback"

_LOGGER = logging.getLogger(__name__)

class OIDCCallbackView(HomeAssistantView):
    """OIDC Plugin Callback View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:callback"

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        _LOGGER.debug("Callback view accessed")

        return web.Response(
            headers={"content-type": "text/html"},
            text="<h1>Callback</h1>",
        )