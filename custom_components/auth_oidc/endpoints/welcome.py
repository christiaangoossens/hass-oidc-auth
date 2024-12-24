from aiohttp import web
from homeassistant.components.http import HomeAssistantView
import logging

PATH = "/auth/oidc/welcome"

_LOGGER = logging.getLogger(__name__)

class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:welcome"

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        _LOGGER.debug("Welcome view accessed")

        return web.Response(
            headers={"content-type": "text/html"},
            text="<h1>Welcome!</h1>",
        )