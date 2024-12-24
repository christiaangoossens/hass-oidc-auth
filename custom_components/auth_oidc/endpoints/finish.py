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

        code = request.query.get("code", "FAIL")

        return web.Response(
            headers={"content-type": "text/html"},
            text=f"<h1>Done!</h1><p>Your code is: <b>{code}</b></p><p>Please return to the Home Assistant login screen (or your mobile app) and fill in this code into the single login field. It should be visible if you select 'Login with OpenID Connect (SSO)'.</p>",
        )