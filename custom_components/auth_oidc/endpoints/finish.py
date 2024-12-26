"""Finish route to allow the user to view their code."""

from homeassistant.components.http import HomeAssistantView
from aiohttp import web

from auth_oidc.helpers import get_url

PATH = "/auth/oidc/finish"


class OIDCFinishView(HomeAssistantView):
    """OIDC Plugin Finish View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:finish"

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        code = request.query.get("code", "FAIL")
        link = get_url("/")

        return web.Response(
            headers={
                "content-type": "text/html",
                "set-cookie": "auth_oidc_code="
                + code
                + "; Path=/auth/login_flow; SameSite=Strict; HttpOnly; Max-Age=300",
            },
            text=f"<h1>Done!</h1><p>Your code is: <b>{code}</b></p>"
            + "<p>Please return to the Home Assistant login "
            + "screen (or your mobile app) and fill in this code into the single login field. "
            + "It should be visible if you "
            + "select 'Login with OpenID Connect (SSO)'.</p><p><a href='"
            + link
            + "'>Click here to login automatically (on desktop).</a></p>",
        )
