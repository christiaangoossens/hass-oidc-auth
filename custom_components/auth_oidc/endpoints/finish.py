"""Finish route to allow the user to view their code."""

from homeassistant.components.http import HomeAssistantView
from aiohttp import web
from ..helpers import get_view, get_url

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

        view_html = await get_view("finish", {"code": code, "link": link})
        return web.Response(
            headers={
                "content-type": "text/html",
                # Set a cookie to enable autologin on only the specific path used
                # for the POST request, with all strict parameters set
                # This cookie should not be read by any Javascript or any other paths.
                "set-cookie": "auth_oidc_code="
                + code
                + "; Path=/auth/login_flow; SameSite=Strict; HttpOnly; Max-Age=300",
            },
            text=view_html,
        )
