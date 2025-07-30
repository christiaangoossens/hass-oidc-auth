"""Finish route to allow the user to view their code."""

from homeassistant.components.http import HomeAssistantView
from aiohttp import web
from ..helpers import get_view

PATH = "/auth/oidc/finish"


class OIDCFinishView(HomeAssistantView):
    """OIDC Plugin Finish View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:finish"

    async def get(self, request: web.Request) -> web.Response:
        """Show the finish screen to allow the user to view their code."""

        code = request.query.get("code")

        if not code:
            view_html = await get_view(
                "error",
                {"error": "Missing code to show the finish screen."},
            )
            return web.Response(text=view_html, content_type="text/html")

        view_html = await get_view("finish", {"code": code})
        return web.Response(text=view_html, content_type="text/html")

    async def post(self, request: web.Request) -> web.Response:
        """Receive response."""

        # Get code from the message body
        data = await request.post()
        code = data.get("code")

        if not code:
            return web.Response(text="No code received", status=500)

        # Return redirect to the main page for sign in with a cookie
        return web.HTTPFound(
            location="/?storeToken=true",
            headers={
                # Set a cookie to enable autologin on only the specific path used
                # for the POST request, with all strict parameters set
                # This cookie should not be read by any Javascript or any other paths.
                # It can be really short lifetime as we redirect immediately (5 seconds)
                "set-cookie": "auth_oidc_code="
                + code
                + "; Path=/auth/login_flow; SameSite=Strict; HttpOnly; Max-Age=5",
            },
        )
