"""Welcome route to show the user the OIDC login button and give instructions."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from ..helpers import get_view

PATH = "/auth/oidc/welcome"


class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:welcome"

    def __init__(self, name: str) -> None:
        self.name = name

    async def get(self, _: web.Request) -> web.Response:
        """Receive response."""
        view_html = await get_view("welcome", {"name": self.name})
        return web.Response(text=view_html, content_type="text/html")
