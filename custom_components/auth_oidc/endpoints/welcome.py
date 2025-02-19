"""Welcome route to show the user the OIDC login button and give instructions."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from ..helpers import get_view


class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False

    def __init__(self, name: str, path: str) -> None:
        self.name = name
        self.url = path
        self.name = "auth:oidc:welcome"

    async def get(self, _: web.Request) -> web.Response:
        """Receive response."""
        view_html = await get_view("welcome", {"name": self.name})
        return web.Response(text=view_html, content_type="text/html")
