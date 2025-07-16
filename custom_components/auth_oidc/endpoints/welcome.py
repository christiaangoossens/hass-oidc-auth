"""Welcome route to show the user the OIDC login button and give instructions."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from ..helpers import get_url, get_view

PATH = "/auth/oidc/welcome"


class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:welcome"

    def __init__(self, name: str, is_enabled: bool, force_https: bool) -> None:
        self.name = name
        self.is_enabled = is_enabled
        self.force_https = force_https

    async def get(self, _: web.Request) -> web.Response:
        """Receive response."""

        if not self.is_enabled:
            return web.HTTPTemporaryRedirect(get_url("/", self.force_https))

        view_html = await get_view("welcome", {"name": self.name})
        return web.Response(text=view_html, content_type="text/html")
