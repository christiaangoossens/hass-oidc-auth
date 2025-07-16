"""Redirect route to redirect the user to the external OIDC server,
can either be linked to directly or accessed through the welcome page."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..oidc_client import OIDCClient
from ..helpers import get_url, get_view

PATH = "/auth/oidc/redirect"


class OIDCRedirectView(HomeAssistantView):
    """OIDC Plugin Redirect View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:redirect"

    def __init__(self, oidc_client: OIDCClient, force_https: bool) -> None:
        self.oidc_client = oidc_client
        self.force_https = force_https

    async def get(self, _: web.Request) -> web.Response:
        """Receive response."""

        redirect_uri = get_url("/auth/oidc/callback", self.force_https)
        auth_url = await self.oidc_client.async_get_authorization_url(redirect_uri)

        if auth_url:
            return web.HTTPFound(auth_url)

        view_html = await get_view(
            "error",
            {"error": "Integration is misconfigured, discovery could not be obtained."},
        )
        return web.Response(text=view_html, content_type="text/html")

    async def post(self, request: web.Request) -> web.Response:
        """POST"""
        return await self.get(request)
