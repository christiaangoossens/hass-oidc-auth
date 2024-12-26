"""Redirect route to redirect the user to the external OIDC server,
can either be linked to directly or accessed through the welcome page."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from auth_oidc.oidc_client import OIDCClient
from auth_oidc.helpers import get_url

PATH = "/auth/oidc/redirect"


class OIDCRedirectView(HomeAssistantView):
    """OIDC Plugin Redirect View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:redirect"

    def __init__(self, oidc_client: OIDCClient) -> None:
        self.oidc_client = oidc_client

    async def get(self) -> web.Response:
        """Receive response."""

        redirect_uri = get_url("/auth/oidc/callback")
        auth_url = await self.oidc_client.async_get_authorization_url(redirect_uri)

        if auth_url:
            return web.HTTPFound(auth_url)

        return web.Response(
            headers={"content-type": "text/html"},
            text="<h1>Plugin is misconfigured, discovery could not be obtained</h1>",
        )

    async def post(self) -> web.Response:
        """POST"""
        return await self.get()
