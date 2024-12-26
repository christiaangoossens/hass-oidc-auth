from aiohttp import web
from homeassistant.components.http import HomeAssistantView
import logging

from ..oidc_client import OIDCClient
from ..helpers import get_url

PATH = "/auth/oidc/redirect"

_LOGGER = logging.getLogger(__name__)

class OIDCRedirectView(HomeAssistantView):
    """OIDC Plugin Redirect View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:redirect"

    def __init__(
        self, oidc_client: OIDCClient
    ) -> None:
        self.oidc_client = oidc_client

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        _LOGGER.debug("Redirect view accessed")


        redirect_uri = get_url("/auth/oidc/callback")
        auth_url = await self.oidc_client.async_get_authorization_url(redirect_uri)

        if auth_url:
            return web.HTTPFound(auth_url)
        else:
            return web.Response(
            headers={"content-type": "text/html"},
            text="<h1>Plugin is misconfigured, discovery could not be obtained</h1>",
        )

    async def post(self, request: web.Request) -> web.Response:
        """POST"""

        _LOGGER.debug("Redirect POST view accessed")
        return await self.get(request)