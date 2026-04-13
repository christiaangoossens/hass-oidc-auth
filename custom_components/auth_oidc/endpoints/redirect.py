"""Redirect route to redirect the user to the external OIDC server,
can either be linked to directly or accessed through the welcome page."""

from urllib.parse import quote
from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..provider import OpenIDAuthProvider
from ..tools.oidc_client import OIDCClient
from ..tools.helpers import error_response, get_url, get_valid_state_id, get_view

PATH = "/auth/oidc/redirect"


class OIDCRedirectView(HomeAssistantView):
    """OIDC Plugin Redirect View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:redirect"

    def __init__(
        self,
        oidc_client: OIDCClient,
        oidc_provider: OpenIDAuthProvider,
        force_https: bool,
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider
        self.force_https = force_https

    async def get(self, req: web.Request) -> web.Response:
        """Receive response."""

        # Get cookie to get the state_id
        state_id = await get_valid_state_id(req, self.oidc_provider)

        if not state_id:
            # Direct access to the redirect endpoint, go to welcome page instead
            welcome_url = get_url("/auth/oidc/welcome", self.force_https)
            raise web.HTTPFound(welcome_url)

        try:
            redirect_uri = get_url("/auth/oidc/callback", self.force_https)
            auth_url = await self.oidc_client.async_get_authorization_url(
                redirect_uri, state_id
            )

            if auth_url:
                view_html = await get_view("redirect", {"url": quote(auth_url)})
                return web.Response(text=view_html, content_type="text/html")
        except RuntimeError:
            pass

        return await error_response(
            "Integration is misconfigured, discovery could not be obtained.",
            status=500,
        )

    async def post(self, req: web.Request) -> web.Response:
        """POST"""
        return await self.get(req)
