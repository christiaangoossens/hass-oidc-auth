"""Callback route to return the user to after external OIDC interaction."""

from homeassistant.components.http import HomeAssistantView
from aiohttp import web
from auth_oidc.oidc_client import OIDCClient
from auth_oidc.provider import OpenIDAuthProvider
from auth_oidc.helpers import get_url

PATH = "/auth/oidc/callback"


class OIDCCallbackView(HomeAssistantView):
    """OIDC Plugin Callback View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:callback"

    def __init__(
        self, oidc_client: OIDCClient, oidc_provider: OpenIDAuthProvider
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        params = request.rel_url.query
        code = params.get("code")
        state = params.get("state")

        if not (code and state):
            return web.Response(
                headers={"content-type": "text/html"},
                text="<h1>Error</h1><p>Missing code or state parameter</p>",
            )

        redirect_uri = get_url("/auth/oidc/callback")
        user_details = await self.oidc_client.async_complete_token_flow(
            redirect_uri, code, state
        )
        if user_details is None:
            return web.Response(
                headers={"content-type": "text/html"},
                text="<h1>Error</h1><p>Failed to get user details, see console.</p>",
            )

        code = await self.oidc_provider.async_save_user_info(user_details)

        return web.HTTPFound(get_url("/auth/oidc/finish?code=" + code))
