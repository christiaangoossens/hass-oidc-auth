"""Callback route to return the user to after external OIDC interaction."""

from homeassistant.components.http import HomeAssistantView
from aiohttp import web
from ..oidc_client import OIDCClient
from ..provider import OpenIDAuthProvider
from ..helpers import get_url, get_view

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
            view_html = await get_view(
                "error",
                {
                    "error": "Missing code or state parameter.",
                    "link": get_url("/auth/oidc/redirect"),
                },
            )
            return web.Response(text=view_html, content_type="text/html")

        redirect_uri = get_url("/auth/oidc/callback")
        user_details = await self.oidc_client.async_complete_token_flow(
            redirect_uri, code, state
        )
        if user_details is None:
            view_html = await get_view(
                "error",
                {
                    "error": "Failed to get user details, "
                    + "see Home Assistant logs for more information.",
                    "link": get_url("/auth/oidc/redirect"),
                },
            )
            return web.Response(text=view_html, content_type="text/html")

        code = await self.oidc_provider.async_save_user_info(user_details)
        return web.HTTPFound(get_url("/auth/oidc/finish?code=" + code))
