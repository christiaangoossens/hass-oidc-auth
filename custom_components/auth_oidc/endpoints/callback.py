from aiohttp import web
from homeassistant.components.http import HomeAssistantView
import logging
from ..oidc_client import OIDCClient
from ..provider import OpenIDAuthProvider

PATH = "/auth/oidc/callback"

_LOGGER = logging.getLogger(__name__)

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

        _LOGGER.debug("Callback view accessed")

        params = request.rel_url.query
        code = params.get("code")
        state = params.get("state")
        base_uri = str(request.url).split('/auth', 2)[0]

        if not (code and state):
            return web.Response(
                headers={"content-type": "text/html"},
                text="<h1>Error</h1><p>Missing code or state parameter</p>",
            )

        user_details = await self.oidc_client.complete_token_flow(base_uri, code, state)
        if user_details is None:
            return web.Response(
                headers={"content-type": "text/html"},
                text="<h1>Error</h1><p>Failed to get user details, see console.</p>",
            )

        code = await self.oidc_provider.save_user_info(user_details)

        return web.HTTPFound(base_uri + "/auth/oidc/finish?code=" + code)