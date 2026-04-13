"""Callback route to return the user to after external OIDC interaction."""

from homeassistant.components.http import HomeAssistantView
from aiohttp import web
from ..tools.oidc_client import OIDCClient
from ..provider import OpenIDAuthProvider
from ..tools.helpers import error_response, get_state_id, get_url

PATH = "/auth/oidc/callback"


class OIDCCallbackView(HomeAssistantView):
    """OIDC Plugin Callback View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:callback"

    def __init__(
        self,
        oidc_client: OIDCClient,
        oidc_provider: OpenIDAuthProvider,
        force_https: bool,
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider
        self.force_https = force_https

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        # Get cookie to get the state_id
        state_id = get_state_id(request)
        if not state_id:
            return await error_response("Missing state cookie, please restart login.")

        # Get the OIDC query parameters
        params = request.rel_url.query
        code = params.get("code")
        state = params.get("state")

        if not (code and state):
            return await error_response("Missing code or state parameter.")

        # Check if the states match
        if state != state_id:
            return await error_response(
                "State parameter does not match, possible CSRF attack."
            )

        # Complete the OIDC flow to get user details
        redirect_uri = get_url("/auth/oidc/callback", self.force_https)
        user_details = await self.oidc_client.async_complete_token_flow(
            redirect_uri, code, state
        )
        if user_details is None:
            return await error_response(
                "Failed to get user details, see Home Assistant logs for more information.",
                status=500,
            )

        if user_details.get("role") == "invalid":
            return await error_response(
                "User is not in the correct group to access Home Assistant, "
                + "contact your administrator!",
                status=403,
            )

        # Finalize on the state
        success = await self.oidc_provider.async_save_user_info(state_id, user_details)
        if not success:
            return await error_response(
                "Failed to save user information, session probably expired. Please sign in again.",
                status=500,
            )

        raise web.HTTPFound(get_url("/auth/oidc/finish", self.force_https))
