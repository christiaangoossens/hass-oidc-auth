"""Callback route to return the user to after external OIDC interaction."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..provider import OpenIDAuthProvider
from ..tools.helpers import error_response, get_url, get_valid_state_id
from ..tools.oidc_client import OIDCClient

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

    async def get(self, request: web.Request) -> web.Response:  # pylint: disable=too-many-return-statements
        """Receive response."""

        # Get cookie to get the state_id
        state_id = await get_valid_state_id(request, self.oidc_provider)
        if not state_id:
            return await error_response("missing_state_cookie")

        # Get the OIDC query parameters
        params = request.rel_url.query
        code = params.get("code")
        state = params.get("state")

        # If the provider returned an OAuth error (for example access_denied),
        # surface the provider error instead of the misleading missing code or
        # state message. The error view still offers the retry link.
        if params.get("error"):
            error_description = params.get("error_description", params.get("error"))
            return await error_response(
                "oidc_error", status=400, message=error_description
            )

        if not (code and state):
            return await error_response("missing_code_or_state")

        # Check if the states match
        if state != state_id:
            return await error_response("state_mismatch")

        # Complete the OIDC flow to get user details
        redirect_uri = get_url("/auth/oidc/callback", self.force_https)
        user_details = await self.oidc_client.async_complete_token_flow(
            redirect_uri, code, state
        )
        if user_details is None:
            return await error_response("user_details_failed", status=500)

        if user_details.get("role") == "invalid":
            return await error_response("user_not_in_group", status=403)

        # Finalize on the state
        success = await self.oidc_provider.async_save_user_info(state_id, user_details)
        if not success:
            return await error_response("save_user_info_failed", status=500)

        raise web.HTTPFound(get_url("/auth/oidc/finish", self.force_https))
