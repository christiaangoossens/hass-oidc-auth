"""Callback route to return the user to after external OIDC interaction."""

import logging

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..provider import OpenIDAuthProvider
from ..stores.state_store import StateStore
from ..tools.helpers import error_response, get_url, get_valid_state_id
from ..tools.oidc_client import OIDCClient

PATH = "/auth/oidc/callback"

_LOGGER = logging.getLogger(__name__)


class OIDCCallbackView(HomeAssistantView):
    """OIDC Plugin Callback View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:callback"

    def __init__(
        self,
        oidc_client: OIDCClient,
        oidc_provider: OpenIDAuthProvider,
        state_store: StateStore,
        force_https: bool,
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider
        self.state_store = state_store
        self.force_https = force_https

    async def get(self, request: web.Request) -> web.Response:  # pylint: disable=too-many-return-statements
        """Receive response."""

        # Get cookie to get the state_id
        state_id = get_valid_state_id(request, self.state_store)
        if not state_id:
            return await error_response("missing_state_cookie")

        # Get the OIDC query parameters
        params = request.rel_url.query
        code = params.get("code")
        state = params.get("state")

        error = params.get("error")
        description = params.get("error_description")
        if error:
            _LOGGER.warning(
                "Identity provider returned error %r: %r", error, description
            )

        # The state is still valid from here on, so errors keep the cookie and
        # "Try again" restarts the login with the original redirect_uri.

        # Both codes and errors from the identity provider carry our state
        # (RFC 6749 Section 4.1.2 and 4.1.2.1). Checking it first means a
        # crafted link can't show its own error text on this page.
        if not state:
            return await error_response("missing_code_or_state", reset_cookie=False)

        if state != state_id:
            return await error_response("state_mismatch", reset_cookie=False)

        # Show the identity provider's error (for example access_denied)
        # instead of the misleading missing code message
        if error:
            return await error_response(
                "oidc_error",
                placeholders={"description": description or error},
                reset_cookie=False,
            )

        if not code:
            return await error_response("missing_code_or_state", reset_cookie=False)

        # The flow is only there if this state was sent to the identity provider.
        # Going back to an earlier callback leaves the login itself intact.
        flow = self.state_store.pop_flow_for_state(state_id, request.remote)
        if flow is None:
            return await error_response("invalid_state", reset_cookie=False)

        # Complete the OIDC flow to get user details
        redirect_uri = get_url("/auth/oidc/callback", self.force_https)
        user_details = await self.oidc_client.async_complete_token_flow(
            redirect_uri, code, flow
        )
        if user_details is None:
            return await error_response(
                "user_details_failed", status=500, reset_cookie=False
            )

        if user_details.get("role") == "invalid":
            return await error_response(
                "user_not_in_group", status=403, reset_cookie=False
            )

        # Reject here, as Home Assistant's login page can only say "Login aborted"
        if not await self.oidc_provider.async_can_log_in(user_details):
            return await error_response(
                "user_not_allowed", status=403, reset_cookie=False
            )

        # Finalize on the state
        success = self.state_store.set_userinfo_for_state(state_id, user_details)
        if not success:
            return await error_response("save_user_info_failed", status=500)

        raise web.HTTPFound(get_url("/auth/oidc/finish", self.force_https))
