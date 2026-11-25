"""Finish route to allow the user to view their code."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..stores.state_store import StateStore
from ..tools.helpers import (
    concat_url_query,
    error_response,
    get_valid_state_id,
    template_response,
)

PATH = "/auth/oidc/finish"


class OIDCFinishView(HomeAssistantView):
    """OIDC Plugin Finish View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:finish"

    def __init__(self, state_store: StateStore) -> None:
        self.state_store = state_store

    async def get(self, request: web.Request) -> web.Response:
        """Show the finish screen to pick between login & device code."""
        # Get cookie to get the state_id
        state_id = get_valid_state_id(request, self.state_store)
        if not state_id:
            return await error_response("missing_state_cookie")

        return await template_response("finish", {})

    async def post(self, request: web.Request) -> web.Response:
        """Receive response."""

        # Get cookie to get the state_id
        state_id = get_valid_state_id(request, self.state_store)
        if not state_id:
            return await error_response("missing_state_cookie")

        # Get redirect_uri from the state
        redirect_uri = self.state_store.get_redirect_uri_for_state(
            state_id, request.remote
        )

        if not redirect_uri:
            return await error_response("invalid_state")

        # Get the message body
        data = await request.post()
        device_code = data.get("device_code")

        # We are trying sign-in on this browser
        if not device_code:
            # Redirect to this new URL for login, make sure to skip OIDC to prevent loops
            redirect_uri = concat_url_query(redirect_uri, "skip_oidc_redirect=true")
            raise web.HTTPFound(location=redirect_uri)

        # Only plain form values are valid device codes, not uploaded files
        if not isinstance(device_code, str):
            return await error_response("device_link_failed")

        # Check if we can link this device
        linked = self.state_store.link_state_to_code(
            state_id, device_code, request.remote
        )

        if not linked:
            return await error_response("device_link_failed")

        return await template_response("device_success", {})
