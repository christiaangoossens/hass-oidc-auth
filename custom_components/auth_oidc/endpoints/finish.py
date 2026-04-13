"""Finish route to allow the user to view their code."""

from homeassistant.components.http import HomeAssistantView
from aiohttp import web
from ..provider import OpenIDAuthProvider
from ..tools.helpers import (
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

    def __init__(
        self,
        oidc_provider: OpenIDAuthProvider,
    ) -> None:
        self.oidc_provider = oidc_provider

    async def get(self, request: web.Request) -> web.Response:
        """Show the finish screen to pick between login & device code."""
        # Get cookie to get the state_id
        state_id = await get_valid_state_id(request, self.oidc_provider)
        if not state_id:
            return await error_response("Missing state cookie, please restart login.")

        return await template_response("finish", {})

    async def post(self, request: web.Request) -> web.Response:
        """Receive response."""

        # Get cookie to get the state_id
        state_id = await get_valid_state_id(request, self.oidc_provider)
        if not state_id:
            return await error_response("Missing state cookie, please restart login.")

        # Get redirect_uri from the state
        redirect_uri = await self.oidc_provider.async_get_redirect_uri_for_state(
            state_id
        )

        if not redirect_uri:
            return await error_response("Invalid state, please restart login.")

        # Get the message body
        data = await request.post()
        device_code = data.get("device_code")

        # We are trying sign-in on this browser
        if not device_code:
            # Add to the URL correctly (also handle case where it's just the root)
            separator = "?"
            if "?" in redirect_uri:
                separator = "&"

            # Redirect to this new URL for login
            new_url = (
                redirect_uri + separator + "storeToken=true&skip_oidc_redirect=true"
            )
            raise web.HTTPFound(location=new_url)

        # Check if we can link this device
        linked = await self.oidc_provider.async_link_state_to_code(
            state_id, device_code
        )

        if not linked:
            return await error_response(
                "Failed to link state to device code, please restart login."
            )

        return await template_response("device_success", {})
