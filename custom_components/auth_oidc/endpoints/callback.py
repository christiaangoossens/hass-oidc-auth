"""Callback route to return the user to after external OIDC interaction."""

import logging
from homeassistant.components.http import HomeAssistantView
from aiohttp import web
import jwt
from ..oidc_client import OIDCClient
from ..provider import OpenIDAuthProvider
from ..helpers import get_url, get_view

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
        force_https: bool,
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider
        self.force_https = force_https

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
                },
            )
            return web.Response(text=view_html, content_type="text/html")

        redirect_uri = get_url("/auth/oidc/callback", self.force_https)
        user_details = await self.oidc_client.async_complete_token_flow(
            redirect_uri, code, state
        )
        if user_details is None:
            view_html = await get_view(
                "error",
                {
                    "error": "Failed to get user details, "
                    + "see Home Assistant logs for more information.",
                },
            )
            return web.Response(text=view_html, content_type="text/html")

        if user_details.get("role") == "invalid":
            view_html = await get_view(
                "error",
                {
                    "error": "User is not in the correct group to access Home Assistant, "
                    + "contact your administrator!",
                },
            )
            return web.Response(text=view_html, content_type="text/html")

        code = await self.oidc_provider.async_save_user_info(user_details)

        if state.startswith("jwt-"):
            # There is a suffix attached to the state
            jwt_token = state[4:]
            _LOGGER.debug("JWT Token: %s", jwt_token)

            try:
                contents = jwt.decode(
                    jwt_token,
                    options={"verify_signature": False},
                )

                hass_client_id = contents.get("client_id", "")
                hass_callback_uri = contents.get("callback_uri", "")
                _LOGGER.debug("Hass client ID: %s", hass_client_id)
                _LOGGER.debug("Hass callback URI: %s", hass_callback_uri)

                # If the callback starts with homeassistant://, we assume it is a mobile app
                if hass_callback_uri.startswith("homeassistant://"):
                    return await self.login_mobile_app(
                        hass_client_id, hass_callback_uri, user_details
                    )
            except jwt.DecodeError:
                view_html = await get_view(
                    "error",
                    {
                        "error": "Invalid state",
                    },
                )
                return web.Response(text=view_html, content_type="text/html")

        # Redirect to the finish page with the code to show both options
        # (options = copy code externally or use the cookie method to sign in)
        return web.HTTPFound(
            get_url("/auth/oidc/finish?code=" + code, self.force_https)
        )

    async def login_mobile_app(
        self, hass_client_id: str, hass_callback_uri: str, user_details: dict
    ) -> web.Response:
        """Handle login for mobile app."""
        view_html = await get_view(
            "error",
            {
                "error": "Mobile signin not implemented yet, "
                + hass_callback_uri
                + " - "
                + hass_client_id,
            },
        )
        _LOGGER.debug(
            "Got user_details, we should implement mobile login: %s ", user_details
        )
        return web.Response(text=view_html, content_type="text/html")
