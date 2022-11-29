from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant, callback
import logging

DATA_VIEW_REGISTERED = "oauth2_view_reg"
AUTH_CALLBACK_PATH = "/auth/oidc/callback"

_LOGGER = logging.getLogger(__name__)

@callback
def async_register_view(hass: HomeAssistant) -> None:
    """Make sure callback view is registered."""
    if not hass.data.get(DATA_VIEW_REGISTERED, False):
        hass.http.register_view(OAuth2AuthorizeCallbackView())  # type: ignore
        hass.data[DATA_VIEW_REGISTERED] = True


class OAuth2AuthorizeCallbackView(HomeAssistantView):
    """OAuth2 Authorization Callback View."""

    requires_auth = False
    url = AUTH_CALLBACK_PATH
    name = "auth:oidc:callback"

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""

        _LOGGER.debug(request.query)

        hass = request.app["hass"]
        flow_mgr = hass.auth.login_flow

        await flow_mgr.async_configure(
            flow_id=request.query["flow_id"], user_input=request.query["test"]
        )

        return web.Response(
            headers={"content-type": "text/html"},
            text="<script>if (window.opener) { window.opener.postMessage({type: 'externalCallback'}); } window.close();</script>",
        )