"""OIDC Authentication provider.
Allow access to users based on login with an external OpenID Connect Identity Provider (IdP).
"""
import logging
from secrets import token_hex
from typing import Any, Dict, Optional, cast
from homeassistant.auth.providers import (
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
)
from homeassistant.exceptions import HomeAssistantError
import voluptuous as vol
from homeassistant.helpers.network import get_url

from .callback import async_register_view, AUTH_CALLBACK_PATH

_LOGGER = logging.getLogger(__name__)

class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""

@AUTH_PROVIDERS.register("oidc")
class OpenIDAuthProvider(AuthProvider):
    """Allow access to users based on login with an external OpenID Connect Identity Provider (IdP)."""

    DEFAULT_TITLE = "OpenID Connect"

    @property
    def type(self) -> str:
        return "auth_oidc"

    @property
    def support_mfa(self) -> bool:
        return False

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""

        async_register_view(self.hass)
        return OpenIdLoginFlow(self)


class OpenIdLoginFlow(LoginFlow):
    """Handler for the login flow."""

    async def async_step_init(
        self, user_input: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Handle the step of the form."""
        return await self.async_step_authenticate()

    def redirect_uri(self) -> str:
        """Return the redirect uri."""
        return f"{get_url(self.hass, require_current_request=True)}{AUTH_CALLBACK_PATH}?test=value&flow_id={self.flow_id}"

    async def async_step_authenticate(
        self, user_input: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Authenticate user using external step."""

        if user_input:
            self.external_data = str(user_input)
            return self.async_external_step_done(next_step_id="authorize")

        return self.async_external_step(step_id="authenticate", url=self.redirect_uri())

    async def async_step_authorize(
        self, user_input: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Authorize user received from external step."""
        _LOGGER.log(user_input)
        return self.async_abort(reason="invalid_auth")