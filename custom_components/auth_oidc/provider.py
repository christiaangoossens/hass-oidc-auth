"""OIDC Authentication provider.
Allow access to users based on login with an external OpenID Connect Identity Provider (IdP).
"""
import logging
from typing import Dict, Optional
from homeassistant.auth.providers import (
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
    AuthFlowResult,
)
from homeassistant.exceptions import HomeAssistantError
import voluptuous as vol

_LOGGER = logging.getLogger(__name__)

class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""

@AUTH_PROVIDERS.register("oidc")
class OpenIDAuthProvider(AuthProvider):
    """Allow access to users based on login with an external OpenID Connect Identity Provider (IdP)."""

    DEFAULT_TITLE = "OpenID Connect (SSO)"

    @property
    def type(self) -> str:
        return "auth_oidc"

    @property
    def support_mfa(self) -> bool:
        return False

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""
        return OpenIdLoginFlow(self)


class OpenIdLoginFlow(LoginFlow):
    """Handler for the login flow."""

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the step of the form."""

        # Show the login form
        # Currently, this form looks bad because the frontend gives no options to make it look better
        # We will investigate options to make it look better in the future
        return self.async_show_form(
            step_id="mfa",
            data_schema=vol.Schema(
            {
                vol.Required("code"): str,
            }
            ),
            errors={},
        )
    

    async def async_step_mfa(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the result of the form."""

        if user_input is None:
            return self.async_abort(reason="no_code_given")

        # Log
        _LOGGER.info("User input %s", user_input)
        _LOGGER.info("Code %s was entered", user_input["code"])
        return self.async_abort(reason="invalid_code")