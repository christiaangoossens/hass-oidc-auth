"""OIDC Provider"""
from __future__ import annotations

from collections.abc import Mapping
import hmac
from typing import Any, cast

import voluptuous as vol

from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from homeassistant.auth.providers import (
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
)

from homeassistant.auth.models import Credentials, UserMeta

class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


@AUTH_PROVIDERS.register("insecure_example_2")
class ExampleAuthProvider(AuthProvider):
    """Example auth provider based on hardcoded usernames and passwords."""

    DEFAULT_TITLE = "OpenID Connect (SSO)"

    @property
    def type(self) -> str:
        return "auth_oidc"

    @property
    def support_mfa(self) -> bool:
        """OIDC Authentication Provider does not support MFA in Home Assistant, only external."""
        return False

    async def async_login_flow(self) -> LoginFlow:
        """Return a flow to login."""
        return ExampleLoginFlow(self)

    @callback
    def async_validate_login(self, input: str) -> None:
        """Validate a username and password."""
        
        if input is "example":
            return
        else:
            raise InvalidAuthError

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        username = flow_result["input"]

        for credential in await self.async_credentials():
            if credential.data["input"] == username:
                return credential

        # Create new credentials.
        return self.async_create_credentials({"username": username})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.
        Will be used to populate info when creating a new user.
        """
        username = credentials.data["username"]
        name = None

        for user in self.config["users"]:
            if user["username"] == username:
                name = user.get("name")
                break

        return UserMeta(name=name, is_active=True)


class ExampleLoginFlow(LoginFlow):
    """Handler for the login flow."""

    async def async_step_init(
        self, user_input: dict[str] | None = None
    ) -> FlowResult:
        """Handle the step of the form."""
        errors = None

        if user_input is not None:
            try:
                cast(ExampleAuthProvider, self._auth_provider).async_validate_login(
                    user_input["input"]
                )
            except InvalidAuthError:
                errors = {"base": "invalid_auth"}

            if not errors:
                return await self.async_finish(user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required("input"): str,
                }
            ),
            errors=errors,
        )