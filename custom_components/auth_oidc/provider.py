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
    Credentials,
    UserMeta,
)
from homeassistant.exceptions import HomeAssistantError
import voluptuous as vol
from datetime import datetime, timedelta
import random
import string
from homeassistant.helpers.storage import Store
from collections.abc import Mapping

_LOGGER = logging.getLogger(__name__)

class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""

@AUTH_PROVIDERS.register("oidc")
class OpenIDAuthProvider(AuthProvider):
    """Allow access to users based on login with an external OpenID Connect Identity Provider (IdP)."""

    DEFAULT_TITLE = "OpenID Connect (SSO)"

    def __init__(self, *args, **kwargs):
        """Initialize the OpenIDAuthProvider."""
        super().__init__(*args, **kwargs)
        self._user_meta = {}

    @property
    def type(self) -> str:
        return "auth_oidc"

    @property
    def support_mfa(self) -> bool:
        return False
        
    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""
        return OpenIdLoginFlow(self)
    
    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        username = flow_result["username"]
        for credential in await self.async_credentials():
            if credential.data["username"] == username:
                return credential

        # Create new credentials.
        return self.async_create_credentials({"username": username})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Currently, supports name, group and local_only.
        """
        meta = self._user_meta.get(credentials.data["username"], {})
        groups = meta.get("groups", [])

        group = "system-admin" if "admins" in groups else "system-users"
        return UserMeta(
            name=meta.get("name"),
            is_active=True,
            group=group,
            local_only="true",
        )
        
    async def save_user_info(self, user_info: dict) -> str:
        """Save user info during login."""
        _LOGGER.info("User info to be saved: %s", user_info)

        code = self._generate_code()
        expiration = datetime.utcnow() + timedelta(minutes=5)
        user_data = {
            "user_info": user_info,
            "code": code,
            "expiration": expiration.isoformat()
        }

        await self._save_to_db(self._get_code_key(code), user_data)
        return code
        
    async def async_retrieve_username(self, code: str) -> Optional[dict]:
        """Retrieve user info based on the code."""
        user_data = await self._get_from_db(self._get_code_key(code))
        await self._wipe_from_db(self._get_code_key(code))

        if user_data and datetime.fromisoformat(user_data["expiration"]) > datetime.utcnow():
            username = user_data["user_info"]["preferred_username"]
            self._user_meta[username] = user_data["user_info"]
            return username
        return None
        
    def _generate_code(self) -> str:
        """Generate a random six-digit code."""
        return ''.join(random.choices(string.digits, k=6))
    
    def _get_code_key(self, code: str) -> str:
        return f"provider_oidc_auth_user_{code}"

    async def _save_to_db(self, key: str, value: dict) -> None:
        """Save key-value data to the Home Assistant storage."""
        store = Store(self.hass, 1, key)
        await store.async_save(value)

    async def _get_from_db(self, key: str) -> Optional[dict]:
        """Retrieve key-value data from the Home Assistant storage."""
        store = Store(self.hass, 1, key)
        return await store.async_load()

    async def _wipe_from_db(self, key: str) -> None:
        """Delete key-value data from the Home Assistant storage."""
        store = Store(self.hass, 1, key)
        return await store.async_remove()


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

        username = await self._auth_provider.async_retrieve_username(user_input["code"])
        if username:
            _LOGGER.info("Logged in user: %s", username)
            
            return await self.async_finish({
                "username": username,
            })

        return self.async_abort(reason="invalid_code")