"""OIDC Authentication provider.
Allow access to users based on login with an external OpenID Connect Identity Provider (IdP).
"""

import logging

from typing import Dict, Optional
import asyncio
from homeassistant.auth.providers import (
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
    AuthFlowResult,
    Credentials,
    UserMeta,
)
from homeassistant.components import http
from homeassistant.exceptions import HomeAssistantError
import voluptuous as vol

from .stores.code_store import CodeStore

_LOGGER = logging.getLogger(__name__)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


@AUTH_PROVIDERS.register("oidc")
class OpenIDAuthProvider(AuthProvider):
    """Allow access to users based on login with an external
    OpenID Connect Identity Provider (IdP)."""

    DEFAULT_TITLE = "OpenID Connect (SSO)"

    @property
    def type(self) -> str:
        return "auth_oidc"

    @property
    def support_mfa(self) -> bool:
        return False

    def __init__(self, *args, **kwargs):
        """Initialize the OpenIDAuthProvider."""
        super().__init__(*args, **kwargs)
        self._user_meta = {}
        self._code_store: CodeStore | None = None
        self._init_lock = asyncio.Lock()

    async def async_initialize(self) -> None:
        """Initialize the auth provider."""

        # Init the code store first
        # Use the same technique as the HomeAssistant auth provider for storage
        # (/auth/providers/homeassistant.py#L392)
        async with self._init_lock:
            if self._code_store is not None:
                return

            store = CodeStore(self.hass)
            await store.async_load()
            self._code_store = store
            self._user_meta = {}

    async def async_retrieve_username(self, code: str) -> Optional[str]:
        """Retrieve user from the code, return username and save meta
        for later use with this provider instance."""
        if self._code_store is None:
            await self.async_initialize()
            assert self._code_store is not None

        user_data = await self._code_store.receive_userinfo_for_code(code)
        if user_data is None:
            return None

        username = user_data["username"]
        self._user_meta[username] = user_data
        return username

    async def async_save_user_info(self, user_info: dict[str, dict | str]) -> str:
        """Save user info and return a code."""
        if self._code_store is None:
            await self.async_initialize()
            assert self._code_store is not None

        return await self._code_store.async_generate_code_for_userinfo(user_info)

    # ====
    # Required functions for Home Assistant Auth Providers
    # ====

    async def async_login_flow(self, context: Optional[Dict]) -> LoginFlow:
        """Return a flow to login."""
        return OpenIdLoginFlow(self)

    async def async_get_or_create_credentials(
        self, flow_result: dict[str, str]
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

        Currently, supports name, is_active, group and local_only.
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


class OpenIdLoginFlow(LoginFlow):
    """Handler for the login flow."""

    async def _finalize_user(self, code: str) -> AuthFlowResult:
        username = await self._auth_provider.async_retrieve_username(code)
        if username:
            _LOGGER.info("Logged in user: %s", username)
            return await self.async_finish(
                {
                    "username": username,
                }
            )

        raise InvalidAuthError

    def _show_login_form(
        self, errors: Optional[dict[str, str]] = None
    ) -> AuthFlowResult:
        if errors is None:
            errors = {}

        # Show the login form
        # Abuses the MFA form, as it works better for our usecase
        # UI suggestions are welcome (make a PR!)
        return self.async_show_form(
            step_id="mfa",
            data_schema=vol.Schema(
                {
                    vol.Required("code"): str,
                }
            ),
            errors=errors,
        )

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the step of the form."""

        # Try to use the user input first
        if user_input is not None:
            try:
                return await self._finalize_user(user_input["code"])
            except InvalidAuthError:
                return self._show_login_form({"base": "invalid_auth"})

        # If not available, check the cookie
        req = http.current_request.get()
        code_cookie = req.cookies.get("auth_oidc_code")

        if code_cookie:
            _LOGGER.debug("Code cookie found on login: %s", code_cookie)
            try:
                return await self._finalize_user(code_cookie)
            except InvalidAuthError:
                pass

        # If none are available, just show the form
        return self._show_login_form()

    async def async_step_mfa(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        # This is a dummy step function just to use the nicer MFA UI instead
        return await self.async_step_init(user_input)
