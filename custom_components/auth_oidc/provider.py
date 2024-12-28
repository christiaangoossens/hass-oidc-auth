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
    User,
    AuthStore,
)
from homeassistant.const import CONF_ID, CONF_NAME, CONF_TYPE
from homeassistant.core import HomeAssistant
from homeassistant.components import http
from homeassistant.exceptions import HomeAssistantError
import voluptuous as vol

from .stores.code_store import CodeStore
from .types import UserDetails

_LOGGER = logging.getLogger(__name__)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


@AUTH_PROVIDERS.register("oidc")
class OpenIDAuthProvider(AuthProvider):
    """Allow access to users based on login with an external
    OpenID Connect Identity Provider (IdP)."""

    DEFAULT_TITLE = "OpenID Connect (SSO)"

    @property
    def support_mfa(self) -> bool:
        return False

    def __init__(self, hass: HomeAssistant, store: AuthStore, config: dict[str, str]):
        """Initialize the OpenIDAuthProvider."""
        super().__init__(
            hass,
            store,
            {
                # Currently register as default, might be used when we have multiple OIDC providers
                CONF_ID: "default",
                # Name displayed in the UI
                CONF_NAME: config.get("display_name", self.DEFAULT_TITLE),
                # Type
                CONF_TYPE: "auth_oidc",
            },
        )

        self._user_meta: dict[UserDetails] = {}
        self._code_store: CodeStore | None = None
        self._init_lock = asyncio.Lock()

        self.user_linking = config.get("user_linking", False)

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

    async def async_get_subject(self, code: str) -> Optional[str]:
        """Retrieve user from the code, return subject and save meta
        for later use with this provider instance."""
        if self._code_store is None:
            await self.async_initialize()
            assert self._code_store is not None

        user_data = await self._code_store.receive_userinfo_for_code(code)
        if user_data is None:
            return None

        sub = user_data["sub"]
        self._user_meta[sub] = user_data
        return sub

    async def async_save_user_info(self, user_info: dict[str, dict | str]) -> str:
        """Save user info and return a code."""
        if self._code_store is None:
            await self.async_initialize()
            assert self._code_store is not None

        return await self._code_store.async_generate_code_for_userinfo(user_info)

    async def _async_find_user_by_username(self, username: str) -> Optional[User]:
        """Find a user by username."""
        users = await self.store.async_get_users()
        for user in users:
            # System generated users don't have usernames and aren't our target here
            if user.system_generated:
                continue

            # Check if we have a homeassistant credential with the provided username
            for credential in user.credentials:
                if (
                    credential.auth_provider_type == "homeassistant"
                    and credential.data.get("username") == username
                ):
                    return user

        return None

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
        sub = flow_result["sub"]
        meta = self._user_meta.get(sub)

        # Audit logging for the login that is about to occur
        _LOGGER.info(
            "Logged in user through OIDC: %s, %s", meta["sub"], meta["display_name"]
        )

        # Iterate over previously created credentials to find one with the same sub
        for credential in await self.async_credentials():
            # When logging in again, use the subject to check if the credential exist
            # OpenID spec says that sub is the only claim we can rely on, as username
            # might change over time.
            if credential.data.get("sub") == sub:
                return credential

        # If no credential was found, create a new one
        # Username cannot be supplied here as it won't be shown by Home Assistant regardless
        # Source: homeassistant/components/config/auth.py, line 162
        credential = self.async_create_credentials({"sub": sub})

        # If we have user linking enabled, try to link the user here
        if self.user_linking:
            user = await self._async_find_user_by_username(meta["username"])
            if user is not None:
                _LOGGER.info(
                    "User already exists, adding credential for "
                    + "OIDC to existing user with username '%s'.",
                    meta["username"],
                )

                # Link the credential to the existing user
                # Will set the credential isNew = false
                await self.store.async_link_user(user, credential)

        # If the credential is new, HA will automatically create a new user for us
        return credential

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Currently, supports name, is_active, group and local_only.
        """

        sub = credentials.data["sub"]
        meta = self._user_meta.get(sub, {})

        groups = meta.get("groups", [])

        # TODO: Allow setting which group is for admins
        group = "system-admin" if "admins" in groups else "system-users"
        return UserMeta(
            name=meta.get("display_name"),
            is_active=True,
            group=group,
            local_only=False,
        )


class OpenIdLoginFlow(LoginFlow):
    """Handler for the login flow."""

    async def _finalize_user(self, code: str) -> AuthFlowResult:
        sub = await self._auth_provider.async_get_subject(code)
        if sub:
            return await self.async_finish(
                {
                    "sub": sub,
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
