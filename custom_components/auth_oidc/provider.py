"""OIDC Authentication provider.
Allow access to users based on login with an external OpenID Connect Identity Provider (IdP).
"""

import logging

from typing import Dict, Optional
import asyncio
import bcrypt
from homeassistant.auth import EVENT_USER_ADDED
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
from homeassistant.core import HomeAssistant, callback
from homeassistant.components import http, person
from homeassistant.exceptions import HomeAssistantError
import voluptuous as vol

from .config import (
    FEATURES,
    FEATURES_AUTOMATIC_USER_LINKING,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    DEFAULT_TITLE,
)
from .stores.code_store import CodeStore
from .types import UserDetails

_LOGGER = logging.getLogger(__name__)

PROVIDER_TYPE = "auth_oidc"
HASS_PROVIDER_TYPE = "homeassistant"


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


@AUTH_PROVIDERS.register("oidc")
class OpenIDAuthProvider(AuthProvider):
    """Allow access to users based on login with an external
    OpenID Connect Identity Provider (IdP)."""

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
                CONF_NAME: config.get("display_name", DEFAULT_TITLE),
                # Type
                CONF_TYPE: PROVIDER_TYPE,
            },
        )

        self._user_meta: dict[UserDetails] = {}
        self._code_store: CodeStore | None = None
        self._init_lock = asyncio.Lock()

        features = config.get(
            FEATURES,
            {},
        )

        # Link users automatically?
        # False by default to always make new accounts for OIDC users
        # Turn this on to migrate from HA accounts to OIDC
        self.user_linking = features.get(FEATURES_AUTOMATIC_USER_LINKING, False)

        # Create person entries automatically?
        # True by default to create a person for each new user (just like normal HA)
        # Turn this off if you don't want OIDC to interfere more than necessary
        self.create_persons = features.get(FEATURES_AUTOMATIC_PERSON_CREATION, True)

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

        # Listen for user creation events
        self.hass.bus.async_listen(EVENT_USER_ADDED, self.async_user_created)

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
                    credential.auth_provider_type == HASS_PROVIDER_TYPE
                    and credential.data.get("username") == username
                ):
                    return user

        return None

    # ====
    # Handler for user created and related functions (person creation)
    # ====

    @callback
    async def async_user_created(self, event) -> None:
        """Handle the user created event."""
        user_id = event.data["user_id"]
        user = await self.store.async_get_user(user_id)

        # Get the first credential, if it's not ours, return
        if not user.credentials or len(user.credentials) == 0:
            return

        credential = user.credentials[0]
        if not (
            credential.auth_provider_type == self.type
            and credential.auth_provider_id == self.id
        ):
            # Not mine, return
            return

        # Audit log the user creation
        _LOGGER.info(
            "User was created for first OIDC sign in: %s from subject %s",
            user.id,
            credential.data["sub"],
        )

        # If person creation is enabled, add a person for this user
        if self.create_persons:
            user_meta = await self.async_user_meta_for_credentials(credential)
            await self.async_create_person(user, user_meta.name)

    async def async_create_person(self, user: User, name: str) -> None:
        """Create a person for the user."""
        _LOGGER.info("Automatically creating person for new user %s", user.id)

        # Create a person for the user
        try:
            await person.async_create_person(
                hass=self.hass,
                name=name,
                user_id=user.id,
            )
        # Catch all, we don't want to fail here
        # pylint: disable=broad-exception-caught
        except Exception:
            _LOGGER.warning(
                "Requested automatic person creation, but person creation failed."
            )
        # pylint: enable=broad-exception-caught

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

        role = meta.get("role")
        return UserMeta(
            name=meta.get("display_name"),
            is_active=True,
            group=role,
            local_only=False,
        )


class OpenIdLoginFlow(LoginFlow):
    """Handler for the login flow."""

    async def _finalize_user(self, code: str) -> AuthFlowResult:
        # Verify a dummy hash to make it last a bit longer
        # as security measure (limits the amount of attempts you have in 5 min)
        # Similar to what the HomeAssistant auth provider does
        dummy = b"$2b$12$CiuFGszHx9eNHxPuQcwBWez4CwDTOcLTX5CbOpV6gef2nYuXkY7BO"
        bcrypt.checkpw(b"foo", dummy)

        # Actually look up the auth provider after,
        # this doesn't take a lot of time (regardless of it's in there or not)
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
