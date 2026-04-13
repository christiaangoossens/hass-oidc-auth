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

from .config.const import (
    FEATURES,
    FEATURES_AUTOMATIC_USER_LINKING,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    DEFAULT_TITLE,
)
from .stores.state_store import StateStore
from .tools.types import UserDetails

_LOGGER = logging.getLogger(__name__)

PROVIDER_TYPE = "auth_oidc"
HASS_PROVIDER_TYPE = "homeassistant"
COOKIE_NAME = "auth_oidc_state"


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
        self._state_store: StateStore | None = None
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

        # Init the store first
        # Use the same technique as the HomeAssistant auth provider for storage
        # (/auth/providers/homeassistant.py#L392)
        async with self._init_lock:
            if self._state_store is not None:
                return

            store = StateStore(self.hass)
            await store.async_load()
            self._state_store = store
            self._user_meta = {}

        # Listen for user creation events
        self.hass.bus.async_listen(EVENT_USER_ADDED, self.async_user_created)

    def _resolve_ip(self, ip: str | None = None) -> str:
        """Resolve client IP from explicit input or current request context."""
        if ip:
            return ip

        req = http.current_request.get()
        if req and req.remote:
            _LOGGER.debug("Resolved client IP from request: %s", req.remote)
            return req.remote

        return "unknown"

    async def async_create_state(self, redirect_uri: str, ip: str | None = None) -> str:
        """Create a new OIDC state and return the state id."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        return await self._state_store.async_create_state_from_url(
            redirect_uri, self._resolve_ip(ip)
        )

    async def async_generate_device_code(self, state_id: str) -> Optional[str]:
        """Generate a device code for the state, used for device login."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        return await self._state_store.async_generate_code_for_state(state_id)

    async def async_save_user_info(
        self, state_id: str, user_info: dict[str, dict | str]
    ) -> bool:
        """Save user info to the given state."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        return await self._state_store.async_add_userinfo_to_state(state_id, user_info)

    async def async_get_redirect_uri_for_state(
        self, state_id: str, ip: str | None = None
    ) -> Optional[str]:
        """Get the redirect_uri for the given state."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        return await self._state_store.async_get_redirect_uri_for_state(
            state_id, self._resolve_ip(ip)
        )

    async def async_is_state_valid(self, state_id: str, ip: str | None = None) -> bool:
        """Check if a state exists, belongs to this IP, and is not expired."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        return (
            await self._state_store.async_get_redirect_uri_for_state(
                state_id, self._resolve_ip(ip)
            )
            is not None
        )

    async def async_is_state_ready(self, state_id: str, ip: str | None = None) -> bool:
        """Check if the state has received the user info from the OIDC callback."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        return await self._state_store.async_is_state_ready(state_id, self._resolve_ip(ip))

    async def async_link_state_to_code(
        self, state_id: str, code: str, ip: str | None = None
    ) -> bool:
        """Link two states together by copying the user info from one to the other."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        return await self._state_store.async_link_state_to_code(
            state_id, code, self._resolve_ip(ip)
        )

    async def async_get_subject(self, state_id: str, ip: str | None = None) -> Optional[str]:
        """Retrieve user from the state_id, return subject and save meta
        for later use with this provider instance."""
        if self._state_store is None:
            await self.async_initialize()
            assert self._state_store is not None

        # This also deletes the state as we are using it for sign-in
        user_data = await self._state_store.async_receive_userinfo_for_state(
            state_id, self._resolve_ip(ip)
        )
        if user_data is None:
            return None

        sub = user_data["sub"]
        self._user_meta[sub] = user_data
        return sub

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

    def get_cookie_header(self, state_id: str):
        """Get the cookie header to set the state_id cookie."""
        return {
            # Set a cookie for the other pages to know the state_id
            # Keep cookie lifetime aligned with state lifetime in storage (5 minutes).
            "set-cookie": f"{COOKIE_NAME}="
            + state_id
            + "; Path=/auth/; SameSite=Strict; HttpOnly; Max-Age=300",
        }

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
            await self._async_create_person(user, user_meta.name)

    async def _async_create_person(self, user: User, name: str) -> None:
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
                "Requested automatic person creation, but person creation failed"
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

    async def _finalize_user(self, state_id: str) -> AuthFlowResult:
        # Verify a dummy hash to make it last a bit longer
        # as security measure (limits the amount of attempts you have in 5 min)
        # Similar to what the HomeAssistant auth provider does
        dummy = b"$2b$12$CiuFGszHx9eNHxPuQcwBWez4CwDTOcLTX5CbOpV6gef2nYuXkY7BO"
        bcrypt.checkpw(b"foo", dummy)

        # Actually look up the auth provider after,
        # this doesn't take a lot of time (regardless of it's in there or not)
        sub = await self._auth_provider.async_get_subject(state_id)
        if sub:
            return await self.async_finish(
                {
                    "sub": sub,
                }
            )

        raise InvalidAuthError

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the step of the form."""

        # Check if the cookie is present to login
        req = http.current_request.get()
        if req and req.cookies:
            state_cookie = req.cookies.get(COOKIE_NAME)

            if state_cookie:
                _LOGGER.debug("State cookie found on login: %s", state_cookie)
                try:
                    return await self._finalize_user(state_cookie)
                except InvalidAuthError:
                    pass

        # If no cookie is found, abort.
        # User should either be redirected or start manually on the welcome
        return self.async_abort(reason="no_oidc_cookie_found")
