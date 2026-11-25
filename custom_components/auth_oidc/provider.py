"""OIDC Authentication provider.
Allow access to users based on login with an external OpenID Connect Identity Provider (IdP).
"""

import logging
from collections.abc import Mapping
from ipaddress import (
    IPv4Address,
    IPv6Address,
    ip_address,
)
from typing import Any, cast

from aiohttp import web
from homeassistant.auth import EVENT_USER_ADDED
from homeassistant.auth import InvalidAuthError as HAInvalidAuthError
from homeassistant.auth.auth_store import AuthStore
from homeassistant.auth.models import (
    AuthFlowContext,
    AuthFlowResult,
    Credentials,
    User,
    UserMeta,
)
from homeassistant.auth.providers import AUTH_PROVIDERS, AuthProvider, LoginFlow
from homeassistant.components import http, person
from homeassistant.const import CONF_ID, CONF_NAME, CONF_TYPE
from homeassistant.core import HomeAssistant, callback

from .config.const import (
    DEFAULT_TITLE,
    DISPLAY_NAME,
    FEATURES,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    FEATURES_AUTOMATIC_USER_LINKING,
    FEATURES_REQUIRE_EXISTING_USER,
)
from .stores.state_store import StateStore
from .tools.helpers import get_state_id
from .tools.types import UserDetails

type IPAddress = IPv4Address | IPv6Address

_LOGGER = logging.getLogger(__name__)

PROVIDER_TYPE = "auth_oidc"
HASS_PROVIDER_TYPE = "homeassistant"


def has_login_hook() -> bool:
    """Check if Home Assistant asks providers whether their login can start (2026.11+)."""
    return hasattr(AuthProvider, "async_can_start_login")


class InvalidAuthError(HAInvalidAuthError):
    """Raised when submitting invalid authentication."""


class ExistingUserRequiredError(InvalidAuthError):
    """Raised when a new OIDC identity is not allowed to provision a user."""


# pylint: disable-next=abstract-method
class OpenIDAuthProvider(AuthProvider):
    """Allow access to users based on login with an external
    OpenID Connect Identity Provider (IdP)."""

    @property
    def support_mfa(self) -> bool:
        """Does this provider support MFA within HA? -> No we don't (the OIDC provider should)."""
        return False

    def __init__(
        self,
        hass: HomeAssistant,
        store: AuthStore,
        config: dict[str, Any],
        state_store: StateStore,
    ):
        """Initialize the OpenIDAuthProvider."""
        super().__init__(
            hass,
            store,
            {
                # Currently register as default, might be used when we have multiple OIDC providers
                CONF_ID: "default",
                # Shown on the welcome page and in Home Assistant's provider picker
                CONF_NAME: config.get(DISPLAY_NAME, DEFAULT_TITLE),
                # Type
                CONF_TYPE: PROVIDER_TYPE,
            },
        )

        self._user_meta: dict[str, UserDetails] = {}
        self._state_store = state_store

        features = config.get(
            FEATURES,
            {},
        )

        # Link users automatically?
        # False by default to always make new accounts for OIDC users
        # Turn this on to migrate from HA accounts to OIDC
        self.user_linking = features.get(FEATURES_AUTOMATIC_USER_LINKING, False)

        # Prevent provisioning new Home Assistant users?
        # Existing OIDC credentials continue to work. A first-time OIDC identity
        # can only proceed when automatic user linking finds an existing user.
        self.require_existing_user = features.get(FEATURES_REQUIRE_EXISTING_USER, False)

        # Create person entries automatically?
        # True by default to create a person for each new user (just like normal HA)
        # Turn this off if you don't want OIDC to interfere more than necessary
        self.create_persons = features.get(FEATURES_AUTOMATIC_PERSON_CREATION, True)

    async def async_initialize(self) -> None:
        """Initialize the auth provider, called once from the integration's setup."""
        self.hass.bus.async_listen(EVENT_USER_ADDED, self.async_user_created)

    def is_trusted_network_host(self) -> bool:
        """Check if the current request is coming from a trusted network host."""
        req = http.current_request.get()
        if req is None or req.remote is None:
            return False

        ip = req.remote

        # Check if trusted networks auth provider is present
        trusted_network_provider: Any = self.hass.auth.get_auth_provider(
            "trusted_networks", None
        )
        if not trusted_network_provider:
            return False

        _LOGGER.debug(
            "Trusted networks present and checking if we should OIDC redirect"
        )

        try:
            trusted_network_provider.async_validate_access(ip_address(ip))
            _LOGGER.info("IP %s is in a trusted network, skipping OIDC flow", ip)
            return True
        except HAInvalidAuthError:
            # Log the error
            _LOGGER.info(
                "IP %s is not in a trusted network, proceeding with OIDC flow", ip
            )
            return False
        # Catch every other error, HA might have changed the API.
        # pylint: disable-next=broad-except
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning(
                "Error while validating trusted network for IP %s: %s", ip, e
            )
            return False

    def can_offer_other_login(self, req: web.Request) -> bool:
        """Check if Home Assistant's login page offers another provider to this request."""
        others = [p for p in self.hass.auth.auth_providers if p is not self]

        if has_login_hook():
            # Same context as Home Assistant's /auth/providers (AuthProvidersView.get), see
            # https://github.com/home-assistant/core/blob/master/homeassistant/components/auth/login_flow.py
            context = AuthFlowContext(ip_address=ip_address(cast(str, req.remote)))
            return any(provider.async_can_start_login(context) for provider in others)

        # Before 2026.11, trusted networks is the only provider that hides itself
        return any(
            provider.type != "trusted_networks" or self.is_trusted_network_host()
            for provider in others
        )

    def is_login_ready(self) -> bool:
        """Check if the current request carries a state that finished the OIDC login.

        Used to offer OIDC on the login page only when its login can finish, as
        starting it otherwise can only show "Login aborted". Errors are caught,
        as Home Assistant would otherwise fail the whole login page.
        """
        try:
            req = http.current_request.get()
            if req is None:
                return False

            state_id = get_state_id(req)
            return state_id is not None and self._state_store.is_state_ready(
                state_id, req.remote
            )
        # pylint: disable-next=broad-except
        except Exception:
            _LOGGER.exception(
                "Could not check if the OIDC login is ready, so OIDC is hidden on the "
                "login page. Please report this as a bug"
            )
            return False

    @callback
    def async_can_start_login(self, context: AuthFlowContext) -> bool:
        """Offer OIDC only when its login can finish (Home Assistant 2026.11+)."""
        return self.is_login_ready()

    def get_subject(self, state_id: str, ip: str | None) -> str | None:
        """Retrieve user from the state_id, return subject and save meta
        for later use with this provider instance."""
        # This also deletes the state as we are using it for sign-in
        user_data = self._state_store.pop_userinfo_for_state(state_id, ip)
        if user_data is None:
            return None

        sub = user_data["sub"]
        self._user_meta[sub] = user_data
        return sub

    async def async_can_log_in(self, user_details: UserDetails) -> bool:
        """Check if this OIDC identity may log in to Home Assistant.

        With require_existing_user, it must already have a Home Assistant user,
        or be linkable to one through automatic user linking.
        """
        if not self.require_existing_user:
            return True

        sub = user_details["sub"]
        if await self._async_find_credential(sub) is not None:
            return True

        if await self._async_find_linkable_user(user_details["username"]) is not None:
            return True

        _LOGGER.warning(
            "Denied OIDC login for subject '%s': creating new Home Assistant users "
            "is disabled and no existing user could be linked.",
            sub,
        )
        return False

    async def _async_find_credential(self, sub: str) -> Credentials | None:
        """Find the credential of an OIDC identity that logged in before.

        OpenID Connect only guarantees that sub is stable, a username can change.
        """
        for credential in await self.async_credentials():
            if credential.data.get("sub") == sub:
                return credential

        return None

    async def _async_find_linkable_user(self, username: str | None) -> User | None:
        """Find the Home Assistant user to link to, only with automatic user linking.

        Keeping this lookup behind the feature flag avoids silently weakening
        the security of automatic_user_linking=False.
        """
        if not self.user_linking or not username:
            return None

        return await self._async_find_user_by_username(username)

    async def _async_find_user_by_username(self, username: str) -> User | None:
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

    async def async_user_created(self, event) -> None:
        """Handle the user created event."""
        user_id = event.data["user_id"]
        user = await self.store.async_get_user(user_id)

        # Get the first credential, if it's not ours, return
        if user is None or not user.credentials:
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
            await self._async_create_person(user, user_meta.name or "")

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
        # pylint: disable-next=broad-except
        except Exception:  # noqa: BLE001
            _LOGGER.warning(
                "Requested automatic person creation, but person creation failed"
            )

    # ====
    # Required functions for Home Assistant Auth Providers
    # ====

    async def async_login_flow(self, context: AuthFlowContext | None) -> LoginFlow:
        """Return a flow to login."""
        return OpenIdLoginFlow(self)

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        sub = flow_result["sub"]
        meta = self._user_meta.get(sub)
        if meta is None:
            raise InvalidAuthError("No OIDC user info found for this sign in")

        # Audit logging for the login that is about to occur
        _LOGGER.info(
            "Logged in user through OIDC: %s, %s", meta["sub"], meta["display_name"]
        )

        credential = await self._async_find_credential(sub)
        if credential is not None:
            return credential

        user = await self._async_find_linkable_user(meta["username"])

        # A new, unlinked credential causes Home Assistant to create a user. Reject
        # before creating the credential when provisioning has been disabled.
        # The callback already rejects these, this guards against a user removed since.
        if self.require_existing_user and user is None:
            _LOGGER.warning(
                "Denied first OIDC sign in for subject '%s': creating new Home "
                "Assistant users is disabled and no existing user could be linked.",
                sub,
            )
            raise ExistingUserRequiredError(
                "OIDC user is not linked to an existing Home Assistant user"
            )

        # If no credential was found, create a new one. Username cannot be supplied
        # here as it won't be shown by Home Assistant regardless.
        # Source: homeassistant/components/config/auth.py, line 162
        credential = self.async_create_credentials({"sub": sub})

        if user is not None:
            _LOGGER.info(
                "User already exists, adding credential for "
                + "OIDC to existing user with username '%s'.",
                meta["username"],
            )

            # Link the credential to the existing user. This sets is_new to False,
            # preventing Home Assistant from provisioning another user.
            await self.store.async_link_user(user, credential)

        # If the credential is still new, HA will automatically create a new user.
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


# Registered without the decorator form, as HA types that as returning the base class,
# which hides all OpenIDAuthProvider methods from type checkers.
AUTH_PROVIDERS.register("oidc")(OpenIDAuthProvider)


class OpenIdLoginFlow(LoginFlow[OpenIDAuthProvider]):
    """Handler for the login flow."""

    async def _finalize_user(self, state_id: str, ip: str | None) -> AuthFlowResult:
        sub = self._auth_provider.get_subject(state_id, ip)
        if sub:
            credentials = await self._auth_provider.async_get_or_create_credentials(
                {"sub": sub}
            )

            # Giving a Credential prevents calling async_get_or_create_credentials again
            # Some side-effects about MFA are irrelevant for us
            # https://github.com/home-assistant/core/blob/master/homeassistant/auth/__init__.py#L143
            return await self.async_finish(credentials)

        raise InvalidAuthError

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the step of the form."""

        # Check if the cookie is present to login
        req = http.current_request.get()
        if req:
            state_cookie = get_state_id(req)

            if state_cookie:
                try:
                    return await self._finalize_user(state_cookie, req.remote)
                except ExistingUserRequiredError:
                    # Keep the browser response generic to avoid disclosing whether
                    # a particular Home Assistant username exists.
                    return self.async_abort(reason="invalid_auth")
                except InvalidAuthError:
                    return self.async_abort(reason="oidc_cookie_invalid")

        # If no cookie is found, abort.
        # User should either be redirected or start manually on the welcome
        return self.async_abort(reason="no_oidc_cookie_found")
