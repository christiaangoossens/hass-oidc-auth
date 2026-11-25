"""State Store, keeps the authentication states (redirect_uri) in memory."""

import secrets
import string
from datetime import UTC, datetime, timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from ..tools.types import OIDCState, UserDetails

# States used to be saved to disk, this file is removed on startup
LEGACY_STORAGE_KEY = "auth_provider.auth_oidc.states"

STATE_TTL = timedelta(minutes=5)
MAX_STATES = 100
MAX_DEVICE_CODE_ATTEMPTS = 10


class StateStore:
    """Holds the authentication states and associated data"""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the state store."""
        self.hass = hass
        self._data: dict[str, OIDCState] = {}

    async def async_remove_legacy_storage(self) -> None:
        """Remove the states file that older versions saved to disk."""
        await Store(self.hass, 1, LEGACY_STORAGE_KEY, private=True).async_remove()

    def _generate_id(self) -> str:
        """Generate a random identifier."""
        return secrets.token_urlsafe(32)

    def _generate_code(self) -> str:
        """Generate a random six-digit code."""
        return "".join(secrets.choice(string.digits) for _ in range(6))

    def _generate_unique_code(self) -> str:
        """Generate a six-digit code that no active state uses."""
        in_use = {
            state["device_code"]
            for state in self._data.values()
            if not self._is_expired(state)
        }

        while (code := self._generate_code()) in in_use:
            continue

        return code

    def _is_expired(self, state: OIDCState) -> bool:
        """Check if a state is expired."""
        return datetime.fromisoformat(state["expiration"]) < datetime.now(UTC)

    def _is_valid(self, state: OIDCState, ip: str | None) -> bool:
        """Check if a state is valid"""
        return (
            not self._is_expired(state)
            and bool(state["redirect_uri"])
            and ip is not None
            and state["ip_address"] == ip
        )

    def _make_room(self) -> None:
        """Remove expired states, then the oldest states until there is room for one more.

        Pending logins are removed first. Only a real login at the identity provider
        makes a state ready, so a flood of new logins can't push those out.
        """
        for state_id in [
            state_id
            for state_id, state in self._data.items()
            if self._is_expired(state)
        ]:
            del self._data[state_id]

        while len(self._data) >= MAX_STATES:
            # Dicts keep insertion order, so the first match is the oldest state
            oldest_pending = next(
                (
                    state_id
                    for state_id, state in self._data.items()
                    if state["user_details"] is None
                ),
                None,
            )
            del self._data[oldest_pending or next(iter(self._data))]

    async def async_create_state_from_url(
        self, redirect_uri: str, ip: str | None
    ) -> str:
        """Create a new state for the redirect_uri, valid for STATE_TTL."""
        self._make_room()

        state_id = self._generate_id()
        self._data[state_id] = {
            "id": state_id,
            "redirect_uri": redirect_uri,
            "device_code": None,
            "device_code_attempts": 0,
            "user_details": None,
            "expiration": (datetime.now(UTC) + STATE_TTL).isoformat(),
            "ip_address": ip,
        }

        return state_id

    async def async_generate_code_for_state(self, state_id: str) -> str | None:
        """Generates a one time code for the state to link device clients."""
        state = self._data.get(state_id)
        if state is None:
            return None

        state["device_code"] = self._generate_unique_code()
        return state["device_code"]

    async def async_add_userinfo_to_state(
        self, state_id: str, user_info: UserDetails
    ) -> bool:
        """Add userinfo to existing state to complete login"""
        state = self._data.get(state_id)
        if state is None:
            return False

        state["user_details"] = user_info
        return True

    async def async_get_redirect_uri_for_state(
        self, state_id: str, ip: str | None
    ) -> str | None:
        """Get the redirect_uri for a given state_id."""
        state = self._data.get(state_id)
        if state and self._is_valid(state, ip):
            return state["redirect_uri"]

        return None

    async def async_is_state_ready(self, state_id: str, ip: str | None) -> bool:
        """Check if the state has received the user info from the OIDC callback."""
        state = self._data.get(state_id)
        return (
            state is not None
            and state["user_details"] is not None
            and self._is_valid(state, ip)
        )

    async def async_link_state_to_code(
        self, state_id: str, code: str, ip: str | None
    ) -> bool:
        """Link a state to a device code, used for mobile sign-in."""
        state_data = self._data.get(state_id)
        if (
            not state_data
            or not self._is_valid(state_data, ip)
            or state_data["user_details"] is None
        ):
            return False

        attempts = state_data["device_code_attempts"]
        if attempts >= MAX_DEVICE_CODE_ATTEMPTS:
            return False

        # Only a device that is still waiting can be linked, never one that already has a user
        matching_states = [
            state
            for state in self._data.values()
            if state["device_code"] == code
            and state["user_details"] is None
            and not self._is_expired(state)
        ]

        # Codes are unique, so anything but exactly one match is a wrong code
        if len(matching_states) != 1:
            state_data["device_code_attempts"] = attempts + 1
            return False

        # Give the device state the user details, and delete the one time use donor state
        matching_states[0]["user_details"] = state_data["user_details"]
        del self._data[state_id]

        return True

    async def async_receive_userinfo_for_state(
        self, state_id: str, ip: str | None
    ) -> UserDetails | None:
        """Retrieve user info based on the state_id, the state can only be used once."""
        state = self._data.pop(state_id, None)
        if state and self._is_valid(state, ip):
            return state["user_details"]

        return None

    def get_data(self) -> dict[str, OIDCState]:
        """Get the internal data for testing purposes."""
        return self._data
