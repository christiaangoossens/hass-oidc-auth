"""State Store, keeps the authentication states (redirect_uri) in memory."""

import secrets
import string
from collections import Counter
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Network, ip_address

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from ..tools.types import OIDCFlow, OIDCState, UserDetails

# States used to be saved to disk, this file is removed on startup
LEGACY_STORAGE_KEY = "auth_provider.auth_oidc.states"

STATE_TTL = timedelta(minutes=5)
MAX_STATES = 100
MAX_DEVICE_CODE_ATTEMPTS = 10


def client_network(ip: str | None) -> str | None:
    """Return the addresses one client controls: its IPv4 address, or its IPv6 /64.

    Providers hand out a whole IPv6 /64 per customer, so a client can send every
    request from another address in it.
    """
    if ip is None:
        return None

    try:
        address = ip_address(ip)
    except ValueError:
        return ip

    if isinstance(address, IPv4Address):
        return str(address)

    if address.ipv4_mapped:
        return str(address.ipv4_mapped)

    return str(IPv6Network((int(address), 64), strict=False))


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
        """Remove expired states, then evict states until there is room for one more."""
        for state_id in [
            state_id
            for state_id, state in self._data.items()
            if self._is_expired(state)
        ]:
            del self._data[state_id]

        while len(self._data) >= MAX_STATES:
            del self._data[self._choose_eviction()]

    def _choose_eviction(self) -> str:
        """Return the state to remove from a full store.

        The oldest pending login of the client with the most pending logins goes first,
        so a flood from one client only pushes out its own logins. Ready logins need a
        real login at the identity provider, so they only go when all are ready.
        """
        # Dicts keep insertion order, so the first match is the oldest state
        pending = [
            (state_id, client_network(state["ip_address"]))
            for state_id, state in self._data.items()
            if state["user_details"] is None
        ]
        if not pending:
            return next(iter(self._data))

        busiest, _ = Counter(network for _, network in pending).most_common(1)[0]
        return next(state_id for state_id, network in pending if network == busiest)

    def create_state(self, redirect_uri: str, ip: str | None) -> str:
        """Create a new state for the redirect_uri, valid for STATE_TTL."""
        self._make_room()

        state_id = self._generate_id()
        self._data[state_id] = {
            "id": state_id,
            "redirect_uri": redirect_uri,
            "device_code": None,
            "device_code_attempts": 0,
            "user_details": None,
            "flow": None,
            "expiration": (datetime.now(UTC) + STATE_TTL).isoformat(),
            "ip_address": ip,
        }

        return state_id

    def create_device_code(self, state_id: str) -> str | None:
        """Generates a one time code for the state to link device clients."""
        state = self._data.get(state_id)
        if state is None:
            return None

        state["device_code"] = self._generate_unique_code()
        return state["device_code"]

    def set_flow_for_state(self, state_id: str, flow: OIDCFlow, ip: str | None) -> bool:
        """Store the PKCE code verifier and nonce on the state.

        This starts a new identity provider login, so a user from an
        earlier login on this state is forgotten."""
        state = self._data.get(state_id)
        if state is None or not self._is_valid(state, ip):
            return False

        state["flow"] = flow
        state["user_details"] = None
        return True

    def pop_flow_for_state(self, state_id: str, ip: str | None) -> OIDCFlow | None:
        """Retrieve the PKCE code verifier and nonce of the state, they can only be used once."""
        state = self._data.get(state_id)
        if state is None or not self._is_valid(state, ip):
            return None

        flow, state["flow"] = state["flow"], None
        return flow

    def set_userinfo_for_state(self, state_id: str, user_info: UserDetails) -> bool:
        """Add userinfo to existing state to complete login"""
        state = self._data.get(state_id)
        if state is None:
            return False

        state["user_details"] = user_info
        return True

    def get_redirect_uri_for_state(self, state_id: str, ip: str | None) -> str | None:
        """Get the redirect_uri for a given state_id."""
        state = self._data.get(state_id)
        if state and self._is_valid(state, ip):
            return state["redirect_uri"]

        return None

    def is_state_valid(self, state_id: str, ip: str | None) -> bool:
        """Check if a state exists, belongs to this IP, and is not expired."""
        state = self._data.get(state_id)
        return state is not None and self._is_valid(state, ip)

    def is_state_ready(self, state_id: str, ip: str | None) -> bool:
        """Check if the state has received the user info from the OIDC callback."""
        state = self._data.get(state_id)
        return (
            state is not None
            and state["user_details"] is not None
            and self._is_valid(state, ip)
        )

    def link_state_to_code(self, state_id: str, code: str, ip: str | None) -> bool:
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

    def pop_userinfo_for_state(
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
