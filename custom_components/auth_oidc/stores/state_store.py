"""State Store, store authentication states (redirect_uri)."""

import secrets
import random
import string

from datetime import datetime, timedelta, timezone
from typing import cast, Optional
from homeassistant.helpers.storage import Store
from homeassistant.core import HomeAssistant

from ..tools.types import OIDCState, UserDetails

STORAGE_VERSION = 1
STORAGE_KEY = "auth_provider.auth_oidc.states"

class StateStore:
    """Holds the authentication states and associated data"""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the user data store."""
        self.hass = hass
        self._store = Store[dict[str, OIDCState]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: dict[str, OIDCState] | None = None

    async def async_load(self) -> None:
        """Load stored data."""
        if (data := await self._store.async_load()) is None:
            data = cast(dict[str, OIDCState], {})
        self._data = data

    async def _async_save(self) -> None:
        """Save data."""
        if self._data is not None:
            await self._store.async_save(self._data)

    def _generate_id(self) -> str:
        """Generate a random identifier."""
        return secrets.token_urlsafe(16)

    def _generate_code(self) -> str:
        """Generate a random six-digit code."""
        return "".join(random.choices(string.digits, k=6))
    
    def _is_expired(self, state: OIDCState) -> bool:
        """Check if a state is expired."""
        return datetime.fromisoformat(state["expiration"]) < datetime.now(timezone.utc)

    async def async_create_state_from_url(self, redirect_uri: str) -> str:
        """Generates a the OIDC state adds it to the database for 5 minutes."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state_id = self._generate_id()
        expiration = datetime.now(timezone.utc) + timedelta(minutes=5)

        self._data[state_id] = {
            "id": state_id,
            "redirect_uri": redirect_uri,
            "device_code": None,
            "user_details": None,
            "expiration": expiration.isoformat(),
            "oidc_state": self._generate_id(), # Another id for verification later
        }

        await self._async_save()
        return state_id
    
    async def async_generate_code_for_state(self, state_id: str) -> Optional[str]:
        """Generates a one time code for the state to link device clients."""
        if self._data is None:
            raise RuntimeError("Data not loaded")
        
        code = self._generate_code()
        self._data[state_id]["device_code"] = code
        await self._async_save()
        return code

    async def async_add_userinfo_to_state(self, state_id: str, user_info: UserDetails):
        """Add userinfo to existing state to complete login"""
        if self._data is None:
            raise RuntimeError("Data not loaded")
        
        self._data[state_id]["user_details"] = user_info
        await self._async_save()

    async def async_get_redirect_uri_for_state(self, state_id: str) -> Optional[str]:
        """Get the redirect_uri for a given state_id."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state = self._data.get(state_id)
        if state and not self._is_expired(state):
            return state["redirect_uri"]

        return None

    async def async_receive_userinfo_for_state(self, state_id: str) -> Optional[OIDCState]:
        """Retrieve user info based on the state_id."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        user_data = self._data.get(state_id)

        if user_data:
            # We should now wipe it from the database, as it's one time use
            self._data.pop(state_id)
            await self._async_save()

        if user_data and not self._is_expired(user_data):
            return user_data["user_details"]

        return None

    def get_data(self):
        """Get the internal data for testing purposes."""
        return self._data
