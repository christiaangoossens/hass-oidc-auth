"""Code Store, stores the codes and their associated authenticated user temporarily."""

import random
import string

from datetime import datetime, timedelta
from typing import cast, Optional
from homeassistant.helpers.storage import Store
from homeassistant.core import HomeAssistant

from ..types import UserDetails

STORAGE_VERSION = 1
STORAGE_KEY = "auth_provider.auth_oidc.codes"


class CodeStore:
    """Holds the codes and associated data"""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the user data store."""
        self.hass = hass
        self._store = Store[dict[str, UserDetails]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: dict[str, dict[str, dict | str]] | None = None

    async def async_load(self) -> None:
        """Load stored data."""
        if (data := await self._store.async_load()) is None:
            data = cast(dict[str, UserDetails], {})
        self._data = data

    async def async_save(self) -> None:
        """Save data."""
        if self._data is not None:
            await self._store.async_save(self._data)

    def _generate_code(self) -> str:
        """Generate a random six-digit code."""
        return "".join(random.choices(string.digits, k=6))

    async def async_generate_code_for_userinfo(self, user_info: UserDetails) -> str:
        """Generates a one time code and adds it to the database for 5 minutes."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        code = self._generate_code()
        expiration = datetime.utcnow() + timedelta(minutes=5)

        self._data[code] = {
            "user_info": user_info,
            "code": code,
            "expiration": expiration.isoformat(),
        }

        await self.async_save()
        return code

    async def receive_userinfo_for_code(self, code: str) -> Optional[UserDetails]:
        """Retrieve user info based on the code."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        user_data = self._data.get(code)

        if user_data:
            # We should now wipe it from the database, as it's one time use code
            self._data.pop(code)
            await self.async_save()

        if (
            user_data
            and datetime.fromisoformat(user_data["expiration"]) > datetime.utcnow()
        ):
            return user_data["user_info"]

        return None
