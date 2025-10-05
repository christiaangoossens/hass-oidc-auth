"""Tests for the code store"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from homeassistant.core import HomeAssistant

import pytest

from auth_oidc.stores.code_store import CodeStore


@pytest.mark.asyncio
async def test_code_store_generate_and_receive_code(hass: HomeAssistant):
    """Test generating and receiving a code."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        code_store = CodeStore(hass)

        # Simulate loading with empty data
        store_mock.async_load.return_value = {}
        await code_store.async_load()
        assert code_store.get_data() == {}

        user_info = {"sub": "user1", "name": "Test User"}
        code = await code_store.async_generate_code_for_userinfo(user_info)
        assert code in code_store.get_data()

        # Should return user_info and remove the code
        with patch("custom_components.auth_oidc.stores.code_store.datetime") as dt_mock:
            dt_mock.utcnow.return_value = datetime.now(timezone.utc)
            dt_mock.fromisoformat.side_effect = datetime.fromisoformat
            result = await code_store.receive_userinfo_for_code(code)
            assert result == user_info
            assert code not in code_store.get_data()


@pytest.mark.asyncio
async def test_code_store_expired_code(hass):
    """Test that expired codes return None."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        code_store = CodeStore(hass)
        store_mock.async_load.return_value = {}
        await code_store.async_load()
        assert code_store.get_data() == {}

        user_info = {"sub": "user2", "name": "Expired User"}
        code = await code_store.async_generate_code_for_userinfo(user_info)

        # Patch expiration to be in the past
        code_store.get_data()[code]["expiration"] = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat()

        with patch("custom_components.auth_oidc.stores.code_store.datetime") as dt_mock:
            dt_mock.utcnow.return_value = datetime.now(timezone.utc)
            dt_mock.fromisoformat.side_effect = datetime.fromisoformat
            result = await code_store.receive_userinfo_for_code(code)
            assert result is None
            assert code not in code_store.get_data()


@pytest.mark.asyncio
async def test_code_store_data_not_loaded(hass):
    """Test that using the store before loading raises RuntimeError."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        code_store = CodeStore(hass)

        # Data is not loaded yet, should result in RuntimeError

        with pytest.raises(RuntimeError):
            await code_store.async_generate_code_for_userinfo({"sub": "user3"})
        with pytest.raises(RuntimeError):
            await code_store.receive_userinfo_for_code("123456")


@pytest.mark.asyncio
async def test_code_store_generate_code_length(hass):
    """Test that generated codes are 6 digits."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        code_store = CodeStore(hass)
        store_mock.async_load.return_value = {}
        await code_store.async_load()
        assert code_store.get_data() == {}
        user_info = {"sub": "user4"}
        code = await code_store.async_generate_code_for_userinfo(user_info)
        assert len(code) == 6
        assert code.isdigit()
