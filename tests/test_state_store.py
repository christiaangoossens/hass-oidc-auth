"""Tests for the state store."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.core import HomeAssistant

from auth_oidc.stores.state_store import StateStore

TEST_IP = "127.0.0.1"


@pytest.mark.asyncio
async def test_state_store_generate_and_receive_state(hass: HomeAssistant):
    """Test creating a state, storing user info, and receiving it once."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        state_store = StateStore(hass)

        store_mock.async_load.return_value = {}
        await state_store.async_load()
        assert state_store.get_data() == {}

        redirect_uri = "https://example.com/callback"
        state_id = await state_store.async_create_state_from_url(redirect_uri, TEST_IP)
        assert state_id in state_store.get_data()
        assert (
            await state_store.async_get_redirect_uri_for_state(state_id, TEST_IP)
            == redirect_uri
        )

        user_info = {
            "sub": "user1",
            "display_name": "Test User",
            "username": "testuser",
            "role": "system-users",
        }
        assert (
            await state_store.async_add_userinfo_to_state(state_id, user_info) is True
        )
        assert state_id in state_store.get_data()
        assert await state_store.async_is_state_ready(state_id, TEST_IP) is True
        assert state_id in state_store.get_data()

        result = await state_store.async_receive_userinfo_for_state(state_id, TEST_IP)
        assert result == user_info
        assert state_id not in state_store.get_data()


@pytest.mark.asyncio
async def test_state_store_generate_code_and_link_state(hass: HomeAssistant):
    """Test generating a device code and linking another state to it."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        state_store = StateStore(hass)

        store_mock.async_load.return_value = {}
        await state_store.async_load()

        donor_state = await state_store.async_create_state_from_url(
            "https://example.com/donor", TEST_IP
        )
        target_state = await state_store.async_create_state_from_url(
            "https://example.com/target", TEST_IP
        )

        code = await state_store.async_generate_code_for_state(target_state)
        assert code is not None
        assert len(code) == 6
        assert code.isdigit()

        user_info = {
            "sub": "user2",
            "display_name": "Device User",
            "username": "deviceuser",
            "role": "system-admin",
        }
        assert (
            await state_store.async_add_userinfo_to_state(donor_state, user_info)
            is True
        )
        assert donor_state in state_store.get_data()

        assert (
            await state_store.async_link_state_to_code(donor_state, code, TEST_IP)
            is True
        )
        assert donor_state not in state_store.get_data()
        assert await state_store.async_is_state_ready(target_state, TEST_IP) is True
        assert target_state in state_store.get_data()
        assert (
            await state_store.async_receive_userinfo_for_state(target_state, TEST_IP)
            == user_info
        )
        assert target_state not in state_store.get_data()


@pytest.mark.asyncio
async def test_state_store_link_state_returns_false_for_wrong_code(hass: HomeAssistant):
    """Test linking fails when the device code does not match any state."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        state_store = StateStore(hass)

        store_mock.async_load.return_value = {}
        await state_store.async_load()

        donor_state = await state_store.async_create_state_from_url(
            "https://example.com/donor", TEST_IP
        )
        target_state = await state_store.async_create_state_from_url(
            "https://example.com/target", TEST_IP
        )
        await state_store.async_generate_code_for_state(target_state)

        user_info = {
            "sub": "user3",
            "display_name": "Wrong Code User",
            "username": "wrongcode",
            "role": "system-users",
        }
        assert (
            await state_store.async_add_userinfo_to_state(donor_state, user_info)
            is True
        )

        assert (
            await state_store.async_link_state_to_code(donor_state, "000000", TEST_IP)
            is False
        )
        assert donor_state in state_store.get_data()
        assert await state_store.async_is_state_ready(target_state, TEST_IP) is False


@pytest.mark.asyncio
async def test_state_store_expired_state(hass: HomeAssistant):
    """Test that expired states are treated as invalid."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        state_store = StateStore(hass)

        store_mock.async_load.return_value = {}
        await state_store.async_load()

        state_id = await state_store.async_create_state_from_url(
            "https://example.com/expired", TEST_IP
        )
        state_store.get_data()[state_id]["expiration"] = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat()

        assert (
            await state_store.async_get_redirect_uri_for_state(state_id, TEST_IP)
            is None
        )
        assert await state_store.async_is_state_ready(state_id, TEST_IP) is False
        assert (
            await state_store.async_receive_userinfo_for_state(state_id, TEST_IP)
            is None
        )


@pytest.mark.asyncio
async def test_state_store_data_not_loaded(hass: HomeAssistant):
    """Test that using the store before loading raises RuntimeError."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        state_store = StateStore(hass)

        with pytest.raises(RuntimeError):
            await state_store.async_create_state_from_url(
                "https://example.com", TEST_IP
            )
        with pytest.raises(RuntimeError):
            await state_store.async_generate_code_for_state("state")
        with pytest.raises(RuntimeError):
            await state_store.async_add_userinfo_to_state(
                "state",
                {
                    "sub": "user4",
                    "display_name": "Not Loaded",
                    "username": "notloaded",
                    "role": "system-users",
                },
            )
        with pytest.raises(RuntimeError):
            await state_store.async_get_redirect_uri_for_state("state", TEST_IP)
        with pytest.raises(RuntimeError):
            await state_store.async_is_state_ready("state", TEST_IP)
        with pytest.raises(RuntimeError):
            await state_store.async_link_state_to_code("state", "123456", TEST_IP)
        with pytest.raises(RuntimeError):
            await state_store.async_receive_userinfo_for_state("state", TEST_IP)


@pytest.mark.asyncio
async def test_state_store_missing_keys(hass: HomeAssistant):
    """Test that missing keys raise correct responses."""
    store_mock = AsyncMock()
    with patch("homeassistant.helpers.storage.Store", return_value=store_mock):
        state_store = StateStore(hass)

        # async_generate_code_for_state returns None if state_id is not found
        store_mock.async_load.return_value = {}
        await state_store.async_load()
        assert await state_store.async_generate_code_for_state("nonexistent") is None

        # async_add_userinfo_to_state returns False if state_id is not found
        user_info = {
            "sub": "user5",
            "display_name": "Missing Keys",
            "username": "missingkeys",
            "role": "system-users",
        }
        assert (
            await state_store.async_add_userinfo_to_state("nonexistent", user_info)
            is False
        )
