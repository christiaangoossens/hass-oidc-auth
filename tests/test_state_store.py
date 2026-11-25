"""Tests for the state store."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant

from custom_components.auth_oidc.stores.state_store import (
    MAX_DEVICE_CODE_ATTEMPTS,
    StateStore,
)
from custom_components.auth_oidc.tools.types import OIDCState, UserDetails

TEST_IP = "127.0.0.1"


@pytest.fixture
async def state_store(hass: HomeAssistant) -> StateStore:
    """Return a loaded, empty state store."""
    store = StateStore(hass)
    await store.async_load()

    return store


def get_states(state_store: StateStore) -> dict[str, OIDCState]:
    """Return the states of a loaded store."""
    data = state_store.get_data()
    assert data is not None

    return data


def make_user(sub: str) -> UserDetails:
    """Return user details for the given subject."""
    return {
        "sub": sub,
        "display_name": f"User {sub}",
        "username": sub,
        "role": "system-users",
    }


async def create_device_state(state_store: StateStore) -> tuple[str, str]:
    """Create a state with a device code, as a mobile device would."""
    state_id = await state_store.async_create_state_from_url(
        "https://example.com/device", TEST_IP
    )
    code = await state_store.async_generate_code_for_state(state_id)
    assert code is not None

    return state_id, code


async def create_ready_state(state_store: StateStore, user: UserDetails) -> str:
    """Create a state that completed the OIDC login, as the approving browser would."""
    state_id = await state_store.async_create_state_from_url(
        "https://example.com/browser", TEST_IP
    )
    assert await state_store.async_add_userinfo_to_state(state_id, user)

    return state_id


async def test_state_store_generate_and_receive_state(state_store: StateStore):
    """Test creating a state, storing user info, and receiving it once."""
    assert get_states(state_store) == {}

    redirect_uri = "https://example.com/callback"
    state_id = await state_store.async_create_state_from_url(redirect_uri, TEST_IP)
    assert state_id in get_states(state_store)
    assert (
        await state_store.async_get_redirect_uri_for_state(state_id, TEST_IP)
        == redirect_uri
    )

    user = make_user("user1")
    assert await state_store.async_add_userinfo_to_state(state_id, user) is True
    assert await state_store.async_is_state_ready(state_id, TEST_IP) is True
    assert state_id in get_states(state_store)

    result = await state_store.async_receive_userinfo_for_state(state_id, TEST_IP)
    assert result == user
    assert state_id not in get_states(state_store)


async def test_state_store_generate_code_and_link_state(state_store: StateStore):
    """Test generating a device code and linking another state to it."""
    user = make_user("user2")
    donor_state = await create_ready_state(state_store, user)
    target_state, code = await create_device_state(state_store)

    assert len(code) == 6
    assert code.isdigit()

    assert (
        await state_store.async_link_state_to_code(donor_state, code, TEST_IP) is True
    )
    assert donor_state not in get_states(state_store)
    assert await state_store.async_is_state_ready(target_state, TEST_IP) is True
    assert (
        await state_store.async_receive_userinfo_for_state(target_state, TEST_IP)
        == user
    )
    assert target_state not in get_states(state_store)


async def test_state_store_link_state_returns_false_for_wrong_code(
    state_store: StateStore,
):
    """Test linking fails when the device code does not match any state."""
    donor_state = await create_ready_state(state_store, make_user("user3"))
    target_state, code = await create_device_state(state_store)
    wrong_code = "000000" if code != "000000" else "111111"

    assert (
        await state_store.async_link_state_to_code(donor_state, wrong_code, TEST_IP)
        is False
    )
    assert donor_state in get_states(state_store)
    assert await state_store.async_is_state_ready(target_state, TEST_IP) is False


async def test_state_store_throttles_device_code_link_attempts(
    state_store: StateStore,
):
    """Test that repeated wrong device codes are throttled per state."""
    donor_state = await create_ready_state(state_store, make_user("user-throttle"))
    _, code = await create_device_state(state_store)
    wrong_code = "000000" if code != "000000" else "111111"

    for _ in range(MAX_DEVICE_CODE_ATTEMPTS):
        assert (
            await state_store.async_link_state_to_code(donor_state, wrong_code, TEST_IP)
            is False
        )

    assert (
        await state_store.async_link_state_to_code(donor_state, code, TEST_IP) is False
    )


async def test_state_store_device_codes_are_unique(state_store: StateStore):
    """A new device code never reuses the code of another active state."""
    with patch.object(
        state_store, "_generate_code", side_effect=["111111", "111111", "222222"]
    ):
        _, first_code = await create_device_state(state_store)
        _, second_code = await create_device_state(state_store)

    assert first_code == "111111"
    assert second_code == "222222"


async def test_state_store_reuses_codes_of_expired_states(state_store: StateStore):
    """Codes of expired states may be handed out again."""
    with patch.object(state_store, "_generate_code", return_value="111111"):
        expired_state, _ = await create_device_state(state_store)
        get_states(state_store)[expired_state]["expiration"] = (
            datetime.now(UTC) - timedelta(minutes=10)
        ).isoformat()

        _, code = await create_device_state(state_store)

    assert code == "111111"


async def test_state_store_duplicate_codes_link_nothing(state_store: StateStore):
    """Duplicate codes (from before codes were unique) are a wrong code, not an error."""
    donor_state = await create_ready_state(state_store, make_user("user6"))
    first_state, code = await create_device_state(state_store)
    second_state, _ = await create_device_state(state_store)
    get_states(state_store)[second_state]["device_code"] = code

    assert (
        await state_store.async_link_state_to_code(donor_state, code, TEST_IP) is False
    )
    assert await state_store.async_is_state_ready(first_state, TEST_IP) is False
    assert await state_store.async_is_state_ready(second_state, TEST_IP) is False
    assert get_states(state_store)[donor_state]["device_code_attempts"] == 1


async def test_state_store_never_relinks_a_linked_device(state_store: StateStore):
    """A device that already received a user can't be given another one."""
    victim = make_user("victim")
    target_state, code = await create_device_state(state_store)
    victim_donor = await create_ready_state(state_store, victim)
    assert await state_store.async_link_state_to_code(victim_donor, code, TEST_IP)

    attacker_donor = await create_ready_state(state_store, make_user("attacker"))
    assert (
        await state_store.async_link_state_to_code(attacker_donor, code, TEST_IP)
        is False
    )

    assert (
        await state_store.async_receive_userinfo_for_state(target_state, TEST_IP)
        == victim
    )


async def test_state_store_expired_state(state_store: StateStore):
    """Test that expired states are treated as invalid."""
    state_id = await state_store.async_create_state_from_url(
        "https://example.com/expired", TEST_IP
    )
    get_states(state_store)[state_id]["expiration"] = (
        datetime.now(UTC) - timedelta(minutes=10)
    ).isoformat()

    assert await state_store.async_get_redirect_uri_for_state(state_id, TEST_IP) is None
    assert await state_store.async_is_state_ready(state_id, TEST_IP) is False
    assert await state_store.async_receive_userinfo_for_state(state_id, TEST_IP) is None


async def test_state_store_data_not_loaded(hass: HomeAssistant):
    """Test that using the store before loading raises RuntimeError."""
    state_store = StateStore(hass)

    with pytest.raises(RuntimeError):
        await state_store.async_create_state_from_url("https://example.com", TEST_IP)
    with pytest.raises(RuntimeError):
        await state_store.async_generate_code_for_state("state")
    with pytest.raises(RuntimeError):
        await state_store.async_add_userinfo_to_state("state", make_user("user4"))
    with pytest.raises(RuntimeError):
        await state_store.async_get_redirect_uri_for_state("state", TEST_IP)
    with pytest.raises(RuntimeError):
        await state_store.async_is_state_ready("state", TEST_IP)
    with pytest.raises(RuntimeError):
        await state_store.async_link_state_to_code("state", "123456", TEST_IP)
    with pytest.raises(RuntimeError):
        await state_store.async_receive_userinfo_for_state("state", TEST_IP)


async def test_state_store_missing_keys(state_store: StateStore):
    """Test that missing keys raise correct responses."""
    assert await state_store.async_generate_code_for_state("nonexistent") is None
    assert (
        await state_store.async_add_userinfo_to_state("nonexistent", make_user("user5"))
        is False
    )
