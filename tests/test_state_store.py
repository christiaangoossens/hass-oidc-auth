"""Tests for the state store."""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant

from custom_components.auth_oidc.stores.state_store import (
    MAX_DEVICE_CODE_ATTEMPTS,
    MAX_STATES,
    StateStore,
    client_network,
)
from custom_components.auth_oidc.tools.types import OIDCFlow, UserDetails

TEST_IP = "127.0.0.1"
TEST_FLOW: OIDCFlow = {"code_verifier": "verifier", "nonce": "nonce"}


@pytest.fixture(name="state_store")
def fixture_state_store(hass: HomeAssistant) -> StateStore:
    """Return an empty state store."""
    return StateStore(hass)


def expire(state_store: StateStore, state_id: str) -> None:
    """Let a state expire."""
    state_store.get_data()[state_id]["expiration"] = (
        datetime.now(UTC) - timedelta(minutes=10)
    ).isoformat()


def create_states(state_store: StateStore, count: int, ip: str = TEST_IP) -> list[str]:
    """Create pending states, as visits to the welcome page do."""
    return [
        state_store.create_state("https://example.com/pending", ip)
        for _ in range(count)
    ]


def make_user(sub: str) -> UserDetails:
    """Return user details for the given subject."""
    return {
        "sub": sub,
        "display_name": f"User {sub}",
        "username": sub,
        "role": "system-users",
    }


def create_device_state(state_store: StateStore) -> tuple[str, str]:
    """Create a state with a device code, as a mobile device would."""
    state_id = state_store.create_state("https://example.com/device", TEST_IP)
    code = state_store.create_device_code(state_id)
    assert code is not None

    return state_id, code


def create_ready_state(state_store: StateStore, user: UserDetails) -> str:
    """Create a state that completed the OIDC login, as the approving browser would."""
    state_id = state_store.create_state("https://example.com/browser", TEST_IP)
    assert state_store.set_userinfo_for_state(state_id, user)

    return state_id


async def test_state_store_generate_and_receive_state(state_store: StateStore):
    """Test creating a state, storing user info, and receiving it once."""
    assert state_store.get_data() == {}

    redirect_uri = "https://example.com/callback"
    state_id = state_store.create_state(redirect_uri, TEST_IP)
    assert state_id in state_store.get_data()
    assert state_store.get_redirect_uri_for_state(state_id, TEST_IP) == redirect_uri

    user = make_user("user1")
    assert state_store.set_userinfo_for_state(state_id, user) is True
    assert state_store.is_state_ready(state_id, TEST_IP) is True
    assert state_id in state_store.get_data()

    result = state_store.pop_userinfo_for_state(state_id, TEST_IP)
    assert result == user
    assert state_id not in state_store.get_data()


async def test_state_store_generate_code_and_link_state(state_store: StateStore):
    """Test generating a device code and linking another state to it."""
    user = make_user("user2")
    donor_state = create_ready_state(state_store, user)
    target_state, code = create_device_state(state_store)

    assert len(code) == 6
    assert code.isdigit()

    assert state_store.link_state_to_code(donor_state, code, TEST_IP) is True
    assert donor_state not in state_store.get_data()
    assert state_store.is_state_ready(target_state, TEST_IP) is True
    assert state_store.pop_userinfo_for_state(target_state, TEST_IP) == user
    assert target_state not in state_store.get_data()


async def test_state_store_link_state_returns_false_for_wrong_code(
    state_store: StateStore,
):
    """Test linking fails when the device code does not match any state."""
    donor_state = create_ready_state(state_store, make_user("user3"))
    target_state, code = create_device_state(state_store)
    wrong_code = "000000" if code != "000000" else "111111"

    assert state_store.link_state_to_code(donor_state, wrong_code, TEST_IP) is False
    assert donor_state in state_store.get_data()
    assert state_store.is_state_ready(target_state, TEST_IP) is False


async def test_state_store_throttles_device_code_link_attempts(
    state_store: StateStore,
):
    """Test that repeated wrong device codes are throttled per state."""
    donor_state = create_ready_state(state_store, make_user("user-throttle"))
    _, code = create_device_state(state_store)
    wrong_code = "000000" if code != "000000" else "111111"

    for _ in range(MAX_DEVICE_CODE_ATTEMPTS):
        assert state_store.link_state_to_code(donor_state, wrong_code, TEST_IP) is False

    assert state_store.link_state_to_code(donor_state, code, TEST_IP) is False


async def test_state_store_new_login_forgets_previous_user(state_store: StateStore):
    """Starting a new identity provider login on a ready state makes it not ready."""
    state_id = create_ready_state(state_store, make_user("first-user"))

    assert state_store.set_flow_for_state(state_id, TEST_FLOW, TEST_IP)

    assert state_store.is_state_ready(state_id, TEST_IP) is False


async def test_state_store_new_login_keeps_device_code_attempts(
    state_store: StateStore,
):
    """Logging in again on the same state doesn't give new device code attempts."""
    donor_state = create_ready_state(state_store, make_user("user-retry"))
    _, code = create_device_state(state_store)
    wrong_code = "000000" if code != "000000" else "111111"

    for _ in range(MAX_DEVICE_CODE_ATTEMPTS):
        state_store.link_state_to_code(donor_state, wrong_code, TEST_IP)

    assert state_store.set_flow_for_state(donor_state, TEST_FLOW, TEST_IP)
    assert state_store.set_userinfo_for_state(donor_state, make_user("user-retry"))

    assert state_store.link_state_to_code(donor_state, code, TEST_IP) is False


async def test_state_store_device_codes_are_unique(state_store: StateStore):
    """A new device code never reuses the code of another active state."""
    with patch.object(
        state_store, "_generate_code", side_effect=["111111", "111111", "222222"]
    ):
        _, first_code = create_device_state(state_store)
        _, second_code = create_device_state(state_store)

    assert first_code == "111111"
    assert second_code == "222222"


async def test_state_store_reuses_codes_of_expired_states(state_store: StateStore):
    """Codes of expired states may be handed out again."""
    with patch.object(state_store, "_generate_code", return_value="111111"):
        expired_state, _ = create_device_state(state_store)
        expire(state_store, expired_state)

        _, code = create_device_state(state_store)

    assert code == "111111"


async def test_state_store_duplicate_codes_link_nothing(state_store: StateStore):
    """Duplicate codes (from before codes were unique) are a wrong code, not an error."""
    donor_state = create_ready_state(state_store, make_user("user6"))
    first_state, code = create_device_state(state_store)
    second_state, _ = create_device_state(state_store)
    state_store.get_data()[second_state]["device_code"] = code

    assert state_store.link_state_to_code(donor_state, code, TEST_IP) is False
    assert state_store.is_state_ready(first_state, TEST_IP) is False
    assert state_store.is_state_ready(second_state, TEST_IP) is False
    assert state_store.get_data()[donor_state]["device_code_attempts"] == 1


async def test_state_store_never_relinks_a_linked_device(state_store: StateStore):
    """A device that already received a user can't be given another one."""
    victim = make_user("victim")
    target_state, code = create_device_state(state_store)
    victim_donor = create_ready_state(state_store, victim)
    assert state_store.link_state_to_code(victim_donor, code, TEST_IP)

    attacker_donor = create_ready_state(state_store, make_user("attacker"))
    assert state_store.link_state_to_code(attacker_donor, code, TEST_IP) is False

    assert state_store.pop_userinfo_for_state(target_state, TEST_IP) == victim


async def test_state_store_expired_state(state_store: StateStore):
    """Test that expired states are treated as invalid."""
    state_id = state_store.create_state("https://example.com/expired", TEST_IP)
    expire(state_store, state_id)

    assert state_store.get_redirect_uri_for_state(state_id, TEST_IP) is None
    assert state_store.is_state_ready(state_id, TEST_IP) is False
    assert state_store.pop_userinfo_for_state(state_id, TEST_IP) is None


async def test_state_store_state_is_only_valid_for_its_ip(state_store: StateStore):
    """A state is only valid for the client that created it, until it expires."""
    state_id = state_store.create_state("https://example.com/valid", TEST_IP)

    assert state_store.is_state_valid(state_id, TEST_IP)
    assert not state_store.is_state_valid(state_id, "10.0.0.1")
    assert not state_store.is_state_valid(state_id, None)
    assert not state_store.is_state_valid("unknown", TEST_IP)

    expire(state_store, state_id)
    assert not state_store.is_state_valid(state_id, TEST_IP)


async def test_state_store_keeps_states_in_memory(
    state_store: StateStore, hass: HomeAssistant, hass_storage: dict[str, Any]
):
    """Logins never write to disk."""
    state_id = state_store.create_state("https://example.com/memory", TEST_IP)
    state_store.set_userinfo_for_state(state_id, make_user("user7"))
    await hass.async_block_till_done()

    assert not [
        key for key in hass_storage if key.startswith("auth_provider.auth_oidc")
    ]


async def test_state_store_prunes_expired_states(state_store: StateStore):
    """Expired states are removed when a new state is created."""
    expired_state, kept_state = create_states(state_store, 2)
    expire(state_store, expired_state)

    new_state = state_store.create_state("https://example.com/new", TEST_IP)

    assert list(state_store.get_data()) == [kept_state, new_state]


async def test_state_store_evicts_oldest_pending_state_when_full(
    state_store: StateStore,
):
    """A full store makes room by removing the oldest pending login."""
    ready_state = create_ready_state(state_store, make_user("user8"))
    pending_states = create_states(state_store, MAX_STATES - 1)

    new_state = state_store.create_state("https://example.com/new", TEST_IP)

    assert len(state_store.get_data()) == MAX_STATES
    assert pending_states[0] not in state_store.get_data()
    assert ready_state in state_store.get_data()
    assert new_state in state_store.get_data()


async def test_state_store_evicts_oldest_ready_state_when_all_ready(
    state_store: StateStore,
):
    """Only when every login is ready, the oldest ready login is removed."""
    ready_states = [
        create_ready_state(state_store, make_user(f"user{i}"))
        for i in range(MAX_STATES)
    ]

    new_state = state_store.create_state("https://example.com/new", TEST_IP)

    assert len(state_store.get_data()) == MAX_STATES
    assert ready_states[0] not in state_store.get_data()
    assert new_state in state_store.get_data()


async def test_state_store_flood_only_evicts_its_own_logins(state_store: StateStore):
    """A flood from one IP address can't push out the pending login of another."""
    [victim_state] = create_states(state_store, 1, ip="192.168.1.10")
    flood_states = create_states(state_store, MAX_STATES * 3)

    assert victim_state in state_store.get_data()
    assert len(state_store.get_data()) == MAX_STATES
    assert flood_states[-1] in state_store.get_data()


async def test_state_store_evicts_from_the_ip_with_most_pending_logins(
    state_store: StateStore,
):
    """A full store evicts from the busiest IP address, also for a request from another IP."""
    [victim_state] = create_states(state_store, 1, ip="192.168.1.10")
    flood_states = create_states(state_store, MAX_STATES - 1)

    [new_state] = create_states(state_store, 1, ip="192.168.1.10")

    assert victim_state in state_store.get_data()
    assert new_state in state_store.get_data()
    assert flood_states[0] not in state_store.get_data()


async def test_state_store_ipv6_flood_only_evicts_its_own_logins(
    state_store: StateStore,
):
    """A flood that uses another address of its IPv6 /64 for every request is one client."""
    [victim_state] = create_states(state_store, 1, ip="2001:db8:1::10")
    for i in range(MAX_STATES * 3):
        create_states(state_store, 1, ip=f"2001:db8:2::{i:x}")

    assert victim_state in state_store.get_data()
    assert len(state_store.get_data()) == MAX_STATES


@pytest.mark.parametrize(
    ("ip", "network"),
    [
        ("192.168.1.10", "192.168.1.10"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
        ("2001:db8:1:2::1", "2001:db8:1:2::/64"),
        ("fe80::1%eth0", "fe80::/64"),
        ("::ffff:192.168.1.10", "192.168.1.10"),
        ("not-an-ip", "not-an-ip"),
        (None, None),
    ],
)
def test_client_network(ip: str | None, network: str | None):
    """IPv4 addresses count on their own, IPv6 addresses per /64."""
    assert client_network(ip) == network


async def test_state_store_never_links_expired_device(state_store: StateStore):
    """An expired device state can't receive a user, and the attempt counts."""
    donor_state = create_ready_state(state_store, make_user("user9"))
    device_state, code = create_device_state(state_store)
    expire(state_store, device_state)

    assert state_store.link_state_to_code(donor_state, code, TEST_IP) is False
    assert state_store.get_data()[device_state]["user_details"] is None
    assert state_store.get_data()[donor_state]["device_code_attempts"] == 1


async def test_state_store_never_exceeds_max_states(state_store: StateStore):
    """A flood of new logins never grows the store past its cap."""
    create_states(state_store, MAX_STATES * 3)

    assert len(state_store.get_data()) == MAX_STATES


async def test_state_store_flow_can_be_used_once(state_store: StateStore):
    """The PKCE verifier and nonce are handed out once."""
    [state_id] = create_states(state_store, 1)
    assert state_store.set_flow_for_state(state_id, TEST_FLOW, TEST_IP)

    assert state_store.pop_flow_for_state(state_id, TEST_IP) == TEST_FLOW
    assert state_store.pop_flow_for_state(state_id, TEST_IP) is None


async def test_state_store_flow_requires_valid_state(state_store: StateStore):
    """Flows are bound to an active state from the same IP."""
    assert not state_store.set_flow_for_state("missing", TEST_FLOW, TEST_IP)

    [state_id] = create_states(state_store, 1)
    assert not state_store.set_flow_for_state(state_id, TEST_FLOW, "10.0.0.1")

    assert state_store.set_flow_for_state(state_id, TEST_FLOW, TEST_IP)
    assert state_store.pop_flow_for_state(state_id, "10.0.0.1") is None

    expire(state_store, state_id)
    assert state_store.pop_flow_for_state(state_id, TEST_IP) is None


async def test_state_store_flow_is_evicted_with_its_state(state_store: StateStore):
    """An evicted state takes its flow with it, so flows are bounded too."""
    [state_id] = create_states(state_store, 1)
    state_store.set_flow_for_state(state_id, TEST_FLOW, TEST_IP)

    create_states(state_store, MAX_STATES)

    assert state_store.pop_flow_for_state(state_id, TEST_IP) is None


async def test_state_store_missing_keys(state_store: StateStore):
    """Test that missing keys raise correct responses."""
    assert state_store.create_device_code("nonexistent") is None
    assert (
        state_store.set_userinfo_for_state("nonexistent", make_user("user5")) is False
    )
