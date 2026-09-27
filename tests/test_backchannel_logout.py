"""Unit tests for the OIDC back-channel logout token validator."""

import base64
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.setup import async_setup_component
from joserfc import jwk, jwt
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.config.const import (
    BACKCHANNEL_LOGOUT_EVENT,
    DISCOVERY_URL,
)
from custom_components.auth_oidc.config.const import (
    CLIENT_ID as CLIENT_ID_KEY,
)
from custom_components.auth_oidc.endpoints.backchannel_logout import (
    OIDCBackchannelLogoutView,
)
from custom_components.auth_oidc.tools.backchannel import (
    BackchannelLogoutValidator,
    LogoutTokenInvalid,
)
from custom_components.auth_oidc.tools.oidc_client import OIDCClient, hash_subject

ISSUER = "https://issuer.example.com"
CLIENT_ID = "homeassistant"
JWKS_URI = "https://issuer.example.com/jwks"
SUBJECT = "user-subject-123"


def make_client(hass) -> OIDCClient:
    """Build an OIDC client suitable for validator tests."""
    return OIDCClient(
        hass=hass,
        discovery_url=f"{ISSUER}/.well-known/openid-configuration",
        client_id=CLIENT_ID,
        scope="openid profile",
        features={},
        claims={},
        roles={},
        network={},
        id_token_signing_alg="RS256",
    )


@pytest.fixture
def signing_key():
    """Generate a fresh RSA signing key with a JWKS representation."""
    key = jwk.generate_key(
        "RSA", 2048, {"alg": "RS256", "use": "sig"}, private=True, auto_kid=True
    )
    return key, {"keys": [key.as_dict(private=False)]}


@pytest.fixture
def validator(hass, signing_key):
    """Build a validator wired to mocked discovery/JWKS lookups."""
    _, jwks = signing_key
    client = make_client(hass)
    client._fetch_discovery_document = AsyncMock(
        return_value={"issuer": ISSUER, "jwks_uri": JWKS_URI}
    )
    client._fetch_jwks = AsyncMock(return_value=jwks)
    return BackchannelLogoutValidator(client)


def make_logout_token(key, **claim_overrides) -> str:
    """Sign a logout token with sane defaults plus the requested overrides."""
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "jti": f"jti-{now}",
        "sub": SUBJECT,
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    claims.update(claim_overrides)
    for name in [k for k, v in claims.items() if v is None]:
        del claims[name]
    return jwt.encode(
        {"alg": "RS256", "kid": key.kid}, claims, key, algorithms=["RS256"]
    )


@pytest.mark.asyncio
async def test_valid_logout_token_is_accepted(validator, signing_key):
    """A well-formed logout token should validate and return its claims."""
    key, _ = signing_key
    token = make_logout_token(key)

    claims = await validator.validate(token)

    assert claims["sub"] == SUBJECT
    assert BACKCHANNEL_LOGOUT_EVENT in claims["events"]


@pytest.mark.asyncio
async def test_wrong_issuer_is_rejected(validator, signing_key):
    """A token from another issuer must be rejected."""
    key, _ = signing_key
    token = make_logout_token(key, iss="https://evil.example.com")

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_wrong_audience_is_rejected(validator, signing_key):
    """A token that is not addressed to our client_id must be rejected."""
    key, _ = signing_key
    token = make_logout_token(key, aud="some-other-client")

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_audience_list_containing_client_id_is_accepted(validator, signing_key):
    """The aud claim may be a list, as long as it contains our client_id."""
    key, _ = signing_key
    token = make_logout_token(key, aud=[CLIENT_ID, "another-client"])

    claims = await validator.validate(token)

    assert claims["sub"] == SUBJECT


@pytest.mark.asyncio
async def test_missing_events_is_rejected(validator, signing_key):
    """The required back-channel logout event member must be present."""
    key, _ = signing_key
    token = make_logout_token(key, events=None)

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_nonce_is_rejected(validator, signing_key):
    """A logout token must not contain a nonce claim."""
    key, _ = signing_key
    token = make_logout_token(key, nonce="should-not-be-here")

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_sid_only_token_is_accepted(validator, signing_key):
    """A logout token with a sid but no sub is valid per the spec."""
    key, _ = signing_key
    token = make_logout_token(key, sub=None, sid="session-1")

    claims = await validator.validate(token)

    assert claims["sid"] == "session-1"
    assert "sub" not in claims


@pytest.mark.asyncio
async def test_token_without_sub_or_sid_is_rejected(validator, signing_key):
    """A token with neither sub nor sid cannot identify anything."""
    key, _ = signing_key
    token = make_logout_token(key, sub=None)

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_missing_jti_is_rejected(validator, signing_key):
    """A token without a jti cannot be protected against replay."""
    key, _ = signing_key
    token = make_logout_token(key, jti=None)

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_expired_token_is_rejected(validator, signing_key):
    """An expired logout token must be rejected."""
    key, _ = signing_key
    now = int(time.time())
    token = make_logout_token(key, iat=now - 600, exp=now - 300)

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_replayed_token_is_rejected(validator, signing_key):
    """The same jti must not be accepted twice."""
    key, _ = signing_key
    token = make_logout_token(key, jti="reused-jti")

    await validator.validate(token)

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_wrong_algorithm_is_rejected(validator, signing_key):
    """A token whose header claims a different algorithm must be rejected."""
    key, _ = signing_key
    token = make_logout_token(key)
    _, payload, signature = token.split(".")
    forged_header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": key.kid}).encode())
        .rstrip(b"=")
        .decode()
    )
    forged_token = f"{forged_header}.{payload}.{signature}"

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(forged_token)


@pytest.mark.asyncio
async def test_unknown_kid_is_rejected(validator, signing_key):
    """A token signed by a key we do not know must be rejected."""
    other = jwk.generate_key(
        "RSA", 2048, {"alg": "RS256", "use": "sig"}, private=True, auto_kid=True
    )
    token = make_logout_token(other)

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_empty_token_is_rejected(validator):
    """An empty or missing token must be rejected."""
    with pytest.raises(LogoutTokenInvalid):
        await validator.validate("")


@pytest.mark.asyncio
async def test_malformed_token_is_rejected(validator):
    """A syntactically invalid token must raise instead of crashing."""
    with pytest.raises(LogoutTokenInvalid):
        await validator.validate("not-a-jwt")


@pytest.mark.asyncio
async def test_missing_iat_is_rejected(validator, signing_key):
    """The required iat claim must be present."""
    key, _ = signing_key
    token = make_logout_token(key, iat=None)

    with pytest.raises(LogoutTokenInvalid):
        await validator.validate(token)


@pytest.mark.asyncio
async def test_jti_cache_expires(validator, signing_key):
    """A jti may be reused once its cache entry has expired."""
    key, _ = signing_key
    validator.jti_cache_ttl = 0
    token = make_logout_token(key, jti="short-lived-jti")

    await validator.validate(token)
    # With a zero TTL the entry is pruned immediately, so reuse is allowed.
    claims = await validator.validate(token)

    assert claims["jti"] == "short-lived-jti"


async def setup_component(hass) -> None:
    """Set up the integration with a minimal YAML configuration."""
    result = await async_setup_component(
        hass,
        DOMAIN,
        {
            DOMAIN: {
                CLIENT_ID_KEY: CLIENT_ID,
                DISCOVERY_URL: f"{ISSUER}/.well-known/openid-configuration",
            }
        },
    )
    assert result


@pytest.mark.asyncio
async def test_backchannel_endpoint_rejects_missing_token(
    hass, hass_client: ClientSessionGenerator
):
    """The endpoint must respond 400 when no logout_token is provided."""
    await setup_component(hass)
    client = await hass_client()

    resp = await client.post("/auth/oidc/backchannel_logout", data={})

    assert resp.status == 400


@pytest.mark.asyncio
async def test_backchannel_endpoint_requires_no_auth(
    hass, hass_client: ClientSessionGenerator
):
    """The endpoint must be reachable without a Home Assistant session."""
    await setup_component(hass)
    client = await hass_client()

    # No auth cookie is sent; a 400 (missing token) proves the route is public.
    resp = await client.post("/auth/oidc/backchannel_logout")

    assert resp.status == 400
    assert resp.status != 401


def make_view(issuer: str, users: list) -> tuple:
    """Build a view with a mocked auth store for revocation tests."""
    remove_refresh_token = MagicMock()
    auth = SimpleNamespace(
        async_get_users=AsyncMock(return_value=users),
        async_remove_refresh_token=remove_refresh_token,
    )
    provider = SimpleNamespace(
        hass=SimpleNamespace(auth=auth), type="auth_oidc", id="default"
    )
    client = SimpleNamespace(discovery_document={"issuer": issuer})
    return OIDCBackchannelLogoutView(client, provider), remove_refresh_token


@pytest.mark.asyncio
async def test_revocation_removes_all_refresh_tokens_of_linked_user():
    """A valid logout should revoke every refresh token of the linked user."""
    hashed = hash_subject(ISSUER, SUBJECT)
    own_credential = SimpleNamespace(
        auth_provider_type="auth_oidc",
        auth_provider_id="default",
        data={"sub": hashed},
    )
    other_credential = SimpleNamespace(
        auth_provider_type="homeassistant", auth_provider_id=None, data={}
    )
    linked_user = SimpleNamespace(
        id="linked",
        credentials=[other_credential, own_credential],
        refresh_tokens={"a": object(), "b": object()},
    )
    unrelated_user = SimpleNamespace(
        id="unrelated",
        credentials=[other_credential],
        refresh_tokens={"c": object()},
    )
    view, remove = make_view(ISSUER, [unrelated_user, linked_user])

    await view._async_revoke_linked_sessions({"sub": SUBJECT, "sid": "session-1"})

    assert remove.call_count == 2


@pytest.mark.asyncio
async def test_revocation_ignores_unknown_subject():
    """A logout for an unknown subject must not revoke anything."""
    unrelated_user = SimpleNamespace(
        id="unrelated",
        credentials=[
            SimpleNamespace(
                auth_provider_type="auth_oidc",
                auth_provider_id="default",
                data={"sub": "someone-else"},
            )
        ],
        refresh_tokens={"c": object()},
    )
    view, remove = make_view(ISSUER, [unrelated_user])

    await view._async_revoke_linked_sessions({"sub": "unknown"})

    assert remove.call_count == 0


@pytest.mark.asyncio
async def test_revocation_works_for_sub_only_token():
    """A sub-bearing token must still revoke without a sid claim."""
    hashed = hash_subject(ISSUER, SUBJECT)
    linked_user = SimpleNamespace(
        id="linked",
        credentials=[
            SimpleNamespace(
                auth_provider_type="auth_oidc",
                auth_provider_id="default",
                data={"sub": hashed},
            )
        ],
        refresh_tokens={"a": object()},
    )
    view, remove = make_view(ISSUER, [linked_user])

    await view._async_revoke_linked_sessions({"sub": SUBJECT})

    assert remove.call_count == 1


@pytest.mark.asyncio
async def test_revocation_is_skipped_for_sid_only_token(caplog):
    """A sid-only token cannot be mapped, so nothing must be revoked."""
    linked_user = SimpleNamespace(
        id="linked",
        credentials=[
            SimpleNamespace(
                auth_provider_type="auth_oidc",
                auth_provider_id="default",
                data={"sub": hash_subject(ISSUER, SUBJECT)},
            )
        ],
        refresh_tokens={"a": object()},
    )
    view, remove = make_view(ISSUER, [linked_user])

    await view._async_revoke_linked_sessions({"sid": "session-1"})

    assert remove.call_count == 0
    assert "no session could be mapped" in caplog.text


def make_real_view(hass, signing_key, users: list | None = None) -> tuple:
    """Build a view with the real validator and mocked discovery/JWKS."""
    key, jwks = signing_key
    client = make_client(hass)
    discovery = {"issuer": ISSUER, "jwks_uri": JWKS_URI}

    async def fake_discovery():
        client.discovery_document = discovery
        return discovery

    client._fetch_discovery_document = AsyncMock(side_effect=fake_discovery)
    client._fetch_jwks = AsyncMock(return_value=jwks)
    remove_refresh_token = MagicMock()
    auth = SimpleNamespace(
        async_get_users=AsyncMock(return_value=users or []),
        async_remove_refresh_token=remove_refresh_token,
    )
    provider = SimpleNamespace(
        hass=SimpleNamespace(auth=auth), type="auth_oidc", id="default"
    )
    return OIDCBackchannelLogoutView(client, provider), key, remove_refresh_token


def make_request(logout_token: str) -> SimpleNamespace:
    """Build a minimal aiohttp-like request carrying a logout token."""
    return SimpleNamespace(post=AsyncMock(return_value={"logout_token": logout_token}))


@pytest.mark.asyncio
async def test_endpoint_accepts_sid_only_token_without_revoking(hass, signing_key):
    """A validated sid-only token returns 200 but revokes nothing."""
    view, key, remove = make_real_view(hass, signing_key)
    token = make_logout_token(key, sub=None, sid="session-1")

    resp = await view.post(make_request(token))

    assert resp.status == 200
    assert remove.call_count == 0


@pytest.mark.asyncio
async def test_endpoint_revokes_for_sub_bearing_token(hass, signing_key):
    """A validated sub-bearing token returns 200 and revokes its user."""
    linked_user = SimpleNamespace(
        id="linked",
        credentials=[
            SimpleNamespace(
                auth_provider_type="auth_oidc",
                auth_provider_id="default",
                data={"sub": hash_subject(ISSUER, SUBJECT)},
            )
        ],
        refresh_tokens={"a": object(), "b": object()},
    )
    view, key, remove = make_real_view(hass, signing_key, [linked_user])
    token = make_logout_token(key)

    resp = await view.post(make_request(token))

    assert resp.status == 200
    assert remove.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.example.com"},
        {"aud": "some-other-client"},
        {"events": None},
        {"nonce": "should-not-be-here"},
    ],
    ids=["wrong-iss", "wrong-aud", "missing-events", "nonce"],
)
async def test_endpoint_rejects_invalid_tokens(hass, signing_key, overrides):
    """Invalid logout tokens must be rejected with 400 and revoke nothing."""
    view, key, remove = make_real_view(hass, signing_key)
    token = make_logout_token(key, **overrides)

    resp = await view.post(make_request(token))

    assert resp.status == 400
    assert remove.call_count == 0


@pytest.mark.asyncio
async def test_endpoint_rejects_replayed_token(hass, signing_key):
    """The same token must be accepted once and then rejected as a replay."""
    view, key, _remove = make_real_view(hass, signing_key)
    token = make_logout_token(key, jti="replayed-at-endpoint")

    first = await view.post(make_request(token))
    second = await view.post(make_request(token))

    assert first.status == 200
    assert second.status == 400
