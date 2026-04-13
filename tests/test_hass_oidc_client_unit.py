"""Unit tests for OIDC client token and security behavior."""

# pylint: disable=protected-access

import hashlib
import json
import base64
import time
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.core import HomeAssistant
from joserfc import errors as joserfc_errors, jwt, jwk

from custom_components.auth_oidc.tools.oidc_client import (
    HTTPClientError,
    OIDCClient,
    OIDCDiscoveryInvalid,
    OIDCIdTokenSigningAlgorithmInvalid,
    OIDCTokenResponseInvalid,
    OIDCUserinfoInvalid,
    http_raise_for_status,
)


def make_client(hass: HomeAssistant, **kwargs) -> OIDCClient:
    """Build an OIDC client with explicit defaults for unit testing."""
    return OIDCClient(
        hass=hass,
        discovery_url="https://issuer/.well-known/openid-configuration",
        client_id="test-client",
        scope="openid profile",
        features=kwargs.pop("features", {}),
        claims=kwargs.pop("claims", {}),
        roles=kwargs.pop("roles", {}),
        network=kwargs.pop("network", {}),
        **kwargs,
    )


def make_jwt(
    header: dict | None,
    payload: dict | None = None,
    signature: str = "sig",
) -> str:
    """Build a compact JWT string for parser-focused tests."""

    def _b64url_json(data: dict) -> str:
        encoded = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("utf-8")

    protected = _b64url_json(header) if header is not None else ""
    claims = _b64url_json(payload or {"sub": "subject"})
    return f"{protected}.{claims}.{signature}"


def make_signed_hs256_jwt(secret: str, claims: dict) -> str:
    """Build a real HS256 signed JWT for parser validation tests."""
    jwk_obj = jwk.import_key(
        {
            "kty": "oct",
            "k": base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
            "alg": "HS256",
        }
    )
    return jwt.encode({"alg": "HS256"}, claims, jwk_obj)


@pytest.mark.asyncio
async def test_complete_token_flow_rejects_missing_state(hass: HomeAssistant):
    """Flow state must exist; missing state should fail closed."""
    client = make_client(hass)

    result = await client.async_complete_token_flow(
        "https://example.com/callback", "code", "missing-state"
    )

    assert result is None


@pytest.mark.asyncio
async def test_complete_token_flow_rejects_nonce_mismatch(hass: HomeAssistant):
    """Nonce mismatch should reject the token flow."""
    client = make_client(hass)
    client.flows["state-1"] = {"code_verifier": "verifier", "nonce": "expected"}

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(return_value={"token_endpoint": "https://issuer/token"}),
    ), patch.object(
        client,
        "_make_token_request",
        new=AsyncMock(return_value={"id_token": "id", "access_token": "access"}),
    ), patch.object(
        client,
        "_parse_id_token",
        new=AsyncMock(return_value={"sub": "abc", "nonce": "wrong"}),
    ):
        result = await client.async_complete_token_flow(
            "https://example.com/callback", "code", "state-1"
        )

    assert result is None
    assert "state-1" not in client.flows


@pytest.mark.asyncio
async def test_complete_token_flow_handles_token_request_failure(hass: HomeAssistant):
    """Token endpoint failures should return None to caller."""
    client = make_client(hass)
    client.flows["state-2"] = {"code_verifier": "verifier", "nonce": "nonce"}

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(return_value={"token_endpoint": "https://issuer/token"}),
    ), patch.object(
        client,
        "_make_token_request",
        new=AsyncMock(side_effect=OIDCTokenResponseInvalid()),
    ):
        result = await client.async_complete_token_flow(
            "https://example.com/callback", "code", "state-2"
        )

    assert result is None


@pytest.mark.asyncio
async def test_parse_user_details_handles_non_list_groups(hass: HomeAssistant):
    """Non-list groups should not accidentally grant roles."""
    client = make_client(hass, roles={"user": "users", "admin": "admins"})

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(return_value={"issuer": "https://issuer"}),
    ):
        details = await client.parse_user_details(
            {
                "sub": "subject",
                "name": "Display Name",
                "preferred_username": "username",
                "groups": "admins",
            },
            "access-token",
        )

    assert details["role"] == "invalid"
    assert details["display_name"] == "Display Name"
    assert details["username"] == "username"


@pytest.mark.asyncio
async def test_parse_user_details_uses_userinfo_for_missing_claims(
    hass: HomeAssistant,
):
    """Missing claims in id_token should be filled from userinfo when available."""
    client = make_client(hass)

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(
            return_value={
                "issuer": "https://issuer",
                "userinfo_endpoint": "https://issuer/userinfo",
            }
        ),
    ), patch.object(
        client,
        "_get_userinfo",
        new=AsyncMock(
            return_value={
                "name": "From UserInfo",
                "preferred_username": "userinfo-user",
                "groups": ["admins"],
            }
        ),
    ):
        details = await client.parse_user_details({"sub": "subject"}, "access-token")

    expected_sub = hashlib.sha256("https://issuer.subject".encode("utf-8")).hexdigest()
    assert details["sub"] == expected_sub
    assert details["display_name"] == "From UserInfo"
    assert details["username"] == "userinfo-user"
    assert details["role"] == "system-admin"


@pytest.mark.asyncio
async def test_parse_user_details_assigns_system_users_role(hass: HomeAssistant):
    """Configured user role should map to system-users when group is present."""
    client = make_client(hass, roles={"user": "users", "admin": "admins"})

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(return_value={"issuer": "https://issuer"}),
    ):
        details = await client.parse_user_details(
            {
                "sub": "subject",
                "name": "Display Name",
                "preferred_username": "username",
                "groups": ["users"],
            },
            "access-token",
        )

    assert details["role"] == "system-users"


@pytest.mark.asyncio
async def test_parse_user_details_admin_role_overrides_user_role(
    hass: HomeAssistant,
):
    """Admin group should take precedence when both user and admin groups are present."""
    client = make_client(hass, roles={"user": "users", "admin": "admins"})

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(return_value={"issuer": "https://issuer"}),
    ):
        details = await client.parse_user_details(
            {
                "sub": "subject",
                "name": "Display Name",
                "preferred_username": "username",
                "groups": ["users", "admins"],
            },
            "access-token",
        )

    assert details["role"] == "system-admin"


@pytest.mark.asyncio
async def test_get_authorization_url_omits_pkce_when_disabled(
    hass: HomeAssistant,
):
    """Authorization URL should omit PKCE params when compatibility mode disables PKCE."""
    client = make_client(hass, features={"disable_rfc7636": True})

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(return_value={"authorization_endpoint": "https://issuer/authorize"}),
    ):
        url = await client.async_get_authorization_url(
            "https://example.com/callback", "state-xyz"
        )

    assert url is not None
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    assert query["state"] == ["state-xyz"]
    assert "nonce" in query
    assert "code_challenge" not in query
    assert "code_challenge_method" not in query


@pytest.mark.asyncio
async def test_parse_id_token_returns_none_when_kid_missing(hass: HomeAssistant):
    """ID token without kid should be rejected."""
    client = make_client(hass)
    client.discovery_document = {"issuer": "https://issuer", "jwks_uri": "https://issuer/jwks"}

    token = make_jwt({"alg": "RS256"})

    with patch.object(
        client,
        "_fetch_jwks",
        new=AsyncMock(return_value={"keys": []}),
    ):
        parsed = await client._parse_id_token(token)

    assert parsed is None


@pytest.mark.asyncio
async def test_parse_id_token_returns_none_when_kid_not_found(hass: HomeAssistant):
    """ID token with unknown kid should be rejected."""
    client = make_client(hass)
    client.discovery_document = {"issuer": "https://issuer", "jwks_uri": "https://issuer/jwks"}

    token = make_jwt({"alg": "RS256", "kid": "missing"})

    with patch.object(
        client,
        "_fetch_jwks",
        new=AsyncMock(return_value={"keys": [{"kid": "other"}]}),
    ):
        parsed = await client._parse_id_token(token)

    assert parsed is None


@pytest.mark.asyncio
async def test_parse_id_token_rejects_hs_without_client_secret(hass: HomeAssistant):
    """HMAC-signed id_token requires client_secret and must fail otherwise."""
    client = make_client(hass, id_token_signing_alg="HS256")
    client.discovery_document = {"issuer": "https://issuer", "jwks_uri": "https://issuer/jwks"}

    token = make_jwt({"alg": "HS256"})

    with patch.object(
        client,
        "_fetch_jwks",
        new=AsyncMock(return_value={"keys": []}),
    ):
        with pytest.raises(OIDCIdTokenSigningAlgorithmInvalid):
            await client._parse_id_token(token)


@pytest.mark.asyncio
async def test_parse_id_token_returns_none_when_decode_fails_jose(hass: HomeAssistant):
    """Jose decode/verification failures should be handled without raising to callers."""
    client = make_client(hass)
    client.discovery_document = {"issuer": "https://issuer", "jwks_uri": "https://issuer/jwks"}

    token = make_jwt({"alg": "RS256", "kid": "kid1"})

    with patch.object(
        client,
        "_fetch_jwks",
        new=AsyncMock(return_value={"keys": [{"kid": "kid1", "kty": "RSA"}]}),
    ), patch(
        "custom_components.auth_oidc.tools.oidc_client.jwk.import_key",
        return_value=object(),
    ), patch(
        "custom_components.auth_oidc.tools.oidc_client.jwt.decode",
        side_effect=joserfc_errors.JoseError("bad token"),
    ):
        parsed = await client._parse_id_token(token)

    assert parsed is None


@pytest.mark.asyncio
async def test_parse_id_token_rejects_wrong_signing_algorithm(hass: HomeAssistant):
    """ID token signed with unexpected alg should be rejected."""
    client = make_client(hass, id_token_signing_alg="RS256")
    client.discovery_document = {"issuer": "https://issuer", "jwks_uri": "https://issuer/jwks"}

    token = make_jwt({"alg": "HS256"})

    with patch.object(
        client,
        "_fetch_jwks",
        new=AsyncMock(return_value={"keys": []}),
    ):
        with pytest.raises(OIDCIdTokenSigningAlgorithmInvalid):
            await client._parse_id_token(token)


@pytest.mark.asyncio
async def test_parse_id_token_rejects_missing_header(hass: HomeAssistant):
    """ID token without protected header should be rejected."""
    client = make_client(hass)
    client.discovery_document = {"issuer": "https://issuer", "jwks_uri": "https://issuer/jwks"}

    token = make_jwt(None)

    with patch.object(
        client,
        "_fetch_jwks",
        new=AsyncMock(return_value={"keys": []}),
    ):
        parsed = await client._parse_id_token(token)

    assert parsed is None


@pytest.mark.asyncio
async def test_parse_id_token_rejects_invalid_registered_claims(hass: HomeAssistant):
    """Invalid aud/iss/sub style claim validation should fail closed."""
    client = make_client(
        hass,
        id_token_signing_alg="HS256",
        client_secret="top-secret",
    )
    client.discovery_document = {"issuer": "https://issuer", "jwks_uri": "https://issuer/jwks"}

    now = int(time.time())
    token = make_signed_hs256_jwt(
        "top-secret",
        {
            "sub": "abc",
            "aud": "wrong-audience",
            "iss": "https://wrong-issuer",
            "nbf": now,
            "iat": now,
            "exp": now + 3600,
        },
    )

    with patch.object(
        client,
        "_fetch_jwks",
        new=AsyncMock(return_value={"keys": []}),
    ):
        parsed = await client._parse_id_token(token)

    assert parsed is None


@pytest.mark.asyncio
async def test_get_authorization_url_returns_none_when_discovery_fails(
    hass: HomeAssistant,
):
    """Discovery failures should return None from authorization URL generation."""
    client = make_client(hass)

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(side_effect=OIDCDiscoveryInvalid()),
    ):
        url = await client.async_get_authorization_url(
            "https://example.com/callback", "state-1"
        )

    assert url is None


@pytest.mark.asyncio
async def test_complete_token_flow_omits_code_verifier_when_pkce_disabled(
    hass: HomeAssistant,
):
    """When PKCE is disabled, token request should omit code_verifier."""
    client = make_client(hass, features={"disable_rfc7636": True})
    client.flows["state-3"] = {"code_verifier": "verifier", "nonce": "nonce"}

    with patch.object(
        client,
        "_fetch_discovery_document",
        new=AsyncMock(return_value={"token_endpoint": "https://issuer/token"}),
    ), patch.object(
        client,
        "_make_token_request",
        new=AsyncMock(return_value={"id_token": "id", "access_token": "access"}),
    ) as make_token_request, patch.object(
        client,
        "_parse_id_token",
        new=AsyncMock(return_value={"sub": "abc", "nonce": "nonce"}),
    ), patch.object(
        client,
        "parse_user_details",
        new=AsyncMock(return_value={"sub": "abc", "display_name": "n", "username": "u", "role": "system-users"}),
    ):
        result = await client.async_complete_token_flow(
            "https://example.com/callback", "code", "state-3"
        )

    assert result is not None
    token_params = make_token_request.await_args.args[1]
    assert "code_verifier" not in token_params


@pytest.mark.asyncio
async def test_http_raise_for_status_noop_on_ok_response():
    """Status helper should not raise for successful responses."""
    response = MagicMock()
    response.ok = True

    await http_raise_for_status(response)


@pytest.mark.asyncio
async def test_http_raise_for_status_raises_http_client_error_with_body():
    """Status helper should include response body in raised exception."""
    response = MagicMock()
    response.ok = False
    response.reason = "Bad Request"
    response.status = 400
    response.request_info = MagicMock()
    response.history = ()
    response.headers = {}
    response.text = AsyncMock(return_value="problem details")

    with pytest.raises(HTTPClientError) as exc_info:
        await http_raise_for_status(response)

    assert "400 (Bad Request)" in str(exc_info.value)
    assert "problem details" in str(exc_info.value)


@pytest.mark.asyncio
async def test_get_http_session_reuses_existing_session(hass: HomeAssistant):
    """Session helper should return existing session when already created."""
    client = make_client(hass)
    existing_session = MagicMock()
    client.http_session = existing_session

    session = await client._get_http_session()

    assert session is existing_session


@pytest.mark.asyncio
async def test_get_http_session_applies_tls_verify_flag(hass: HomeAssistant):
    """Session helper should pass tls_verify setting into TCP connector."""
    client = make_client(hass, network={"tls_verify": False})

    with patch(
        "custom_components.auth_oidc.tools.oidc_client.aiohttp.TCPConnector",
        return_value=MagicMock(),
    ) as tcp_connector, patch(
        "custom_components.auth_oidc.tools.oidc_client.aiohttp.ClientSession",
        return_value=MagicMock(),
    ):
        await client._get_http_session()

    tcp_connector.assert_called_once_with(verify_ssl=False)


@pytest.mark.asyncio
async def test_get_http_session_uses_custom_ca_path(hass: HomeAssistant):
    """Session helper should create SSL context when custom CA path is configured."""
    client = make_client(
        hass,
        network={"tls_verify": True, "tls_ca_path": "/tmp/test-ca.pem"},
    )
    fake_ssl_context = object()

    with patch.object(
        hass.loop,
        "run_in_executor",
        new=AsyncMock(return_value=fake_ssl_context),
    ) as run_in_executor, patch(
        "custom_components.auth_oidc.tools.oidc_client.aiohttp.TCPConnector",
        return_value=MagicMock(),
    ) as tcp_connector, patch(
        "custom_components.auth_oidc.tools.oidc_client.aiohttp.ClientSession",
        return_value=MagicMock(),
    ):
        await client._get_http_session()

    run_in_executor.assert_awaited_once()
    tcp_connector.assert_called_once_with(verify_ssl=True, ssl=fake_ssl_context)


@pytest.mark.asyncio
async def test_make_token_request_returns_json_on_success(hass: HomeAssistant):
    """Token request helper should return JSON payload for successful responses."""
    client = make_client(hass)
    response = MagicMock()
    response.ok = True
    response.json = AsyncMock(return_value={"access_token": "token"})

    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = response
    session = MagicMock()
    session.post.return_value = context_manager

    with patch.object(client, "_get_http_session", new=AsyncMock(return_value=session)):
        payload = await client._make_token_request("https://issuer/token", {"code": "abc"})

    assert payload == {"access_token": "token"}


@pytest.mark.asyncio
async def test_make_token_request_raises_invalid_on_non_400_http_error(
    hass: HomeAssistant,
):
    """Token request helper should map upstream HTTP errors to OIDCTokenResponseInvalid."""
    client = make_client(hass)
    response = MagicMock()
    response.ok = False
    response.reason = "Server Error"
    response.status = 500
    response.request_info = MagicMock()
    response.history = ()
    response.headers = {}
    response.text = AsyncMock(return_value="boom")

    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = response
    session = MagicMock()
    session.post.return_value = context_manager

    with patch.object(client, "_get_http_session", new=AsyncMock(return_value=session)):
        with pytest.raises(OIDCTokenResponseInvalid):
            await client._make_token_request("https://issuer/token", {"code": "abc"})


@pytest.mark.asyncio
async def test_get_userinfo_returns_json_on_success(hass: HomeAssistant):
    """Userinfo helper should return JSON payload for successful responses."""
    client = make_client(hass)
    response = MagicMock()
    response.ok = True
    response.json = AsyncMock(return_value={"sub": "abc"})

    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = response
    session = MagicMock()
    session.get.return_value = context_manager

    with patch.object(client, "_get_http_session", new=AsyncMock(return_value=session)):
        payload = await client._get_userinfo("https://issuer/userinfo", "access")

    assert payload == {"sub": "abc"}


@pytest.mark.asyncio
async def test_get_userinfo_raises_invalid_on_http_error(hass: HomeAssistant):
    """Userinfo helper should map upstream HTTP errors to OIDCUserinfoInvalid."""
    client = make_client(hass)
    response = MagicMock()
    response.ok = False
    response.reason = "Unavailable"
    response.status = 503
    response.request_info = MagicMock()
    response.history = ()
    response.headers = {}
    response.text = AsyncMock(return_value="oops")

    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = response
    session = MagicMock()
    session.get.return_value = context_manager

    with patch.object(client, "_get_http_session", new=AsyncMock(return_value=session)):
        with pytest.raises(OIDCUserinfoInvalid):
            await client._get_userinfo("https://issuer/userinfo", "access")
