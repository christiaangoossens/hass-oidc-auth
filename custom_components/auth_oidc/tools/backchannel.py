"""Validator for OpenID Connect Back-Channel Logout tokens (Relying Party side).

Implements the RP-side token validation requirements from
OpenID Connect Back-Channel Logout 1.0 (incorporating errata set 1), Section 2.6.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import TYPE_CHECKING

from joserfc import errors as joserfc_errors
from joserfc import jwk, jws, jwt

from ..config.const import (
    BACKCHANNEL_LOGOUT_EVENT,
    BACKCHANNEL_LOGOUT_JTI_CACHE_TTL,
)

if TYPE_CHECKING:
    from .oidc_client import OIDCClient

_LOGGER = logging.getLogger(__name__)


class LogoutTokenInvalid(Exception):
    """Raised when a logout token is missing, malformed or fails validation."""


class BackchannelLogoutValidator:
    """Validates back-channel logout tokens against the configured OpenID Provider."""

    # pylint: disable=too-few-public-methods

    def __init__(
        self,
        oidc_client: OIDCClient,
        jti_cache_ttl: int = BACKCHANNEL_LOGOUT_JTI_CACHE_TTL,
    ) -> None:
        self.oidc_client = oidc_client
        self.jti_cache_ttl = jti_cache_ttl
        # Maps a seen jti to the monotonic time at which it may be forgotten.
        self._seen_jti: dict[str, float] = {}

    def _register_jti(self, jti: str) -> None:
        """Reject replayed tokens and remember this jti for a short while."""
        now = time.monotonic()

        for known_jti, expires_at in list(self._seen_jti.items()):
            if expires_at <= now:
                del self._seen_jti[known_jti]

        if jti in self._seen_jti:
            raise LogoutTokenInvalid("logout token was already used (replay)")

        self._seen_jti[jti] = now + self.jti_cache_ttl

    async def _verify_signature(self, logout_token: str, jwks_data: dict) -> dict:
        """Verify the JWS signature and return the decoded token claims."""
        expected_alg = self.oidc_client.id_token_signing_alg
        client_secret = self.oidc_client.client_secret

        try:
            token_obj = jws.extract_compact(logout_token.encode())
            header = token_obj.protected
            if not header:
                raise LogoutTokenInvalid("could not read logout token header")

            alg = header.get("alg")
            if alg != expected_alg:
                raise LogoutTokenInvalid(
                    f"logout token signed with unexpected algorithm: {alg}"
                )

            if alg.startswith("HS"):
                if not client_secret:
                    raise LogoutTokenInvalid(
                        "logout token uses HMAC but no client_secret is configured"
                    )
                jwk_obj = jwk.import_key(
                    {
                        "kty": "oct",
                        "k": base64.urlsafe_b64encode(client_secret.encode())
                        .decode()
                        .rstrip("="),
                        "alg": alg,
                    }
                )
            else:
                kid = header.get("kid")
                if not kid:
                    raise LogoutTokenInvalid("logout token has no kid (Key ID)")

                signing_key = next(
                    (key for key in jwks_data.get("keys", []) if key.get("kid") == kid),
                    None,
                )
                if signing_key is None:
                    raise LogoutTokenInvalid(f"no JWKS key found for kid: {kid}")

                if "alg" not in signing_key:
                    signing_key["alg"] = alg
                jwk_obj = jwk.import_key(signing_key)

            decoded_token = jwt.decode(logout_token, jwk_obj, algorithms=[alg])
        except (joserfc_errors.JoseError, ValueError, TypeError) as e:
            raise LogoutTokenInvalid(f"logout token signature invalid: {e}") from e

        return decoded_token.claims

    def _validate_claims(self, claims: dict, discovery_document: dict) -> None:
        """Validate the logout token claims required by the specification."""
        # OpenID Connect Back-Channel Logout 1.0, Section 2.4:
        # the iss claim must match the issuer discovered for the OP.
        if claims.get("iss") != discovery_document.get("issuer"):
            raise LogoutTokenInvalid("logout token issuer does not match")

        # OpenID Connect Core 1.0, Section 3.1.3.7.3:
        # the aud claim must contain the client_id.
        audience = claims.get("aud")
        if isinstance(audience, str):
            audience = [audience]
        if not isinstance(audience, list) or self.oidc_client.client_id not in audience:
            raise LogoutTokenInvalid("logout token audience does not contain client_id")

        # A nonce claim MUST NOT be present in a logout token.
        if "nonce" in claims:
            raise LogoutTokenInvalid("logout token must not contain a nonce")

        # The events claim must contain the back-channel logout event member.
        events = claims.get("events")
        if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
            raise LogoutTokenInvalid("logout token is missing the backchannel event")

        # OpenID Connect Back-Channel Logout 1.0, Section 2.4:
        # the token MUST contain either a sub or a sid claim (at least one).
        # A sub is required for the coarse user-level revocation we perform,
        # while a sid-only token can be validated but cannot currently be
        # mapped to a Home Assistant session (see the endpoint).
        if not claims.get("sub") and not claims.get("sid"):
            raise LogoutTokenInvalid("logout token is missing both sub and sid claims")

        # A jti is required to prevent token reuse.
        if not claims.get("jti"):
            raise LogoutTokenInvalid("logout token is missing a jti claim")

        # An iat is required by the specification.
        if "iat" not in claims:
            raise LogoutTokenInvalid("logout token is missing an iat claim")

        # Validate temporal claims (exp/iat/nbf) with a small leeway.
        try:
            jwt.JWTClaimsRegistry(leeway=5).validate(claims)
        except joserfc_errors.JoseError as e:
            raise LogoutTokenInvalid(f"logout token claims invalid: {e}") from e

    async def validate(self, logout_token: str) -> dict:
        """Validate a logout token and return its claims.

        Raises LogoutTokenInvalid when the token is missing, malformed or
        fails any of the specification checks.
        """
        if not logout_token or not isinstance(logout_token, str):
            raise LogoutTokenInvalid("missing logout_token")

        # Reuse the client's discovered document and JWKS cache.
        # pylint: disable=protected-access
        discovery_document = await self.oidc_client._fetch_discovery_document()
        jwks_data = await self.oidc_client._fetch_jwks(discovery_document["jwks_uri"])

        claims = await self._verify_signature(logout_token, jwks_data)
        self._validate_claims(claims, discovery_document)

        # Reject replays last so an already-seen token fails closed.
        self._register_jti(claims["jti"])
        return claims
