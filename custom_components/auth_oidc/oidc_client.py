"""OIDC Client class"""

import urllib.parse
import logging
import os
import base64
import hashlib
from typing import Optional
import aiohttp
from jose import jwt, jwk

_LOGGER = logging.getLogger(__name__)


class OIDCClientException(Exception):
    "Raised when the OIDC Client encounters an error"


class OIDCDiscoveryInvalid(OIDCClientException):
    "Raised when the discovery document is not found, invalid or otherwise malformed."


class OIDCTokenResponseInvalid(OIDCClientException):
    "Raised when the token request returns invalid."


class OIDCJWKSInvalid(OIDCClientException):
    "Raised when the JWKS is invalid or cannot be obtained."


class OIDCStateInvalid(OIDCClientException):
    "Raised when the state for your request cannot be matched against a stored state."


class OIDCClient:
    """OIDC Client implementation for Python, including PKCE."""

    # Flows stores the state, code_verifier and nonce of all current flows.
    flows = {}

    def __init__(self, discovery_url, client_id, scope):
        self.discovery_url = discovery_url
        self.discovery_document = None
        self.client_id = client_id
        self.scope = scope

    async def _fetch_discovery_document(self):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.discovery_url) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                _LOGGER.warning(
                    "Error: Discovery document not found at %s", self.discovery_url
                )
            else:
                _LOGGER.warning("Error: %s - %s", e.status, e.message)
            raise OIDCDiscoveryInvalid from e

    async def async_get_authorization_url(self, redirect_uri: str) -> Optional[str]:
        """Generates the authorization URL for the OIDC flow."""
        try:
            if self.discovery_document is None:
                self.discovery_document = await self._fetch_discovery_document()

            auth_endpoint = self.discovery_document["authorization_endpoint"]

            # Generate the necessary PKCE parameters, nonce & state
            code_verifier = (
                base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("utf-8")
            )
            code_challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode("utf-8")).digest()
                )
                .rstrip(b"=")
                .decode("utf-8")
            )
            nonce = (
                base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
            )
            state = (
                base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
            )

            # Save all of them for later verification
            self.flows[state] = {"code_verifier": code_verifier, "nonce": nonce}

            # Construct the params
            query_params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "scope": self.scope,
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }

            url = f"{auth_endpoint}?{urllib.parse.urlencode(query_params)}"
            return url
        except OIDCClientException as e:
            _LOGGER.warning("Error generating authorization URL: %s", e)
            return None

    async def _make_token_request(self, token_endpoint, query_params):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(token_endpoint, data=query_params) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientResponseError as e:
            _LOGGER.warning("Error exchanging token: %s - %s", e.status, e.message)
            raise OIDCTokenResponseInvalid from e

    async def _get_jwks(self, jwks_uri):
        """Fetches JWKS from the given URL."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(jwks_uri) as response:
                    response.raise_for_status()
                    return await response.json()
        except aiohttp.ClientResponseError as e:
            _LOGGER.warning("Error fetching JWKS: %s - %s", e.status, e.message)
            raise OIDCJWKSInvalid from e

    async def _parse_id_token(self, id_token: str):
        if self.discovery_document is None:
            self.discovery_document = await self._fetch_discovery_document()

        # Parse the id token to obtain the relevant details
        # Use python-jose

        jwks_uri = self.discovery_document["jwks_uri"]
        jwks_data = await self._get_jwks(jwks_uri)

        try:
            unverified_header = jwt.get_unverified_header(id_token)
            if not unverified_header:
                print("Could not parse JWT Header")
                return None

            kid = unverified_header.get("kid")
            if not kid:
                print("JWT does not have kid (Key ID)")
                return None

            # Get the correct key
            rsa_key = None
            for key in jwks_data["keys"]:
                if key["kid"] == kid:
                    rsa_key = key
                    break

            if not rsa_key:
                print(f"Could not find matching key with kid:{kid}")
                return None

            # Construct the JWK
            jwk_obj = jwk.construct(rsa_key)

            # Verify the token
            decoded_token = jwt.decode(
                id_token,
                jwk_obj,
                algorithms=["RS256"],  # Adjust if your algorithm is different
                audience=self.client_id,
                issuer=self.discovery_document["issuer"],
            )
            return decoded_token

        except jwt.JWTError as e:
            print(f"JWT Verification failed: {e}")
            return None

        return None

    async def async_complete_token_flow(
        self, redirect_uri: str, code: str, state: str
    ) -> dict[str, str | dict]:
        """Completes the OIDC token flow to obtain a user's details."""

        try:
            if state not in self.flows:
                raise OIDCStateInvalid

            flow = self.flows[state]
            code_verifier = flow["code_verifier"]

            if self.discovery_document is None:
                self.discovery_document = await self._fetch_discovery_document()

            token_endpoint = self.discovery_document["token_endpoint"]

            # Construct the params
            query_params = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }

            token_response = await self._make_token_request(
                token_endpoint, query_params
            )
            id_token = token_response.get("id_token")

            # Parse the id token to obtain the relevant details
            id_token = await self._parse_id_token(id_token)

            # Verify nonce
            if id_token.get("nonce") != flow["nonce"]:
                _LOGGER.warning("Nonce mismatch!")
                return None

            return {
                "name": id_token.get("name"),
                "username": id_token.get("preferred_username"),
                "groups": id_token.get("groups"),
            }
        except OIDCClientException as e:
            _LOGGER.warning("Error completing token flow: %s", e)
            return None
