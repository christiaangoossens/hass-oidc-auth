"""OIDC Client class"""

import urllib.parse
import logging
import os
import base64
import hashlib
import ssl
from typing import Optional
from functools import partial
import aiohttp
from jose import jwt, jwk
from homeassistant.core import HomeAssistant

from .types import UserDetails
from .config import (
    FEATURES_DISABLE_PKCE,
    CLAIMS_DISPLAY_NAME,
    CLAIMS_USERNAME,
    CLAIMS_GROUPS,
    ROLE_ADMINS,
    ROLE_USERS,
    NETWORK_TLS_VERIFY,
    NETWORK_TLS_CA_PATH,
)

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


class OIDCUserinfoInvalid(OIDCClientException):
    "Raised when the user info is invalid or cannot be obtained."


class OIDCIdTokenSigningAlgorithmInvalid(OIDCTokenResponseInvalid):
    "Raised when the id_token is signed with the wrong algorithm, adjust your config accordingly."


class HTTPClientError(aiohttp.ClientResponseError):
    "Raised when the HTTP client encounters not OK (200) status code."

    body: str

    def __init__(self, *args, **kwargs):
        self.body = kwargs.pop("body")
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"{self.status} ({self.message}) with response body: {self.body}"


# pylint: disable=too-many-instance-attributes
class OIDCClient:
    """OIDC Client implementation for Python, including PKCE."""

    # Flows stores the state, code_verifier and nonce of all current flows.
    flows = {}

    # HTTP session to be used
    http_session: aiohttp.ClientSession = None

    def __init__(
        self,
        hass: HomeAssistant,
        discovery_url: str,
        client_id: str,
        scope: str,
        **kwargs: str,
    ):
        self.hass = hass
        self.discovery_url = discovery_url
        self.discovery_document = None
        self.client_id = client_id
        self.scope = scope

        # Optional parameters
        self.client_secret = kwargs.get("client_secret")

        # Default id_token_signing_alg to RS256 if not specified
        self.id_token_signing_alg = kwargs.get("id_token_signing_alg")
        if self.id_token_signing_alg is None:
            self.id_token_signing_alg = "RS256"

        features = kwargs.get("features")
        claims = kwargs.get("claims")
        roles = kwargs.get("roles")
        network = kwargs.get("network")

        self.disable_pkce = features.get(FEATURES_DISABLE_PKCE, False)
        self.display_name_claim = claims.get(CLAIMS_DISPLAY_NAME, "name")
        self.username_claim = claims.get(CLAIMS_USERNAME, "preferred_username")
        self.groups_claim = claims.get(CLAIMS_GROUPS, "groups")
        self.user_role = roles.get(ROLE_USERS, None)
        self.admin_role = roles.get(ROLE_ADMINS, "admins")
        self.tls_verify = network.get(NETWORK_TLS_VERIFY, True)
        self.tls_ca_path = network.get(NETWORK_TLS_CA_PATH)

    def __del__(self):
        """Cleanup the HTTP session."""

        # HA never seems to run this, but it's good practice to close the session
        if self.http_session:
            _LOGGER.debug("Closing HTTP session")
            self.http_session.close()

    async def http_raise_for_status(self, response: aiohttp.ClientResponse) -> None:
        """Raises an exception if the response is not OK."""
        if not response.ok:
            # reason should always be not None for a started response
            assert response.reason is not None

            body = await response.text()

            raise HTTPClientError(
                response.request_info,
                response.history,
                status=response.status,
                message=response.reason,
                headers=response.headers,
                body=body,
            )

    def _base64url_encode(self, value: str) -> str:
        """Uses base64url encoding on a given string"""
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")

    def _generate_random_url_string(self, length: int = 16) -> str:
        """Generates a random URL safe string (base64_url encoded)"""
        return self._base64url_encode(os.urandom(length))

    async def _get_http_session(self) -> aiohttp.ClientSession:
        """Create or get the existing client session with custom networking/TLS options"""
        if self.http_session is not None:
            return self.http_session

        _LOGGER.debug(
            "Creating HTTP session provider with options: "
            + "verify certificates: %r, custom CA file: %s",
            self.tls_verify,
            self.tls_ca_path,
        )

        tcp_connector_args = {"verify_ssl": self.tls_verify}

        if self.tls_ca_path:
            # Move to hass' executor to prevent blocking code inside non-blocking method
            ssl_context = await self.hass.loop.run_in_executor(
                None, partial(ssl.create_default_context, cafile=self.tls_ca_path)
            )
            tcp_connector_args["ssl"] = ssl_context

        self.http_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(**tcp_connector_args)
        )
        return self.http_session

    async def _fetch_discovery_document(self):
        """Fetches discovery document from the given URL."""
        try:
            session = await self._get_http_session()

            async with session.get(self.discovery_url) as response:
                await self.http_raise_for_status(response)
                return await response.json()
        except HTTPClientError as e:
            if e.status == 404:
                _LOGGER.warning(
                    "Error: Discovery document not found at %s", self.discovery_url
                )
            else:
                _LOGGER.warning("Error fetching discovery: %s", e)
            raise OIDCDiscoveryInvalid from e

    async def _get_jwks(self, jwks_uri):
        """Fetches JWKS from the given URL."""
        try:
            session = await self._get_http_session()

            async with session.get(jwks_uri) as response:
                await self.http_raise_for_status(response)
                return await response.json()
        except HTTPClientError as e:
            _LOGGER.warning("Error fetching JWKS: %s", e)
            raise OIDCJWKSInvalid from e

    async def _make_token_request(self, token_endpoint, query_params):
        """Performs the token POST call"""
        try:
            session = await self._get_http_session()

            async with session.post(token_endpoint, data=query_params) as response:
                await self.http_raise_for_status(response)
                return await response.json()
        except HTTPClientError as e:
            if e.status == 400:
                _LOGGER.warning(
                    "Error: Token could not be obtained (%s, %s), "
                    + "did you forget the client_secret? Server returned: %s",
                    e.status,
                    e.message,
                    e.body,
                )
            else:
                _LOGGER.warning("Unexpected error exchanging token: %s", e)

            raise OIDCTokenResponseInvalid from e

    async def _get_userinfo(self, userinfo_uri, access_token):
        """Fetches userinfo from the given URL."""
        try:
            session = await self._get_http_session()
            headers = {"Authorization": "Bearer " + access_token}

            async with session.get(userinfo_uri, headers=headers) as response:
                await self.http_raise_for_status(response)
                return await response.json()
        except HTTPClientError as e:
            _LOGGER.warning("Error fetching userinfo: %s", e)
            raise OIDCUserinfoInvalid from e

    async def _parse_id_token(
        self, id_token: str, access_token: str | None
    ) -> Optional[dict]:
        """Parses the ID token into a dict containing token contents."""
        if self.discovery_document is None:
            self.discovery_document = await self._fetch_discovery_document()

        jwks_uri = self.discovery_document["jwks_uri"]
        jwks_data = await self._get_jwks(jwks_uri)

        try:
            # Obtain the id_token header
            unverified_header = jwt.get_unverified_header(id_token)
            if not unverified_header:
                _LOGGER.warning("Could not get header from received id_token.")
                return None

            # Obtain the signing algorithm from the header of the id_token
            alg = unverified_header.get("alg")
            if alg != self.id_token_signing_alg:
                # Verify that it matches our requested algorithm
                _LOGGER.warning(
                    "ID Token received signed with the wrong algorithm: %s, expected %s",
                    alg,
                    self.id_token_signing_alg,
                )
                raise OIDCIdTokenSigningAlgorithmInvalid()

            # OpenID Connect Core 1.0 Section 3.1.3.7.8
            # If the JWT alg Header Parameter uses a MAC based algorithm
            # such as HS256, HS384, or HS512, the octets of the UTF-8 [RFC3629]
            # representation of the client_secret corresponding to the client_id
            # contained in the aud (audience) Claim are used as the key to
            # validate the signature.
            if alg.startswith("HS"):
                if not self.client_secret:
                    _LOGGER.warning(
                        "ID Token signed with HMAC algorithm, but no client_secret provided."
                    )
                    raise OIDCIdTokenSigningAlgorithmInvalid()

                jwk_obj = jwk.construct(
                    {
                        "kty": "oct",
                        "k": base64.urlsafe_b64encode(
                            self.client_secret.encode()
                        ).decode(),
                        "alg": alg,
                    }
                )
            else:
                # TODO: Deal with cases where kid is not specified (just take the first key?)
                # Obtain the kid (Key ID) from the header of the id_token
                kid = unverified_header.get("kid")
                if not kid:
                    _LOGGER.warning("JWT does not have kid (Key ID)")
                    return None

                # Get the correct key
                signing_key = None
                for key in jwks_data["keys"]:
                    if key["kid"] == kid:
                        signing_key = key
                        break

                if not signing_key:
                    _LOGGER.warning("Could not find matching key with kid: %s", kid)
                    return None

                # If signing_key does not have alg, set it to the one passed in the token
                if "alg" not in signing_key:
                    signing_key["alg"] = alg

                # Construct the JWK from the RSA key
                jwk_obj = jwk.construct(signing_key)

            # Verify the token
            decoded_token = jwt.decode(
                id_token,
                jwk_obj,
                # OpenID Connect Core 1.0 Section 3.1.3.7.6
                # The Client MUST validate the signature of all other ID Tokens
                # according to JWS [JWS] using the algorithm specified in the JWT
                # alg Header Parameter.
                algorithms=[self.id_token_signing_alg],
                # OpenID Connect Core 1.0 Section 3.1.3.7.3
                # The Client MUST validate that the aud (audience) Claim contains
                # its client_id value registered at the Issuer identified by the
                # iss (issuer) Claim as an audience.
                audience=self.client_id,
                # OpenID Connect Core 1.0 Section 3.1.3.7.2
                # The Issuer Identifier for the OpenID Provider MUST exactly
                # match the value of the iss (issuer) Claim.
                issuer=self.discovery_document["issuer"],
                access_token=access_token,
                options={
                    # Verify everything if present
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iat": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_sub": True,
                    "verify_jti": True,
                    "verify_at_hash": True,
                    # OpenID Connect Core 1.0 Section 3.1.3.7.3
                    "require_aud": True,
                    # OpenID Connect Core 1.0 Section 3.1.3.7.10
                    "require_iat": True,
                    # OpenID Connect Core 1.0 Section 3.1.3.7.9
                    "require_exp": True,
                    # OpenID Connect Core 1.0 Section 3.1.3.7.2
                    "require_iss": True,
                    # We need the sub as it's used to identify the user
                    "require_sub": True,
                    # Other values, not required.
                    "require_nbf": False,
                    "require_jti": False,
                    "require_at_hash": False,
                    "leeway": 5,
                },
            )
            return decoded_token

        except jwt.JWTError as e:
            _LOGGER.warning("JWT Verification failed: %s", e)
            return None

    async def async_get_authorization_url(self, redirect_uri: str) -> Optional[str]:
        """Generates the authorization URL for the OIDC flow."""
        try:
            if self.discovery_document is None:
                self.discovery_document = await self._fetch_discovery_document()

            auth_endpoint = self.discovery_document["authorization_endpoint"]

            # Generate random nonce & state
            nonce = self._generate_random_url_string()
            state = self._generate_random_url_string()

            # Generate PKCE (RFC 7636) parameters
            code_verifier = self._generate_random_url_string(32)
            code_challenge = self._base64url_encode(
                hashlib.sha256(code_verifier.encode("utf-8")).digest()
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
                # Nonce is always set in accordance with OpenID Connect Core 1.0
                "nonce": nonce,
            }

            # We always want to use PKCE (RFC 7636), unless it's disabled for compatibility.
            # PKCE is the recommended method of securing the authorization code grant
            # for public clients as much as possible.
            # (see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11#section-7.5.1)
            if not self.disable_pkce:
                query_params["code_challenge"] = code_challenge
                query_params["code_challenge_method"] = "S256"

            url = f"{auth_endpoint}?{urllib.parse.urlencode(query_params)}"
            return url
        except OIDCClientException as e:
            _LOGGER.warning("Error generating authorization URL: %s", e)
            return None

    async def parse_user_details(self, id_token: str, access_token: str) -> UserDetails:
        """Parses the ID token and/or userinfo into user details."""

        # Fetch userinfo if there is an userinfo_endpoint available
        # and use the data to supply the missing values in id_token
        if "userinfo_endpoint" in self.discovery_document:
            userinfo_endpoint = self.discovery_document["userinfo_endpoint"]
            userinfo = await self._get_userinfo(userinfo_endpoint, access_token)

            # Replace missing claims in the id_token with their userinfo version
            for claim in (
                self.groups_claim,
                self.display_name_claim,
                self.username_claim,
            ):
                if claim not in id_token and claim in userinfo:
                    id_token[claim] = userinfo[claim]

        # Get and parse groups (to check if it's an array)
        groups = id_token.get(self.groups_claim, [])
        if not isinstance(groups, list):
            _LOGGER.warning("Groups claim is not a list, using empty list instead.")
            groups = []

        # Assign role if user has the required groups
        role = "invalid"
        if self.user_role in groups or self.user_role is None:
            role = "system-users"

        if self.admin_role in groups:
            role = "system-admin"

        # Create a user details dict based on the contents of the id_token & userinfo
        return {
            # Subject Identifier. A locally unique and never reassigned identifier within the
            # Issuer for the End-User, which is intended to be consumed by the Client
            # Only unique per issuer, so we combine it with the issuer and hash it.
            # This might allow multiple OIDC providers to be used with this integration.
            "sub": hashlib.sha256(
                f"{self.discovery_document['issuer']}.{id_token.get('sub')}".encode(
                    "utf-8"
                )
            ).hexdigest(),
            # Display name, configurable
            "display_name": id_token.get(self.display_name_claim),
            # Username, configurable
            "username": id_token.get(self.username_claim),
            # Role
            "role": role,
        }

    async def async_complete_token_flow(
        self, redirect_uri: str, code: str, state: str
    ) -> Optional[UserDetails]:
        """Completes the OIDC token flow to obtain a user's details."""

        try:
            if state not in self.flows:
                raise OIDCStateInvalid

            flow = self.flows[state]

            if self.discovery_document is None:
                self.discovery_document = await self._fetch_discovery_document()

            token_endpoint = self.discovery_document["token_endpoint"]

            # Construct the params
            query_params = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "redirect_uri": redirect_uri,
            }

            # Send the client secret if we have one
            if self.client_secret is not None:
                query_params["client_secret"] = self.client_secret

            # If we disable PKCE, don't send the code verifier
            if not self.disable_pkce:
                query_params["code_verifier"] = flow["code_verifier"]

            # Exchange the code for a token
            token_response = await self._make_token_request(
                token_endpoint, query_params
            )

            id_token = token_response.get("id_token")
            access_token = token_response.get("access_token")

            # Parse the id token to obtain the relevant details
            # Access token is supplied to check at_hash if present
            id_token = await self._parse_id_token(id_token, access_token)

            if id_token is None:
                _LOGGER.warning("ID token could not be parsed!")
                return None

            # OpenID Connect Core 1.0 Section 3.1.3.7.11
            # If a nonce value was sent in the Authentication Request,
            # a nonce Claim MUST be present and its value checked to verify
            # that it is the same value as the one that was sent in the Authentication Request.
            if id_token.get("nonce") != flow["nonce"]:
                _LOGGER.warning("Nonce mismatch!")
                return None

            data = await self.parse_user_details(id_token, access_token)

            # Log which details were obtained for debugging
            # Also log the original subject identifier such that you can look it up in your provider
            _LOGGER.debug(
                "Obtained user details from OIDC provider: %s (issuer subject: %s)",
                data,
                id_token.get("sub"),
            )
            return data
        except OIDCClientException as e:
            _LOGGER.warning("Failed to complete token flow, returning None. (%s)", e)
            return None
