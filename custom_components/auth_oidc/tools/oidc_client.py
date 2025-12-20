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
from joserfc import jwt, jwk, jws, errors as joserfc_errors
from homeassistant.core import HomeAssistant
import json
from pathlib import Path
import aiofiles
from .helpers import compute_allowed_signing_algs

from .types import UserDetails
from ..config.const import (
    FEATURES_DISABLE_PKCE,
    CLAIMS_DISPLAY_NAME,
    CLAIMS_USERNAME,
    CLAIMS_GROUPS,
    ROLE_ADMINS,
    ROLE_USERS,
    NETWORK_TLS_VERIFY,
    NETWORK_TLS_CA_PATH,
    DEFAULT_ID_TOKEN_SIGNING_ALGORITHM,
)
from .validation import validate_url

_LOGGER = logging.getLogger(__name__)


class OIDCClientException(Exception):
    "Raised when the OIDC Client encounters an error"


class OIDCDiscoveryInvalid(OIDCClientException):
    "Raised when the discovery document is not found, invalid or otherwise malformed."

    type: Optional[str]
    details: Optional[dict]

    def __init__(self, **kwargs):
        self.message = "OIDC Discovery document is invalid"
        self.type = kwargs.pop("type", None)
        self.details = kwargs.pop("details", None)
        super().__init__(self.message)

    def get_detail_string(self) -> str:
        """Returns a detailed string for logging purposes."""
        string = []

        if self.type:
            string.append(f"type: {self.type}")

        if self.details:
            for key, value in self.details.items():
                string.append(f"{key}: {value}")

        return ", ".join(string)


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


async def http_raise_for_status(response: aiohttp.ClientResponse) -> None:
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


class OIDCDiscoveryClient:
    """OIDC Discovery Client implementation for Python"""

    def __init__(
        self,
        discovery_url: str,
        http_session: aiohttp.ClientSession,
        verification_context: dict,
    ):
        self.discovery_url = discovery_url
        self.http_session = http_session
        self.verification_context = verification_context

    async def _fetch_discovery_document(self):
        """Fetches discovery document from the given URL."""
        # Pass verbose context from OIDCClient (additive)
        verbose_mode = getattr(self, 'verbose_debug_mode', False)
        capture_dir = getattr(self, 'capture_dir', None)
        
        try:
            if verbose_mode and capture_dir:
                _LOGGER.debug(f"Attempting to fetch discovery document from: {self.discovery_url}")
                discovery_txt = capture_dir / "get_discovery.txt"
                async with aiofiles.open(discovery_txt, 'w', encoding='utf-8') as f:
                    await f.write(
                        "/*\n----------BEGIN DISCOVERY DOCUMENT REQUEST----------\n"
                        f"Discovery Endpoint URL: {self.discovery_url}\n*/\n\n"
                    )
                _LOGGER.debug("Check Discovery doc request capture in: %s for more details...", discovery_txt)

            async with self.http_session.get(self.discovery_url) as response:
                await http_raise_for_status(response)
                response_text = await response.text()
                
                if verbose_mode and capture_dir:
                    _LOGGER.debug(f"Discovery response received: Status {response.status}")
                    async with aiofiles.open(discovery_txt, 'a', encoding='utf-8') as f:
                        await f.write(
                            "/*\n----------BEGIN DISCOVERY DOCUMENT RESPONSE----------\n"
                            f"Fetch Discovery Doc Response Status: {response.status}\n*/\n"
                            f"//Response Body:\n{response_text}\n"
                        )
                    _LOGGER.debug("Check Discovery doc response capture in: %s for more details...", discovery_txt)
                
                return await response.json()
        except HTTPClientError as e:
            if e.status == 404:
                _LOGGER.warning(
                    "Error: Discovery document not found at %s", self.discovery_url
                )
            else:
                _LOGGER.warning("Error fetching discovery: %s", e)
            raise OIDCDiscoveryInvalid(type="fetch_error") from e

    async def _fetch_jwks(self, jwks_uri):
        """Fetches JWKS from the given URL."""
        # Pass verbose context (additive)
        verbose_mode = getattr(self, 'verbose_debug_mode', False)
        capture_dir = getattr(self, 'capture_dir', None)
        
        try:
            if verbose_mode and capture_dir:
                _LOGGER.debug(f"Retrieving JWKS keys from endpoint: {jwks_uri}")
                jwks_txt = capture_dir / "get_jwks.txt"
                async with aiofiles.open(jwks_txt, 'w', encoding='utf-8') as f:
                    await f.write(
                        "/*\n----------BEGIN JWKS REQUEST----------\n"
                        f"JWKS Endpoint URL: {jwks_uri}\n*/\n\n"
                    )
                _LOGGER.debug("Check JWKS request capture in: %s for more details...", jwks_txt)

            async with self.http_session.get(jwks_uri) as response:
                await http_raise_for_status(response)
                response_text = await response.text()
                
                if verbose_mode and capture_dir:
                    _LOGGER.debug(f"JWKS response received: Status {response.status}")
                    async with aiofiles.open(jwks_txt, 'a', encoding='utf-8') as f:
                        await f.write(
                            "/*\n----------BEGIN JWKS RESPONSE----------\n"
                            f"Fetch JWKS Keys Status: {response.status}\n*/\n"
                            f"//Response Body:\n{response_text}\n"
                        )
                    _LOGGER.debug("Check JWKS response capture in: %s for more details...", jwks_txt)
                
                return await response.json()
        except HTTPClientError as e:
            _LOGGER.warning("Error fetching JWKS: %s", e)
            raise OIDCJWKSInvalid from e

    # pylint: disable=too-many-branches
    async def _validate_discovery_document(self, document):
        """Validates the discovery document."""

        # Verify that required endpoints are present
        required_endpoints = [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
        ]

        for endpoint in required_endpoints:
            if endpoint not in document:
                _LOGGER.warning(
                    "Error: Discovery document %s is missing required endpoint: %s",
                    self.discovery_url,
                    endpoint,
                )
                raise OIDCDiscoveryInvalid(
                    type="missing_endpoint", details={"endpoint": endpoint}
                )
            if validate_url(document[endpoint]) is False:
                _LOGGER.warning(
                    "Error: Discovery document %s has invalid URL in endpoint: %s (%s)",
                    self.discovery_url,
                    endpoint,
                    document[endpoint],
                )
                raise OIDCDiscoveryInvalid(
                    type="invalid_endpoint",
                    details={"endpoint": endpoint, "url": document[endpoint]},
                )

        # Verify optional response_modes_supported
        if "response_modes_supported" in document:
            if "query" not in document["response_modes_supported"]:
                _LOGGER.warning(
                    "Error: Discovery document %s does not support required 'query' "
                    "response mode, only supports: %s",
                    self.discovery_url,
                    document["response_modes_supported"],
                )
                raise OIDCDiscoveryInvalid(
                    type="does_not_support_response_mode",
                    details={"modes": document["response_modes_supported"]},
                )

        # If grant_types_supported is set, should support 'authorization_code'
        if "grant_types_supported" in document:
            if "authorization_code" not in document["grant_types_supported"]:
                _LOGGER.warning(
                    "Error: Discovery document %s does not support required "
                    "'authorization_code' grant type, only supports: %s",
                    self.discovery_url,
                    document["grant_types_supported"],
                )
                raise OIDCDiscoveryInvalid(
                    type="does_not_support_grant_type",
                    details={
                        "required": "authorization_code",
                        "supported": document["grant_types_supported"],
                    },
                )

        # If response_types_supported is set, should support 'code'
        if "response_types_supported" in document:
            if "code" not in document["response_types_supported"]:
                _LOGGER.warning(
                    "Error: Discovery document %s does not support required "
                    "'code' response type, only supports: %s",
                    self.discovery_url,
                    document["response_types_supported"],
                )
                raise OIDCDiscoveryInvalid(
                    type="does_not_support_response_type",
                    details={
                        "required": "code",
                        "supported": document["response_types_supported"],
                    },
                )

        # If code_challenge_methods_supported is present, check that it contains S256
        if "code_challenge_methods_supported" in document:
            if "S256" not in document["code_challenge_methods_supported"]:
                _LOGGER.warning(
                    "Error: Discovery document %s does not support required "
                    "'S256' code challenge method, only supports: %s",
                    self.discovery_url,
                    document["code_challenge_methods_supported"],
                )
                raise OIDCDiscoveryInvalid(
                    type="does_not_support_required_code_challenge_method",
                    details={
                        "required": "S256",
                        "supported": document["code_challenge_methods_supported"],
                    },
                )

        # Verify the id_token_signing_alg_values_supported field is present and filled
        signing_values = document.get("id_token_signing_alg_values_supported", None)
        if signing_values is None:
            _LOGGER.warning(
                "Error: Discovery document %s does not have "
                "'id_token_signing_alg_values_supported' field",
                self.discovery_url,
            )
            raise OIDCDiscoveryInvalid(type="missing_id_token_signing_alg_values")

        # Verify that the requested id_token_signing_alg is supported (WARN only, flexible)
        requested_alg = self.verification_context.get("id_token_signing_alg", None)
        signing_values = document.get("id_token_signing_alg_values_supported", None)
        if signing_values is None:
            _LOGGER.warning(
                "Error: Discovery document %s does not have "
                "'id_token_signing_alg_values_supported' field",
                self.discovery_url,
            )
            raise OIDCDiscoveryInvalid(type="missing_id_token_signing_alg_values")

        if requested_alg is not None and requested_alg not in signing_values:
            _LOGGER.warning(  # WARN, not raise (flexible via compute_allowed_signing_algs)
                "Discovery document %s does not support requested "
                "id_token_signing_alg '%s', only supports: %s. Proceeding anyway.",
                self.discovery_url,
                requested_alg,
                signing_values,
            )
            # raise ...  # REMOVED: Now handled flexibly in _parse_id_token

    async def fetch_discovery_document(self):
        """Fetches discovery document."""
        document = await self._fetch_discovery_document()
        await self._validate_discovery_document(document)
        return document

    async def fetch_jwks(self, jwks_uri: str | None = None):
        """Fetches JWKS."""
        if jwks_uri is None:
            discovery_document = await self._fetch_discovery_document()
            jwks_uri = discovery_document["jwks_uri"]
        return await self._fetch_jwks(jwks_uri)


# pylint: disable=too-many-instance-attributes
class OIDCClient:
    """OIDC Client implementation for Python, including PKCE."""

    # Flows stores the state, code_verifier and nonce of all current flows.
    flows = {}

    # HTTP session to be used
    http_session: aiohttp.ClientSession = None

    # OIDC Discovery tool to be used
    discovery_class: OIDCDiscoveryClient = None

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
        self.id_token_signing_alg = kwargs.get("id_token_signing_alg", DEFAULT_ID_TOKEN_SIGNING_ALGORITHM)

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
        
        self.verbose_debug_mode = kwargs.get("enable_verbose_debug_mode", False)
        if self.verbose_debug_mode:
            _LOGGER.warning(
                "VERBOSE_DEBUG_MODE is enabled so detailed token request and response "
                + "logging is active. Do NOT leave this enabled in production!"
            )
            self.capture_dir = Path(self.hass.config.config_dir) / "custom_components" / "auth_oidc" / "verbose_debug"
            self.capture_dir.mkdir(parents=True, exist_ok=True)
            _LOGGER.info(f"The following scopes will be included in auth request: {self.scope}")
        if self.verbose_debug_mode:
            _LOGGER.debug(
                "Configured ID token signing algorithm: %s",
                self.id_token_signing_alg or "none (will use OP discovery)"
            )
    def __del__(self):
        """Cleanup the HTTP session."""

        # HA never seems to run this, but it's good practice to close the session
        if self.http_session:
            _LOGGER.debug("Closing HTTP session")
            self.http_session.close()

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

    async def _make_token_request(self, token_endpoint, query_params):
        """Performs the token POST call"""
        try:
            session = await self._get_http_session()
            
            if self.verbose_debug_mode:
                _LOGGER.debug(f"Attempting Token request via Endpoint URL: {token_endpoint}")
                token_req_txt = self.capture_dir / "get_token.txt"
                async with aiofiles.open(token_req_txt, 'w', encoding='utf-8') as f:
                    await f.write(
                        "/*\n----------BEGIN TOKEN REQUEST----------\n"
                        f"Token Endpoint URL: {token_endpoint}\n*/\n"
                        f"//Query Parameters:\n{json.dumps(query_params, indent=2)}\n\n"
                    )
                _LOGGER.debug("Check Token request capture in: %s for more details...", token_req_txt)

            async with session.post(token_endpoint, data=query_params) as response:
                await http_raise_for_status(response)
                response_text = await response.text()
            
                if self.verbose_debug_mode:
                    _LOGGER.debug(f"Token response received: Status {response.status}")
                    async with aiofiles.open(token_req_txt, 'a', encoding='utf-8') as f:
                        await f.write(
                            "/*\n----------BEGIN TOKEN RESPONSE----------\n"
                            f"Fetch Token Status: {response.status}\n*/\n"
                            f"//Response Body:\n{response_text}\n"
                        )
                    _LOGGER.debug("Check Token response capture in: %s for more details...", token_req_txt)

                try:
                    parsed_json = json.loads(response_text)
                    if self.verbose_debug_mode:
                        _LOGGER.debug(f"Success! Token received from Endpoint: {token_endpoint}")
                    return parsed_json
                except json.JSONDecodeError:
                    if self.verbose_debug_mode:
                        unhandled_txt = self.capture_dir / "unhandled_token_response.txt"
                        async with aiofiles.open(unhandled_txt, 'w', encoding='utf-8') as f:
                            await f.write(response_text)
                    _LOGGER.error("Unhandled Exception: Token Response is not json!")
                    raise OIDCTokenResponseInvalid("Token response not JSON")
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
            
            if self.verbose_debug_mode:
                _LOGGER.debug(f"Sending request to: {userinfo_uri} to collect Userinfo")
                userinfo_txt = self.capture_dir / "get_userinfo.txt"
                async with aiofiles.open(userinfo_txt, 'w', encoding='utf-8') as f:
                    await f.write(
                        "/*\n----------BEGIN USERINFO REQUEST----------\n"
                        f"Userinfo URL: {userinfo_uri}\n*/\n"
                        f"//Request Headers:\n{json.dumps(headers, indent=2)}\n\n"
                    )
                _LOGGER.debug("Check Userinfo request capture in: %s for more details...", userinfo_txt)

            async with session.get(userinfo_uri, headers=headers) as response:
                await http_raise_for_status(response)
                response_text = await response.text()
                
                if self.verbose_debug_mode:
                    _LOGGER.debug(f"Userinfo response received: Status {response.status}")
                    async with aiofiles.open(userinfo_txt, 'a', encoding='utf-8') as f:
                        await f.write(
                            "/*\n----------BEGIN USERINFO RESPONSE----------\n"
                            f"Userinfo Response Status: {response.status}\n*/\n"
                            f"//Response Body:\n{response_text}\n"
                        )
                    _LOGGER.debug("Check Userinfo response capture in: %s for more details...", userinfo_txt)
                
                return json.loads(response_text)
        except HTTPClientError as e:
            _LOGGER.warning("Error fetching userinfo: %s", e)
            raise OIDCUserinfoInvalid from e

    async def _fetch_discovery_document(self):
        """Fetches discovery document."""
        if self.discovery_document is not None:
            return self.discovery_document

        if self.discovery_class is None:
            session = await self._get_http_session()
            self.discovery_class = OIDCDiscoveryClient(
                discovery_url=self.discovery_url,
                http_session=session,
                verification_context={
                    "id_token_signing_alg": self.id_token_signing_alg,
                },
            )
            # Pass verbose context (additive)
            self.discovery_class.verbose_debug_mode = self.verbose_debug_mode
            self.discovery_class.capture_dir = self.capture_dir

        self.discovery_document = await self.discovery_class.fetch_discovery_document()
        return self.discovery_document

    async def _fetch_jwks(self, jwks_uri: str):
        """Fetches JWKS."""
        return await self.discovery_class.fetch_jwks(jwks_uri)

    async def _parse_id_token(self, id_token: str) -> Optional[dict]:
        """Parses the ID token into a dict containing token contents."""
        if self.discovery_document is None:
            self.discovery_document = await self._fetch_discovery_document()
        
        # Flexible algorithm handling
        allowed_algs = compute_allowed_signing_algs(
            self.discovery_document,
            self.id_token_signing_alg,
            self.verbose_debug_mode,
            _LOGGER,
        )

        jwks_uri = self.discovery_document["jwks_uri"]
        jwks_data = await self._fetch_jwks(jwks_uri)

        try:
            # Obtain the (unverified) id_token header
            token_obj = jws.extract_compact(id_token.encode())
            unverified_header = token_obj.protected
            if not unverified_header:
                _LOGGER.warning("Could not get header from received id_token.")
                return None

            # Obtain the signing algorithm from the header of the id_token
            alg = unverified_header.get("alg")
            if not alg:
                _LOGGER.warning("JWT does not have alg")
                return None

            if alg not in allowed_algs:
                _LOGGER.warning(
                    "ID Token received signed with unsupported algorithm: %s (allowed: %s)",
                    alg, allowed_algs
                )
                raise OIDCIdTokenSigningAlgorithmInvalid
            
            if self.verbose_debug_mode:
                _LOGGER.debug("ID token signed with algorithm '%s'", alg)

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

                jwk_obj = jwk.import_key(
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

                # Get the correct key from the JWKS via: kid
                signing_key = next((key for key in jwks_data["keys"] if key["kid"] == kid), None)

                if not signing_key:
                    _LOGGER.warning("Could not find matching key with kid: %s", kid)
                    return None

                # If signing_key does not have alg, set it to the one passed in the token
                if "alg" not in signing_key:
                    signing_key["alg"] = alg

                # Construct the JWK from the RSA key
                jwk_obj = jwk.import_key(signing_key)

            # Decode the token, decode does not verify it
            decoded_token = jwt.decode(
                id_token,
                jwk_obj,
                # OpenID Connect Core 1.0 Section 3.1.3.7.6
                # The Client MUST validate the signature of all other ID Tokens
                # according to JWS [JWS] using the algorithm specified in the JWT
                # alg Header Parameter.
                algorithms=[alg],
                #algorithms=[self.id_token_signing_alg],
            )

            # Create Claims Registry for validation
            # (aud/iss/sub/exp/nbf/iat + leeway)
            id_token_validator = jwt.JWTClaimsRegistry(
                leeway=5,
                # OpenID Connect Core 1.0 Section 3.1.3.7.3
                # The Client MUST validate that the aud (audience) Claim contains
                # its client_id value registered at the Issuer identified by the
                # iss (issuer) Claim as an audience.
                aud={"essential": True, "value": self.client_id},
                # OpenID Connect Core 1.0 Section 3.1.3.7.2
                # The Issuer Identifier for the OpenID Provider MUST exactly
                # match the value of the iss (issuer) Claim.
                iss={"essential": True, "value": self.discovery_document["issuer"]},
                # OpenID Connect Core 1.0 Section 3.1.3.7.9
                # OpenID Connect Core 1.0 Section 3.1.3.7.10
                # No need to specify exp, nbf, iat, they are in here by default
                sub={"essential": True},
            )

            id_token_validator.validate(decoded_token.claims)
            
            # Nonce check (post-decode, per spec §3.1.3.7.11) - assume checked earlier in flow
            # at_hash omitted for brevity (add if access_token passed)

            return decoded_token.claims

        except (joserfc_errors.JoseError, jwt.JWTClaimsError) as e:
            _LOGGER.warning("JWT verification failed: %s", e)
            return None

    async def async_get_authorization_url(self, redirect_uri: str) -> Optional[str]:
        """Generates the authorization URL for the OIDC flow."""
        try:
            discovery_document = await self._fetch_discovery_document()
            auth_endpoint = discovery_document["authorization_endpoint"]

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
        discovery_document = await self._fetch_discovery_document()
        if "userinfo_endpoint" in discovery_document:
            userinfo_endpoint = discovery_document["userinfo_endpoint"]
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
                f"{discovery_document['issuer']}.{id_token.get('sub')}".encode("utf-8")
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

            discovery_document = await self._fetch_discovery_document()
            token_endpoint = discovery_document["token_endpoint"]

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

            # Parse the id token to obtain the relevant details
            id_token = await self._parse_id_token(id_token)

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

            access_token = token_response.get("access_token")
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
