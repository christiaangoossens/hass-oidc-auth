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
from .helpers import compute_allowed_signing_algs, capture_auth_flows

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
    NETWORK_USERINFO_FALLBACK,
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


class OIDCIdTokenInvalid(OIDCClientException):
    """Raised when the ID token is invalid, unverifiable, or claims validation fails."""


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
        verbose_mode = getattr(self, "verbose_debug_mode", False)
        capture_dir = getattr(self, "capture_dir", None)

        try:
            await capture_auth_flows(
                (_LOGGER, 10),  # logger.DEBUG is 10
                verbose_mode,
                capture_dir,
                f"Attempting to fetch discovery document from: {self.discovery_url}",
                "get_discovery.txt",
                f"Discovery Endpoint URL: {self.discovery_url}",
                mode="w",
                header="",
                is_request=True,
            )

            async with self.http_session.get(self.discovery_url) as response:
                await http_raise_for_status(response)
                response_text = await response.text()

                await capture_auth_flows(
                    (_LOGGER, 10),
                    verbose_mode,
                    capture_dir,
                    f"Discovery response received: Status {response.status}",
                    "get_discovery.txt",
                    f"Fetch Discovery Doc Response Status: {response.status}\n//Response Body:\n{response_text}",
                    mode="a",
                    header="",
                    is_request=False,
                )

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
        verbose_mode = getattr(self, "verbose_debug_mode", False)
        capture_dir = getattr(self, "capture_dir", None)

        try:
            await capture_auth_flows(
                (_LOGGER, 10),
                verbose_mode,
                capture_dir,
                f"Retrieving JWKS keys from endpoint: {jwks_uri}",
                "get_jwks.txt",
                f"JWKS Endpoint URL: {jwks_uri}",
                mode="w",
                header="",
                is_request=True,
            )

            async with self.http_session.get(jwks_uri) as response:
                await http_raise_for_status(response)
                response_text = await response.text()

                await capture_auth_flows(
                    (_LOGGER, 10),
                    verbose_mode,
                    capture_dir,
                    f"JWKS response received: Status {response.status}",
                    "get_jwks.txt",
                    f"Fetch JWKS Keys Status: {response.status}\n//Response Body:\n{response_text}",
                    mode="a",
                    header="",
                    is_request=False,
                )

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

        # OpenID Connect Discovery 1.0 §2.1 & Core 1.0 §3.1.3.7.2: Explicitly validate
        # that the 'issuer' from discovery document exactly matches the discovery URL
        # (normalized: scheme/host only, lowercase scheme, no path/query/fragment).
        # Prevents issuer mismatch attacks or misconfigs.
        def normalize_issuer(issuer_url: str) -> str:
            """Normalize issuer URL per OIDC §8.1 (scheme/host only, lowercase scheme)."""
            parsed = urllib.parse.urlparse(issuer_url.rstrip("/"))
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

        expected_issuer = normalize_issuer(self.discovery_url)
        actual_issuer = normalize_issuer(document["issuer"])
        if expected_issuer != actual_issuer:
            _LOGGER.warning(
                "Error: Discovery issuer mismatch. Expected (normalized): %s, got: %s",
                expected_issuer,
                actual_issuer,
            )
            raise OIDCDiscoveryInvalid(
                type="issuer_mismatch",
                details={"expected": expected_issuer, "actual": actual_issuer},
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
        # Instance-level discovery caching with TTL (1h) for efficiency/freshness
        # Prevents stale data on OP endpoint/JWKS rotations while minimizing fetches.
        self.discovery_timestamp = None
        self.discovery_ttl = 3600  # 1 hour
        self.client_id = client_id
        self.scope = scope

        # Optional parameters
        self.client_secret = kwargs.get("client_secret")

        # Default id_token_signing_alg to RS256 if not specified
        self.id_token_signing_alg = kwargs.get(
            "id_token_signing_alg", DEFAULT_ID_TOKEN_SIGNING_ALGORITHM
        )

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
        self.userinfo_fallback = network.get(NETWORK_USERINFO_FALLBACK, False)

        self.verbose_debug_mode = kwargs.get("enable_verbose_debug_mode", False)
        if self.verbose_debug_mode:
            _LOGGER.warning(
                "VERBOSE_DEBUG_MODE is enabled so detailed token request and response "
                + "logging is active. Do NOT leave this enabled in production!"
            )
            self.capture_dir = (
                Path(self.hass.config.config_dir)
                / "custom_components"
                / "auth_oidc"
                / "verbose_debug"
            )
            self.capture_dir.mkdir(parents=True, exist_ok=True)
            _LOGGER.info(
                f"The following scopes will be included in auth request: {self.scope}"
            )
        if self.verbose_debug_mode:
            _LOGGER.debug(
                "Configured ID token signing algorithm: %s",
                self.id_token_signing_alg or "none (will use OP discovery)",
            )

        # Flows stores the state, code_verifier and nonce of all current flows.
        # Made instance-level to prevent collisions across multiple OIDCClient instances
        # (e.g., multiple providers). Previously class-level caused state sharing/leaks.
        self.flows = {}

    def __del__(self):
        """Cleanup the HTTP session."""

        # HA never seems to run this, but it's good practice to close the session
        if self.http_session:
            _LOGGER.debug("Closing HTTP session")
            self.http_session.close()

    def _base64url_encode(self, value: bytes) -> str:
        """Uses base64url encoding on a given byte string"""
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

            await capture_auth_flows(
                (_LOGGER, 10),
                self.verbose_debug_mode,
                self.capture_dir,
                f"Attempting Token request via Endpoint URL: {token_endpoint}",
                "get_token.txt",
                f"Token Endpoint URL: {token_endpoint}\n//Query Parameters:\n{json.dumps(query_params, indent=2)}",
                mode="w",
                header="",
                is_request=True,
            )

            async with session.post(token_endpoint, data=query_params) as response:
                await http_raise_for_status(response)
                response_text = await response.text()

                await capture_auth_flows(
                    (_LOGGER, 10),
                    self.verbose_debug_mode,
                    self.capture_dir,
                    f"Token response received: Status {response.status}",
                    "get_token.txt",
                    f"Fetch Token Status: {response.status}\n//Response Body:\n{response_text}",
                    mode="a",
                    header="",
                    is_request=False,
                )

                try:
                    parsed_json = json.loads(response_text)
                    if self.verbose_debug_mode:
                        _LOGGER.debug(
                            f"Success! Token received from Endpoint: {token_endpoint}"
                        )
                    return parsed_json
                except json.JSONDecodeError:
                    await capture_auth_flows(
                        (_LOGGER, 10),
                        self.verbose_debug_mode,
                        self.capture_dir,
                        "Unhandled token response (not JSON)",
                        "unhandled_token_response.txt",
                        response_text,
                        mode="w",
                        header="",
                        is_request=False,
                    )
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

            await capture_auth_flows(
                (_LOGGER, 10),
                self.verbose_debug_mode,
                self.capture_dir,
                f"Sending request to: {userinfo_uri} to collect Userinfo",
                "get_userinfo.txt",
                f"Userinfo URL: {userinfo_uri}\n//Request Headers:\n{json.dumps(headers, indent=2)}",
                mode="w",
                header="",
                is_request=True,
            )

            async with session.get(userinfo_uri, headers=headers) as response:
                await http_raise_for_status(response)
                response_text = await response.text()

                await capture_auth_flows(
                    (_LOGGER, 10),
                    self.verbose_debug_mode,
                    self.capture_dir,
                    f"Userinfo response received: Status {response.status}",
                    "get_userinfo.txt",
                    f"Userinfo Response Status: {response.status}\n//Response Body:\n{response_text}",
                    mode="a",
                    header="",
                    is_request=False,
                )

                return json.loads(response_text)
        except HTTPClientError as e:
            _LOGGER.warning("Error fetching userinfo: %s", e)
            raise OIDCUserinfoInvalid from e

    async def _fetch_discovery_document(self):
        """Fetches discovery document if missing or expired (TTL=1h)."""
        import time  # Local import for TTL check

        now = time.time()
        if (
            self.discovery_document is not None
            and self.discovery_timestamp is not None
            and (now - self.discovery_timestamp) < self.discovery_ttl
        ):
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
        self.discovery_timestamp = now
        return self.discovery_document

    async def _fetch_jwks(self, jwks_uri: str):
        """Fetches JWKS."""
        return await self.discovery_class.fetch_jwks(jwks_uri)

    async def _parse_id_token(
        self, id_token: str, access_token: Optional[str] = None
    ) -> Optional[dict]:
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
                    alg,
                    allowed_algs,
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
                        "k": self._base64url_encode(
                            self.client_secret.encode("utf-8")
                        ),  # RFC 7517 §4.2: base64url without padding
                        "alg": alg,
                    }
                )

            else:
                # RFC 7515 (JWS) §4.1.11: "kid" (Key ID) is OPTIONAL but RECOMMENDED.
                # If absent, select key via other means (e.g., try candidates until verification succeeds).
                # Priority: 1. Exact "kid" match. 2. Matching key["alg"]. 3. All keys.
                # OpenID Connect Core 1.0 §3.1.3.7: MUST validate signature using header "alg".
                # RFC 7518 (JWK) §7.2: Inherit "alg" from header if missing in key.
                kid = unverified_header.get("kid")
                if not kid:
                    if self.verbose_debug_mode:
                        _LOGGER.debug(
                            "JWT header lacks 'kid'; will try all JWKS candidates"
                        )
                    else:
                        _LOGGER.warning(
                            "JWT does not have 'kid' (Key ID); trying all JWKS keys (add 'kid' to provider config for efficiency)"
                        )

                # Collect candidate keys from JWKS (jwks_data["keys"] is list of dicts)
                candidates = []
                if kid:
                    # Priority 1: Exact kid match
                    matching_kid = next(
                        (key for key in jwks_data["keys"] if key.get("kid") == kid),
                        None,
                    )
                    if matching_kid:
                        candidates.append(matching_kid)
                        if self.verbose_debug_mode:
                            _LOGGER.debug(
                                "Selected JWKS key by exact 'kid' match: %s", kid
                            )

                # Priority 2-3: No kid or no match → add keys matching alg, then all (avoid dupes)
                for key in jwks_data["keys"]:
                    if key.get("alg") == alg:
                        if key not in candidates:  # Avoid dupes
                            candidates.append(key)
                            if self.verbose_debug_mode:
                                _LOGGER.debug(
                                    "Added JWKS candidate by 'alg' match: %s (kid=%s)",
                                    alg,
                                    key.get("kid", "none"),
                                )
                    elif (
                        kid is None or key.get("kid") != kid
                    ) and key not in candidates:  # Fallback: all non-dupe keys
                        candidates.append(key)
                        if self.verbose_debug_mode:
                            _LOGGER.debug(
                                "Added JWKS fallback candidate (kid=%s, alg=%s)",
                                key.get("kid", "none"),
                                key.get("alg", "none"),
                            )

                if not candidates:
                    _LOGGER.warning(
                        "No candidate keys found in JWKS for alg '%s' (kid='%s')",
                        alg,
                        kid or "none",
                    )
                    return None

                # Try verification on each candidate until success (RFC 7515 compliant)
                decoded_token = None
                selected_key_info = None
                for candidate_key in candidates:
                    try:
                        # If key lacks "alg", inherit from header (per JWK §7.2, optional)
                        key_dict = candidate_key.copy()
                        if "alg" not in key_dict:
                            key_dict["alg"] = alg

                        jwk_obj = jwk.import_key(key_dict)

                        # Attempt decode+verify (raises on sig fail/mismatch)
                        candidate_decoded = jwt.decode(
                            id_token,
                            jwk_obj,
                            # OpenID Connect Core 1.0 Section 3.1.3.7.6
                            # The Client MUST validate the signature of all other ID Tokens
                            # according to JWS [JWS] using the algorithm specified in the JWT
                            # alg Header Parameter.
                            algorithms=[alg],
                        )
                        decoded_token = candidate_decoded
                        selected_key_info = {
                            "kid": candidate_key.get("kid", "none"),
                            "alg": candidate_key.get("alg", alg),
                            "kty": candidate_key.get("kty"),
                        }
                        if self.verbose_debug_mode:
                            _LOGGER.debug(
                                "Signature verified successfully with JWKS key: %s",
                                selected_key_info,
                            )
                        break  # Success! Proceed
                    except (joserfc_errors.JoseError, jwt.JWTClaimsError) as verify_err:
                        if self.verbose_debug_mode:
                            _LOGGER.debug(
                                "Key candidate failed verification (kid=%s): %s",
                                candidate_key.get("kid", "none"),
                                verify_err,
                            )
                        continue  # Try next

                if decoded_token is None:
                    _LOGGER.warning(
                        "No JWKS key verified the ID token signature (alg='%s', tried %d candidates; check JWKS rotation/provider config)",
                        alg,
                        len(candidates),
                    )
                    return None

                # Log successful key selection
                if self.verbose_debug_mode:
                    _LOGGER.debug(
                        "Final selected key for verification: %s", selected_key_info
                    )

            # Claims validation (post-signature verification)
            # Create Claims Registry for validation (aud/iss/sub/exp/nbf/iat + leeway)
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

            # OpenID Connect Core 1.0 §3.1.3.6: Validate at_hash if access_token present
            # Binds ID token to access_token (prevents tampering/replay).
            # at_hash = base64url(SHA256(left half of access_token))[0:hash_len/2]
            if access_token:  # Pass access_token to method
                try:
                    # Compute at_hash (OpenID Connect Core §3.1.3.6)
                    access_token_bytes = access_token.encode("utf-8")
                    hashed_access_token = hashlib.sha256(access_token_bytes).digest()
                    left_half_hash = hashed_access_token[
                        : len(hashed_access_token) // 2
                    ]
                    expected_at_hash = self._base64url_encode(left_half_hash)

                    actual_at_hash = decoded_token.claims.get("at_hash")
                    if actual_at_hash != expected_at_hash:
                        _LOGGER.warning(
                            "ID token at_hash mismatch! Expected: %s, got: %s (access_token tampering?)",
                            expected_at_hash,
                            actual_at_hash,
                        )
                        return None
                    if self.verbose_debug_mode:
                        _LOGGER.debug("at_hash validated successfully")
                except Exception as e:
                    _LOGGER.warning("at_hash computation/validation failed: %s", e)
                    return None  # Fail closed

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
            else:
                # Warn once per-flow if PKCE disabled (security risk for legacy OPs)
                _LOGGER.warning(
                    "PKCE (RFC 7636) disabled via features.disable_rfc7636! "
                    "Authorization code interception risk increased. Only for legacy OPs."
                )

            url = f"{auth_endpoint}?{urllib.parse.urlencode(query_params)}"
            return url
        except OIDCClientException as e:
            _LOGGER.warning("Error generating authorization URL: %s", e)
            return None

    async def parse_user_details(
        self, id_token_claims: dict, access_token: str
    ) -> UserDetails:
        """Parses the ID token and/or userinfo into user details."""

        # Fetch userinfo if there is an userinfo_endpoint available
        # and use the data to supply the missing values in id_token
        discovery_document = await self._fetch_discovery_document()
        userinfo_endpoint = discovery_document.get("userinfo_endpoint")
        # Users may attempt fallback userinfo endpoint if OP doesn't advertise it
        # Commonly /userinfo even if not in discovery document
        if not userinfo_endpoint and self.userinfo_fallback:
            userinfo_endpoint = f"{discovery_document['issuer'].rstrip('/')}/userinfo"
            _LOGGER.info("Using userinfo fallback endpoint: %s", userinfo_endpoint)
        if userinfo_endpoint:
            userinfo = await self._get_userinfo(userinfo_endpoint, access_token)

            # Replace missing claims in the id_token with their userinfo version
            for claim in (
                self.groups_claim,
                self.display_name_claim,
                self.username_claim,
            ):
                if claim not in id_token_claims and claim in userinfo:
                    id_token_claims[claim] = userinfo[claim]

        # Get and parse groups (to check if it's an array)
        groups = id_token_claims.get(self.groups_claim, [])
        if not isinstance(groups, list):
            _LOGGER.warning("Groups claim is not a list, using empty list instead.")
            groups = []

        # Extract case insensitive username and apply email stripping if configured to use 'email' claim.
        # This converts full email (e.g., 'user@domain.com') to local-part (e.g., 'user') for username only.
        # 1. Not all OP's support username / preferred_username claim, so email is often used, but
        # this is not ideal for usernames in HA (even without username linking support **currently**).
        # 2. Many RPs/OPs provide some level of claim matching / processing to increase flexibility.
        username_raw = id_token_claims.get(self.username_claim)
        username = username_raw
        if (
            (self.username_claim.lower() in ["email", "e-mail"])
            and username_raw
            and "@" in username_raw
        ):
            username = username_raw.split("@")[0]
            if self.verbose_debug_mode:
                _LOGGER.debug(
                    "Stripped email '%s' to username '%s' (local-part before '@')",
                    username_raw,
                    username,
                )

        # Assign role if user has the required groups
        role = "invalid"
        if self.user_role in groups or self.user_role is None:
            role = "system-users"

        if self.admin_role in groups:
            role = "system-admin"

        # Create a user details dict based on the contents of the id_token & userinfo
        # Note: if user username claim is email, will be processed with local var 'username' above
        # Other claims use originals from id_token_claims/userinfo merge.
        return {
            # Subject Identifier. A locally unique and never reassigned identifier within the
            # Issuer for the End-User, which is intended to be consumed by the Client
            # Only unique per issuer, so we combine it with the issuer and hash it.
            # This might allow multiple OIDC providers to be used with this integration.
            "sub": hashlib.sha256(
                f"{discovery_document['issuer']}.{id_token_claims.get('sub')}".encode(
                    "utf-8"
                )
            ).hexdigest(),
            # Display name, configurable
            "display_name": id_token_claims.get(self.display_name_claim),
            # Username, configurable (uses processed 'username' var: email-stripped if applicable
            "username": username,
            # Role
            "role": role,
        }

    async def async_complete_token_flow(
        self, redirect_uri: str, code: str, state: str
    ) -> Optional[UserDetails]:
        """Completes the OIDC token flow to obtain a user's details."""

        try:
            flow = self.flows.pop(state, None)
            if flow is None:
                raise OIDCStateInvalid

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

            id_token_str = token_response.get("id_token")
            access_token = token_response.get("access_token")

            # Parse the id token to obtain the relevant details
            id_token_claims = await self._parse_id_token(
                id_token_str, access_token=access_token
            )
            if id_token_claims is None:
                _LOGGER.warning("ID token could not be parsed!")
                return None

            # OpenID Connect Core 1.0 Section 3.1.3.7.11
            # If a nonce value was sent in the Authentication Request,
            # a nonce Claim MUST be present and its value checked to verify
            # that it is the same value as the one that was sent in the Authentication Request.
            if id_token_claims.get("nonce") != flow["nonce"]:
                _LOGGER.warning("Nonce mismatch!")
                return None

            data = await self.parse_user_details(id_token_claims, access_token)

            # Log which details were obtained for debugging
            # Also log the original subject identifier such that you can look it up in your provider
            _LOGGER.debug(
                "Obtained user details from OIDC provider: %s (issuer subject: %s)",
                data,
                id_token_claims.get("sub"),
            )
            return data
        except OIDCClientException as e:
            _LOGGER.warning("Failed to complete token flow, returning None. (%s)", e)
            return None
