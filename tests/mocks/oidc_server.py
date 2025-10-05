"""A simple mock OIDC server for testing purposes."""

import time
import logging
import random
from urllib.parse import urlparse, parse_qs
from joserfc import jwt
from joserfc.jwk import RSAKey, KeySet

_LOGGER = logging.getLogger(__name__)


class MockOIDCServer:
    """A simple mock OIDC server for testing purposes."""

    _base_url = "https://mock-oidc-server.com"
    _code_storage = {}

    def __init__(self):
        """Initialize the mock OIDC server."""
        # Create a JWK private key
        self._jwk = RSAKey.generate_key(
            2048, {"alg": "RS256", "use": "sig"}, private=True, auto_kid=True
        )

    def get_random_code(self):
        """Return a random authorization code."""
        return "".join(str(random.randint(0, 9)) for _ in range(6))

    def get_discovery_url(self):
        """Return the discovery URL for the given base URL."""
        return f"{self._base_url}/.well-known/openid-configuration"

    def get_authorize_url(self):
        """Return the authorization URL for the given base URL."""
        return f"{self._base_url}/authorize"

    def process_request(self, url: str, method: str, body: dict) -> tuple[dict, int]:
        """Process a request to the mock OIDC server."""
        _LOGGER.debug("Received %s request to %s in OIDC mock server", method, url)

        if url == self.get_discovery_url() and method == "GET":
            response = self._get_discovery_document()
        elif url.startswith(self.get_authorize_url()) and method == "GET":
            response = self._get_authorize_response(url)
        elif url == f"{self._base_url}/token" and method == "POST":
            response = self._get_token_response(body)
        elif url == f"{self._base_url}/jwks" and method == "GET":
            response = self._get_jwks_response()
        else:
            response = {"error": "Unknown endpoint"}, 404

        _LOGGER.debug("Responding with: %s", response)
        return response

    def _get_discovery_document(self) -> tuple[dict, int]:
        """Return a mock discovery document."""
        return {
            "issuer": self._base_url,
            "authorization_endpoint": self.get_authorize_url(),
            "token_endpoint": f"{self._base_url}/token",
            "userinfo_endpoint": f"{self._base_url}/userinfo",
            "jwks_uri": f"{self._base_url}/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }, 200

    def _get_authorize_response(self, url: str) -> tuple[dict, int]:
        """Return a mock authorization response."""
        # Parse the url
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        code = self.get_random_code()
        self._code_storage[code] = query_params

        return {"code": code, "state": "xyz"}, 200

    def _get_token_response(self, body: dict) -> tuple[dict, int]:
        """Return a mock token response."""

        if body.get("code") in self._code_storage:
            # TODO: Verify PKCE?
            return {
                "access_token": "exampleAccessToken",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": self._create_id_token(body.get("code")),
            }, 200
        else:
            return {"error": "invalid_request"}, 400

    def _create_id_token(self, code: str) -> str:
        """Create a mock ID token."""
        # Get the query params
        if code not in self._code_storage:
            raise ValueError("Invalid code")
        query_params = self._code_storage[code]
        _LOGGER.debug("Creating ID token with query params: %s", query_params)

        # Create a simple signed JWT with our JWK
        header = {"alg": self._jwk.alg, "kid": self._jwk.kid}
        claims = {
            "iss": self._base_url,
            "sub": "1234567890",
            "aud": query_params.get("client_id", [""])[0],
            "nonce": query_params.get("nonce", [""])[0],
        }

        now = int(time.time())
        claims["nbf"] = now
        claims["iat"] = now
        claims["exp"] = now + 3600  # 1 hour expiry

        return jwt.encode(header, claims, self._jwk)

    def _get_jwks_response(self) -> tuple[dict, int]:
        """Return a mock JWKS response."""
        private_key = self._jwk
        public_key_dict = private_key.as_dict(private=False)
        public_key = RSAKey.import_key(
            public_key_dict, {"use": "sig", "alg": "RS256", "kid": private_key.kid}
        )

        key_set = KeySet([public_key])

        return key_set.as_dict(), 200
