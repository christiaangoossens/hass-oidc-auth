"""A simple mock OIDC server for testing purposes."""

from contextlib import contextmanager
import time
import logging
import random
import json
import os
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse, parse_qs
from joserfc import jwt
from joserfc.jwk import RSAKey, KeySet

_LOGGER = logging.getLogger(__name__)

BASE_URL = "https://oidc.example.com"


class MockOIDCServer:
    """A simple mock OIDC server for testing purposes."""

    _code_storage = {}
    _scenario = {}

    def __init__(self, scenario: str | None = None):
        """Initialize the mock OIDC server."""
        # Create a JWK private key
        self._jwk = RSAKey.generate_key(
            2048, {"alg": "RS256", "use": "sig"}, private=True, auto_kid=True
        )

        if scenario:
            # Load scenario JSON file from disk
            scenario_path = os.path.join(
                os.path.dirname(__file__), "scenarios", f"{scenario}.json"
            )
            with open(scenario_path, "r", encoding="utf-8") as f:
                self._scenario = json.load(f)

            # Log it
            _LOGGER.debug("Loaded scenario: %s", self._scenario)

    def get_random_code(self):
        """Return a random authorization code."""
        return "".join(str(random.randint(0, 9)) for _ in range(6))

    @staticmethod
    def get_discovery_url():
        """Return the discovery URL for the given base URL."""
        return f"{BASE_URL}/.well-known/openid-configuration"

    @staticmethod
    def get_authorize_url():
        """Return the authorization URL for the given base URL."""
        return f"{BASE_URL}/authorize"

    def process_request(self, url: str, method: str, body: dict) -> tuple[dict, int]:
        """Process a request to the mock OIDC server."""
        _LOGGER.debug("Received %s request to %s in OIDC mock server", method, url)

        if url == self.get_discovery_url() and method == "GET":
            response = self._get_discovery_document()
        elif url.startswith(self.get_authorize_url()) and method == "GET":
            response = self._get_authorize_response(url)
        elif url == f"{BASE_URL}/token" and method == "POST":
            response = self._get_token_response(body)
        elif url == f"{BASE_URL}/jwks" and method == "GET":
            response = self._get_jwks_response()
        else:
            response = {"error": "Unknown endpoint"}, 404

        _LOGGER.debug("Responding with: %s", response)
        return response

    def _get_discovery_document(self) -> tuple[dict, int]:
        """Return a mock discovery document."""

        if "discovery" in self._scenario:
            return self._scenario["discovery"], 200

        return {
            "issuer": BASE_URL,
            "authorization_endpoint": self.get_authorize_url(),
            "token_endpoint": f"{BASE_URL}/token",
            "userinfo_endpoint": f"{BASE_URL}/userinfo",
            "jwks_uri": f"{BASE_URL}/jwks",
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
            "iss": BASE_URL,
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


@contextmanager
def mock_oidc_responses(scenario: str | None = None):
    """Mock OIDC responses for testing."""

    mock_oidc_server = MockOIDCServer(scenario)

    def make_mock_response(json_data, status):
        mock_response = AsyncMock()
        mock_response.__aenter__.return_value = mock_response
        mock_response.__aexit__.return_value = None
        mock_response.json = AsyncMock(return_value=json_data)
        mock_response.status = status
        return mock_response

    def default_handler(method, url, *args, **kwargs):
        _LOGGER.debug("Mocked %s request to %s", method, url)
        body = kwargs.get("data") or kwargs.get("json") or None
        response = mock_oidc_server.process_request(url, method, body)
        return make_mock_response(response[0], response[1])

    def get_side_effect(url, *args, **kwargs):
        return default_handler("GET", url, *args, **kwargs)

    def post_side_effect(url, *args, **kwargs):
        return default_handler("POST", url, *args, **kwargs)

    with (
        patch("aiohttp.ClientSession.get", side_effect=get_side_effect) as get_patch,
        patch("aiohttp.ClientSession.post", side_effect=post_side_effect) as post_patch,
    ):
        yield (get_patch, post_patch, default_handler)
