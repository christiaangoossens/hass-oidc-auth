"""A simple mock OIDC server for testing purposes."""

import base64
import hashlib
import json
import logging
import os
import random
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

_LOGGER = logging.getLogger(__name__)

BASE_URL = "https://oidc.example.com"
SUBJECT = "testuser"
ACCESS_TOKEN = "exampleAccessToken"

AuthorizeParams = dict[str, list[str]]


class MockOIDCServer:
    """A simple mock OIDC server for testing purposes.

    A scenario file can override the discovery document ("discovery"),
    the subject ("subject"), the username ("username"), the userinfo
    response ("userinfo") and
    require a client secret at the token endpoint ("client_secret").
    """

    def __init__(self, scenario: str | None = None):
        """Initialize the mock OIDC server."""
        self._jwk = RSAKey.generate_key(
            2048, {"alg": "RS256", "use": "sig"}, private=True, auto_kid=True
        )
        self._scenario: dict[str, Any] = {}
        self._code_storage: dict[str, AuthorizeParams] = {}
        self.last_token_request: dict[str, str] | None = None

        # Path -> error raised when that endpoint is requested
        self.failing_paths: dict[str, Exception] = {}

        if scenario:
            scenario_path = os.path.join(
                os.path.dirname(__file__), "scenarios", f"{scenario}.json"
            )
            with open(scenario_path, "r", encoding="utf-8") as f:
                self._scenario = json.load(f)

            _LOGGER.debug("Loaded scenario: %s", self._scenario)

    def get_random_code(self) -> str:
        """Return a random authorization code."""
        return "".join(str(random.randint(0, 9)) for _ in range(6))

    @staticmethod
    def get_discovery_url() -> str:
        """Return the discovery URL for the given base URL."""
        return f"{BASE_URL}/.well-known/openid-configuration"

    @staticmethod
    def get_authorize_url() -> str:
        """Return the authorization URL for the given base URL."""
        return f"{BASE_URL}/authorize"

    def process_request(
        self, url: str, method: str, body: dict[str, str] | None
    ) -> tuple[Any, int]:
        """Process a request to the mock OIDC server."""
        _LOGGER.debug("Received %s request to %s in OIDC mock server", method, url)

        if url == self.get_discovery_url() and method == "GET":
            response = self._get_discovery_document()
        elif url.startswith(self.get_authorize_url()) and method == "GET":
            response = self._get_authorize_response(url)
        elif url == f"{BASE_URL}/token" and method == "POST":
            response = self._get_token_response(body or {})
        elif url == f"{BASE_URL}/jwks" and method == "GET":
            response = self._get_jwks_response()
        elif url == f"{BASE_URL}/userinfo" and method == "GET":
            response = self._get_userinfo_response()
        else:
            response = {"error": "Unknown endpoint"}, 404

        _LOGGER.debug("Responding with: %s", response)
        return response

    def _get_username(self) -> str:
        """Return the username this server reports for the user."""
        return self._scenario.get("username", "testuser")

    def _get_subject(self) -> str:
        """Return the subject this server reports for the user."""
        return self._scenario.get("subject", SUBJECT)

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
        query_params = parse_qs(urlparse(url).query)

        code = self.get_random_code()
        self._code_storage[code] = query_params

        return {"code": code, "state": "xyz"}, 200

    def _get_token_response(self, body: dict[str, str]) -> tuple[dict, int]:
        """Return a mock token response, using up the authorization code."""
        self.last_token_request = body

        query_params = self._code_storage.pop(body.get("code", ""), None)
        if query_params is None:
            return {"error": "invalid_grant"}, 400

        if not self._is_pkce_valid(query_params, body.get("code_verifier")):
            return {"error": "invalid_grant"}, 400

        required_secret = self._scenario.get("client_secret")
        if required_secret is not None and body.get("client_secret") != required_secret:
            return {"error": "invalid_client"}, 401

        return {
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": self._create_id_token(query_params),
        }, 200

    @staticmethod
    def _is_pkce_valid(query_params: AuthorizeParams, verifier: str | None) -> bool:
        """Check the PKCE verifier against the challenge sent to /authorize."""
        challenges = query_params.get("code_challenge")
        if not challenges:
            return True

        if verifier is None:
            return False

        digest = hashlib.sha256(verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return expected == challenges[0]

    def _create_id_token(self, query_params: AuthorizeParams) -> str:
        """Create a mock ID token for the given authorization request."""
        _LOGGER.debug("Creating ID token with query params: %s", query_params)

        header = {"alg": self._jwk.alg, "kid": self._jwk.kid}
        now = int(time.time())
        claims = {
            "iss": BASE_URL,
            "sub": self._get_subject(),
            "aud": query_params.get("client_id", [""])[0],
            "nonce": query_params.get("nonce", [""])[0],
            "name": "Test Name",
            "preferred_username": self._get_username(),
            "nbf": now,
            "iat": now,
            "exp": now + 3600,
        }

        return jwt.encode(header, claims, self._jwk)

    def _get_jwks_response(self) -> tuple[dict, int]:
        """Return a mock JWKS response with only the public key."""
        return dict(KeySet([self._jwk]).as_dict(private=False)), 200

    def _get_userinfo_response(self) -> tuple[dict, int]:
        """Return a mock userinfo response."""
        if "userinfo" in self._scenario:
            return self._scenario["userinfo"], 200

        return {
            "sub": self._get_subject(),
            "name": "Test Name",
            "preferred_username": self._get_username(),
        }, 200

    @staticmethod
    def get_final_subject(subject: str = SUBJECT) -> str:
        """Return the subject that's returned to HA for the given IdP subject."""
        return hashlib.sha256(f"{BASE_URL}.{subject}".encode()).hexdigest()


def make_mock_response(json_data: Any, status: int) -> AsyncMock:
    """Return a mocked aiohttp response with the given JSON body and status."""
    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.__aexit__.return_value = None
    mock_response.status = status
    mock_response.ok = status < 400
    mock_response.reason = HTTPStatus(status).phrase
    mock_response.json = AsyncMock(return_value=json_data)
    mock_response.text = AsyncMock(return_value=json.dumps(json_data))
    return mock_response


@contextmanager
def mock_oidc_responses(scenario: str | None = None) -> Iterator[MockOIDCServer]:
    """Route aiohttp requests to a mock OIDC server and yield that server."""
    mock_oidc_server = MockOIDCServer(scenario)

    def handle(method: str, url: str, **kwargs: Any) -> AsyncMock:
        _LOGGER.debug("Mocked %s request to %s", method, url)

        if (
            error := mock_oidc_server.failing_paths.get(urlparse(url).path)
        ) is not None:
            raise error

        body = kwargs.get("data") or kwargs.get("json")
        json_data, status = mock_oidc_server.process_request(url, method, body)
        return make_mock_response(json_data, status)

    def get_side_effect(url: str, *_args: Any, **kwargs: Any) -> AsyncMock:
        return handle("GET", url, **kwargs)

    def post_side_effect(url: str, *_args: Any, **kwargs: Any) -> AsyncMock:
        return handle("POST", url, **kwargs)

    with (
        patch("aiohttp.ClientSession.get", side_effect=get_side_effect),
        patch("aiohttp.ClientSession.post", side_effect=post_side_effect),
    ):
        yield mock_oidc_server
