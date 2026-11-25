"""Tests for the helpers and validation tools"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from custom_components.auth_oidc.config.const import REPO_ROOT_URL
from custom_components.auth_oidc.tools.helpers import (
    STATE_COOKIE_NAME,
    error_response,
    get_state_id,
    get_url,
    get_valid_state_id,
    get_view,
    html_response,
    template_response,
)
from custom_components.auth_oidc.tools.validation import (
    sanitize_client_secret,
    validate_client_id,
    validate_discovery_url,
    validate_url,
)

# Config values can be anything, the validators must reject what isn't a string
NOT_STRINGS: list[Any] = [42, []]


@pytest.mark.asyncio
async def test_get_url():
    """Test the get_url helper."""

    with pytest.raises(RuntimeError) as excinfo:
        get_url("/test", False)
    assert str(excinfo.value) == "No current request in context"


@pytest.mark.parametrize(
    ("host", "path", "force_https", "expected"),
    [
        ("example.com", "/auth/oidc/welcome", False, "http://example.com/test"),
        ("example.com", "/auth/oidc/welcome", True, "https://example.com/test"),
        (
            "auth.example.com",
            "/auth/oidc/welcome",
            False,
            "http://auth.example.com/test",
        ),
        (
            "authentik-ha.lan:8123",
            "/auth/oidc/callback?code=/auth",
            False,
            "http://authentik-ha.lan:8123/test",
        ),
    ],
)
def test_get_url_uses_request_origin(
    host: str, path: str, force_https: bool, expected: str
):
    """URLs are built from the origin, also for hosts that start with "auth"."""
    with patch("homeassistant.components.http.current_request") as current_request:
        current_request.get.return_value = make_mocked_request(
            "GET", path, headers={"Host": host}
        )

        assert get_url("/test", force_https) == expected


@pytest.mark.asyncio
async def test_get_view():
    """Test the get_view helper."""

    data = await get_view("welcome")
    assert data.startswith("<!DOCTYPE html>")


@pytest.mark.asyncio
async def test_get_state_id():
    """State cookie helper should return cookie value when present."""
    request = make_mocked_request(
        "GET", "/", headers={"Cookie": f"{STATE_COOKIE_NAME}=abc"}
    )
    assert get_state_id(request) == "abc"

    request_without_cookie = make_mocked_request("GET", "/")
    assert get_state_id(request_without_cookie) is None


def test_get_valid_state_id():
    """Valid-state helper should return only existing and valid cookie states."""
    state_store = MagicMock()
    state_store.is_state_valid.return_value = True

    request = make_mocked_request(
        "GET", "/", headers={"Cookie": f"{STATE_COOKIE_NAME}=state-1"}
    )
    state_id = get_valid_state_id(request, state_store)

    assert state_id == "state-1"
    state_store.is_state_valid.assert_called_once_with("state-1", request.remote)


def test_get_valid_state_id_invalid_or_missing_cookie():
    """Valid-state helper should reject missing and invalid states."""
    state_store = MagicMock()
    state_store.is_state_valid.return_value = False

    request = make_mocked_request(
        "GET", "/", headers={"Cookie": f"{STATE_COOKIE_NAME}=state-2"}
    )
    assert get_valid_state_id(request, state_store) is None
    state_store.is_state_valid.assert_called_once_with("state-2", request.remote)

    request_without_cookie = make_mocked_request("GET", "/")
    state_store.is_state_valid.reset_mock()
    assert get_valid_state_id(request_without_cookie, state_store) is None
    state_store.is_state_valid.assert_not_called()


@pytest.mark.asyncio
async def test_html_response_and_template_helpers():
    """Response helpers should preserve status and render HTML views."""
    response = html_response("<p>ok</p>", status=418)
    assert isinstance(response, web.Response)
    assert response.status == 418
    assert response.content_type == "text/html"
    assert response.text == "<p>ok</p>"

    with patch(
        "custom_components.auth_oidc.tools.helpers.get_view",
        new=AsyncMock(return_value="<p>rendered</p>"),
    ) as mocked_get_view:
        rendered = await template_response("welcome", {"name": "OIDC"})

    assert rendered.status == 200
    assert rendered.text == "<p>rendered</p>"
    mocked_get_view.assert_awaited_once_with(
        "welcome", {"name": "OIDC", "help_url": REPO_ROOT_URL}
    )


@pytest.mark.asyncio
async def test_error_response():
    """Error response helper should render the shared error template with status
    and translate the given error key."""
    with patch(
        "custom_components.auth_oidc.tools.helpers.get_view",
        new=AsyncMock(return_value="<p>error</p>"),
    ) as mocked_get_view:
        rendered = await error_response("misconfigured", status=500)

    assert rendered.status == 500
    assert rendered.text == "<p>error</p>"
    mocked_get_view.assert_awaited_once_with(
        "error",
        {
            "error": "Integration is misconfigured, discovery could not be obtained.",
            "help_url": REPO_ROOT_URL,
        },
    )


@pytest.mark.asyncio
async def test_validate_url():
    """Test the validate_url helper."""

    assert not validate_url("ftp://example.com")
    assert validate_url("http://example.com")
    assert validate_url("https://example.com")
    assert not validate_url("example.com")
    assert not any(validate_url(value) for value in NOT_STRINGS)


@pytest.mark.asyncio
async def test_validate_discovery_url():
    """Test the validate_discovery_url helper."""

    assert not validate_discovery_url("ftp://example.com")
    assert not validate_discovery_url("http://example.com")
    assert not validate_discovery_url("https://example.com")
    assert not validate_discovery_url("example.com")
    assert not validate_discovery_url(
        "https://example.com/.well-known/openid_configuration"
    )
    assert validate_discovery_url(
        "https://example.com/.well-known/openid-configuration"
    )
    assert not any(validate_discovery_url(value) for value in NOT_STRINGS)


@pytest.mark.asyncio
async def test_client_secret():
    """Test the sanitize_client_secret helper."""

    assert sanitize_client_secret("test ") == "test"
    assert sanitize_client_secret("test2") == "test2"


@pytest.mark.asyncio
async def test_client_id():
    """Test the validate_client_id helper."""

    assert not validate_client_id(" ")
    assert validate_client_id("test4")
    assert validate_client_id("test4 ")
