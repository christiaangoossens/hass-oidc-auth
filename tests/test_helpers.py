"""Tests for the helpers and validation tools"""

from unittest.mock import patch
import pytest

from aiohttp.test_utils import make_mocked_request

from custom_components.auth_oidc.tools.helpers import get_url, get_view
from custom_components.auth_oidc.tools.validation import (
    validate_client_id,
    sanitize_client_secret,
    validate_discovery_url,
    validate_url,
)


@pytest.mark.asyncio
async def test_get_url():
    """Test the get_url helper."""

    with pytest.raises(RuntimeError) as excinfo:
        get_url("https://example.com", "/test")
    assert str(excinfo.value) == "No current request in context"

    # Mock homeassistant.components.http.current_request.get() to test the force HTTP flag
    with patch("homeassistant.components.http.current_request") as mock_current_request:
        fake_request = make_mocked_request("GET", "http://example.com")
        mock_current_request.get.return_value = fake_request
        result = get_url("/test", True)
        assert result == "https://example.com/test"


@pytest.mark.asyncio
async def test_get_view():
    """Test the get_view helper."""

    data = await get_view("welcome")
    assert data.startswith("<!DOCTYPE html>")


@pytest.mark.asyncio
async def test_validate_url():
    """Test the validate_url helper."""

    assert not validate_url("ftp://example.com")
    assert validate_url("http://example.com")
    assert validate_url("https://example.com")
    assert not validate_url("example.com")
    assert not validate_url(42)
    assert not validate_url([])


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
    assert not validate_discovery_url(2)
    assert not validate_discovery_url([])


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
