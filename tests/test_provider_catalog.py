"""Tests for the provider catalog helpers."""

import pytest

from custom_components.auth_oidc.config.const import OIDC_PROVIDERS, REPO_ROOT_URL
from custom_components.auth_oidc.config.provider_catalog import (
    get_provider_config,
    get_provider_docs_url,
    get_provider_name,
)


@pytest.mark.parametrize(
    ("provider_key", "expected_name", "expected_supports_groups"),
    [
        ("authentik", "Authentik", True),
        ("generic", "OpenID Connect (SSO)", False),
    ],
)
def test_get_provider_config_and_name(provider_key, expected_name, expected_supports_groups):
    """Known providers should resolve to their configured metadata."""
    config = get_provider_config(provider_key)

    assert config == OIDC_PROVIDERS[provider_key]
    assert get_provider_name(provider_key) == expected_name
    assert config["supports_groups"] is expected_supports_groups


@pytest.mark.parametrize("provider_key", [None, "unknown", ""])
def test_provider_fallbacks(provider_key):
    """Unknown providers should fall back to neutral defaults."""
    assert get_provider_config(provider_key or "unknown") == OIDC_PROVIDERS.get(
        provider_key or "unknown", {}
    )
    assert get_provider_name(provider_key) == "Unknown Provider"
    assert get_provider_docs_url(provider_key) == f"{REPO_ROOT_URL}/docs/configuration.md"


@pytest.mark.parametrize(
    ("provider_key", "expected_suffix"),
    [
        ("authentik", "/docs/provider-configurations/authentik.md"),
        ("authelia", "/docs/provider-configurations/authelia.md"),
        ("pocketid", "/docs/provider-configurations/pocket-id.md"),
        ("kanidm", "/docs/provider-configurations/kanidm.md"),
        ("microsoft", "/docs/provider-configurations/microsoft-entra.md"),
    ],
)
def test_provider_docs_urls(provider_key, expected_suffix):
    """Known providers should point to provider-specific docs."""
    assert get_provider_docs_url(provider_key) == f"{REPO_ROOT_URL}{expected_suffix}"
