"""Provider catalog and helpers for OIDC providers."""

from __future__ import annotations
from typing import Any, Dict

from .const import OIDC_PROVIDERS, REPO_ROOT_URL


def get_provider_config(key: str) -> Dict[str, Any]:
    """Return provider configuration by key."""
    return OIDC_PROVIDERS.get(key, {})


def get_provider_name(key: str | None) -> str:
    """Return provider display name by key."""
    if not key:
        return "Unknown Provider"
    return OIDC_PROVIDERS.get(key, {}).get("name", "Unknown Provider")


def get_provider_docs_url(key: str | None) -> str:
    """Return documentation URL for a provider key."""
    base_url = REPO_ROOT_URL + "/docs/provider-configurations"

    provider_docs = {
        "authentik": f"{base_url}/authentik.md",
        "authelia": f"{base_url}/authelia.md",
        "pocketid": f"{base_url}/pocket-id.md",
        "kanidm": f"{base_url}/kanidm.md",
        "microsoft": f"{base_url}/microsoft-entra.md",
    }

    if key in provider_docs:
        return provider_docs[key]
    return REPO_ROOT_URL + "/docs/configuration.md"
