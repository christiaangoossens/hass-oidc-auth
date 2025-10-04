"""Provider catalog and helpers for OIDC providers."""

from __future__ import annotations

from typing import Any, Dict

DEFAULT_ADMIN_GROUP = "admins"


OIDC_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "authentik": {
        "name": "Authentik",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "authelia": {
        "name": "Authelia",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "pocketid": {
        "name": "Pocket ID",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "kanidm": {
        "name": "Kanidm",
        "discovery_url": "",
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
    "microsoft": {
        "name": "Microsoft Entra ID",
        "discovery_url": (
            "https://login.microsoftonline.com/common/v2.0/"
            ".well-known/openid_configuration"
        ),
        "default_admin_group": DEFAULT_ADMIN_GROUP,
        "supports_groups": True,
        "claims": {
            "display_name": "name",
            "username": "preferred_username",
            "groups": "groups",
        },
    },
}


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
    base_url = (
        "https://github.com/christiaangoossens/hass-oidc-auth/blob/main"
        "/docs/provider-configurations"
    )

    provider_docs = {
        "authentik": f"{base_url}/authentik.md",
        "authelia": f"{base_url}/authelia.md",
        "pocketid": f"{base_url}/pocket-id.md",
        "kanidm": f"{base_url}/kanidm.md",
        "microsoft": f"{base_url}/microsoft-entra.md",
    }

    if key in provider_docs:
        return provider_docs[key]
    return (
        "https://github.com/christiaangoossens/hass-oidc-auth"
        "/blob/main/docs/configuration.md"
    )
