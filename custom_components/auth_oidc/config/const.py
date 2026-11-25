"""Config constants."""

from pathlib import Path
from typing import Any

## ===
## General integration constants
## ===

DEFAULT_TITLE = "OpenID Connect (SSO)"
DOMAIN = "auth_oidc"
REPO_ROOT_URL = "https://github.com/christiaangoossens/hass-oidc-auth/tree/v1.3.0"

## ===
## Config keys
## ===

CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"
DISCOVERY_URL = "discovery_url"
DISPLAY_NAME = "display_name"
ID_TOKEN_SIGNING_ALGORITHM = "id_token_signing_alg"
GROUPS_SCOPE = "groups_scope"
ADDITIONAL_SCOPES = "additional_scopes"
FEATURES = "features"
FEATURES_AUTOMATIC_USER_LINKING = "automatic_user_linking"
FEATURES_REQUIRE_EXISTING_USER = "require_existing_user"
FEATURES_AUTOMATIC_PERSON_CREATION = "automatic_person_creation"
FEATURES_DISABLE_PKCE = "disable_rfc7636"
FEATURES_INCLUDE_GROUPS_SCOPE = "include_groups_scope"
FEATURES_FORCE_HTTPS = "force_https"
FEATURES_DEFAULT_REDIRECT = "default_redirect"
CLAIMS = "claims"
CLAIMS_DISPLAY_NAME = "display_name"
CLAIMS_USERNAME = "username"
CLAIMS_GROUPS = "groups"
ROLES = "roles"
ROLE_ADMINS = "admin"
ROLE_USERS = "user"
ROLE_READ_ONLY = "read_only"
NETWORK = "network"
NETWORK_TLS_VERIFY = "tls_verify"
NETWORK_TLS_CA_PATH = "tls_ca_path"

# Internal only, set from the UI groups toggle; YAML always maps groups to roles
MAP_GROUPS_TO_ROLES = "map_groups_to_roles"

## ===
## Default configurations for providers
## ===

REQUIRED_SCOPES = "openid profile"
DEFAULT_ID_TOKEN_SIGNING_ALGORITHM = "RS256"

DEFAULT_GROUPS_SCOPE = "groups"
DEFAULT_ADMIN_GROUP = "admins"

OIDC_PROVIDERS: dict[str, dict[str, Any]] = {
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
    "generic": {
        "name": "OpenID Connect (SSO)",
        "discovery_url": "",
        "supports_groups": False,
        "claims": {"display_name": "name", "username": "preferred_username"},
    },
}

# The integration's own folder, which holds the static files
INTEGRATION_DIR = Path(__file__).parent.parent

# Static files that are in the repository
SOURCE_STATIC_FILES = {
    "/static/auth_oidc/icon.png": [str(INTEGRATION_DIR / "brand/icon.png"), True],
    "/static/auth_oidc/device.js": [str(INTEGRATION_DIR / "static/device.js"), True],
}

# Static files created by scripts/build, so missing from a copy of the source
BUILT_STATIC_FILES = {
    "/static/auth_oidc/style.css": [str(INTEGRATION_DIR / "static/style.css"), True],
}

STATIC_FILE_REGISTRATIONS = SOURCE_STATIC_FILES | BUILT_STATIC_FILES
