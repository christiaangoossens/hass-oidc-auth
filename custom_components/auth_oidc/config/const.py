"""Config constants."""

from typing import Any, Dict

## ===
## General integration constants
## ===

DEFAULT_TITLE = "OpenID Connect (SSO)"
DOMAIN = "auth_oidc"
REPO_ROOT_URL = (
    "https://github.com/christiaangoossens/hass-oidc-auth/tree/v0.7.0-alpha-rc3"
)

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
FEATURES_AUTOMATIC_PERSON_CREATION = "automatic_person_creation"
FEATURES_DISABLE_PKCE = "disable_rfc7636"
FEATURES_INCLUDE_GROUPS_SCOPE = "include_groups_scope"
FEATURES_DISABLE_FRONTEND_INJECTION = "disable_frontend_changes"
FEATURES_FORCE_HTTPS = "force_https"
CLAIMS = "claims"
CLAIMS_DISPLAY_NAME = "display_name"
CLAIMS_USERNAME = "username"
CLAIMS_GROUPS = "groups"
ROLES = "roles"
ROLE_ADMINS = "admin"
ROLE_USERS = "user"
NETWORK = "network"
NETWORK_TLS_VERIFY = "tls_verify"
NETWORK_TLS_CA_PATH = "tls_ca_path"
NETWORK_USERINFO_FALLBACK = "userinfo_fallback"
VERBOSE_DEBUG_MODE = "enable_verbose_debug_mode"

## ===
## Default configurations for providers
## ===

REQUIRED_SCOPES = "openid profile email"
DEFAULT_ID_TOKEN_SIGNING_ALGORITHM = "RS256"

DEFAULT_GROUPS_SCOPE = "groups"
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
    "generic": {
        "name": "OpenID Connect (SSO)",
        "discovery_url": "",
        "supports_groups": False,
        "claims": {"display_name": "name", "username": "preferred_username"},
    },
}
