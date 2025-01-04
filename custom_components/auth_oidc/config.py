"""Config schema and constants."""

import voluptuous as vol

CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"
DISCOVERY_URL = "discovery_url"
DISPLAY_NAME = "display_name"
ID_TOKEN_SIGNING_ALGORITHM = "id_token_signing_alg"
FEATURES = "features"
FEATURES_AUTOMATIC_USER_LINKING = "automatic_user_linking"
FEATURES_AUTOMATIC_PERSON_CREATION = "automatic_person_creation"
FEATURES_DISABLE_PKCE = "disable_rfc7636"
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

DEFAULT_TITLE = "OpenID Connect (SSO)"

DOMAIN = "auth_oidc"
CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                # Required client ID as registered with the OIDC provider
                vol.Required(CLIENT_ID): vol.Coerce(str),
                # Optional Client Secret to enable confidential client mode
                vol.Optional(CLIENT_SECRET): vol.Coerce(str),
                # Which OIDC well-known URL should we use?
                vol.Required(DISCOVERY_URL): vol.Coerce(str),
                # Which name should be shown on the login screens?
                vol.Optional(DISPLAY_NAME): vol.Coerce(str),
                # Should we enforce a specific signing algorithm on the id tokens?
                # Defaults to RS256/RSA-pubkey
                vol.Optional(ID_TOKEN_SIGNING_ALGORITHM): vol.Coerce(str),
                # Which features should be enabled/disabled?
                # Optional, defaults to sane/secure defaults
                vol.Optional(FEATURES): vol.Schema(
                    {
                        # Automatically links users to the HA user based on OIDC username claim
                        # See provider.py for explanation
                        vol.Optional(FEATURES_AUTOMATIC_USER_LINKING): vol.Coerce(bool),
                        # Automatically creates a person entry for your new OIDC user
                        # See provider.py for explanation
                        vol.Optional(FEATURES_AUTOMATIC_PERSON_CREATION): vol.Coerce(
                            bool
                        ),
                        # Feature flag to disable PKCE to support OIDC servers that do not
                        # allow additional parameters and don't support RFC 7636
                        vol.Optional(FEATURES_DISABLE_PKCE): vol.Coerce(bool),
                    }
                ),
                # Determine which specific claims will be used from the id_token
                # Optional, defaults to most common claims
                vol.Optional(CLAIMS): vol.Schema(
                    {
                        # Which claim should we use to obtain the display name from OIDC?
                        vol.Optional(CLAIMS_DISPLAY_NAME): vol.Coerce(str),
                        # Which claim should we use to obtain the username from OIDC?
                        vol.Optional(CLAIMS_USERNAME): vol.Coerce(str),
                        # Which claim should we use to obtain the group(s) from OIDC?
                        vol.Optional(CLAIMS_GROUPS): vol.Coerce(str),
                    }
                ),
                # Determine which specific group values will be mapped to which roles
                # Optional, defaults user = null, admin = 'admins'
                # If user role is set, users that do not have either will be rejected!
                vol.Optional(ROLES): vol.Schema(
                    {
                        # Which group name should we use to assign the user role?
                        vol.Optional(ROLE_USERS): vol.Coerce(str),
                        # What group name should we use to assign the admin role?
                        # Defaults to admins
                        vol.Optional(ROLE_ADMINS): vol.Coerce(str),
                    }
                ),
                # Network options
                vol.Optional(NETWORK): vol.Schema(
                    {
                        # Verify x509 certificates provided when starting TLS connections
                        vol.Optional(NETWORK_TLS_VERIFY, default=True): vol.Coerce(
                            bool
                        ),
                        # Load custom certificate chain for private CAs
                        vol.Optional(NETWORK_TLS_CA_PATH): vol.Coerce(str),
                    }
                ),
            }
        )
    },
    # Any extra fields should not go into our config right now
    # You may set them for upgrading etc
    extra=vol.REMOVE_EXTRA,
)
