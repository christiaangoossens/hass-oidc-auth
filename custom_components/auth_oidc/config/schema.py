"""Config schema"""

import voluptuous as vol
from .const import (
    CLIENT_ID,
    CLIENT_SECRET,
    DISCOVERY_URL,
    DISPLAY_NAME,
    ID_TOKEN_SIGNING_ALGORITHM,
    GROUPS_SCOPE,
    ADDITIONAL_SCOPES,
    FEATURES,
    FEATURES_AUTOMATIC_USER_LINKING,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    FEATURES_DISABLE_PKCE,
    FEATURES_INCLUDE_GROUPS_SCOPE,
    FEATURES_DISABLE_FRONTEND_INJECTION,
    FEATURES_FORCE_HTTPS,
    CLAIMS,
    CLAIMS_DISPLAY_NAME,
    CLAIMS_USERNAME,
    CLAIMS_GROUPS,
    ROLES,
    ROLE_ADMINS,
    ROLE_USERS,
    NETWORK,
    NETWORK_TLS_VERIFY,
    NETWORK_TLS_CA_PATH,
    NETWORK_USERINFO_FALLBACK,
    DOMAIN,
    DEFAULT_GROUPS_SCOPE,
    VERBOSE_DEBUG_MODE,
)

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
                # String value to allow changing the groups scope
                # Defaults to 'groups' which is used by Authelia and Authentik
                vol.Optional(GROUPS_SCOPE, default=DEFAULT_GROUPS_SCOPE): vol.Coerce(
                    str
                ),
                # Additional scopes to request from the OIDC provider
                # Optional, this field is unnecessary if you only use the openid and profile scopes.
                vol.Optional(ADDITIONAL_SCOPES, default=[]): vol.Coerce(list[str]),
                # Added for debugging purposes
                # If enabled, logging will include more detailed information regarding
                # the full OIDC auth chain (including tokens) and is captured within:
                # <component_dir>/custom_components/auth_oidc/verbose_debug/
                vol.Optional(VERBOSE_DEBUG_MODE, default=False): vol.Coerce(bool),
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
                        # Boolean which activates and deactivates scope 'groups'
                        vol.Optional(
                            FEATURES_INCLUDE_GROUPS_SCOPE, default=True
                        ): vol.Coerce(bool),
                        # Disable frontend injection of OIDC login button
                        vol.Optional(
                            FEATURES_DISABLE_FRONTEND_INJECTION, default=False
                        ): vol.Coerce(bool),
                        # Force HTTPS on all generated URLs (like redirect_uri)
                        vol.Optional(FEATURES_FORCE_HTTPS, default=False): vol.Coerce(
                            bool
                        ),
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
                        # Constructed Userinfo endpoint fallback if not provided in discovery
                        # Some OPs omit this endpoint
                        vol.Optional(
                            NETWORK_USERINFO_FALLBACK, default=False
                        ): vol.Coerce(bool),
                    }
                ),
            }
        )
    },
    # Any extra fields should not go into our config right now
    # You may set them for upgrading etc
    extra=vol.REMOVE_EXTRA,
)
