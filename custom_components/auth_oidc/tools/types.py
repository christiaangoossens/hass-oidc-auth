"""Generic data types"""

# Dict types, to give a type to the stored and passed around data
from typing import Literal, TypedDict

type UserRole = Literal["system-admin", "system-users", "system-read-only", "invalid"]


class UserDetails(TypedDict):
    """User details representation"""

    # User subject, persistent identifier
    sub: str

    # Full name of the user for display purposes, None if the claim is missing
    display_name: str | None

    # Preferred username for the user, will be used when first generating the account
    # or to link the account on first login, None if the claim is missing
    username: str | None

    # Home Assistant role to assign to this user
    role: UserRole


class OIDCState(TypedDict):
    """OIDC State representation"""

    # ID of this state
    id: str

    # User friendly device code
    device_code: str | None

    # Number of failed attempts to link a device code to this state
    device_code_attempts: int

    # The redirect_uri associated with this state,
    # to be able to redirect the user back after authentication
    redirect_uri: str

    # User details, if available
    user_details: UserDetails | None

    # Expiration time of this state, in ISO format
    expiration: str

    # IP address
    ip_address: str | None


class OIDCWelcomeOptions(TypedDict):
    """Options for the welcome screen"""

    # User friendly SSO name to display
    name: str

    # Does the user force HTTPS on all generated URLs?
    force_https: bool

    # Has the user registered any other auth providers?
    has_other_auth_providers: bool

    # Does the user prefer to skip the welcome screen?
    prefers_skipping: bool
