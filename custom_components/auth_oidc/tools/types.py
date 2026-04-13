"""Generic data types"""

# Dict class to give a type to the user details
from typing import Literal


class UserDetails(dict):
    """User details representation"""

    # User subject, persistent identifier
    sub: str
    # Full name of the user for display purposes
    display_name: str
    # Preferred username for the user, will be used when first generating the account
    # or to link the account on first login
    username: str
    # Home Assistant role to assign to this user
    role: Literal["system-admin", "system-users", "invalid"]


class OIDCState(dict):
    """OIDC State representation"""

    # ID of this state
    id: str

    # User friendly device code
    device_code: str | None

    # The redirect_uri associated with this state,
    # to be able to redirect the user back after authentication
    redirect_uri: str

    # User details, if available
    user_details: UserDetails | None

    # Expiration time of this state, in ISO format
    expiration: str

    # IP address
    ip_address: str
