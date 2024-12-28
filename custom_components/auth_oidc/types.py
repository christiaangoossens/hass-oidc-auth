"""Generic data types"""


# Dict class to give a type to the user details
class UserDetails(dict):
    """User details representation"""

    # User subject, persistent identifier
    sub: str
    # Full name of the user for display purposes
    display_name: str
    # Preferred username for the user, will be used when first generating the account
    # or to link the account on first login
    username: str
    # Groups that the user has, if any are sent from the OIDC provider
    groups: list[str]
