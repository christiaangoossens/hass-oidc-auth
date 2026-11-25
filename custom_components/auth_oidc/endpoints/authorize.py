"""Send visitors of the Home Assistant login page to the OIDC welcome page."""

import base64
import logging
from urllib.parse import quote, unquote

from aiohttp import web
from homeassistant.core import HomeAssistant

from ..provider import OpenIDAuthProvider
from ..tools.helpers import get_url
from ..tools.http_route_takeover import Handler, take_over_get_route
from .welcome import PATH as WELCOME_PATH

PATH = "/auth/authorize"

_LOGGER = logging.getLogger(__name__)


class AuthorizeRedirect:
    """Decides if a login page visit goes to OIDC, otherwise shows Home Assistant's page."""

    def __init__(
        self,
        provider: OpenIDAuthProvider,
        force_https: bool,
        has_trusted_networks_provider_first: bool,
    ) -> None:
        """Initialize the redirect with the settings of this OIDC provider."""
        self.provider = provider
        self.force_https = force_https
        self.has_trusted_networks_provider_first = has_trusted_networks_provider_first

    def should_redirect(self, req: web.Request) -> bool:
        """Check if we should redirect to the OIDC flow."""
        # Set when we return from finish, or by the "Default login" button
        if req.query.get("skip_oidc_redirect") == "true":
            return False

        # Only login pages started by a client redirect to OIDC
        redirect_uri = req.query.get("redirect_uri")
        if not redirect_uri:
            return False

        # Check if we are on a trusted network if we have trusted networks registered first
        if (
            self.has_trusted_networks_provider_first
            and self.provider.is_trusted_network_host()
        ):
            return False

        # The skip flag can also be inside the client's redirect_uri, encoded or not
        decoded_redirect_uri = unquote(redirect_uri)
        return "skip_oidc_redirect=true" not in decoded_redirect_uri

    def welcome_location(self, req: web.Request) -> str:
        """Build the welcome URL that returns to this login page afterwards."""
        # Only the scheme changes, not http:// inside query values like redirect_uri
        url = str(req.url.with_scheme("https") if self.force_https else req.url)

        encoded_current_url = quote(
            base64.b64encode(url.encode("utf-8")).decode("ascii")
        )
        return get_url(
            f"{WELCOME_PATH}?redirect_uri={encoded_current_url}",
            self.force_https,
        )

    def wrap(self, original_handler: Handler) -> Handler:
        """Return a handler that redirects to OIDC or serves the original page."""

        async def get(req: web.Request) -> web.StreamResponse:
            if self.should_redirect(req):
                raise web.HTTPFound(location=self.welcome_location(req))

            return await original_handler(req)

        return get


def take_over_authorize_page(
    hass: HomeAssistant,
    provider: OpenIDAuthProvider,
    force_https: bool,
    has_trusted_networks_provider_first: bool,
) -> None:
    """Redirect the login page to OIDC. Failures leave Home Assistant's page as is."""
    redirect = AuthorizeRedirect(
        provider, force_https, has_trusted_networks_provider_first
    )

    try:
        if take_over_get_route(hass, PATH, redirect.wrap):
            _LOGGER.info("Redirecting %s to the OIDC welcome page", PATH)
            return

        _LOGGER.error(
            "Could not find %s, so the login page will not redirect to OIDC. "
            "Open %s to log in with OIDC",
            PATH,
            WELCOME_PATH,
        )
    # pylint: disable-next=broad-except
    except Exception:
        _LOGGER.exception(
            "Failed to redirect %s to OIDC. Open %s to log in with OIDC",
            PATH,
            WELCOME_PATH,
        )
