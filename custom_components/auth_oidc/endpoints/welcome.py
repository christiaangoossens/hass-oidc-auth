"""Welcome route to show the user the OIDC login button and give instructions."""

import base64
import binascii
import logging
from urllib.parse import parse_qs, unquote, urlencode, urlparse

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..provider import OpenIDAuthProvider
from ..stores.state_store import StateStore
from ..tools.helpers import (
    concat_url_query,
    error_response,
    get_url,
    state_cookie_header,
    template_response,
)
from ..tools.types import OIDCWelcomeOptions

PATH = "/auth/oidc/welcome"

_LOGGER = logging.getLogger(__name__)


class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:welcome"

    def __init__(
        self,
        oidc_provider: OpenIDAuthProvider,
        state_store: StateStore,
        options: OIDCWelcomeOptions,
    ) -> None:
        self.oidc_provider = oidc_provider
        self.state_store = state_store
        self.force_https = options.get("force_https")
        self.prefers_skipping = options.get("prefers_skipping")

    async def _process_url(self, redirect_uri: str) -> tuple[str, str, bool]:
        """Processes the redirect URI to determine if we need setTokens and if this is mobile.

        Returns the decoded redirect URI, the URI to store in the state and the mobile flag.
        """
        # decodeURIComponent(btoa(...)) -> unquote first, then base64 decode
        decoded_redirect_uri = base64.b64decode(
            unquote(redirect_uri), validate=True
        ).decode("utf-8")

        oauth2_url = urlparse(decoded_redirect_uri)

        base = urlparse(get_url("/", self.force_https))
        if (
            oauth2_url.scheme != base.scheme
            or oauth2_url.netloc.lower() != base.netloc.lower()
        ):
            _LOGGER.warning(
                "Rejected redirect_uri based on mismatch same-origin "
                + "same-scheme: is your proxy misconfigured?"
            )
            raise ValueError("redirect_uri is not a same-origin same-scheme URL")

        if oauth2_url.path != "/auth/authorize":
            _LOGGER.warning(
                "Rejected redirect_uri based on invalid OAuth2 url, "
                + "did HA change its implementation?"
            )
            raise ValueError("redirect_uri is not an HA OAuth2 URL")

        oauth2_query = parse_qs(oauth2_url.query)
        client_id = oauth2_query["client_id"][0]
        original_redirect_uri = oauth2_query["redirect_uri"][0]

        # If the client_id starts with https://home-assistant.io/
        # we assume it's a mobile client
        # Android = https://home-assistant.io/Android,
        # iOS = https://home-assistant.io/iOS
        is_mobile = client_id.startswith("https://home-assistant.io/")

        # Check if we appear to be signing in to the web version,
        # for which we want to store tokens.
        # We don't want to set storeTokens on sign-in to Google for instance
        base_url = get_url("/", self.force_https)
        is_web_client = original_redirect_uri.startswith(base_url)

        if is_web_client:
            # Adjust the original_redirect_uri to include the storeTokens parameter
            original_redirect_uri = concat_url_query(
                original_redirect_uri, "storeToken=true"
            )
            oauth2_query["redirect_uri"] = [original_redirect_uri]

            # Create new redirect_uri with the updated query parameters
            new_oauth2_url = oauth2_url._replace(
                query=urlencode(oauth2_query, doseq=True)
            )
            state_redirect_uri = new_oauth2_url.geturl()
        else:
            state_redirect_uri = decoded_redirect_uri

        # Make sure to also return the original decoded URL for other_return_url
        return decoded_redirect_uri, state_redirect_uri, is_mobile

    async def get(self, req: web.Request) -> web.Response:
        """Receive response."""

        # Get the query parameter with the redirect_uri
        redirect_uri = req.query.get("redirect_uri")

        # Failsafe the other return to / in case of mobile or direct open of the welcome page
        other_return_url = get_url("/", self.force_https)

        # Do some processing on the redirect_uri to correct it
        # and determine if this is a mobile client.
        if redirect_uri:
            try:
                other_return_url, redirect_uri, is_mobile = await self._process_url(
                    redirect_uri
                )
            except (
                binascii.Error,
                UnicodeDecodeError,
                ValueError,
                KeyError,
                TypeError,
            ):
                return await error_response("invalid_redirect_uri")

        else:
            # Backwards compatibility with older versions that directly go to /auth/oidc/welcome
            # If not set, redirect back to the main page and assume that this is a web client
            redirect_uri = get_url("/?storeToken=true", self.force_https)
            is_mobile = False

        # Create OIDC state with the redirect_uri so we can use it later in the flow
        state_id = self.state_store.create_state(redirect_uri, req.remote)
        cookie_header = state_cookie_header(
            state_id, secure=self.force_https or req.url.scheme == "https"
        )

        # On desktop, go straight to OIDC if the login page has nothing else to offer
        can_offer_other_login = self.oidc_provider.can_offer_other_login(req)
        if not is_mobile and (self.prefers_skipping or not can_offer_other_login):
            raise web.HTTPFound(
                location=get_url("/auth/oidc/redirect", self.force_https),
                headers=cookie_header,
            )

        # Otherwise display the screen with either mobile sign in or the buttons
        # First generate code if mobile
        code = None
        if is_mobile:
            # Create a code to login
            code = self.state_store.create_device_code(state_id)
            if not code:
                return await error_response("device_code_failed", status=500)

        other_link = None
        if can_offer_other_login:
            other_link = concat_url_query(other_return_url, "skip_oidc_redirect=true")

        # And display
        response = await template_response(
            "welcome",
            {
                "name": self.oidc_provider.name,
                "other_link": other_link,
                "code": code,
            },
        )
        response.headers.update(cookie_header)
        return response
