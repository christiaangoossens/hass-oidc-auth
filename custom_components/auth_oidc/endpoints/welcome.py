"""Welcome route to show the user the OIDC login button and give instructions."""

import base64
import binascii
from urllib.parse import urlparse, parse_qs, unquote, urlencode
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from ..tools.helpers import error_response, get_url, template_response
from ..provider import OpenIDAuthProvider
from ..tools.types import OIDCWelcomeOptions

PATH = "/auth/oidc/welcome"


class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:welcome"

    def __init__(
        self, oidc_provider: OpenIDAuthProvider, options: OIDCWelcomeOptions
    ) -> None:
        self.oidc_provider = oidc_provider
        self.name = options.get("name")
        self.force_https = options.get("force_https")
        self.has_other_auth_providers = options.get("has_other_auth_providers")
        self.prefers_skipping = options.get("prefers_skipping")

    async def _process_url(self, redirect_uri: str) -> tuple[str, bool]:
        """Processes the redirect URI to determine if we need setTokens and if this is mobile."""
        # decodeURIComponent(btoa(...)) -> unquote first, then base64 decode
        redirect_uri = base64.b64decode(unquote(redirect_uri), validate=True).decode(
            "utf-8"
        )

        oauth2_url = urlparse(redirect_uri)
        oauth2_query = parse_qs(oauth2_url.query)
        client_id = oauth2_query.get("client_id")[0]
        original_redirect_uri = oauth2_query.get("redirect_uri")[0]

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
            separator = "?"
            if "?" in original_redirect_uri:
                separator = "&"

            original_redirect_uri = f"{original_redirect_uri}{separator}storeToken=true"
            oauth2_query.update({"redirect_uri": original_redirect_uri})

            # Create new redirect_uri with the updated query parameters
            new_oauth2_url = oauth2_url._replace(
                query=urlencode(oauth2_query, doseq=True)
            )
            redirect_uri = new_oauth2_url.geturl()

        return redirect_uri, is_mobile

    async def get(self, req: web.Request) -> web.Response:
        """Receive response."""

        # Get the query parameter with the redirect_uri
        redirect_uri = req.query.get("redirect_uri")

        # Do some processing on the redirect_uri to correct it
        # and determine if this is a mobile client.
        if redirect_uri:
            try:
                redirect_uri, is_mobile = await self._process_url(redirect_uri)
            except (
                binascii.Error,
                UnicodeDecodeError,
                ValueError,
                KeyError,
                TypeError,
            ):
                return await error_response(
                    "Invalid redirect_uri, please restart login."
                )

        else:
            # Backwards compatibility with older versions that directly go to /auth/oidc/welcome
            # If not set, redirect back to the main page and assume that this is a web client
            redirect_uri = get_url("/?storeToken=true", self.force_https)
            is_mobile = False

        # Create OIDC state with the redirect_uri so we can use it later in the flow
        state_id = await self.oidc_provider.async_create_state(redirect_uri)
        cookie_header = self.oidc_provider.get_cookie_header(
            state_id, secure=self.force_https or req.url.scheme == "https"
        )

        # If this is the only provider and we are on desktop,
        # automatically go through the OIDC login
        if not is_mobile and (
            not self.has_other_auth_providers or self.prefers_skipping
        ):
            raise web.HTTPFound(
                location=get_url("/auth/oidc/redirect", self.force_https),
                headers=cookie_header,
            )

        # Otherwise display the screen with either mobile sign in or the buttons
        # First generate code if mobile
        code = None
        if is_mobile:
            # Create a code to login
            code = await self.oidc_provider.async_generate_device_code(state_id)
            if not code:
                return await error_response(
                    "Failed to generate device code, please restart login.",
                    status=500,
                )

        # And add the other link if we have other auth providers
        other_link = None
        if self.has_other_auth_providers:
            other_link = get_url("/?skip_oidc_redirect=true", self.force_https)

        # And display
        response = await template_response(
            "welcome",
            {
                "name": self.name,
                "other_link": other_link,
                "code": code,
            },
        )
        response.headers.update(cookie_header)
        return response
