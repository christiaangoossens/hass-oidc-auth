"""Welcome route to show the user the OIDC login button and give instructions."""

import base64
import binascii
from urllib.parse import urlparse, parse_qs, unquote
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from ..tools.helpers import error_response, get_url, template_response
from ..provider import OpenIDAuthProvider

PATH = "/auth/oidc/welcome"


class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:welcome"

    def __init__(
        self,
        oidc_provider: OpenIDAuthProvider,
        name: str,
        force_https: bool,
        has_other_auth_providers: bool,
    ) -> None:
        self.oidc_provider = oidc_provider
        self.name = name
        self.force_https = force_https
        self.has_other_auth_providers = has_other_auth_providers

    def determine_if_mobile(self, redirect_uri: str) -> bool:
        """Determine if the client is a mobile client based on the redirect_uri."""
        oauth2_url = urlparse(redirect_uri)
        client_id = parse_qs(oauth2_url.query).get("client_id")

        # If the client_id starts with https://home-assistant.io/ we assume it's a mobile client
        return bool(client_id and client_id[0].startswith("https://home-assistant.io/"))

    async def get(self, req: web.Request) -> web.Response:
        """Receive response."""

        # Get the query parameter with the redirect_uri
        redirect_uri = req.query.get("redirect_uri")

        # If set, determine if this is a mobile client based on the redirect_uri,
        # otherwise assume it's not mobile
        if redirect_uri:
            try:
                # decodeURIComponent(btoa(...)) -> unquote first, then base64 decode
                redirect_uri = base64.b64decode(
                    unquote(redirect_uri), validate=True
                ).decode("utf-8")
                is_mobile = self.determine_if_mobile(redirect_uri)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                return await error_response(
                    "Invalid redirect_uri, please restart login."
                )
        else:
            # Backwards compatibility with older versions that directly go to /auth/oidc/welcome
            # If not set, redirect back to the main page and assume that this is a web client
            redirect_uri = get_url("/", self.force_https)
            is_mobile = False

        # Create OIDC state with the redirect_uri so we can use it later in the flow
        state_id = await self.oidc_provider.async_create_state(redirect_uri)
        cookie_header = self.oidc_provider.get_cookie_header(
            state_id, secure=self.force_https or req.url.scheme == "https"
        )

        # If this is the only provider and we are on desktop,
        # automatically go through the OIDC login
        if not is_mobile and not self.has_other_auth_providers:
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
