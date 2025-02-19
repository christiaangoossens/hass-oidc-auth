"""Welcome route to show the user the OIDC login button and give instructions."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from ..helpers import get_view


class OIDCWelcomeView(HomeAssistantView):
    """OIDC Plugin Welcome View."""

    requires_auth = False

    def __init__(self, name: str, path: str, redirect_path: str) -> None:
        """Initialize the OIDC Welcome View.

        Args:
            name (str): The name of the view.
            path (str): The URL path for the view.
            redirect_path (str): The URL path for the redirect.
        """
        self.name = name
        self.url = path
        self.redirect_url = redirect_path
        self.name = "auth:oidc:welcome"

    async def get(self, request: web.Request) -> web.Response:
        """Handle GET requests.

        Args:
            request (web.Request): The incoming request.

        Returns:
            web.Response: The response to be sent back to the client.
        """
        try:
            view_html = await get_view(
                "welcome", {"name": self.name, "redirect_url": self.redirect_url}
            )
            return web.Response(text=view_html, content_type="text/html")
        except Exception as e:
            # Log the error and return an error response
            self._logger.error(f"Error in OIDCWelcomeView: {e}")
            return web.Response(text="An error occurred", status=500)
