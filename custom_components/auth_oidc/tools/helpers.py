"""Helper functions for the integration."""

from homeassistant.components import http
from aiohttp import web

from ..views.loader import AsyncTemplateRenderer

STATE_COOKIE_NAME = "auth_oidc_state"


def get_url(path: str, force_https: bool) -> str:
    """Returns the requested path appended to the current request base URL."""
    if (req := http.current_request.get()) is None:
        raise RuntimeError("No current request in context")

    base_uri = str(req.url).split("/auth", 2)[0]
    if force_https:
        base_uri = base_uri.replace("http://", "https://")
    return f"{base_uri}{path}"


async def get_view(template: str, parameters: dict | None = None) -> str:
    """Returns the generated HTML of the requested view."""
    if parameters is None:
        parameters = {}

    renderer = AsyncTemplateRenderer()
    return await renderer.render_template(f"{template}.html", **parameters)


def get_state_id(request: web.Request) -> str | None:
    """Return the current OIDC state cookie, if present."""
    return request.cookies.get(STATE_COOKIE_NAME)


def html_response(html: str) -> web.Response:
    """Return an HTML response with the standard content type."""
    return web.Response(text=html, content_type="text/html")


async def template_response(
    template: str, parameters: dict | None = None
) -> web.Response:
    """Render a template and return it as an HTML response."""
    return html_response(await get_view(template, parameters))


async def error_response(message: str) -> web.Response:
    """Render the shared error view."""
    return await template_response("error", {"error": message})
