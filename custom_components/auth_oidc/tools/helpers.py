"""Helper functions for the integration."""

from typing import TYPE_CHECKING

from homeassistant.components import http
from aiohttp import web

from ..views.loader import AsyncTemplateRenderer
from ..config.const import REPO_ROOT_URL

if TYPE_CHECKING:
    from ..provider import OpenIDAuthProvider

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


def reset_state_cookie() -> str:
    """Return a Set-Cookie header value to reset the state cookie."""
    return f"{STATE_COOKIE_NAME}=; Path=/auth/; SameSite=Lax; HttpOnly; Max-Age=0"


async def get_valid_state_id(
    request: web.Request, oidc_provider: "OpenIDAuthProvider"
) -> str | None:
    """Return state id only when cookie exists and state is still valid."""
    state_id = get_state_id(request)
    if not state_id:
        return None

    if not await oidc_provider.async_is_state_valid(state_id):
        return None

    return state_id


def html_response(html: str, status: int = 200, headers=None) -> web.Response:
    """Return an HTML response with the standard content type."""
    return web.Response(
        text=html, content_type="text/html", status=status, headers=headers
    )


async def template_response(
    template: str, parameters: dict | None = None
) -> web.Response:
    """Render a template and return it as an HTML response."""
    parameters["help_url"] = REPO_ROOT_URL
    return html_response(await get_view(template, parameters))


async def error_response(message: str, status: int = 400) -> web.Response:
    """Render the shared error view."""
    return html_response(
        await get_view("error", {"error": message, "help_url": REPO_ROOT_URL}),
        status=status,
        headers={
            "set-cookie": reset_state_cookie(),
        },
    )


def concat_url_query(base: str, new_query: str) -> str:
    """Concatenate a base URL with a new query string, handling existing queries."""
    separator = "?"
    if "?" in base:
        separator = "&"
    return f"{base}{separator}{new_query}"
