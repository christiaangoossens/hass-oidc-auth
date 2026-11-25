"""Helper functions for the integration."""

from aiohttp import web
from homeassistant.components import http

from ..config.const import REPO_ROOT_URL
from ..stores.state_store import STATE_TTL, StateStore
from ..views.i18n import async_get_translator
from ..views.loader import AsyncTemplateRenderer

STATE_COOKIE_NAME = "auth_oidc_state"


def get_url(path: str, force_https: bool) -> str:
    """Returns the requested path appended to the origin of the current request."""
    if (req := http.current_request.get()) is None:
        raise RuntimeError("No current request in context")

    base_uri = str(req.url.origin())
    if force_https:
        base_uri = base_uri.replace("http://", "https://")
    return f"{base_uri}{path}"


def get_accept_language() -> str | None:
    """Returns the Accept-Language header of the current request, if any."""
    if (req := http.current_request.get()) is None:
        return None
    return req.headers.get("Accept-Language")


async def get_view(template: str, parameters: dict | None = None) -> str:
    """Returns the generated HTML of the requested view,
    translated for the current request."""
    if parameters is None:
        parameters = {}

    renderer = AsyncTemplateRenderer()
    return await renderer.render_template(
        f"{template}.html", accept_language=get_accept_language(), **parameters
    )


def get_state_id(request: web.Request) -> str | None:
    """Return the current OIDC state cookie, if present."""
    return request.cookies.get(STATE_COOKIE_NAME)


def state_cookie_header(state_id: str, secure: bool) -> dict[str, str]:
    """Return the header that sets the state cookie, for as long as the state lives."""
    secure_flag = "; Secure" if secure else ""
    max_age = int(STATE_TTL.total_seconds())

    return {
        "set-cookie": f"{STATE_COOKIE_NAME}={state_id}; Path=/auth/; SameSite=Lax; "
        + f"HttpOnly; Max-Age={max_age}{secure_flag}",
    }


def reset_state_cookie() -> str:
    """Return a Set-Cookie header value to reset the state cookie."""
    return f"{STATE_COOKIE_NAME}=; Path=/auth/; SameSite=Lax; HttpOnly; Max-Age=0"


def get_valid_state_id(request: web.Request, state_store: StateStore) -> str | None:
    """Return state id only when cookie exists and state is still valid."""
    state_id = get_state_id(request)
    if not state_id:
        return None

    if not state_store.is_state_valid(state_id, request.remote):
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
    if parameters is None:
        parameters = {}

    parameters["help_url"] = REPO_ROOT_URL
    return html_response(
        await get_view(template, parameters),
        headers={
            "vary": "Accept-Language",
        },
    )


async def error_response(
    error_key: str,
    status: int = 400,
    reset_cookie: bool = True,
    retry_url: str = "/auth/oidc/redirect",
    placeholders: dict[str, str] | None = None,
) -> web.Response:
    """Render the shared error view with the translated message
    for the given error key, filled in with the placeholders.

    Pass reset_cookie=False when the login state is still valid, so the
    user can retry without starting over. The "Try again" button goes
    to retry_url."""
    translator = await async_get_translator(get_accept_language())
    message = translator(f"error.messages.{error_key}", **(placeholders or {}))

    headers = {"vary": "Accept-Language"}
    if reset_cookie:
        headers["set-cookie"] = reset_state_cookie()

    parameters = {"error": message, "help_url": REPO_ROOT_URL, "retry_url": retry_url}
    return html_response(
        await get_view("error", parameters),
        status=status,
        headers=headers,
    )


def concat_url_query(base: str, new_query: str) -> str:
    """Concatenate a base URL with a new query string, handling existing queries."""
    separator = "?"
    if "?" in base:
        separator = "&"
    return f"{base}{separator}{new_query}"
