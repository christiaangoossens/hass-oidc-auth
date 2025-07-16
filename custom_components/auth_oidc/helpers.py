"""Helper functions for the integration."""

import base64
from homeassistant.components import http
from .views.loader import AsyncTemplateRenderer


def get_url(path: str, force_https: bool) -> str:
    """Returns the requested path appended to the current request base URL."""
    if (req := http.current_request.get()) is None:
        raise RuntimeError("No current request in context")

    base_uri = str(req.url).split("/auth", 2)[0]
    if force_https:
        base_uri = base_uri.replace("http://", "https://")

    url = f"{base_uri}{path}"
    return url


async def get_view(template: str, parameters: dict | None = None) -> str:
    """Returns the generated HTML of the requested view."""
    if parameters is None:
        parameters = {}

    renderer = AsyncTemplateRenderer()
    return await renderer.render_template(f"{template}.html", **parameters)


def base64url_encode(value: bytes) -> str:
    """Uses base64url encoding on a given string"""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def base64url_decode(value: str) -> str:
    """Uses base64url decoding on a given string"""
    padding = "=" * (4 - len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode("utf-8")
