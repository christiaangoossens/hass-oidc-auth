"""Jinja2 Async Environment"""

import logging
from hashlib import md5
from os import path
from typing import Any

from aiofiles import open as async_open
from aiofiles.os import scandir as async_scandir
from jinja2 import DictLoader, Environment

from ..config import STATIC_FILE_REGISTRATIONS
from .i18n import async_get_translator

_LOGGER = logging.getLogger(__name__)

templates: dict[str, str] = {}
computed_hashes: dict[str, str] = {}


class AsyncTemplateRenderer:
    """An asynchronous template renderer that caches rendered templates."""

    def __init__(self, template_dir: str | None = None):
        self.template_dir = template_dir or path.join(
            path.dirname(path.abspath(__file__)), "templates"
        )

    async def fetch_templates(self) -> None:
        """Fetches all HTML files from the template directory.

        The shared cache is only replaced once every file is read, so a render
        running at the same time never sees a partly filled cache.
        """
        loaded: dict[str, str] = {}

        for file in await async_scandir(self.template_dir):
            if file.is_dir() or not file.name.endswith(".html"):
                continue

            template_path = path.join(self.template_dir, file.name)
            try:
                _LOGGER.debug("Fetching template %s from disk", file.name)
                async with async_open(template_path, mode="r", encoding="utf-8") as f:
                    loaded[file.name] = await f.read()
            except OSError as e:  # pragma: no cover
                _LOGGER.warning("Error reading template file %s: %s", file.name, e)

        templates.clear()
        templates.update(loaded)

    async def render_template(
        self, template_name: str, accept_language: str | None = None, **kwargs: Any
    ) -> str:
        """Renders a template with the given parameters.

        The template language is negotiated from the given Accept-Language
        header value and exposed to the template as the 't' translation
        function and the 'lang' variable.
        """

        # Load the templates on first use, and again if one is missing
        if template_name not in templates:
            await self.fetch_templates()

        if template_name not in templates:
            raise ValueError(f"Template '{template_name}' not found.")

        env = Environment(
            loader=DictLoader(templates), enable_async=True, autoescape=True
        )

        env.filters["static_url"] = self.get_static_file_url

        translator = await async_get_translator(accept_language)
        env.globals["t"] = translator
        env.globals["lang"] = translator.locale

        template = env.get_template(template_name)

        # Render template
        rendered_output = await template.render_async(**kwargs)
        return rendered_output

    @staticmethod
    async def get_static_file_url(url: str) -> str:
        """Return the URL for a static file in the integration."""
        # Lookup the static file in the STATIC_FILE_REGISTRATIONS dictionary
        if url not in STATIC_FILE_REGISTRATIONS:
            raise ValueError(f"Static file '{url}' is not registered.")

        file_path = STATIC_FILE_REGISTRATIONS[url][0]

        if file_path not in computed_hashes:
            try:
                async with async_open(file_path, mode="rb") as f:
                    computed_hashes[file_path] = md5(await f.read()).hexdigest()[:8]
            except FileNotFoundError:
                # A broken install shouldn't break login, the page renders without it
                _LOGGER.warning(
                    "Static file '%s' is missing, reinstall the integration properly!",
                    file_path,
                )
                return url

        return f"{url}?v={computed_hashes[file_path]}"
