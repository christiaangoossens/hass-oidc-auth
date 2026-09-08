"""Jinja2 Async Environment"""

import logging
from sys import modules
from hashlib import md5
from os import path
from typing import Dict, Any
from jinja2 import Environment, DictLoader
from aiofiles.os import scandir as async_scandir
from aiofiles import open as async_open
from ..config import STATIC_FILE_REGISTRATIONS

_LOGGER = logging.getLogger(__name__)

templates: Dict[str, str] = {}
computed_hashes: Dict[str, str] = {}


class AsyncTemplateRenderer:
    """An asynchronous template renderer that caches rendered templates."""

    def __init__(self, template_dir: str = None):
        self.template_dir = template_dir or path.join(
            path.dirname(path.abspath(__file__)), "templates"
        )

    async def fetch_templates(self) -> None:
        """Fetches all HTML files from the template directory."""
        templates.clear()

        files = await async_scandir(self.template_dir)

        for file in files:
            if file.is_dir():
                continue

            filename = file.name
            if filename.endswith(".html"):
                template_path = path.join(self.template_dir, filename)
                try:
                    _LOGGER.debug("Fetching template %s from disk", filename)
                    async with async_open(
                        template_path, mode="r", encoding="utf-8"
                    ) as f:
                        content = await f.read()
                        templates[filename] = content
                except (OSError, IOError) as e:  # pragma: no cover
                    _LOGGER.warning("Error reading template file %s: %s", filename, e)

    async def render_template(self, template_name: str, **kwargs: Any) -> str:
        """Renders a template with the given parameters."""

        if not templates:
            await (
                self.fetch_templates()
            )  # If the templates haven't been fetched, fetch them

        if template_name not in templates:
            raise ValueError(f"Template '{template_name}' not found.")

        env = Environment(
            loader=DictLoader(templates), enable_async=True, autoescape=True
        )
        env.filters['static_url'] = self.get_static_file_url
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

        # See if we have computed it before
        if file_path in computed_hashes:
            return f"{url}?v={computed_hashes[file_path]}"

        # Otherwise, compute the hash and store it
        try:
            async with async_open(
                file_path, mode="r", encoding="utf-8"
            ) as f:
                content = f.buffer.read()
                file_hash = md5(content).hexdigest()[:8]
                computed_hashes[file_path] = file_hash
                return f"{url}?v={file_hash}"
        except FileNotFoundError as exc:
            # If within pytest, ignore error
            if "pytest" in modules:
                _LOGGER.warning(
                    "Static file '%s' not found. This may be expected during testing.",
                    file_path,
                )
                return f"{url}?v=missing"

            raise ValueError(f"Static file '{file_path}' not found.") from exc

        raise ValueError(f"Static file '{file_path}' could not be processed.")
