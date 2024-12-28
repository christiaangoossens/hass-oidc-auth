"""Jinja2 Async Environment"""

import logging
from os import path
from typing import Dict, Any
from jinja2 import Environment, DictLoader
from aiofiles.os import scandir as async_scandir
from aiofiles import open as async_open

_LOGGER = logging.getLogger(__name__)

templates: Dict[str, str] = {}


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
                except (OSError, IOError) as e:
                    _LOGGER.warning("Error reading template file %s: %s", filename, e)

    async def render_template(self, template_name: str, **kwargs: Any) -> str:
        """Renders a template with the given parameters."""

        if not templates:
            await (
                self.fetch_templates()
            )  # If the templates haven't been fetched, fetch them

        if template_name not in templates:
            raise ValueError(f"Template '{template_name}' not found.")

        env = Environment(loader=DictLoader(templates), enable_async=True)
        template = env.get_template(template_name)

        # Render template
        rendered_output = await template.render_async(**kwargs)
        return rendered_output
