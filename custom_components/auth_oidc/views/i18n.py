"""Translations for the server-rendered login pages.

The login pages are shown before the user is authenticated, so the language
preference from the Home Assistant user profile is not available. Instead,
the language is negotiated from the Accept-Language request header against
the catalogs available in the translations directory next to this module.
"""

import json
import logging
from os import path
from typing import Any, Dict

from aiofiles import open as async_open
from aiofiles.os import scandir as async_scandir

_LOGGER = logging.getLogger(__name__)

DEFAULT_LOCALE = "en"

TRANSLATIONS_DIR = path.join(path.dirname(path.abspath(__file__)), "translations")

catalogs: Dict[str, dict] = {}


async def fetch_catalogs(directory: str | None = None) -> None:
    """Fetches all JSON translation catalogs from the translations directory."""
    directory = directory or TRANSLATIONS_DIR
    loaded: Dict[str, dict] = {}

    files = await async_scandir(directory)

    for file in files:
        if file.is_dir():
            continue

        filename = file.name
        if filename.endswith(".json"):
            catalog_path = path.join(directory, filename)
            try:
                _LOGGER.debug("Fetching translation catalog %s from disk", filename)
                async with async_open(catalog_path, mode="r", encoding="utf-8") as f:
                    content = await f.read()
                    loaded[filename[: -len(".json")].lower()] = json.loads(content)
            except (OSError, IOError, ValueError) as e:  # pragma: no cover
                _LOGGER.warning("Error reading translation catalog %s: %s", filename, e)

    # Swap without an await in between so concurrent requests never observe
    # a cleared or partially loaded catalogs dict
    catalogs.clear()
    catalogs.update(loaded)


def _parse_accept_language(header: str) -> list[str]:
    """Parse an Accept-Language header into language tags ordered by quality."""
    languages: list[tuple[float, int, str]] = []

    for index, part in enumerate(header.split(",")):
        tag, _, params = part.strip().partition(";")
        tag = tag.strip().lower()
        if not tag:
            continue

        quality = 1.0
        params = params.strip()
        if params.startswith("q="):
            try:
                quality = float(params[2:])
            except ValueError:
                continue

        if quality <= 0:
            continue

        # Sort by descending quality, ties keep the original header order
        languages.append((-quality, index, tag))

    return [tag for _, _, tag in sorted(languages)]


def resolve_locale(accept_language: str | None, available: set[str]) -> str:
    """Resolve the best matching locale for an Accept-Language header."""
    if not accept_language:
        return DEFAULT_LOCALE

    for tag in _parse_accept_language(accept_language):
        # A wildcard means any language is fine, keep the default
        if tag == "*":
            continue

        if tag in available:
            return tag

        # Fall back from a regional variant to the primary subtag (de-DE -> de)
        primary = tag.split("-", 1)[0]
        if primary in available:
            return primary

    return DEFAULT_LOCALE


def _lookup(locale: str, key: str) -> str | None:
    """Look up a dot-separated key in the catalog of the given locale."""
    node: Any = catalogs.get(locale)
    for part in key.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node if isinstance(node, str) else None


class Translator:  # pylint: disable=too-few-public-methods
    """Translates dot-separated catalog keys for a single resolved locale."""

    def __init__(self, locale: str) -> None:
        self.locale = locale

    def __call__(self, key: str, **kwargs: Any) -> str:
        message = _lookup(self.locale, key)
        if message is None and self.locale != DEFAULT_LOCALE:
            message = _lookup(DEFAULT_LOCALE, key)
        if message is None:
            _LOGGER.warning("Missing translation for key '%s'", key)
            return key
        if kwargs:
            return message.format(**kwargs)
        return message


async def async_get_translator(accept_language: str | None = None) -> Translator:
    """Return a translator for the best matching locale."""
    if not catalogs:
        await fetch_catalogs()  # If the catalogs haven't been fetched, fetch them

    return Translator(resolve_locale(accept_language, set(catalogs)))
