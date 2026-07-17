"""Tests for the login page translation catalogs and locale negotiation"""

import re
from os import path

import pytest

from custom_components.auth_oidc.views.i18n import (
    DEFAULT_LOCALE,
    Translator,
    async_get_translator,
    catalogs,
    fetch_catalogs,
    resolve_locale,
)


FAKE_TEMPLATE_PATH = path.join(
    path.dirname(path.abspath(__file__)), "resources", "fake_templates"
)


def _flatten(catalog: dict, prefix: str = "") -> dict[str, str]:
    """Flatten a nested catalog into dot-separated keys."""
    flat: dict[str, str] = {}
    for key, value in catalog.items():
        full_key = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, f"{full_key}."))
        else:
            flat[full_key] = value
    return flat


def test_resolve_locale():
    """Locale negotiation should honor quality values and fall back to English."""
    available = {"en", "de"}

    # No or empty header falls back to the default locale
    assert resolve_locale(None, available) == "en"
    assert resolve_locale("", available) == "en"

    # Simple matches, case-insensitive
    assert resolve_locale("de", available) == "de"
    assert resolve_locale("DE", available) == "de"

    # Regional variants fall back to the primary subtag
    assert resolve_locale("de-DE,de;q=0.9,en;q=0.8", available) == "de"
    assert resolve_locale("de-CH", available) == "de"

    # Quality values determine the order, not the header position
    assert resolve_locale("en;q=0.8,de", available) == "de"
    assert resolve_locale("fr;q=0.9,de;q=0.8", available) == "de"

    # Unsupported languages and wildcards fall back to the default locale
    assert resolve_locale("fr-FR,fr;q=0.9", available) == "en"
    assert resolve_locale("*", available) == "en"

    # Malformed or zero quality values are skipped
    assert resolve_locale("de;q=0,en;q=0.5", available) == "en"
    assert resolve_locale("de;q=broken,en", available) == "en"
    assert resolve_locale(",,;q=1", available) == "en"


@pytest.mark.asyncio
async def test_catalogs_are_complete():
    """All catalogs should contain the same keys and placeholders as English."""
    await fetch_catalogs()

    assert DEFAULT_LOCALE in catalogs
    reference = _flatten(catalogs[DEFAULT_LOCALE])
    assert reference

    for locale, catalog in catalogs.items():
        flat = _flatten(catalog)
        assert set(flat) == set(reference), (
            f"Catalog '{locale}' keys differ from '{DEFAULT_LOCALE}'"
        )

        for key, value in flat.items():
            assert isinstance(value, str)
            assert set(re.findall(r"{\w+}", value)) == set(
                re.findall(r"{\w+}", reference[key])
            ), f"Catalog '{locale}' placeholders differ for '{key}'"


@pytest.mark.asyncio
async def test_translator_lookup_and_formatting():
    """Translator should return translated strings with formatted parameters."""
    translator = await async_get_translator("de")
    assert translator.locale == "de"
    assert translator("welcome.login_with", name="Example") == "Mit Example anmelden"

    default_translator = await async_get_translator(None)
    assert default_translator.locale == DEFAULT_LOCALE
    assert (
        default_translator("welcome.login_with", name="Example") == "Login with Example"
    )


@pytest.mark.asyncio
async def test_translator_falls_back_to_default_locale():
    """Translator should fall back to English and then to the key itself."""
    await fetch_catalogs()
    catalogs["xx"] = {"welcome": {"title": "XX Title"}}
    try:
        translator = Translator("xx")
        assert translator("welcome.title") == "XX Title"

        # Keys missing from the catalog fall back to the default locale
        assert translator("welcome.login_with", name="Example") == "Login with Example"

        # Keys missing from every catalog return the key itself
        assert translator("does.not.exist") == "does.not.exist"

        # Lookups through a non-dict node return the key as well
        assert translator("welcome.title.nested") == "welcome.title.nested"
    finally:
        catalogs.pop("xx", None)


@pytest.mark.asyncio
async def test_fetch_catalogs_skips_directories_and_non_json_files():
    """Catalog loading should ignore directories and non-JSON files."""
    try:
        # The fake template directory contains a subdirectory and an HTML file
        await fetch_catalogs(FAKE_TEMPLATE_PATH)
        assert not catalogs
    finally:
        await fetch_catalogs()
