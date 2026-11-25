"""Tests for the view templates"""

import asyncio
from hashlib import md5
from os import path
from unittest.mock import patch

import pytest

from custom_components.auth_oidc.views import loader
from custom_components.auth_oidc.views.loader import (
    AsyncTemplateRenderer,
    computed_hashes,
)

FAKE_TEMPLATE_PATH = path.join(
    path.dirname(path.abspath(__file__)), "resources", "fake_templates"
)


@pytest.mark.asyncio
async def test_real_template_render():
    """Test that view template can render an real existing template."""

    renderer = AsyncTemplateRenderer()
    await renderer.fetch_templates()
    rendered = await renderer.render_template(
        "welcome.html", name="<script>alert(1)</script>"
    )
    assert "<!DOCTYPE html>" in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered


@pytest.mark.asyncio
async def test_template_render_translated():
    """Test that templates render translated when requested via Accept-Language."""

    renderer = AsyncTemplateRenderer()
    await renderer.fetch_templates()
    rendered = await renderer.render_template(
        "welcome.html", accept_language="de-DE,de;q=0.9,en;q=0.8", name="Example"
    )
    assert 'lang="de"' in rendered
    assert "Mit Example anmelden" in rendered


@pytest.mark.asyncio
async def test_template_render_falls_back_to_english():
    """Test that templates fall back to English for unsupported languages."""

    renderer = AsyncTemplateRenderer()
    await renderer.fetch_templates()
    rendered = await renderer.render_template(
        "welcome.html", accept_language="fr-FR,fr;q=0.9", name="Example"
    )
    assert 'lang="en"' in rendered
    assert "Login with Example" in rendered


@pytest.mark.asyncio
async def test_fake_template_render():
    """Test that view template can render an fake existing template."""

    renderer = AsyncTemplateRenderer(template_dir=FAKE_TEMPLATE_PATH)
    await renderer.fetch_templates()
    rendered = await renderer.render_template("index.html")
    assert "<p>Example template</p>" in rendered


@pytest.mark.asyncio
async def test_dir_render_error():
    """Test that view template sends correct error if you try to render directory."""

    renderer = AsyncTemplateRenderer(template_dir=FAKE_TEMPLATE_PATH)
    await renderer.fetch_templates()
    with pytest.raises(ValueError):
        await renderer.render_template("folder.html")


@pytest.mark.asyncio
async def test_random_render_error():
    """Test that view template sends correct error if you try to render non-existing."""

    renderer = AsyncTemplateRenderer(template_dir=FAKE_TEMPLATE_PATH)
    await renderer.fetch_templates()
    with pytest.raises(ValueError):
        await renderer.render_template("non_existing.html")


async def test_render_reloads_a_partly_filled_cache():
    """A template missing from the cache, e.g. after an interrupted load, is loaded."""
    loader.templates.clear()
    loader.templates["other.html"] = "<p>Other</p>"

    rendered = await AsyncTemplateRenderer().render_template("welcome.html", name="X")

    assert "<!DOCTYPE html>" in rendered


async def test_interrupted_load_leaves_cache_untouched():
    """A load that is cancelled halfway doesn't replace the cache with a partial one."""
    loader.templates.clear()
    loader.templates["index.html"] = "<p>Cached</p>"

    with (
        patch.object(loader, "async_open", side_effect=asyncio.CancelledError),
        pytest.raises(asyncio.CancelledError),
    ):
        await AsyncTemplateRenderer(template_dir=FAKE_TEMPLATE_PATH).fetch_templates()

    assert loader.templates == {"index.html": "<p>Cached</p>"}


@pytest.mark.asyncio
async def test_static_url_includes_hash(tmp_path, monkeypatch):
    """Test that static URLs include the file hash query parameter."""

    url = "/static/auth_oidc/test.css"
    file_path = tmp_path / "test.css"
    file_path.write_text("abc", encoding="utf-8")

    monkeypatch.setitem(loader.STATIC_FILE_REGISTRATIONS, url, [str(file_path), True])
    computed_hashes.clear()

    result = await AsyncTemplateRenderer.get_static_file_url(url)

    assert result == f"{url}?v={md5(b'abc').hexdigest()[:8]}"


async def test_static_url_of_unregistered_file_is_refused():
    """Only files the integration registers can be linked from a page."""
    with pytest.raises(ValueError, match="not registered"):
        await AsyncTemplateRenderer.get_static_file_url("/static/auth_oidc/nope.js")


@pytest.mark.asyncio
async def test_static_url_works_from_any_working_directory(tmp_path, monkeypatch):
    """Home Assistant can be started from any directory, the hash still works."""
    url = "/static/auth_oidc/device.js"
    computed_hashes.clear()
    from_repository = await AsyncTemplateRenderer.get_static_file_url(url)

    monkeypatch.chdir(tmp_path)
    computed_hashes.clear()

    assert await AsyncTemplateRenderer.get_static_file_url(url) == from_repository


@pytest.mark.asyncio
async def test_pages_render_when_a_static_file_is_missing(
    tmp_path, monkeypatch, caplog
):
    """A broken install without e.g. style.css still renders the login pages."""
    url = "/static/auth_oidc/style.css"
    monkeypatch.setitem(
        loader.STATIC_FILE_REGISTRATIONS, url, [str(tmp_path / "style.css"), True]
    )
    computed_hashes.clear()

    rendered = await AsyncTemplateRenderer().render_template("welcome.html", name="X")

    assert f'href="{url}"' in rendered
    assert "is missing" in caplog.text
