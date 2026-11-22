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
async def test_real_template_render(monkeypatch):
    """Test that view template can render an real existing template."""

    renderer = AsyncTemplateRenderer()
    monkeypatch.setattr(loader, "templates", {"_alert.html": "stale"})
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


@pytest.mark.asyncio
async def test_cancelled_template_load(monkeypatch):
    """Cancellation after one file leaves the cold cache available for retry."""

    renderer = AsyncTemplateRenderer()
    monkeypatch.setattr(loader, "templates", {})
    real_open = loader.async_open
    opened_first = False

    def cancel_on_second_open(*args, **kwargs):
        nonlocal opened_first
        if opened_first:
            task.cancel()
        opened_first = True
        return real_open(*args, **kwargs)

    with patch.object(loader, "async_open", side_effect=cancel_on_second_open):
        task = asyncio.create_task(renderer.render_template("welcome.html"))
        with pytest.raises(asyncio.CancelledError):
            await task

    assert loader.templates == {}
    assert "Login with A" in await renderer.render_template("welcome.html", name="A")


@pytest.mark.asyncio
async def test_concurrent_template_load(monkeypatch):
    """Concurrent cold renders share a single directory scan."""

    renderer = AsyncTemplateRenderer()
    monkeypatch.setattr(loader, "templates", {})
    with patch.object(loader, "async_scandir", wraps=loader.async_scandir) as scan:
        first, second = await asyncio.gather(
            renderer.render_template("welcome.html", name="A"),
            renderer.render_template("welcome.html", name="B"),
        )
    scan.assert_awaited_once_with(renderer.template_dir)
    assert "Login with A" in first
    assert "Login with B" in second
