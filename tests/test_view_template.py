"""Tests for the view templates"""

import asyncio
from hashlib import md5
from os import path

import pytest

from custom_components.auth_oidc.views import loader
from custom_components.auth_oidc.views.loader import (
    AsyncTemplateRenderer,
    computed_hashes,
    templates,
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


@pytest.mark.asyncio
async def test_render_reloads_incomplete_cache():
    """Test that a template missing from a partially filled cache is reloaded."""

    templates.clear()
    templates["_alert.html"] = "<p>alert</p>"

    renderer = AsyncTemplateRenderer()
    rendered = await renderer.render_template("welcome.html", name="Example")
    assert "<!DOCTYPE html>" in rendered


@pytest.mark.asyncio
async def test_cancelled_fetch_leaves_cache_untouched(monkeypatch):
    """Test that a fetch cancelled halfway does not leave a partial cache."""

    templates.clear()
    real_open = loader.async_open
    calls = 0

    def cancel_on_second_file(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise asyncio.CancelledError
        return real_open(*args, **kwargs)

    monkeypatch.setattr(loader, "async_open", cancel_on_second_file)

    renderer = AsyncTemplateRenderer()
    with pytest.raises(asyncio.CancelledError):
        await renderer.fetch_templates()
    assert not templates

    monkeypatch.setattr(loader, "async_open", real_open)
    rendered = await renderer.render_template("welcome.html", name="Example")
    assert "<!DOCTYPE html>" in rendered


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
