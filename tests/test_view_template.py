"""Tests for the view templates"""

import asyncio
from hashlib import md5
from os import path

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
async def test_a_cancelled_fetch_does_not_poison_the_cache():
    """A fetch cancelled part-way must not leave a cache that never heals.

    The old fetch cleared the module dict and refilled it file by file with
    awaits in between, and render_template treated a non-empty dict as
    "loaded". A cancellation between two files therefore left the cache
    permanently incomplete: every later request raised
    "Template '<name>' not found" until a restart.
    """
    loader.templates.clear()
    loader.loaded_dirs.clear()

    renderer = AsyncTemplateRenderer()  # the real directory, several files
    real_open = loader.async_open
    reads = {"count": 0}

    def cancelling_open(*args, **kwargs):
        reads["count"] += 1
        if reads["count"] == 4:
            raise asyncio.CancelledError
        return real_open(*args, **kwargs)

    loader.async_open = cancelling_open
    try:
        with pytest.raises(asyncio.CancelledError):
            await renderer.fetch_templates()
    finally:
        loader.async_open = real_open

    assert reads["count"] == 4, "the cancellation must land after some files were read"
    # Nothing was swapped in, so the next render fetches for real.
    assert loader.templates == {}
    assert renderer.template_dir not in loader.loaded_dirs
    rendered = await renderer.render_template("welcome.html", name="x")
    assert "<!DOCTYPE html>" in rendered


@pytest.mark.asyncio
async def test_a_cache_left_non_empty_but_incomplete_heals_on_the_next_render():
    """The poisoned state the old fetch left behind: entries present, one file absent."""
    loader.templates.clear()
    loader.loaded_dirs.clear()

    renderer = AsyncTemplateRenderer()
    await renderer.fetch_templates()

    loader.templates.pop("welcome.html")
    assert loader.templates, "the cache must stay non-empty, or the old guard fires"
    assert "welcome.html" not in loader.templates

    # The directory is not marked loaded, because the swap never completed for
    # this state, so the render fetches again instead of raising.
    loader.loaded_dirs.discard(renderer.template_dir)
    rendered = await renderer.render_template("welcome.html", name="x")
    assert "<!DOCTYPE html>" in rendered


@pytest.mark.asyncio
async def test_an_empty_fetch_does_not_mark_the_directory_loaded(tmp_path):
    """A fetch that produced nothing must not count as loaded.

    Marking it would make the guard skip the retry, so a template that appears
    after an empty or unreadable fetch would never be served until a restart —
    the same failure this change removes, on a different trigger.
    """
    loader.templates.clear()
    loader.loaded_dirs.clear()

    renderer = AsyncTemplateRenderer(template_dir=str(tmp_path))
    with pytest.raises(ValueError, match="not found"):
        await renderer.render_template("t.html")

    (tmp_path / "t.html").write_text("<p>t</p>")

    assert "<p>t</p>" in await renderer.render_template("t.html")
