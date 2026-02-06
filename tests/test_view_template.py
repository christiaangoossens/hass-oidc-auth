"""Tests for the view templates"""

import pytest
from os import path

from custom_components.auth_oidc.views.loader import AsyncTemplateRenderer

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
