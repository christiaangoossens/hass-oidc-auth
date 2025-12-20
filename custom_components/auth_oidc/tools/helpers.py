"""Helper functions for the integration."""

from homeassistant.components import http
from ..views.loader import AsyncTemplateRenderer
from typing import Optional


def get_url(path: str, force_https: bool) -> str:
    """Returns the requested path appended to the current request base URL."""
    if (req := http.current_request.get()) is None:
        raise RuntimeError("No current request in context")

    base_uri = str(req.url).split("/auth", 2)[0]
    if force_https:
        base_uri = base_uri.replace("http://", "https://")
    return f"{base_uri}{path}"


async def get_view(template: str, parameters: dict | None = None) -> str:
    """Returns the generated HTML of the requested view."""
    if parameters is None:
        parameters = {}

    renderer = AsyncTemplateRenderer()
    return await renderer.render_template(f"{template}.html", **parameters)

def compute_allowed_signing_algs(
    discovery: dict,
    id_token_signing_alg: Optional[str],
    verbose_debug_mode: bool,
    logger,
) -> list[str]:
    """Compute allowed ID token signing algorithms from config and OP discovery document.
    
    - If `id_token_signing_alg` set: Use only it (warn if not in OP-supported).
    - Else: Use OP's `id_token_signing_alg_values_supported` (fallback ['RS256']).
    
    Args:
        discovery: Fetched OIDC discovery document.
        id_token_signing_alg: Configured alg from
        self.id_token_signing_alg (or None; falls
        back to DEFAULT_ID_TOKEN_SIGNING_ALGORITHM="RS256").
        verbose_debug_mode: Enable debug logs.
    
    Returns:
        List of allowed algs (e.g., ['RS256', 'ES256']).
    """
    supported_algs = discovery.get("id_token_signing_alg_values_supported", [])
    
    if id_token_signing_alg:
        allowed_algs = [id_token_signing_alg]
        if id_token_signing_alg not in supported_algs:
            logger.warning(
                "Configured id_token_signing_alg '%s' not in OP supported algorithms %s. Proceeding anyway.",
                id_token_signing_alg, supported_algs
            )
    else:
        allowed_algs = supported_algs or ["RS256"]
        if not supported_algs:
            logger.info(
                "No 'id_token_signing_alg_values_supported' in discovery document, defaulting to RS256"
            )
    
    if verbose_debug_mode:
        logger.debug("Allowed ID token signing algorithms: %s", allowed_algs)
    
    return allowed_algs