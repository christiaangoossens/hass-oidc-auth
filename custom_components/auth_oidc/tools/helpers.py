"""Helper functions for the integration."""

import logging
from pathlib import Path
from typing import Optional

import aiofiles
from homeassistant.components import http

from ..views.loader import AsyncTemplateRenderer


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
    logger: logging.Logger,
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
        logger: Logger instance (e.g., _LOGGER).

    Returns:
        List of allowed algs (e.g., ['RS256', 'ES256']).
    """
    supported_algs = discovery.get("id_token_signing_alg_values_supported", [])

    if id_token_signing_alg:
        allowed_algs = [id_token_signing_alg]
        if id_token_signing_alg not in supported_algs:
            logger.warning(
                (
                "Configured signing algorithm '%s' is not in OP"
                " supported algorithms: %s. Proceeding anyway."
                ),
                id_token_signing_alg,
                supported_algs,
            )
    else:
        allowed_algs = supported_algs or ["RS256"]
        if not supported_algs:
            logger.info(
                (
                "No signing algorithms supported from OP"
                " discovery document! Will default to RS256"
                )
            )

    if verbose_debug_mode:
        logger.debug("Allowed ID token signing algorithms: %s", allowed_algs)

    return allowed_algs


async def capture_auth_flows(
    log_info: tuple[logging.Logger, int],
    verbose_debug_mode: bool,
    capture_dir: Path | None,
    debug_msg: str,
    filename: str,
    content: str,
    mode: str = "a",
    header: str = "",
    is_request: bool = False,
) -> None:
    """Helper to log verbose debug messages and optionally capture content to file.

    Reduces repetition in OIDCClient/OIDCDiscoveryClient verbose logging and file captures.
    Only writes/captures if verbose_debug_mode is True and capture_dir exists.

    Args:
        log_info: Tuple containing logger instance (e.g., (_LOGGER, 10) is Debug level).
        verbose_debug_mode: Whether verbose mode is enabled.
        capture_dir: Directory path for captures (if None, skips file write).
        debug_msg: Message for _LOGGER.debug().
        filename: Base filename for capture file (e.g., 'get_discovery.txt').
        content: Content to write (e.g., JSON string or URL).
        mode: File write mode ('w' to overwrite, 'a' to append).
        header: Prepend header comment to content (e.g., discovery endpoint info).
        is_request: If True, uses 'BEGIN REQUEST' header; else 'BEGIN RESPONSE'.
    """

    # Unpack logger and log level
    logger, log_level = log_info

    if verbose_debug_mode:
        logger.log(log_level, debug_msg)

    if verbose_debug_mode and capture_dir:
        header_str = (
            f"/*\n----------BEGIN {'REQUEST' if is_request else 'RESPONSE'}----------\n"
            f"{header}*/\n\n"
            if header
            else ""
        )
        full_content = header_str + content
        file_path = capture_dir / filename
        async with aiofiles.open(file_path, mode=mode, encoding="utf-8") as f:
            await f.write(full_content)
        logger.log(
            log_level,
            "Check %s capture in: %s for more details...",
            filename,
            file_path,
        )
