"""Back-channel logout endpoint (Relying Party side).

Receives logout tokens from the OpenID Provider when a user logs out (or a
session is terminated) at the IdP and revokes the linked Home Assistant
user's refresh tokens.

Endpoint configured at the IdP as the Back-Channel Logout URL:
    https://<home-assistant>/auth/oidc/backchannel_logout
"""

import logging

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..config.const import BACKCHANNEL_LOGOUT_PATH
from ..provider import OpenIDAuthProvider
from ..tools.backchannel import BackchannelLogoutValidator, LogoutTokenInvalid
from ..tools.oidc_client import OIDCClient, hash_subject

_LOGGER = logging.getLogger(__name__)

PATH = BACKCHANNEL_LOGOUT_PATH


class OIDCBackchannelLogoutView(HomeAssistantView):
    """OIDC Back-Channel Logout View.

    This endpoint is unauthenticated on purpose: the OpenID Provider calls it
    server-to-server without a Home Assistant session. Authenticity is instead
    established by validating the signed logout token with the OP's JWKS.
    """

    requires_auth = False
    url = PATH
    name = "auth:oidc:backchannel_logout"

    def __init__(
        self,
        oidc_client: OIDCClient,
        oidc_provider: OpenIDAuthProvider,
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider
        self.validator = BackchannelLogoutValidator(oidc_client)

    async def post(self, request: web.Request) -> web.Response:
        """Handle a logout token posted by the OpenID Provider."""
        data = await request.post()
        logout_token = data.get("logout_token")

        if not logout_token:
            _LOGGER.warning("Back-channel logout request without a logout_token")
            return web.Response(status=400, text="missing logout_token")

        try:
            claims = await self.validator.validate(logout_token)
        except LogoutTokenInvalid as e:
            _LOGGER.warning("Rejected back-channel logout token: %s", e)
            return web.Response(status=400, text="invalid logout_token")

        await self._async_revoke_linked_sessions(claims)
        return web.Response(status=200, text="OK")

    async def _async_revoke_linked_sessions(self, claims: dict) -> None:
        """Coarsely revoke all refresh tokens of the linked Home Assistant user.

        Revocation is based on the ``sub`` claim only. This logs out every
        device/session for the user, not just the single session identified by
        an optional ``sid`` claim (per-session revocation would require Home
        Assistant core hooks that are not available to custom integrations).
        """
        # Set by the validator while fetching discovery during validation.
        discovery_document = self.oidc_client.discovery_document or {}
        expected_sub = hash_subject(discovery_document["issuer"], claims["sub"])
        sid = claims.get("sid")

        for user in await self.oidc_provider.hass.auth.async_get_users():
            is_linked = any(
                credential.auth_provider_type == self.oidc_provider.type
                and credential.auth_provider_id == self.oidc_provider.id
                and credential.data.get("sub") == expected_sub
                for credential in user.credentials
            )
            if not is_linked:
                continue

            refresh_tokens = list(user.refresh_tokens.values())
            for refresh_token in refresh_tokens:
                self.oidc_provider.hass.auth.async_remove_refresh_token(refresh_token)

            _LOGGER.info(
                "Back-channel logout revoked %d refresh token(s) for a linked "
                "Home Assistant user (sid present: %s)",
                len(refresh_tokens),
                sid is not None,
            )
            return

        _LOGGER.warning(
            "Back-channel logout received for a subject with no linked "
            "Home Assistant user; nothing to revoke"
        )
