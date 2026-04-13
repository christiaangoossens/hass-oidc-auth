"""SSE handler for OIDC device authentication."""

import asyncio
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from ..provider import OpenIDAuthProvider

PATH = "/auth/oidc/device-sse"


class OIDCDeviceSSE(HomeAssistantView):
    """OIDC Plugin SSE Handler."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:device-sse"

    def __init__(self, oidc_provider: OpenIDAuthProvider) -> None:
        self.oidc_provider = oidc_provider

    async def get(self, req: web.Request) -> web.Response:
        """Check for mobile sign-in completion with short server-side polling."""
        state_id = req.cookies.get("auth_oidc_state")
        if not state_id:
            raise web.HTTPBadRequest(text="Missing session cookie")

        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
        await response.prepare(req)

        try:
            while True:
                ready = await self.oidc_provider.async_is_state_ready(state_id)
                if ready:
                    await response.write(b"event: ready\ndata: true\n\n")
                    break

                await response.write(b"event: waiting\ndata: false\n\n")
                await asyncio.sleep(2)
        except (ConnectionResetError, RuntimeError):
            # Client disconnected while listening for state changes.
            pass
        finally:
            try:
                await response.write_eof()
            except ConnectionResetError:
                pass

        return response
