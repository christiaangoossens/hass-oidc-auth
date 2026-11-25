"""SSE handler for OIDC device authentication."""

import asyncio

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..stores.state_store import StateStore
from ..tools.helpers import get_valid_state_id

PATH = "/auth/oidc/device-sse"

POLL_SECONDS = 0.5

# Proxies and mobile networks may close a connection that stays silent for too long
KEEPALIVE_SECONDS = 15

HEADERS = {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    # Stops nginx from buffering the stream
    "X-Accel-Buffering": "no",
}

EXPIRED_EVENT = b"event: expired\ndata: false\n\n"


class OIDCDeviceSSE(HomeAssistantView):
    """OIDC Plugin SSE Handler."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:device-sse"

    def __init__(self, state_store: StateStore) -> None:
        self.state_store = state_store

    async def get(self, req: web.Request) -> web.StreamResponse:
        """Stream the login state of this device until its code is approved."""
        state_id = get_valid_state_id(req, self.state_store)

        response = web.StreamResponse(status=200, headers=HEADERS)
        await response.prepare(req)

        try:
            if state_id:
                await self._wait_for_approval(response, state_id, req.remote)
            else:
                # Also an answer, so the page can offer a new code instead of retrying
                await response.write(EXPIRED_EVENT)
        except (ConnectionResetError, RuntimeError):
            # Client disconnected while listening for state changes.
            pass
        finally:
            try:
                await response.write_eof()
            except ConnectionResetError:
                pass

        return response

    async def _wait_for_approval(
        self, response: web.StreamResponse, state_id: str, ip: str | None
    ) -> None:
        """Poll the state until it is ready or expired, with keepalives in between."""
        loop = asyncio.get_running_loop()
        last_write = loop.time()
        await response.write(b"event: waiting\ndata: false\n\n")

        while True:
            if self.state_store.is_state_ready(state_id, ip):
                await response.write(b"event: ready\ndata: true\n\n")
                return

            if not self.state_store.is_state_valid(state_id, ip):
                await response.write(EXPIRED_EVENT)
                return

            if loop.time() - last_write >= KEEPALIVE_SECONDS:
                await response.write(b": keepalive\n\n")
                last_write = loop.time()

            await asyncio.sleep(POLL_SECONDS)
