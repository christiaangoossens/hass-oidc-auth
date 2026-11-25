"""Put our own handler in front of an existing Home Assistant GET route."""

from collections.abc import Awaitable, Callable

from aiohttp import web
from homeassistant.core import HomeAssistant

type Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


def take_over_get_route(
    hass: HomeAssistant, path: str, wrap: Callable[[Handler], Handler]
) -> bool:
    """Serve GET requests for path with wrap(original handler).

    The handler is swapped in place, so the route keeps its CORS settings and
    other methods. Returns False if the route is not found or the swap did not work.
    """
    for resource in hass.http.app.router.resources():
        if resource.canonical != path:
            continue

        route = next((route for route in resource if route.method == "GET"), None)
        if route is None:
            return False

        # aiohttp has no public way to replace a handler, so check that it worked
        wrapper = wrap(route.handler)
        # pylint: disable-next=protected-access
        route._handler = wrapper  # pyright: ignore[reportAttributeAccessIssue]
        return route.handler is wrapper

    return False
