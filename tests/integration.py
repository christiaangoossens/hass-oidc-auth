"""Access to what the integration registers in Home Assistant, for tests."""

from homeassistant.core import HomeAssistant

from custom_components.auth_oidc import DOMAIN
from custom_components.auth_oidc.provider import OpenIDAuthProvider
from custom_components.auth_oidc.stores.state_store import StateStore


def get_oidc_provider(hass: HomeAssistant) -> OpenIDAuthProvider:
    """Return the registered OIDC provider."""
    provider = hass.auth.get_auth_providers(DOMAIN)[0]
    assert isinstance(provider, OpenIDAuthProvider)
    return provider


def get_state_store(hass: HomeAssistant) -> StateStore:
    """Return the login states the integration's views share with the provider."""
    return get_oidc_provider(hass)._state_store
