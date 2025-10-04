"""Config flow for OIDC Authentication integration."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any
import aiohttp

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import (
    DOMAIN,
    DEFAULT_ADMIN_GROUP,
    CLIENT_ID,
    CLIENT_SECRET,
    DISCOVERY_URL,
    DISPLAY_NAME,
    FEATURES,
    CLAIMS,
    ROLES,
    DEFAULT_ID_TOKEN_SIGNING_ALGORITHM,
)

from ..tools.oidc_client import (
    OIDCDiscoveryClient,
    OIDCDiscoveryInvalid,
    OIDCJWKSInvalid,
)

from .provider_catalog import (
    OIDC_PROVIDERS,
    get_provider_name,
    get_provider_docs_url,
)

from ..tools.validation import (
    validate_discovery_url,
    sanitize_client_secret,
    validate_client_id,
)

_LOGGER = logging.getLogger(__name__)


# Configuration field names
CONF_PROVIDER = "provider"
CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"
CONF_DISCOVERY_URL = "discovery_url"
CONF_ENABLE_GROUPS = "enable_groups"
CONF_ADMIN_GROUP = "admin_group"
CONF_USER_GROUP = "user_group"
CONF_ENABLE_USER_LINKING = "enable_user_linking"

# Cache settings
DISCOVERY_CACHE_TTL = 300  # 5 minutes
MAX_CACHE_SIZE = 10


@dataclass
class FlowState:
    """State tracking for the configuration flow."""

    provider: str | None = None
    discovery_url: str | None = None


@dataclass
class ClientConfig:
    """Client configuration settings."""

    client_id: str | None = None
    client_secret: str | None = None


@dataclass
class FeatureConfig:
    """Feature configuration settings."""

    enable_groups: bool = False
    admin_group: str = DEFAULT_ADMIN_GROUP
    user_group: str | None = None
    enable_user_linking: bool = False


class OIDCConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for OIDC Authentication."""

    VERSION = 1

    def is_matching(self, other_flow):
        """Check if this flow is the same as another flow."""
        self_state = getattr(self, "_flow_state", None)
        other_state = getattr(other_flow, "_flow_state", None)

        if not self_state or not other_state:
            return False

        self_discovery_url = self_state.discovery_url
        other_discovery_url = other_state.discovery_url

        return (
            self_discovery_url
            and other_discovery_url
            and self_discovery_url.rstrip("/").lower()
            == other_discovery_url.rstrip("/").lower()
        )

    def __init__(self):
        """Initialize the config flow."""
        self._flow_state = FlowState()
        self._client_config = ClientConfig()
        self._feature_config = FeatureConfig()
        self._discovery_cache = {}
        self._cache_timestamps = {}

    @property
    def current_provider_config(self) -> dict[str, Any]:
        """Get the configuration for the currently selected provider."""
        if not self._flow_state.provider:
            return {}
        return OIDC_PROVIDERS.get(self._flow_state.provider, {})

    @property
    def current_provider_name(self) -> str:
        """Get the name of the currently selected provider."""
        return get_provider_name(self._flow_state.provider)

    def _cleanup_discovery_cache(self) -> None:
        """Remove expired and excess cache entries."""
        current_time = time.time()

        # Remove expired entries
        expired_keys = [
            key
            for key, timestamp in self._cache_timestamps.items()
            if current_time - timestamp > DISCOVERY_CACHE_TTL
        ]
        for key in expired_keys:
            self._discovery_cache.pop(key, None)
            self._cache_timestamps.pop(key, None)

        # Remove oldest entries if cache is too large
        if len(self._discovery_cache) > MAX_CACHE_SIZE:
            sorted_items = sorted(self._cache_timestamps.items(), key=lambda x: x[1])
            excess_count = len(self._discovery_cache) - MAX_CACHE_SIZE
            for key, _ in sorted_items[:excess_count]:
                self._discovery_cache.pop(key, None)
                self._cache_timestamps.pop(key, None)

    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if a cache entry is still valid."""
        if cache_key not in self._cache_timestamps:
            return False

        age = time.time() - self._cache_timestamps[cache_key]
        return age <= DISCOVERY_CACHE_TTL

    # =================
    # Step 1: Provider selection
    # =================

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step - provider selection."""
        # Check if OIDC is already configured (only one instance allowed)
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        # Check if YAML configuration exists
        if self.hass.data.get(DOMAIN, {}).get("yaml_config"):
            return self.async_abort(reason="yaml_configured")

        errors = {}

        if user_input is not None:
            self._flow_state.provider = user_input[CONF_PROVIDER]

            # If provider has a predefined discovery URL, prefill it but still
            # show the discovery URL step so the user can customize it.
            predefined = self.current_provider_config.get("discovery_url")
            if predefined:
                self._flow_state.discovery_url = predefined

            # Always request discovery URL next (prefilled when available)
            return await self.async_step_discovery_url()

        data_schema = vol.Schema(
            {
                vol.Required(CONF_PROVIDER): vol.In(
                    {key: provider["name"] for key, provider in OIDC_PROVIDERS.items()}
                )
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={},
        )

    # =================
    # Step 2: Discovery URL
    # =================

    async def async_step_discovery_url(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle discovery URL input for providers requiring URL configuration."""
        errors = {}

        if user_input is not None:
            discovery_url = user_input[CONF_DISCOVERY_URL].rstrip("/")

            # Validate discovery URL format
            if not validate_discovery_url(discovery_url):
                errors["discovery_url"] = "invalid_url_format"
            else:
                self._flow_state.discovery_url = discovery_url
                return await self.async_step_validate_connection()

        provider_name = self.current_provider_name
        provider_key = self._flow_state.provider

        # Pre-populate with existing discovery URL if available
        default_url = (
            self._flow_state.discovery_url
            if self._flow_state.discovery_url
            else vol.UNDEFINED
        )

        data_schema = vol.Schema(
            {vol.Required(CONF_DISCOVERY_URL, default=default_url): str}
        )

        return self.async_show_form(
            step_id="discovery_url",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "provider_name": provider_name,
                "documentation_url": get_provider_docs_url(provider_key),
            },
        )

    # =================
    # Step 3: Discovery Validation
    # =================

    async def _handle_validation_actions(
        self, user_input: dict[str, Any]
    ) -> FlowResult | None:
        """Handle user actions from the validation form so they can fix errors."""
        action = user_input.get("action")

        # Handle special actions first
        if action == "retry":
            return None  # Continue with validation
        if action == "continue":
            return await self.async_step_client_config()

        # Handle redirect actions
        action_handlers = {
            "fix_discovery": self.async_step_discovery_url,
            "change_provider": self.async_step_user,
        }

        handler = action_handlers.get(action)
        return await handler() if handler else None

    async def _perform_oidc_validation(self) -> tuple[dict, dict]:
        """Perform the actual OIDC validation and return discovery doc and errors."""
        errors = {}
        discovery_doc = {}

        try:
            http_session = aiohttp.ClientSession()
            discovery_client = OIDCDiscoveryClient(
                discovery_url=self._flow_state.discovery_url,
                http_session=http_session,
                verification_context={
                    # Cannot be changed from the UI config currently
                    "id_token_signing_alg": DEFAULT_ID_TOKEN_SIGNING_ALGORITHM,
                },
            )

            # Clean up expired cache entries first
            self._cleanup_discovery_cache()

            # Check if discovery document is already cached and valid
            cache_key = self._flow_state.discovery_url
            if cache_key in self._discovery_cache and self._is_cache_valid(cache_key):
                discovery_doc = self._discovery_cache[cache_key]

                # Still validate JWKS if available since this might be a retry
                if "jwks_uri" in discovery_doc:
                    await discovery_client.fetch_jwks(discovery_doc["jwks_uri"])
            else:
                # Perform discovery and JWKS validation
                discovery_doc = await discovery_client.fetch_discovery_document()

                # Cache the discovery document with timestamp
                self._discovery_cache[cache_key] = discovery_doc
                self._cache_timestamps[cache_key] = time.time()

                # Validate JWKS if available
                if "jwks_uri" in discovery_doc:
                    await discovery_client.fetch_jwks(discovery_doc["jwks_uri"])

        except OIDCDiscoveryInvalid as e:
            errors["base"] = "discovery_invalid"
            errors["detail_string"] = e.get_detail_string()
        except OIDCJWKSInvalid:
            errors["base"] = "jwks_invalid"
        except aiohttp.ClientError:
            errors["base"] = "cannot_connect"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected error during validation")
            errors["base"] = "unknown"

        await http_session.close()
        return discovery_doc, errors

    def _get_action_options(self, has_errors: bool) -> dict[str, str]:
        """Get action options based on validation state."""
        if has_errors:
            return {
                "retry": "Retry Validation",
                "fix_discovery": "Change Discovery URL",
                "change_provider": "Change Provider",
            }
        return {
            "continue": "Continue Setup",
            "fix_discovery": "Change Discovery URL",
            "change_provider": "Change Provider",
        }

    def _build_discovery_success_details(self, discovery_doc: dict) -> str:
        """Build success details from discovery document."""
        return (
            f"✅ Connected and verified succesfully!\n"
            f"_Discovered valid OIDC issuer: {discovery_doc['issuer']}_\n\n"
        )

    def _build_error_details(self, errors: dict[str, str]) -> str:
        """Build error details from validation errors."""

        base = errors.get("base", "")
        detail_string = errors.get("detail_string", "")

        error_messages = {
            "discovery_invalid": (
                "❌ **Discovery document could not be validated.**\n"
                "Please verify the discovery URL is correct and accessible.\n\n"
                f"_({detail_string})_"
            ),
            "jwks_invalid": (
                "❌ **JWKS validation failed**\n"
                "The JSON Web Key Set could not be retrieved or validated."
            ),
            "cannot_connect": (
                "❌ **Connection failed**\n"
                "Unable to connect to the OIDC provider. Check your network and URL."
            ),
        }
        return error_messages.get(base, "")

    async def _build_validation_form(
        self, errors: dict[str, str], discovery_doc: dict | None = None
    ) -> FlowResult:
        """Build the validation form with errors and action options."""
        action_options = self._get_action_options(bool(errors))
        data_schema = vol.Schema({vol.Required("action"): vol.In(action_options)})

        # Build description with discovery details
        description_placeholders = {
            "discovery_url": self._flow_state.discovery_url,
            "provider_name": self.current_provider_name,
            "discovery_details": "",
            "documentation_url": get_provider_docs_url(self._flow_state.provider),
        }

        # Add appropriate details based on validation state
        if discovery_doc and not errors:
            description_placeholders["discovery_details"] = (
                self._build_discovery_success_details(discovery_doc)
            )
        elif errors:
            description_placeholders["discovery_details"] = self._build_error_details(
                errors
            )

        return self.async_show_form(
            step_id="validate_connection",
            data_schema=data_schema,
            errors=errors,
            description_placeholders=description_placeholders,
        )

    async def async_step_validate_connection(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Validate the OIDC configuration by testing discovery and JWKS."""
        # Handle user actions from validation form
        if user_input is not None:
            action_result = await self._handle_validation_actions(user_input)
            if action_result is not None:
                return action_result

        # Perform validation (either initial attempt or retry)
        discovery_doc, errors = await self._perform_oidc_validation()

        # Always show validation form with results (success or error)
        return await self._build_validation_form(errors, discovery_doc)

    # =================
    # Step 4: Configure client details (client_id & client_secret)
    # =================

    async def _proceed_to_next_step_after_client_config(self) -> FlowResult:
        """Proceed to next step after client config."""
        if self.current_provider_config.get("supports_groups", True):
            return await self.async_step_groups_config()
        return await self.async_step_user_linking()

    async def async_step_client_config(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle client ID and client type selection."""
        errors = {}

        if user_input is not None:
            client_id = user_input[CONF_CLIENT_ID]

            # Validate client ID
            if not validate_client_id(client_id):
                errors["client_id"] = "invalid_client_id"
            if not errors:
                self._client_config.client_id = client_id.strip()
                # Optional client secret determines confidential/public
                provided_secret = sanitize_client_secret(
                    user_input.get(CONF_CLIENT_SECRET, "")
                )
                self._client_config.client_secret = provided_secret or None

                if not errors:
                    return await self._proceed_to_next_step_after_client_config()

        provider_name = self.current_provider_name

        # Pre-populate with existing values if available
        default_client_id = (
            self._client_config.client_id
            if self._client_config.client_id
            else vol.UNDEFINED
        )
        default_client_secret = (
            self._client_config.client_secret
            if self._client_config.client_secret
            else vol.UNDEFINED
        )

        data_schema = vol.Schema(
            {
                vol.Required(CONF_CLIENT_ID, default=default_client_id): str,
                vol.Optional(CONF_CLIENT_SECRET, default=default_client_secret): str,
            }
        )

        return self.async_show_form(
            step_id="client_config",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "provider_name": provider_name,
                "discovery_url": self._flow_state.discovery_url,
                "documentation_url": get_provider_docs_url(self._flow_state.provider),
            },
        )

    # =================
    # Step 5: Configure groups settings
    # =================

    async def async_step_groups_config(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure groups and roles."""
        errors = {}

        if user_input is not None:
            self._feature_config.enable_groups = user_input.get(
                CONF_ENABLE_GROUPS, False
            )
            if self._feature_config.enable_groups:
                self._feature_config.admin_group = user_input.get(
                    CONF_ADMIN_GROUP, "admins"
                )
                self._feature_config.user_group = user_input.get(CONF_USER_GROUP)

            return await self.async_step_user_linking()

        default_admin_group = self.current_provider_config.get(
            "default_admin_group", "admins"
        )

        data_schema_dict = {vol.Optional(CONF_ENABLE_GROUPS, default=True): bool}

        # Add group configuration fields if groups are enabled
        if user_input is None or user_input.get(CONF_ENABLE_GROUPS, True):
            data_schema_dict.update(
                {
                    vol.Optional(CONF_ADMIN_GROUP, default=default_admin_group): str,
                    vol.Optional(CONF_USER_GROUP): str,
                }
            )

        data_schema = vol.Schema(data_schema_dict)

        return self.async_show_form(
            step_id="groups_config",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={"provider_name": self.current_provider_name},
        )

    # =================
    # Step 6: Configure user linking
    # =================

    async def async_step_user_linking(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure user linking options."""
        errors = {}

        if user_input is not None:
            self._feature_config.enable_user_linking = user_input.get(
                CONF_ENABLE_USER_LINKING, False
            )
            return await self.async_step_finalize()

        data_schema = vol.Schema(
            {vol.Optional(CONF_ENABLE_USER_LINKING, default=False): bool}
        )

        return self.async_show_form(
            step_id="user_linking",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={},
        )

    # =================
    # Step 7: Finalize and create entry
    # =================

    async def async_step_finalize(self) -> FlowResult:
        """Finalize the configuration and create the config entry."""
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()

        # Build the configuration
        config_data = {
            "provider": self._flow_state.provider,
            "client_id": self._client_config.client_id,
            "discovery_url": self._flow_state.discovery_url,
            "display_name": f"{self.current_provider_name}",
        }

        # Add optional fields
        if self._client_config.client_secret:
            config_data["client_secret"] = self._client_config.client_secret

        # Configure features
        features = {
            "automatic_user_linking": self._feature_config.enable_user_linking,
            "automatic_person_creation": True,
            "include_groups_scope": self._feature_config.enable_groups,
        }
        config_data["features"] = features

        # Configure claims using provider defaults
        claims = self.current_provider_config["claims"].copy()
        config_data["claims"] = claims

        # Configure roles if groups are enabled
        if self._feature_config.enable_groups:
            roles = {}
            if self._feature_config.admin_group:
                roles["admin"] = self._feature_config.admin_group
            if self._feature_config.user_group:
                roles["user"] = self._feature_config.user_group
            config_data["roles"] = roles

        title = f"{self.current_provider_name}"

        return self.async_create_entry(title=title, data=config_data)

    # =================
    # Allow reconfiguration of client ID and secret
    # =================

    async def _validate_reconfigure_input(
        self, entry, user_input: dict[str, Any]
    ) -> tuple[dict[str, str], dict[str, Any] | None]:
        """Validate reconfigure input and return errors and data updates."""
        errors = {}

        # Validate client ID
        client_id = user_input[CONF_CLIENT_ID].strip()
        if not validate_client_id(client_id):
            errors["client_id"] = "invalid_client_id"
            return errors, None

        # Determine confidentiality by presence of client secret
        client_secret = user_input.get(CONF_CLIENT_SECRET, "").strip()
        # If secret is empty, keep the existing one (if any)
        if not client_secret:
            client_secret = entry.data.get("client_secret")

        # Build updated data
        data_updates = {"client_id": client_id}

        if client_secret:
            data_updates["client_secret"] = client_secret
        elif "client_secret" in entry.data and not client_secret:
            # Remove client secret if switching from confidential to public
            data_updates = {**entry.data, **data_updates}
            data_updates.pop("client_secret", None)

        return errors, data_updates

    def _build_reconfigure_schema(
        self, current_data: dict[str, Any], _user_input: dict[str, Any] | None
    ) -> vol.Schema:
        """Build the reconfigure form schema."""
        schema_dict = {
            vol.Required(
                CONF_CLIENT_ID, default=current_data.get("client_id", vol.UNDEFINED)
            ): str,
        }

        # Always allow updating or clearing the client secret
        schema_dict[vol.Optional(CONF_CLIENT_SECRET)] = str

        return vol.Schema(schema_dict)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reconfiguration of OIDC client credentials."""
        errors = {}
        entry = self._get_reconfigure_entry()
        if entry is None:
            return self.async_abort(reason="unknown")

        if user_input is not None:
            try:
                errors, data_updates = await self._validate_reconfigure_input(
                    entry, user_input
                )

                if not errors:
                    # Update the config entry
                    await self.async_set_unique_id(entry.unique_id)
                    self._abort_if_unique_id_mismatch()

                    return self.async_update_reload_and_abort(
                        entry, data_updates=data_updates
                    )
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected error during reconfiguration")
                errors["base"] = "unknown"

        # Show form
        current_data = entry.data
        data_schema = self._build_reconfigure_schema(current_data, user_input)

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=data_schema,
            errors=errors,
            description_placeholders={
                "provider_name": get_provider_name(current_data.get("provider")),
                "discovery_url": current_data.get("discovery_url", ""),
            },
        )

    def _get_reconfigure_entry(self):
        """Return the config entry being reconfigured if available.

        Prefer the entry referenced by the flow context's entry_id. Fall back to the
        first existing entry for this domain when only a single instance is allowed.
        """
        # Try from flow context (preferred)
        entry_id = None
        context = getattr(self, "context", None)
        if context and hasattr(context, "get"):
            entry_id = context.get("entry_id")

        if entry_id:
            entry = self.hass.config_entries.async_get_entry(entry_id)
            if entry and entry.domain == DOMAIN:
                return entry

        # Fallback: this integration allows a single instance; use the first
        current = self._async_current_entries()
        if current:
            return current[0]

        return None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return OIDCOptionsFlowHandler()


class OIDCOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for OIDC Authentication."""

    async def async_step_init(self, user_input=None):
        """Handle options flow."""
        if user_input is not None:
            # Process the updated configuration
            updated_features = {
                "automatic_user_linking": user_input.get("enable_user_linking", False),
                "include_groups_scope": user_input.get("enable_groups", False),
            }

            updated_roles = {}
            if user_input.get("enable_groups", False):
                if user_input.get("admin_group"):
                    updated_roles["admin"] = user_input["admin_group"]
                if user_input.get("user_group"):
                    updated_roles["user"] = user_input["user_group"]

            # Update the config entry data
            new_data = self.config_entry.data.copy()
            new_data["features"] = {**new_data.get("features", {}), **updated_features}
            if updated_roles:
                new_data["roles"] = updated_roles
            elif "roles" in new_data:
                # Remove roles if groups are disabled
                if not user_input.get("enable_groups", False):
                    del new_data["roles"]

            # Update the config entry
            self.hass.config_entries.async_update_entry(
                self.config_entry, data=new_data
            )

            return self.async_create_entry(title="", data={})

        current_config = self.config_entry.data
        current_features = current_config.get("features", {})
        current_roles = current_config.get("roles", {})

        # Determine if this provider supports groups
        provider = current_config.get("provider", "authentik")
        provider_supports_groups = OIDC_PROVIDERS.get(provider, {}).get(
            "supports_groups", True
        )

        # Build schema based on provider capabilities
        schema_dict = {
            vol.Optional(
                "enable_user_linking",
                default=current_features.get("automatic_user_linking", False),
            ): bool
        }

        # Add groups options if provider supports them
        if provider_supports_groups:
            enable_groups_default = current_features.get("include_groups_scope", False)
            schema_dict[
                vol.Optional("enable_groups", default=enable_groups_default)
            ] = bool

            # Add group name fields if groups are currently enabled or being enabled
            if enable_groups_default or (
                user_input and user_input.get("enable_groups", False)
            ):
                schema_dict.update(
                    {
                        vol.Optional(
                            "admin_group",
                            default=current_roles.get("admin", DEFAULT_ADMIN_GROUP),
                        ): str,
                        vol.Optional(
                            "user_group", default=current_roles.get("user", "")
                        ): str,
                    }
                )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(schema_dict),
            description_placeholders={
                "provider_name": get_provider_name(provider),
            },
        )


def convert_ui_config_entry_to_internal_format(config_data: dict) -> dict:
    """Convert config entry data to internal configuration format."""
    my_config = {}

    # Required fields
    my_config[CLIENT_ID] = config_data["client_id"]
    my_config[DISCOVERY_URL] = config_data["discovery_url"]

    # Optional fields
    if "client_secret" in config_data:
        my_config[CLIENT_SECRET] = config_data["client_secret"]

    if "display_name" in config_data:
        my_config[DISPLAY_NAME] = config_data["display_name"]

    # Features configuration
    if "features" in config_data:
        my_config[FEATURES] = config_data["features"]

    # Claims configuration
    if "claims" in config_data:
        my_config[CLAIMS] = config_data["claims"]

    # Roles configuration
    if "roles" in config_data:
        my_config[ROLES] = config_data["roles"]

    return my_config
