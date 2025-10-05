"""Tests for the UI config flow"""

import pytest

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType


from custom_components.auth_oidc import DOMAIN, async_setup_entry
from custom_components.auth_oidc.config.const import (
    OIDC_PROVIDERS,
    CLIENT_ID,
    CLIENT_SECRET,
    DISCOVERY_URL,
    DISPLAY_NAME,
    FEATURES,
    FEATURES_AUTOMATIC_USER_LINKING,
    FEATURES_AUTOMATIC_PERSON_CREATION,
    FEATURES_INCLUDE_GROUPS_SCOPE,
    CLAIMS,
    CLAIMS_DISPLAY_NAME,
    CLAIMS_GROUPS,
    CLAIMS_USERNAME,
    ROLES,
    ROLE_ADMINS,
    ROLE_USERS,
)

from .mocks.oidc_server import MockOIDCServer, mock_oidc_responses

DEMO_CLIENT_ID = "testing_example_client_id"
DEMO_CLIENT_SECRET = "faz"
DEMO_ADMIN_ROLE = "boo"
DEMO_USER_ROLE = "far"


@pytest.mark.asyncio
async def test_full_config_flow_success(hass: HomeAssistant):
    """Test a successful full config flow."""

    with mock_oidc_responses():
        # 1. Start the user step
        # This simulates clicking "Add Integration" in the UI.
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )

        # Assert that it's a form and expects user input for the 'user' step
        # 'user' is always the first step if it is user triggered
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "user"
        assert result["data_schema"] is not None
        schema = result["data_schema"]
        # Extract the schema dict from voluptuous Schema
        schema_dict = schema.schema
        # Assert 'provider' is a key in the schema
        assert "provider" in schema_dict
        # Assert 'authentik' is one of the allowed values for 'provider'
        provider_field = schema_dict["provider"]
        # If provider_field is a voluptuous In validator, get its container
        allowed_providers = getattr(provider_field, "container", None)
        assert "authentik" in OIDC_PROVIDERS
        assert allowed_providers is not None and "authentik" in allowed_providers

        assert result["errors"] == {}

        # 2. Submit user input for the 'user' step
        # This simulates the user filling out host/port
        user_input_step_user = {"provider": "authentik"}
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input_step_user
        )

        # Assert that it proceeds to the 'auth' step
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "discovery_url"
        assert result["data_schema"] is not None
        assert result["errors"] == {}

        # Fill in the discovery URL
        user_input_step_discovery = {
            "discovery_url": MockOIDCServer.get_discovery_url()
        }
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input_step_discovery
        )

        # Assert that it proceeds to the 'credentials' step
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "validate_connection"

        # Assert that it validates correctly with our mock
        assert result["errors"] == {}

        # Send in continue
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"action": "continue"}
        )
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "client_config"
        assert result["data_schema"] is not None
        assert result["errors"] == {}

        # Fill in the client config
        user_input_step_client_config = {
            "client_id": DEMO_CLIENT_ID,
            "client_secret": DEMO_CLIENT_SECRET,
        }
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input_step_client_config
        )

        # Assert that we are at groups_config
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "groups_config"
        assert result["data_schema"] is not None
        assert result["errors"] == {}

        # Fill in the groups config
        user_input_step_groups_config = {
            "admin_group": DEMO_ADMIN_ROLE,
            "user_group": DEMO_USER_ROLE,
        }
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input_step_groups_config
        )

        # Assert that were are at user_linking config
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "user_linking"
        assert result["data_schema"] is not None
        assert result["errors"] == {}

        # Fill in the user linking config
        user_input_step_user_linking = {"enable_user_linking": False}
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input_step_user_linking
        )

        # Finally, assert that the flow is complete and a config entry is created
        assert result["type"] == FlowResultType.CREATE_ENTRY
        assert result["title"] == OIDC_PROVIDERS["authentik"]["name"]

        expected_data = {
            "provider": "authentik",
            CLIENT_ID: DEMO_CLIENT_ID,
            CLIENT_SECRET: DEMO_CLIENT_SECRET,
            DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
            DISPLAY_NAME: OIDC_PROVIDERS["authentik"]["name"],
            FEATURES: {
                FEATURES_AUTOMATIC_USER_LINKING: False,
                FEATURES_AUTOMATIC_PERSON_CREATION: True,
                FEATURES_INCLUDE_GROUPS_SCOPE: True,
            },
            CLAIMS: {
                CLAIMS_DISPLAY_NAME: OIDC_PROVIDERS["authentik"]["claims"][
                    "display_name"
                ],
                CLAIMS_USERNAME: OIDC_PROVIDERS["authentik"]["claims"]["username"],
                CLAIMS_GROUPS: OIDC_PROVIDERS["authentik"]["claims"]["groups"],
            },
            ROLES: {ROLE_ADMINS: DEMO_ADMIN_ROLE, ROLE_USERS: DEMO_USER_ROLE},
        }

        assert result["data"] == expected_data

        # Verify that the config entry was loaded into Home Assistant
        entries = hass.config_entries.async_entries(DOMAIN)
        assert len(entries) == 1
        assert entries[0].data == expected_data

        # You can also assert that `async_setup_entry` was called for this entry
        # (assuming it's mocked or you let it run if it's simple)
        # The PHCC `hass` fixture automatically mocks `async_setup_entry`
        # and `async_unload_entry` for you, making it easy to test that they're called.
        assert await async_setup_entry(hass, entries[0]) is True


@pytest.mark.asyncio
async def test_options_flow_success(hass: HomeAssistant):
    """Test a successful options flow."""

    # First, set up an initial config entry as in the full config flow
    initial_data = {
        "provider": "authentik",
        CLIENT_ID: DEMO_CLIENT_ID,
        CLIENT_SECRET: DEMO_CLIENT_SECRET,
        DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
        DISPLAY_NAME: OIDC_PROVIDERS["authentik"]["name"],
        FEATURES: {
            FEATURES_AUTOMATIC_USER_LINKING: False,
            FEATURES_AUTOMATIC_PERSON_CREATION: True,
            FEATURES_INCLUDE_GROUPS_SCOPE: True,
        },
        CLAIMS: {
            CLAIMS_DISPLAY_NAME: OIDC_PROVIDERS["authentik"]["claims"]["display_name"],
            CLAIMS_USERNAME: OIDC_PROVIDERS["authentik"]["claims"]["username"],
            CLAIMS_GROUPS: OIDC_PROVIDERS["authentik"]["claims"]["groups"],
        },
        ROLES: {ROLE_ADMINS: DEMO_ADMIN_ROLE, ROLE_USERS: DEMO_USER_ROLE},
    }

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=0,
        domain=DOMAIN,
        title=OIDC_PROVIDERS["authentik"]["name"],
        data=initial_data,
        source=config_entries.SOURCE_USER,
        entry_id="1",
        unique_id="test_unique_id",
        options={},
        pref_disable_new_entities=False,
        pref_disable_polling=False,
        discovery_keys=None,
        subentries_data=None,
    )

    await hass.config_entries.async_add(entry)

    # Start the reconfigure flow
    result = await hass.config_entries.options.async_init(entry.entry_id)

    # Should start the options flow
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "init"
    assert result["data_schema"] is not None

    # Assert that the schema is as expected
    # Schema contains enable_user_linking, enable_groups, admin_group & user_groups and no other keys
    schema = result["data_schema"]
    schema_dict = schema.schema
    # Assert that the schema contains the expected keys
    expected_keys = {
        "admin_group",
        "enable_user_linking",
        "enable_groups",
        "user_group",
    }
    assert set(schema_dict.keys()) == expected_keys

    # Change the client_id and client_secret
    new_enable_linking = True
    new_enable_groups = True
    new_admin_group = "bazzbbb"
    new_user_group = "foobar"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "enable_user_linking": new_enable_linking,
            "enable_groups": new_enable_groups,
            "admin_group": new_admin_group,
            "user_group": new_user_group,
        },
    )

    # Should finish and update the entry options
    assert result["type"] == FlowResultType.CREATE_ENTRY

    # Optionally, check that the entry options are updated
    updated_entry = hass.config_entries.async_get_entry(entry.entry_id)
    assert updated_entry is not None

    # Verify that the config entry was loaded into Home Assistant
    entries = hass.config_entries.async_entries(DOMAIN)
    assert len(entries) == 1

    assert (
        entries[0].data[FEATURES][FEATURES_AUTOMATIC_USER_LINKING] == new_enable_linking
    )
    assert entries[0].data[FEATURES][FEATURES_INCLUDE_GROUPS_SCOPE] == new_enable_groups
    assert entries[0].data[ROLES][ROLE_ADMINS] == new_admin_group
    assert entries[0].data[ROLES][ROLE_USERS] == new_user_group


@pytest.mark.asyncio
async def test_reconfigure_flow_success(hass: HomeAssistant):
    """Test a successful reconfigure flow."""

    # First, set up an initial config entry as in the full config flow
    initial_data = {
        "provider": "authentik",
        CLIENT_ID: DEMO_CLIENT_ID,
        CLIENT_SECRET: DEMO_CLIENT_SECRET,
        DISCOVERY_URL: MockOIDCServer.get_discovery_url(),
        DISPLAY_NAME: OIDC_PROVIDERS["authentik"]["name"],
        FEATURES: {
            FEATURES_AUTOMATIC_USER_LINKING: False,
            FEATURES_AUTOMATIC_PERSON_CREATION: True,
            FEATURES_INCLUDE_GROUPS_SCOPE: True,
        },
        CLAIMS: {
            CLAIMS_DISPLAY_NAME: OIDC_PROVIDERS["authentik"]["claims"]["display_name"],
            CLAIMS_USERNAME: OIDC_PROVIDERS["authentik"]["claims"]["username"],
            CLAIMS_GROUPS: OIDC_PROVIDERS["authentik"]["claims"]["groups"],
        },
        ROLES: {ROLE_ADMINS: DEMO_ADMIN_ROLE, ROLE_USERS: DEMO_USER_ROLE},
    }

    entry = config_entries.ConfigEntry(
        version=1,
        minor_version=0,
        domain=DOMAIN,
        title=OIDC_PROVIDERS["authentik"]["name"],
        data=initial_data,
        source=config_entries.SOURCE_USER,
        entry_id="1",
        unique_id="test_unique_id",
        options={},
        pref_disable_new_entities=False,
        pref_disable_polling=False,
        discovery_keys=None,
        subentries_data=None,
    )

    await hass.config_entries.async_add(entry)

    # Start async_step_reconfigure to reconfigure the entry
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={
            "source": config_entries.SOURCE_RECONFIGURE,
            "entry_id": entry.entry_id,
        },
    )

    # Should start the reconfigure flow
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    assert result["data_schema"] is not None

    # Assert that the schema is client_id & client_secret
    schema = result["data_schema"]
    schema_dict = schema.schema
    # Assert that the schema contains the expected keys
    expected_keys = {
        "client_id",
        "client_secret",
    }
    assert set(schema_dict.keys()) == expected_keys

    # Change the client_id and client_secret
    new_client_id = "newclientid"
    new_client_secret = "newclientsecret"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            "client_id": new_client_id,
            "client_secret": new_client_secret,
        },
    )

    # Should finish and update the entry data
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"

    # Verify that the config entry was loaded into Home Assistant
    entries = hass.config_entries.async_entries(DOMAIN)
    assert len(entries) == 1
    assert entries[0].data[CLIENT_ID] == new_client_id
    assert entries[0].data[CLIENT_SECRET] == new_client_secret
