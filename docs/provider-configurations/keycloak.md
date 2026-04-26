# Keycloak

> [!TIP]
> This guide describes configuring Keycloak. Due to how Keycloak handles user roles and groups, you must configure a specific **Group Membership Mapper** in Keycloak for this integration to work correctly.

## Step 1. Install the integration

Make sure that you have fully installed the latest release of the integration. The easiest way to install the integration is through [the Home Assistant Community Store (HACS)](https://hacs.xyz/). 

After installing HACS, search for "OpenID Connect" in the HACS search box or click the button below:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

## Step 2. Configure Keycloak

1. Log in to your Keycloak Admin Console and select the Realm you want to use.
2. Navigate to **Clients** and click **Create client**.
   * **Client ID**: `homeassistant` (or a name of your choice).
   * **Client Authentication**: Turn **ON** if you want to use a Client Secret (Confidential Client), or leave **OFF** for a Public Client.
   * **Valid redirect URIs**: `https://<your HA URL>/auth/oidc/callback`
   * Save the client. If you enabled Client Authentication, go to the **Credentials** tab and copy your **Client Secret**.
3. Navigate to **Groups** and create the groups you want to use for Home Assistant access. 
   * Example: `homeassistant` (for standard users) and `homeassistantadmin` (for administrators).
   * Assign your users to these groups.

### Step 2.1 Configure the Group Mapper
By default, Keycloak does not send a user's groups in the OIDC token in a format that Home Assistant expects. You must create a specific mapper:

1. In Keycloak, go to **Client Scopes**. You can either edit the default `roles` scope, or create a dedicated scope (e.g., `groups`) and assign it to your `homeassistant` client as a Default Scope.
2. Click into the scope and go to the **Mappers** tab.
3. Click **Configure a new mapper** (or Add mapper -> By configuration) and select **Group Membership**.
4. Configure the mapper exactly as follows:
   * **Name**: `groups`
   * **Token Claim Name**: `groups`
   * **Full group path**: **OFF** *(Important: This ensures Home Assistant receives `homeassistant` instead of the full path `/users/homeassistant`, if you use nested groups)*.
   * **Add to ID token**: **ON**
   * **Add to access token**: **ON**
   * **Add to userinfo**: **ON**
5. Save the mapper.

## Step 3. Home Assistant Configuration

You can configure this via the UI, or by using `configuration.yaml`. Here is the recommended `configuration.yaml` setup for Keycloak:

```yaml
auth_oidc:
  client_id: "homeassistant"
  client_secret: !secret oidc_client_secret # Remove this line if Client Authentication is OFF in Keycloak
  discovery_url: "https://<your-keycloak-domain>/realms/<your-realm>/.well-known/openid-configuration"
  
  # Optional: Change the button text on the login screen
  display_name: "Keycloak SSO"

  features:
    # CAUTION: Only enable temporarily during migrations. If true, a Keycloak
    # user with a matching username can take over an existing HA user.
    automatic_user_linking: false
    # Set to true to skip the welcome screen on desktop browsers
    default_redirect: false

  claims:
    display_name: name
    username: preferred_username
    groups: groups

  roles:
    # These must exactly match the group names you created in Keycloak
    user: homeassistant
    admin: homeassistantadmin
