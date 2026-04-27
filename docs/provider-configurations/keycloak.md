# Keycloak


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

*(If you are using the UI configuration in Home Assistant, you can stop here and proceed to Step 3. Group and role mapping is only supported via `configuration.yaml`.)*

3. Navigate to **Groups** and create the groups you want to use for Home Assistant access. 
   * Example: `homeassistant` (for standard users) and `homeassistantadmin` (for administrators).
   * Assign your users to these groups.

### Step 2.1 Configure the Group Mapper (YAML only)

By default, Keycloak does not send a user's groups in the OIDC token in a format that Home Assistant expects. You must create a specific mapper:

> [!NOTE]
> If you name the scope something other than `groups`, you have to set `claims.groups` to the correct name and `groups_scope` to the new name in your Home Assistant configuration.

1. In Keycloak, go to **Client Scopes**. Create a dedicated scope `groups` and assign it to your `homeassistant` client as a Default Scope.
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

You can configure this via the UI, or by using `configuration.yaml`.

### Option A: Configuration via UI (Simple)

The UI flow is the easiest way to get started. Note that the UI does not currently offer group/role customization, so the group mapper setup from Keycloak is not needed.

1. Go to **Settings** -> **Devices & Services** in Home Assistant.
2. Click **Add Integration** and search for **OpenID Connect**.
3. As OIDC Provider select **OpenID Connect (SSO)**.
4. Follow the UI flow and enter the following details:
   * **Discovery URL**: `https://<your-keycloak-domain>/realms/<your-realm>/.well-known/openid-configuration`
   * **Client ID**: The Client ID you created in Keycloak (e.g., `homeassistant`).
   * **Client Secret**: The Client Secret from Keycloak (if Client Authentication was enabled).
5. Finish the setup in the UI.

### Option B: Configuration via `configuration.yaml` (Advanced / Group Mapping)

Here is the minimal `configuration.yaml` setup for Keycloak if you want to use group-based role mapping:

```yaml
auth_oidc:
  client_id: "homeassistant"
  client_secret: !secret oidc_client_secret # Remove this line if Client Authentication is OFF in Keycloak
  discovery_url: "https://<your-keycloak-domain>/realms/<your-realm>/.well-known/openid-configuration"

  roles:
    # These must exactly match the group names you created in Keycloak
    user: homeassistant
    admin: homeassistantadmin
```
