# Pocket ID

> [!TIP]
> This guide describes configuring Pocket ID using the UI method. You can also configure Pocket ID by hand with YAML. Instructions for configuring any provider using YAML can be found here: [YAML Configuration Guide](../configuration.md).


## Step 1. Install the integration

Make sure that you have fully installed the latest release of the integration. The easiest way to install the integration is through [the Home Assistant Community Store (HACS)](https://hacs.xyz/). You can find usage instructions for HACS here: https://hacs.xyz/docs/use/.

After installing HACS, search for "OpenID Connect" in the HACS search box or click the button below:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

## Step 2. Configure Pocket ID

You can choose between configuring Pocket ID as a public or confidential client.

### Public client configuration

1. Login to Pocket ID and go to `OIDC Clients`

2. Click on `Add OIDC Client`

3. Fill the following details:
    - Name: `Home Assistant`
    - Callback URLs: `<your-homeassistant-url>/auth/oidc/callback` (for example: https://hass.example.com/auth/oidc/callback)
    - Click on `Public Client` (PKCE will be automatically marked when doing this)
      
4. Click on `Save`

5. Click on `Show more details` and note down your `Client ID` and `OIDC Discovery URL` since you will need them later.

### Confidential client configuration:

1. Login to Pocket ID and go to `OIDC Clients`

2. Click on `Add OIDC Client`

3. Fill the following details:
    - Name: `Home Assistant`
    - Callback URLs: `<your-homeassistant-url>/auth/oidc/callback` (for example: https://hass.example.com/auth/oidc/callback)
      
4. Click on `Save`

5. Click on `Show more details` and note down your:
    - `Client ID`
    - `Client secret`
    - `OIDC Discovery URL`

## Step 3. Home Assistant configuration

The recommended setup method for beginners is through the "Integrations" panel within the Home Assistant UI. You can also use YAML setup, for which you can find the configuration guide here: [YAML Configuration Guide](../configuration.md).

1. Open Home Assistant and go to **Settings -> Devices & Services**.
2. Click Add Integration and select **OpenID Connect/SSO Authentication**.

![UI Configuration GIF](../ui-config-steps/ui-configuration.gif)

3. Now click "Pocket ID" and continue to the next screen
4. Set the discovery URL to `https://<your Pocket ID URL>/.well-known/openid-configuration` and click **Submit**

![Picture of the relevant configuration screen: discovery-url](../ui-config-steps/discovery-url.png)

5. Your URL will be tested. You may see an error, such as the picture below. Check your URL and verify that Home Assistant can access your Pocket ID installation. Change the URL or retry.

![Picture of the relevant configuration screen: discovery-url-failure](../ui-config-steps/discovery-url-failure.png)

6. If your discovery URL is tested succesfully, you will see something like this and you can continue with the **Submit** button to continue.


![Picture of the relevant configuration screen: discovery-url-success](../ui-config-steps/discovery-url-success.png)

7. You will then be prompted to fill in the client details, the **Client ID** and the **Client Secret** (if you used the Public Client type in the Pocket ID configuration, there is no Client Secret required). Paste them in the relevant input boxes and continue setup with **Submit**.

![Picture of the relevant configuration screen: client-details](../ui-config-steps/client-details.png)

8. You will then be asked about **Groups & Role Configuration** and **User Linking**. Configure these options as you wish or leave the defaults in place. You can also change these settings later by opening the integration settings and clicking the reconfiguration icon.


![Reconfiguration Configuration GIF](../ui-config-steps/ui-reconfigure.gif)

## Done!

You should now automatically see the welcome screen upon opening your Home Assistant URL. On the welcome screen you can choose to either start login through SSO or to use an alternative login method, which will bring you back to the normal Home Assistant username/password login screen.