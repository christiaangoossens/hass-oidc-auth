# Authelia

> [!TIP]
> This guide describes configuring Authelia using the UI method. You can also configure Authelia by hand with YAML. Instructions for configuring any provider using YAML can be found here: [YAML Configuration Guide](../configuration.md).


## Step 1. Install the integration

Make sure that you have fully installed the latest release of the integration. The easiest way to install the integration is through [the Home Assistant Community Store (HACS)](https://hacs.xyz/). You can find usage instructions for HACS here: https://hacs.xyz/docs/use/.

After installing HACS, search for "OpenID Connect" in the HACS search box or click the button below:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

## Step 2. Configure Authelia

You can choose between configuring Authelia as a public or confidential client.

### Public client configuration

> [!NOTE]  
> This configuration strictly requires a HTTPS redirect uri.

Authelia `configuration.yml`
```yaml
identity_providers:
  oidc:
    ## The other portions of the mandatory OpenID Connect 1.0 configuration go here.
    ## See: https://www.authelia.com/c/oidc
    clients:
      - client_id: 'homeassistant'
        client_name: 'Home Assistant'
        public: true
        require_pkce: true
        pkce_challenge_method: 'S256'
        redirect_uris:
          - 'https://hass.example.com/auth/oidc/callback'
```

### Confidential client configuration:

Authelia `configuration.yml`
```yaml
identity_providers:
  oidc:
    ## The other portions of the mandatory OpenID Connect 1.0 configuration go here.
    ## See: https://www.authelia.com/c/oidc
    clients:
      - client_id: 'homeassistant'
        client_name: 'Home Assistant'
        client_secret: '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2CJPOsKaPK0hjf.9yHxzQGZziziccp6Yng'  # The digest of 'insecure_secret'.
        public: false
        require_pkce: true
        pkce_challenge_method: 'S256'
        redirect_uris:
          - 'https://hass.example.com/auth/oidc/callback'
        token_endpoint_auth_method: 'client_secret_post'
```

## Step 3. Home Assistant configuration

The recommended setup method for beginners is through the "Integrations" panel within the Home Assistant UI. You can also use YAML setup, for which you can find the configuration guide here: [YAML Configuration Guide](../configuration.md).

1. Open Home Assistant and go to **Settings -> Devices & Services**.
2. Click Add Integration and select **OpenID Connect/SSO Authentication**.

![UI Configuration GIF](../ui-config-steps/ui-configuration.gif)

3. Now click "Authelia" and continue to the next screen
4. Set the discovery URL to `https://<your Authelia URL>/.well-known/openid-configuration` and click **Submit**

![Picture of the relevant configuration screen: discovery-url](../ui-config-steps/discovery-url.png)

5. Your URL will be tested. You may see an error, such as the picture below. Check your URL and verify that Home Assistant can access your Authelia installation. Change the URL or retry.

![Picture of the relevant configuration screen: discovery-url-failure](../ui-config-steps/discovery-url-failure.png)

6. If your discovery URL is tested succesfully, you will see something like this and you can continue with the **Submit** button to continue.


![Picture of the relevant configuration screen: discovery-url-success](../ui-config-steps/discovery-url-success.png)

7. You will then be prompted to fill in the client details, the **Client ID** and the **Client Secret** (if you used the Public Client type in the Authelia configuration, there is no Client Secret required). Paste them in the relevant input boxes and continue setup with **Submit**.

![Picture of the relevant configuration screen: client-details](../ui-config-steps/client-details.png)

8. You will then be asked about **Groups & Role Configuration** and **User Linking**. Configure these options as you wish or leave the defaults in place. You can also change these settings later by opening the integration settings and clicking the reconfiguration icon.


![Reconfiguration Configuration GIF](../ui-config-steps/ui-reconfigure.gif)

## Done!

You should now automatically see the welcome screen upon opening your Home Assistant URL. On the welcome screen you can choose to either start login through SSO or to use an alternative login method, which will bring you back to the normal Home Assistant username/password login screen.