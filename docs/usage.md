# How do I use the OIDC Integration for Home Assistant?

Here's a step by step guide to use the integration:

### Step 1: HACS
Install the integration through [HACS](https://hacs.xyz/). You can add it automatically using the button below, or use the Github URL and type `Integration` in the manual Custom Repository add dialog.

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)


### Step 2: Configuration of the integration
The integration is currently configurable through YAML only. See the [Configuration Guide](./docs/configuration.md) for more details or pick your OIDC provider below:

| <img src="https://goauthentik.io/img/icon_top_brand_colour.svg" width="100"> | <img src="https://www.authelia.com/images/branding/logo-cropped.png" width="100"> | <img src="https://github.com/user-attachments/assets/4ceb2708-9f29-4694-b797-be833efce17d" width="100"> |
|:-----------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------:|
| [Authentik](./provider-configurations/authentik.md)                                       | [Authelia](./provider-configurations/authelia.md)                                     | [Pocket ID](./provider-configurations/pocket-id.md)                                     |

By default, the integration assumes you configure Home Assistant as a **public client** and thus only specify the `client_id` and no `client_secret`. For example, your configuration might look like:

```yaml
auth_oidc:
    client_id: "example"
    discovery_url: "https://example.com/.well-known/openid-configuration"
```

When registering Home Assistant at your OIDC provider, use `<your HA URL>/auth/oidc/callback` as the callback URL and select 'public client'. You should now get the `client_id` and `issuer_url` or `discovery_url` to fill in.

### Step 3: Restart
Restart Home Assistant. You can do so by going to the Reparations/Update section in Home Assistant.

### Step 4: Go to the OIDC login screen
After restarting Home Assistant, you should now be able to get to the login screen. You can find it at `<your HA URL>/auth/oidc/welcome`. You will have to go there manually for now. For example, it might be located at http://homeassistant.local:8123/auth/oidc/welcome.

It should look like this:

![image](https://github.com/user-attachments/assets/7320b7d3-b9f9-4268-ba1f-4deb0c6805ea)

If you have configured everything correctly, you should be redirected to your OIDC Provider after clicking the button. Please login there.

You should return to a screen like this:

![image](https://github.com/user-attachments/assets/d9c305bd-4a93-4a97-ae55-dba6361d92c8)

Either click the automatic sign in button or copy the code.
This screen will give you a one-time code to login that expires in 5 minutes.

#### Step 4a: Automatic login
If you would like to login automatically, click the button. It will log you in to your user in the current browser window.

#### Step 4b: Code login
If you would like to login using the code, go to your normal Home Assistant URL without any user logged in, such as on your mobile device/wall tablet/smart watch. You will now see the following screen:

![image](https://github.com/user-attachments/assets/4ed2b408-53e4-429e-920a-7628ddbcfc02)

If you don't, you likely see:

![image](https://github.com/user-attachments/assets/80629c60-793e-4933-8b45-283234798ffb)

If so, click "OpenID Connect (SSO)" to get to the first screen. If you have configured a [display name](./configuration.md#configuring-a-display-name-for-your-oidc-provider), that will show instead.

Enter your code into the single input field:

![image](https://github.com/user-attachments/assets/f031a41c-5a85-44b8-8517-3feabaa44fd5)

Upon clicking login, you should now login.
If the code is wrong, you will see this instead:

![image](https://github.com/user-attachments/assets/317d20e4-0e10-40f7-bb68-5cf456faf87d)

#### Step 5: Logged in
You will be logged in after following this guide.

With the default configuration, [a person entry](https://www.home-assistant.io/integrations/person/) will be created for every new OIDC user logging in. New OIDC users will get their own fresh user, linked to their persistent ID (subject) at the OpenID Connect provider. You may change your name, username or email at the provider and still have the same Home Assistant user profile.

# How can I make this easier for my users?

You can link the user directly to one of these following URLs:

- `/auth/oidc/welcome` (if you would like a nice welcome screen for your users)
- `/auth/oidc/redirect` (if you would like to just redirect them without a welcome screen)

For a seamless user experience, configure a new domain on your proxy to redirect to the `/auth/oidc/welcome` path or configure that path on your homelab dashboard or in your OIDC provider (such as in the app settings in Authentik). Users will then always start on the OIDC welcome page, which will allow them to visit the dashboard if they are already logged in.

*Note: do not replace the standard path with a redirect to the OIDC screen. This breaks login with code.*