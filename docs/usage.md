# How do I use the OIDC Integration for Home Assistant?

Here's a step by step guide to use the integration:

1. Install the integration through HACS.




















# OLD













Afterwards, restart Home Assistant. 

You can find all possible configuration options below.

### Login
You should now be able to see a second option on your login screen ("OpenID Connect (SSO)"). It provides you with a single input field.

To start, go to one of to one of these URLs (you may also set these as application URLs in your OIDC Provider):
- `/auth/oidc/welcome` (if you would like a nice welcome screen for your users)
- `/auth/oidc/redirect` (if you would like to just redirect them without a welcome screen)

So, for example, you may start at http://homeassistant.local:8123/auth/oidc/welcome.

> [!TIP]
> You can use a different device to login instead. Open the `/auth/oidc/welcome` link on device A and then type the obtained code into the normal HA login on device B (can also be the mobile app) to login.

> [!TIP]
> For a seamless user experience, configure a new domain on your proxy to redirect to the `/auth/oidc/welcome` path or configure that path on your homelab dashboard or in Authentik. Users will then always start on the OIDC welcome page, which will allow them to visit the dashboard if they are already logged in.


With the default configuration, [a person entry](https://www.home-assistant.io/integrations/person/) will be created for every new OIDC user logging in. New OIDC users will get their own fresh user, linked to their persistent ID (subject) at the OpenID Connect provider. You may change your name, username or email at the provider and still have the same Home Assistant user profile.