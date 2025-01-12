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




## Development
This project uses the Rye package manager for development. You can find installation instructions here: https://rye.astral.sh/guide/installation/.
Start by installing the dependencies using `rye sync` and then point your editor towards the environment created in the `.venv` directory.

### Help wanted
If you have any tips or would like to contribute, send me a message. You are also welcome to contribute a PR to fix any of the TODOs.

Currently, this is a pre-alpha, so I welcome issues but I cannot guarantee I can fix them (at least within a reasonable time). Please turn on watch for this repository to remain updated. When the component is in a beta stage, issues will likely get fixed more frequently.

### TODOs

- [X] Basic flow
- [X] Implement a final link back to the main page from the finish page
- [X] Improve welcome screen UI, should render a simple centered Tailwind UI instructing users that you should login externally to obtain a code.
- [X] Improve finish screen UI, showing the code clearly with instructions to paste it into Home Assistant.
- [X] Implement error handling on top of this proof of concept (discovery, JWKS, OIDC)
- [X] Make id_token claim used for the group (admin/user) configurable
- [X] Make id_token claim used for the username configurable
- [X] Make id_token claim used for the name configurable
- [ ] Add instructions on how to deploy this with Authentik & Authelia
- [X] Configure Github Actions to automatically lint and build the package
- [ ] Configure Dependabot for automatic updates
- [ ] Configure tests
- [ ] Consider use of setup UI instead of YAML (see https://github.com/christiaangoossens/hass-oidc-auth/discussions/6)

Currently waiting on HA feature additions:

- [ ] Update the HA frontend code to allow a redirection to be requested from an auth provider instead of manually opening welcome page (possibly after https://github.com/home-assistant/frontend/pull/23204)
- [ ] Implement this redirection logic to open a new tab on desktop (#23204 uses popup)
- [ ] Implement this redirection logic to open a Android Custom Tab (Android) / SFSafariViewController (iOS), instead of opening the link in the HA webview
