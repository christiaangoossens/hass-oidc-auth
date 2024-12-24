# OIDC Auth for Home Assistant

> [!CAUTION]
> This is a pre-alpha release. I give no guarantees about code quality, error handling or security at this stage. Please treat this repo as a proof of concept for now and only use it on development HA installs.

Provides an OIDC implementation for Home Assistant. We will likely have a sub-optimal user experience as the HA frontend does not allow updating the login form as required from a custom component.

TODOs:

- [X] Basic flow
- [ ] Improve welcome screen UI, should render a simple centered Tailwind UI instructing users that you should login externally to obtain a code.
- [ ] Improve finish screen UI, showing the code clearly with a copy button and instructions to paste it into Home Assistant.
- [ ] Implement error handling on top of this proof of concept (discovery, JWKS, OIDC)
- [ ] Make id_token claim used for the group (admin/user) configurable
- [ ] Make id_token claim used for the username configurable
- [ ] Make id_token claim used for the name configurable
- [ ] Add instructions on how to deploy this with Authentik & Authelia
- [ ] Configure Github Actions to automatically lint and build the package
- [ ] Configure Dependabot for automatic updates

Currently impossible TODOs (waiting for assistance from HA devs, not possible without forking HA frontend & apps right now):

- [ ] Update the HA frontend code to allow a redirection to be requested from an auth provider instead of manually opening welcome page
- [ ] Implement this redirection logic to open a new tab on desktop
- [ ] Implement this redirection logic to open a Android Custom Tab (Android) / SFSafariViewController (iOS), instead of opening the link in the HA webview
- [ ] Implement a final redirect back to the main page with the code as a query param instead of showing the finalize page

### Background
If you would like to read the background/open letter that lead to this component, please see https://community.home-assistant.io/t/open-letter-for-improving-home-assistants-authentication-system-oidc-sso/494223. It's currently one of the most upvoted feature requests for Home Assistant.

### Help wanted
If you have any tips or would like to contribute, send me a message. You are also welcome to contribute a PR to fix any of the TODOs.

Currently, this is a pre-alpha, so I welcome issues but I cannot guarantee I can fix them (at least within a reasonable time). Please turn on watch for this repository to remain updated. When the component is in a beta stage, issues will likely get fixed more frequently.

## How to use
### Installation

Add this repository to [HACS](https://hacs.xyz/).

Update your configuration.yaml file with

```yaml
auth_oidc:
    client_id: ""
    discovery_url: ""
```

Register your client with your OIDC Provider (e.g. Authentik/Authelia) as a public client and get the client_id. Fill it in to the configuration.yaml. Then, fill in the OpenID Discovery URL as well.

For example:
```yaml
auth_oidc:
   client_id: "someValueForTheClientId"
   discovery_url: "https://example.com/application/o/application/.well-known/openid-configuration"
```

Afterwards, restart Home Assistant.

### Login
You should now be able to see a second option on your login screen ("OpenID Connect (SSO)"). It provides you with a single input field.

Sadly, the user experience is pretty poor right now. Go to `/auth/oidc/welcome` (for example `https://hass.io/auth/oidc/welcome`, replace the URL with your Home Assistant URL) and follow the prompts provided to login, then copy the code into the input field from before. You should now login automatically with your username from SSO.

> [!TIP]
> You can use a different device to login instead. Open the `/auth/oidc/welcome` link on device A and then type the obtained code into the normal HA login on device B (can also be the mobile app) to login.

## Development
This project uses the Rye package manager for development. You can find installation instructions here: https://rye.astral.sh/guide/installation/.
Start by installing the dependencies using `rye sync` and then point your editor towards the environment created in the `.venv` directory.