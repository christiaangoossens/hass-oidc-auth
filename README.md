# OIDC Auth for Home Assistant

Aims to provide an OIDC implementation for Home Assistant. We will likely have a sub-optimal user experience as the HA frontend does not allow updating the login form as required from a custom component.

TODOs:

- [X] Basic flow
- [ ] Improve welcome screen UI, should render a simple centered Tailwind UI instructing users that you should login externally to obtain a code.
- [ ] Improve finish screen UI, showing the code clearly with a copy button and instructions to paste it into Home Assistant.
- [ ] Implement error handling on top of this proof of concept (discovery, JWKS, OIDC)
- [ ] Make id_token claim used for the group (admin/user) configurable
- [ ] Make id_token claim used for the username configurable
- [ ] Make id_token claim used for the name configurable
- [ ] Add instructions on how to deploy this with Authentik & Authelia

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
> You can use a different device to login instead. Open the /auth/oidc/welcome link on device A and then type the obtained code into the normal HA login on device B (can also be the mobile app) to login.

## Development
This project uses the Rye package manager for development. You can find installation instructions here: https://rye.astral.sh/guide/installation/.
Start by installing the dependencies using `rye sync` and then point your editor towards the environment created in the `.venv` directory.