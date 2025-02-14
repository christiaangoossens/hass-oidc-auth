# OIDC Auth for Home Assistant

> [!CAUTION]
> This is an alpha release. I give no guarantees about code quality, error handling or security at this stage. Use at your own risk.

Provides an OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration. Through this integration, you can create an SSO (single-sign-on) environment within your self-hosted application stack / homelab.

### Background
If you would like to read the background/open letter that lead to this component, please see https://community.home-assistant.io/t/open-letter-for-improving-home-assistants-authentication-system-oidc-sso/494223. It is currently one of the most upvoted feature requests for Home Assistant.

## How to use
### Installation

Add this repository to [HACS](https://hacs.xyz/).

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

Update your `configuration.yaml` file with

```yaml
auth_oidc:
    client_id: ""
    discovery_url: ""
```

Register your client with your OIDC Provider (e.g. Authentik/Authelia) as a public client and get the client_id. Then, use the obtained client_id and discovery URLs to fill the fields in `configuration.yaml`.

For example:
```yaml
auth_oidc:
    client_id: "someValueForTheClientId"
    discovery_url: "https://example.com/application/o/application/.well-known/openid-configuration"
```

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

### Configuration Options

| Option                      | Type     | Required | Default             | Description                                                                                             |
|-----------------------------|----------|----------|----------------------|---------------------------------------------------------------------------------------------------------|
| `client_id`                 | `string` | Yes      |                      | The Client ID as registered with your OpenID Connect provider.                                        |
| `client_secret`            | `string` | No       |                      | The Client Secret for enabling confidential client mode.                                             |
| `discovery_url`            | `string` | Yes      |                      | The OIDC well-known configuration URL.                                                                |
| `display_name`              | `string` | No       | `"OpenID Connect (SSO)"` | The name to display on the login screen, both for the Home Assistant screen and the OIDC welcome screen.                                                                |
| `id_token_signing_alg`       | `string` | No       | `RS256`              | The signing algorithm that is used for your id_tokens.
| `features.automatic_user_linking`   | `boolean`| No       | `false`          | Automatically links users to existing Home Assistant users based on the OIDC username claim. Disabled by default for security. When disabled, OIDC users will get their own new user profile upon first login.     |
| `features.automatic_person_creation` | `boolean` | No       | `true`          | Automatically creates a person entry for new user profiles created by this integration. Recommended if you would like to assign presence detection to OIDC users.                                            |
| `features.include_groups_scope`  | `boolean` | No       | `true`           | Include the 'groups' scope in the OIDC request. Set to `false` to exclude it. |
| `features.disable_rfc7636`  | `boolean`| No       | `false`         | Disables PKCE (RFC 7636) for OIDC providers that don't support it. You should not need this with most providers.                                    |
| `features.include_groups_scope`  | `boolean` | No       | `true`           | Include the 'groups' scope in the OIDC request. Set to `false` to exclude it. |
| `claims.display_name`      | `string` | No       | `name`                     | The claim to use to obtain the display name.
| `claims.username`         | `string` | No       | `preferred_username`                     | The claim to use to obtain the username.
| `claims.groups`            | `string` | No       | `groups`                     | The claim to use to obtain the user's group(s). |
| `roles.admin`            | `string` | No       | `admins`                     | Group name to require for users to get the 'admin' role in Home Assistant. Defaults to 'admins', the default group name for admins in Authentik. Doesn't do anything if no groups claim is found in your token. |
| `roles.user`            | `string` | No       |                     | Group name to require for users to get the 'user' role in Home Assistant. Defaults to giving all users this role, unless configured. |
| `network.tls_verify`         | `boolean` | No       | `true`                     | Verify TLS certificate. You may want to set this set to `false` when testing locally. |
| `network.tls_ca_path`            | `string` | No       |                       | Path to file containing a private certificate authority chain. |

#### Example: Migrating from HA username/password users to OIDC users
If you already have users created within Home Assistant and would like to re-use the current user profile for your OIDC login, you can (temporarily) enable `features.automatic_user_linking`, with the following config (example):

```yaml
auth_oidc:
    client_id: "someValueForTheClientId"
    discovery_url: "https://example.com/application/o/application/.well-known/openid-configuration"
    features:
        automatic_user_linking: true
```

Upon login, OIDC users will then automatically be linked to the HA user with the same username.

> [!IMPORTANT]
> It's recommended to only enable this temporarily as it may pose a security risk. Any OIDC user with a username corresponding to a user in Home Assistant can get access to that user, and it's existing rights (admin), even if MFA is currently enabled for that account. After you have migrated your users (and linked OIDC to all existing accounts) you can disable the feature and keep using the linked users.

#### Example: Using a private certificate authority
If you use a private certificate authority to secure your OIDC provider (e.g. Keycloak), your CA must be able to be used by this component. Otherwise you will receive a certificate error (`[SSL: CERTIFICATE_VERIFY_FAILED]`) when connecting to the OIDC provider.
You can either make the CA known to the entire operating system or configure only this component to use the CA. If you only want to let this component know your CA, you can specify it via `network.tls_ca_path`:

```yaml
auth_oidc:
    network:
        tls_ca_path: /path/to/private-ca.pem
```

If you want to deactivate the validation of the certificates for test purposes, you can do this via `network.tls_verify: false`:

```yaml
auth_oidc:
    network:
        tls_verify: false
```

In productive use, however, you should set `network.tls_verify` to `true`.

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
- [ ] Create a configurable bool for scope "groups" to activate/deactivate
- [ ] Make scope "groups" a configurable custom scope

Currently waiting on HA feature additions:

- [ ] Update the HA frontend code to allow a redirection to be requested from an auth provider instead of manually opening welcome page (possibly after https://github.com/home-assistant/frontend/pull/23204)
- [ ] Implement this redirection logic to open a new tab on desktop (#23204 uses popup)
- [ ] Implement this redirection logic to open a Android Custom Tab (Android) / SFSafariViewController (iOS), instead of opening the link in the HA webview
