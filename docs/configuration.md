# UI Configuration

If you want to use the (limited) UI configuration method, please see [the README](../README.md).

# YAML Configuration

You can configure this integration using YAML in your `configuration.yaml` file. All features of the integration will always be available within the YAML configuration.

By default, only two fields are required:

```yaml
auth_oidc:
  client_id: ""
  discovery_url: ""
```

The default settings assume that you configure Home Assistant as a **public client**, without a client secret. If so, you should only need to provide the `client_id` from your OIDC provider and its discovery URL (ending in `.well-known/openid-configuration`).
You don't have to configure other settings in most cases, as they have secure defaults set. If your provider requires manually configuring the callback URL, use `<your HA URL>/auth/oidc/callback`.

## Provider Configurations
Here are some documentation links for specific providers that you may want to follow:

* [Authentik](./provider-configurations/authentik.md)
* [Authelia](./provider-configurations/authelia.md)
* [Pocket ID](./provider-configurations/pocket-id.md)
* [Kanidm](./provider-configurations/kanidm.md)
* [Microsoft Entra ID](./provider-configurations/microsoft-entra.md)
* [Zitadel](./provider-configurations/zitadel.md)
* [Keycloak](./provider-configurations/keycloak.md)

_Missing a provider? Submit your guide using a PR._

## Common Configurations
### Configuring Client Secret
If you want to configure Home Assistant as a **confidential client**, you should provide the client secret as well. An example configuration might look like this:

```yaml
auth_oidc:
  client_id: ""
  client_secret: !secret oidc_client_secret
  discovery_url: ""
```

You should use the Home Assistant secrets helper (`!secret`) to make sure you store secrets securely. See https://www.home-assistant.io/docs/configuration/secrets/ for more information.

> [!IMPORTANT]  
> Most users will not experience any benefits from using a confidential client, as using properly configured redirect URLs + PKCE already provides enough security in a home setting and using a client secret introduces the risk of it getting lost/stolen/put on the internet. Do not use a confidential setup if you don't know what you are doing.

### Configuring roles & scopes or OIDC settings

If your provider isn't listed above, you might want to configure OIDC settings yourself. Here's an example configuration for that use case:

```yaml
auth_oidc:
  client_id: ""
  discovery_url: ""
  id_token_signing_alg: <HS256, RS256, ES256, ...>
  groups_scope: <groups scope>
  claims:
    display_name: <display name claim from your provider>
    username: <username claim from your provider>
    groups: <groups claim from your provider>
  roles:
    admin: <group name to use for admins>
    user: <group name to use for users>
```

If you configure the user role, OIDC users that have neither configured group name will be rejected! If you configure the admin role, users with that role will receive administrator rights in Home Assistant automatically upon login.

### Configuring a display name for your OIDC provider
If you would like to change the default name on the OIDC welcome screen and Home Assistant login screens from `OpenID Connect (SSO)` to your own display name, you can set the `display_name` configuration property.

```yaml
auth_oidc:
  client_id: ""
  discovery_url: ""
  display_name: "Example"
```

This will show the provider on the login screen as: "Login with Example".

### Skipping the welcome screen
If you would like to skip the welcome screen, you can either enable the `features.default_redirect` feature, or [disable the Home Assistant auth provider](https://github.com/christiaangoossens/hass-oidc-auth/discussions/67).

If you want to keep the default login (backup login) enabled, but still skip the welcome screen by default, you can configure the following yaml:

```yaml
auth_oidc:
  features:
    default_redirect: true
```

If you have this feature enabled and you would like to use the backup login, make sure to append `?skip_oidc_redirect=true` to your login URL. For example, if your HA is at `https://ha.example.com`, you can go to `https://ha.example.com/?skip_oidc_redirect=true` to see the HA username/password login screen.

### Forcing HTTPS
First check if you are setting the header `X-Forwarded-Proto` in your proxy and if the [proxy settings for Home Assistant](https://www.home-assistant.io/integrations/http/#use_x_forwarded_for) are configured correctly. You should also check if IP addresses in your logs actually match the origin IP (instead of proxy IP). If you cannot find any mistakes, you may use the following config option to force HTTPS regardless:

```yaml
auth_oidc:
  features:
     force_https: true
```

### Disabling registration for new users
This integration does not allow disabling registration for new users, as there is no way to abort registration that late in the process while providing a good user experience.
You can however set both roles to groups that only contain certain users or to a non-existent group.

```yaml
auth_oidc:
  roles:
     user: "non_existent"
     admin: "admins"
```

Note that if you put both on non-existent groups, no users will be able to login.

### Migrating from HA username/password users to OIDC users
If you already have users created within Home Assistant and would like to re-use the current user profile for your OIDC login, you can (temporarily) enable `features.automatic_user_linking`, with the following config (example):

```yaml
auth_oidc:
  client_id: "someValueForTheClientId"
  discovery_url: "https://example.com/application/o/application/.well-known/openid-configuration"
  features:
    automatic_user_linking: true
```

Upon login, OIDC users will then automatically be linked to the HA user with the same username. It's recommended to **only enable this temporarily** as it may pose a security risk. You should disable it after linking all your users, as existing links will still work if you disable it, but no new links will be created.

> [!CAUTION]
> Any OIDC user with a username corresponding to a user in Home Assistant can get access to that user and all its rights/configuration.

> [!CAUTION]
> MFA is ignored when using this setting, thus bypassing any MFA configuration the user has originally configured, as long as the username is an exact match. This is dangerous if you are not aware of it!



### Using a private certificate authority
If you use a private certificate authority to secure your OIDC provider, you must configure the root certificates of your private certificate authority. Otherwise you will get an error (`[SSL: CERTIFICATE_VERIFY_FAILED]`) when connecting to the OIDC provider.

You can either make the CA known to the entire operating system or configure only this component to use the CA. If you want to only use your private CA with this integration, you can specify it via `network.tls_ca_path`:

```yaml
auth_oidc:
  network:
    tls_ca_path: /path/to/private-ca.pem
```

If you want to deactivate the validation of all TLS certificates for test purposes, you can do this via `network.tls_verify: false`:

```yaml
auth_oidc:
  network:
    tls_verify: false
```

> [!CAUTION]
> Do not disable `tls_verify` in a production setting or when your Home Assistant installation is exposed outside of your network. If disabled, man-in-the-middle attacks can be used to change the provider configuration to allow fake tokens to be used.

## All configuration Options

Here's a table of all options that you can set:

| Option                      | Type     | Required | Default             | Description                                                                                             |
|-----------------------------|----------|----------|----------------------|---------------------------------------------------------------------------------------------------------|
| `client_id`                 | `string` | Yes      |                      | The Client ID as registered with your OpenID Connect provider.                                        |
| `client_secret`            | `string` | No       |                      | The Client Secret for enabling confidential client mode.                                             |
| `discovery_url`            | `string` | Yes      |                      | The OIDC well-known configuration URL.                                                                |
| `display_name`              | `string` | No       | `"OpenID Connect (SSO)"` | The name to display on the login screen, both for the Home Assistant screen and the OIDC welcome screen.                                                                |
| `id_token_signing_alg`       | `string` | No       | `RS256`              | The signing algorithm that is used for your id_tokens.
| `groups_scope`  | `string` | No       | `groups`           | Override the default groups scope with another scope of your choice. |
| `additional_scopes`|`list of strings`| No        | `empty list`    | Add additional scopes to request for custom identity provider configurations in addition to the automatic `openid` and `profile` scopes and the `groups_scope` configuration option |
| `features.automatic_user_linking`   | `boolean`| No       | `false`          | Automatically links users to existing Home Assistant users based on the OIDC username claim. Disabled by default for security. When disabled, OIDC users will get their own new user profile upon first login.     |
| `features.automatic_person_creation` | `boolean` | No       | `true`          | Automatically creates a person entry for new user profiles created by this integration. Recommended if you would like to assign presence detection to OIDC users.                                            |
| `features.disable_rfc7636`  | `boolean`| No       | `false`         | Disables PKCE (RFC 7636) for OIDC providers that don't support it. You should not need this with most providers.                                    |
| `features.include_groups_scope`  | `boolean` | No       | `true`           | Include the 'groups' scope in the OIDC request. Set to `false` to exclude it. |
| `features.force_https`  | `boolean` | No       | `false`           | Set to `true` to force all URLs generated to use `https` instead of automatically determining based on the request scheme or `X-Forwarded-Proto`. |
| `features.default_redirect`  | `boolean` | No       | `false`           | Set to `true` to always skip the welcome screen (on desktop), regardless of if there are any other auth providers registered. |
| `claims.display_name`      | `string` | No       | `name`                     | The claim to use to obtain the display name.
| `claims.username`         | `string` | No       | `preferred_username`                     | The claim to use to obtain the username.
| `claims.groups`            | `string` | No       | `groups`                     | The claim to use to obtain the user's group(s). |
| `roles.admin`            | `string` | No       | `admins`                     | Group name to require for users to get the 'admin' role in Home Assistant. Defaults to 'admins', the default group name for admins in Authentik. Doesn't do anything if no groups claim is found in your token. |
| `roles.user`            | `string` | No       |                     | Group name to require for users to get the 'user' role in Home Assistant. Defaults to giving all users this role, unless configured. |
| `network.tls_verify`         | `boolean` | No       | `true`                     | Verify TLS certificate. You may want to set this to `false` when testing locally. |
| `network.tls_ca_path`            | `string` | No       |                       | Path to file containing a private certificate authority chain. |
