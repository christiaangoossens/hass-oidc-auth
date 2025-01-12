# Configuration
For now, this integration is configured using YAML in your `configuration.yaml` file. By default, only two fields are required:

```yaml
auth_oidc:
    client_id: ""
    discovery_url: ""
```

All other fields have sensible, secure defaults set, or are only required in specific configurations.

## Configuration Options

Here's a table of all options that you can set:

| Option                      | Type     | Required | Default             | Description                                                                                             |
|-----------------------------|----------|----------|----------------------|---------------------------------------------------------------------------------------------------------|
| `client_id`                 | `string` | Yes      |                      | The Client ID as registered with your OpenID Connect provider.                                        |
| `client_secret`            | `string` | No       |                      | The Client Secret for enabling confidential client mode.                                             |
| `discovery_url`            | `string` | Yes      |                      | The OIDC well-known configuration URL.                                                                |
| `display_name`              | `string` | No       | `"OpenID Connect (SSO)"` | The name to display on the login screen, both for the Home Assistant screen and the OIDC welcome screen.                                                                |
| `id_token_signing_alg`       | `string` | No       | `RS256`              | The signing algorithm that is used for your id_tokens.
| `features.automatic_user_linking`   | `boolean`| No       | `false`          | Automatically links users to existing Home Assistant users based on the OIDC username claim. Disabled by default for security. When disabled, OIDC users will get their own new user profile upon first login.     |
| `features.automatic_person_creation` | `boolean` | No       | `true`          | Automatically creates a person entry for new user profiles created by this integration. Recommended if you would like to assign presence detection to OIDC users.                                            |
| `features.disable_rfc7636`  | `boolean`| No       | `false`         | Disables PKCE (RFC 7636) for OIDC providers that don't support it. You should not need this with most providers.                                    |
| `claims.display_name`      | `string` | No       | `name`                     | The claim to use to obtain the display name.
| `claims.username`         | `string` | No       | `preferred_username`                     | The claim to use to obtain the username.
| `claims.groups`            | `string` | No       | `groups`                     | The claim to use to obtain the user's group(s). |
| `roles.admin`            | `string` | No       | `admins`                     | Group name to require for users to get the 'admin' role in Home Assistant. Defaults to 'admins', the default group name for admins in Authentik. Doesn't do anything if no groups claim is found in your token. |
| `roles.user`            | `string` | No       |                     | Group name to require for users to get the 'user' role in Home Assistant. Defaults to giving all users this role, unless configured. |
| `network.tls_verify`         | `boolean` | No       | `true`                     | Verify TLS certificate. You may want to set this set to `false` when testing locally. |
| `network.tls_ca_path`            | `string` | No       |                       | Path to file containing a private certificate authority chain. |

## Common Configurations

### Migrating from HA username/password users to OIDC users
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
> It's recommended to only enable this temporarily as it may pose a security risk. Any OIDC user with a username corresponding to a user in Home Assistant can get access to that user and all its rights/configuration. After you have migrated your users (and linked OIDC to all existing accounts) you should disable the feature. You will still be able to use linked accounts, but no more links will be created or updated.

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