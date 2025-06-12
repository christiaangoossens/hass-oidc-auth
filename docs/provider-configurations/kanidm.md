# Kanidm

## Public client configuration

[Home Assistant](https://github.com/home-assistant/core) `/var/lib/hass/configuration.yaml`

```yaml
auth_oidc:
  client_id: "homeassistant"
  discovery_url: "https://idm.example.org/oauth2/openid/homeassistant/.well-known/openid-configuration"
  features:
    automatic_person_creation: true
  id_token_signing_alg: "ES256"
  roles:
    admin: "homeassistant_admins@idm.example.org"
    user: "idm_all_persons@idm.example.org"
```

[Kanidm](https://github.com/kanidm/kanidm)

1. Create your Kanidm account, if you don't have one already:

```shell
kanidm person create "your_username" "Your Username" --name "idm_admin"
```

2. Create a new Kanidm group for your HomeAssistant administrators (`homeassistant_admins`), and add your regular account to it:

```shell
kanidm group create "homeassistant_admins" --name "idm_admin"
kanidm group add-members "homeassistant_admins" "your_username" --name "idm_admin"
```

3. Create a new OAuth2 application configuration in Kanidm (`homeassistant`), configure the redirect URL, and scope access:

```shell
kanidm system oauth2 create-public "homeassistant" "Home Assistant" "https://hass.example.org/auth/oidc/welcome" --name "idm_admin"
kanidm system oauth2 add-redirect-url "homeassistant" "https://hass.example.org/auth/oidc/callback" --name "idm_admin"
kanidm system oauth2 update-scope-map "homeassistant" "homeassistant_users" "email" "groups" "openid" "profile" --name "idm_admin"
```

[Kanidm Provision](https://github.com/oddlama/kanidm-provision) `state.json`

```jsonc
{
  "groups": {
    "homeassistant_admins": {
      "members": ["your_username"]
    }
  },
  "persons": {
    "your_username": {
      "displayName": "Your Username"
    },
  },
  "systems": {
    "oauth2": {
      "homeassistant": {
        "displayName": "Home Assistant",
        "originLanding": "https://hass.example.org/auth/oidc/welcome",
        "originUrl": "https://hass.example.org/auth/oidc/callback",
        "public": true,
        "scopeMaps": {
          "homeassistant_users": ["email", "groups", "openid", "profile"]
        }
      }
    }
  }
}
```

## Confidential client configuration

[Home Assistant](https://github.com/home-assistant/core) `/var/lib/hass/configuration.yaml`

```yaml
auth_oidc:
  client_id: "homeassistant"
  client_secret: !secret oidc_client_secret
  discovery_url: "https://idm.example.org/oauth2/openid/homeassistant/.well-known/openid-configuration"
  features:
    automatic_person_creation: true
  id_token_signing_alg: "ES256"
  roles:
    admin: "homeassistant_admins@idm.example.org"
    user: "idm_all_persons@idm.example.org"
```

[Kanidm](https://github.com/kanidm/kanidm)

1. Create your Kanidm account, if you don't have one already:

```shell
kanidm person create "your_username" "Your Username" --name "idm_admin"
```

2. Create a new Kanidm group for your HomeAssistant administrators (`homeassistant_admins`), and add your regular account to it:

```shell
kanidm group create "homeassistant_admins" --name "idm_admin"
kanidm group add-members "homeassistant_admins" "your_username" --name "idm_admin"
```

3. Create a new OAuth2 application configuration in Kanidm (`homeassistant`), configure the redirect URL, and scope access:

```shell
kanidm system oauth2 create "homeassistant" "Home Assistant" "https://hass.example.org/auth/oidc/welcome" --name "idm_admin"
kanidm system oauth2 add-redirect-url "homeassistant" "https://hass.example.org/auth/oidc/callback" --name "idm_admin"
kanidm system oauth2 update-scope-map "homeassistant" "homeassistant_users" "email" "groups" "openid" "profile" --name "idm_admin"
```

4. Get the `homeassistant` OAuth2 client secret from Kanidm:

```shell
kanidm system oauth2 show-basic-secret "homeassistant" --name "idm_admin" | xargs echo 'oidc_client_secret: {}' | tee --append "/var/lib/hass/secrets.yaml"
```

[Kanidm Provision](https://github.com/oddlama/kanidm-provision) `state.json`

```jsonc
{
  "groups": {
    "homeassistant_admins": {
      "members": ["your_username"]
    }
  },
  "persons": {
    "your_username": {
      "displayName": "Your Username"
    },
  },
  "systems": {
    "oauth2": {
      "homeassistant": {
        "displayName": "Home Assistant",
        "originLanding": "https://hass.example.org/auth/oidc/welcome",
        "originUrl": "https://hass.example.org/auth/oidc/callback",
        "scopeMaps": {
          "homeassistant_users": ["email", "groups", "openid", "profile"]
        }
      }
    }
  }
}
```
