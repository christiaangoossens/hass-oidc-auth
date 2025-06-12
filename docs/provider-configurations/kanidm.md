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

```shell
kanidm group create "homeassistant_admins" --name "idm_admin"
kanidm group add-members "homeassistant_admins" "testaccount" --name "idm_admin"
kanidm system oauth2 create-public "homeassistant" "Home Assistant" "https://hass.example.org/auth/oidc/welcome" --name "idm_admin"
kanidm system oauth2 add-redirect-url "homeassistant" "https://hass.example.org/auth/oidc/callback" --name "idm_admin"
kanidm system oauth2 set-image "homeassistant" "/var/www/html/images/homeassistant.svg" --name "idm_admin"
kanidm system oauth2 update-scope-map "homeassistant" "homeassistant_users" "email" "groups" "openid" "profile" --name "idm_admin"
```

[Kanidm Provision](https://github.com/oddlama/kanidm-provision) `state.json`

```jsonc
{
  "groups": {
    "homeassistant_admins": {
      "members": ["testaccount"]
    }
  },
  "persons": {
    "testaccount": {
      "displayName": "testaccount",
      "mailAddresses": ["testaccount@example.org"]
    },
  },
  "systems": {
    "oauth2": {
      "homeassistant": {
        "displayName": "Home Assistant",
        "imageFile": "/var/www/html/images/homeassistant.svg",
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

```shell
kanidm group create "homeassistant_admins" --name "idm_admin"
kanidm group add-members "homeassistant_admins" "testaccount" --name "idm_admin"
kanidm system oauth2 create "homeassistant" "Home Assistant" "https://hass.example.org/auth/oidc/welcome" --name "idm_admin"
kanidm system oauth2 add-redirect-url "homeassistant" "https://hass.example.org/auth/oidc/callback" --name "idm_admin"
kanidm system oauth2 set-image "homeassistant" "/var/www/html/images/homeassistant.svg" --name "idm_admin"
kanidm system oauth2 update-scope-map "homeassistant" "homeassistant_users" "email" "groups" "openid" "profile" --name "idm_admin"
kanidm system oauth2 show-basic-secret "homeassistant" --name "idm_admin" | xargs echo 'oidc_client_secret: {}' | tee --append "/var/lib/hass/secrets.yaml"
```

[Kanidm Provision](https://github.com/oddlama/kanidm-provision) `state.json`

```jsonc
{
  "groups": {
    "homeassistant_admins": {
      "members": ["testaccount"]
    }
  },
  "persons": {
    "testaccount": {
      "displayName": "testaccount",
      "mailAddresses": ["testaccount@example.org"]
    },
  },
  "systems": {
    "oauth2": {
      "homeassistant": {
        "displayName": "Home Assistant",
        "imageFile": "/var/www/html/images/homeassistant.svg",
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
