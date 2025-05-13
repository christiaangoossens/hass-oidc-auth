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
    user: "homeassistant_users@idm.example.org"
```

[Kanidm](https://github.com/kanidm/kanidm)

```shell
kanidm group create "homeassistant_admins" --name "idm_admin"
kanidm group create "homeassistant_users" --name "idm_admin"
kanidm group add-members "homeassistant_admins" "testaccount" --name "idm_admin"
kanidm group add-members "homeassistant_users" "testaccount" --name "idm_admin"
kanidm system oauth2 create-public "homeassistant" "Home Assistant" "https://hass.example.org/auth/oidc/welcome" --name "idm_admin"
kanidm system oauth2 add-redirect-url "homeassistant" "https://hass.example.org/auth/oidc/callback" --name "idm_admin"
kanidm system oauth2 set-image "homeassistant" "/var/www/html/images/homeassistant.svg" --name "idm_admin"
kanidm system oauth2 update-scope-map "homeassistant" "homeassistant_users" "email" "openid" "profile" "groups" --name "idm_admin"
```

[Kanidm Provision](https://github.com/oddlama/kanidm-provision) `state.json`

```jsonc
{
  "groups": {
    "homeassistant_admins": {
      "members": ["test"]
    },
    "homeassistant_users": {
      "members": ["test"]
    },
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

````diff
diff --git a/docs/provider-configurations/kanidm.md b/docs/provider-configurations/kanidm.md
index 40ff969..7e49fac 100644
--- a/docs/provider-configurations/kanidm.md
+++ b/docs/provider-configurations/kanidm.md
@@ -5,6 +5,7 @@
 ```yaml
 auth_oidc:
   client_id: "homeassistant"
+  client_secret: !secret oidc_client_secret
   discovery_url: "https://idm.example.org/oauth2/openid/homeassistant/.well-known/openid-configuration"
   features:
     automatic_person_creation: true
@@ -21,9 +22,10 @@ kanidm group create "homeassistant_admins" --name "idm_admin"
 kanidm group create "homeassistant_users" --name "idm_admin"
 kanidm group add-members "homeassistant_admins" "testaccount" --name "idm_admin"
 kanidm group add-members "homeassistant_users" "testaccount" --name "idm_admin"
-kanidm system oauth2 create-public "homeassistant" "Home Assistant" "https://hass.example.org/auth/oidc/welcome" --name "idm_admin"
+kanidm system oauth2 create "homeassistant" "Home Assistant" "https://hass.example.org/auth/oidc/welcome" --name "idm_admin"
 kanidm system oauth2 add-redirect-url "homeassistant" "https://hass.example.org/auth/oidc/callback" --name "idm_admin"
 kanidm system oauth2 set-image "homeassistant" "/var/www/html/images/homeassistant.svg" --name "idm_admin"
+kanidm system oauth2 show-basic-secret "homeassistant" --name "idm_admin" | xargs echo 'oidc_client_secret: {}' | tee --append "/var/lib/hass/secrets.yaml"
 kanidm system oauth2 update-scope-map "homeassistant" "homeassistant_users" "email" "openid" "profile" "groups" --name "idm_admin"
 ```

@@ -52,7 +54,7 @@ kanidm system oauth2 update-scope-map "homeassistant" "homeassistant_users" "ema
         "imageFile": "/var/www/html/images/homeassistant.svg",
         "originLanding": "https://hass.example.org/auth/oidc/welcome",
         "originUrl": "https://hass.example.org/auth/oidc/callback",
-        "public": true,
+        "public": false,
         "scopeMaps": {
           "homeassistant_users": ["email", "groups", "openid", "profile"]
         }
````
