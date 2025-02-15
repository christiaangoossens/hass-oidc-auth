# Authentik

## Authentik configuration

1. From the admin interface, go to `Applications > Providers` and click on `Create`
2. Select `OAuth2/OpenID Provider` and click `Next`
3. Fill the following details:
    - Name: `Home Assistant Provider`
    - Authorization flow: `default-provider-authorization-explicit-consent`
    - Client type: `Confidential`
    - Client ID: `homeassistant`
    - Client Secret: **Copy this value**
    - Redirect URIs/Origins: Click on `Add entry` (You can use either DNS, Internal/External IP or localhost)
        - Strict: https://hass.example.com/auth/oidc/callback
4. Click `Finish` to save the provider configuration
5. Open the created Provider 
6. On the Assigned to application section click on `Create`:
    - Name: `Home Assistant`
    - Slug: `home-assistant`
    - Provider: `Home Assistant Provider`
    
    Then save the configuration

## Home Assistant configuration

**Important note**: For HTTPS configuration make sure to have a public valid SSL certificate (i.e. LetsEncrypt), if not, use HTTP instead (more insecure) or add your Authentik CA certificate to your Home Assistant installation OS (more complicated).

After installing this HACS addon, edit your `configuration.yaml` file and add:
```yaml
auth_oidc:
  client_id: "homeassistant"
  client_secret: "client_secret"
  discovery_url: "https://auth.example.com/application/o/home-assistant/.well-known/openid-configuration"
  features:
    automatic_user_linking: true
```

Restart Home Assistant and go to https://hass.example.com/auth/oidc/welcome