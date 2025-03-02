# Pocket ID

## Public client configuration

## Pocket ID configuration
1. Login to Pocket ID and go to OIDC Clients

2. Click on "Add OIDC Client"

3. Select OAuth2/OpenID Provider and click Next

4. Fill the following details:
    - Name: `Home Assistant`
    - Callback URLs: `<your-homeassistant-url>/auth/oidc/callback` (for example: https://hass.example.com/auth/oidc/callback)
    - Click on `Public Client` (PKCE will be automatically marked when doing this)
      
5. Click on "Save"

6. Click on "Show more details" and note down your "Client ID" and OIDC Discovery URL since you will need them later.

## Home Assistant configuration
1. Add following configuration in Home Assistant's configuration.yaml:
```yaml
auth_oidc:
  client_id: <The Client ID you have noted down> 
  discovery_url: <The OIDC Discovery URL you have noted down> (for example: https://id.example.com/.well-known/openid-configuration)
```

2. Restart Home Assistant and go to your Home Assistant OIDC URL (for example: https://hass.example.com/auth/oidc/welcome)
