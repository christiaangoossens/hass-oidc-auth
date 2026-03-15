# Zitadel

## Zitadel configuration

1. From the Zitadel home screen, go to `Projects` and click `Create New Project`
2. Enter "Home Assistant" or your preferred name
3. Click on `New` to create a new Application
4. Enter "Home Assistant" or your preferred name
5. Select `Web` and `Continue`
6. Select `CODE` (not `PKCE`) and `Continue`
7. Enter https://hass.example.com/auth/oidc/callback as the Redirect URI, and click `Continue`
8. Click `Create`. A pop-up will dispay the `ClientId` and `ClientSecret`

## Home Assistant configuration

> [!IMPORTANT]  
> For HTTPS configuration make sure to have a public valid SSL certificate (i.e. LetsEncrypt), if not, use HTTP instead (more insecure) or add your Zitadel CA certificate to `network.tls_ca_path`.

After installing this HACS addon, edit your `configuration.yaml` file and add:
```yaml
auth_oidc:
  client_id: <ClientID from above>
  client_secret: <ClientSecret from above>
  discovery_url: "https://auth.example.com/.well-known/openid-configuration"
```

Restart Home Assistant and go to https://hass.example.com/auth/oidc/welcome
