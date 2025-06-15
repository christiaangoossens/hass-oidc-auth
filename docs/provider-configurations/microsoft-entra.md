# Microsoft Entra ID
> [!WARNING]  
> Microsoft Entra ID does not support public clients that are not Single Page Applications (SPA's). Therefore, you will have to use a client secret.

1. Go to app registrations in Entra ID.
2. Create a new app, use the "Web" type for the redirect URI and fill in your URL: `<ha url>/auth/oidc/callback`. Note that you either have to use localhost, or HTTPS.
3. Copy the 'Application (client) ID' on the overview page of your app and use it as your `client_id`.
4. Create the discovery URL:
   -  If you selected 'own tenant only' use the 'Directory (tenant) ID' on the overview page of your app and create the discovery URL using: `https://login.microsoftonline.com/<tenant id>/v2.0/.well-known/openid-configuration`.
   - If you selected any Azure AD account (would not recommend this) or also personal accounts, use `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`.
5. Go to Certificates & Secrets and create a client secret. Make sure to copy the 'Value' and not the Secret ID. Use this value for `client_secret` in the HA config.
    - Make sure to renew this secret in time. It will expire in two years.
6. Go to API Permissions and click 'Add permission'. Add the `openid` and `profile` permissions from Microsoft Graph. You can remove `User.Read`.

Now configure Home Assistant with the following:

```
auth_oidc:
   client_id: < client id from the 'Application (client) ID field' >
   discovery_url: < discovery URL you made in step 4 >
   client_secret: < client seret from step 5 >
   features:
      include_groups_scope: False
```

> [!CAUTION]
> Be careful! Configuring Entra ID wrong may leave your Home Assistant install open for anyone with a Microsoft account. Please use "Single tenant" account types only. Do not enable "Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)" or personal account modes without enabling the mode to only allow specific accounts first!
