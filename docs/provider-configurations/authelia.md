# Authelia

## Public client configuration

> [!NOTE]  
> This configuration strictly requires a HTTPS redirect uri.

Authelia `configuration.yml`
```yaml
identity_providers:
  oidc:
    ## The other portions of the mandatory OpenID Connect 1.0 configuration go here.
    ## See: https://www.authelia.com/c/oidc
    clients:
      - client_id: 'homeassistant'
        client_name: 'Home Assistant'
        public: true
        require_pkce: true
        pkce_challenge_method: 'S256'
        authorization_policy: 'two_factor'
        redirect_uris:
          - 'https://hass.example.com/auth/oidc/callback'
        scopes:
          - 'openid'
          - 'profile'
          - 'groups'
        id_token_signed_response_alg: 'RS256'
```

Home Assistant `configuration.yaml`
```yaml
auth_oidc:
    client_id: "homeassistant"
    discovery_url: "https://auth.example.com/.well-known/openid-configuration"
```

## Confidential client configuration:

Authelia `configuration.yml`
```yaml
identity_providers:
  oidc:
    ## The other portions of the mandatory OpenID Connect 1.0 configuration go here.
    ## See: https://www.authelia.com/c/oidc
    clients:
      - client_id: 'homeassistant'
        client_name: 'Home Assistant'
        client_secret: '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2CJPOsKaPK0hjf.9yHxzQGZziziccp6Yng'  # The digest of 'insecure_secret'.
        public: false
        require_pkce: true
        pkce_challenge_method: 'S256'
        authorization_policy: 'two_factor'
        redirect_uris:
          - 'https://hass.example.com/auth/oidc/callback'
        scopes:
          - 'openid'
          - 'profile'
          - 'groups'
        id_token_signed_response_alg: 'RS256'
        token_endpoint_auth_method: 'client_secret_post'
```

Home Assistant `configuration.yaml`
```yaml
auth_oidc:
  client_id: "homeassistant"
  client_secret: "insecure_secret"
  discovery_url: "https://auth.example.com/.well-known/openid-configuration"
```
