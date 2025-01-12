<!-- Based on the Best-README-template from https://github.com/christiaangoossens/hass-oidc-auth -->
<a id="readme-top"></a>

<div align="center">

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

</div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/christiaangoossens/hass-oidc-auth/">
    <img src="logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">OpenID Connect for Home Assistant</h3>

  <p align="center">
    OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration
    <br />
    <a href="https://github.com/christiaangoossens/hass-oidc-auth"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/christiaangoossens/hass-oidc-auth">View Demo</a>
    &middot;
    <a href="https://github.com/christiaangoossens/hass-oidc-auth/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    &middot;
    <a href="https://github.com/christiaangoossens/hass-oidc-auth/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>




# 

> [!CAUTION]
> This is an alpha release. I give no guarantees about code quality, error handling or security at this stage. Use at your own risk.

Provides an OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration. Through this integration, you can create an SSO (single-sign-on) environment within your self-hosted application stack / homelab.

### Background
If you would like to read the background/open letter that lead to this component, please see https://community.home-assistant.io/t/open-letter-for-improving-home-assistants-authentication-system-oidc-sso/494223. It is currently one of the most upvoted feature requests for Home Assistant.

## How to use
### Quick installation guide

Add this repository to [HACS](https://hacs.xyz/).

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

Update your `configuration.yaml` file with

```yaml
auth_oidc:
    client_id: ""
    discovery_url: ""
```

Register your client with your OIDC Provider (e.g. Authentik/Authelia) as a public client and get the client_id. Then, use the obtained client_id and discovery URLs to fill the fields in `configuration.yaml`.

For example:
```yaml
auth_oidc:
    client_id: "someValueForTheClientId"
    discovery_url: "https://example.com/application/o/application/.well-known/openid-configuration"
```

Afterwards, restart Home Assistant. 

You can find all possible configuration options below.

### Login
You should now be able to see a second option on your login screen ("OpenID Connect (SSO)"). It provides you with a single input field.

To start, go to one of to one of these URLs (you may also set these as application URLs in your OIDC Provider):
- `/auth/oidc/welcome` (if you would like a nice welcome screen for your users)
- `/auth/oidc/redirect` (if you would like to just redirect them without a welcome screen)

So, for example, you may start at http://homeassistant.local:8123/auth/oidc/welcome.

> [!TIP]
> You can use a different device to login instead. Open the `/auth/oidc/welcome` link on device A and then type the obtained code into the normal HA login on device B (can also be the mobile app) to login.

> [!TIP]
> For a seamless user experience, configure a new domain on your proxy to redirect to the `/auth/oidc/welcome` path or configure that path on your homelab dashboard or in Authentik. Users will then always start on the OIDC welcome page, which will allow them to visit the dashboard if they are already logged in.


With the default configuration, [a person entry](https://www.home-assistant.io/integrations/person/) will be created for every new OIDC user logging in. New OIDC users will get their own fresh user, linked to their persistent ID (subject) at the OpenID Connect provider. You may change your name, username or email at the provider and still have the same Home Assistant user profile.




## Development
This project uses the Rye package manager for development. You can find installation instructions here: https://rye.astral.sh/guide/installation/.
Start by installing the dependencies using `rye sync` and then point your editor towards the environment created in the `.venv` directory.

### Help wanted
If you have any tips or would like to contribute, send me a message. You are also welcome to contribute a PR to fix any of the TODOs.

Currently, this is a pre-alpha, so I welcome issues but I cannot guarantee I can fix them (at least within a reasonable time). Please turn on watch for this repository to remain updated. When the component is in a beta stage, issues will likely get fixed more frequently.

### TODOs

- [X] Basic flow
- [X] Implement a final link back to the main page from the finish page
- [X] Improve welcome screen UI, should render a simple centered Tailwind UI instructing users that you should login externally to obtain a code.
- [X] Improve finish screen UI, showing the code clearly with instructions to paste it into Home Assistant.
- [X] Implement error handling on top of this proof of concept (discovery, JWKS, OIDC)
- [X] Make id_token claim used for the group (admin/user) configurable
- [X] Make id_token claim used for the username configurable
- [X] Make id_token claim used for the name configurable
- [ ] Add instructions on how to deploy this with Authentik & Authelia
- [X] Configure Github Actions to automatically lint and build the package
- [ ] Configure Dependabot for automatic updates
- [ ] Configure tests
- [ ] Consider use of setup UI instead of YAML (see https://github.com/christiaangoossens/hass-oidc-auth/discussions/6)

Currently waiting on HA feature additions:

- [ ] Update the HA frontend code to allow a redirection to be requested from an auth provider instead of manually opening welcome page (possibly after https://github.com/home-assistant/frontend/pull/23204)
- [ ] Implement this redirection logic to open a new tab on desktop (#23204 uses popup)
- [ ] Implement this redirection logic to open a Android Custom Tab (Android) / SFSafariViewController (iOS), instead of opening the link in the HA webview


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/christiaangoossens/hass-oidc-auth.svg?style=for-the-badge
[contributors-url]: https://github.com/christiaangoossens/hass-oidc-auth/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/christiaangoossens/hass-oidc-auth.svg?style=for-the-badge
[forks-url]: https://github.com/christiaangoossens/hass-oidc-auth/network/members
[stars-shield]: https://img.shields.io/github/stars/christiaangoossens/hass-oidc-auth.svg?style=for-the-badge
[stars-url]: https://github.com/christiaangoossens/hass-oidc-auth/stargazers
[issues-shield]: https://img.shields.io/github/issues/christiaangoossens/hass-oidc-auth.svg?style=for-the-badge
[issues-url]: https://github.com/christiaangoossens/hass-oidc-auth/issues
[license-shield]: https://img.shields.io/github/license/christiaangoossens/hass-oidc-auth.svg?style=for-the-badge
[license-url]: https://github.com/christiaangoossens/hass-oidc-auth/blob/master/LICENSE.txt