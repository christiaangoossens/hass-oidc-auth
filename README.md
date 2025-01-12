<!-- Based on the Best-README-template from https://github.com/christiaangoossens/hass-oidc-auth -->
<a id="readme-top"></a>

<div align="center">

[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
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
    <br />
    <a href="./docs/usage.md">Usage Guide</a>
    &middot;
    <a href="./docs/configuration.md">Configuration Guide</a>
    &middot;
    <a href="https://github.com/christiaangoossens/hass-oidc-auth/discussions">Questions</a>
  </p>
</div>

---

> [!CAUTION]
> This is an alpha release. I give no guarantees about code quality, error handling or security at this stage. Use at your own risk.

Provides an OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration. Through this integration, you can create an SSO (single-sign-on) environment within your self-hosted application stack / homelab.

### Background
If you would like to read the background/open letter that lead to this component, please see https://community.home-assistant.io/t/open-letter-for-improving-home-assistants-authentication-system-oidc-sso/494223. It is currently one of the most upvoted feature requests for Home Assistant.

---

## Quick installation guide

> [!TIP]
> For the full usage guide, see [Usage Guide](./docs/usage.md)


1. Add this repository to [HACS](https://hacs.xyz/).

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

2. Add the YAML configuration that matches your OIDC provider to `configuration.yaml`. By default, the integration assumes you configure Home Assistant as a **public client** and thus only specify the `client_id` and no `client_secret`. See the [Configuration Guide](./docs/configuration.md) for more details.

The following OIDC providers also have their own setup guides:

| <img src="https://goauthentik.io/img/icon_top_brand_colour.svg" width="100"> | <img src="https://www.authelia.com/images/branding/logo-cropped.png" width="100"> | <img src="https://github.com/user-attachments/assets/4ceb2708-9f29-4694-b797-be833efce17d" width="100"> |
|:-----------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------:|
| [Authentik](./docs/provider-configurations/authentik.md)                                       | [Authelia](./docs/provider-configurations/authelia.md)                                     | [Pocket ID](./docs/provider-configurations/pocket-id.md)                                     |

For example, your configuration might look like:

```yaml
auth_oidc:
    client_id: "example"
    discovery_url: "https://example.com/.well-known/openid-configuration"
```

3. Restart Home Assistant (either on your own, or from the Repairs tab where HACS will popup a note to restart after installing the integration)

4. Login through the OIDC Welcome URL at `<your HA URL>/auth/oidc/welcome`. You will have to go there manually. For example, it might be located at http://homeassistant.local:8123/auth/oidc/welcome. More usage instructions can be found in the [Usage Guide](./docs/usage.md).


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