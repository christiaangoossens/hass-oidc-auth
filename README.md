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
    <a href="./CONTRIBUTING.md">Contribution Guide</a>
    <br />
    <br />
    <a href="https://github.com/christiaangoossens/hass-oidc-auth/discussions?discussions_q=is%3Aopen+category%3AAnnouncements+category%3APolls">Announcements & Polls</a>
    &middot;
    <a href="https://github.com/christiaangoossens/hass-oidc-auth/issues">Issues</a>
    &middot;
    <a href="https://github.com/christiaangoossens/hass-oidc-auth/discussions/categories/q-a">Questions</a>
    &middot;
    <a href="https://github.com/christiaangoossens/hass-oidc-auth/discussions/categories/ideas">Feature Requests</a>
  </p>
</div>

> [!CAUTION]
> This is an alpha release. I give no guarantees about code quality, error handling or security at this stage. Use at your own risk.

Provides an OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration. Through this integration, you can create an SSO (single-sign-on) environment within your self-hosted application stack / homelab.

### Background
If you would like to read the background/open letter that lead to this component, you can find the original post at https://community.home-assistant.io/t/open-letter-for-improving-home-assistants-authentication-system-oidc-sso/494223. It is currently one of the most upvoted feature requests for Home Assistant.

> [!TIP]
> If you support the addition of this feature to the Home Assistant core, please upvote https://github.com/orgs/home-assistant/discussions/48. It's the successor of the Home Assistant Community post mentioned above (with almost 900 upvotes).

## Installation guide

1. Add this repository to [HACS](https://hacs.xyz/) (or search for "OpenID Connect" in HACS).

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

2. Add the YAML configuration that matches your OIDC provider to `configuration.yaml`. See the [Configuration Guide](./docs/configuration.md) for more details or pick your OIDC provider below:

    | <img src="https://goauthentik.io/img/icon_top_brand_colour.svg" width="100"> | <img src="https://www.authelia.com/images/branding/logo-cropped.png" width="100"> | <img src="https://github.com/user-attachments/assets/4ceb2708-9f29-4694-b797-be833efce17d" width="100"> |
    |:-----------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------:|
    | [Authentik](./docs/provider-configurations/authentik.md)                                       | [Authelia](./docs/provider-configurations/authelia.md)                                     | [Pocket ID](./docs/provider-configurations/pocket-id.md)                                     |

    By default, the integration assumes you configure Home Assistant as a **public client** and thus only specify the `client_id` and no `client_secret`. For example, your configuration might look like:

    ```yaml
    auth_oidc:
        client_id: "example"
        discovery_url: "https://example.com/.well-known/openid-configuration"
    ```

    When registering Home Assistant at your OIDC provider, use `<your HA URL>/auth/oidc/callback` as the callback URL and select 'public client'. You should now get the `client_id` and `issuer_url` or `discovery_url` to fill in.

3. Restart Home Assistant

4. Login through the OIDC Welcome URL at `<your HA URL>/auth/oidc/welcome`. You will have to go there manually for now. For example, it might be located at http://homeassistant.local:8123/auth/oidc/welcome.

More (detailed) usage instructions can be found in the [Usage Guide](./docs/usage.md).

## Contributions
Contibutions are very welcome! If you program in Python or have worked with Home Assistant integrations before, please try to contribute. A list of requested contributions/future goals is in the [Contribution Guide](./CONTRIBUTING.md).

Please see the [Contribution Guide](./CONTRIBUTING.md) for more information.

### Found a security issue?
Please see [SECURITY.md](./SECURITY.md) for more information on how to submit your security issue securely. You can find previously found vulnerablities and their corresponding security advisories at the [Security Advisories page](https://github.com/christiaangoossens/hass-oidc-auth/security/advisories).

## License
Distributed under the MIT license with no warranty. You are fully liable for configuring this integration correctly to keep your Home Assistant installation secure. Use at your own risk. The full license can be found in [LICENSE.md](./LICENSE.md)


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
