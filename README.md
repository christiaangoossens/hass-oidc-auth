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
    OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration,<br/>with a strong focus on <b>security, stability and accessibility.</b>
    <br />
    <br />
    <a href="./docs/configuration.md">YAML Configuration Guide</a>
    &middot;
    <a href="./CONTRIBUTING.md">Contribution Guide</a>
    &middot;
    <a href="./docs/faq.md">Frequently Asked Questions (FAQ)</a>
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

Provides a **stable and secure** OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration. With this integration, you can create a single-sign-on (SSO) environment in your self-hosted application stack / homelab.

The core values for this integration are:

1. **Security**: strict adherence to the [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 6749 (OAuth2)](https://datatracker.ietf.org/doc/html/rfc6749), [RFC 7519 (JWT)](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636) and [RFC 9700 (OAuth2 Security Best Practices)](https://datatracker.ietf.org/doc/html/rfc9700) as well as a focus on security tests in the automated test suite.
2. **Stability**: minimal patching of the core Home Assistant code such that updates of HA are less likely to break the integration and leave you without a way to login.
3. **Accessibility**: the integration should work for everyone as much as possible with default settings, regardless of your preferred authentication method.

**TLDR**: *Login to Home Assistant with this integration should 'just work', every time, for everyone in your household ([even your dad](https://github.com/home-assistant/architecture/issues/832#issuecomment-1328052330)), securely.*

If you are deciding if this integration is the right fit for your setup, please see the [Frequently Asked Questions (FAQ)](./docs/faq.md) for more information.


## Installation guide

The easiest way to install the integration is through [the Home Assistant Community Store (HACS)](https://hacs.xyz/). You can find usage instructions for HACS here: https://hacs.xyz/docs/use/.

After installing HACS, search for "OpenID Connect" in the HACS search box or click the button below:

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=christiaangoossens&repository=hass-oidc-auth&category=Integration)

Next, setup your OIDC provider. You can find setup guides for common providers here:

| <img src="https://goauthentik.io/img/icon_top_brand_colour.svg" width="100"> | <img src="https://www.authelia.com/images/branding/logo-cropped.png" width="100"> | <img src="https://github.com/user-attachments/assets/4ceb2708-9f29-4694-b797-be833efce17d" width="100"> |
|:-----------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------:|
| [authentik](./docs/provider-configurations/authentik.md)                                       | [Authelia](./docs/provider-configurations/authelia.md)                                     | [Pocket ID](./docs/provider-configurations/pocket-id.md)                                     |

You can also find additional provider guides in the [the Provider Configurations folder](./docs/provider-configurations). If your provider isn't specified, you can use either a **public client** (recommended) or **confidential client** with the callback url set to `<your HA URL>/auth/oidc/callback`.

Finally, choose your preferred configuration style (UI or YAML). After configuration, you should automatically be sent to the OIDC login page(s) if you open Home Assistant (web or app).

### Configuration in the HA UI

The recommended setup method for beginners is through the "Integrations" panel within the Home Assistant UI. 

Many configuration options are available through this method, but some advanced features are only available in YAML to simplify the setup process in the UI.

1. Open Home Assistant and go to **Settings -> Devices & Services**.
2. Click Add Integration and select **OpenID Connect/SSO Authentication**.
3. Follow the prompts on screen carefully.

### Configuration by YAML

Alternatively, you can configure the integration using YAML. You can find a full configuration guide for YAML here: [YAML Configuration Guide](./docs/configuration.md).

## Contributions
Contibutions are very welcome! If you program in Python or have worked with Home Assistant integrations before, please try to contribute. You can find more information in the [Contribution Guide](./CONTRIBUTING.md).

### Security issue?
Please see [SECURITY.md](./SECURITY.md) for more information on how to submit your security issue securely. You can find previously found vulnerablities and their corresponding security advisories at the [Security Advisories page](https://github.com/christiaangoossens/hass-oidc-auth/security/advisories).

## Background
If you would like to read the background/open letter that lead to this component, you can find it at https://github.com/orgs/home-assistant/discussions/48. It is currently one of the most upvoted feature requests for Home Assistant.

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
