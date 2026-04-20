# Frequently Asked Questions

## What are the values of this project? Why would I choose this integration over alternatives?

Provides a **stable and secure** OpenID Connect (OIDC) implementation for Home Assistant through a custom component/integration. With this integration, you can create a single-sign-on (SSO) environment in your self-hosted application stack / homelab.

The core values for this integration are:

1. **Security**: strict adherence to the [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html), [RFC 6749 (OAuth2)](https://datatracker.ietf.org/doc/html/rfc6749), [RFC 7519 (JWT)](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7636 (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636) and [RFC 9700 (OAuth2 Security Best Practices)](https://datatracker.ietf.org/doc/html/rfc9700) as well as a focus on security tests in the automated test suite.
2. **Stability**: minimal patching of the core Home Assistant code such that updates of HA are less likely to break the integration and leave you without a way to login.
3. **Accessibility**: the integration should work for everyone as much as possible with default settings, regardless of your preferred authentication method.

**TLDR**: *Login to Home Assistant with this integration should 'just work', every time, for everyone in your household ([even your dad](https://github.com/home-assistant/architecture/issues/832#issuecomment-1328052330)), securely.*

## Is the integration stable?

Yes, this integration has been tested in production environments for multiple years and has almost full automated test coverage to test both security and regressions. Security issues as well as dependency updates are actively monitored through automated pipelines and [a security policy is available here](../SECURITY.md).

## What does this integration not do (yet)?

The integration is currently very suitable for homelab use, but not for enterprise use, because these specs/todos have not been implemented yet:

- [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html): users that are disabled at the IdP do not get logged out in Home Assistant until their refresh token expires/they logout manually
- [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html): logout in Home Assistant does not automatically log the user out at the IdP
- [OpenID Connect Back-Channel Logout 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- *Open TODO*: Permissions are only set upon first login (https://github.com/christiaangoossens/hass-oidc-auth/discussions/187), as permission changes would necessitate revoking refresh tokens/implementing session management
- Other RFC's and best practices with regards to token expiration and revocation in the app itself

These features are hard to implement correctly within a custom integration, as they involve the full authentication lifecycle. Home Assistant does currently implement some features to see which refresh tokens were issued (and thus which sessions are open), which work well with this integration, but lacks any further security focussed features.

For home use where users rarely change permissions/status, these features aren't commonly required. However, if you would like to help implement any of these specifications (while sticking to the value of 'Stability' and minimal Home Assistant core code patching), feel free to create a PR.

## Why does this integration only allow for sign-in on mobile with a device code?
Several attempts have been made at implementing a direct mobile sign-in, but due to many issues (which can be found in https://github.com/orgs/home-assistant/discussions/48 and https://github.com/christiaangoossens/hass-oidc-auth/discussions/95), an approach was chosen that works for all setups and all authentication methods. The mobile apps now show a code, which can be entered into either the Chrome (Android)/Safari (iOS) apps on the mobile device or on another computer, after which the app automatically links and continues with the setup.

If you would like to make another attempt at implementing direct sign-in anyway, please submit a PR.

## I am using a proxy setup where my reverse proxy authenticates users
This integration is intended to be public-facing (as most OIDC apps). If you are authenticating users at the reverse proxy level (such as if you are migrating from https://github.com/BeryJu/hass-auth-header), **you should remove this authentication layer after installing this integration.**.

In general, make sure to set your Home Assistant configuration correctly for your reverse proxy as well (see https://www.home-assistant.io/integrations/http/#reverse-proxies). It is important that the original visitor IP is passed through to Home Assistant for optimal security.

## Help! I have no styling/CSS!
Did you install the integration using HACS, or directly using the `hass-oidc-auth.zip` from the release? If so, this might be a bug. Please submit an issue so we can debug this.

If you installed the integration by cloning master/downloading the source code (either from Github or the releases page), this is intended. You are using a development build in that case, for which you need to build the styles yourself using these instructions: [CONTRIBUTING.md](./CONTRIBUTING.md#compiling-css).

Installing development builds is not recommended! See the question below for more information.

## Why should I only install releases (either from Github or HACS) instead of using the source code?
The `main` branch is in constant development, both manually (PR's) as well as automatically (Renovate Bot/dependency management). While a CI pipeline with tests is run on the `main` branch, manual tests are only performed upon PR merge and during the release creation.

Therefore, issues that occur because of the use of the `main` branch (or any other specific commmit/release source code) will not be processed. At any time, the state of `main` may be broken, as it is only intended for development.

Releases, available at [Releases](https://github.com/christiaangoossens/hass-oidc-auth/releases), by constrast, are immutable and tested manually before release. While a release may be deleted, releases cannot be altered after publishing.

This ensures that - even if a security issue with my accounts occured - no malicious code enters an existing release and that the release is installed exactly as intended.

HACS automatically - and only - uses these releases and is thus the recommended install method. If you want to install a release manually, please specifically use the `hass-oidc-auth.zip` (and not the release source code zip), such that you get styling.
