# Contribution Guide
Contibutions are very welcome!

## Non-code contributions
If you are not a programmer, you can still contribute by:

    - Adding discussion items over at the [Discussions page](https://github.com/christiaangoossens/hass-oidc-auth/discussions) if you have a question, feature idea or a setup you would like to show off.
    - Helping others in issues and discussion posts.
    - Voting on polls and providing input.

## Code contributions
You may also submit Pull Requests (PRs) to add features yourself! You can find a list that we are currently working on below. Please note that workflows will be run on your pull request and a pull request will only be merged when all checks pass and a review has been conducted (together with a manual test).

### Development

This project uses the Rye package manager for development. You can find installation instructions here: https://rye.astral.sh/guide/installation/. Start by installing the dependencies using rye sync and then point your editor towards the environment created in the .venv directory.

You can then run Home Assistant and put the `custom_components/auth_oidc` directory in your HA `config` folder.

### Docker Compose Development Environment
You can also use the following Docker Compose configuration to automatically start up the latest HA release with the `auth_oidc` integration:

```
services:
  homeassistant:
    container_name: homeassistant
    image: "ghcr.io/home-assistant/home-assistant:stable"
    volumes:
      - ./config:/config
      - ./custom_components/auth_oidc:/config/custom_components/auth_oidc
      - /etc/localtime:/etc/localtime:ro
    ports:
      - 8123:8123
```

# Found a security issue?
Please see [SECURITY.md](./SECURITY.md) for more information on how to submit your security issue securely. You can find previously found vulnerablities and their corresponding security advisories at the [Security Advisories page](https://github.com/christiaangoossens/hass-oidc-auth/security/advisories).

# Roadmap
The following features are on the roadmap:

## Better user experience
*Copied from https://github.com/christiaangoossens/hass-oidc-auth/issues/19*

Current status on the user experience:

- I cannot change the login screen as all of this is hard coded in the frontend code. So, I am stuck with the title of "Just checking" and without any description or even a title for the input box. Changing this would require a PR on the Home Assistant frontend repository.
  - If anyone can refactor their code to allow integrations (Auth Providers) to send custom translations to the frontend when sending the form (here: [custom_components/auth_oidc/provider.py, line 302](https://github.com/christiaangoossens/hass-oidc-auth/blob/main/custom_components/auth_oidc/provider.py#L302)), such that I can send custom translation keys for the title (instead of just using the `mfa` version), description and input label, I would be very happy to accept a PR here as well that accomplishes that.
  - Bonus points if it uses the same translation system you would use for any normal setup/config flow in the UI.
  - Extra bonus points if we can add a button or link besides it that allows for opening the start of the OIDC flow there too, within the description for instance.

- I cannot redirect you to the start of the OIDC process yet, both on mobile and on desktop. Whenever [the PR](https://github.com/home-assistant/frontend/pull/23204) gets merged and a Home Assistant version that's includes the PR is released (or planned), I will hopefully be able to get something like that to work on desktop.
  - It likely will not work on mobile, as the PR that's now approved only does it for desktop, I tested mobile with that code 2 years ago and it didn't work. I will contact someone on the Android team to see if we can make that happen too at some point.
    - Mobile will need to open the `window.open` call using Android Custom Tab (Android) / SFSafariViewController (iOS) instead of the normal webview. It seems that external links didn't work at all when I tried it.

PR's that improve the user experience are welcome, but they should be stable and preferably hack as little as possible.

## Tests
The project still needs the following automated tests on every PR:

- Spin up Home Assistant (both the required version from the `hacs.json` and the latest version) and verify that it starts up with no warnings or errors
- Normal pytest unit testing (https://developers.home-assistant.io/docs/development_testing/)
  - You might be able to re-use some unit tests from the original implementation by @elupus: https://github.com/home-assistant/core/pull/32926 or from it's inspired work by @allenporter: https://github.com/allenporter/home-assistant-openid-auth-provider/tree/main/tests
- Integration test that performs an automatic run-through of an entire flow with an example/mocked OIDC provider, either in Python code or using an external tool (such as Playwright)

Together, these should test the following:
- The integration registers correctly without any errors (spin-up test)
- The integration works with both the minimum HA version as well as the latest HA version (spin-up test)
- Configuration can be set without any errors (unit test)
- Configuration has the correct effects (unit test)
- Code works correctly on its own (unit test)
- Full flow is functional and displays as expected, including integration with an external OIDC provider (integration test)

Preferably, we run all tests on every PR to make manual testing unnecessary.

## Better configuration experience
While the configuration poll is still open (https://github.com/christiaangoossens/hass-oidc-auth/discussions/6), it seems that the best option would be to keep the current YAML configuration for advanced uses and add a UI configuration for the common providers.

You are welcome to contribute the following:

- UI configuration process which allows selection of an OIDC provider (or manual if you want as well), input of the client id & discovery URL (and optional secret) and then checks that these parameters entered are correct by performing a discovery and authorization call (prompt=none) in the setup process.
  - This allows for rejecting invalid parameters if they are wrong before saving.
- You may get the claim configuration from the provider selector or allow a manual provider override.
- You may allow users to input their group names to have role mapping.
- You may offer automatic user linking as an option, provided that you warn users and allow disabling it later.
- You should not offer the other feature flags as options or the network advanced config to prevent novice users from misconfiguring the integration by accident. You may refer to the YAML config to do so.

While I welcome adding configuration by UI, it's not at the top of my priority list. Ask me in the PR if you have any other suggestions and don't forget to add tests for this too.