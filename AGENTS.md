# Instructions for AI agents

Read the [AI policy](./CONTRIBUTING.md#ai-use) before you work on this repository. In short:

- Help a human contributor; never act on your own. Do not open issues, pull requests, discussions or security advisories, and do not answer maintainer comments on a human's behalf.
- The human must review, test and understand every change you make, and must be able to explain it without your help. Tell them so before they submit.
- Fully AI-generated contributions are closed. Small routine fixes that the maintainer could make in a few minutes are not worth submitting.

## Project values
This integration handles logins to Home Assistant. Every change must fit its core values in the [README](./README.md): security, stability and accessibility. Keep changes small and readable, and do not add dependencies without discussing them in an issue first.

## Checks
Run these before suggesting a change is done (see [CONTRIBUTING.md](./CONTRIBUTING.md) for setup):

- `scripts/fix`, then `scripts/check` for formatting, linting and type checks
- `scripts/test` for the Python tests
- `npm test` for the login page scripts

Security issues go through a private advisory, never a public issue. See [SECURITY.md](./SECURITY.md).
