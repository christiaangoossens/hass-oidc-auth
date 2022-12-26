# OIDC Auth for Home Assistant

Status: in progress, but very slowly.

Current roadblocks:

[ ] Find a way to do a redirect within the login step in Home Assistant, we should not use window.open
[ ] Find out how to make this redirect work on all platforms (including mobile)

If this is solved, implementing OIDC itself is doable.

If you have any tips or would like to contribute, send me a message.

## Installation

Add this repository to [HACS](https://hacs.xyz/).

Update your configuration.yaml file with

```yaml
auth_oidc:
```

Afterwards, restart Home Assistant.

## Development
This package uses poetry: https://github.com/python-poetry/poetry. Use `poetry install` to install.
You can force the venv within the project with `poetry config virtualenvs.in-project true`.
