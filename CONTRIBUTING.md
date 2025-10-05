# Contribution Guide
Contibutions are very welcome!

## Non-code contributions
If you are not a programmer, you can still contribute by:

- Adding discussion items over at the [Discussions page](https://github.com/christiaangoossens/hass-oidc-auth/discussions) if you have a question, feature idea or a setup you would like to show off.
- Helping others in issues and discussion posts.
- Voting on polls and providing input.
- If you want to, contributing financially through [Github Sponsors](https://github.com/sponsors/christiaangoossens)

## Code contributions
You may also submit Pull Requests (PRs) to add features yourself! You can find a list that we are currently working on below. Please note that workflows will be run on your pull request and a pull request will only be merged when all checks pass and a review has been conducted (together with a manual test).

### Development
This project uses the uv package manager for development. You can find installation instructions here: https://docs.astral.sh/uv/getting-started/installation/. Start by installing the dependencies using `uv sync` and then point your editor towards the environment created in the .venv directory.
You can then run Home Assistant and put the `custom_components/auth_oidc` directory in your HA `config` folder.

#### Other useful commands
Some useful scripts are in the `scripts` directory. If you run Linux (or WSL under Windows), you can run these directly:

- `scripts/check` will check your Python files for linting errors
- `scripts/fix` will fix some formatting mistakes automatically
- `scripts/test` will run the testing suite
- `scripts/coverage-report` will run the testing suite and generate a code coverage report (and runs a webserver to serve the report)

You can also run these commands manually on Windows:

##### Compiling css

To compile tailwind css styles for the pages you need the tailwind CLI version 4+

You can run the [css](./scripts/css) script to compile css once and while developing you can run the [watchcss](./scripts/watchcss) script to recompile the css every time the html changes.

Tailwind cli standalone can be downloaded from the [tailwindcss github](https://github.com/tailwindlabs/tailwindcss/releases)

on nixos you need to use the `tailwindcss_4` package

##### Check
```
uv run ruff check
uv run ruff format --check
uv run pylint custom_components
```

##### Fix
```
uv run ruff check --fix
uv run ruff format
```

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
