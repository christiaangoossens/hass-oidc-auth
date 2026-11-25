# Contribution Guide
Contributions are very welcome!

## AI use
### What is allowed?
When contributing to this repository, for instance through creating issues, contributing to discussions, submitting security advisories or by making a PR, you are allowed to use AI to:

- Create your work, for instance in AI-assisted programming or by using AI security analysis tools (like Mythos) to find possible vulnerabilities
- Check your work, for instance to create tests or to verify the first proof of concept

You are welcome to submit AI-assisted work that you reviewed and submitted yourself, and that you fully understand and can discuss without a bot.

### What is not allowed?
Your contribution will be declined if:

- You communicate with maintainers exclusively through AI, for instance by having a bot answer comments.
- You created your work fully with AI, for instance with an AI submissions bot that also writes the issue/PR/advisory text.
- You do not fully understand your submitted work when asked to explain.
- You did not check your work manually (code review, vulnerability testing) in addition to any AI checks.
- The contribution is not aligned with the values of this project (see the [core values in the README](./README.md)).

TL;DR: fully vibe-coded work is not accepted.

### Why?
Now that LLMs are commonplace, open source maintainers are getting spammed with low quality bug reports, security advisories and PRs. I encourage users to spend their time on complicated and exciting issues and new features, but instead I keep receiving AI-made fixes for the easiest issues, often submitted to build up a contribution count.

This integration is focused on security and stability and review takes time. Besides just taking time, some PRs and proposed solutions that AI created are just plain wrong, do not follow the project values or have other maintainability downsides.

TL;DR: If I can create the same thing within a few minutes with my own AI assistance and manually understand and review it, it is not worth reviewing your vibe-coded contribution.


## Non-code contributions
If you are not a programmer, you can still contribute by:

- Adding discussion items over at the [Discussions page](https://github.com/christiaangoossens/hass-oidc-auth/discussions) if you have a question, feature idea or a setup you would like to show off.
- Helping others in issues and discussion posts.
- Voting on polls and providing input.
- If you want to, contributing financially through [Github Sponsors](https://github.com/sponsors/christiaangoossens)

## Code contributions
You may also submit Pull Requests (PRs) to add features yourself! You can find TODOs to work on in the [Issue Tracker](https://github.com/christiaangoossens/hass-oidc-auth/issues), the [Feature Requests](https://github.com/christiaangoossens/hass-oidc-auth/discussions/categories/ideas) and in the [FAQ](./docs/faq.md).


Please note that workflows will be run on your pull request (linting, tests, security audit) and a pull request will only be merged when all checks pass and a review has been conducted (together with a manual test).

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

To compile tailwind css styles for the pages you need the NodeJS and NPM installed.

You can run the `npm run css` script to generate the css once and you can run the `npm run css:watch` to recompile the css every time the templates change

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

#### Translating the login pages

The server-rendered login pages (welcome, finish, error, etc.) are translated through JSON catalogs in `custom_components/auth_oidc/views/translations/`. The language is selected automatically from the browser's `Accept-Language` header, falling back to English.

To add a new language:

1. Copy `en.json` to `<language code>.json` (lowercase, e.g. `fr.json`) in the same directory.
2. Translate the values. Keep the keys and any `{placeholders}` unchanged.

Strings missing from a catalog fall back to English at runtime, so existing translations do not block new features or strings. The test suite only verifies that catalogs contain no unknown keys and that `{placeholders}` match `en.json`.

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
Please see [SECURITY.md](./SECURITY.md) for more information on how to submit your security issue securely. You can find previously found vulnerabilities and their corresponding security advisories at the [Security Advisories page](https://github.com/christiaangoossens/hass-oidc-auth/security/advisories).

Do not submit security issues as normal public issues!
