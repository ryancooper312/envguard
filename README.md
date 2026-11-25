# envguard

[![CI](https://github.com/ryancooper312/envguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ryancooper312/envguard/actions/workflows/ci.yml)

Zero-dependency CLI tool to keep `.env` and `.env.example` in sync, enforce typed environment variable schemas via inline comments, and catch accidental secret leaks before they reach version control.

## Why envguard?

Broken deployments often trace back to a missing variable in `.env`, a typo in a port number, or an API key accidentally committed into `.env.example`. `envguard` validates both structure and semantics using standard Python (`>= 3.10`) with zero external dependencies.

## Features

- **Drift Detection**: Ensures every required key declared in `.env.example` exists in `.env` and optionally flags undocumented extra keys.
- **Inline Schema Directives**: Validate `int`, `float`, `bool`, `port`, `url`, `nonempty`, and `enum(...)` directly from comments in `.env.example`.
- **Example Leak Scanner**: Detects high-risk credential patterns (e.g., `ghp_`, `github_pat_`, `AKIA`, `sk_live_`, `AIza`, PEM private keys) accidentally left inside `.env.example`.
- **CI-Friendly Output**: Supports human-readable summaries and machine-parseable `--json` output with predictable exit codes.

## Quick Start

Run directly from source or install locally with `pip`:

```bash
pip install -e .
envguard --env .env --example .env.example
```

Without installing:

```bash
PYTHONPATH=src python3 -m envguard --env .env --example .env.example
```

## Schema Comment Syntax

Annotate variables in `.env.example` using inline comments (`# @...`) or a directive comment on the immediately preceding line:

```dotenv
# @required @type=url
API_BASE_URL=https://api.example.com

PORT=8080 # @required @type=port
DEBUG=false # @type=bool
LOG_LEVEL=info # @type=enum(debug,info,warn,error)
DATABASE_URL= # @required @type=nonempty
```

Supported directives:

| Directive | Description |
| :--- | :--- |
| `@required` | Variable must be present and non-empty in `.env` |
| `@type=int` | Signed integer value |
| `@type=float` | Floating-point numeric value |
| `@type=bool` | `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` (case-insensitive) |
| `@type=port` | Integer between `1` and `65535` |
| `@type=url` | HTTP/HTTPS/WS/Postgres/Redis URL with scheme and host |
| `@type=nonempty` | Non-empty string after trimming |
| `@type=enum(a,b,c)` | Value must match one of the comma-separated choices |

## CLI Options & Exit Codes

```text
usage: envguard [-h] [--env PATH] [--example PATH] [--allow-extra] [--no-secret-scan] [--json]
```

- `0`: All checks passed.
- `1`: Validation errors or secret-leak findings detected.
- `2`: Input file not found or invalid CLI arguments.

## GitHub Actions Example

```yaml
- name: Validate .env.example hygiene
  run: |
    cp .env.example .env.ci
    PYTHONPATH=src python3 -m envguard --env .env.ci --example .env.example --json
```

## License

MIT License. See [LICENSE](LICENSE) for details.
