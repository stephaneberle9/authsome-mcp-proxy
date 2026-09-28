<!-- omit from toc -->
# Contributing

- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites)
  - [Initial Setup](#initial-setup)
- [Running the Server](#running-the-server)
  - [Inside dev environment](#inside-dev-environment)
  - [Outside dev environment](#outside-dev-environment)
  - [As Web Connector Proxy (HTTP Transport)](#as-web-connector-proxy-http-transport)
  - [With MCP Inspector](#with-mcp-inspector)
  - [With Claude Desktop](#with-claude-desktop)
  - [With Claude Code](#with-claude-code)
  - [With Minimal Token-Validating Upstream MCP Example](#with-minimal-token-validating-upstream-mcp-example)
- [Code Quality](#code-quality)
  - [Enable automatic execution on git commit](#enable-automatic-execution-on-git-commit)
  - [Manual execution](#manual-execution)
- [Testing](#testing)
- [CI/CD Workflows](#cicd-workflows)
  - [Static Analysis](#static-analysis)
  - [Test Suite](#test-suite)
  - [Publishing](#publishing)
- [Release Process](#release-process)
- [Building Packages](#building-packages)
- [Dependency Management and Lock Files](#dependency-management-and-lock-files)
  - [Why `uvx` Doesn't Use `uv.lock`](#why-uvx-doesnt-use-uvlock)
  - [Ensuring Compatibility for `uvx` Users](#ensuring-compatibility-for-uvx-users)
  - [When to Update `uv.lock`](#when-to-update-uvlock)

## Development Setup

### Prerequisites

- [Python 3.10](https://www.python.org/downloads) or later
- [uv](https://docs.astral.sh/uv/) — Python package and project manager

### Initial Setup

Clone the repository and install dependencies in an editable virtual
environment that `uv` manages for you:

```bash
git clone https://github.com/stephaneberle9/authsome-mcp-proxy.git
cd authsome-mcp-proxy
uv sync
```

## Running the Server

### Inside dev environment

```bash
# Run the MCP proxy server (see --help for CLI options)
uv run authsome-mcp-proxy [options] https://mcp-upstream.company.com/mcp
# or load credentials from a .env file
uv run --env-file .env authsome-mcp-proxy [options]
```

Press `Ctrl+C` to stop the server.

### Outside dev environment

```bash
# Run the MCP server directly from the sources (see --help for CLI options)
uv run --env-file /path/to/authsome-mcp-proxy/.env --project "/path/to/authsome-mcp-proxy" authsome-mcp-proxy [options]

# Run as editable install to enable live code reloading during development (see --help for CLI options)
uv run --env-file /path/to/authsome-mcp-proxy/.env --with-editable "/path/to/authsome-mcp-proxy" authsome-mcp-proxy [options]
```

### As Web Connector Proxy (HTTP Transport)

Run the dev build as a persistent HTTP server instead of the default stdio transport:

```bash
uv run authsome-mcp-proxy --transport http --port 8000 \
  --proxy-base-url http://localhost:8000 \
  --inbound-auth-provider oidc \
  --oidc-issuer-url https://auth.example.com \
  --oidc-client-id my-client-id \
  --oidc-client-secret your-client-secret \
  https://mcp-upstream.example.com/mcp
# or load all config from a .env file
uv run --env-file .env authsome-mcp-proxy --transport http --port 8000
```

The proxy authenticates via browser on first run, then serves MCP over HTTP at `http://localhost:8000/mcp`. Connect any MCP client to that URL while the server is running.

### With MCP Inspector

**Stdio (inspector launches the proxy):**

Create an `mcp.json` file containing:

```jsonc
{
  "mcpServers": {
    "authsome-mcp-proxy": {
      "command": "uv",
      "args": [
        "run",
        "--env-file", // optional, can also be provided via "env" object
        ".env",
        "authsome-mcp-proxy",
        "https://mcp-upstream.company.com/mcp"
      ],
      // Optional, can also be provided via .env file
      "env": {
          "OIDC_ISSUER_URL": "https://auth.company.com",
          "OIDC_CLIENT_ID": "your-client-id",
          "OIDC_CLIENT_SECRET": "your-client-secret", // to be omitted for public OIDC clients that don't require any such
          "OIDC_SCOPES": "openid profile",
          "OIDC_REDIRECT_URL": "http://localhost:8080/auth/callback"
      }
    }
  }
}
```

From a terminal, start the MCP Inspector:

```bash
# Start and open MCP Inspector in your browser
npx -y @modelcontextprotocol/inspector --config mcp.json --server authsome-mcp-proxy
```

In your browser, connect to your MCP proxy server, authenticate and use the tools, resources and prompts of the upstream MCP server:

- Connect to MCP proxy server: `Connect`
- Sign up/sign in and approve required scopes as needed
- List tools of upstream MCP server: `Tools` > `List Tools`
- Find MCP proxy server logs under `Server Notifications`

**HTTP (connecting to a running proxy):**

Start the proxy in HTTP mode first (see [As Web Connector Proxy](#as-web-connector-proxy-http-transport)), then launch the inspector and connect via its UI:

```bash
npx -y @modelcontextprotocol/inspector
```

In the UI, set *Transport Type* to **Streamable HTTP**, paste
`http://localhost:8000/mcp` into *URL*, and — importantly — set
*Connection Type* to **Via Proxy** (the default *Direct* mode bypasses
Inspector's local OAuth helper and breaks the authorization flow against
the proxy). Then click *Connect*.

### With Claude Desktop

Add the following to your Claude Desktop configuration file (`claude_desktop_config.json`), adjusting the paths to match your local setup:

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```jsonc
{
  "mcpServers": {
    "authsome-mcp-proxy": {
      "command": "uv",
      "args": [
        "run",
        "--env-file", // optional, can also be provided via "env" object
        "/path/to/authsome-mcp-proxy/.env",
        "--with-editable",
        "/path/to/authsome-mcp-proxy",
        "authsome-mcp-proxy",
        "https://mcp-upstream.company.com/mcp"
      ],
      // Optional, can also be provided via .env file
      "env": {
        "OIDC_ISSUER_URL": "https://auth.company.com",
        "OIDC_CLIENT_ID": "your-client-id",
        "OIDC_CLIENT_SECRET": "your-client-secret", // to be omitted for public OIDC clients that don't require any such
        "OIDC_SCOPES": "openid profile",
        "OIDC_REDIRECT_URL": "http://localhost:8080/auth/callback"
      }
    }
  }
}
```

After saving the configuration, restart Claude Desktop. Then:

- Sign up/sign in and approve required scopes as needed
- Open a new chat, click `+` and verify that `authsome-mcp-proxy` appears under `Connectors`
- Use the tools, resources and prompts of the upstream MCP server

If an error popup appears, open the MCP server logs to diagnose the issue:

- **Windows**: `%LOCALAPPDATA%\Claude\Logs\mcp-server-authsome-mcp-proxy.log`
- **macOS**: `~/Library/Logs/Claude/mcp-server-authsome-mcp-proxy.log`

Alternatively, go to `Settings` > `Developer` > select `authsome-mcp-proxy` > `Open Logs Folder`.

### With Claude Code

**Stdio (Claude Code launches the proxy as a subprocess):**

```bash
claude mcp add --transport stdio authsome-mcp-proxy -- \
  uv run --with-editable /path/to/authsome-mcp-proxy authsome-mcp-proxy \
  --oidc-issuer-url https://auth.company.com \
  --oidc-client-id your-client-id \
  https://mcp-upstream.company.com/mcp
```

Or using an `.env` file for credentials:

```bash
claude mcp add --transport stdio authsome-mcp-proxy -- \
  uv run --env-file /path/to/authsome-mcp-proxy/.env \
  --with-editable /path/to/authsome-mcp-proxy \
  authsome-mcp-proxy \
  https://mcp-upstream.company.com/mcp
```

**HTTP (connecting to a running dev proxy):**

Start the proxy in HTTP mode first (see [As Web Connector Proxy](#as-web-connector-proxy-http-transport)), then register it:

```bash
claude mcp add --transport http authsome-mcp-proxy http://localhost:8000/mcp
```

### With Minimal Token-Validating Upstream MCP Example

For quick testing without a real remote MCP server, run the minimal token-validating upstream MCP example:

```bash
# Change to example upstream MCP directory
cd examples/token_validating_upstream_mcp

# Install required dependencies
uv pip install -r requirements.txt

# Run the minimal example MCP client
uv run --env-file .env upstream_mcp.py
```

## Code Quality

This project uses `pre-commit` hooks for running static checks to maintain high code quality standards:

| Hook                   | Purpose                                 |
| ---------------------- | --------------------------------------- |
| `ruff-format`          | Python code formatting                  |
| `ruff-check`           | Python linting (with auto-fix)          |
| `ty check`             | Modern type checking for Python         |
| `prettier`             | JSON, YAML, and Markdown formatting     |
| `codespell`            | Common spelling error detection         |
| `validate-pyproject`   | Project configuration validation        |

### Enable automatic execution on git commit

```bash
uv run pre-commit install
```

### Manual execution

```bash
# Run all checks on all files
uv run pre-commit run --all-files

# Run individual tools
uv run ruff format          # Code formatting
uv run ruff check --fix     # Linting with auto-fix
uv run ty check             # Type checking
```

## Testing

This project includes a comprehensive test suite to ensure reliability and maintainability of the MCP proxy server functionality. They include:

- **Unit tests**: Test configuration, OIDC authentication, and main application components
- **Integration tests**: Test end-to-end OIDC flows with realistic scenarios
- **Coverage tracking**: Code coverage reports generated automatically (see `htmlcov/` directory)

```bash
# Sync project dependencies (includes both dev and test groups)
uv sync

# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run with coverage report output to terminal and enforce minimum coverage
uv run pytest --cov=src/authsome_mcp_proxy --cov-report=term-missing --cov-fail-under=65

# Run specific test file
uv run pytest tests/test_main.py

# Run specific test class
uv run pytest tests/test_main.py::TestCLI

# Run specific test
uv run pytest tests/test_main.py::TestCLI::test_cli_with_minimal_args

# Generate HTML coverage report
uv run pytest --cov-report=html
# Open htmlcov/index.html to view detailed coverage
```

## CI/CD Workflows

This project uses GitHub Actions for continuous integration and deployment. All workflows are located in `.github/workflows/`.

### Static Analysis

**Workflow:** `run-static.yml`

Runs automatically on:

- Push to `main` branch (when source files change)
- All pull requests
- Manual trigger via workflow dispatch

Checks performed:

- Verifies `uv.lock` is up to date
- Runs all pre-commit hooks (Ruff, ty, Prettier, Codespell, etc.)

### Test Suite

**Workflow:** `run-tests.yml`

Runs automatically on:

- Push to `main` branch (when source files change)
- All pull requests
- Manual trigger via workflow dispatch

Test matrix:

- **OS**: Ubuntu, Windows
- **Python**: 3.10

### Publishing

**Workflow:** `publish.yml` (PyPI)

Runs automatically when a GitHub Release is published. Can also be triggered manually.

**Workflow:** `publish-test.yml` (TestPyPI)

Manual trigger only. Use this to test the publishing process before creating a real release.

Both workflows:

- Build the package using `uv build`
- Validate the version format (rejects development versions like `0.1.0.dev1`)
- Publish using PyPI trusted publishing (no API tokens needed)

## Release Process

1. Ensure all tests pass on the `main` branch.

2. Create and push a version tag:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. Create a GitHub release from the tag and add release notes. The `publish.yml` workflow will automatically build, validate, and publish the package to PyPI.

The package version is derived automatically from the git tag by [uv-dynamic-versioning](https://github.com/nicoddemus/uv-dynamic-versioning).

> [!IMPORTANT]
> Tags must follow the format `vX.Y.Z` (e.g. `v0.1.0`, `v1.2.3`).
> The `publish.yml` workflow rejects any other format and any
> development-style version (e.g. `0.1.0.dev1`) — a malformed tag blocks
> the release.

**Testing the release process:** Use the "Publish to TestPyPI" workflow to verify everything works before creating a real release.

## Building Packages

For local package building or manual publishing:

```bash
# Sync project dependencies (production only)
uv sync --no-dev

# Build distribution packages
uv build
```

This will create a `dist` folder containing an `authsome_mcp_proxy-X.X.X.tar.gz` and an `authsome_mcp_proxy-X.X.X-py3-none-any.whl` file.

## Dependency Management and Lock Files

### Why `uvx` Doesn't Use `uv.lock`

When users run `uvx authsome-mcp-proxy`, the `uv.lock` file is **not used**. This is by design and is standard Python packaging practice:

1. **Wheels don't contain lock files**: When publishing to PyPI, the wheel format (preferred by installers) only contains package code, metadata from `pyproject.toml`, and licenses. The `uv.lock` file is deliberately excluded from wheels.

2. **Lock files are development tools**: The `uv.lock` file ensures reproducible development environments when using `uv sync`. It's not part of the PEP 517/621 distribution metadata standard.

3. **uvx creates ephemeral environments**: When running `uvx authsome-mcp-proxy`, it downloads the package from PyPI, creates a temporary virtual environment, and resolves dependencies from package metadata (derived from `pyproject.toml`). No mechanism exists to read or use lock files from the installed package.

### Ensuring Compatibility for `uvx` Users

To ensure users get compatible dependency versions when running `uvx authsome-mcp-proxy`, we use **version constraints in `pyproject.toml`**:

```toml
dependencies = [
    "fastmcp>=4.0.8",
    "py-key-value-aio[disk]>=0.3.0",  # Explicitly requires disk extra
]
```

These constraints are included in the wheel metadata and respected by all package installers (uvx, pip, poetry, etc.), preventing breaking changes from transitive dependencies.

### When to Update `uv.lock`

Update the lock file whenever dependencies change:

```bash
# After modifying pyproject.toml dependencies
uv lock

# Verify the lock file is current
uv sync
```

The lock file ensures all developers use identical dependency versions, but remember: **end users will get versions based on `pyproject.toml` constraints, not the lock file**.
