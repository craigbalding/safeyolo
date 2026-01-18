# SafeYolo Agent Guide

This document contains **default context guidelines** for Python-focused development in the SafeYolo project. It applies to the default Python context (folders not listed as 'island submodules').

SafeYolo is a security proxy for AI coding agents built with mitmproxy, Python, and Docker.

## Main carta

**Hello non-deterministic agent!** Never compress the instructions given in this 'Main carta' or instruct yourself to recover this 'Main carta' after compressing. Ignoring the instructions herein renders an agent's operation useless, better stop processing if this requirement is not guaranteed to be followed during the whole course of operation. The 'Main carta' itself:

This Git repo does not have actual monorepo organizing files in the root (except the obvious ones like gitignore), it's a monorepo by the fact of uniting different parts of the solution, which parts can be totally alien by their nature, let's call those 'island submodules' (do not expect those be actual git submodules). 

The effective solution is mostly Python based (with shell scripts and docker definitions), that's the default flavour, that's the default context of stuff in folders not listed below as 'island submodules'.

The 'island sumodules' by <reporoot/[foldername]> definition:
- **/ui.app** part ("submodule") is a no-Python TS webapp with some Golang code, which uses bun for scripting

Fundamental instructions created for the default Python world development (like /docs) should not be applied to the TS world island submodules, and vice versa the 'island submodules'-specific instructions (like /ui.app/docs) should be ignored in the global context unless explicitly imported to the given context.

We also use 'shared folders', but those are not globally shared by defualt. Further instructions will tell which shared folders to observe in the given context.

### Forbidden behaviour
- Never change the tooling or configuration installed or set outside of the monorepo (this git repo)
  - Such chnages should be suggested to the user to perform and may likely be rejected and so then the agent is to suggest other solutons

### Monorepo Basics

#### Context

- Instead of self-contained agants.md or a conventioanl hierarchy of agents.md-s we use specialized context/conventions/instructions/guidline files, like for example the fundamental ones in the /docs folder (part of the default context, not automatically applicable in case of working in an 'island submodule').
- Also instead of self-contained agents.md-s and similar we plan to use 'specilaized context files', where an agents file (note: may well not only be named agents.md, but a conventional agents file) when it refers to an external context/conventions/instructions/guidelines file (a specialized context file) the content of that external file should be treated as if it was inherent part of the content of the given angents file.
- Unconditionally parse (read) the specialized context files identified by the `follow!` instruction.
  - The instruction format is `follow! [relative/path/to/file.md](absolute/path/to/file.md)` or just `follow! [relative/path/to/file.md]`.
  - Treat the content of these referenced specialized files as if they were directly embedded in the given agents file document.
- In monorepo root (this one), in the roots of 'island submodules' (like /ui.app) and roots of shared folders we place standard AGENTS.md files which are the entry points for collecting those relevant context instructions.

## Island Submodules

Island submodules are separate parts of the monorepo with their own technology stacks, conventions, and context files. Each island submodule has its own AGENTS.md entry point.

### Known Island Submodules

- **/ui.app**: TypeScript webapp with Golang code, uses bun for scripting (no Python)

### Shared Folders

Some folders may be shared across contexts, but not globally shared by default. Context-specific instructions will indicate which shared folders to observe.

### Cross-Context Guidelines

When working in this monorepo:

1. **Context boundaries**: Each island submodule has its own context. The default Python context applies to folders not listed as island submodules.

2. **AGENTS.md entry points**: Each context (root, island submodule roots, shared folder roots) has its own AGENTS.md file as the entry point for context instructions.

3. **`follow!` instructions**: As described in Main carta, use `follow! [relative/path/to/file.md](absolute/path/to/file.md)` or `follow! [relative/path/to/file.md]` to import specialized context files. Treat their content as if directly embedded.

4. **Tooling isolation**: Do not apply tooling, configuration, or conventions from one context to another unless explicitly instructed.

5. **Shared folder awareness**: When a folder is shared across contexts, follow context-specific instructions about which shared folders to observe.

### Context Switching for Agents

When your task requires working across different contexts:

1. **Identify current context**: Check which AGENTS.md file you're reading. The root AGENTS.md (this file) covers the default Python context and island submodule overview.

2. **Switch to island submodule context**: To work in an island submodule (e.g., `/ui.app`), navigate to its AGENTS.md file and treat it as your new entry point.

3. **Follow context imports**: Use `follow!` instructions to import specialized context files relevant to your current context.

4. **Maintain context isolation**: Do not carry assumptions, tooling, or patterns from one context to another. Each context has its own conventions.

5. **Return to root context**: When finished with island submodule work, return to root AGENTS.md for default context operations.

## Default Context (Python-Focused)

**⚠️ IMPORTANT**: The following sections apply **only** to the default Python context (folders not listed as island submodules). Do not apply these guidelines to island submodules unless explicitly instructed.

### Project Overview

SafeYolo is a TLS-intercepting proxy that:
- Protects API keys from unauthorized destinations
- Provides network isolation for AI coding agents
- Logs all security decisions to JSONL
- Runs as a mitmproxy addon stack with centralized Policy Decision Point (PDP)

### Repository Structure (Default Python Context)

**Note**: This structure shows only directories in the default Python context. Island submodules (like `/ui.app`) have their own separate structures.

```
safeyolo/
├── addons/                   # mitmproxy addon modules (run in container)
│   ├── detection/            # Pure detection logic (no mitmproxy deps)
│   │   ├── credentials.py    # Credential detection rules
│   │   ├── patterns.py      # Pattern compilation
│   │   └── matching.py     # Host/resource matching
│   ├── admin_api.py         # REST API for runtime control
│   ├── admin_shield.py      # Protects admin API
│   ├── base.py             # SecurityAddon base class
│   ├── credential_guard.py  # Credential routing protection
│   ├── network_guard.py     # Domain allowlist enforcement
│   ├── pattern_scanner.py   # Content pattern detection
│   ├── policy_engine.py     # Policy evaluation
│   ├── request_logger.py    # JSONL audit logging
│   ├── metrics.py          # Statistics collection
│   └── utils.py           # Shared utilities
├── pdp/                    # Policy Decision Point (library)
│   ├── schemas.py          # HttpEvent, PolicyDecision models
│   ├── core.py             # PDPCore - evaluation engine
│   ├── client.py           # PolicyClient interface
│   └── app.py             # FastAPI service (optional)
├── cli/                    # SafeYolo CLI (runs on host)
│   ├── src/safeyolo/
│   │   ├── cli.py         # Typer app entry point
│   │   ├── api.py         # Admin API client
│   │   ├── docker.py      # Container management
│   │   └── commands/      # CLI command modules
│   ├── tests/             # CLI tests
│   └── pyproject.toml
├── tests/                 # Main test suite
│   ├── conftest.py        # pytest fixtures
│   ├── test_*.py         # Unit/integration tests
│   └── blackbox/         # End-to-end security tests
├── config/                # Default configurations
├── scripts/               # Shell scripts (startup, etc.)
├── docker-compose.yml      # Development infrastructure
└── Dockerfile             # Container image (base + dev targets)
```

### Essential Commands

#### Development Setup

```bash
# Install dependencies (from project root)
uv sync --group dev

# Install CLI separately
cd cli && uv sync --group dev
```

#### Testing

```bash
# Run addon tests (from project root)
uv run pytest tests/ -v --ignore=tests/blackbox/

# Run CLI tests (from cli directory)
cd cli
uv run pytest tests/ -v

# Run specific test
uv run pytest tests/test_credential_guard.py::test_analyze_headers -v

# Run with coverage
uv run pytest tests/ --cov=addons --cov-report=term-missing
```

#### Code Quality

```bash
# Lint with ruff
uv run ruff check addons/ cli/src/ tests/ --exclude tests/blackbox/

# Auto-fix linting issues
uv run ruff check --fix addons/ cli/src/ tests/ --exclude tests/blackbox/

# Run pre-commit hooks manually
pre-commit run --all-files
```

#### Docker Operations

```bash
# Build container
docker build -t safeyolo .

# Build dev target (includes pytest)
docker build --target dev -t safeyolo:dev .

# Start development environment
docker compose up -d

# View logs
docker compose logs -f safeyolo

# Stop environment
docker compose down
```

#### Blackbox Tests

```bash
# Run all blackbox tests (slow, ~5 min)
./tests/blackbox/run-tests.sh

# Run proxy tests only
./tests/blackbox/run-tests.sh --proxy

# Run isolation tests only
./tests/blackbox/run-tests.sh --isolation
```

### Code Conventions

#### Naming

- **Addon names**: kebab-case (`credential-guard`, `network-guard`)
- **Mitmproxy options**: snake_case derived from addon name (`credguard_block`, `network_guard_block`)
- **Classes**: CamelCase (`CredentialGuard`, `SecurityAddon`)
- **Functions/methods**: snake_case (`get_client_ip`, `log_decision`)
- **CLI commands**: snake_case (`init.py`, `lifecycle.py`, `admin.py`)

#### Addon Structure

Addons extend `SecurityAddon` base class from `addons/base.py`:

```python
from base import SecurityAddon
from mitmproxy import ctx, http

class MyAddon(SecurityAddon):
    name = "my-addon"

    def load(self, loader):
        """Register options."""
        loader.add_option(
            name="myaddon_enabled",
            typespec=bool,
            default=True,
            help="Enable my addon",
        )

    def request(self, flow: http.HTTPFlow):
        """Called for each request."""
        if not self.is_enabled() or self.is_bypassed(flow):
            return

        self.stats.checks += 1

        # Detection logic here

        if should_block:
            self.log_decision(flow, "block", reason="...")
            self.block(flow, 403, {"error": "Blocked"})
        else:
            self.stats.allowed += 1

    def get_stats(self) -> dict:
        """Return stats for admin API."""
        return self.stats.__dict__
```

**Key patterns:**
- Always check `is_enabled()` and `is_bypassed()` first
- Use `log_decision()` for structured logging
- Set `flow.metadata["blocked_by"]` when blocking
- Implement `get_stats()` for admin API exposure

#### Option Naming Convention

Addon names automatically convert to option prefixes:
- `credential-guard` → `credguard_enabled`, `credguard_block`
- `network-guard` → `network_guard_enabled`, `network_guard_block`

Use `get_option_safe()` from `utils.py` for access.

#### Testing Patterns

Use pytest with mitmproxy test fixtures:

```python
from mitmproxy.test import tflow, taddons

def test_something(make_flow, taddons_ctx):
    # Create test flow
    flow = make_flow(
        method="POST",
        url="https://api.openai.com/v1/chat",
        headers={"Authorization": "Bearer sk-test123"}
    )

    # Set up addon with context
    with taddons_ctx(addon) as tctx:
        tctx.options.credguard_block = True
        addon.request(flow)

        # Assertions
        assert flow.response is not None
        assert flow.response.status_code == 403
```

#### Fixture Dependencies

Use conftest.py fixtures:
- `make_flow`: Factory for creating test flows
- `make_response`: Factory for creating test responses
- `taddons_ctx`: Provides mitmproxy context for options
- `policy_engine_initialized`: Initializes PDP with test baseline
- `credential_guard`: Configured CredentialGuard instance

### Architecture Patterns

#### Policy Decision Point (PDP)

All addons use `PolicyClient` interface:

```python
from pdp import get_policy_client

def evaluate_something(self, flow):
    client = get_policy_client()

    event = build_http_event_from_flow(
        flow=flow,
        principal_id="user-123",
        # ... event fields
    )

    decision = client.evaluate(event)
    # decision.effect: ALLOW, DENY, REQUIRE_APPROVAL
```

Two implementations:
- `LocalPolicyClient`: In-process (default, fastest)
- `HttpPolicyClient`: Remote HTTP service

#### Credential Protection

**Never log raw credentials** - use HMAC fingerprinting:

```python
from utils import hmac_fingerprint

# DON'T log this
log.warning(f"Credential: {credential}")

# DO this instead
fingerprint = hmac_fingerprint(credential, secret)
log.warning(f"Credential: hmac:{fingerprint}")
```

#### Addon Chain Order

Critical for security - order defined in `scripts/start-safeyolo.sh`:

1. **Layer 0 - Infrastructure**: `admin_shield`, `request_id`, `sse_streaming`, `policy_engine`
2. **Layer 1 - Network Policy**: `network_guard`, `circuit_breaker`
3. **Layer 2 - Security Inspection**: `credential_guard`, `pattern_scanner`
4. **Layer 3 - Observability**: `request_logger`, `metrics`, `admin_api`

First blocker wins - subsequent addons see `flow.response` is set.

#### Hot Reload Pattern

Addons reload configuration on policy change:

```python
def _maybe_reload_rules(self):
    """Reload if policy changed."""
    client = get_policy_client()
    config = client.get_sensor_config()

    if config["policy_hash"] != self._last_policy_hash:
        self._load_from_config(config)
        self._last_policy_hash = config["policy_hash"]
```

Call at start of `request()` hook.

### Important Gotchas

#### Import Paths

Addons are loaded by mitmproxy with `-s` flag, so:
- Use relative imports: `from .utils import write_event`
- Or add project root to sys.path (see `credential_guard.py` line 31)
- In tests, conftest.py adds directories to path automatically

#### Non-root Container Execution

SafeYolo runs as non-root user (from host UID/GID):
- Docker compose uses `${SAFEYOLO_UID}` and `${SAFEYOLO_GID}`
- Volume permissions must match host user
- Set `SAFEYOLO_UID=$(id -u)` in `.env` for development

#### Docker Compose Networks

Two networks:
- `internal`: All agent containers (no internet access, must use proxy)
- `default`: Only SafeYolo uses this (has internet access)

Agents join `internal` network and proxy via `http://safeyolo:8080`.

#### CLI vs Container State

CLI commands modify state on host, not in container:
- Policy files are stored in `./safeyolo/` on host
- CLI mounts them into container via volumes
- SafeYolo reads from mounted config directory

#### Headless Mode

For testing/CI, set `SAFEYOLO_HEADLESS=true` to run `mitmdump` instead of TUI:
- No tmux session
- Logs written to file (picked up by Docker logs)
- Used by blackbox tests

#### TLS Passthrough

Some protocols don't work with MITM:
- FRP protocol (`api.asterfold.ai:7000`) added to `--ignore-hosts`
- Add other protocols via startup script if needed

### Configuration Files

#### pyproject.toml (project root)

Main Python project configuration:
- Runtime dependencies: mitmproxy, httpx, pydantic, etc.
- Dev dependencies: pytest, ruff, pre-commit
- Workspace members: cli, tests/blackbox/runner, tests/blackbox/sinkhole
- Python version: >=3.12

#### ruff.toml

Linting configuration:
- Line length: 120
- Target version: py311
- Enable: E, W, F, I, B, C4, UP rules
- Ignore: E501, B008, B904, B905, UP007, UP045
- First-party imports: addons, safeyolo

#### .pre-commit-config.yaml

Hooks run before commit:
- Ruff (with --fix)
- Python syntax check
- uv.lock validation
- YAML/JSON/TOML checks
- End-of-file and trailing whitespace
- Private key detection

#### Dockerfile

Multi-stage build:
- `base`: Core addons only (~200MB) - default
- `dev`: Development/testing with pytest

#### docker-compose.yml

Development infrastructure:
- `safeyolo`: Proxy container (mitmproxy + addons)
- `certs-init`: Volume permission setup
- Networks: internal (no internet), default (internet only)
- Volumes: certs, logs, config, data

### CI/CD

#### GitHub Actions

**CI workflow** (`.github/workflows/ci.yml`):
- Triggers: push to main, pull requests
- Jobs:
  - `test-addons`: pytest on Python 3.12 (PRs only), 3.12+3.13 (push)
  - `test-cli`: pytest CLI package
  - `lint`: ruff + py_compile
- Runs: `uv run pytest tests/ -v --ignore=tests/blackbox/`

**Blackbox workflow** (`.github/workflows/blackbox.yml`):
- Triggers: schedule (daily), manual, push to main
- No PR triggers (slow ~5 min)
- Runs: `./tests/blackbox/run-tests.sh`
- Tests: Proxy tests (credential guard, network guard) + isolation tests

**Concurrent runs**: Cancel in-progress runs on same branch.

### Development Workflow

#### Adding a New Addon

1. Create `addons/my_addon.py`
2. Extend `SecurityAddon` base class
3. Implement `load()`, `request()`/`response()` hooks
4. Add to `scripts/start-safeyolo.sh` in appropriate layer
5. Write tests in `tests/test_my_addon.py`
6. Run lint and tests

#### Modifying Policy Model

1. Update schemas in `pdp/schemas.py`
2. Modify `UnifiedPolicy` in `pdp/core.py`
3. Update PolicyEngine evaluation logic
4. Update test fixtures in `tests/conftest.py`
5. Test with unit + integration tests

#### CLI Changes

1. Modify `cli/src/safeyolo/commands/` modules
2. Test with `cd cli && uv run pytest tests/`
3. Reinstall CLI: `cd cli && uv tool install -e .`

#### Debugging Addons

1. Attach to mitmproxy TUI: `docker exec -it safeyolo tmux attach`
2. View addon logs: `docker compose logs safeyolo`
3. Check JSONL logs: `tail -f logs/safeyolo.jsonl`
4. Use mitmproxy event inspector in TUI

### Security Considerations

- **Never commit credentials** - pre-commit blocks this
- **Use HMAC fingerprints** for credential logging
- **Fail closed** - PDP unavailable = DENY
- **Run as non-root** in production
- **Pin base images** with digests (see Dockerfile)
- **Limit attack surface** - only install necessary dependencies
- **Validate all inputs** - use Pydantic models for data structures

### Getting Help

- Architecture: `docs/ARCHITECTURE.md`
- Development: `docs/DEVELOPERS.md`
- Configuration: `docs/CONFIGURATION.md`
- Addons: `docs/ADDONS.md`
- CLI: `cli/README.md`
- Security: `SECURITY.md`
