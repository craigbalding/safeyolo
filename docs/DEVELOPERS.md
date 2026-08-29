# SafeYolo Developer Guide

This guide is for developers who want to contribute to SafeYolo, build integrations, or extend it with custom addons.

Before changing agent attribution or sandbox lifecycle, read the
[agent identity and run-lifecycle implementation plan](agent-lifecycle-identity-plan.md).
It separates operator-facing names from durable agent identity, records the
current restart behavior, and defines the proposed minimal runtime incarnation.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     HOST (trusted)                            │
│                                                              │
│  ┌──────────────┐        ┌──────────────────────────────┐   │
│  │ safeyolo CLI │───────▶│ mitmproxy (host process)     │   │
│  │  (Typer)     │  admin │   + addons (credential-guard,│   │
│  │  init/start/ │  :9090 │     policy_engine, agent_api,│   │
│  │  watch/logs  │◀───────│     network_guard, ...)      │   │
│  └──────┬───────┘  JSONL └──────────────┬───────────────┘   │
│         │                               │ per-agent UDS      │
│         ▼                               ▼                    │
│  ┌───────────────┐          ┌───────────────────────────┐   │
│  │ ~/.safeyolo/  │          │ Agent sandbox VMs         │   │
│  │  config.yaml  │          │  macOS: Virtualization.fw │   │
│  │  policy.toml  │          │  Linux: rootless gVisor   │   │
│  │  addons.yaml  │          │  (no external network —   │   │
│  │  logs/        │          │   UDS is the only egress) │   │
│  └───────────────┘          └───────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Key design principles:**
- Addons are sensors: detect credentials/patterns, build HttpEvents, call PolicyClient
- PDP package (~2500 lines) handles policy evaluation (can run in-process or as service)
- Detection module (~350 lines) is pure Python for easy testing/fuzzing
- CLI handles user interaction, approval workflow, notifications
- Communication via Admin API (HTTP) and JSONL logs (file)
- Policy files are the source of truth for approvals

## Repository Structure

```
safeyolo/
├── addons/                   # mitmproxy addons (sensors, run in host proxy)
│   ├── detection/            # Pure detection logic (no mitmproxy deps)
│   │   ├── patterns.py       # PatternRule, compile_rules, scan_text
│   │   ├── credentials.py    # CredentialRule, analyze_headers, entropy
│   │   └── matching.py       # Host/resource matching, HMAC fingerprinting
│   ├── admin_api.py          # REST API for runtime control
│   ├── admin_shield.py       # Protects admin API endpoints
│   ├── agent_api.py          # Read-only PDP agent API for agent self-service
│   ├── base.py               # Base addon class with shared functionality
│   ├── budget_tracker.py     # GCRA-based rate limiting
│   ├── circuit_breaker.py    # Fail-fast for unhealthy upstreams
│   ├── credential_guard.py   # Core credential detection and protection
│   ├── file_logging.py       # Structured JSONL file logging setup
│   ├── flow_pruner.py        # TUI-only: prune old flows for memory
│   ├── loop_guard.py         # Proxy loop detection (Via header)
│   ├── memory_monitor.py     # Process memory + connection tracking
│   ├── metrics.py            # Statistics collection
│   ├── network_guard.py      # Network-level security policies
│   ├── pattern_scanner.py    # Regex pattern matching for secrets
│   ├── policy_engine.py      # PolicyEngineAddon, mitmproxy integration
│   ├── policy_loader.py      # Policy file loading and caching
│   ├── request_id.py         # Request ID generation
│   ├── request_logger.py     # JSONL audit logging
│   ├── sensor_utils.py       # HttpEvent builders for sensors
│   ├── service_discovery.py  # Client IP to project mapping
│   ├── sse_streaming.py      # Server-sent events handling
│   ├── test_context.py       # X-SafeYolo-Test-Context header enforcement
│   └── utils.py              # Shared utilities (logging, blocking)
├── pdp/                      # Policy Decision Point (library + service)
│   ├── schemas.py            # HttpEvent, PolicyDecision, Effect enums
│   ├── core.py               # PDPCore - policy evaluation engine
│   ├── client.py             # PolicyClient interface (local/HTTP modes, incl. admin)
│   ├── tokens.py             # HMAC-signed readonly tokens for agent API
│   └── app.py                # FastAPI service (optional deployment)
├── cli/                      # safeyolo CLI (runs on host)
│   ├── src/safeyolo/
│   │   ├── cli.py            # Typer app entry point
│   │   ├── config.py         # Configuration loading
│   │   ├── api.py            # Admin API client
│   │   ├── proxy.py          # Host mitmproxy lifecycle
│   │   ├── vm.py             # Sandbox VM lifecycle (macOS / Linux)
│   │   └── commands/         # CLI command modules
│   │       ├── admin.py      # check, mode, policies
│   │       ├── agent.py      # agent subcommands
│   │       ├── cert.py       # certificate management
│   │       ├── doctor.py     # 11-check diagnostic cascade
│   │       ├── init.py       # init command
│   │       ├── lifecycle.py  # start, stop, status
│   │       ├── logs.py       # log viewing
│   │       ├── sandbox.py    # sandbox subcommands
│   │       ├── setup.py      # setup subcommands
│   │       ├── token.py      # token create/list/revoke
│   │       └── watch.py      # real-time log watching
│   └── pyproject.toml
├── fuzz/                     # Atheris fuzz targets (ClusterFuzzLite)
├── contrib/                  # Example integrations
├── config/                   # Default configurations
├── tests/                    # Test suite (unit + integration)
└── docs/                     # Documentation
```

## Coord trust boundary

Envelope attribution is authoritative; message bodies are untrusted data, and
any SafeYolo-owned UI that presents provenance must keep the two separate when
rendering. Both spoofing bugs found in the Stage-1 dogfood were in the display
layer with a correct envelope. See [coord-trust-boundary.md](coord-trust-boundary.md)
for the contract and the per-sink obligations (terminal, web, log export).

## Building Integrations

### Option 1: Consume JSONL Events

The simplest integration is tailing the JSONL log file. Every security decision is logged with structured data.

**Event format:**
```json
{
  "timestamp": "2024-01-15T14:32:15.123Z",
  "event": "security.credential",
  "request_id": "req-abc123",
  "data": {
    "addon": "credential-guard",
    "decision": "block",
    "rule": "openai",
    "host": "api.example.com",
    "fingerprint": "hmac:a1b2c3d4e5f6",
    "reason": "destination_mismatch",
    "expected_hosts": ["api.openai.com"],
    "confidence": "high",
    "project_id": "default"
  }
}
```

**Event types:**
| Event | Description |
|-------|-------------|
| `security.credential` | Credential detected, decision made |
| `security.ratelimit` | Rate limit hit |
| `security.circuit` | Circuit breaker state change |
| `traffic.request` | Request logged |
| `traffic.response` | Response logged |
| `gateway.allow` | Service gateway allowed a request (capability match) |
| `gateway.deny` | Service gateway denied a request (no matching capability) |
| `gateway.risky_route` | Request matched a risky route, PDP evaluated |
| `gateway.grant_added` | Operator approved a grant for a risky route |
| `gateway.grant_consumed` | Once-grant consumed after successful (2xx) response |
| `gateway.grant_expired` | Grant expired (TTL exceeded) |
| `gateway.grant_revoked` | Grant revoked by operator |
| `admin.policy_write` | Policy file updated |
| `admin.approval_added` | Approval rule added |
| `admin.mode_change` | Addon mode changed |

**Python example:**
```python
import json
from pathlib import Path

def tail_events(log_path: Path):
    """Tail JSONL log for events."""
    with open(log_path) as f:
        f.seek(0, 2)  # Start at end
        while True:
            line = f.readline()
            if line:
                yield json.loads(line)
            else:
                time.sleep(0.1)

# React to blocked credentials
for event in tail_events(Path("./safeyolo/logs/safeyolo.jsonl")):
    if event.get("event") == "security.credential":
        data = event.get("data", {})
        if data.get("decision") == "block":
            # Send notification, update dashboard, etc.
            print(f"Blocked: {data.get('fingerprint')} -> {data.get('host')}")
```

### Option 2: Use the Admin API

The Admin API provides runtime control and status.

**Base URL:** `http://localhost:9090`

**Authentication:** Bearer token
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/stats
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth required) |
| GET | `/stats` | Aggregated addon stats |
| GET | `/modes` | Current addon modes |
| PUT | `/modes` | Set all addon modes |
| GET | `/plugins/{addon}/mode` | Get specific addon mode |
| PUT | `/plugins/{addon}/mode` | Set specific addon mode |
| GET | `/admin/policy/baseline` | Get baseline policy |
| PUT | `/admin/policy/baseline` | Update baseline policy (see note below) |
| POST | `/admin/policy/baseline/approve` | Add credential approval |
| GET | `/admin/policy/task/{task_id}` | Get task-specific policy |
| PUT | `/admin/policy/task/{task_id}` | Create/update task policy |
| GET | `/admin/budgets` | Get budget usage stats |
| POST | `/admin/budgets/reset` | Reset budget counters |
| POST | `/admin/policy/validate` | Validate YAML policy content |

> **Note on `PUT /admin/policy/baseline`:** Full baseline replacement is intended
> for machine-to-machine automation. This operation may not preserve comments,
> layout, or human-authored formatting in the policy file. Operators who use inline
> comments as guidance should prefer incremental local updates or regenerate from
> a canonical source.

**Add an approval via API:**
```bash
curl -X POST "http://localhost:9090/admin/policy/baseline/approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "api.openai.com",
    "credential": "sk-proj-abc123",
    "tier": "explicit"
  }'
```

**Python client:**
```python
from safeyolo.api import AdminAPI

api = AdminAPI(base_url="http://localhost:9090", token="...")

# Get stats
stats = api.stats()
print(stats["credential-guard"]["violations_total"])

# Get current modes
modes = api.get_modes()
print(modes)

# Change mode
api.set_mode("credential-guard", "warn")
```

### Option 3: Write a Custom Addon

Create a new mitmproxy addon for custom logic.

**Basic addon structure:**
```python
# addons/my_addon.py
from mitmproxy import ctx, http

try:
    from .utils import write_event
except ImportError:
    from utils import write_event

class MyAddon:
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
        if not ctx.options.myaddon_enabled:
            return

        # Your logic here
        host = flow.request.host

        if self.should_block(flow):
            flow.response = http.Response.make(
                403,
                b'{"error": "Blocked by my-addon"}',
                {"Content-Type": "application/json", "X-Blocked-By": self.name}
            )
            flow.metadata["blocked_by"] = self.name

            # Log the event
            write_event("security.custom",
                addon=self.name,
                decision="block",
                host=host,
                request_id=flow.metadata.get("request_id")
            )

    def should_block(self, flow: http.HTTPFlow) -> bool:
        # Your detection logic
        return False

    def get_stats(self) -> dict:
        """Return stats for admin API."""
        return {"blocks": 0}

# TrafficMaster registers this list directly
addons = [MyAddon()]
```

**Add to startup:**
```python
# In cli/src/safeyolo/mitm_addons/__init__.py, add the filename to
# ADDON_CHAIN at the required security hook position:
"my_addon.py",
```

Production addons are package imports, not mitmproxy `-s` scripts. The traffic
process loads each addon and its imported `safeyolo.*` dependencies once; source
edits take effect together on the next proxy restart rather than through an
implicit partial hot reload.

**Key patterns:**
- Use `flow.metadata["blocked_by"]` when blocking (logger picks it up)
- Use `write_event()` for structured logging
- Implement `get_stats()` for admin API integration
- Check `flow.metadata.get("policy")` for per-domain config

## Development Setup

**Running with live source editing:**
```bash
# `--dev` runs the proxy from your local checkout so edits to addons/pdp
# source pick up on the next start (no container image, no rebuild step).
safeyolo start --dev

# Edit mitm_addons/*.py, safeyolo/*.py, or pdp/*.py, then restart the traffic
# process to pick up one consistent code generation:
safeyolo stop && safeyolo start --dev
```

Guest VM artifacts (kernel, initramfs, rootfs) are rebuilt separately via
`safeyolo build` — see the top-level README for the full guest-build flow.

**Install dev dependencies and pre-commit hooks:**
```bash
# Install dev dependencies (using uv)
uv sync --group dev

# Install fast commit hooks and the deeper CodeQL pre-push hook
uv run pre-commit install --hook-type pre-commit --hook-type pre-push

# Run the fast hooks manually on all files
uv run pre-commit run --all-files

# Run the Python security-and-quality CodeQL suite used in CI when available
uv run python scripts/check_codeql.py
```

The commit hooks mirror CI's fast static checks:
- **ruff** - linting and import sorting
- **py_compile** - Python syntax validation
- **blackbox schema/docs** - validate test documentation and generated coverage
- **check-yaml/json/toml** - config file validation
- **detect-private-key** - prevent accidental key commits

The pre-push hook additionally runs the same CodeQL Python
`security-and-quality` suite as `.github/workflows/codeql.yml` on supported
local platforms. Its first run downloads the checksum-pinned official stable
bundle used by the workflow action (about 600–850 MB on Linux, depending on
whether `zstd` is available) and caches it under
`~/.cache/safeyolo/codeql`. Set `SAFEYOLO_CODEQL_CACHE` to relocate the cache
or `SAFEYOLO_CODEQL_BIN` to use an already-installed matching CLI. An explicit
binary is validated and used on every architecture; an invalid path is a
pre-push failure. Temporary databases and SARIF files are deleted after each
analysis.

GitHub does not yet publish a pinned official stable native CodeQL bundle for
Linux ARM64 ([upstream tracking PR](https://github.com/github/codeql-action/pull/4072)).
On `aarch64` and `arm64`, the default pre-push hook therefore reports that
local CodeQL is unavailable and skipped, and exits successfully without a
download or analysis. GitHub CI CodeQL remains the required analysis gate; the
skip message does not mean that the commit was analyzed locally. Set
`SAFEYOLO_CODEQL_BIN` to an executable matching CLI to opt into real local
analysis on Linux ARM64. `--install-only` fails if neither that override nor a
supported pinned bundle is available, while `--verify-version` and
`--update-bundle` remain platform-independent. When an official stable native
asset becomes available, adding its platform layout and pinned digest to the
manifest enables it without a separate architecture bypass.

Treat CodeQL findings as defects by default. When a finding is a verified
false positive, put a rationale and a query-specific `# codeql[query-id]`
comment immediately before the reported line. The local runner includes
CodeQL's alert-suppression query, so the annotation behaves the same locally
and in GitHub; broad or unexplained suppressions are not appropriate.

`.github/codeql/local-bundle.json` is the single source of truth for the
CodeQL version. CI compares the version selected from GitHub's hosted tool
cache with that manifest and fails clearly on drift. Refresh the manifest and
official release digests with:

```bash
uv run python scripts/check_codeql.py --update-bundle VERSION_FROM_CI
```

Local analysis uses `--no-download`, so after the initial bundle installation
a missing query pack fails instead of contacting a package registry.

## CLI Development

The CLI is part of the root SafeYolo package and uses Typer.

**Setup:**
```bash
uv sync --group dev
```

**Add a new command:**
```python
# cli/src/safeyolo/commands/mycommand.py
import typer
from rich.console import Console

console = Console()

def mycommand(
    arg: str = typer.Argument(..., help="Required argument"),
    flag: bool = typer.Option(False, "--flag", "-f", help="Optional flag"),
) -> None:
    """Description shown in --help."""
    console.print(f"Running with {arg}, flag={flag}")
```

**Register in cli.py:**
```python
from .commands.mycommand import mycommand
app.command()(mycommand)
```

## Testing

**Run tests:**
```bash
uv sync --group dev
uv run pytest tests/ -v          # unit + integration; integration needs running proxy
uv run pytest tests/test_http_integration.py -v   # integration only
```

**Run CLI tests:**
```bash
uv run pytest cli/tests/ -v
```

**Test credential detection:**
```bash
# Start SafeYolo and add a test agent
safeyolo start
safeyolo agent add scratch --host-script @claude

# Shell into the agent and issue requests through its per-agent socket
safeyolo agent shell scratch
$ curl -H "Authorization: Bearer sk-test123..." https://api.openai.com/v1/models
# Should return 403 (blocked) with X-Blocked-By header

$ curl https://httpbin.org/get
# Should return 200 (allowed)
```

## Documentation drift protection

User-facing docs listed in `scripts/doc_allowlist.toml` are guarded by
six pre-commit hooks that fail CI when a claim in a doc no longer matches
the code. Each mechanism addresses one drift class; together they cover
the five drift classes we've actually observed in this repo.

### The six checks

| Check | Script | Catches |
|---|---|---|
| Marker co-change | `check_skill_markers.py` | Source lines with `# DOC:` markers edited/removed without a matching doc update |
| CLI-flag drift | `check_doc_cli_flags.py` | Docs referencing `safeyolo <cmd>` commands or flags that don't exist |
| Constants-in-prose | `check_doc_constants.py` + `doc_constants.toml` | Pinned values in code no longer matching what docs quote |
| Repo-relative links | `check_doc_links.py` | `[text](path)` / `[label]: path` references to moved or renamed files |
| Forbidden phrases | `check_doc_forbidden.py` + `doc_forbidden.toml` | Stale mechanism claims after the enforcing code was deleted (no anchor left to mark against) |
| Agent token argv | `check_agent_token_argv.py` | Agent API curl examples that expand the bearer into `-H` / `--header` process arguments |

An additional soft check, `audit_doc_coverage.py`, reports which docs
carry how many bindings and which curated security keywords appear in
any doc without a binding. Run it manually — it's a visibility tool,
not a gate.

### Where the allowlist lives

The shipped-docs allowlist is `scripts/doc_allowlist.toml`, with two
tiers reflecting the two audiences:

- `user_facing_docs` — human-operator docs (`README.md`, `SECURITY.md`,
  `docs/*`, `guest/README.md`, `cli/README.md`, `contrib/*.md`). Explicit
  list, no globs.
- `skill_files` — agent-facing docs shipped INTO agent sandboxes as part
  of the safeyolo skill (`SKILL.md` + `references/*.md`). Glob patterns
  allowed — new reference files get automatic coverage.

Both tiers are exposed via `scripts/_doc_config.py` as
`USER_FACING_DOCS`, `SKILL_FILES`, and their union `ALL_SHIPPED_DOCS`.
The link and CLI-flag checks scan the union. The marker check accepts
DOC refs pointing at either tier. The audit tool reports per-tier
binding counts. Design/planning docs (`docs/*-design.md`,
`docs/FUTURE.md`, etc.) are deliberately out of scope — they describe
intent, not runtime behaviour.

`doc_forbidden.toml` and `doc_constants.toml` rules each declare their
own `docs = [...]` list independent of the allowlist, so a rule can
target any file in the repo (used, for example, by the
`skill-must-use-uv-run-pre-commit` rule that scans the skill reference
file directly).

### Where to place a `# DOC:` marker

**Rule of thumb: place the marker on the specific expression that, if
changed, would invalidate the doc claim.** Check semantics are "edits
and removals fire; pure declarative additions do not" — so the marker
line needs to actually change when the enforced fact changes.

Concrete choices used in this repo:

| Kind of claim | Marker location | Example |
|---|---|---|
| Typer command exists | The `def cmdname(` line | `def start(  # DOC: README.md` |
| Typer flag exists (specific flag) | The `"--flag"` string line, not the `def` | `"--dev",  # DOC: docs/DEVELOPERS.md` |
| Pinned constant (shell) | The assignment line | `ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB:-2048}"  # DOC: guest/README.md` |
| Security invariant (specific expression) | The enforcement expression | `HTTPServer(("127.0.0.1", port), ...)  # DOC: SECURITY.md` |
| Class-level property (whole class defends the claim) | The `class Foo:` line | `class AdminShield:  # DOC: SECURITY.md` |
| Function-level property (whole function defends the claim) | The `def foo(` line | `def hmac_fingerprint(...):  # DOC: SECURITY.md` |

A marker can list multiple docs: `# DOC: SECURITY.md, README.md`.
Anchors (`# DOC: docs/AGENTS.md#agents-section`) are advisory in v1.

### Adding a new claim to a user-facing doc

1. **CLI reference** (`safeyolo cmd --flag`) → no action needed; the
   CLI-flag check catches broken references automatically. If you want
   the reverse binding ("changing this flag reminds me to update the
   doc"), add a `# DOC:` marker per the table above.
2. **Pinned value** (version, size, IP, path) → add an `[[assertion]]`
   to `scripts/doc_constants.toml`. Use `must_contain_any = [...]` when
   several phrasings are equivalent (e.g. `["127.0.0.1", "loopback only"]`).
3. **Security or behavioural invariant** → place a `# DOC:` marker on
   the specific enforcement expression per the table above.
4. **Claim about a mechanism that could be removed later** → add a
   `[[rule]]` to `scripts/doc_forbidden.toml` listing the phrases that
   should never appear if the mechanism is gone. This is the check that
   catches "the code that used to defend the claim was deleted" — no
   marker helps there because there's nothing left to mark.
5. **Referenced file path** → the link check handles it automatically
   once the path is in a `[text](path)` or `[label]: path`.

Run `pre-commit run --all-files` locally to verify all six checks pass.
Run `python3 scripts/audit_doc_coverage.py` to see current coverage per
doc and per security keyword — useful for planning what to mark next.

### When *not* to add a marker

- **Design or planning doc** — out of scope; those describe intent.
- **Prose that describes a behaviour enforced by absence of code**
  (e.g. "no external network interface" is defended by the absence of
  bridge configuration — no line to mark). Cover it with a
  forbidden-phrase rule for the stale-mechanism variant, or a
  constants-in-prose assertion for a specific verifiable value.
- **The same claim already has a marker at a stronger enforcement site.**
  One marker per claim is fine; N markers on the same claim add churn
  without extra coverage.

## Contributing

### Contribution Process

1. **Fork and clone** the repository
2. **Create a branch** for your feature/fix
3. **Write tests** for new functionality
4. **Run tests** to ensure nothing breaks
5. **Submit a PR** with a clear description

### Coding Standards

All contributions must:

- **Pass syntax checks** - CI runs `python -m py_compile` on all Python files
- **Pass tests** - All existing tests must pass, new features need tests
- **Support Python 3.12 and 3.13** - CI tests both versions
- **Use type hints** - For function signatures (not enforced by CI yet, but preferred)
- **Follow existing patterns** - Match the style of surrounding code

**Code style:**
- Use descriptive variable names (no single letters except loop counters)
- Keep functions focused and single-purpose
- Add docstrings for public functions
- Avoid bare `except:` - always catch specific exceptions or log the type

### Testing Requirements

Before submitting a PR:

```bash
# Run addon tests
pytest tests/ -v

# Run CLI tests
uv run pytest cli/tests/ -v

# Check syntax (what CI does)
find cli/src -name "*.py" -exec uv run python -m py_compile {} \;
```

### Pull Request Guidelines

- PRs should address a single concern (bug fix, feature, refactor)
- Include tests for new functionality
- Update documentation if adding user-facing changes
- Keep commits atomic and well-described
- CI must pass before merge

### Areas for Contribution

- New credential patterns for additional providers
- Notification backends (Slack, Discord, email)
- CLI improvements
- Documentation
- Test coverage

## Example Integrations

The `contrib/` directory contains example integrations you can use as templates:

| Integration | Description |
|-------------|-------------|
| `contrib/claude-code-chokepoint/` | **Recommended**: Claude Code in enforced chokepoint mode |
| `contrib/monitors/` | Log monitoring and visualization tools |
| `contrib/notifiers/` | Push notifications via ntfy with optional approval buttons |

See [contrib/README.md](../contrib/README.md) for the integration pattern and how to build your own.

**Ideas for new integrations:**
- **Slack/Discord bot** - Post blocked credentials to a channel
- **Dashboard** - Real-time visualization of proxy traffic
- **Metrics exporter** - Push to Prometheus/Grafana
- **CI integration** - Block builds if credentials leak in tests
- **IDE plugin** - Show SafeYolo status in VS Code

## Questions?

Open an issue on GitHub or reach out to the maintainers.
