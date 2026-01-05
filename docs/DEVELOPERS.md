# SafeYolo Developer Guide

This guide is for developers who want to contribute to SafeYolo, build integrations, or extend it with custom addons.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     SafeYolo System                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Host Side                       Container Side              │
│  ──────────                      ──────────────              │
│                                                              │
│  ┌──────────────┐               ┌──────────────────────┐    │
│  │ safeyolo CLI │               │ mitmproxy + addons   │    │
│  │  (Python)    │◄──────────────│                      │    │
│  │              │  Admin API    │ credential_guard.py  │    │
│  │  - init      │  :9090        │ policy_engine.py     │    │
│  │  - start     │               │ admin_api.py         │    │
│  │  - watch     │◄──────────────│ ...                  │    │
│  │  - logs      │  JSONL logs   │                      │    │
│  └──────────────┘               └──────────────────────┘    │
│         │                                │                   │
│         │                                │                   │
│         ▼                                ▼                   │
│  ┌──────────────┐               ┌──────────────────────┐    │
│  │ ./safeyolo/  │               │ Proxy :8080          │    │
│  │  config.yaml │               │                      │    │
│  │  rules.json  │               │ Intercepts HTTP      │    │
│  │  policies/   │               │ from AI agents       │    │
│  │  logs/       │               │                      │    │
│  └──────────────┘               └──────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key design principles:**
- Proxy addons (~5500 lines) are focused on detect/decide/emit
- CLI handles user interaction, approval workflow, notifications
- Communication via Admin API (HTTP) and JSONL logs (file)
- Policy files are the source of truth for approvals

## Repository Structure

```
safeyolo/
├── addons/                   # mitmproxy addons (run in container)
│   ├── admin_api.py          # REST API for runtime control
│   ├── admin_shield.py       # Protects admin API endpoints
│   ├── base.py               # Base addon class with shared functionality
│   ├── budget_tracker.py     # Token/cost budget tracking
│   ├── circuit_breaker.py    # Fail-fast for unhealthy upstreams
│   ├── credential_guard.py   # Core credential detection and protection
│   ├── metrics.py            # Statistics collection
│   ├── network_guard.py      # Network-level security policies
│   ├── pattern_scanner.py    # Regex pattern matching for secrets
│   ├── policy_engine.py      # Approval/deny policy evaluation
│   ├── policy_loader.py      # Policy file loading and caching
│   ├── request_id.py         # Request ID generation
│   ├── request_logger.py     # JSONL audit logging
│   ├── service_discovery.py  # API provider detection
│   ├── sse_streaming.py      # Server-sent events handling
│   └── utils.py              # Shared utilities
├── cli/                      # safeyolo CLI (runs on host)
│   ├── src/safeyolo/
│   │   ├── cli.py            # Typer app entry point
│   │   ├── config.py         # Configuration loading
│   │   ├── api.py            # Admin API client
│   │   ├── docker.py         # Container management
│   │   └── commands/         # CLI command modules
│   │       ├── admin.py      # check, mode, policies, test
│   │       ├── agent.py      # agent subcommands
│   │       ├── cert.py       # certificate management
│   │       ├── lifecycle.py  # start, stop, status
│   │       ├── logs.py       # log viewing
│   │       ├── sandbox.py    # sandbox subcommands
│   │       ├── setup.py      # setup subcommands
│   │       └── watch.py      # real-time log watching
│   └── pyproject.toml
├── contrib/                  # Example integrations
├── config/                   # Default configurations
├── tests/                    # Addon test suite
└── docs/                     # Documentation
```

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
| PUT | `/admin/policy/baseline` | Update baseline policy |
| POST | `/admin/policy/baseline/approve` | Add credential approval |
| GET | `/admin/policy/task/{task_id}` | Get task-specific policy |
| GET | `/admin/budgets` | Get budget usage stats |
| POST | `/admin/budgets/reset` | Reset budget counters |
| POST | `/admin/policy/validate` | Validate YAML policy content |

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

# mitmproxy discovers this
addons = [MyAddon()]
```

**Add to startup:**
```bash
# In scripts/start-safeyolo.sh, add:
-s addons/my_addon.py
```

**Key patterns:**
- Use `flow.metadata["blocked_by"]` when blocking (logger picks it up)
- Use `write_event()` for structured logging
- Implement `get_stats()` for admin API integration
- Check `flow.metadata.get("policy")` for per-domain config

## CLI Development

The CLI is a standard Python package using Typer.

**Setup:**
```bash
cd cli
pip install -e ".[dev]"
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

**Run addon tests:**
```bash
# In container
docker exec safeyolo pytest tests/ -v

# Locally (requires mitmproxy)
pip install -r requirements/dev.txt
pytest tests/ -v
```

**Run CLI tests:**
```bash
cd cli
pytest tests/ -v
```

**Test credential detection:**
```bash
# Start SafeYolo
safeyolo start

# Test with fake credential
safeyolo test -H "Authorization: Bearer sk-test123..." https://api.openai.com/v1/models
# Should return 403 (blocked) with X-Blocked-By header

# Test without credential
safeyolo test https://httpbin.org/get
# Should return 200 (allowed)
```

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
- **Support Python 3.11+** - Addons tested on 3.11, 3.12, 3.13
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
cd cli && pytest tests/ -v

# Check syntax (what CI does)
python -m py_compile addons/*.py
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
