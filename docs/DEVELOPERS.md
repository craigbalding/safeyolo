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
│  │  - init      │  :9090        │ rate_limiter.py      │    │
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
- Proxy addon is slim (~750 lines) and focused on detect/decide/emit
- CLI handles user interaction, approval workflow, notifications
- Communication via Admin API (HTTP) and JSONL logs (file)
- Policy files are the source of truth for approvals

## Repository Structure

```
safeyolo/
├── addons/                  # mitmproxy addons (run in container)
│   ├── credential_guard.py  # Core credential detection
│   ├── rate_limiter.py      # Per-domain rate limiting
│   ├── circuit_breaker.py   # Fail-fast for unhealthy upstreams
│   ├── pattern_scanner.py   # Regex pattern matching
│   ├── admin_api.py         # REST API for control
│   ├── request_logger.py    # JSONL audit logging
│   ├── metrics.py           # Statistics collection
│   ├── utils.py             # Shared utilities
│   └── ...
├── cli/                     # safeyolo CLI (runs on host)
│   ├── src/safeyolo/
│   │   ├── cli.py           # Typer app entry point
│   │   ├── config.py        # Configuration loading
│   │   ├── api.py           # Admin API client
│   │   ├── docker.py        # Container management
│   │   └── commands/        # CLI commands
│   └── pyproject.toml
├── config/                  # Default configurations
├── tests/                   # Test suite
└── docs/                    # Documentation
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
| GET | `/health` | Health check (no auth) |
| GET | `/stats` | Aggregated addon stats |
| GET | `/modes` | Current addon modes |
| PUT | `/modes` | Set all addon modes |
| PUT | `/plugins/{addon}/mode` | Set specific addon mode |
| GET | `/admin/policies` | List policy files |
| GET | `/admin/policy/{project}` | Get project policy |
| PUT | `/admin/policy/{project}` | Write project policy |
| POST | `/admin/policy/{project}/approve` | Add approval rule |

**Add an approval via API:**
```bash
curl -X POST "http://localhost:9090/admin/policy/default/approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token_hmac": "a1b2c3d4e5f6...",
    "hosts": ["api.example.com"],
    "paths": ["/**"],
    "name": "My API key"
  }'
```

**Python client:**
```python
from safeyolo.api import AdminAPI

api = AdminAPI(base_url="http://localhost:9090", token="...")

# Get stats
stats = api.stats()
print(stats["credential-guard"]["violations_total"])

# Add approval
api.add_approval(
    project="default",
    token_hmac="a1b2c3d4e5f6...",
    hosts=["api.example.com"]
)

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
safeyolo test -H "Authorization: Bearer sk-fake123..." https://httpbin.org/get
# Should return 428 (blocked)
```

## Contributing

1. **Fork and clone** the repository
2. **Create a branch** for your feature/fix
3. **Write tests** for new functionality
4. **Run tests** to ensure nothing breaks
5. **Submit a PR** with a clear description

**Areas for contribution:**
- New credential patterns for additional providers
- Notification backends (Slack, Discord, email)
- CLI improvements
- Documentation
- Test coverage

## Example Integrations

The `contrib/` directory contains example integrations you can use as templates:

| Integration | Description |
|-------------|-------------|
| `contrib/notifiers/` | Push notifications via ntfy.sh, Pushcut |

See [contrib/README.md](../contrib/README.md) for the integration pattern and how to build your own.

**Ideas for new integrations:**
- **Slack/Discord bot** - Post blocked credentials to a channel
- **Dashboard** - Real-time visualization of proxy traffic
- **Metrics exporter** - Push to Prometheus/Grafana
- **CI integration** - Block builds if credentials leak in tests
- **IDE plugin** - Show SafeYolo status in VS Code

## Questions?

Open an issue on GitHub or reach out to the maintainers.
