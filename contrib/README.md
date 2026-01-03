# SafeYolo Contrib

Community integrations and examples. These are not part of the core SafeYolo package but demonstrate integration patterns.

## Available Integrations

| Directory | Description |
|-----------|-------------|
| `notifiers/` | Push notifications with one-tap approval via ntfy.sh, Pushcut |

## Using Contrib Integrations

Contrib scripts are standalone - copy what you need and adapt to your setup.

```bash
# Example: Run the notifier with approval buttons
export NTFY_TOPIC=https://ntfy.sh/my-safeyolo-alerts
export SAFEYOLO_ADMIN_TOKEN=$(cat ./safeyolo/data/admin_token)

# Terminal 1: Send notifications with [Approve] [Deny] buttons
python contrib/notifiers/notify.py

# Terminal 2: Handle button callbacks -> admin API
python contrib/notifiers/listener.py
```

See [notifiers/README.md](notifiers/README.md) for full setup instructions.

## Building Your Own Integration

SafeYolo integrations follow a simple pattern:

### 1. Tail the JSONL Log

```python
import json
import time
from pathlib import Path

def tail_jsonl(path: Path):
    with open(path) as f:
        f.seek(0, 2)  # Start at end
        while True:
            line = f.readline()
            if line:
                yield json.loads(line)
            else:
                time.sleep(0.1)
```

### 2. Filter for Events You Care About

```python
for event in tail_jsonl(Path("./safeyolo/logs/safeyolo.jsonl")):
    # Credential blocks
    if event.get("event") == "security.credential":
        if event["data"].get("decision") == "block":
            handle_block(event)

    # Rate limits
    if event.get("event") == "security.ratelimit":
        handle_ratelimit(event)
```

### 3. Take Action

```python
def handle_block(event):
    data = event["data"]
    # Send to Slack, Discord, PagerDuty, etc.
    # Update a dashboard
    # Trigger an automation
```

## Event Reference

| Event | When | Key Fields |
|-------|------|------------|
| `security.credential` | Credential detected | `decision`, `rule`, `host`, `fingerprint`, `reason` |
| `security.ratelimit` | Rate limit hit | `domain`, `retry_after_seconds` |
| `security.circuit` | Circuit breaker change | `domain`, `state`, `retry_after_seconds` |
| `traffic.request` | Request logged | `method`, `host`, `path` |
| `traffic.response` | Response logged | `status_code`, `duration_ms` |

See [docs/DEVELOPERS.md](../docs/DEVELOPERS.md) for full event documentation.

## Alternative: Admin API

For integrations that need to modify SafeYolo (not just observe), use the Admin API:

```python
import httpx

API = "http://localhost:9090"
TOKEN = "your-admin-token"

# Get stats
resp = httpx.get(f"{API}/stats", headers={"Authorization": f"Bearer {TOKEN}"})

# Add approval
httpx.post(
    f"{API}/admin/policy/default/approve",
    headers={"Authorization": f"Bearer {TOKEN}"},
    json={"token_hmac": "abc123...", "hosts": ["api.example.com"]}
)
```

## Contributing

1. Create a directory for your integration
2. Include a README explaining setup and usage
3. Follow the patterns shown in existing integrations
4. Submit a PR

Integrations that prove useful may graduate to core features in a future release.
