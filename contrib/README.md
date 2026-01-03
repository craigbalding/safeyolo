# SafeYolo Contrib

Example integrations. Copy and adapt for your own use.

## Available Examples

| Directory | Description |
|-----------|-------------|
| `monitors/` | Log monitoring and visualization tools |
| `notifiers/` | Push notifications via ntfy with optional approval buttons |

## The Integration Pattern

SafeYolo integrations work by tailing the JSONL log:

```python
import json
import time

def tail_jsonl(path):
    with open(path) as f:
        f.seek(0, 2)  # Start at end
        while True:
            line = f.readline()
            if line:
                yield json.loads(line)
            else:
                time.sleep(0.1)

for event in tail_jsonl("./safeyolo/logs/safeyolo.jsonl"):
    if event.get("event") == "security.credential":
        if event["data"].get("decision") == "block":
            # Send notification, update dashboard, etc.
            print(f"Blocked: {event['data']}")
```

## Key Events

| Event | When | Key Fields |
|-------|------|------------|
| `security.credential` | Credential detected | `decision`, `rule`, `host`, `fingerprint` |
| `security.ratelimit` | Rate limit hit | `domain`, `retry_after_seconds` |

## Admin API

To modify SafeYolo (add approvals, change modes):

```python
import httpx

resp = httpx.post(
    "http://localhost:9090/admin/policy/default/approve",
    headers={"Authorization": f"Bearer {token}"},
    json={"token_hmac": "abc123...", "hosts": ["api.example.com"]},
)
```

## Contributing

Add your integration in a new directory with a README. Keep it simple.
