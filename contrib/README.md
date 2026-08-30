# SafeYolo Contrib

Example integrations. Copy and adapt for your own use.

## Available Examples

| Entry | Description |
|-------|-------------|
| `HOST_SCRIPT_GUIDE.md` | How to write host setup scripts for `safeyolo agent add --host-script` |
| `ROOTFS_SCRIPT_GUIDE.md` | How to write custom rootfs builders for `safeyolo agent add --rootfs-script` (replace the default base with any distro) |
| `../docs/AGENTS.md` | Compact always-on agent baseline (environment, guest tools, Agent API health check, security boundaries) |
| `skills/safeyolo/` | Shared Codex/Claude skill for guest tool installation, Agent API, flows, service gateway, plumb, block responses, and troubleshooting |
| `claude-host-setup.sh` | Host setup for Claude Code -- stages auth/extensions and the default coord MCP server, injects the baseline, links `/safeyolo`, and writes an install-on-first-run foreground command |
| `codex-host-setup.sh` | Host setup for OpenAI Codex CLI -- stages user state and the default coord MCP server, injects the baseline, links `$safeyolo`, and writes an install-on-first-run foreground command |
| `coord-mcp-bootstrap.sh` | Shared idempotent coord MCP staging/registration helper used by the bundled Claude and Codex setup scripts |
| `safeyolo-coord-mcp-launcher.sh` | SafeYolo-owned launcher that restores the current proxy/TLS environment before starting the coord adapter |
| `safeyolo-coord-mcp.py` | Standalone coord MCP adapter staged into first-party agent homes by the shared bootstrap |
| `mise-shell-host-setup.sh` | Minimal BYOA -- drops into an interactive shell with mise ready; install whatever tools you want with `mise use -g ...` |
| `lib/stage-safeyolo-context.sh` | Shared idempotent baseline/skill staging used by the bundled host scripts |
| `alpine-minimal/build-alpine-rootfs.sh` | Minimal custom rootfs example -- Alpine Linux via skopeo+umoci+apk |
| `kali-pentest/build-kali-rootfs.sh` | Kali Linux pentest toolkit rootfs (nuclei, httpx, ffuf, sqlmap, ...) |
| `kali-pentest/pentest-tools.md` | Tool reference for the Kali rootfs -- usage, proxy integration notes |
| `monitors/` | Log monitoring and visualization tools |
| `notifiers/` | Push notifications via ntfy with optional approval buttons |

The bundled Codex coord registration sets `tool_timeout_sec = 330`. SafeYolo
allows a foreground `wait_for_coord` call to wait for at most 300 seconds, so
the Codex MCP deadline must stay strictly higher. The 30-second margin lets the
adapter resolve the returned page and deliver its adoptable cursor after a
full idle wait. Change these coupled bounds together; do not shorten the coord
wait to fit a harness timeout.

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
