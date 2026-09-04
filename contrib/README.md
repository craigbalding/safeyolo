# SafeYolo Contrib

Example integrations. Copy and adapt for your own use.

## Available Examples

| Entry | Description |
|-------|-------------|
| `HOST_SCRIPT_GUIDE.md` | How to write host setup scripts for `safeyolo agent add --host-script` |
| `ROOTFS_SCRIPT_GUIDE.md` | How to write custom rootfs builders for `safeyolo agent add --rootfs-script` (replace the default base with any distro) |
| `../docs/AGENTS.md` | Compact always-on agent baseline (environment, guest tools, Agent API health check, security boundaries) |
| `../cli/src/safeyolo/agent_context/skills/safeyolo/` | Shared Codex/Claude skill for guest tool installation, Agent API, flows, service gateway, plumb, block responses, and troubleshooting |
| `../cli/src/safeyolo/agent_context/skills/safeyolo-lab-controller/` | Codex skill and helper scripts for persistent, operator-visible tmux labs |
| `../cli/src/safeyolo/agent_context/skills/safeyolo-factory/` | Codex operator skill for designing, cross-reviewing, proving, and troubleshooting supervised factories |
| `claude-host-setup.sh` | Host setup for Claude Code -- stages auth/extensions and the default coord MCP server, injects the baseline, links `/safeyolo`, and writes an install-on-first-run foreground command |
| `codex-host-setup.sh` | Host setup for OpenAI Codex CLI -- stages user state and the default coord MCP server, injects the baseline, links `$safeyolo`, `$safeyolo-lab-controller`, and `$safeyolo-factory`, installs the `safeyolo-lab` guest command, and writes an install-on-first-run foreground command |
| `codex-coord-host-setup.sh` | Opt-in `@codex-coord` setup for a long-lived factory worker; it uses the normal Codex setup and runs bounded non-interactive turns under the guest-side coord supervisor |
| `codex-coord-supervisor.py` | Event-driven persistent-process supervisor for one Codex thread and bounded atomic Coord recovery state |
| `codex-coord-supervisor-fake-codex.sh` | Observable no-model Codex substitute for nested supervisor labs |
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

The supervisor owns the bounded Coord attention wait and launches Codex only
after actionable canonical work is checkpointed. The bundled Codex coord
registration still sets `tool_timeout_sec = 330` for ordinary Coord tools, but
that MCP timeout is independent of the supervisor wait.

The normal `@codex` setup stays interactive. For a factory worker, set the
receive rooms and the operator-designated coordinators, then select the
separate `@codex-coord` alias:

```bash
SAFEYOLO_CODEX_COORD_ROOMS=backlog \
SAFEYOLO_CODEX_COORDINATORS=relay \
  safeyolo agent run worker --host-script @codex-coord
```

See [the supervised worker contract](../docs/codex-coord-supervisor.md) before
you enable this mode.

## The Integration Pattern

SafeYolo integrations work by tailing the JSONL log:

```python
import json
import os
import time
from pathlib import Path


def tail_jsonl(path):
    with open(path) as f:
        f.seek(0, 2)  # Start at end
        while True:
            line = f.readline()
            if line:
                yield json.loads(line)
            else:
                time.sleep(0.1)

logs_dir = os.environ.get("SAFEYOLO_LOGS_DIR")
if not logs_dir:
    state_home = Path(
        os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")
    )
    logs_dir = state_home / "safeyolo"
log_path = Path(logs_dir) / "safeyolo.jsonl"

for event in tail_jsonl(log_path):
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
