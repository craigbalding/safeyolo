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
| `pi-host-setup.sh` | Host setup for Pi coding agent -- installs `@earendil-works/pi-coding-agent@0.85.0` with a fixed integrity and Node boundary, stages the baseline/shared skill and `repo-map`, and writes an install-on-first-run foreground command |
| `pi-coord-host-setup.sh` | `@pi-coord` factory setup; stages Pi's native Coord `send` tool and runs bounded JSON turns under the common supervisor |
| `pi-coord-extension.ts` | Minimal native Pi adapter for canonical Coord sends using the agent's transport identity |
| `codex-coord-host-setup.sh` | `@codex-coord` setup for a long-lived factory worker; uses the normal Codex setup and runs bounded non-interactive turns under the common supervisor |
| `codex-coord-supervisor.py` | Event-driven supervisor shared by Codex and Pi, with one harness session and bounded atomic Coord recovery state |
| `codex-coord-supervisor-fake-codex.sh` | Observable no-model Codex substitute for nested supervisor labs |
| `coord-mcp-bootstrap.sh` | Shared idempotent coord MCP staging/registration helper used by the bundled Claude and Codex setup scripts |
| `safeyolo-coord-mcp-launcher.sh` | SafeYolo-owned launcher that restores the current proxy/TLS environment before starting the coord adapter |
| `safeyolo-coord-mcp.py` | Standalone coord MCP adapter staged into first-party agent homes by the shared bootstrap |
| `mise-shell-host-setup.sh` | Minimal BYOA -- drops into an interactive shell with mise ready; install whatever tools you want with `mise use -g ...` |
| `lib/stage-safeyolo-context.sh` | Shared idempotent baseline/skill staging used by the bundled host scripts |
| `lib/stage-factory-supervisor.py` | Shared snapshot/role verifier and supervisor-config stager for both factory harnesses |
| `alpine-minimal/build-alpine-rootfs.sh` | Minimal custom rootfs example -- Alpine Linux via skopeo+umoci+apk |
| `kali-pentest/build-kali-rootfs.sh` | Kali Linux pentest toolkit rootfs (nuclei, httpx, ffuf, sqlmap, ...) |
| `kali-pentest/pentest-tools.md` | Tool reference for the Kali rootfs -- usage, proxy integration notes |
| `monitors/` | Log monitoring and visualization tools |
| `notifiers/` | Push notifications via ntfy with optional approval buttons |

The supervisor owns the bounded Coord attention wait and launches the selected
harness only after actionable canonical work is checkpointed. Codex uses its
Coord MCP adapter for canonical sends; Pi uses its native extension. The
supervisor wait is direct Agent API traffic in both cases.

The normal `@codex` and `@pi` setups stay interactive. Factory snapshots select
the matching `@codex-coord` or `@pi-coord` setup per role. The standalone Codex
form is also available:

```bash
SAFEYOLO_CODEX_COORD_ROOMS=backlog \
SAFEYOLO_CODEX_COORDINATORS=relay \
  safeyolo agent run worker --host-script @codex-coord
```

See [the supervised worker contract](../docs/codex-coord-supervisor.md) before
you enable this mode.

## Detached command supervision

`safeyolo agent run <name> --detach` with a configured
`$SAFEYOLO_AGENT_HOME/.safeyolo-command` publishes the command to a runtime
supervisor owned by guest PID 1. It restarts every unexpected command exit,
including a clean exit, with bounded backoff and resets the crash-loop window
after a stable run. It records exit classification, byte-counted/truncated
stderr, a digest, and a sanitized tail, and exposes `running`, `restarting`,
`failed`, and `stopped` through `safeyolo agent diag` and `safeyolo status`. It
never restarts the sandbox and is independent of the Coord event room. `safeyolo
agent stop` records durable stop intent before sandbox cleanup, fencing restart.

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
