# SafeYolo Contrib

Example integrations. Copy and adapt for your own use.

## Available Examples

| Entry | Description |
|-------|-------------|
| [macOS Seatbelt SSH account](macos-seatbelt-agent/README.md) | Native login entry, developer policy, tmux, and validation for a dedicated non-admin macOS account |
| `HOST_SCRIPT_GUIDE.md` | How to write host setup scripts for `safeyolo agent configure NAME --host-script FILE` |
| `ROOTFS_SCRIPT_GUIDE.md` | How to prepare custom platform assets for a native installation |
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
| `../proxy/src/bin/safeyolo-coord.rs` | Native Coord client, Model Context Protocol (MCP) adapter, bounded Codex/Pi supervision and checkpoint recovery |
| `codex-coord-supervisor-fake-codex.sh` | Observable no-model Codex substitute for nested supervisor labs |
| `coord-mcp-bootstrap.sh` | Shared idempotent coord MCP staging/registration helper used by the bundled Claude and Codex setup scripts |
| `safeyolo-coord-mcp-launcher.sh` | SafeYolo-owned launcher that restores the current proxy/TLS environment before starting the coord adapter |
| `mise-shell-host-setup.sh` | Minimal BYOA -- drops into an interactive shell with mise ready; install whatever tools you want with `mise use -g ...` |
| `lib/stage-safeyolo-context.sh` | Shared idempotent baseline/skill staging used by the bundled host scripts |
| `lib/stage-coord-native.sh` | Stages the checked Linux native Coord executable and invokes native role/context setup |
| `alpine-minimal/build-alpine-rootfs.sh` | Minimal custom rootfs example -- Alpine Linux via skopeo+umoci+apk |
| `kali-pentest/build-kali-rootfs.sh` | Kali Linux pentest toolkit rootfs (nuclei, httpx, ffuf, sqlmap, ...) |
| `kali-pentest/pentest-tools.md` | Tool reference for the Kali rootfs -- usage, proxy integration notes |

The supervisor owns the bounded Coord attention wait and launches the selected
harness only after actionable canonical work is checkpointed. Codex uses its
Coord MCP adapter for canonical sends; Pi uses its native extension. The
supervisor wait is direct Agent API traffic in both cases.

The normal `@codex` and `@pi` setups stay interactive. Factory snapshots select
the matching `@codex-coord` or `@pi-coord` setup per role. The standalone Codex
form is also available:

Use an installed native product with its matching Linux guest assets. The worker
must have its own adopted Codex login, or explicit external-provider settings.
See [login and role setup](../docs/factories.md#fresh-setup-check-approve-and-run).
Run from a trusted checkout outside the worker's writable shares. Stop the
existing worker before applying the host setup:

```bash
safeyolo agent stop worker
SAFEYOLO_CODEX_COORD_ROOMS=backlog \
SAFEYOLO_CODEX_COORDINATORS=relay \
  safeyolo agent configure worker --host-script "$PWD/contrib/codex-coord-host-setup.sh"
safeyolo agent start worker
```

See [the supervised worker contract](../docs/codex-coord-supervisor.md) before
you enable this mode.

## Agent launchers and explicit supervision

Ordinary `safeyolo agent start NAME` starts the interactive coding agent
in a persistent host tmux session. `--sandbox-only` boots without a harness.
Factories and `@codex-coord` / `@pi-coord` explicitly select the existing
guest-PID-1-owned supervisor; an executable guest entrypoint no longer implies
supervision.

See [agent launchers](../docs/agent-launchers.md) for defaults, per-agent
overrides and attach. Use [the host launcher template](agent-launcher-template.sh)
only when the built-in presets do not cover your workflow. The
[configuration prompt](agent-launcher-prompt.md) helps an operator work with
a coding agent without writing one script per agent.

## Operator evidence and notifications

Use the native `safeyolo logs`, `safeyolo traffic` and `safeyolo approvals`
commands for operator evidence and decisions. The retained
[Mattermost adapter](../docs/coord-mattermost.md) provides Coord notifications
and scoped actions. [Dispatch](../docs/dispatch-generation.md) generates
public output from the approved manifest.

The former Python ntfy notification/action and log-monitor examples are
retired. They are optional examples, with no reached native installer or
launcher consumer. Their ntfy push buttons and custom log summaries are no
longer provided. Native evidence/approval commands and the retained adapters
keep their separate authorities; a network allowance does not grant credential
permission.

## Contributing

Add your integration in a new directory with a README. Keep it simple.
