# SafeYolo

[![CI](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/craigbalding/safeyolo/badge)](https://scorecard.dev/viewer/?uri=github.com/craigbalding/safeyolo)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11693/badge)](https://www.bestpractices.dev/projects/11693)
[![CodeQL](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml)

**Want your AI agents to do more without giving them access to more?**

SafeYolo gives coding agents room to work without handing them your desktop,
vaulted service credentials, or unrestricted access to your network and
third-party services.

Give the agent guest-local root. Let it install tools, run browsers, start
services, and debug code within the scope you choose. SafeYolo contains those
actions inside the sandbox while preserving ordinary development tools.

SafeYolo does not replace external systems with a small set of approved tools.
Agents can use normal command-line interfaces (CLIs), software development kits
(SDKs), browsers, and web services. SafeYolo controls which destinations and
service capabilities the agent can reach. Its service gateway keeps vaulted
credentials on the host and injects them only into authorized requests.

Coding-harness authentication is a separate, explicit path. The bundled Claude
Code and Codex host scripts copy the operator's subscription state into the
agent's persistent `/home/agent`. The agent process can read and use those
copies. Use a host script only when that trust decision is acceptable.

Each agent runs in an isolated Linux sandbox — hardware-backed microVM on macOS, gVisor on Linux — with network traffic forced through a programmable [mitmproxy](https://mitmproxy.org/) policy layer.

**You steer. Your agents get on with the job.**

Works with Claude Code, OpenAI Codex, or whatever agent you want to run.

Built on the fantastic [mitmproxy](https://mitmproxy.org/) project. MicroVM patterns informed by [Shuru](https://github.com/superhq-ai/shuru/).

> [!NOTE]
> **SafeYolo is pre-v1.** Distribution via PyPI / brew is on the roadmap; today the install is a `git clone` + four short commands. See "Install from source" further down if you want to run the individual `init`/`build`/`setup` steps by hand.

## Quick Start

### Prerequisites

- macOS with Apple Silicon (M1+) **or** Linux (x86_64/arm64)
- Python 3.12 or 3.13
- [uv](https://docs.astral.sh/uv/) — the Python package/project manager SafeYolo uses. Grab it from your distro's package manager or the upstream installer.
- macOS only: [Lima](https://lima-vm.io/) for the guest image build (`brew install lima`, `sudo port install lima`, or `mise use -g lima`).
- Linux (apt-based): `safeyolo bootstrap` installs gVisor `runsc`, `uidmap`, `acl`, and other build prereqs via apt. On non-apt distros install gVisor first per its [upstream instructions](https://gvisor.dev/).
- Linux SafeYolo can also run inside an outer SafeYolo agent as a disposable
  proxy-only integration lab; see [SafeYolo-in-SafeYolo](docs/nested-linux-lab.md).

### Install

```bash
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo
./install.sh
safeyolo bootstrap
```

`./install.sh` puts `safeyolo` on your `PATH` at `~/.local/bin/safeyolo`.
`safeyolo bootstrap` initializes configuration, builds the platform-specific
guest artifacts, and applies host prerequisites. The command is idempotent.

If a Linux build prerequisite is missing, `safeyolo bootstrap` prints one
`sudo apt-get install ...` command and exits without using `sudo`. The operator
decides whether to run that command. Use `safeyolo bootstrap --json` for
machine-readable continuous-integration (CI) or acceptance-harness output.

_macOS only_ — one additional step to build the Swift VM helper:

```bash
cd vm && make install && cd ..
```

### Run your first agent

```bash
safeyolo agent add work ~/code --host-script @claude
safeyolo agent run work
```

`~/code` is the project directory mounted read-write at `/workspace`. The
`@claude` argument selects a bundled host-script alias.

| Alias | Guest setup |
|---|---|
| `@claude` | Claude Code plus the coord Model Context Protocol (MCP) adapter. |
| `@codex` | Interactive OpenAI Codex CLI plus the coord MCP adapter. |
| `@codex-coord` | Opt-in supervised Codex factory worker. |
| `@mise-shell` | Interactive shell with mise. |

You can also pass the path of any executable host script.

Inside the sandbox:

- **All traffic routes through SafeYolo proxy** — the sandbox has no external network interface; the only path out is through the proxy
- **Credentials in proxied requests are guarded** — detected credentials can
  reach only destinations that policy permits. This guard does not hide files
  that a host script intentionally copies into `/home/agent`.
- **Security decisions are logged** — structured JSON Lines (JSONL) records are
  available for review.
- **Development state persists** — agents install toolchains through mise, and
  the persistent home survives restarts.
- **Linux agents run rootless** — `safeyolo agent run` is zero-sudo; `bootstrap` applies a one-time AppArmor profile and a KVM udev rule so ongoing operation needs no elevated privileges

### Verify isolation

From inside the agent:

```bash
# This works (routed through proxy):
curl https://httpbin.org/ip

# This is blocked (no external network interface — nothing to route through):
curl --noproxy '*' https://ifconfig.co
# Error: Could not resolve host
```

### Health check

```bash
safeyolo doctor              # rich console
safeyolo doctor --raw        # no color / no wrap (grep-friendly)
safeyolo doctor --json | jq  # machine-parseable single JSON object
```

On Linux, the command reports the `runsc` version, the selected KVM or systrap
isolation platform and its reason, user-namespace prerequisites, the guest
rootfs tree, and running agents. On macOS, it confirms Apple Silicon and the
`safeyolo-vm` helper. The command exits nonzero if any check fails.

### Install from source (advanced)

`safeyolo bootstrap` wraps three commands: `safeyolo init`, `safeyolo build`,
and `safeyolo setup`. Run them individually when you want to inspect or retry
one phase:

```bash
# Linux only: install build prereqs up front (bootstrap prints the list for you;
# doing it manually here means bootstrap has nothing left to name).
sudo apt-get install -y skopeo umoci mmdebstrap debootstrap acl jq curl

./install.sh        # or: uv tool install --editable . --overrides <(printf '%s\n' \
                    #      'flask>=3.1.3' 'pygments>=2.20.0' 'cryptography>=50.0.0' \
                    #      'msgpack>=1.2.1' 'pyopenssl>=26.0.0' 'tornado>=6.5.5')

safeyolo init       # writes ~/.safeyolo/{policy.toml, addons.yaml, tokens, ...}
safeyolo build      # builds + installs the guest rootfs into ~/.safeyolo/share/
safeyolo setup      # applies AppArmor profile + /dev/kvm ACL (Linux; sudo prompt)
```

End-state is identical to `./install.sh && safeyolo bootstrap`. Also useful when troubleshooting: any individual command can be re-run in isolation; each is idempotent.

If `mitmdump` ends up missing from SafeYolo's tool environment (rare), fall back to pipx:

```bash
./scripts/install-mitmproxy-pipx.sh
```

That pipx-installs `mitmproxy` and injects the exact addon-deps SafeYolo needs.

## How It Works

Each agent runs in an isolated Linux sandbox with **no external network interface**. The only egress path is a per-agent socket bound to a host-side bridge, which routes through SafeYolo's mitmproxy:

```
Agent sandbox (loopback-only; no eth0)
    │
    │  HTTP_PROXY → in-guest forwarder → Unix domain socket (AF_UNIX)
    │                                  or virtual socket (AF_VSOCK)
    ▼
Per-agent bridge socket (one per agent, host-owned)
    │
    │  bridge connects on a per-agent port;
    │  mitmproxy attributes every request to the right agent
    ▼
SafeYolo mitmproxy (host process)
    │  policy, credential guard, rate limits, audit
    ▼
Internet
```

On macOS, the sandbox is a hardware-backed microVM that uses Apple
Virtualization.framework and virtual sockets. On Linux, it is a rootless gVisor
container that runs `runsc` in an unprivileged user namespace with
`--network=sandbox` and `--host-uds=open`.

Both platforms omit an external network interface. Unsetting the proxy
variables therefore does not create another egress path. Raw external TCP has
no interface, and external Domain Name System (DNS) resolution has no reachable
resolver. **The egress boundary is structural:** it does not depend on host
firewall rules.

Agent identity uses a per-agent Unix domain socket (UDS) on both platforms.
Each agent connects to the host-owned `<ip>_<agent>/proxy.sock`. At bind time,
mitmproxy's `UnixMode` listener parses that path and stamps
`client.peername = (ip, 0)` on every accepted connection. SafeYolo uses no
per-agent `lo0` aliases and no host `sudo` at runtime.

See [docs/networking-vsock-uds.md](docs/networking-vsock-uds.md) for hop-by-hop detail, attribution mechanics, log correlation, and troubleshooting.

## Key Features

- **One-command agent setup** — host scripts configure Claude Code, OpenAI Codex, or your own agent; `mise-shell-host-setup.sh` gives you a ready sandbox for anything else
- **Strong isolation** — each agent gets its own sandbox: a hardware-backed Linux microVM on macOS, rootless gVisor on Linux
- **Structural egress control** — sandboxes have no external network interface; the only path out is a per-agent host socket through SafeYolo. No firewall rules to bypass or misconfigure.
- **Safe browser and desktop previews** — agents can run browsers, graphical tools and the webapps they are building inside the sandbox, while giving the operator a safe window onto the result without exposing the host
- **First-class traffic inspection** — inspect each agent's live HTTP(S) traffic through mitmproxy's web interface; particularly useful for debugging, QA and security testing against remote applications and APIs
- **Operator access from anywhere over Tailscale** — if you use Tailscale, publish the traffic-inspection UI and agent previews to your tailnet so you can review, approve or debug from any device without exposing anything to the public internet
- **Scoped network access** — allow, deny, prompt or rate-limit access by host, with per-agent overrides and a global traffic budget
- **Capability-scoped service access** — give an agent only the operations it needs against services such as Gmail or GitHub; risky routes can require explicit approval
- **Vaulted service credentials stay outside the sandbox** — the service
  gateway injects them only into authorized requests, and credential guards
  stop detected secrets from reaching the wrong destination. Host scripts can
  separately copy coding-harness authentication into the sandbox.
- **Human-in-the-loop where it matters** — new egress, credential use and risky service actions can stop for approval in `safeyolo watch`, rather than interrupting the agent for routine work
- **Runaway protection** — rate budgets, circuit breakers and loop detection contain broken retry loops before they hammer an API, fill logs or damage your IP reputation
- **Agent-visible guardrails** — agents can inspect their own policy, budgets, available capabilities and block reasons, then self-correct instead of guessing
- **Traffic evidence and audit trail** — correlated audit events and queryable HTTP flow recording preserve what actually happened, including test context for QA and security workflows
- **Productive sandboxes** — toolchains, shell history and agent state persist; agents get a real PTY, guest-local root for package installs, and useful in-sandbox debugging
- **Bring your own environment** — use the standard dev image or build and clone custom environments such as Kali or Alpine

## Multiple Agents

Run multiple agents with separate policies and isolated networks:

```bash
safeyolo agent add work         ~/work           --host-script contrib/claude-host-setup.sh
safeyolo agent add side-project ~/side-project   --host-script contrib/claude-host-setup.sh
safeyolo agent add codex        ~/experiments    --host-script contrib/codex-host-setup.sh

safeyolo agent run work       # Each agent gets its own isolated sandbox
```

The folder chosen by `agent add` is the persistent host folder mounted at
`/workspace`. Change it without recreating the agent or rerunning its host setup:

```bash
safeyolo agent config work --folder ~/new-work
safeyolo agent stop work      # required only if it is currently running
safeyolo agent run work
```

Relative paths and `~` are normalized before they are saved, and the folder
must already exist and be owned by you. Use `--dangerously-allow-unowned` only
when that ownership mismatch is intentional. A running sandbox keeps its
current `/workspace` until stop/restart. In contrast, the `--folder` option on
`agent run` overrides `/workspace` for that run only and does not change the
saved folder.

Agents can collaborate through SafeYolo's retained coord rooms. Operators who
run that message plane should use the [coord operations
runbook](docs/coord-operations.md) for its managed NATS credential lifecycle,
safe manual rotation, health checks, and history-preservation procedure.
For an optional mobile-facing projection, see the
[Mattermost coord operator adapter](docs/coord-mattermost.md). Coord remains
authoritative; the Mattermost bot is only a presentation/input adapter.

## Host scripts

`safeyolo agent add` accepts an optional `--host-script PATH`. Before the
sandbox boots, SafeYolo runs the script on the host with the operator's user
permissions. The script can copy authentication, settings, and extensions into
the agent's persistent home at `~/.safeyolo/agents/<name>/home/`. Files copied
there are mounted at `/home/agent` and are readable by the agent process. The
script also writes `.safeyolo-command`, which becomes the default foreground
command in the guest.

For an existing agent, reapply or change the setup with
`safeyolo agent run <name> --host-script PATH`.

The `contrib/` directory has ready-made host scripts:

| Script | Purpose |
|--------|---------|
| `contrib/claude-host-setup.sh` | Copies Claude Code authentication and selected user extensions into `/home/agent`, registers the coord MCP adapter, installs SafeYolo context, and launches Claude Code. |
| `contrib/codex-host-setup.sh` | Copies `~/.codex/` into `/home/agent`, registers the coord MCP adapter, installs SafeYolo context including `$safeyolo-lab-controller` and the `safeyolo-lab` guest command, and launches Codex with its inner sandbox disabled (`-s danger-full-access -a never`). SafeYolo remains the outer boundary. |
| `contrib/codex-coord-host-setup.sh` | Uses the Codex setup above, including copied subscription authentication, then supervises bounded non-interactive turns. See the [supervisor contract](docs/codex-coord-supervisor.md). |
| `contrib/mise-shell-host-setup.sh` | Opens an interactive shell with mise ready for `mise use -g ...`. |

Without `--host-script`, the sandbox boots to an interactive bash shell in a per-agent persistent home.

Writing your own: see [`contrib/HOST_SCRIPT_GUIDE.md`](contrib/HOST_SCRIPT_GUIDE.md).

The Codex setup includes an inspectable tmux lab for experiments that benefit
from persistent shells, visible output, and operator control. Enter the agent,
then run one command from the guest shell at `/home/agent`:

```bash
safeyolo agent shell codex
# Inside the guest:
safeyolo-lab
```

The guest tmux prefix is `C-a`. Run `safeyolo-lab` again after a disconnect to
attach to the existing lab. The controller first asks what you want to explore;
it does not create experiment panes until you describe the work.

## Custom rootfs

`safeyolo agent add` also takes an optional `--rootfs-script PATH` for agents that need a different base system than SafeYolo's default Debian-trixie rootfs — e.g. Kali for a pentest agent or Alpine for a minimal shell. The script builds a full per-agent rootfs from any distribution's Open Container Initiative (OCI) image or bootstrap tarball. Examples: [`contrib/kali-pentest/build-kali-rootfs.sh`](contrib/kali-pentest/build-kali-rootfs.sh), [`contrib/alpine-minimal/build-alpine-rootfs.sh`](contrib/alpine-minimal/build-alpine-rootfs.sh). Writing your own: see [`contrib/ROOTFS_SCRIPT_GUIDE.md`](contrib/ROOTFS_SCRIPT_GUIDE.md).

The default Debian base is intentionally small. It includes common search and
debugging tools (`ripgrep`, `fd-find`, `file`, `unzip`, `zip`, `tmux`, `lsof`,
`strace`, `jq`, `less`), Python virtual-environment support, and BusyBox-backed
`nc` and `hexdump` shims. Install language runtimes through `mise`; the base
rootfs does not include them.

SafeYolo splits agent guidance by when it is needed. The compact, always-on
baseline at [`docs/AGENTS.md`](docs/AGENTS.md) covers environment invariants,
the correct Agent API health check, and security boundaries. Detailed Agent
API, flow, gateway, `plumb`, block-response, and troubleshooting workflows live
in one progressively disclosed [`safeyolo` skill](cli/src/safeyolo/agent_context/skills/safeyolo/SKILL.md).

The bundled host scripts stage the baseline under `~/.safeyolo/`. Claude
receives it through `--append-system-prompt`; Codex receives it as
`developer_instructions`. Bundled skills are refreshed in the read-only
`/safeyolo` share on every run. The scripts link the applicable managed skills
into each agent's native skill directory, leaving existing user instructions
untouched. Both integrations get the operational `safeyolo` skill. Codex also
gets the `safeyolo-lab-controller` skill and the `safeyolo-lab` command.

## Controlling Agent Access

Grant agents specific capabilities for specific services. Credentials managed
by this service-gateway path stay in SafeYolo's vault. Agents make requests,
and SafeYolo injects the vaulted credential after authorization. This guarantee
does not apply to coding-harness authentication copied by a host script.

```bash
safeyolo agent authorize boris gmail --capability read_agent_folder --token-env GMAIL_TOKEN
```

`safeyolo watch` is your real-time control surface. When an agent needs access to a service, you see it here:

```
$ safeyolo watch

╭─ boris requests authenticated access 14:32:15 ────────────╮
│ Service      gmail                                        │
│ Capability   read_agent_folder                             │
│                                                           │
│ This will permanently bind a credential to this agent.    │
├───────────────────────────────────────────────────────────┤
│ [A]uthorize · [D]eny · [L]ater                            │
╰───────────────────────────────────────────────────────────╯
```

**Try it yourself:** Run `safeyolo demo` for a guided tour, with `safeyolo watch` in a second terminal.

## Architecture

The current [architecture overview](docs/ARCHITECTURE.md) describes the shared
system. The [macOS microVM](docs/microvm-architecture.md) and [historical Linux
port](docs/linux-port-design.md) documents preserve platform design context.
Current highlights common to both paths:

- **Networking**: no external interface in the sandbox — egress is UDS/vsock to a per-agent host socket → proxy bridge → mitmproxy (structural isolation)
- **Terminal**: full PTY with resize — vsock PTY bridge on macOS, `runsc exec` on Linux
- **Guest init**: served from a writable status share + read-only config share (changes without rootfs rebuild)
- **Identity**: per-agent Unix domain socket at `<ip>_<agent>/proxy.sock` — mitmproxy's `UnixMode` parses the path at bind and stamps `client.peername = (ip, 0)` on every accepted connection

Linux specifics:

- **Rootless host operation**: runsc runs in an unprivileged user namespace (`unshare -Un` + `newuidmap`/`newgidmap`) and launching agents requires no host sudo. Agents start as uid 1000; in-guest `sudo` may enter sandbox uid 0 for ephemeral package installs. That identity maps to subordinate host uid 100000, while container uid 1000 maps to the operator.
- **Rootfs**: a single shared directory tree at
  `~/.safeyolo/share/rootfs-tree/` is the gVisor OCI `root.path`; Linux does
  not package it as an image. By default, writes
  go to a per-agent file-backed overlay and persist across stop and run.
  `--ephemeral` selects a memory-backed overlay whose rootfs writes are
  discarded on stop. Per-agent package-cache bind mounts keep reinstalls cheap.
- **Isolation platform**: KVM (hardware-enforced) if available; systrap (seccomp-BPF) fallback otherwise. Auto-detected by `safeyolo setup` and surfaced in `safeyolo doctor`.
- **One-time setup**: AppArmor profile to allow unprivileged user namespaces on Ubuntu 24.04+, and a udev rule granting the subordinate uid access to `/dev/kvm` — both applied idempotently by `safeyolo setup`.

## Trust Model

**What SafeYolo does NOT do:**
- Eliminate prompt injection — but it constrains the blast radius
- Defend against determined adversaries with host code execution
- Replace application-layer auth

See [SECURITY.md](SECURITY.md) for the full security model, trust boundaries, and enforcement details.

## Requirements

- macOS Apple Silicon (M1+) **or** Linux (x86_64/arm64)
- Python 3.12 or 3.13 with [uv](https://docs.astral.sh/uv/)
- macOS only: Lima (build-time, for the guest image) — install via `brew install lima`, `sudo port install lima`, or `mise use -g lima`
- Linux only: gVisor `runsc` (VM runtime) — see the Build section above for the install command; plus `newuidmap`/`newgidmap` (from `uidmap` on Debian/Ubuntu) and a subuid/subgid range for the operator. `safeyolo setup` verifies all of this.

Run `safeyolo setup` to check and apply one-time prerequisites, then `safeyolo doctor` any time to see the current state of runtime, isolation platform, user namespaces, guest images, and running agents.

## Status

SafeYolo is **pre-v1**. Sandbox runtime is hardware-backed microVMs on macOS and rootless gVisor on Linux.

## Documentation

- [MicroVM Architecture](docs/microvm-architecture.md)
- [Agent Networking (vsock/UDS)](docs/networking-vsock-uds.md)
- [Configuration](docs/CONFIGURATION.md)
- [Mattermost Coord Adapter](docs/coord-mattermost.md)
- [Coord Completion Notes](docs/coord-completion-notes.md)
- [Relay Factory Proposals](docs/factory-proposals.md)
- [SafeYolo Dispatch Generation](docs/dispatch-generation.md)
- [Architecture & Addons](docs/ADDONS.md)
- [Security & Threat Model](SECURITY.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
