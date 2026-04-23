# SafeYolo

[![CI](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/craigbalding/safeyolo/badge)](https://scorecard.dev/viewer/?uri=github.com/craigbalding/safeyolo)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11693/badge)](https://www.bestpractices.dev/projects/11693)
[![CodeQL](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml)

**Don't slow your agents down, just scope their access.**

SafeYolo is a security proxy that gives operators scoped control over what AI agents can access. Agents run in isolated Linux sandboxes — hardware-backed microVMs on macOS, gVisor on Linux — with enforced network egress control that the agent cannot bypass.

Built on the fantastic [mitmproxy](https://mitmproxy.org/) project. MicroVM patterns informed by [Shuru](https://github.com/superhq-ai/shuru/).

> [!NOTE]
> **SafeYolo is pre-v1.** The install below is deliberately step-by-step so you can see exactly what gets built on your machine. A one-command installer lands with v1.

## Quick Start

### Prerequisites

- macOS with Apple Silicon (M1+) **or** Linux (x86_64/arm64)
- Python 3.12+ with [uv](https://docs.astral.sh/uv/)
- macOS only: [Lima](https://lima-vm.io/) for the guest image build — `brew install lima`
- Linux only: [gVisor (`runsc`)](https://gvisor.dev/) as the VM runtime — install command below

### Build

```bash
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo

# Build guest VM images (kernel, initramfs, rootfs) — one-time, ~10 min.
# On macOS this auto-shells into a Lima VM; on Linux it runs natively via
# skopeo+umoci pulling the debian:trixie OCI image. See guest/README.md
# for platform-specific setup notes.
#   Linux build prerequisite: sudo apt-get install skopeo umoci e2fsprogs erofs-utils curl
cd guest && ./build-all.sh && cd ..
mkdir -p ~/.safeyolo/share && cp guest/out/* ~/.safeyolo/share/

# Install the `safeyolo` CLI onto your PATH (survives shell restarts).
# Requires `uv` (https://docs.astral.sh/uv/).
uv tool install ./cli
```

`uv tool install` puts `safeyolo` in `~/.local/bin/safeyolo`. Make sure that directory is on your `PATH` (uv will tell you if it isn't). To pick up upstream changes later: `uv tool install --reinstall ./cli`.

**Then, one platform-specific step:**

_macOS_ — build the Swift VM helper and its guest-side companion binaries:

```bash
cd vm && make install && cd ..
```

_Linux_ — install gVisor (`runsc`) as the VM runtime. The `vm/` directory is macOS-only and is not used here:

```bash
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc
```

If `uv sync --all-packages` did not install `mitmproxy` into the workspace venv (Python 3.12 resolution can drop it), fall back to pipx with the addon dependencies injected:

```bash
./scripts/install-mitmproxy-pipx.sh
```

### Run

```bash
# One-time config bootstrap — writes ~/.safeyolo/policy.toml (the baseline
# policy), addons.yaml, an admin token, and the certs/data/lists directories.
safeyolo init

# Check and apply any host-level prerequisites (Linux: AppArmor profile
# for user namespaces, /dev/kvm udev rule for hardware isolation).
# Safe to re-run; idempotent. No effect on macOS.
safeyolo setup

# Start the proxy
safeyolo start

# Run Claude Code in an isolated sandbox
safeyolo agent add myproject ~/code --host-script contrib/claude-host-setup.sh
```

The last argument (`~/code`) is your project directory — mounted read-write into the sandbox (VirtioFS on macOS, bind mount on Linux). The agent runs in an isolated Linux sandbox where:

- **All traffic routes through SafeYolo proxy** — the sandbox has no external network interface; the only path out is through the proxy
- **API keys are protected** — credentials only reach their intended hosts
- **Everything is logged** — JSONL audit trail for review
- **Dev-ready VMs** — agents install toolchains via mise, state persists across restarts
- **Linux agents run rootless** — `safeyolo agent run` is zero-sudo; setup applies a one-time AppArmor profile and a KVM udev rule so ongoing operation needs no elevated privileges

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
safeyolo doctor
```

On Linux this reports the sandbox runtime (runsc version), isolation platform (KVM vs systrap and why), user-namespace prerequisites (newuidmap, subuid, AppArmor profile), the guest image, and any running agents. On macOS it confirms Apple Silicon + the safeyolo-vm helper.

## How It Works

Each agent runs in an isolated Linux sandbox with **no external network interface**. The only egress path is a per-agent socket bound to a host-side bridge, which routes through SafeYolo's mitmproxy:

```
Agent sandbox (loopback-only; no eth0)
    │
    │  HTTP_PROXY → in-guest forwarder → AF_UNIX or AF_VSOCK
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

The sandbox itself is a hardware-backed microVM on macOS (Apple Virtualization.framework + vsock) and a rootless gVisor container on Linux (runsc in an unprivileged user namespace, with `--network=sandbox` and `--host-uds=open`). Either way: if the agent unsets proxy vars → no effect, because there is no other network path. Raw TCP → impossible (no external interface). DNS → no resolver reachable (no external interface). **Enforcement is structural, not policy-based** — there are no firewall rules to misconfigure; there's simply nowhere else for traffic to go.

Agent identity is cross-platform via PROXY protocol v2 — the host bridge stamps every upstream connection with the agent's attribution IP, and mitmproxy's `next_layer` hook resolves it. No per-agent lo0 aliases, no sudo at runtime.

See [docs/networking-vsock-uds.md](docs/networking-vsock-uds.md) for hop-by-hop detail, attribution mechanics, log correlation, and troubleshooting.

## Key Features

- **One-command agent setup** — host scripts in `contrib/` install and configure Claude Code, OpenAI Codex, or any tool of your choice; a minimal `mise-shell-host-setup.sh` drops you into a ready sandbox for BYO agents
- **Strong isolation** — each agent in its own sandbox: hardware-backed microVM on macOS, gVisor on Linux
- **Structural egress control** — sandbox has no external network interface; the only path out is a per-agent host socket routed through the proxy. No firewall rules to misconfigure.
- **Scoped API access** — grant agents specific capabilities per service
- **Credential isolation** — agents access your services without seeing your keys
- **Human-in-the-loop** — risky actions need approval via `safeyolo watch`
- **Rate limiting** — prevent runaway loops from harming your IP reputation
- **Audit trail** — every request logged with decisions and correlation
- **Persistent sandboxes** — mise installs, shell history, agent state survive restarts
- **Proper terminal** — full PTY with resize support (vsock bridge on macOS, `runsc exec` on Linux)

## Multiple Agents

Run multiple agents with separate policies and isolated networks:

```bash
safeyolo agent add work         ~/work           --host-script contrib/claude-host-setup.sh
safeyolo agent add side-project ~/side-project   --host-script contrib/claude-host-setup.sh
safeyolo agent add codex        ~/experiments    --host-script contrib/codex-host-setup.sh

safeyolo agent run work       # Each agent gets its own isolated sandbox
```

## Host scripts

`safeyolo agent add` takes an optional `--host-script PATH`. The script runs on the host, as you, before the sandbox boots. It populates the agent's persistent home (`~/.safeyolo/agents/<name>/home/`) with whatever the agent needs — credentials, settings, user extensions — and writes a `.safeyolo-command` file the guest execs as the default foreground command.

The `contrib/` directory has ready-made host scripts:

| Script | Purpose |
|--------|---------|
| `contrib/claude-host-setup.sh` | Claude Code — stages host `~/.claude/` auth + user extensions, installs claude-code via mise on first boot, launches nag-free |
| `contrib/codex-host-setup.sh` | OpenAI Codex CLI — stages `~/.codex/`, installs codex via mise on first boot, launches with sandboxing disabled inside the guest (`-s danger-full-access -a never`) while SafeYolo remains the outer boundary |
| `contrib/mise-shell-host-setup.sh` | BYOA — boots into an interactive shell with mise ready; install whatever tools you want with `mise use -g ...` |

Without `--host-script`, the sandbox boots to an interactive bash shell in a per-agent persistent home.

Writing your own: see [`contrib/HOST_SCRIPT_GUIDE.md`](contrib/HOST_SCRIPT_GUIDE.md).

## Custom rootfs

`safeyolo agent add` also takes an optional `--rootfs-script PATH` for agents that need a different base system than SafeYolo's default Debian-trixie rootfs — e.g. Kali for a pentest agent or Alpine for a minimal shell. The script builds a full per-agent rootfs from any distro's OCI image or bootstrap tarball. Examples: [`contrib/kali-pentest/build-kali-rootfs.sh`](contrib/kali-pentest/build-kali-rootfs.sh), [`contrib/alpine-minimal/build-alpine-rootfs.sh`](contrib/alpine-minimal/build-alpine-rootfs.sh). Writing your own: see [`contrib/ROOTFS_SCRIPT_GUIDE.md`](contrib/ROOTFS_SCRIPT_GUIDE.md).

The default Debian base is intentionally small but agent-friendly. It includes common search and debugging tools (`ripgrep`, `fd-find`, `file`, `unzip`, `zip`, `tmux`, `lsof`, `strace`, `jq`, `less`), Python venv support, and BusyBox-backed `nc`/`hexdump` shims. Language ecosystems still come from `mise`, not from stuffing extra runtimes into the image.

Once inside the sandbox, the agent-facing reference lives at [`docs/AGENTS.md`](docs/AGENTS.md) -- agent environment, agent API endpoints, block-response anatomy, security boundaries, troubleshooting. The bundled host scripts stage it at `~/.safeyolo/AGENTS.md` inside the sandbox; the Claude Code host script also feeds it to `claude --append-system-prompt` so the model has it in context from turn 1.

## Controlling Agent Access

Grant agents access to specific services with specific capabilities. Your credentials stay in SafeYolo's vault — agents make requests, SafeYolo handles authentication.

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

Full technical design: [docs/microvm-architecture.md](docs/microvm-architecture.md) (macOS microVM path) and [docs/linux-port-design.md](docs/linux-port-design.md) (Linux gVisor path). Highlights common to both paths:

- **Networking**: no external interface in the sandbox — egress is UDS/vsock to a per-agent host socket → proxy bridge → mitmproxy (structural isolation)
- **Terminal**: full PTY with resize — vsock PTY bridge on macOS, `runsc exec` on Linux
- **Guest init**: served from a writable status share + read-only config share (changes without rootfs rebuild)
- **Identity**: PROXY protocol v2 — the bridge stamps upstream TCP with each agent's attribution IP; mitmproxy's `next_layer` hook parses it

Linux specifics:

- **Rootless**: runsc runs in an unprivileged user namespace (`unshare -Un` + `newuidmap`/`newgidmap`). Agents operate with zero sudo; container uid 0 maps to a subordinate uid (100000), container uid 1000 maps to the operator.
- **Rootfs**: a single shared EROFS image mounted read-only by gVisor's sentry, with a memory-backed writable overlay inside the sandbox. No per-agent on-disk overlays.
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
- Python 3.12+ with [uv](https://docs.astral.sh/uv/)
- macOS only: Lima (build-time, for the guest image) — `brew install lima`
- Linux only: gVisor `runsc` (VM runtime) — see the Build section above for the install command; plus `newuidmap`/`newgidmap` (from `uidmap` on Debian/Ubuntu) and a subuid/subgid range for the operator. `safeyolo setup` verifies all of this.

Run `safeyolo setup` to check and apply one-time prerequisites, then `safeyolo doctor` any time to see the current state of runtime, isolation platform, user namespaces, guest images, and running agents.

## Status

SafeYolo is **pre-v1**. The current sandbox design — hardware-backed microVMs on macOS, rootless gVisor on Linux — replaces the earlier Docker-based implementation; the container-era code is preserved on the [`docker`](https://github.com/craigbalding/safeyolo/tree/docker) branch for reference.

## Documentation

- [MicroVM Architecture](docs/microvm-architecture.md)
- [Agent Networking (vsock/UDS)](docs/networking-vsock-uds.md)
- [Configuration](docs/CONFIGURATION.md)
- [Architecture & Addons](docs/ADDONS.md)
- [Security & Threat Model](SECURITY.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
