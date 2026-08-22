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
- Python 3.12 or 3.13
- [uv](https://docs.astral.sh/uv/) — the Python package/project manager SafeYolo uses for the editable install. Grab it with your distro's package manager, or follow the upstream install instructions; either works.
- macOS only: [Lima](https://lima-vm.io/) for the guest image build. Any of `brew install lima`, `sudo port install lima`, or `mise use -g lima` is fine.
- Linux only: [gVisor (`runsc`)](https://gvisor.dev/) as the VM runtime. On apt-based hosts, `safeyolo setup` installs it from gVisor's signed repository; other distributions must install it first using the upstream instructions.

### Build

```bash
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo

# Build the guest VM image. On Linux only the rootfs is produced (gVisor
# supplies its own kernel); ~4-6 min. On macOS the driver auto-shells into a
# Lima VM and additionally builds the kernel + initramfs for Apple
# Virtualization.framework; ~10 min first time.
#
# See guest/README.md for platform-specific setup notes. On Linux you'll
# also need `BUILD_KERNEL=1 ./build-all.sh` if you're producing artifacts for
# a macOS consumer from a Linux box.
#   Linux build prerequisite: sudo apt-get install skopeo umoci e2fsprogs curl
cd guest && ./build-all.sh && cd ..
mkdir -p ~/.safeyolo/share && sudo cp -a guest/out/* ~/.safeyolo/share/

# Install SafeYolo onto your PATH (survives shell restarts).
# Requires `uv` (https://docs.astral.sh/uv/).
#
# --editable keeps the checkout wired into the installed command while
# installing the proxy runtime dependencies, including mitmproxy, into the
# same tool environment.
uv tool install --editable .
```

`uv tool install` puts `safeyolo` in `~/.local/bin/safeyolo`. Make sure that directory is on your `PATH` (uv will tell you if it isn't). To pick up upstream changes later: `uv tool install --reinstall --editable .`.

**Then, one platform-specific step:**

_macOS_ — build the Swift VM helper and its guest-side companion binaries:

```bash
cd vm && make install && cd ..
```

_Linux (apt-based)_ — no separate step. `safeyolo setup` below installs gVisor (`runsc`), `uidmap`, and `acl` when they are missing. The `vm/` directory is macOS-only and is not used here.

For a non-apt Linux distribution, install gVisor using its upstream instructions before running `safeyolo setup`. The equivalent apt commands are:

```bash
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc
```

If the `uv tool install` above didn't end up with `mitmdump` available in SafeYolo's tool environment, fall back to pipx with the addon dependencies injected:

```bash
./scripts/install-mitmproxy-pipx.sh
```

This script pipx-installs `mitmproxy` and injects the exact set of addon deps SafeYolo needs into that environment.

### Run

```bash
# One-time config bootstrap — writes ~/.safeyolo/policy.toml (the baseline
# policy), addons.yaml, an admin token, and the certs/data/lists directories.
safeyolo init

# Check and apply any host-level prerequisites (Linux: gVisor, uidmap, acl,
# AppArmor profile for user namespaces, /dev/kvm udev rule for hardware isolation).
# Safe to re-run; idempotent. No effect on macOS.
safeyolo setup

# Start the proxy
safeyolo start

# Optional: persistently publish the authenticated WebMITM UI to your tailnet
safeyolo proxy web share --tailnet

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

Agent identity is cross-platform via a per-agent Unix domain socket. On both macOS and Linux each agent talks to its own host-owned UDS at `<ip>_<agent>/proxy.sock`; mitmproxy's `UnixMode` listener parses the path at bind and stamps `client.peername = (ip, 0)` on every accepted connection. No per-agent lo0 aliases, no sudo at runtime.

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
- **Credentials stay outside the sandbox** — SafeYolo holds real credentials and injects them only into authorized requests; credential guards stop secrets being sent to the wrong destination
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

## Host scripts

`safeyolo agent add` takes an optional `--host-script PATH`. The script runs on the host, as you, before the sandbox boots. It populates the agent's persistent home (`~/.safeyolo/agents/<name>/home/`) with whatever the agent needs — credentials, settings, user extensions — and writes a `.safeyolo-command` file the guest execs as the default foreground command. For an existing agent, reapply or switch the setup with `safeyolo agent run <name> --host-script PATH`.

The `contrib/` directory has ready-made host scripts:

| Script | Purpose |
|--------|---------|
| `contrib/claude-host-setup.sh` | Claude Code — stages host `~/.claude/` auth + user extensions, injects SafeYolo's compact baseline, installs the shared `/safeyolo` skill, and launches nag-free |
| `contrib/codex-host-setup.sh` | OpenAI Codex CLI — stages `~/.codex/`, injects SafeYolo's compact baseline, installs the shared `$safeyolo` skill, and launches with sandboxing disabled inside the guest (`-s danger-full-access -a never`) while SafeYolo remains the outer boundary |
| `contrib/mise-shell-host-setup.sh` | BYOA — boots into an interactive shell with mise ready; install whatever tools you want with `mise use -g ...` |

Without `--host-script`, the sandbox boots to an interactive bash shell in a per-agent persistent home.

Writing your own: see [`contrib/HOST_SCRIPT_GUIDE.md`](contrib/HOST_SCRIPT_GUIDE.md).

## Custom rootfs

`safeyolo agent add` also takes an optional `--rootfs-script PATH` for agents that need a different base system than SafeYolo's default Debian-trixie rootfs — e.g. Kali for a pentest agent or Alpine for a minimal shell. The script builds a full per-agent rootfs from any distro's OCI image or bootstrap tarball. Examples: [`contrib/kali-pentest/build-kali-rootfs.sh`](contrib/kali-pentest/build-kali-rootfs.sh), [`contrib/alpine-minimal/build-alpine-rootfs.sh`](contrib/alpine-minimal/build-alpine-rootfs.sh). Writing your own: see [`contrib/ROOTFS_SCRIPT_GUIDE.md`](contrib/ROOTFS_SCRIPT_GUIDE.md).

The default Debian base is intentionally small but agent-friendly. It includes common search and debugging tools (`ripgrep`, `fd-find`, `file`, `unzip`, `zip`, `tmux`, `lsof`, `strace`, `jq`, `less`), Python venv support, and BusyBox-backed `nc`/`hexdump` shims. Language ecosystems still come from `mise`, not from stuffing extra runtimes into the image.

SafeYolo splits agent guidance by when it is needed. The compact, always-on
baseline at [`docs/AGENTS.md`](docs/AGENTS.md) covers environment invariants,
the correct Agent API health check, and security boundaries. Detailed Agent
API, flow, gateway, `plumb`, block-response, and troubleshooting workflows live
in one progressively disclosed [`safeyolo` skill](cli/src/safeyolo/agent_context/skills/safeyolo/SKILL.md).

The bundled host scripts stage the baseline under `~/.safeyolo/`. Claude
receives it through `--append-system-prompt`; Codex receives it as
`developer_instructions`. The skill itself is refreshed in the read-only
`/safeyolo` share on every run. The scripts link that managed copy into each
agent's native skill directory, leaving existing user instructions untouched.

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
- **Identity**: per-agent Unix domain socket at `<ip>_<agent>/proxy.sock` — mitmproxy's `UnixMode` parses the path at bind and stamps `client.peername = (ip, 0)` on every accepted connection

Linux specifics:

- **Rootless host operation**: runsc runs in an unprivileged user namespace (`unshare -Un` + `newuidmap`/`newgidmap`) and launching agents requires no host sudo. Agents start as uid 1000; in-guest `sudo` may enter sandbox uid 0 for ephemeral package installs. That identity maps to subordinate host uid 100000, while container uid 1000 maps to the operator.
- **Rootfs**: a single shared directory tree at `~/.safeyolo/share/rootfs-tree/` used directly as gVisor's OCI `root.path` (no image packaging step). Writes go to a memory-backed overlay upper per sandbox; per-agent persistent bind mounts cover apt caches so reinstalls stay cheap.
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
