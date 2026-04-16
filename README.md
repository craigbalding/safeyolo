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
# mmdebstrap. See guest/README.md for platform-specific setup notes.
cd guest && ./build-all.sh && cd ..
mkdir -p ~/.safeyolo/share && cp guest/out/* ~/.safeyolo/share/

# Install CLI and dependencies
uv sync --all-packages
# Put the `safeyolo` CLI on your shell's PATH (or prefix every command with `uv run`)
source .venv/bin/activate
```

**Then, one platform-specific step:**

_macOS_ — build the Swift VM helper + `feth-bridge` + `vsock-term`:

```bash
cd vm && make install && cd ..
```

_Linux_ — install gVisor (`runsc`) as the VM runtime. The `vm/` directory is macOS-only and is not used here:

```bash
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc
```

### Run

```bash
# One-time config bootstrap — writes ~/.safeyolo/policy.toml (the baseline
# policy), addons.yaml, an admin token, and the certs/data/lists directories.
safeyolo init

# Start the proxy
safeyolo start

# Run Claude Code in an isolated sandbox
safeyolo agent add myproject claude-code ~/code
```

The last argument (`~/code`) is your project directory — mounted read-write into the sandbox (VirtioFS on macOS, bind mount on Linux). The agent runs in an isolated Linux sandbox where:

- **All traffic routes through SafeYolo proxy** — host firewall (pf on macOS, iptables on Linux) blocks direct internet access
- **API keys are protected** — credentials only reach their intended hosts
- **Everything is logged** — JSONL audit trail for review
- **Dev-ready VMs** — agents install toolchains via mise, state persists across restarts

### Verify isolation

From inside the agent:

```bash
# This works (routed through proxy):
curl https://httpbin.org/ip

# This is blocked (host firewall drops it):
curl --noproxy '*' https://ifconfig.co
# Error: Could not resolve host
```

## How It Works

Each agent runs in an isolated Linux sandbox with a dedicated network segment:

```
Agent sandbox (192.168.68.2)
    │
    │  HTTP_PROXY → host bridge IP
    ▼
Host bridge (firewall: allow proxy port, block everything else)
    │
    ▼
SafeYolo mitmproxy (host process)
    │  policy, credential guard, rate limits, audit
    ▼
Internet
```

The sandbox itself is a hardware-backed microVM on macOS (Apple Virtualization.framework + feth + pf) and a gVisor container on Linux (runsc + veth + iptables). Either way: if the agent unsets proxy vars → blocked by the host firewall. Raw TCP → blocked. DNS → blocked (no DNS from inside the sandbox). Enforcement is at the network level, not the process level.

## Key Features

- **One-command agent setup** — pre-configured templates for Claude Code and Codex, plus a `byoa` (Bring Your Own Agent) template for installing your own
- **Strong isolation** — each agent in its own sandbox: hardware-backed microVM on macOS, gVisor on Linux
- **Enforced egress** — host firewall (pf/iptables) on dedicated bridge interfaces, not just env vars
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
safeyolo agent add work claude-code ~/work
safeyolo agent add side-project claude-code ~/side-project
safeyolo agent add codex openai-codex ~/experiments

safeyolo agent run work       # Each agent gets its own VM and subnet
```

## Templates

| Template | Agent |
|----------|-------|
| `claude-code` | Anthropic Claude Code CLI |
| `openai-codex` | OpenAI Codex CLI |
| `byoa` | Bring Your Own Agent — bash shell for custom agent installation |

If you've already authenticated on your host (via `claude` or `codex`), credentials are mounted automatically via VirtioFS.

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

Full technical design: [docs/microvm-architecture.md](docs/microvm-architecture.md) (macOS microVM path) and [docs/linux-port-design.md](docs/linux-port-design.md) (Linux gVisor path). Highlights from the macOS microVM path:

- **Networking**: VZFileHandleNetworkDeviceAttachment + feth pairs + pf (not VZNATNetworkDeviceAttachment — Apple blocks pf on bridge interfaces)
- **Terminal**: vsock PTY bridge with proper resize (not serial console)
- **Guest init**: served from VirtioFS config share (changes without rootfs rebuild)
- **Service discovery**: file-based agent IP map

The Linux path runs the same guest rootfs under `runsc` with veth + iptables for network isolation and overlayfs for per-agent writable layers — see `docs/linux-port-design.md` for the full design.

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
- Linux only: gVisor `runsc` (VM runtime) — see the Build section above for the install command

Run `safeyolo setup` to check all prerequisites.

## Status

SafeYolo is **pre-v1**. The current sandbox design — hardware-backed microVMs on macOS, gVisor on Linux — replaces the earlier Docker-based implementation; the container-era code is preserved on the [`docker`](https://github.com/craigbalding/safeyolo/tree/docker) branch for reference.

## Documentation

- [MicroVM Architecture](docs/microvm-architecture.md)
- [Sandbox Mode](docs/SANDBOX_MODE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Architecture & Addons](docs/ADDONS.md)
- [Security & Threat Model](SECURITY.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
