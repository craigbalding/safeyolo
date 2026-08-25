# SafeYolo

[![CI](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/craigbalding/safeyolo/badge)](https://scorecard.dev/viewer/?uri=github.com/craigbalding/safeyolo)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11693/badge)](https://www.bestpractices.dev/projects/11693)
[![CodeQL](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml/badge.svg)](https://github.com/craigbalding/safeyolo/actions/workflows/codeql.yml)

**Want your AI agents to do more without giving them access to more?**

SafeYolo gives coding agents room to get useful work done without handing them your desktop, your credentials, or unrestricted access to your network and third-party services.

Give the agent root. Let it install tools, run browsers, start services, debug code and improvise within the scope you give it. The sandbox is there to limit the blast radius, not to hobble the agent.

SafeYolo doesn't try to make agents safe by replacing the world with a small set of approved tools. Agents can use normal CLIs, SDKs, browsers and web services — GitHub is GitHub, AWS is AWS. SafeYolo sits at the boundary, controlling what the agent can reach and keeping credentials out of its hands.

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

### Install

```bash
git clone https://github.com/craigbalding/safeyolo.git
cd safeyolo
./install.sh
safeyolo bootstrap
```

`./install.sh` puts `safeyolo` on your `PATH` at `~/.local/bin/safeyolo`.
`safeyolo bootstrap` runs first-time setup (config init, guest image build, host prereqs). Idempotent — safe to re-run.

If a Linux build prerequisite is missing, `bootstrap` prints the single `sudo apt-get install ...` line you need and exits so you decide when to sudo. Machine-parseable output via `safeyolo bootstrap --json` for CI / harness use.

_macOS only_ — one additional step to build the Swift VM helper:

```bash
cd vm && make install && cd ..
```

### Run your first agent

```bash
safeyolo agent add work ~/code --host-script @claude
safeyolo agent run work
```

`~/code` is your project directory, mounted read-write into the sandbox. `@claude` is a bundled host-script alias that stages Claude Code inside the guest. Other bundled aliases: `@codex` (OpenAI Codex CLI), `@mise-shell` (interactive shell with mise). Paths still work — pass any executable script if you have your own.

Inside the sandbox:

- **All traffic routes through SafeYolo proxy** — the sandbox has no external network interface; the only path out is through the proxy
- **API keys are protected** — credentials only reach their intended hosts
- **Everything is logged** — JSONL audit trail for review
- **Dev-ready VMs** — agents install toolchains via mise, state persists across restarts
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

On Linux this reports the sandbox runtime (runsc version), isolation platform (KVM vs systrap and why), user-namespace prerequisites (newuidmap, subuid, AppArmor profile), the guest image, and any running agents. On macOS it confirms Apple Silicon + the safeyolo-vm helper. Exits non-zero on any failed check.

### Install from source (advanced)

`safeyolo bootstrap` above wraps three separate commands (`safeyolo init`, `safeyolo build`, `safeyolo setup`). If you want to run them individually — for example to peek at exactly what each does — the sequence is:

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

SafeYolo is **pre-v1**. Sandbox runtime is hardware-backed microVMs on macOS and rootless gVisor on Linux.

## Documentation

- [MicroVM Architecture](docs/microvm-architecture.md)
- [Agent Networking (vsock/UDS)](docs/networking-vsock-uds.md)
- [Configuration](docs/CONFIGURATION.md)
- [Architecture & Addons](docs/ADDONS.md)
- [Security & Threat Model](SECURITY.md)
- [Contributing](docs/DEVELOPERS.md)

## License

MIT License. Built with [mitmproxy](https://mitmproxy.org/).
