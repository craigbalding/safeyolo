# MicroVM Architecture

SafeYolo runs AI coding agents in persistent Linux microVMs with hardware-level isolation and structural egress control.

The microVM approach — guest image build, vsock terminal, openpty/setsid/TIOCSCTTY PTY pattern — was informed by [Shuru](https://github.com/superhq-ai/shuru/), an open-source microVM sandbox for AI agents.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Host (macOS, Apple Silicon)                                      │
│                                                                  │
│  ┌────────────────────────────────────┐                          │
│  │ mitmproxy (host process, UDS-only) │                          │
│  │   - mitmdump with ~15 addons       │                          │
│  │   - per-agent UnixInstance listens │                          │
│  │     on <ip>_<agent>.sock (identity │                          │
│  │     parsed from filename)          │                          │
│  │   - admin API on 127.0.0.1:9090    │                          │
│  └──────────────▲─────────────────────┘                          │
│                 │  AF_UNIX (per-agent UDS)                       │
│  ┌──────────────┴─────────────────────┐                          │
│  │ safeyolo-vm                        │                          │
│  │   VSockProxyRelay: vsock:1080  →   │                          │
│  │     per-agent UDS (dumb pump)      │                          │
│  │   VSockShellBridge: per-agent UDS →│                          │
│  │     vsock:2220 (guest sshd)        │                          │
│  │   VSockTerminal: vsock:1024/1025 → │                          │
│  │     guest vsock-term (foreground)  │                          │
│  └──────────────▲─────────────────────┘                          │
│                 │  vsock (virtio socket) — no virtio-net         │
│  ┌──────────────┴──────────────────────────┐                     │
│  │ Apple Virtualization.framework          │                     │
│  │                                         │                     │
│  │  ┌───────────────────────────────────┐  │                     │
│  │  │ Agent MicroVM                     │  │                     │
│  │  │   Debian trixie + mise + node@22  │  │                     │
│  │  │   Loopback-only (no eth0)         │  │                     │
│  │  │   HTTP_PROXY → 127.0.0.1:8080 →   │  │                     │
│  │  │     guest-proxy-forwarder → vsock │  │                     │
│  │  │   Workspace via VirtioFS          │  │                     │
│  │  │   Terminal via vsock PTY          │  │                     │
│  │  │   Persistent ext4 root disk      │  │                     │
│  │  └───────────────────────────────────┘  │                     │
│  └─────────────────────────────────────────┘                     │
└──────────────────────────────────────────────────────────────────┘
```

## Network Isolation

The sandbox has **no external network interface**. There is no virtio-net attachment — the only ingress/egress channels into the guest are vsock (a virtio socket, not a network device) and VirtioFS. This is structural isolation: there is no firewall rule to misconfigure and no way to route around, because the guest kernel never sees an interface it could use.

All agent-initiated HTTP traffic takes this path:

1. Agent makes an HTTP request honouring `HTTP_PROXY=http://127.0.0.1:8080`
2. `guest-proxy-forwarder.sh` (socat, listening on `127.0.0.1:8080` inside the guest) accepts the connection and relays bytes over vsock
3. `VSockProxyRelay` (in `safeyolo-vm`) accepts on vsock port 1080 and connects to the per-agent host UDS
4. mitmproxy's per-agent `UnixInstance` accepts on that UDS. Identity (attribution IP + agent name) is parsed from the socket filename (`<ip>_<agent>.sock`) once at bind time and stamped on every connection via `client.peername = (ip, 0)`
5. mitmproxy's `service_discovery` addon maps the attribution IP back to the agent name for policy evaluation and audit

An agent that unsets proxy env vars has nowhere to go — there is no other network path out of the sandbox.

See `docs/networking-vsock-uds.md` for the hop-by-hop detail, attribution mechanics, log correlation, and troubleshooting.

## Terminal

The VM terminal uses vsock (virtio socket) with a proper PTY:

**Guest side (`vsock-term`)**: Listens on vsock port 1024 (data) and 1025 (resize). On host connection: `openpty()` with the host's window dimensions, `fork()`, `setsid()`, `TIOCSCTTY`, `dup2` slave to 0/1/2, drop privileges, `execvp` the agent binary directly. No shell wrapper — this preserves `process.stdout.isTTY` for Node.js TUI apps.

**Host side (`VSockTerminal.swift`)**: Connects to vsock after VM boots. Full `cfmakeraw` terminal mode. `write_all()` with retry to prevent split ANSI sequences. SIGWINCH → 4-byte resize message on control channel. Drains PTY output before closing.

For detached agents (`safeyolo agent run --detach`), the foreground terminal is skipped and shell access goes via SSH through `VSockShellBridge` → `vsock:2220` → `guest-shell-bridge` → sshd.

## Config Share Architecture

All SafeYolo-specific logic lives on the VirtioFS config share, not baked into the rootfs:

```
~/.safeyolo/agents/<name>/config-share/
├── guest-init          # The real init script (written by CLI on every run)
├── vsock-term          # Terminal daemon (cross-compiled ARM64 binary)
├── guest-proxy-forwarder
├── guest-shell-bridge
├── proxy.env           # HTTP_PROXY, HTTPS_PROXY, SSL_CERT_FILE, etc.
├── agent.env           # SAFEYOLO_AGENT_CMD, MISE_PACKAGE, auto_args, etc.
├── network.env         # GUEST_IP=127.0.0.1, GATEWAY_IP=127.0.0.1
├── mitmproxy-ca-cert.pem
├── authorized_keys     # SSH public key for `agent shell`
├── agent_token         # Agent API bearer token
├── instructions.md     # CLAUDE.md or equivalent (injected to guest path)
├── host-mounts         # VirtioFS mount manifest (tag:guest_path)
├── host-files-manifest # Individual file copy manifest
├── agent-name          # Written by CLI; read by guest-init + forwarders
└── vm-status           # "installing" during first-run install
```

The rootfs has a 30-line stub at `/usr/local/bin/safeyolo-guest-init` that mounts VirtioFS and execs `/safeyolo/guest-init`.

**Iteration loop**: Change guest-init.sh → instant. Change vsock-term.c → `make install` (10s cross-compile). Change rootfs packages → full rebuild (rare).

## Trust Boundaries

```
TRUSTED: Host
  mitmproxy + addons + PDP + policy (owns per-agent UDS listeners
    via UnixInstance; identity from socket filename)
  safeyolo-vm (Swift, manages VM lifecycle + vsock bridges)
  Python CLI (agent management)
  VirtioFS config share contents

UNTRUSTED: Guest VM
  Agent process (claude, codex, etc.)
  Guest OS, tools, anything the agent installs
  Guest networking configuration

  If the guest unsets HTTP_PROXY → no path out (no external interface)
  If the guest opens a raw socket → no interface to bind to
  VM boundary is hardware virtualisation (stronger than Docker namespaces)
```

## Guest Image

Built via a Lima VM on macOS for ARM64 cross-compilation (see `guest/README.md`):

- **Kernel**: Linux 6.12, minimal defconfig. Virtio-vsock built in; virtio-net still available for local development but not attached by the runtime.
- **Rootfs**: Debian trixie minbase, 2GB ext4 (sparse). Includes: git, curl, jq, build-essential, gnupg, openssh-server, mise + node@22, gh CLI, package-manager intercepts
- **Initramfs**: busybox-static + e2fsck + resize2fs. Mounts root, `switch_root` to stub init. Network configuration is a no-op — there is no eth0.

Artifacts stored at `~/.safeyolo/share/`: `Image`, `initramfs.cpio.gz`, `rootfs-base.ext4`.

## Persistence

One mutable ext4 disk per agent at `~/.safeyolo/agents/<name>/rootfs.ext4`. Cloned from base image on `agent add`. All changes persist: mise installs, shell history, agent state.

## Service Discovery

The CLI writes `~/.safeyolo/data/agent_map.json` when VMs start/stop:

```json
{"test": {"ip": "10.200.0.1", "socket": "/Users/me/.safeyolo/data/sockets/10.200.0.1_test.sock", "started": "2026-04-17T..."}}
```

The `service_discovery` addon reads this file (mtime-cached) to resolve the attribution IP (10.200.N.N) back to the agent name for per-agent policy evaluation. `safeyolo agent add`/`remove` calls admin API `PUT /admin/proxy/mode` with a `unix:<path>` list derived from the map; mitmproxy's `Proxyserver` hot-reloads `options.mode` to spawn / tear down the matching `UnixInstance`s.

## Components

| Component | Language | Purpose |
|-----------|----------|---------|
| `safeyolo-vm` | Swift | VM lifecycle (Apple Virtualization.framework) + vsock bridges |
| `vsock-term` | C (static, ARM64) | Guest terminal daemon (vsock PTY bridge) |
| `guest-proxy-forwarder.sh` | Shell + socat (in guest) | `127.0.0.1:8080` → vsock:1080 / UDS |
| `guest-shell-bridge.py` | Python (in guest) | vsock:2220 → sshd on `127.0.0.1:22` |
| `proxy.py` | Python | Host mitmproxy process management |
| `unix_listener.py` (addon) | Python | `UnixMode`/`UnixInstance` — per-agent UDS ingress |
| `sockets.py` | Python | Socket-path helpers; `<ip>_<agent>.sock` is identity |
| `vm.py` | Python | VM lifecycle, config share, agent map |
| `guest-init.sh` | Bash | Guest init (on config share, not rootfs) |

## Limitations

1. **macOS only** (Apple Silicon) for the microVM path. Linux runs gVisor containers via `runsc`; see `docs/linux-port-design.md`.
2. **Non-HTTP traffic has no path at all.** There is no external interface; raw TCP/UDP have no kernel route out of the guest.
3. **No guest snapshots by default** (though `--snapshot` is a beta flag on `agent run`). Corrupted rootfs → re-create agent.
4. **Guest image build requires Lima on macOS** (for cross-compilation). Runtime has no Docker or Lima dependency.
