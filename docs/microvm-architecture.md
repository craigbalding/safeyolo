# MicroVM Architecture

SafeYolo runs AI coding agents in persistent Linux microVMs with hardware-level isolation and structural egress control.

The microVM approach — guest image build, vsock terminal, openpty/setsid/TIOCSCTTY PTY pattern — was informed by [Shuru](https://github.com/superhq-ai/shuru/), an open-source microVM sandbox for AI agents.

## Architecture

On an Apple Silicon Mac, the guest forwarder sends proxy traffic over vsock
port 1080. The `safeyolo-vm` helper relays those bytes to the agent's host
Unix domain socket (UDS). The Rust proxy owns that listener.

```text
Agent microVM -> guest forwarder -> vsock:1080 -> VSockProxyRelay
                                                   -> per-agent host UDS
                                                   -> Rust proxy -> upstream
```

The helper also bridges the separate operator shell UDS to guest SSH over
vsock port 2220. The interactive terminal uses its own vsock
pseudo-terminal (PTY) channels.
The guest has no external network interface; its workspace and configuration
shares use VirtioFS.

## Network Isolation

The microVM has no virtio-net attachment. Its guest forwarder listens on
`127.0.0.1:8080`. Agent HTTP clients use
`HTTP_PROXY=http://127.0.0.1:8080`. The guest forwarder, the
`VSockProxyRelay` in `safeyolo-vm`, and the host UDS carry the connection to
the Rust proxy.

The host command-line interface (CLI) derives a private socket path for the
agent, writes its identity to
`agent_map.json`, and puts `agent_id`, `source_id`, and `socket_path` in the
native listener configuration. The Rust proxy binds the UDS and fixes the
configured identity when it accepts a connection. It does not use a
guest-supplied header or a mitmproxy mode to select the agent. Removing proxy
environment variables does not create another external route from the guest.

For the host and guest hops, listener reload, and diagnostics, see
[agent networking](networking-vsock-uds.md). This describes the implemented
macOS bridge; the physical Virtualization.framework (VZ) release pilot remains open under
[issue #640](https://github.com/craigbalding/safeyolo/issues/640).

## Connection admission on macOS

The shipped bridges reserve capacity before opening VZ connections:

| Path | Maximum pending or established connections | Excess connections |
| --- | --- | --- |
| Proxy | 232 proxy connections | Wait in the guest TCP listen backlog, configured to 128; clients can time out |
| Shell | 6 shell connections | The helper closes the incoming host socket and records a connection-limit error |
| Terminal | One data connection and one resize connection | A retry waits until the previous attempt completes or its connection closes |

These discrete limits allow at most 240 connections through these paths.
They reserve shell and terminal capacity even when the proxy is full. The
host control Unix socket does not open a VZ connection. Linux UDS forwarding
does not use the macOS proxy limit.

Proxy admission happens in the guest because VZ allocates a connection before
the host listener can accept or reject it. Shell and terminal admission happens
in the helper before it calls VZ. A caller timeout does not release a slot for
an unresolved VZ callback. A late successful callback closes its connection
before releasing the slot. A callback that never arrives retains its slot
until the helper exits.

The limits address ordinary workload overload through the shipped bridges.
They do not restrict guest programs that create vsock connections directly.
The connection counts also exclude framework descriptors, so native acceptance
must include the full guest and its configured shares. A framework resource
limit or allocation failure can still stop the VM.

## Terminal

The VM terminal uses vsock (virtio socket) with a proper PTY:

**Guest side (`vsock-term`)**: Listens on vsock port 1024 (data) and 1025 (resize). On host connection: `openpty()` with the host's window dimensions, `fork()`, `setsid()`, `TIOCSCTTY`, `dup2` slave to 0/1/2, drop privileges, `execvp` the agent binary directly. No shell wrapper — this preserves `process.stdout.isTTY` for Node.js TUI apps.

**Host side (`VSockTerminal.swift`)**: Connects to vsock after VM boots. Full `cfmakeraw` terminal mode. `write_all()` with retry to prevent split ANSI sequences. SIGWINCH → 4-byte resize message on control channel. Drains PTY output before closing.

For persistent agents (`safeyolo agent start NAME`), a configured host launcher owns the agent terminal, or an explicit supervisor owns headless harness turns. `--sandbox-only` boots without a coding agent. The separate `safeyolo agent shell` route uses SSH through `VSockShellBridge` → `vsock:2220` → `guest-shell-bridge` → sshd; see [agent launchers](agent-launchers.md).

## Config Share Architecture

The CLI stages guest boot scripts and environment on the VirtioFS configuration share:

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

The host owns the Rust proxy, per-agent UDS listeners, policy and evidence,
the Python CLI, the Swift VM helper, and the VirtioFS configuration share.
The guest and its coding agent can be compromised. The helper's relay can
reach only the host UDS selected for that VM; the Rust listener attaches
the host-configured identity. The guest has no external network interface,
so unsetting proxy variables or opening a raw socket does not create
general outbound network access.

## Guest Image

Built via a Lima VM on macOS for ARM64 cross-compilation (see `guest/README.md`):

- **Kernel**: Linux 6.12, minimal defconfig. Virtio-vsock built in; virtio-net still available for local development but not attached by the runtime.
- **Rootfs**: Debian trixie minbase, 2GB ext4 (sparse). Includes: git, curl, jq, build-essential, gnupg, openssh-server, mise, gh CLI, and package-manager proxy/cache support
- **Initramfs**: busybox-static + e2fsck + resize2fs. Mounts root, `switch_root` to stub init. Network configuration is a no-op — there is no eth0.

Artifacts stored at `~/.safeyolo/share/`: `Image`, `initramfs.cpio.gz`, `rootfs-base.ext4`.

## Persistence

One mutable ext4 disk per agent at `~/.safeyolo/agents/<name>/rootfs.ext4`. Cloned from base image on `agent add`. All changes persist: mise installs, shell history, agent state.

## Agent map and native listeners

The CLI writes the host-controlled `~/.safeyolo/data/agent_map.json` before
starting a VM. A running agent entry identifies its attribution IP and
private socket, for example
`~/.safeyolo/data/sockets/10.200.0.1_test/proxy.sock`. The CLI derives the
managed native listener from this map. When an agent starts or stops, the CLI
reconciles its managed listeners, sends SIGHUP to the Rust proxy, and waits
for the matching readiness reload marker. Operator-defined listeners remain
intact. The current package has no `PUT /admin/proxy/mode` route.

## Components

| Component | Language | Purpose |
| --- | --- | --- |
| `safeyolo-vm` | Swift | VM lifecycle, proxy and shell vsock relays |
| `vsock-term` | C | Guest terminal daemon and PTY bridge |
| `guest-proxy-forwarder` | Shell and socat | Guest loopback proxy port to vsock:1080 |
| `guest-shell-bridge` | Shell and socat | vsock:2220 to guest `sshd` |
| `proxy/src/lib.rs` | Rust | Per-agent UDS listeners and fixed accept identity |
| `rust_proxy.py` | Python | Native process launch, listener reconciliation, reload acknowledgement |
| `sockets.py` | Python | Private socket paths under `<ip>_<agent>/proxy.sock` |
| `vm.py` | Python | VM lifecycle and configuration share |
| `guest-init.sh` | Shell | Guest init staged on the configuration share |

## Limitations

1. **macOS only** (Apple Silicon) for the microVM path. Linux runs gVisor containers via `runsc`; see `docs/linux-port-design.md`.
2. **No general raw TCP/UDP egress path.** There is no external interface for those connections; the proxy forwarder and operator shell use their explicit bridges.
3. **No guest snapshots by default.** The native start command has no snapshot flag. Corrupted rootfs → re-create agent.
4. **Guest image build requires Lima on macOS** (for cross-compilation). Runtime itself has no Lima dependency.
