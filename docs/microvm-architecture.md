# MicroVM Architecture

SafeYolo runs AI coding agents in persistent Linux microVMs with hardware-level isolation and enforced network egress control.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Host (macOS, Apple Silicon)                                      │
│                                                                  │
│  ┌────────────────────────────────────┐                          │
│  │ mitmproxy (host process, 0.0.0.0)  │                          │
│  │   - mitmdump with ~15 addons      │                          │
│  │   - admin API on :9090            │                          │
│  └──────────────┬─────────────────────┘                          │
│                 │                                                │
│  ┌──────────────┼──────────────────────────┐                     │
│  │ pf anchor    │  (com.safeyolo)          │                     │
│  │   pass TCP to proxy port on feth        │                     │
│  │   block everything else from VM subnet  │                     │
│  └──────────────┼──────────────────────────┘                     │
│                 │                                                │
│  ┌──────────────▼──────────────────────────┐                     │
│  │ feth pair (per VM)                      │                     │
│  │   fethN ◄──BPF──► feth-bridge ◄──► VZ socket                │
│  │   fethN+1: host IP (192.168.x.1)       │                     │
│  └─────────────────────────────────────────┘                     │
│                                                                  │
│  ┌─────────────────────────────────────────┐                     │
│  │ Apple Virtualization.framework          │                     │
│  │                                         │                     │
│  │  ┌───────────────────────────────────┐  │                     │
│  │  │ Agent MicroVM                     │  │                     │
│  │  │   Debian trixie + mise + node@22  │  │                     │
│  │  │   Static IP on eth0              │  │                     │
│  │  │   HTTP_PROXY → host feth IP      │  │                     │
│  │  │   Workspace via VirtioFS         │  │                     │
│  │  │   Terminal via vsock PTY         │  │                     │
│  │  │   Persistent ext4 root disk      │  │                     │
│  │  └───────────────────────────────────┘  │                     │
│  └─────────────────────────────────────────┘                     │
└──────────────────────────────────────────────────────────────────┘
```

## Network Isolation

### Why not VZNATNetworkDeviceAttachment?

Apple's vmnet NAT creates bridge interfaces. The XNU kernel explicitly blocks pf IP filtering on bridge interfaces (`bridge_ioctl_sfilt` returns EINVAL for `IFBF_FILT_USEIPF`). This means pf rules on the bridge are silently ignored — no network isolation.

### feth pair approach

Each VM gets a dedicated feth (fake Ethernet) pair. feth interfaces are regular network interfaces where pf works:

1. `VZFileHandleNetworkDeviceAttachment` connects the VM to a Unix datagram socketpair
2. `feth-bridge` (C binary) forwards Ethernet frames between the socket and a feth interface via BPF
3. pf rules on the feth interface allow only the proxy port, block everything else
4. NAT from the feth subnet to the outbound interface enables proxy upstream connections

```
VM eth0 ──► VZ socketpair ──► feth-bridge ──► BPF on fethN ──► fethN+1 (host IP)
                                                                    │
                                                              pf rules here
                                                              (allow proxy, block all)
```

Each VM gets its own /24 subnet: `192.168.(65+index).0/24`. The guest uses static IP `.2`, host is `.1`.

### pf rules

```
nat on en0 from 192.168.68.0/24 to any -> (en0)
pass in quick on feth proto tcp from 192.168.68.0/24 to 192.168.68.1 port 8090
block in quick on feth proto tcp from 192.168.68.0/24 to any port 9090
block in on feth from 192.168.68.0/24 to any
```

BPF access requires the `access_bpf` group (added by Wireshark or OrbStack). No sudo needed for feth-bridge.

## Terminal

The VM terminal uses vsock (virtio socket) with a proper PTY:

**Guest side (`vsock-term`)**: Listens on vsock port 1024 (data) and 1025 (resize). On host connection: `openpty()` with the host's window dimensions, `fork()`, `setsid()`, `TIOCSCTTY`, `dup2` slave to 0/1/2, drop privileges, `execvp` the agent binary directly. No shell wrapper — this preserves `process.stdout.isTTY` for Node.js TUI apps.

**Host side (`VSockTerminal.swift`)**: Connects to vsock after VM boots. Full `cfmakeraw` terminal mode. `write_all()` with retry to prevent split ANSI sequences. SIGWINCH → 4-byte resize message on control channel. Drains PTY output before closing.

## Config Share Architecture

All SafeYolo-specific logic lives on the VirtioFS config share, not baked into the rootfs:

```
~/.safeyolo/agents/<name>/config-share/
├── guest-init          # The real init script (written by CLI on every run)
├── vsock-term          # Terminal daemon (cross-compiled ARM64 binary)
├── proxy.env           # HTTP_PROXY, HTTPS_PROXY, SSL_CERT_FILE, etc.
├── agent.env           # SAFEYOLO_AGENT_CMD, MISE_PACKAGE, auto_args, etc.
├── network.env         # GUEST_IP, GATEWAY_IP, NETMASK
├── mitmproxy-ca-cert.pem
├── authorized_keys     # SSH public key for `agent shell`
├── agent_token         # Agent API bearer token
├── instructions.md     # CLAUDE.md or equivalent (injected to guest path)
├── host-mounts         # VirtioFS mount manifest (tag:guest_path)
├── host-files-manifest # Individual file copy manifest
├── vm-ip               # Written by guest init after boot (read by CLI)
└── vm-status           # "installing" during first-run install
```

The rootfs has a 30-line stub at `/usr/local/bin/safeyolo-guest-init` that mounts VirtioFS and execs `/safeyolo/guest-init`.

**Iteration loop**: Change guest-init.sh → instant. Change vsock-term.c → `make install` (10s cross-compile). Change rootfs packages → full rebuild (rare).

## Trust Boundaries

```
TRUSTED: Host
  mitmproxy + addons + PDP + policy
  pf rules on feth interfaces
  safeyolo-vm (Swift, manages VM lifecycle)
  feth-bridge (C, forwards Ethernet frames)
  Python CLI (agent management)
  VirtioFS config share contents

UNTRUSTED: Guest VM
  Agent process (claude, codex, etc.)
  Guest OS, tools, anything the agent installs
  Guest networking configuration

  If the guest unsets HTTP_PROXY → pf blocks all non-proxy traffic
  If the guest sends raw TCP → pf blocks it
  VM boundary is hardware virtualisation (stronger than Docker namespaces)
```

## Guest Image

Built via Docker on macOS for ARM64 cross-compilation:

- **Kernel**: Linux 6.12, minimal defconfig (all virtio built-in, no modules)
- **Rootfs**: Debian trixie minbase, 2GB ext4 (sparse). Includes: git, curl, jq, build-essential, gnupg, openssh-server, mise + node@22, gh CLI, package-manager intercepts
- **Initramfs**: busybox-static + e2fsck + resize2fs. Mounts root, configures static IP from VirtioFS, `switch_root` to stub init

Artifacts stored at `~/.safeyolo/share/`: `Image`, `initramfs.cpio.gz`, `rootfs-base.ext4`.

## Persistence

One mutable ext4 disk per agent at `~/.safeyolo/agents/<name>/rootfs.ext4`. Cloned from base image on `agent add`. All changes persist: mise installs, shell history, agent state.

## Service Discovery

The CLI writes `~/.safeyolo/data/agent_map.json` when VMs start/stop:

```json
{"test": {"ip": "192.168.68.2", "started": "2026-04-06T..."}}
```

The `service_discovery` addon reads this file (mtime-cached) to resolve client IPs to agent names for per-agent policy evaluation.

## Components

| Component | Language | Purpose |
|-----------|----------|---------|
| `safeyolo-vm` | Swift | VM lifecycle (Apple Virtualization.framework) |
| `feth-bridge` | C | Ethernet frame forwarding (VZ socket ↔ BPF on feth) |
| `vsock-term` | C (static, ARM64) | Guest terminal daemon (vsock PTY bridge) |
| `proxy.py` | Python | Host mitmproxy process management |
| `firewall.py` | Python | feth pair + pf rule management |
| `vm.py` | Python | VM lifecycle, config share, agent map |
| `guest-init.sh` | Bash | Guest init (on config share, not rootfs) |

## Limitations

1. **macOS only** (Apple Silicon). Linux KVM backend deferred.
2. **Non-HTTP traffic blocked, not intercepted.** pf drops raw TCP/UDP from VMs.
3. **No guest snapshots.** Corrupted rootfs → re-create agent.
4. **Guest image build requires Docker** (for cross-compilation). Runtime has zero Docker dependency.
