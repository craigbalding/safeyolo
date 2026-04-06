# MicroVM Architecture: Replacing Docker with Persistent Linux MicroVMs

## Current Architecture (Docker-based)

SafeYolo runs agents as Docker containers on an isolated Docker network:

```
┌─────────────────────────────────────────────────┐
│ Host                                            │
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │ safeyolo container (mitmproxy + addons)  │   │
│  │   - mitmdump on :8080                    │   │
│  │   - admin API on :9090                   │   │
│  │   - read-only rootfs, non-root           │   │
│  └─────────────┬────────────────────────────┘   │
│                │                                │
│      ┌─────────▼──────────┐                     │
│      │ safeyolo_internal  │  (internal: true)   │
│      │ Docker network     │  (no default gw)    │
│      │                    │                     │
│      │  ┌──────────────┐  │                     │
│      │  │ Agent VM     │  │                     │
│      │  │ HTTP_PROXY=  │  │                     │
│      │  │ safeyolo:8080│  │                     │
│      │  └──────────────┘  │                     │
│      └────────────────────┘                     │
└─────────────────────────────────────────────────┘
```

**Isolation guarantee**: Docker's `internal: true` network has no default gateway. Agent containers can only reach the SafeYolo proxy container. All HTTP/HTTPS traffic goes through `HTTP_PROXY`/`HTTPS_PROXY` env vars.

**Agent image**: `node:22-slim` base, mise 2026.1.1 pinned with checksums, package-manager intercepts, Jinja2-rendered init script for privilege drop + binary installation.

**Persistence**: Docker named volume `<agent>-home` mounted at `/home/agent`. Mise installs, shell history, and config survive container restarts.

**Proxy**: mitmproxy in regular mode inside a container, loaded with ~15 addons via `-s` flags. Addons implement policy evaluation, credential guard, network guard, rate limiting, audit logging, service gateway, etc.

## Proposed Architecture (MicroVM-based)

```
┌──────────────────────────────────────────────────────────────┐
│ Host (macOS / Linux)                                         │
│                                                              │
│  ┌────────────────────────────────────────────┐              │
│  │ mitmproxy (regular mode, host process)     │              │
│  │   - mitmdump on 127.0.0.1:8080             │              │
│  │   - admin API on 127.0.0.1:9090            │              │
│  │   - identical addon stack                  │              │
│  └───────────────────┬────────────────────────┘              │
│                      │                                       │
│  ┌───────────────────┼────────────────────────┐              │
│  │ pf firewall       │                        │              │
│  │   VM subnet ──► only mitmproxy port        │              │
│  │   all other egress dropped                 │              │
│  └───────────────────┼────────────────────────┘              │
│                      │                                       │
│  ┌───────────────────▼────────────────────────┐              │
│  │ Apple Virtualization.framework (macOS)      │              │
│  │ KVM (Linux, future)                         │              │
│  │                                             │              │
│  │  ┌───────────────────────────────────────┐  │             │
│  │  │ Agent MicroVM                         │  │             │
│  │  │   - Debian trixie minimal             │  │             │
│  │  │   - mise + node@22 pre-installed      │  │             │
│  │  │   - HTTP_PROXY=http://host:8080       │  │             │
│  │  │   - SafeYolo CA trusted               │  │             │
│  │  │   - persistent ext4 root disk         │  │             │
│  │  │   - workspace via VirtioFS            │  │             │
│  │  └───────────────────────────────────────┘  │             │
│  │                                             │              │
│  │  ┌───────────────────────────────────────┐  │             │
│  │  │ Agent MicroVM 2 ...                   │  │             │
│  │  └───────────────────────────────────────┘  │             │
│  └─────────────────────────────────────────────┘             │
└──────────────────────────────────────────────────────────────┘
```

### What changes

| Concern | Docker (current) | MicroVM (proposed) |
|---------|-------------------|--------------------|
| Agent sandbox | Docker container on internal network | Linux microVM (Apple Vz / KVM) |
| Network isolation | Docker `internal: true` (no gateway) | pf firewall: VM subnet can only reach mitmproxy port |
| Proxy runtime | mitmproxy in a container | mitmproxy as a host process (identical config) |
| Proxy mode | Regular (HTTP proxy) | Regular (HTTP proxy) — unchanged |
| Agent-to-proxy | `HTTP_PROXY=http://safeyolo:8080` (Docker DNS) | `HTTP_PROXY=http://<host-ip>:8080` (NAT gateway) |
| Persistence | Docker named volume at `/home/agent` | Persistent ext4 disk image per agent |
| Workspace sharing | Docker bind mount | VirtioFS mount |
| Guest base | `node:22-slim` Docker image | Debian trixie rootfs built via debootstrap |
| Tool management | mise in container | mise in VM (identical usage) |
| Agent lifecycle | `docker compose run/stop/rm` | Swift helper binary via Python CLI |
| Service discovery | Docker reverse DNS (container IP → name) | Static agent→VM mapping maintained by CLI |
| CA trust | Bind-mount `/certs/mitmproxy-ca-cert.pem` | Baked into rootfs or injected at boot via VirtioFS |

### What does not change

- mitmproxy addon stack (all 15+ addons, identical load order and config)
- Policy model (`policy.toml`, `addons.yaml`, PDP, PolicyClient)
- Admin API, agent API
- Credential guard, network guard, service gateway
- JSONL audit logging
- CLI commands (user-facing `safeyolo agent add/run/list/remove`)
- Agent DX (mise, package-manager intercepts, same env vars)

## Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│ TRUSTED: Host                                       │
│                                                     │
│  mitmproxy (addons, PDP, policy)                    │
│  pf firewall rules                                  │
│  Swift VM helper (creates/manages VMs)              │
│  Python CLI (safeyolo commands)                     │
│  Guest rootfs build scripts                         │
│  VirtioFS host-side (read-only workspace shares)    │
│                                                     │
├─────────────────────────────────────────────────────┤
│ UNTRUSTED: Guest VM                                 │
│                                                     │
│  Agent process (claude, codex, etc.)                │
│  Guest OS (Debian, mise, tools)                     │
│  Guest networking config                            │
│  Anything the agent installs or runs                │
│                                                     │
│  The guest cannot:                                  │
│  - Bypass the proxy (pf drops non-proxy egress)     │
│  - Access host filesystem (VirtioFS is scoped)      │
│  - Reach the admin API (pf + admin_shield addon)    │
│  - Escape the VM (hardware isolation boundary)      │
│                                                     │
│  If the guest misconfigures its network:            │
│  - It loses connectivity (pf rules are host-side)   │
│  - It does NOT gain a bypass path                   │
└─────────────────────────────────────────────────────┘
```

The VM boundary is stronger than the Docker boundary: hardware virtualisation vs. kernel namespaces. Guest root inside the VM cannot affect host state.

## Networking Detail

### macOS: VZNATNetworkDeviceAttachment + pf

Each VM gets a `VZNATNetworkDeviceAttachment`, which provides:
- DHCP-assigned IP on a host-private subnet
- Default gateway pointing to host
- DNS resolution via host

pf rules restrict the VM subnet:

```
# /etc/pf.anchors/safeyolo
# Allow VMs to reach mitmproxy only
pass in quick on bridge100 proto tcp from <vm_subnet> to 127.0.0.1 port 8080
# Drop everything else from VM subnet
block in on bridge100 from <vm_subnet> to any
```

The VM sees a normal network stack and uses `HTTP_PROXY`/`HTTPS_PROXY` exactly as Docker agents do today. The pf rules are the enforcement layer — transparent to the guest.

### Future: Linux (KVM)

Same model, iptables/nftables instead of pf. VM gets a tap device on a host-private bridge; firewall rules restrict egress to mitmproxy port only.

## Guest Image

### Build process

Built on macOS via Docker (since macOS cannot create ext4 natively), mirroring the Shuru pattern:

1. `debootstrap --variant=minbase trixie` into a raw ext4 image
2. Install packages: `git curl jq ca-certificates build-essential iproute2 openssh-client`
3. Install mise (pinned version, checksum-verified) with `mise install --system node@22`
4. Install package-manager intercepts (same as current Dockerfile)
5. Configure mise activation (`/etc/bash.bashrc`, `BASH_ENV`)
6. Set proxy env vars as defaults (`/etc/environment`)
7. Bake in SafeYolo CA cert
8. Cleanup: remove apt cache, docs, man pages

### Kernel

Minimal ARM64 Linux kernel (same pattern as Shuru):
- Direct boot via `VZLinuxBootLoader` (no UEFI)
- Built-in virtio drivers: blk, net, console, fs, balloon, vsock
- ext4, overlay, tmpfs filesystems
- IPv4 networking, netfilter
- No modules, no USB, no sound, no graphics

### Initramfs

Minimal busybox-based initramfs:
1. Mount proc/dev/sys
2. `e2fsck` + `resize2fs` on root disk (handles first boot + disk growth)
3. Mount ext4 root
4. Configure networking (DHCP or static)
5. `switch_root` to the real rootfs
6. Exec `/sbin/init` (standard Debian init or a simple shell script)

### Guest init script

Shell script at `/usr/local/bin/safeyolo-init` (replaces Docker's `safeyolo-init.sh.j2`):
1. Ensure home directory structure exists
2. Install agent binary via mise if missing (`mise use -g <package>@latest`)
3. Run user init hook if present (`~/.safeyolo-hooks/agent-init.sh`)
4. Exec agent binary

No privilege drop needed — the VM is the isolation boundary, not Unix users.

## Persistence Model

One mutable ext4 disk image per agent, stored at `~/.safeyolo/agents/<name>/rootfs.ext4`.

- First created by cloning the base rootfs image
- All changes persist: mise installs, shell history, config files, agent state
- Survives VM stop/start cycles
- Base image updates: user re-creates the agent (or we add a rebase command later)

No overlay, no CoW cloning, no snapshot chain for V1. Plain file, simple semantics.

## Component Architecture

### Swift helper binary (`safeyolo-vm`)

Minimal Swift binary that the Python CLI invokes. Responsibilities:
- Create and configure `VZVirtualMachine` (CPU, memory, devices)
- Attach persistent root disk (`VZVirtioBlockDeviceConfiguration`)
- Attach VirtioFS shares for workspace (`VZVirtioFileSystemDeviceConfiguration`)
- Attach NAT networking (`VZNATNetworkDeviceAttachment`)
- Attach serial console (`VZVirtioConsoleDeviceSerialPortConfiguration`)
- Start/stop VM, forward serial I/O to stdout/stderr
- Exit with guest's exit code (or error)

Interface: CLI flags or JSON config on stdin. No long-running daemon — one process per VM session.

```
safeyolo-vm run \
  --kernel ~/.safeyolo/share/Image \
  --initrd ~/.safeyolo/share/initramfs.cpio.gz \
  --rootfs ~/.safeyolo/agents/myagent/rootfs.ext4 \
  --cpus 4 --memory 4096 \
  --share /Users/me/code:/workspace:ro \
  --cmdline "console=hvc0 root=/dev/vda rw quiet"
```

### Python CLI changes

The existing `safeyolo agent` commands are re-targeted:
- `agent add`: clone base rootfs → agent directory, save metadata
- `agent run`: invoke `safeyolo-vm run` with the right flags, ensure mitmproxy is running, ensure pf rules are loaded
- `agent stop`: signal `safeyolo-vm` to shut down
- `agent remove`: stop VM if running, delete rootfs + metadata

Docker-specific code (docker-compose rendering, Jinja2 templates, Docker network management) is removed.

### mitmproxy host launcher

New module that starts mitmproxy on the host (not in a container):
- Same addon chain, same load order, same options
- Certs generated/stored in `~/.safeyolo/certs/`
- Listens on `127.0.0.1:8080` (proxy) and `127.0.0.1:9090` (admin)
- Runs as a background process managed by the CLI (`safeyolo start`/`safeyolo stop`)

### service_discovery changes

Currently resolves Docker container IPs via reverse DNS. In the microVM world:
- CLI maintains a map of agent name → VM IP (written to a file or passed as an mitmproxy option)
- `service_discovery` addon reads from this map instead of Docker DNS
- Alternatively: the guest sets a custom header (e.g., `X-SafeYolo-Agent`) that the proxy reads — simpler, no IP tracking needed

## V1 Scope

### In scope
- macOS only (Apple Virtualization.framework)
- ARM64 guests only (Apple Silicon)
- Single proxy instance, multiple concurrent VMs
- Persistent agent disks
- VirtioFS workspace sharing
- pf-based network isolation
- Host-run mitmproxy with identical addon behaviour
- Guest image build script (Debian trixie + mise + node@22)
- Kernel build script (minimal ARM64)
- CLI commands: agent add/run/stop/remove, start/stop proxy
- Serial console for interactive agent sessions

### Out of scope (V2+)
- Linux host (KVM backend)
- x86_64 guests
- Guest snapshots / checkpoint / rebase
- WireGuard mode (if mitmproxy gains multi-peer support)
- Upstream corporate proxy chaining
- Non-HTTP protocol interception (raw TCP, UDP)
- OCI image import (converting Docker images to rootfs)
- Hot-resize (CPU, memory, disk) without restart

## Known V1 Limitations

1. **pf is the isolation boundary, not network topology.** A host-level misconfiguration (pf rules not loaded) would allow the VM to reach the internet directly. Mitigation: CLI validates pf rules are active before starting a VM.

2. **Non-HTTP traffic is not intercepted.** The proxy only sees HTTP/HTTPS through `HTTP_PROXY`/`HTTPS_PROXY`. Raw TCP connections from the guest are dropped by pf (which is correct — deny by default) but not logged. This is the same limitation as the current Docker setup.

3. **macOS only.** Linux KVM backend is deferred. The abstraction layer is designed to accommodate it, but V1 ships macOS/ARM64 only.

4. **No guest snapshot/rollback.** The persistent disk is mutable. If an agent corrupts its rootfs, the fix is to re-create the agent. Snapshots can be added later.

5. **VirtioFS performance.** Host-guest file sharing via VirtioFS may be slower than Docker bind mounts for large workspaces. Acceptable for coding agent workloads.

6. **ARM64 only.** Apple Silicon Macs only. Intel Macs cannot use Apple Virtualization.framework for Linux guests with acceptable performance.
