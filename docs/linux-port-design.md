# Linux Port: gVisor Agent Runtime

> **Status** (exp/erofs-vz-phase-a): the rootfs format has changed.
> What this doc calls "EROFS" now is an **unpacked directory tree**
> at `~/.safeyolo/share/rootfs-tree/`, used as gVisor's OCI
> `root.path` directly (no packaging step). Rationale: gVisor's
> `--overlay2=root:dir=<path>` flag is silently ignored for tree
> root.path, so the overlay is memory-backed; disk-backed overlay
> was the EROFS-era design goal. The ext4 image for macOS VZ and
> the tree for Linux gVisor are built in one pass by
> `guest/build-rootfs.sh`. See `guest/README.md` for the current
> artifact layout. The rest of this file still describes the
> EROFS-era design verbatim for historical context.

## Context

SafeYolo runs on macOS using Apple's Virtualization.framework for agent
isolation. This design describes the Linux port, which uses gVisor (runsc)
to provide agent isolation on Linux servers — including VPS without KVM.

Same threat model: protect the host from a compromised AI coding agent.
Same blackbox tests: verify the security contract regardless of mechanism.

## Why gVisor

- Works on any Linux server — no KVM/nested virtualization required
- Auto-detects KVM when available (hardware-enforced isolation)
- Falls back to systrap (seccomp-bpf interception) on VPS without KVM
- Runs rootless — unprivileged user namespaces + `newuidmap`
  eliminate sudo at agent-run time entirely
- Used in production by Google Cloud Run, DigitalOcean, GKE Sandbox
- Google's Kubernetes Agent Sandbox project chose gVisor specifically
  for AI agent isolation
- Single binary (`runsc`), no Docker daemon required
- 7 CVEs since inception, none in the interception mechanism

## Architecture

```
macOS                                Linux
safeyolo-vm (Swift)                  runsc (gVisor) in unprivileged user namespace
  Virtualization.framework             KVM or systrap (auto-detected)
  no virtio-net, vsock → UDS bridge    loopback-only netns + per-agent UDS bind-mount
  VirtioFS mounts                      OCI bind mounts (workspace, config share, status share)
  SSH for agent shell                  runsc exec (direct process injection)
  guest-init.sh in VM                  guest-init.sh in gVisor sandbox (same script, same phases)
  ext4 image (block device)            shared EROFS image (read-only, memory-backed overlay)
  sudo for lo0 aliases                 zero sudo at runtime (rootless user namespace)
```

Both share:
- Same rootfs content (the filesystem tree)
- Same proxy integration (HTTP_PROXY env var → mitmproxy)
- Same CA cert trust model
- Same blackbox tests verifying the security contract

## What Changes per Platform

| Component | macOS | Linux |
|-----------|-------|-------|
| VM/sandbox launcher | `safeyolo-vm` (Swift) | `runsc` (Go binary) inside unprivileged user namespace |
| Networking | no virtio-net; vsock → UDS bridge (structural) | loopback-only netns + per-agent UDS bind-mount (structural) |
| Filesystem sharing | VirtioFS | OCI bind mounts |
| Rootfs format | per-agent ext4 image file | single shared EROFS image, mounted r/o by sentry with memory-backed overlay |
| Shell access | SSH via vsock shell-bridge UDS | `runsc exec` (no SSH needed) |
| Guest init | guest-init.sh (runs as PID 1 in VM) | guest-init.sh (runs as PID 1 inside sandbox — same script) |
| Kernel | Custom Linux kernel in VM | gVisor Sentry (userspace kernel) |
| KVM | N/A (Hypervisor.framework) | Optional, auto-detected; systrap fallback |
| Runtime privileges | none (sudo only if user opts into lo0 aliases, now unused) | none (rootless user namespace via `newuidmap`/`newgidmap`) |
| Identity attribution | PROXY protocol v2 header on bridge's upstream TCP | PROXY protocol v2 header on bridge's upstream TCP (same mechanism) |

## What Does NOT Change

- `config.py` — all paths platform-agnostic, SAFEYOLO_CONFIG_DIR works
- `proxy.py` — mitmproxy runs on host, same on both platforms
- Policy engine, addons, admin API — all host-side, platform-independent
- `run-tests.sh` — orchestration is the same
- `tests/blackbox/host/` — proxy tests run on host, no platform dependency
- `tests/blackbox/isolation/` — tests assert outcomes, not mechanisms
- Guest rootfs content — same packages, same user (agent, uid 1000)

## Platform Abstraction

Currently macOS code is hardcoded throughout vm.py, firewall.py, and
agent.py. The Linux port introduces a platform layer.

### Interface

```python
# cli/src/safeyolo/platform/__init__.py

class AgentPlatform(ABC):
    """Platform-specific agent lifecycle operations."""

    @abstractmethod
    def setup_networking(self, agent_index: int) -> NetworkAlloc:
        """Create network isolation for an agent.
        Returns allocation with host_ip, guest_ip, subnet, interface names."""

    @abstractmethod
    def teardown_networking(self, agent_index: int) -> None:
        """Remove network isolation for an agent."""

    @abstractmethod
    def load_firewall_rules(self, proxy_port: int, admin_port: int,
                            active_subnets: list[str]) -> None:
        """Load firewall rules allowing only proxy egress."""

    @abstractmethod
    def unload_firewall_rules(self) -> None:
        """Remove all firewall rules for this instance."""

    @abstractmethod
    def start_agent(self, name: str, config: AgentConfig) -> int:
        """Start an agent sandbox. Returns PID."""

    @abstractmethod
    def stop_agent(self, name: str) -> None:
        """Stop an agent sandbox."""

    @abstractmethod
    def exec_in_agent(self, name: str, command: str | None,
                      interactive: bool) -> int:
        """Execute a command in a running agent. Returns exit code."""

    @abstractmethod
    def is_agent_running(self, name: str) -> bool:
        """Check if an agent sandbox is running."""

    @abstractmethod
    def prepare_rootfs(self, name: str, base_rootfs: Path) -> Path:
        """Create agent rootfs from base. Returns rootfs path."""
```

### Platform Detection

```python
# cli/src/safeyolo/platform/__init__.py

import platform as _platform

def get_platform() -> AgentPlatform:
    system = _platform.system()
    if system == "Darwin":
        from .darwin import DarwinPlatform
        return DarwinPlatform()
    elif system == "Linux":
        from .linux import LinuxPlatform
        return LinuxPlatform()
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
```

### File Layout

```
cli/src/safeyolo/platform/
    __init__.py          # AgentPlatform ABC + get_platform()
    darwin.py            # macOS: Virtualization.framework + vsock UDS bridge
    linux.py             # Linux: rootless gVisor + loopback-only netns
```

`darwin.py` delegates VM lifecycle to `vm.py` and sets up the per-agent
shell bridge + lo0 alias for the attribution IP. `linux.py` is the gVisor
implementation.

## Linux Implementation Details

### gVisor Platform Auto-Detection

```python
def _detect_runsc_platform(self) -> str:
    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "kvm"
    return "systrap"
```

Passed to all runsc invocations: `runsc --platform=kvm|systrap ...`

### Rootless user namespace

runsc itself runs inside an unprivileged user namespace created via
`unshare -Un` and configured with `newuidmap`/`newgidmap`:

```
_start_userns(name):
    1. unshare -Un sleep 86400                 # the userns "holder"
    2. newuidmap holder_pid  0 100000 1000  1000 <operator_uid> 1  1001 101001 64534
    3. newgidmap holder_pid  (same shape)
    4. Persist holder pid so nsenter can re-enter the userns for
       subsequent runsc calls (exec, state, delete)
```

Result:
- Container uid 0 → host subordinate uid 100000 (the "sandbox root"
  that gVisor operates as)
- Container uid 1000 → host operator uid (the user launching
  agents; owns workspace, config share, etc.)

The operator launches agents with zero sudo. AppArmor on Ubuntu 24.04+
restricts unprivileged userns creation unless a profile allows it;
`safeyolo setup` installs `safeyolo-runsc` if needed.

### Networking (loopback-only netns + per-agent UDS)

Structural isolation, not policy-based:

```
setup_networking(agent_index):
    1. Allocate attribution IP 10.200.X.Y (within a /16 — agent index
       → deterministic IP; visible to both the operator and mitmproxy
       for log correlation)
    2. Signal needs_bridge_socket=True so agent.py coordinates with
       proxy_bridge to create the per-agent UDS before start_sandbox

(the sandbox's netns is the userns holder's netns; loopback only —
 no veth, no external IP, no routing)
```

The sandbox has no external network interface. The per-agent UDS at
`~/.safeyolo/data/sockets/<name>.sock` is bind-mounted into the sandbox
at `/safeyolo/proxy.sock` (via `runsc --host-uds=open`); the in-guest
forwarder relays HTTP to it, and `proxy_bridge` stamps a PROXY
protocol v2 header carrying the attribution IP on upstream TCP.
mitmproxy's `next_layer` addon parses the header and rewrites
`client_conn.peername` so every flow is attributed to the right agent.

No iptables rules, no firewall, no netfilter state. The sandbox has
nowhere to leak to; misconfiguration scenarios have been engineered
out rather than guarded by rules.

`SAFEYOLO_SUBNET_BASE` (default 65) offsets the attribution-IP slot
so a second instance (blackbox test harness or per-operator dev)
doesn't collide with production's allocation.

### Rootfs (shared EROFS image)

macOS per-agent ext4 images are cloned via APFS reflink. Linux ships
a single read-only EROFS image built by `guest/build-rootfs.sh`:

```
share_dir/rootfs-base.erofs       # ~400MB, mounted r/o by gVisor sentry
```

gVisor mounts the EROFS image internally (via `--overlay-filestores`
annotations in the OCI spec) and provides a memory-backed writable
overlay to every sandbox. No per-agent on-disk overlays; no
fuse-overlayfs; no boot-time chown loop.

Benefits:
- Instant agent creation (no copy, no extraction)
- Zero disk per agent for the rootfs itself — persistent state
  (config share, status share) is the only on-disk footprint
- Ownership is handled at image-build time; no runtime chown fix-ups

EROFS build flags: `-E noinline_data` is required (gVisor's EROFS
reader rejects inline-data layouts). Compression is off for the same
reason — gVisor's `FeatureIncompatSupported` is 0x0, rejecting any
non-zero incompat features.

### OCI Config

The OCI runtime spec declares the sandbox shape: entrypoint is
`/bin/bash -c "... exec /safeyolo/guest-init ..."`, running as uid
0 initially so `guest-init-static.sh` can configure networking,
trust the CA, launch sshd (macOS) or skip (Linux), and then drop
to the agent user. Key fields:

- `process.user`: `{uid: 0, gid: 0}` — init runs as root-in-sandbox
  (mapped to host uid 100000 via the userns); `guest-init-per-run.sh`
  drops to uid 1000 via `su agent -l` before launching the agent
- `process.capabilities`: only what init needs (CAP_CHOWN,
  CAP_DAC_OVERRIDE, CAP_NET_ADMIN to configure loopback, CAP_SETUID,
  CAP_SETGID) — no CAP_NET_RAW, no CAP_SYS_ADMIN
- `mounts`: workspace (rw), `/safeyolo` (ro, the config share),
  `/safeyolo-status` (rw, the status share for guest→host signals),
  `/safeyolo/proxy.sock` (rw, the per-agent UDS)
- `linux.namespaces`: PID, IPC, UTS, mount — and a `network` namespace
  path pointing at the userns holder's netns (`/proc/<holder>/ns/net`),
  so the sandbox's network is the loopback-configured netns we set up
- EROFS annotations pointing runsc at `rootfs-base.erofs`

### Agent Lifecycle

```
start_sandbox(name, ...):
    1. _start_userns(name)                          # unshare -Un sleep + newuidmap
    2. Write OCI config.json with netns_path =
       /proc/<userns_holder_pid>/ns/net
    3. nsenter <userns> runsc --root <root> create/start safeyolo-<name>
    4. Wrap the whole thing in systemd-run --user --scope for cgroup limits

stop_sandbox(name):
    1. nsenter <userns> runsc kill safeyolo-<name> SIGTERM; wait 5s
    2. nsenter <userns> runsc kill --all SIGKILL; wait 1s
    3. nsenter <userns> runsc delete --force
    4. Clean /tmp/runsc-<cid>.sock (owned by subordinate uid 100000)
    5. _kill_userns(name)

exec_in_sandbox(name, command, user):
    nsenter <userns> runsc exec --user <uid>:<gid> --cwd /workspace \
        safeyolo-<name> /bin/bash -lc "<command>"

is_sandbox_running(name):
    state = nsenter <userns> runsc state safeyolo-<name>
    return state["status"] == "running"
```

The nsenter wrapping is necessary for every runsc call because the
runsc state directory is owned by uid 100000 (the subordinate root);
without nsenter into the userns, the operator (uid 1000 on the host)
can't read it.

### Shell Access (runsc exec vs SSH)

On macOS, `safeyolo agent shell` uses SSH because the VM has its own
kernel and network stack. On Linux, `runsc exec` injects a process
directly — no SSH, no network round-trip, no key management.

For non-interactive commands (`-c "uname -a"`):
```
runsc exec --user 1000:1000 --cwd /home/agent/workspace safeyolo-<name> -- /bin/bash -c "uname -a"
```

For interactive shell:
```
runsc exec --user 1000:1000 safeyolo-<name> -- /bin/bash -l
```

The `safeyolo agent shell` command detects the platform and dispatches:
- macOS → SSH
- Linux → runsc exec

## Guest init

Both platforms run the same `guest-init.sh` orchestrator inside the
sandbox as PID 1. The Linux path is the same logic as macOS — there
was an earlier design that tried to push everything into the OCI
config, but shared logic (CA trust, mise install, agent launch) is
easier to keep in one script that runs in both environments. The
OCI spec handles the surrounding plumbing (mounts, user, env, caps).

What's different on Linux:
- No sshd or SSH host keys (runsc exec is the shell channel)
- VirtioFS mounts are no-ops (OCI bind-mounts already in place;
  `mountpoint -q /workspace` detects this and skips the mount)
- CAP_NET_ADMIN is granted only to configure loopback's attribution
  IP at boot, nothing else

## Security Properties (Blackbox Test Mapping)

Every blackbox isolation test maps to a property of the runtime:

| Test | macOS mechanism | Linux/gVisor mechanism |
|------|----------------|----------------------|
| Direct HTTP/HTTPS/DNS blocked | VM has no external interface | sandbox has no external interface (loopback-only netns) |
| Raw socket blocked | VM kernel lacks CAP_NET_RAW | gVisor Sentry blocks SOCK_RAW without the cap |
| Proxy reachable | vsock → host UDS → mitmproxy | bind-mounted UDS → mitmproxy |
| Non-root (uid 1000) | VM runs as agent user | OCI config user.uid=1000; userns maps to operator uid |
| Cannot gain root | setuid(0) in VM kernel fails | Sentry blocks setuid(0); noNewPrivileges set |
| Kernel modules disabled | CONFIG_MODULES=n | gVisor: init_module returns ENOSYS |
| No /dev/mem or /dev/kmem | VM kernel doesn't expose | gVisor's /dev doesn't include them |
| No eBPF | VM kernel blocks BPF | gVisor: BPF syscall not implemented |
| Config share read-only | VirtioFS remount ro | Bind mount with "ro" option |
| Host listener unreachable | no network path out of VM | no network path out of sandbox's netns |
| Public cert trusted | VirtioFS bind + update-ca-certificates | OCI bind mount + update-ca-certificates |

The test files (`test_vm_isolation.py`, `test_key_isolation.py`) run
unchanged. They test outcomes, not mechanisms. See
[docs/blackbox-coverage.md](blackbox-coverage.md) for the full
test list with threat mapping.

The test files (`test_vm_isolation.py`, `test_key_isolation.py`) run
unchanged. They test outcomes, not mechanisms.

## Dependencies

**Host requirements:**
- Linux kernel 4.14.77+ (for seccomp-bpf)
- `runsc` binary (single Go binary, ~30MB)
- `newuidmap`/`newgidmap` (from `uidmap` on Debian/Ubuntu)
- Subordinate uid/gid range for the operator in `/etc/subuid` and
  `/etc/subgid` (provisioned by default on modern Debian/Ubuntu)
- `iproute2` (ip command, standard)
- `systemd-run --user` (for cgroup resource limits via delegation)

**One-time setup** (idempotent, applied by `safeyolo setup`):
- AppArmor profile `safeyolo-runsc` — only needed if the kernel has
  `apparmor_restrict_unprivileged_userns=1` (Ubuntu 24.04+)
- udev rule `/etc/udev/rules.d/99-safeyolo-kvm.rules` granting the
  subordinate uid access to `/dev/kvm` (only when KVM is available
  and hardware isolation is desired; systrap fallback needs no ACL)

**Not required:**
- Docker / containerd / podman
- KVM / nested virtualization (used when available; systrap otherwise)
- Any daemon process
- Sudo at agent-run time (setup is the only sudo step, and it's
  one-time per host)

**Install runsc:**
```bash
# Debian/Ubuntu
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt update && sudo apt install -y runsc uidmap
```

## Implementation Status

All sections above describe the implemented design on the
`feat/proxy-protocol-identity` branch / master (pre-v1). Key
decisions that landed differently from the original plan:

- **No iptables.** Earlier drafts described iptables as a belt-and-
  braces guard. Structural isolation (no external interface) made
  firewall rules redundant, and the netfilter state was removed to
  simplify the architecture.
- **Rootless user namespaces instead of sudo.** The original design
  assumed sudoers for `ip netns add` / `ip link` / mount. The final
  design eliminates sudo at runtime entirely by running gVisor
  inside an unprivileged userns.
- **Shared EROFS image instead of overlayfs.** The per-agent
  overlayfs design was replaced by a single read-only EROFS image
  with gVisor's sentry providing memory-backed writable overlays.
  Zero per-agent disk for rootfs; no boot-time uid fix-ups.
- **Same guest-init.sh on both platforms.** The plan to replace
  guest-init with OCI config lost out to keeping a single source
  of truth for CA trust, mise install, and agent launch.
- **PROXY protocol v2 for identity.** Earlier designs used per-agent
  bridge source ports bound to synthetic 127.0.0.X IPs (macOS lo0
  aliases, Linux attribution IPs) with mitmproxy looking them up.
  Final design uses a standard PROXY-v2 header parsed by an addon —
  cross-platform, no sudo needed on macOS, no lo0 aliasing.
