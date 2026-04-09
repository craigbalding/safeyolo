# Linux Port: gVisor Agent Runtime

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
- Used in production by Google Cloud Run, DigitalOcean, GKE Sandbox
- Google's Kubernetes Agent Sandbox project chose gVisor specifically
  for AI agent isolation
- Single binary (`runsc`), no Docker daemon required
- 7 CVEs since inception, none in the interception mechanism

## Architecture

```
macOS (current)                     Linux (new)
safeyolo-vm (Swift)                 runsc (gVisor)
  Virtualization.framework            KVM or systrap (auto-detected)
  feth pairs + pf                     veth pairs + netns + iptables
  VirtioFS mounts                     bind mounts
  SSH for agent shell                 runsc exec (direct process injection)
  guest-init.sh in VM                 OCI config.json (no guest init needed)
  ext4 image (block device)           overlayfs (directory-based)
```

Both share:
- Same rootfs content (the filesystem tree)
- Same proxy integration (HTTP_PROXY env var → mitmproxy)
- Same CA cert trust model
- Same blackbox tests verifying the security contract

## What Changes per Platform

| Component | macOS | Linux |
|-----------|-------|-------|
| VM/sandbox launcher | `safeyolo-vm` (Swift) | `runsc` (Go binary) |
| Networking | feth pairs + pf anchors | veth pairs + netns + iptables |
| Filesystem sharing | VirtioFS | bind mounts |
| Rootfs format | ext4 image file | overlayfs (extracted dir) |
| Shell access | SSH over network | `runsc exec` (no SSH needed) |
| Guest init | guest-init.sh (runs in VM) | Not needed (OCI config.json) |
| Kernel | Custom Linux kernel in VM | gVisor Sentry (userspace kernel) |
| KVM | N/A (Hypervisor.framework) | Optional, auto-detected |

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
    darwin.py            # macOS: Virtualization.framework + feth + pf
    linux.py             # Linux: gVisor + veth + iptables
```

`darwin.py` wraps the existing code from vm.py and firewall.py.
`linux.py` is the new implementation.

## Linux Implementation Details

### gVisor Platform Auto-Detection

```python
def _detect_runsc_platform(self) -> str:
    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "kvm"
    return "systrap"
```

Passed to all runsc invocations: `runsc --platform=kvm|systrap ...`

### Networking (veth + netns + iptables)

Equivalent of macOS feth + pf, using Linux kernel primitives:

```
setup_networking(agent_index):
    1. ip netns add safeyolo-<name>
    2. ip link add veth-<name> type veth peer name eth0
    3. ip link set eth0 netns safeyolo-<name>
    4. Configure IPs (same 192.168.X.0/24 scheme as macOS)
    5. Enable IP forwarding

load_firewall_rules():
    1. iptables -A FORWARD -i veth-<name> -d <host_ip> -p tcp --dport <proxy_port> -j ACCEPT
    2. iptables -A FORWARD -i veth-<name> -j DROP
    3. iptables -t nat -A POSTROUTING -s <subnet> -o <outbound_if> -j MASQUERADE

teardown_networking(agent_index):
    1. ip netns delete safeyolo-<name>  (removes veth pair automatically)
    2. Remove iptables rules
```

The SAFEYOLO_SUBNET_BASE and SAFEYOLO_PF_ANCHOR (renamed to
SAFEYOLO_FW_CHAIN for Linux) env vars scope these for multi-instance
isolation, same as the macOS implementation.

### Rootfs (overlayfs)

macOS clones ext4 images via APFS reflink. Linux uses overlayfs for
the same CoW semantics:

```
prepare_rootfs(name):
    # One-time: extract base rootfs from ext4 image
    if not base_dir.exists():
        mount -o loop,ro rootfs-base.ext4 /tmp/mnt
        cp -a /tmp/mnt/. <share_dir>/rootfs-base/
        umount /tmp/mnt

    # Per agent: overlayfs
    mkdir -p agents/<name>/{upper,work,rootfs}
    mount -t overlay overlay \
        -o lowerdir=<share>/rootfs-base,upperdir=agents/<name>/upper,workdir=agents/<name>/work \
        agents/<name>/rootfs
```

Benefits:
- Instant agent creation (no copy)
- Minimal disk (only changed files stored in upper)
- Base rootfs shared read-only across all agents

### OCI Config Generation

Instead of guest-init.sh configuring the environment inside a VM,
the OCI config.json declares everything up front:

```python
def _generate_oci_config(self, name: str, config: AgentConfig) -> dict:
    return {
        "ociVersion": "1.0.0",
        "root": {"path": "rootfs", "readonly": False},
        "hostname": f"safeyolo-{name}",
        "process": {
            "terminal": False,
            "user": {"uid": 1000, "gid": 1000},
            "args": ["/bin/sleep", "infinity"],  # init process, agent shell attaches later
            "env": [
                f"HTTP_PROXY=http://{config.host_ip}:{config.proxy_port}",
                f"HTTPS_PROXY=http://{config.host_ip}:{config.proxy_port}",
                "HOME=/home/agent",
                "PATH=/opt/mise/shims:/usr/local/bin:/usr/bin:/bin",
                ...
            ],
            "cwd": "/home/agent",
            "noNewPrivileges": True,
            "capabilities": {
                # Minimal capabilities — no NET_RAW, no SYS_ADMIN
                "bounding": ["CAP_KILL", "CAP_NET_BIND_SERVICE"],
                ...
            },
        },
        "mounts": [
            {"destination": "/home/agent/workspace", "type": "bind",
             "source": config.workspace_path, "options": ["rbind", "rw"]},
            {"destination": "/safeyolo", "type": "bind",
             "source": config.config_share_path, "options": ["rbind", "ro"]},
            {"destination": "/usr/local/share/ca-certificates/safeyolo.crt",
             "type": "bind", "source": config.ca_cert_path,
             "options": ["bind", "ro"]},
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "network", "path": f"/var/run/netns/safeyolo-{name}"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
            ],
            "resources": {
                "memory": {"limit": config.memory_bytes},
                "cpu": {"quota": config.cpu_quota, "period": 100000},
                "pids": {"limit": 4096},
            },
        },
    }
```

### Agent Lifecycle

```
start_agent(name, config):
    1. Generate OCI config.json
    2. runsc --root /run/safeyolo --platform=<auto> create --bundle <path> safeyolo-<name>
    3. runsc start safeyolo-<name>
    4. Write PID file from runsc state

stop_agent(name):
    1. runsc kill safeyolo-<name> SIGTERM
    2. Wait 10s
    3. runsc kill --all safeyolo-<name> SIGKILL
    4. runsc delete safeyolo-<name>
    5. Teardown networking
    6. Unmount overlayfs

exec_in_agent(name, command, interactive):
    if command:
        runsc exec --user 1000:1000 safeyolo-<name> -- /bin/bash -c "<command>"
    else:
        runsc exec --user 1000:1000 safeyolo-<name> -- /bin/bash -l

is_agent_running(name):
    state = runsc state safeyolo-<name>
    return state["status"] == "running"
```

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

## What guest-init.sh Did That OCI Config.json Replaces

| guest-init.sh step | Linux equivalent |
|---------------------|-----------------|
| Read network.env, configure IP | netns + veth created externally |
| Source proxy.env | process.env in config.json |
| Trust CA cert | Bind mount cert into trust store path |
| Install SSH keys | Not needed (runsc exec) |
| Start sshd | Not needed |
| Write vm-ip | runsc state returns container info |
| Remount /safeyolo ro | Mount option "ro" in config.json |
| Run agent binary | process.args in config.json |

## Security Properties (Blackbox Test Mapping)

Every blackbox isolation test maps to a gVisor property:

| Test | macOS mechanism | Linux/gVisor mechanism |
|------|----------------|----------------------|
| Direct HTTP blocked | pf blocks non-proxy | iptables blocks non-proxy |
| Direct HTTPS blocked | pf blocks non-proxy | iptables blocks non-proxy |
| DNS UDP blocked | pf blocks all non-proxy | iptables blocks all non-proxy |
| Raw socket blocked | VM kernel has no route | gVisor Sentry blocks SOCK_RAW |
| Proxy reachable | pf allows proxy port | iptables allows proxy port |
| Non-root (uid 1000) | VM runs as agent user | OCI config.json user.uid=1000 |
| Cannot gain root | setuid(0) in VM kernel | setuid(0) in Sentry — noNewPrivileges |
| Kernel modules disabled | CONFIG_MODULES=n | gVisor: init_module returns ENOSYS |
| No /dev/mem | CONFIG_DEVMEM=n | gVisor: /dev/mem not exposed |
| No /dev/kmem | Not in VM | gVisor: /dev/kmem not exposed |
| No eBPF | VM kernel blocks BPF | gVisor: BPF syscall not implemented |
| Config share read-only | VirtioFS remount ro | Bind mount with "ro" option |
| No private keys | Keys outside workspace | Keys outside workspace |
| Public cert present | VirtioFS mount | Bind mount |

The test files (`test_vm_isolation.py`, `test_key_isolation.py`) run
unchanged. They test outcomes, not mechanisms.

## Dependencies

**Host requirements:**
- Linux kernel 4.14.77+ (for seccomp-bpf)
- `runsc` binary (single Go binary, ~30MB)
- `iptables` or `nftables` (standard on all distros)
- `iproute2` (ip command, standard)
- Root or sudo for networking setup (same as macOS)

**Not required:**
- Docker / containerd / podman
- KVM / nested virtualization (used when available, not required)
- Any daemon process

**Install runsc:**
```bash
# Debian/Ubuntu
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt update && sudo apt install -y runsc

# Or direct download
wget https://storage.googleapis.com/gvisor/releases/release/latest/$(uname -m)/runsc
chmod +x runsc && sudo mv runsc /usr/local/bin/
```

## Implementation Order

1. **Platform abstraction** — create `platform/` package with ABC,
   extract macOS code into `darwin.py`, update agent.py to use the
   abstraction
2. **Linux networking** — `linux.py` networking: veth + netns + iptables
3. **Linux rootfs** — overlayfs setup, base rootfs extraction
4. **Linux sandbox** — OCI config.json generation, runsc lifecycle
5. **Linux shell** — `runsc exec` for `safeyolo agent shell`
6. **Blackbox tests on Linux** — run the existing test suite, fix any
   platform-specific assumptions
7. **Documentation** — install guide, platform comparison, security model

Step 1 is the riskiest — refactoring existing working code. Steps 2-5
are additive (new code, no macOS regression risk). Step 6 validates
everything.

## Open Questions

1. **Sudoers on Linux** — networking needs root. Ship a sudoers template
   like macOS, or use rootless networking (slirp4netns)?
2. **cgroup v1 vs v2** — resource limits differ. Most modern distros use
   v2 but some VPS providers still use v1. Need detection.
3. **Fallback without gVisor** — should we support plain runc as a
   third tier? Weaker isolation but zero dependencies beyond the kernel.
   The blackbox tests would show exactly which properties hold.
4. **x86_64 rootfs** — current rootfs is aarch64. Need x86_64 build
   for most VPS. The `build-rootfs.sh` already runs in a container
   so cross-compilation is straightforward with `--platform linux/amd64`.
