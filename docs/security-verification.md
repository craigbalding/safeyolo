# Security Verification

Evidence and verification procedures for SafeYolo's security claims. For the security model and properties, see [SECURITY.md](../SECURITY.md).

The [runtime reference](ARCHITECTURE.md#linux-runtime-and-storage) describes the
Linux user ID (UID) and group ID (GID) mappings and rootfs artifact model used
by the checks below.
The [security testing design](security-testing-design.md) distinguishes native
component, installed-package and actual-platform evidence. A procedure or test
inventory does not establish that a particular candidate passed.

## Proxy Process

The packaged Rust proxy runs as the operator's host process. The CLI starts
that executable and supplies its policy and listener configuration. The proxy
and the sandboxes have separate dependency and isolation boundaries.

### Proxy Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| Native host CLI and proxy dependencies | Locked in `proxy/Cargo.lock`; host bundles contain compiled Rust executables | [proxy/Cargo.toml](../proxy/Cargo.toml), [proxy/Cargo.lock](../proxy/Cargo.lock), [bundle build and installation](installation.md#build-a-bundle) |
| No root at runtime | Started by the operator, runs as the operator's uid | n/a |
| Bind address | IPv4 loopback Admin listener; per-agent Unix proxy listeners | [proxy/src/host_commands.rs](../proxy/src/host_commands.rs) |
| Admin API listener and gating | Host-local routes require the configured admin token | [proxy/src/admin_api.rs](../proxy/src/admin_api.rs) |
| Proxy management tokens absent from argv | The proxy receives configuration paths; the installed test checks that its command line contains neither the admin nor agent token | [host_commands.rs](../proxy/src/host_commands.rs), [test_firewall_structural.py](../tests/blackbox/host/security/test_firewall_structural.py) |

## Agent Sandbox

Each agent runs in an isolated sandbox with **no external network interface**.

| Platform | Runtime | Rootfs | Isolation |
|----------|---------|--------|-----------|
| macOS (Apple Silicon) | `safeyolo-vm` on Apple Virtualization.framework | per-agent ext4 disk image | Hardware-backed microVM |
| Linux (x86_64 / arm64) | `runsc` (gVisor) in an unprivileged user namespace | shared directory tree at `~/.safeyolo/share/rootfs-tree/` used as gVisor's OCI `root.path`; a temporary file-backed tmpfs overlay by default, or memory-backed with `rootfs_overlay = "memory"`; both lose rootfs writes on stop. Home, caches and the default-mode native scheduler spool use separate per-agent binds | Sentry-emulated kernel; optional KVM hardware platform |

### Sandbox Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| No external interface | Sandbox netns has only loopback (Linux); VM has no virtio-net (macOS) | [host_platform.rs](../proxy/src/host_platform.rs), [VM configuration](../vm/Sources/SafeYoloVM/VMConfiguration.swift) |
| Proxy-only egress | Guest localhost forwarder uses a private per-agent UDS mount on Linux and vsock on macOS | [host_boot.rs](../proxy/src/host_boot.rs), [platform bridges](networking-vsock-uds.md) |
| Connection identity | The per-agent Unix listener binds the selected agent identity to each connection | [host listener lifecycle](../proxy/src/host_commands.rs), [native listener](../proxy/src/lib.rs) |
| Rootless on Linux | `runsc` runs inside an unprivileged userns (`newuidmap`/`newgidmap`); no host sudo at agent launch | [proxy/src/host_platform.rs](../proxy/src/host_platform.rs) |
| Agent and guest-root identities | Starts as UID 1000; guest sudo intentionally reaches UID 0 for administration. Linux maps UID 1000 to the operator and UID 0 to the selected subordinate host UID, never host root; GIDs use their independently selected base. VZ contains guest root inside the microVM | [mapping owner](../proxy/src/linux_host.rs), [guest sudo](../guest/rootfs/safeyolo-sudo), [identity commands and containment tests](security-testing-design.md#security-observations) |
| Capability boundary | The default Linux OCI process has no CAP_SYS_ADMIN. The opt-in [nested Docker setting](nested-docker.md) adds guest CAP_SYS_ADMIN, namespace creation and virtual cgroups; its installed qualification is pending. Host authority remains bounded by the outer userns and gVisor | [proxy/src/host_boot.rs](../proxy/src/host_boot.rs) |
| Read-only config share | `/safeyolo` mounted `ro` | [proxy/src/host_boot.rs](../proxy/src/host_boot.rs) |
| Rootfs overlay (Linux) | Shared tree used as gVisor's OCI `root.path`; both the default file-backed tmpfs and `rootfs_overlay = "memory"` lose rootfs writes on stop. Default-mode cron/at queues persist through a separate per-agent spool bind. Memory mode omits that bind | [guest/build-rootfs.sh](../guest/build-rootfs.sh), [proxy/src/host_boot.rs](../proxy/src/host_boot.rs), [proxy/src/host_platform.rs](../proxy/src/host_platform.rs) |

### Build Verification

Build and install through [installation](installation.md#build-a-bundle),
with [prepared guest inputs](../guest/README.md). Supply their directory with
`--platform-assets DIRECTORY` at fresh install. On Linux keep the prepared
`share/rootfs-tree` available, immutable and owned by the selected subordinate UID/GID bases;
plain ownership-changing copies break this boundary. macOS uses the prepared
ext4 image, signed VM helper, kernel and initramfs.

Read the installed `package-info` file in the selected installation root for
source/profile/platform identity. Native installation verifies internal
checksums, native executables and guest receipts;
macOS additionally checks helper identity/signature. A rootfs tree is not one
hashable file; retain its production input provenance and inspect the actual
paths used by the owned native boot. Host build/install contains no first-party
Python command or wheel environment.

On the operator host, use the installed `safeyolo` on `PATH`. From any
directory, inspect the selected installation and an owned agent; replace
`NAME` with that agent's name. These commands report state:

```sh
safeyolo --version
safeyolo status
safeyolo doctor
safeyolo agent diagnostics NAME
```

These observations distinguish runtime/control/command and proxy state. They
are not by themselves isolation acceptance. Apply the actual
[host prerequisites](installation.md#guest-prerequisites), including AppArmor
and subordinate UID/GID mapping where required.

## Automated Security Testing

The [installed blackbox suite](../tests/blackbox/README.md) exercises the native
package and actual guests: gVisor on Linux and Apple Virtualization.framework
on macOS. Follow that reference for host prerequisites, retained inputs or a
contributor build, lane selection, reports and owned cleanup. Host-side proxy
and guest-side isolation tests observe different boundaries:

The [security model](../SECURITY.md#security-model) trusts the host-owned policy
file; agents cannot write it directly. The relevant policy assurance properties
are semantic permission deltas, cross-agent isolation, concurrent mutation
integrity and fail-closed behavior. Parser conformance alone does not establish
those properties.

Focused native policy command tests live in
[`test_native_policy_cli.py`](../tests/proxy_contracts/test_native_policy_cli.py).
Native [approval tests](../proxy/tests/approvals.rs) include scoped persistence,
activation rollback, invalid edits and concurrent writers. Native policy
decisions have separate Rust checks in [`proxy/tests/policy.rs`](../proxy/tests/policy.rs).
These focused examples do not establish generated transaction sequences,
multiprocess mutation races, coverage of every mutation/failure stage or abrupt
disposable-VM death.
Those broader assurance claims remain unproved.

**Host-side proxy tests** (`tests/blackbox/host/`):

| Test | Verifies |
|------|----------|
| Credential routing | API keys only forwarded to authorized hosts |
| Credential blocking | Exfiltration attempts blocked, sinkhole receives nothing |
| Access control | Allowed domains pass, rate limits enforced |
| Header stripping | Proxy-Authorization removed before forwarding |

**Guest-side isolation tests** (`tests/blackbox/isolation/`):

| Test | Verifies |
|------|----------|
| Guest-root containment | Ordinary macOS processes reject direct `setuid(0)`; guest sudo intentionally reaches root. Linux permits namespace-root with the selected subordinate mapping. Tests check read-only host shares, network, device and process isolation; the separate root pass checks host/config/key/device/filesystem/egress containment on the actual platform |
| Network isolation | Direct HTTP/HTTPS/DNS blocked, proxy-only egress |
| Kernel modules disabled | `init_module` syscall returns ENOSYS |
| No /dev/mem | Physical memory device does not exist |
| No eBPF | BPF syscall blocked |
| Private-key isolation | Fixture CA and operator host private keys are absent. Ordinary and root passes scan for unexpected private keys, allowing the test's listed guest SSH host-key paths and excluding its documented non-scan paths |
| Config share read-only | Agent cannot write to /safeyolo mount |

See [`test_vm_isolation.py`](../tests/blackbox/isolation/test_vm_isolation.py),
[`test_root_containment.py`](../tests/blackbox/isolation/test_root_containment.py)
and [`test_key_isolation.py`](../tests/blackbox/isolation/test_key_isolation.py).
Writable operator mounts can contain real data that the agent can change or
delete. Isolation acceptance does not make those writes harmless. A result on
one mechanism does not prove another; preserve each result's source, inputs,
actual platform and unexecuted assertions.

## Dependency Trust

The native host CLI, proxy and guest executables use
[proxy/Cargo.toml](../proxy/Cargo.toml) and [proxy/Cargo.lock](../proxy/Cargo.lock).
The root [pyproject.toml](../pyproject.toml) declares a non-package test
environment with no runtime dependencies. Its development and guest-test groups
are locked in [uv.lock](../uv.lock); they do not supply a shipped Python CLI.
The separate [acceptance-tool environment](../tools/acceptance/pyproject.toml)
has its own [lock](../tools/acceptance/uv.lock). Use the
[development setup](DEVELOPERS.md#development-setup) and
[acceptance tooling guidance](DEVELOPERS.md#acceptance-tooling) for those
environments and the [guest build reference](../guest/README.md) for guest OS
inputs. Audit each applicable exact closure at release time; source inventories
do not establish a current scan result. Missing supplemental scanner results
remain unknown coverage.

## Code Pointers

| Area | Location |
|------|----------|
| Native policy enforcement | [policy_runtime.rs](../proxy/src/policy_runtime.rs), [policy.rs](../proxy/src/policy.rs) |
| Credential detection and type mapping | [credential_guard.rs](../proxy/src/credential_guard.rs) |
| Credential vault | [credentials.rs](../proxy/src/credentials.rs) |
| HMAC fingerprinting | [credential_guard.rs](../proxy/src/credential_guard.rs); key loading in [credential_hmac.rs](../proxy/src/credential_hmac.rs) |
| Shannon entropy | [credential_guard.rs](../proxy/src/credential_guard.rs) |
| Budget tracking | [policy/budgets.rs](../proxy/src/policy/budgets.rs) |
| Circuit breaker | [circuits.rs](../proxy/src/circuits.rs) |
| Service gateway | [admin_api/gateway.rs](../proxy/src/admin_api/gateway.rs) |
| Admin API auth | [admin_api.rs](../proxy/src/admin_api.rs) |
| Request ID generation | [http.rs](../proxy/src/http.rs) |
| Request decision trace | [request_trace.rs](../proxy/src/request_trace.rs) |
| Request logging | [request_logger.rs](../proxy/src/request_logger.rs) |
| Proxy startup | [host_commands.rs](../proxy/src/host_commands.rs), [main.rs](../proxy/src/main.rs) |
| Blackbox tests | [tests/blackbox/](../tests/blackbox/) |
| Source drift and snapshot limits | [assurance.md](assurance.md) |
