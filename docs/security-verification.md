# Security Verification

Evidence and verification procedures for SafeYolo's security claims. For the security model and properties, see [SECURITY.md](../SECURITY.md).

The [runtime reference](ARCHITECTURE.md#linux-runtime-and-storage) describes the
Linux UID mapping and rootfs artifact model used by the checks below.

## Proxy Process

The packaged Rust proxy runs as the operator's host process. The CLI starts
that executable and supplies its policy and listener configuration. The proxy
and the sandboxes have separate dependency and isolation boundaries.

### Proxy Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| Python CLI deps | Locked with hashes in `uv.lock` (`--frozen`) | [uv.lock](../uv.lock) |
| Native proxy deps | Locked in `proxy/Cargo.lock`; the installer builds the packaged executable | [proxy/Cargo.lock](../proxy/Cargo.lock), [install.sh](../install.sh) |
| No root at runtime | Started by the operator, runs as the operator's uid | n/a |
| Bind address | IPv4 loopback Admin listener; per-agent Unix proxy listeners | [proxy/src/host_commands.rs](../proxy/src/host_commands.rs) |
| Admin API listener and gating | Native host-local routes require the configured admin token | [proxy/src/admin_api.rs](../proxy/src/admin_api.rs) |
| Tokens never in argv | Tokens passed via file paths / env vars, not CLI args | [tests/blackbox/host/security/test_firewall_structural.py](../tests/blackbox/host/security/test_firewall_structural.py) |

## Agent Sandbox

Each agent runs in an isolated sandbox with **no external network interface**.

| Platform | Runtime | Rootfs | Isolation |
|----------|---------|--------|-----------|
| macOS (Apple Silicon) | `safeyolo-vm` on Apple Virtualization.framework | per-agent ext4 disk image | Hardware-backed microVM |
| Linux (x86_64 / arm64) | `runsc` (gVisor) in an unprivileged user namespace | shared directory tree at `~/.safeyolo/share/rootfs-tree/` used as gVisor's OCI `root.path`; a per-agent file-backed overlay persists across stop and run by default; `rootfs_overlay = "memory"` selects a memory-backed overlay that is discarded on stop | Sentry-emulated kernel; optional KVM hardware platform |

### Sandbox Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| No external interface | Sandbox netns has only loopback (Linux); VM has no virtio-net (macOS) | [proxy/src/host_platform.rs](../proxy/src/host_platform.rs), [proxy/src/host_platform.rs](../proxy/src/host_platform.rs) |
| Only egress = proxy UDS | Private per-agent directory mounted read-only at `/safeyolo/proxy`, containing `proxy.sock` | [proxy/src/host_boot.rs](../proxy/src/host_boot.rs) |
| Identity on every flow | The native per-agent Unix listener binds the selected agent identity to each connection | [proxy/src/main.rs](../proxy/src/main.rs), [proxy/src/policy_runtime.rs](../proxy/src/policy_runtime.rs) |
| Rootless on Linux | `runsc` runs inside an unprivileged userns (`newuidmap`/`newgidmap`); zero sudo at agent-run time | [proxy/src/host_platform.rs](../proxy/src/host_platform.rs) |
| Agent and guest-root identities | Starts as uid 1000; Linux may intentionally enter sandbox uid 0 for package installation. Userns maps uid 1000 to the operator and uid 0 to subordinate host uid 100000, never host root | [proxy/src/host_platform.rs](../proxy/src/host_platform.rs) |
| Capability boundary | The Linux OCI process receives the capabilities needed for guest init and namespace-root package management, but no CAP_SYS_ADMIN; host authority remains bounded by the outer userns and gVisor | [proxy/src/host_platform.rs](../proxy/src/host_platform.rs) |
| Read-only config share | `/safeyolo` mounted `ro` | [proxy/src/host_boot.rs](../proxy/src/host_boot.rs) |
| Rootfs overlay (Linux) | Shared directory tree at `~/.safeyolo/share/rootfs-tree/` used as gVisor's OCI `root.path`; the default per-agent file-backed overlay persists across stop and run; `rootfs_overlay = "memory"` selects a memory-backed overlay that is discarded on stop | [guest/build-rootfs.sh](../guest/build-rootfs.sh), [proxy/src/host_platform.rs](../proxy/src/host_platform.rs) |

### Build Verification

Build and install through [native installation](native-policy.md#build-a-native-bundle),
with [prepared guest inputs](../guest/README.md). Supply their directory with
`--platform-assets DIRECTORY` at fresh install. On Linux keep the prepared
`share/rootfs-tree` available, immutable and owned by sandbox root UID 100000;
plain ownership-changing copies break this boundary. macOS uses the prepared
ext4 image, signed VM helper, kernel and initramfs.

Read `package-info` for installed source/profile/platform identity. Native
installation verifies internal checksums, native executables and guest receipts;
macOS additionally checks helper identity/signature. A rootfs tree is not one
hashable file; retain its production input provenance and inspect the actual
paths used by the owned native boot. Host build/install contains no first-party
Python command or wheel environment.

```sh
safeyolo --version
safeyolo status
safeyolo doctor
safeyolo agent diagnostics NAME
```

These observations distinguish runtime/control/command and proxy state. They
are not by themselves isolation acceptance. Apply the actual
[host prerequisites](native-policy.md#guest-prerequisites), including AppArmor
and subordinate UID/GID mapping where required. The retired Python setup
command is not an installed operation.

## Automated Security Testing

The [blackbox test suite](../tests/blackbox/) verifies SafeYolo's security guarantees end-to-end using real microVMs. Tests are split across two domains:

Policy-file assurance is scoped separately in
[Policy File Assurance: Threat-Model Decision](policy-assurance-threat-model.md).
Because agents cannot directly write the host-owned policy file, that strategy
prioritizes semantic permission deltas, cross-agent isolation, concurrent
mutation integrity, and fail-closed behavior over generic parser fuzzing.

The current tree retains focused policy command and transaction tests in
`tests/proxy_contracts/test_native_policy_cli.py` and `tests/test_policy_transaction_regressions.py`.
Native policy decisions have separate Rust checks in `proxy/tests/policy.rs`.
These checks do not replace generated native transaction sequences, concurrent
mutations, failure-stage injection, or abrupt disposable-VM death. Those
assurance claims remain open for the post-deletion release candidate.

The pre-cutover `tools.policy_chaos` runner, its `tests/test_policy_chaos.py`
checks, and its scheduled workflow were retired because they import the removed
Python policy engine and proxy addons. The historical runner and experiment
sources remain available from the pinned pre-cutover checkout
`2ca598ce11d7c375a024b38eb3e7b4104a795d84`. Run them only with that
checkout's locked Python environment. Their results cannot establish native
policy behavior for the current release candidate. The former acceptance-graph
route now reports a coverage gap when generated native policy assurance is
material.

**Host-side proxy tests** (`tests/blackbox/host/`):

| Test | Verifies |
|------|----------|
| Credential routing | API keys only forwarded to authorized hosts |
| Credential blocking | Exfiltration attempts blocked, sinkhole receives nothing |
| Access control | Allowed domains pass, rate limits enforced |
| Header stripping | Proxy-Authorization removed before forwarding |

**VM-side isolation tests** (`tests/blackbox/isolation/`):

| Test | Verifies |
|------|----------|
| Guest-root containment | macOS rejects direct `setuid(0)`; Linux permits namespace-root but verifies its subordinate host uid mapping, read-only host shares, host network isolation, device isolation, and PID isolation |
| Network isolation | Direct HTTP/HTTPS/DNS blocked, proxy-only egress |
| Kernel modules disabled | `init_module` syscall returns ENOSYS |
| No /dev/mem | Physical memory device does not exist |
| No eBPF | BPF syscall blocked |
| Key isolation | No private key material anywhere in the VM filesystem |
| Config share read-only | Agent cannot write to /safeyolo mount |

See [`test_vm_isolation.py`](../tests/blackbox/isolation/test_vm_isolation.py) and [`test_key_isolation.py`](../tests/blackbox/isolation/test_key_isolation.py).

## Dependency Trust

The 2026-01-05 dependency ratings covered the pre-cutover implementation.

The current Python CLI dependency set is declared in
[pyproject.toml](../pyproject.toml) and locked in [uv.lock](../uv.lock). The
native proxy dependency set is declared in [proxy/Cargo.toml](../proxy/Cargo.toml)
and locked in [proxy/Cargo.lock](../proxy/Cargo.lock). The removed mitmproxy,
tenacity, and confusable-homoglyphs dependencies are outside this cutover
candidate's runtime closure. Audit the exact locked closure at release time;
the historical dependency ratings do not establish a current scan result.

## Code Pointers

| Area | Location |
|------|----------|
| Native policy enforcement | [policy_runtime.rs](../proxy/src/policy_runtime.rs), [policy.rs](../proxy/src/policy.rs) |
| Credential detection | [credentials.rs](../proxy/src/credentials.rs), [proxy/src/policy.rs](../proxy/src/policy.rs) |
| Credential type mapping | [credentials.rs](../proxy/src/credentials.rs) |
| HMAC fingerprinting | [credential_hmac.rs](../proxy/src/credential_hmac.rs) |
| Shannon entropy | [credentials.rs](../proxy/src/credentials.rs) |
| Budget tracking | [policy/budgets.rs](../proxy/src/policy/budgets.rs) |
| Circuit breaker | [circuits.rs](../proxy/src/circuits.rs) |
| Service gateway | [admin_api/gateway.rs](../proxy/src/admin_api/gateway.rs) |
| Admin API auth | [admin_api.rs](../proxy/src/admin_api.rs) |
| Request ID | [request_trace.rs](../proxy/src/request_trace.rs) |
| Request logging | [request_logger.rs](../proxy/src/request_logger.rs) |
| Native proxy startup | [host_commands.rs](../proxy/src/host_commands.rs), [main.rs](../proxy/src/main.rs) |
| Blackbox tests | [tests/blackbox/](../tests/blackbox/) |
| Policy assurance threat model | [policy-assurance-threat-model.md](policy-assurance-threat-model.md) |
