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
| Bind address | Loopback by default; listen host configurable | [cli/src/safeyolo/proxy.py](../cli/src/safeyolo/proxy.py) |
| Admin API listener and gating | Native host-local routes require the configured admin token | [proxy/src/admin_api.rs](../proxy/src/admin_api.rs) |
| Tokens never in argv | Tokens passed via file paths / env vars, not CLI args | [tests/blackbox/host/security/test_firewall_structural.py](../tests/blackbox/host/security/test_firewall_structural.py) |

## Agent Sandbox

Each agent runs in an isolated sandbox with **no external network interface**.

| Platform | Runtime | Rootfs | Isolation |
|----------|---------|--------|-----------|
| macOS (Apple Silicon) | `safeyolo-vm` on Apple Virtualization.framework | per-agent ext4 disk image | Hardware-backed microVM |
| Linux (x86_64 / arm64) | `runsc` (gVisor) in an unprivileged user namespace | shared directory tree at `~/.safeyolo/share/rootfs-tree/` used as gVisor's OCI `root.path`; a per-agent file-backed overlay persists across stop and run by default; `--ephemeral` selects a memory-backed overlay that is discarded on stop | Sentry-emulated kernel; optional KVM hardware platform |

### Sandbox Hardening

| Aspect | Implementation | Where |
|--------|----------------|-------|
| No external interface | Sandbox netns has only loopback (Linux); VM has no virtio-net (macOS) | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py), [cli/src/safeyolo/platform/darwin.py](../cli/src/safeyolo/platform/darwin.py) |
| Only egress = proxy UDS | Private per-agent directory mounted read-only at `/safeyolo/proxy`, containing `proxy.sock` | [cli/src/safeyolo/sockets.py](../cli/src/safeyolo/sockets.py) |
| Identity on every flow | The native per-agent Unix listener binds the selected agent identity to each connection | [proxy/src/main.rs](../proxy/src/main.rs), [proxy/src/policy_runtime.rs](../proxy/src/policy_runtime.rs) |
| Rootless on Linux | `runsc` runs inside an unprivileged userns (`newuidmap`/`newgidmap`); zero sudo at agent-run time | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Agent and guest-root identities | Starts as uid 1000; Linux may intentionally enter sandbox uid 0 for package installation. Userns maps uid 1000 to the operator and uid 0 to subordinate host uid 100000, never host root | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Capability boundary | The Linux OCI process receives the capabilities needed for guest init and namespace-root package management, but no CAP_SYS_ADMIN; host authority remains bounded by the outer userns and gVisor | [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |
| Read-only config share | `/safeyolo` mounted `ro` | [cli/src/safeyolo/vm.py](../cli/src/safeyolo/vm.py) |
| Rootfs overlay (Linux) | Shared directory tree at `~/.safeyolo/share/rootfs-tree/` used as gVisor's OCI `root.path`; the default per-agent file-backed overlay persists across stop and run; `--ephemeral` selects a memory-backed overlay that is discarded on stop | [guest/build-rootfs.sh](../guest/build-rootfs.sh), [cli/src/safeyolo/platform/linux.py](../cli/src/safeyolo/platform/linux.py) |

### Build Verification

Build everything from source (no pre-built images):

```bash
# Build the guest rootfs and kernel artefacts
cd guest && ./build-all.sh && cd ..
# `sudo cp -a` preserves the uid-100000 tree ownership required by
# rootless gVisor on Linux; a plain cp would chown-to-you and break
# the sandbox.
mkdir -p ~/.safeyolo/share && sudo cp -a guest/out/* ~/.safeyolo/share/

# Install the CLI and packaged Rust proxy through the supported installer
./install.sh install

# macOS only: the Swift VM helper
cd vm && make install && cd ..
```

Verify the shipped artefacts:

```bash
# Linux: directory tree at ~/.safeyolo/share/rootfs-tree/ used as
# gVisor's OCI root.path. Content is not a single hashable artefact;
# spot-check with a manifest walk.
find ~/.safeyolo/share/rootfs-tree -type f | wc -l   # Linux

# macOS: single ext4 image consumed by Apple Virtualization.framework
sha256sum ~/.safeyolo/share/rootfs-base.ext4         # macOS

# See the selected proxy's status without printing tokens
safeyolo status

# Host-level prerequisites + current sandbox runtime detection
safeyolo setup       # apply one-time config (AppArmor, /dev/kvm udev rule)
safeyolo doctor      # full health check; reports runtime, isolation
                     # platform (KVM vs systrap), userns prerequisites,
                     # guest images, running agents
```

## Automated Security Testing

The [blackbox test suite](../tests/blackbox/) verifies SafeYolo's security guarantees end-to-end using real microVMs. Tests are split across two domains:

Policy-file assurance is scoped separately in
[Policy File Assurance: Threat-Model Decision](policy-assurance-threat-model.md).
Because agents cannot directly write the host-owned policy file, that strategy
prioritizes semantic permission deltas, cross-agent isolation, concurrent
mutation integrity, and fail-closed behavior over generic parser fuzzing.

The current tree retains focused policy command and transaction tests in
`cli/tests/test_policy_cli.py` and `tests/test_policy_transaction_regressions.py`.
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
| Credential detection | [detection/credentials.py](../cli/src/safeyolo/detection/credentials.py), [proxy/src/policy.rs](../proxy/src/policy.rs) |
| Credential type mapping | [detection/credentials.py](../cli/src/safeyolo/detection/credentials.py) |
| HMAC fingerprinting | [detection/matching.py](../cli/src/safeyolo/detection/matching.py) |
| Shannon entropy | [detection/credentials.py](../cli/src/safeyolo/detection/credentials.py) |
| Budget tracking | [policy/budgets.rs](../proxy/src/policy/budgets.rs) |
| Circuit breaker | [circuits.rs](../proxy/src/circuits.rs) |
| Service gateway | [admin_api/gateway.rs](../proxy/src/admin_api/gateway.rs) |
| Admin API auth | [admin_api.rs](../proxy/src/admin_api.rs) |
| Request ID | [request_trace.rs](../proxy/src/request_trace.rs) |
| Request logging | [request_logger.rs](../proxy/src/request_logger.rs) |
| Native proxy startup | [proxy.py](../cli/src/safeyolo/proxy.py), [main.rs](../proxy/src/main.rs) |
| Blackbox tests | [tests/blackbox/](../tests/blackbox/) |
| Policy assurance threat model | [policy-assurance-threat-model.md](policy-assurance-threat-model.md) |
