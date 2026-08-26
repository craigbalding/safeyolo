# SafeYolo Security Testing Design

## Overview

Security tests run against real infrastructure — real proxy, real
sandbox, real Apple VZ microVM or rootless gVisor sandbox. No mocks, no
shortcuts. Every test class has a structured docstring
(Title + Why) and every test function states the probe and the
consequence if the property didn't hold; `docs/blackbox-coverage.md`
is generated from those docstrings.

Tests are split across two execution domains:

- **Host pytest** (`tests/blackbox/host/`): Proxy functional tests and
  agent-identity checks. Runs on the host where sinkhole, admin API,
  and proxy are directly accessible.
- **Sandbox pytest** (`tests/blackbox/isolation/`): Isolation tests. Runs
  inside the sandbox (VZ microVM on macOS, gVisor on Linux) via
  `safeyolo agent shell`, probing from the adversary's perspective. A second
  pass uses `agent shell --root`: guest root is an intended package-management
  feature, and the boundary must remain intact from that context.

## Quick Start

```bash
cd /path/to/safeyolo

# Prepare through install.sh + bootstrap and run a named lane
./tests/blackbox/run-lane.sh systrap --verbose
./tests/blackbox/run-lane.sh kvm --verbose
./tests/blackbox/run-lane.sh vz --verbose

# Proxy-only installation smoke; no sandbox boot
./tests/blackbox/run-lane.sh proxy --verbose

# Already-prepared host
./tests/blackbox/run-tests.sh --expect-platform kvm --verbose
```

## Execution lanes and cadence

| Runtime | Execution host | Evidence |
|---------|----------------|----------|
| gVisor systrap | GitHub-hosted Ubuntu | Nightly/manual full suite; platform assertion recorded |
| gVisor KVM | Fresh libvirt guest on the KVM VPS | Full nested-KVM acceptance evidence |
| Apple VZ | Physical Apple Silicon Mac mini | Full native macOS + VZ acceptance evidence |

Blackbox is not a required per-PR check. The scheduled GitHub lane tests the
latest default-branch state once per day; KVM VPS and Mac mini runs use the
same lane wrapper nightly, for high-risk changes, and before release. Manual
runs select an exact trusted ref. All three runtimes must pass for a release.

GitHub macOS can run a proxy-only smoke or compile the Swift helper, but it
cannot supply VZ runtime evidence. GitHub-hosted nested KVM is not accepted as
KVM evidence. These boundaries keep a green run from claiming an isolation
mechanism it did not execute.

## Architecture

```
Host (pytest)                          Sandbox (pytest via agent shell)
├── proxy_client → proxy:8080          ├── test_vm_isolation.py
├── sinkhole.get_requests() → :19999   │   ├── proxy-only egress
├── admin_client → :9090               │   └── default-user hardening
└── no VM interaction needed           ├── test_root_containment.py (--root)
                                       │   ├── UID 0 + local .deb install
                                       │   └── host/network/share containment
                                       └── test_key_isolation.py (user + root)
                                           └── no private keys anywhere
```

The `run-lane.sh` wrapper performs the supported source install, uses
`safeyolo bootstrap --check --json` as the source of truth for build packages,
runs bootstrap, and declares the required platform. `run-tests.sh` then
orchestrates:
1. Generate test certs (keys stored outside repo tree)
2. Start sinkhole (HTTP/HTTPS capture server)
3. Start proxy in test mode (`safeyolo start --test`)
4. Assert `doctor --json` reports the requested systrap, KVM, or VZ runtime
5. Boot a BYOA sandbox with the repo as workspace
6. Run host-side pytest (credential guard, network guard)
7. Run sandbox-side pytest as the default agent user
8. Open `safeyolo agent shell --root`, prove local package installation, and
   rerun root-relevant containment and key-isolation probes
9. Cleanup

## Test Suites

### Proxy Functional Tests (host-side)

| File | Tests |
|------|-------|
| `test_credential_guard.py` | Credential routing to authorized hosts, exfiltration blocking, block response content |
| `test_network_guard.py` | Domain access control, rate limiting, Proxy-Authorization stripping |

**Verification method:** The sinkhole captures all upstream traffic. Tests query
the sinkhole control API to verify what *actually reached* the upstream — not
what the proxy said it blocked.

### Sandbox Isolation Tests

| File | Tests |
|------|-------|
| `test_vm_isolation.py` | Default-user network escape, privilege transition, kernel/device hardening, filesystem isolation |
| `test_root_containment.py` | Guest UID 0, local package install/purge, root-context egress and host-boundary containment |
| `test_key_isolation.py` | Public cert present and no private keys; also rerun as guest root so permissions cannot hide key material |

**Verification method:** Direct probes from inside the VM. The default-user
suite checks its restricted posture. The guest-root suite positively verifies
UID 0 and a real local package transaction, then tests outcomes at the actual
security boundary: no direct egress, host listener access, writable host share,
host KVM device, or hidden private key material.

## Key Design Decisions

### Host tests verify the proxy, VM tests verify isolation

The host has direct access to the sinkhole control API (port 19999) and admin
API (port 9090). The VM's firewall correctly blocks both — that's a security
property we test, not a problem to work around.

### Private keys outside the repo

Test cert private keys are stored in `~/.safeyolo/test-certs/`, not in the repo
tree. The workspace is mounted into agent VMs via VirtioFS — keys in the repo
would be accessible to agents. The `test_full_filesystem_scan_for_private_keys`
test verifies this on every run.

### Guest root is inside the boundary

SafeYolo deliberately supports guest root for `apt` and repair. The default
agent shell remains uid 1000, but `sudo` and the operator-mediated
`agent shell --root` path reach uid 0. That is not host root:

- gVisor maps sandbox uid 0 to an unprivileged subordinate host uid, verified
  from the host-side live user-namespace map.
- Apple VZ contains uid 0 inside the hardware microVM.

Accordingly, acceptance tests root as a supported capability and then probes
containment, rather than treating `setuid(0)` itself as an escape.

### Ground truth TLS

A dedicated test CA signs the sinkhole certificate. The proxy verifies it the
same way it verifies production certs. No `ssl_insecure` flags. See
[`certs/README.md`](../tests/blackbox/certs/README.md).

## Files

| File | Purpose |
|------|---------|
| `run-lane.sh` | Install/bootstrap/platform-aware acceptance entrypoint |
| `assert-platform.py` | Refuse runtime fallback and normalize doctor evidence |
| `run-tests.sh` | Cross-platform orchestrator (idempotent, reuses running services) |
| `host/conftest.py` | Host-side fixtures (sinkhole, proxy, admin clients) |
| `host/sinkhole_client.py` | Sinkhole control API client |
| `host/proxy/test_credential_guard.py` | Credential routing/blocking tests |
| `host/proxy/test_network_guard.py` | Access control, rate limiting tests |
| `isolation/test_vm_isolation.py` | Default-user network, device, syscall, and filesystem hardening tests |
| `isolation/test_root_containment.py` | Guest-root capability, package install, and containment tests |
| `isolation/test_key_isolation.py` | Private key isolation tests |
| `harness/sinkhole_router.py` | mitmproxy addon redirecting test traffic to sinkhole |
| `sinkhole/server.py` | HTTP/HTTPS capture server |
| `certs/generate-certs.sh` | Test CA and sinkhole cert generation |
