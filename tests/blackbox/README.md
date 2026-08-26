# Black Box Tests

SafeYolo's trust anchor. These tests prove two things:

1. **SafeYolo does what it claims** — credentials are blocked, domains are enforced, rate limits work
2. **A malicious agent cannot escape** — including an agent with intentional guest-root access

Passing evidence is meaningful only when it names the runtime that was tested.
A KVM run which silently fell back to systrap is not KVM evidence.

## Transition assessment

The post-Docker test work was **not** starting from scratch. Before this lane
refresh, `master` already contained a substantial current-architecture suite:
host tests drove the native proxy, isolation tests ran inside real gVisor/VZ
agents, Linux identity checks inspected the rootless uid map, lifecycle tests
covered persistent agent state, and guest root was partially recognized as an
intentional package-management capability.

The stale part was execution infrastructure and its public contract. The old
GitHub workflow still tried to transfer Linux-built artifacts into a hosted
macOS VZ job, did not exercise the current `install.sh`/bootstrap path, did not
build the source-only VZ helper, and could not prove which isolation mechanism
actually ran. The lane wrapper, platform evidence gate, root-capability pass,
and host/cadence matrix below close those gaps while reusing the existing test
suite.

## Runtime lanes

The same suite runs against all three production isolation mechanisms. Blackbox
tests are intentionally not triggered for every pull request; the nightly run
coalesces changes on `master`, and any trusted ref can be run on demand.

| Lane | Where it runs | Coverage | Normal trigger |
|------|---------------|----------|----------------|
| `systrap` | GitHub-hosted Ubuntu | Full host + gVisor isolation + lifecycle | Nightly and manual |
| `kvm` | Fresh libvirt guest on the KVM VPS via the acceptance harness | Full host + gVisor/KVM isolation + lifecycle | Nightly, high-risk change, release |
| `vz` | Physical Apple Silicon Mac mini | Full native proxy + Apple VZ isolation + lifecycle | Nightly, high-risk change, release |
| `proxy` | Any supported host, including GitHub macOS | Host proxy/security tests only | Installation smoke or focused diagnosis |

GitHub-hosted macOS is useful for the `proxy` lane and for compiling the Swift
helper, but it cannot provide VZ isolation evidence because the hosted machine
does not support nested virtualization. Full VZ evidence comes from the
physical Mac mini. GitHub-hosted KVM is similarly not treated as acceptance
evidence because nested virtualization is not a supported runner guarantee.

Before a release, all three full lanes (`systrap`, `kvm`, and `vz`) must pass
against the release commit.

## Execution Model

Tests are split across two execution domains:

**Host-side pytest** (`host/`) — proxy functional tests. Runs on the host where
sinkhole, admin API, and proxy are directly accessible on localhost. Sends
requests through the proxy and verifies what the sinkhole captured.

**Sandbox-side pytest** (`isolation/`) — isolation tests. Runs inside the real
agent sandbox via `safeyolo agent shell`: a gVisor sandbox on Linux or an Apple
VZ microVM on macOS. The suite runs in both the default agent context and an
explicit `agent shell --root` context. Guest root is expected to work; the
tests prove that its privilege stops at the sandbox or microVM boundary.

```
Host (pytest)                          Sandbox (pytest via agent shell)
├── proxy_client → proxy:8080          ├── test_vm_isolation.py
├── sinkhole.get_requests() → :19999   │   ├── curl --noproxy '*' ...
├── admin_client → :9090               │   └── default-user hardening
└── no VM interaction needed           ├── test_root_containment.py (--root)
                                       │   ├── UID 0 and local package install
                                       │   ├── direct egress/host listener blocked
                                       │   └── host share and /dev/kvm inaccessible
                                       └── test_key_isolation.py (user + root)
                                           └── no private key material
```

## Design Principles

**Host tests verify the proxy, VM tests verify isolation.** The host has
access to the sinkhole control API and admin API. The VM's firewall correctly
blocks both — which is a security property we test, not a problem to work around.

**Platform-independent assertions.** Tests assert outcomes, never mechanisms.
`curl --noproxy '*' http://1.1.1.1` fails regardless of whether pf or
iptables dropped it.

**Never duplicate production logic.** Tests use the real proxy, real addons,
real firewall rules, real TLS. No mocks, no shortcuts.

**Guest root is a feature, not an escape.** The normal shell starts as uid
1000, while in-guest `sudo` and the operator's `agent shell --root` provide uid
0 for package management and repair. On gVisor, guest uid 0 maps to an
unprivileged subordinate host uid; on VZ it is root only inside the microVM.
Acceptance requires both that root works and that root cannot bypass egress,
reach host services, mutate the host config share, or obtain host key material.

**Ground truth TLS.** A dedicated test CA signs sinkhole certificates.
The proxy verifies these the same way it verifies production certs.
See `certs/README.md`.

## Test Suites

### Proxy Functional Tests (`host/`)

| Test | Attack Scenario | Security Property |
|------|----------------|-------------------|
| Credential to authorized host | Normal operation | Forwarded with credential intact |
| Credential to unauthorized host | Exfiltration attempt | 428 + sinkhole receives nothing |
| Request without credentials | Normal operation | Passes through |
| Allowed domain | Normal operation | 200 response |
| Rate limit within budget | Normal operation | All requests succeed |
| Proxy-Authorization header | Header exfiltration | Stripped before forwarding |
| Block response content | Audit trail | Contains event_id and approval guidance |

### VM Isolation Tests (`isolation/`)

| Test | Attack Vector | Expected Result |
|------|--------------|-----------------|
| Direct HTTP bypass | `curl --noproxy '*' http://1.1.1.1` | Connection dropped |
| Direct HTTPS bypass | `curl --noproxy '*' https://8.8.8.8` | Connection dropped |
| DNS exfiltration | UDP to 8.8.8.8:53 | Blocked |
| Raw socket | `SOCK_RAW` ICMP | PermissionError |
| Proxy reachable | `curl` through proxy | 200 |
| Default shell identity | `id -u` | 1000 |
| Guest-root availability | `agent shell --root`; `id -u` | 0 |
| Package-management capability | Build/install/purge a local `.deb` | Succeeds without network |
| Root direct egress | `curl --noproxy '*'` as guest root | Connection blocked |
| Root host reachability | Connect to known-live host listener as root | Connection blocked |
| Root host-state mutation | Write `/safeyolo` as root | Read-only failure |
| Root host device access (gVisor) | Inspect `/dev/kvm` as root | Not present |
| No kernel modules | `init_module` syscall | ENOSYS |
| No /dev/mem | Check path | Not found |
| No eBPF | BPF syscall | Returns -1 |
| Config share read-only | Write to /safeyolo | EROFS |
| No private keys | Filesystem scan | No PRIVATE KEY found |
| Public cert present | Check trust store | safeyolo.crt exists |

## Installation and preparation

Acceptance runs exercise the supported installation path rather than creating
a parallel CI-only installation recipe:

1. `install.sh` installs or reinstalls the CLI with the current security pins.
2. `safeyolo bootstrap --check --json` supplies the current Linux package
   prerequisites; the lane wrapper installs missing apt packages on fresh CI
   and KVM VPS guests.
3. `safeyolo bootstrap` initializes, builds guest artifacts, and applies host
   setup. The VZ lane also builds the source-only Swift helper with
   `make -C vm install`.
4. `run-tests.sh --expect-platform ...` records `doctor --json` and refuses a
   runtime mismatch before running isolation tests.

The systrap wrapper explicitly selects `SAFEYOLO_RUNSC_PLATFORM=systrap`, so
that lane remains deterministic if a runner happens to expose `/dev/kvm`.
The KVM lane never forces a label: it must pass auto-detection and prove both
operator and sandbox subordinate-UID access to the device.

This makes changes to `install.sh`, bootstrap dependency detection, guest
builds, platform setup, and the guest-root/package installation path part of
acceptance coverage.

## Running a lane

Run these from the repository root on the appropriate host:

```bash
# GitHub/other Linux VM without KVM
./tests/blackbox/run-lane.sh systrap --verbose

# Fresh nested-KVM guest on the KVM VPS
./tests/blackbox/run-lane.sh kvm --verbose

# Physical Apple Silicon Mac mini
./tests/blackbox/run-lane.sh vz --verbose

# Proxy-only smoke (no sandbox boot)
./tests/blackbox/run-lane.sh proxy --verbose
```

`run-lane.sh` is idempotent on persistent hosts. It calls `install.sh`, uses the
product bootstrap plan for prerequisites, and then delegates to
`run-tests.sh`.

## Running an already-prepared checkout

Use `run-tests.sh` directly when the host is already installed and bootstrapped
and the live installation must remain untouched. It creates a separate
`~/.safeyolo-test` instance, generates test certificates beneath that instance,
uses distinct proxy, admin, and web ports, and borrows the live `share/` and
`bin/` artifacts without rebuilding them. The harness refuses to proceed if
the test and source config paths resolve to the same directory.

```bash
# All suites
./run-tests.sh

# Proxy functional tests only (host-side)
./run-tests.sh --proxy

# VM isolation tests only (in-VM)
./run-tests.sh --isolation

# Verbose
./run-tests.sh --verbose

# Fail unless the requested isolation mechanism is selected
./run-tests.sh --expect-platform kvm --verbose

# Full physical Apple Silicon Mac run without reinstall/bootstrap
./run-tests.sh --expect-platform vz --verbose
```

Do not use `run-lane.sh` for this case: acceptance lanes deliberately exercise
`install.sh`, bootstrap, and (for VZ) host-helper installation.

## Adding Tests

When adding a new test, ask: *"What would a malicious agent try?"*

- **Proxy tests** go in `host/` — if you need to verify what reached upstream
  via the sinkhole, or test proxy policy decisions
- **Isolation tests** go in `isolation/` — if you're testing what an agent
  can or cannot do from inside the VM
- Assert outcomes, not mechanisms — never reference pf, iptables, or feth
