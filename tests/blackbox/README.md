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
tests are intentionally not triggered for every pull request. The
GitHub-hosted `systrap` lane is the only scheduled lane: its nightly run
coalesces changes on `master`, also supports trusted manual dispatch, and
publishes a GitHub Actions artifact. KVM and VZ are manual/on-demand acceptance
lanes for high-risk changes and releases.

<!-- blackbox-cadence-contract:start -->
| Lane | Where it runs | Coverage | Scheduled | Current cadence | Evidence |
|------|---------------|----------|-----------|-----------------|----------|
| `systrap` | GitHub-hosted Ubuntu | Full host + gVisor isolation + lifecycle | yes | Nightly and trusted manual dispatch | GitHub Actions artifact |
| `kvm` | Fresh libvirt guest on the KVM VPS via the acceptance harness | Full host + gVisor/KVM isolation + lifecycle | no | Manual/on-demand for high-risk changes and releases | Harness/operator evidence; not continuously published on GitHub |
| `vz` | Physical Apple Silicon Mac mini | Full native proxy + Apple VZ isolation + lifecycle | no | Manual/on-demand for high-risk changes and releases | Harness/operator evidence; not continuously published on GitHub |
<!-- blackbox-cadence-contract:end -->

The `proxy` lane runs on any supported host, including GitHub macOS, for
installation smoke tests or focused diagnosis; it is not a full isolation
acceptance lane.

GitHub-hosted macOS is useful for the `proxy` lane and for compiling the Swift
helper, but it cannot provide VZ isolation evidence because the hosted machine
does not support nested virtualization. Full VZ evidence comes from the
physical Mac mini. GitHub-hosted KVM is similarly not treated as acceptance
evidence because nested virtualization is not a supported runner guarantee.

Before a release, all three full lanes (`systrap`, `kvm`, and `vz`) must pass
against the release commit. That release gate is independent of automation
cadence: manual exact-ref KVM and VZ evidence is required even though those
hardware lanes are not scheduled. Today that evidence is retained by the
acceptance harness/operator, rather than continuously published as a GitHub
artifact.

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
| No unexpected private keys | Filesystem scan | Only exact guest sshd host-key paths allowed |
| Guest trust isolation | Add a guest-only trust anchor and call its upstream | Host proxy returns 502 |
| Public cert present | Check trust store | safeyolo.crt exists |

## Installation and preparation

Acceptance runs exercise the supported installation path rather than creating
a parallel CI-only installation recipe:

1. `install.sh` installs or reinstalls the CLI with the current security pins.
2. `safeyolo bootstrap --check --json` supplies the current Linux package
   prerequisites; the lane wrapper installs missing apt packages on fresh CI
   and KVM VPS guests.
3. The KVM lane wrapper grants its current operator UID access to
   `/dev/kvm`, replacing the interactive `kvm`-group logout/login step. Product
   bootstrap remains responsible for the persistent udev rule and UID 100000
   ACL required by rootless gVisor.
4. `safeyolo bootstrap` initializes, builds guest artifacts, and applies host
   setup. The VZ lane also builds the source-only Swift helper with
   `make -C vm install`.
5. `run-tests.sh --expect-platform ...` records `doctor --json` and refuses a
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

### Selecting a proxy backend

The prepared-host runner keeps Python as its default.  Explicit proxy runs use
the existing `tests/proxy_migration` process harness, which starts a fresh
selected process and its owned UDS/origin fixtures for every test.  Assertions
stay shared between implementations:

```bash
# Run the focused acceptance against the selected source checkout.
./run-tests.sh --proxy --proxy-impl python \
  --python-source /path/to/python-checkout --verbose

# Run it against an explicitly built native executable.
./run-tests.sh --proxy --proxy-impl rust \
  --rust-bin /path/to/rust-checkout/target/debug/safeyolo-proxy --verbose

# Execute independent Python and Rust runs, retaining separate artifacts.
./run-tests.sh --proxy --proxy-impl both \
  --python-source /path/to/python-checkout \
  --rust-bin /path/to/rust-checkout/target/debug/safeyolo-proxy --verbose

# Forward focused pytest arguments after `--`.
./run-tests.sh --proxy --proxy-impl rust -- \
  tests/proxy_migration/test_http_contract.py -k attribution
```

The selector validates the requested checkout or executable before starting
pytest.  Rust selection runs its `--version` command and records the binary
SHA-256; each backend artifact also records the interpreter, selected Python
package path, source and test-suite revision/dirty state, platform and machine.
Missing binaries, failed readiness, or a failed selected backend are errors.
`both` still starts the second backend after a first-run failure and returns a
nonzero result if either run fails.  `--proxy-impl rust|both` is currently
proxy-only; combining it with VM isolation is rejected so an isolation pass
cannot be attributed to the wrong process.  The full `systrap`, `kvm`, and `vz`
lanes remain available for the default Python installation path.

Selected Rust runs set native policy mode for every migration fixture.  Each
fixture writes `native-policy-provenance.json`, which records the policy file
and confirms that no temporary Python policy adapter was started.  Direct
pytest invocations retain the temporary adapter when a test does not request
`native_policy=True`; those runs are development comparisons and are not
release acceptance.

### Sinkhole observation fidelity

The sinkhole control API keeps its historical UTF-8 replacement `body` field
and also publishes `body_hex`. `SinkholeClient.get_requests()` exposes the
lossless value as `CapturedRequest.body_bytes`, allowing shared migration and
gateway scenarios to assert arbitrary request bytes, including invalid UTF-8,
without changing the existing observer API. Raw request-target and exact
query representation are exposed as `CapturedRequest.raw_target` and
`CapturedRequest.raw_query`; duplicate header ordering, partial-body/connection
outcomes, and receiver readiness are separate observer increments.

### Installed-host stage-A smoke

Use installed_host_smoke.py on a supported Linux or macOS host when a
supplied native executable and an already prepared SafeYolo instance need
identity and ingress checks. The script never runs install.sh, builds the
Rust executable, boots a guest, or changes the selected operator instance.
Keep the evidence file outside the checkout.

The read-only discovery mode requires the installed CLI, native JSON
configuration, and native executable. It records their paths, versions,
SHA-256 values, source revisions where available, the host substrate
(runsc on Linux or safeyolo-vm on macOS), the native readiness receipt, and
the configured listener state:

~~~bash
python3 tests/blackbox/installed_host_smoke.py \
  --mode discover \
  --cli /path/to/safeyolo \
  --rust-bin /path/to/safeyolo-proxy \
  --rust-config /path/to/proxy.json \
  --config-dir /path/to/prepared-instance \
  --output /path/to/evidence/installed-discovery.json
~~~

The lifecycle smoke requires a disposable instance that has already been
prepared through the existing CLI path. Before running it, stop that
instance, confirm that it is not the normal ~/.safeyolo directory, and
create .safeyolo-platform-smoke in the disposable directory. The instance
must select proxy.backend: rust, point to the supplied native JSON file, and
contain at least one registered agent listener and its token. The script
then runs safeyolo start --wait, validates the actual Rust process,
readiness marker, executable, listener sockets, and authenticated Agent API
health response, and runs safeyolo stop:

~~~bash
python3 tests/blackbox/installed_host_smoke.py \
  --mode smoke \
  --cli /path/to/safeyolo \
  --rust-bin /path/to/safeyolo-proxy \
  --rust-config /path/to/proxy.json \
  --config-dir /path/to/disposable-instance \
  --output /path/to/evidence/installed-smoke.json
~~~

The command fails when the selected executable is missing, reports another
program, publishes a stale or mismatched readiness marker, serves a different
process, or cannot stop cleanly. It never retries with Python. Host checks may
complete with status partial_unexecuted and a nonzero exit: the UDS request is
host-driven ingress evidence, not guest-isolation evidence, and therefore
cannot signal Acceptance-A. The report records the current native
runtime-identity endpoint as unavailable, and it leaves allowed/denied origin
requests, cross-guest socket access, and unsupported hardware explicitly for
the retained stage-B pilot.

## Adding Tests

When adding a new test, ask: *"What would a malicious agent try?"*

- **Proxy tests** go in `host/` — if you need to verify what reached upstream
  via the sinkhole, or test proxy policy decisions
- **Isolation tests** go in `isolation/` — if you're testing what an agent
  can or cannot do from inside the VM
- Assert outcomes, not mechanisms — never reference pf, iptables, or feth
