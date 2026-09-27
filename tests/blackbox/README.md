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

The guest isolation and lifecycle suite runs against all three production
isolation mechanisms. Blackbox tests are intentionally not triggered for every
pull request. The GitHub-hosted `systrap` lane is the only scheduled lane: its
nightly run coalesces changes on `master`, also supports trusted manual dispatch, and
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

Run these from the repository root as the operator on a disposable supported
host. The wrapper installs or reinstalls this checkout in the caller's `uv`
tool environment, prepares guest artifacts, and creates an isolated test
instance. Select the command for the host's actual guest mechanism:

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

For the installed native proxy on the same disposable host, add
`--proxy-impl rust` to the platform command. For example, the Ubuntu systrap
host runs:

```bash
./tests/blackbox/run-lane.sh systrap --proxy-impl rust --verbose
```

The native lane uses the Rust executable inside the installed CLI package.
Its host selection is a focused ingress check; the retained Python lane runs
the broader `host/proxy` tests.
It verifies the live process, authenticated operator identity, and guest
listener before host and guest tests run. A missing package binary or a
different running process stops the lane. The native host check sends an
allowed request through the agent listener to the owned sinkhole, checks its
captured marker, then checks a denied management request on that listener.
The runner selects a local sinkhole parent for synthetic hosts and chains all
other destinations through the test instance's configured parent, if present.
It adds the owned test CA to the disposable instance's upstream trust, retains
any configured CA, and restores the original route and trust after the run.
The retained Python host proxy suite still uses its sinkhole
router. The lane records its installed runtime in
`tests/blackbox/artifacts/installed-rust-runtime.json`. An installed lane
does not replace the separate finite consumer pilot for issue #637.

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
stay shared between implementations. From `tests/blackbox` in the test-suite
checkout, with `pytest` installed, replace the paths below with a Python
checkout containing `cli/src/safeyolo` and an already built Rust proxy. The
focused Rust command uses `proxy/target/debug/safeyolo-proxy` from the test-suite
checkout unless `SAFEYOLO_RUST_PROXY` names another executable.

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
  ../proxy_migration/test_http_contract.py -k attribution
```

The selector validates the requested checkout or executable before starting
pytest.  Rust selection runs its `--version` command and records the binary
SHA-256; each backend artifact also records the pytest launcher, Python
package location, source and test-suite revision/dirty state, platform and
machine. When the selector verifies a Python interpreter from the launcher's
shebang, the artifact records that interpreter and version. For a wrapper or
unreadable launcher, those fields are null because the selector cannot identify
the interpreter used by pytest.
Missing binaries, failed readiness, or a failed selected backend are errors.
`both` still starts the second backend after a first-run failure and returns a
nonzero result if either run fails. The `both` and source/binary overrides
remain proxy-only comparison options. The full `systrap`, `kvm`, and `vz`
lanes select one installed backend with `--proxy-impl python|rust`; Python is
the prepared-host default. Rust VM runs reject a supplied `--rust-bin` and use
the executable packaged with the selected installed CLI.

The inexpensive runner self-tests cover invalid selectors, missing or wrong
executables, readiness markers and stale listeners, independent second-backend
execution after a failure, byte-preserving argument forwarding, and owned
cleanup. Run them with:

```bash
pytest -q tests/test_blackbox_harness.py tests/proxy_migration/test_readiness.py
```

These tests use temporary fake processes and do not install SafeYolo, boot a
VM, or build Rust. A selected-backend validation failure writes its
`proxy-<backend>-runtime.json` artifact with `status: infrastructure_failure`;
in `both` mode the other backend still runs and retains its own JUnit and
runtime artifacts.

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
`CapturedRequest.raw_query`; ordered duplicate fields are exposed as
`CapturedRequest.header_items`. `CapturedRequest.body_received_bytes`,
`body_expected_bytes`, `body_complete`, and `connection_closed` distinguish a
complete fixed/chunked body from an accepted connection that closes during
receipt; a connection that sends no request produces no captured request.
The host sinkhole fixture waits for both control health and a direct receiver
probe observed through the control API, then clears that probe before negative
traffic assertions. Receiver readiness is a separate observer increment.

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
cannot signal Acceptance-A. The read-only `attached` mode also checks the
authenticated operator runtime identity against the process-bound readiness
marker. The report leaves guest origin requests, cross-guest socket access,
and unsupported hardware explicitly for the retained pilot.

### Finite installed Linux P2 pilot for issue #637

Run this selection on each operator-owned disposable Ubuntu host: the supported
systrap host and the fresh libvirt guest on the KVM VPS. Use a clean checkout
that contains frozen revision `a1f85d90bacdb271fc9681847ad2202b46c0e4ad`.
The KVM target must expose a usable `/dev/kvm`; the systrap target selects
software isolation. The host needs `uv`, `git`, `dpkg-deb`, `ssh-keygen`,
`sshd`, and the normal `run-lane.sh` bootstrap prerequisites. The operator
account needs noninteractive host `sudo` for bootstrap and KVM setup. Neither
the disposable proxy nor its `bbtest` guest needs to be running before the
command. Local control port 19999 must be free; the wrapper fails if another
sinkhole owns it.

From the repository root on the selected host, run one command for its actual
guest mechanism:

```bash
./tests/blackbox/run-p2-linux.sh systrap
```

```bash
./tests/blackbox/run-p2-linux.sh kvm
```

The wrapper installs the locked R source through `install.sh` in an isolated
`uv` tool directory. It starts a separate native test proxy and a real guest.
The guest fetches and installs a disposable Debian package, clones an owned
read-only repository, receives the first held SSE event before the host
releases completion, exchanges exact WS and WSS markers, checks a blocked
WebSocket canary, and runs one OpenSSH command over CONNECT with a pinned
fixture host key. The disposable SSH server accepts only the selected marker
command and disables forwarding. The origin uses the reserved `failing.test`
hostname routed to the owned sinkhole. The wrapper keeps the caller's parent
proxy and CA settings.
It removes the disposable SSH keys and stops both the test proxy and guest.
On KVM, the existing lane also grants the operator account access to
`/dev/kvm`; that disposable-host ACL remains until the device or host resets.

Expect `Linux <platform> P2: ... verified` followed by
`Linux <platform> P2 result: exit 0`. The printed observations directory
contains `linux-<platform>-p2.json`. Check `status: passed` and
`cleanup: stopped`, then inspect the recorded installed binary, guest bridge,
owned origin deliveries, early SSE state, WS/WSS peer markers, denied canary,
and SSH command marker. A failed or timed-out run reports a nonzero exit. If
cleanup reports a failure, run the two exact cleanup commands printed by the
wrapper. They stop `bbtest` and then the disposable proxy; check that the
guest PID, native receipt, and agent socket are gone before reusing the host.
The wrapper's status does not mark P2 accepted; the actual KVM and systrap
runs and independent review supply that result. macOS/VZ P2 remains a
separate host execution.

### Finite installed P3 consumer pilot for issue #637

Run `run-p3.sh` on an operator-owned disposable host with a clean checkout that
contains frozen revision `d6a947f1343c5a854b735c22a0ce90d641dd5ac0`.
Use a disposable Ubuntu systrap host or a physical Apple Silicon Mac with
Virtualization.framework. The host needs `uv`, `git`, Python 3, the
prerequisites for `run-lane.sh`, and working loopback TCP bind and connect.
The Linux operator account needs noninteractive
`sudo` for bootstrap. Local test ports 8180, 8181, 9190, 18080, 18443–18451,
and 19999 must be free. No disposable proxy or guest needs to be running.
Consumer requests in the pilot use its owned fixture origin. Setup may
download the pinned install dependencies. The lane preserves the configured
parent proxy and certificate
authority for other destinations.
The installed CLI starts owned Coord in the disposable test instance.

From the repository root on the selected host, run the command for its actual
guest mechanism:

```bash
./tests/blackbox/run-p3.sh systrap
```

```bash
./tests/blackbox/run-p3.sh vz
```

The wrapper installs frozen source R in an isolated `uv` tool directory. It
starts a disposable native proxy, two real guests, and an owned HTTP origin.
Guest calls use each guest's local proxy forwarder. The selection checks
service approval and exact vault
credential delivery, a stolen gateway token from the second guest, contract
binding and one-use route approval, test-context and own trace/flow access,
Coord history and attention resolution, collaboration approval and closure,
and an authenticated operator event. The read-only inspector filters retained
flows, reads a WebSocket transcript, and exports one selected raw request.
The export can contain the disposable gateway token. Keep the printed
observations directory private.

Expect the `P3: six installed guest journeys and operator effects verified`
line and a `P3 result: exit 0` line. In the printed observations directory,
inspect `systrap-p3.json` or `vz-p3.json` for `status: passed`,
`cleanup: stopped`, and the named origin, peer, backing-service, event, and
inspector effects. The wrapper stops both guests, the proxy, and the owned fixture
processes. If cleanup fails, run the exact three cleanup commands printed by
the wrapper and verify the guest PID files, native proxy receipt, agent
sockets, and Coord NATS PID file are gone. The disposable directory remains
available for diagnosis. A passed wrapper is a host observation; independent
review decides P3 acceptance.

The current Bristol seatbelt-mac route cannot bind and connect loopback TCP.
It cannot execute the VZ pilot until that host capability is available. The
wrapper checks loopback before installation, so this route can check out and
inspect the procedure without starting the disposable instance.

### Finite installed P4 lifecycle pilot for issue #637

Run `run-p4.sh` on an operator-owned disposable Ubuntu systrap host or a
physical Apple Silicon Mac with Virtualization.framework. Use a clean
checkout that contains frozen revision
`729b48abd2920c424e6513ef0c2eaa6a1f306299`. The host needs `uv`,
`git`, Python 3, the `run-lane.sh` bootstrap prerequisites, and loopback TCP
bind and connect. The Linux operator account needs noninteractive `sudo` for
bootstrap. Local test ports 8180, 8181, 9190, 18080, 18443–18452, and
19999 must be free. The disposable proxy and guests must be stopped before
the command. Setup may download pinned install dependencies. The lane keeps
the configured parent proxy and certificate authority for nonfixture traffic.
The wrapper gives the installed CLI's owned Coord service a disposable data
directory and checks its cleanup.

From the repository root on the selected host, run the command for its guest
mechanism:

```bash
./tests/blackbox/run-p4.sh systrap
```

```bash
./tests/blackbox/run-p4.sh vz
```

The wrapper installs frozen source R in an isolated `uv` tool directory. It
starts a disposable native proxy and real guests. The selection adds, uses,
and removes a second agent listener while the first stays usable. An operator
policy change denies new requests while an admitted SSE response finishes;
restoring that policy permits new requests. The guest exercises the valid
private CA, wrong host, untrusted, future, and expired leaf fixtures. The
invalid cases must produce no application request at the owned origin. An
exact `self-signed.test:443` passthrough change exposes the origin leaf, keeps
an established TLS session usable after removal, and returns new sessions to
inspected TLS. After a same-state restart, a final stop runs with an
active HTTP response, SSE response, WebSocket, and CONNECT tunnel. The guest
checks the completed responses and tunnel closure; host logs check the owned
response and WebSocket close events.

Expect `P4: installed guest configuration, TLS and drain verified` and
`P4 result: exit 0`. Inspect `systrap-p4.json` or `vz-p4.json` in the printed
observations directory. The report records the installed binary and host,
guest bridges, fixture deliveries, reload effects, shutdown ownership, and
one installation with two start/stop cycles. P6 can reuse supported-host
observations after independent review. `status: passed` and `cleanup: stopped`
mean the runner and cleanup completed; they do not mark P4 accepted. The
wrapper stops both guests, the proxy, and owned fixture processes. If cleanup
fails, run the exact three cleanup commands printed by the wrapper. Check that
the guest PID files, native proxy receipt, and Coord NATS PID file are gone.
Check that agent sockets are gone before reusing the host. The disposable
directory remains available for diagnosis.

The approved Bristol physical Mac route currently cannot bind or connect
loopback TCP. The wrapper checks that prerequisite before installation. A VZ
execution and independent review remain necessary before claiming the macOS
P4 result.

## Adding Tests

When adding a new test, ask: *"What would a malicious agent try?"*

- **Proxy tests** go in `host/` — if you need to verify what reached upstream
  via the sinkhole, or test proxy policy decisions
- **Isolation tests** go in `isolation/` — if you're testing what an agent
  can or cannot do from inside the VM
- Assert outcomes, not mechanisms — never reference pf, iptables, or feth
