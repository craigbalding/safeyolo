# Installed blackbox tests

Use this suite to check the installed SafeYolo package, real guest isolation,
agent workloads, access approvals and lifecycle. Native proxy process and
protocol contracts live in [`tests/proxy_contracts`](../proxy_contracts/).
A hosted process or package result does not prove KVM or Apple VZ isolation.

Run installed acceptance on a disposable supported host, from a clean checkout
of the exact commit being tested. Install uv and select Rust 1.94.0 from
[`proxy/rust-toolchain.toml`](../../proxy/rust-toolchain.toml); Cargo must be on
`PATH`. Linux preparation needs noninteractive host sudo, subordinate IDs
covering 100000–165535, and the [native guest prerequisites](../../docs/native-policy.md#guest-prerequisites). The workloads
section additionally needs `dpkg-deb` and `openssh-server` on its host. KVM
requires a fresh libvirt guest with usable `/dev/kvm`. VZ requires physical
Apple Silicon and the Swift helper build prerequisites in the
[installation reference](../../cli/README.md#installation).

## Run installed sections with one preparation

Choose the host's actual mechanism. From the repository root, the following
runs the checked-out HEAD; `--install-commit FULL_SHA` checks an explicit full
commit before installing anything.

```sh
./tests/blackbox/run-installed.sh systrap
```

On a fresh KVM-capable acceptance guest:

```sh
./tests/blackbox/run-installed.sh kvm
```

On the physical Apple Silicon host:

```sh
./tests/blackbox/run-installed.sh vz
```

The runner creates a disk-backed directory under the operator's home. It calls
`run-lane.sh --prepare-only` once: the supported native `install.sh`, locked
host test dependencies and verified NATS input. Supply prepared native bundles
with `SAFEYOLO_NATIVE_BUNDLE`, or matching host/guest/runtime inputs with
`SAFEYOLO_NATIVE_ARTIFACTS`, `SAFEYOLO_NATIVE_GUEST_ARTIFACTS` and
`SAFEYOLO_NATIVE_RUNTIME_ARTIFACTS`; macOS also uses
`SAFEYOLO_NATIVE_VM_ARTIFACTS`. Without artifacts the source assembler builds
them. `SAFEYOLO_BUILD_PROFILE` selects production by default, or debug.

Prepare the platform images/tree separately with the maintained shell builders
and set `SAFEYOLO_PLATFORM_ASSETS` to that directory. Linux requires runsc,
newuidmap/newgidmap, setfacl and unshare plus the prepared rootfs-tree; VZ needs
Image, initramfs.cpio.gz and rootfs-base.ext4. Preparation does not invoke the
retired Python bootstrap. The KVM lane grants the operator and subordinate UID
100000 read/write access to `/dev/kvm`, then actual platform selection must
succeed. Systrap is explicitly selected even when the host exposes KVM. KVM
must pass actual detection instead of forcing a KVM label.

Each section then borrows the same compatible guest artifacts and installed
CLI/native executable. Each gets a fresh agent, config, data, logs, public and
private fixture certificates, overlay, origins, captures, approvals, tokens,
Coord test instance and writable state. The lifecycle section's separate live
owner also gets its own instance. Sharing preparation does not share live
scenario state. NATS executable bytes are prepared once and reverified by the
installed launcher in each instance; credentials and JetStream data are private.
Individual procedural compositions remain intact.

| Lane | Independent sections |
|---|---|
| `systrap` | isolation, workloads, access, lifecycle, host continuity |
| `kvm` | isolation, ingress, workloads |
| `vz` | isolation, access, lifecycle, host continuity |

`--section NAME` runs just that supported section; repeat it to select several.
For example, run access on the software-isolation host:

```sh
./tests/blackbox/run-installed.sh systrap --section access
```

`--install-checkout PATH` uses another clean source checkout at the selected
commit. `--artifacts PATH` changes the ordinary report directory, which defaults
to `tests/blackbox/artifacts/`. `installed-sections.json` attributes product
preparation, each section's exit/result, and owned cleanup separately. Section
reports are below their behavior-named directories. Failed state/logs remain
in the printed private instance directory for diagnosis.

Exit 0 means the selected checks and cleanup passed; 1 means an assertion
failed; 2 means preparation, execution infrastructure or cleanup failed.
Another independent section may run after a failed assertion or setup only
when owned cleanup establishes a clean boundary. A cleanup failure stops the
remaining sections and is recorded as `cleanup_failure`. A later inspection
with no markers cannot clear an inner cleanup failure that already detected a
surviving owned process. Stop the proxy and each disposable guest: `safeyolo stop`
alone does not stop a guest.

## Cadence and hardware evidence

Normal PRs run quick checks and relevant platform tests for platform changes.
Complete retained Python/CLI and native component families run overnight on
supported hosts. The full Mac proxy protocol family runs once, in
[`proxy-rust.yml`](../../.github/workflows/proxy-rust.yml). The separate hosted
Mac installed job runs the short package witness below. Full-suite success is
not a routine PR gate; discovering regression the next morning is accepted.

The approved overnight scope includes systrap, KVM-backed gVisor and physical
Apple Silicon VZ. Current GitHub automation schedules systrap and hosted
package/component checks. Hardware scheduling/publication remains
[#889](https://github.com/craigbalding/safeyolo/issues/889); this restructuring
supplies its maintained runners without claiming that automation is complete.

<!-- blackbox-cadence-contract:start -->
| Lane | Where it runs | Coverage | Scheduled | Current cadence | Evidence |
|---|---|---|---|---|---|
| `systrap` | GitHub-hosted Ubuntu | Installed isolation, workloads, access and lifecycle | yes | Overnight and trusted manual dispatch | Sanitized GitHub Actions artifacts, including failures |
| `kvm` | Fresh libvirt guest through the acceptance harness | Actual KVM isolation, installed ingress and workloads | no | Manual/on-demand until #889 automation | Harness/operator exact-candidate result and cleanup |
| `vz` | Physical Apple Silicon Mac | Actual VZ isolation, installed access and lifecycle | no | Manual/on-demand until #889 automation | Harness/operator exact-candidate result and cleanup |
<!-- blackbox-cadence-contract:end -->

Hosted macOS cannot supply physical VZ evidence, and hosted KVM availability is
not an acceptance guarantee. Hardware runs require a fresh disposable host,
trusted schedule or explicit operator dispatch, resource/owner prechecks,
exact selected commit and binary, actual platform identity, observed result,
owned cleanup and sanitized publication. Public PR code must not execute on a
persistent hardware host through an untrusted trigger. A stale ref or another
owner's live resource does not satisfy those prechecks. Before release, retain
exact-release-commit results for all three actual isolation mechanisms.
Historical #640 receipts remain historical acceptance; #320 does not reopen them.

## Existing single-section entry points

`run-lane.sh` remains the supported native installation plus one test selection
entry point, including the full installed isolation lane used by acceptance
hosts. From the repository root on the matching disposable host, set
`SAFEYOLO_CONFIG_DIR` to a fresh installation root and supply the native and
platform inputs above before running:

```sh
./tests/blackbox/run-lane.sh systrap --verbose
```

If the native product and platform inputs are already prepared, run a section without
reinstalling. `SAFEYOLO_CONFIG_DIR` names the prepared source instance;
`SAFEYOLO_TEST_CONFIG_DIR` names the separate live test instance:

```sh
SAFEYOLO_CONFIG_DIR=/path/to/prepared \
SAFEYOLO_TEST_CONFIG_DIR=/path/to/disposable-test \
  ./tests/blackbox/run-tests.sh --expect-platform systrap --verbose
```

The native Rust package is the default. The runner refuses to use its source
instance, the operator's normal instance or an ambiguous live config as test
state. It links compatible `share/` and `bin/` inputs, creates fresh writable
state, verifies actual native guest metadata for platform selection, and records the
installed source/profile, packaged executable, actual process/start identity, authenticated Admin
runtime identity and per-agent listener before guest assertions. `--workloads`,
`--access`, `--lifecycle` and KVM `--ingress` select procedures and exit before
the full pytest phases. `run-lane.sh` supplies their selected source checkout.
For a direct prepared procedural run, also set
`SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT` to the checkout that produced the installed
native layout and executable. The runner resolves its HEAD; `--install-commit FULL_SHA`
must match that checkout before setup. The installed native executables, package metadata and live runtime
are checked against the same selection. For pytest selections, pass arguments
after `--`; the runner forwards argument boundaries without shell reinterpretation.

The completed migration wrappers, frozen source defaults and comparator
selectors are retired. Use the named sections above for current installed
work. The
[audited Stage A source](https://github.com/craigbalding/safeyolo/tree/e91f69ef85df55341db530bab421f67c4afb83f5)
preserves historical executors; their accepted observations and the finite
pruning scope remain in the
[approved disposition](https://github.com/craigbalding/safeyolo/issues/320#issuecomment-5942642868).
Lens's [physical replacement assessment](https://github.com/craigbalding/safeyolo/issues/320#issuecomment-5961923767)
records the VZ isolation, access and lifecycle observations at their actual
commits, including the five unexecuted isolation assertions. Fresh native installation and direct recovery commands are in the
[CLI guide](../../cli/README.md); there is no old-package rollback operation.

## What each installed selection observes

The **isolation** section selects host `native/`, `security/`, `identity/` and
`lifecycle/`, then ordinary guest `isolation/` excluding root containment, then
guest-root containment and private-key isolation. The three public-cert checks
run as the ordinary user; private-key scans run under both identities.
Root is intentional for package
management and repair: Linux guest UID 0 maps to subordinate host UID 100000;
VZ root stays inside its microVM. Tests observe direct egress, a known-live host
listener, protected host/config/key/device boundaries, real package/root
capabilities, and the installed identity/lifecycle chain. Platform/fixture
skips are limitations, not passes. The generated
[coverage inventory](../../docs/blackbox-coverage.md) distinguishes selected
methods, repeated identities and procedural selections from execution receipts.

The KVM **ingress** section binds a real guest's localhost forwarder to its
mounted per-agent Unix domain socket (UDS), checks actual KVM runsc arguments,
then correlates an exact allowed marker with the owned origin and a denied
request with no origin delivery. Local management API boundaries remain checked.

Linux **workloads** retains package fetch/hash/query/install/payload/purge,
read-only Git clone/commit/marker, SSE first-event and held control/release
ordering, WSS echo and peer-close state, denied-upgrade canary without origin
delivery, and SSH through CONNECT. SSH uses a disposable fixture key, pinned
host key and restricted selected command; forwarding and fixture processes are
owned and cleaned up. The key fixture never borrows an operator credential.
Access owns the plain-WS exchange through the same guest handshake, payload and
close helper, with matching origin and inspector observations.

**Access** stays one composition with two live guests, an operator, native proxy,
NATS and inspector. It checks service approval, contract binding and risky-route
approval/retry, exact credential injection, live peer denial, test context and
trace, populated exact owner-positive/live-peer-negative flow search/detail,
Coord messages and resolved attention, Plumb approval/exchange/closure,
WebSocket peer effects, inspector filtering, transcript and export. Raw inspector
exports may contain disposable gateway tokens and stay in private instance state;
the workflow publishes selected reports instead of raw exports.

**Lifecycle** keeps listener add/remove and primary-listener continuity, policy
changes while SSE is admitted, and all five installed guest-default-trust TLS
cases: valid cross-signed, wrong SAN, self-signed, not yet valid and expired.
Allowed TLS reaches the owned origin; invalid TLS produces no origin delivery
and no silent passthrough. A separate scoped `ignore_hosts` case checks a held
session, removal, new-connection rejection and rejection after restart. The
runner keeps stable CA/upstream-trust/policy observations, mixed HTTP/SSE/WS/CONNECT
drain, three subject start/stop/recovery cycles and the separate live owner's
process, policy and controls throughout. Stop verifies readiness, lifetime
receipt, process start identity, UDS and guest cleanup. The VZ guest verifies
its actual vsock forwarder instead of requiring a Linux socket mount.

**Continuity** selects `installed_state_transition.py` in its own
host instance without booting guests. Four identified native processes write,
replace, revoke and deliberately recover access. Return processes must retain
SQLite ownership, exact bodies, tags and correlated audit; enforce an open
circuit before operator reset and avoid resurrecting it afterward; retain
catalogue, policy, grants and scoped host/service revocations; preserve Coord
messages/attention and the provider-owned lease snapshot; the fresh native
process must report unknown lease state without inventing held ownership.
It retains approved Plumb messages before close returns 403. The same sequence
checks stored OAuth refresh/use, trusted upstream TLS, stable CA/HMAC identity,
0600 private state and process-local task reset. Each process, listener, NATS
server and owned origin must stop. The historical cross-backend executor was
retired after [Lens verified the native Linux replacement](https://github.com/craigbalding/safeyolo/issues/320#issuecomment-5951336164).
Current macOS package and guest replacements still need their own observations
before matching duplicate pruning. Accepted historical migration receipts remain
in their original issues; they are not recurring execution requirements.

## Short installed host-package witness

From a clean exact checkout on a disposable Linux or hosted Mac, with uv and
Cargo available, run the command below. On Linux, the current installed launcher
also requires `runsc`; this witness does not install or boot a guest rootfs.
On macOS, the default continuity fixture needs the owned `127.0.0.2` loopback
alias, as prepared by the workflow.

```sh
./tests/blackbox/run-installed-package.sh
```

This installs the current native layout without a guest rootfs build, uses the
normal launcher/configuration, authenticates exact running identity, observes
native allow/deny at two authorities on one owned HTTP listener and verifies
stop/cleanup. The allowed IP and denied localhost authorities both reach that
known-live fixture before the policy probe. Success
is for this host-package claim; no guest boots and guest isolation is explicitly
unproved. It then runs the three existing `test_https_origin_verification` nodes
against the packaged executable: trusted localhost reaches the origin, wrong
SAN and untrusted origin return 502 without origin delivery. It does not repeat
the complete component matrix against the package.
The same prepared product then runs the separate native host-continuity
procedure above, with fresh config/data/cert/log/origin state.

If a prepared-package witness requires fixed ports, `installed_host_smoke.py`
accepts `--http-port`. The three packaged HTTPS nodes use
`SAFEYOLO_TEST_HTTPS_PORT` for their TLS origin. The continuity procedure accepts
`--origin-host`, `--origin-bind`, `--http-port`, `--https-port`, `--oauth-port` and
`--admin-port`.
Its selected HTTP/TLS host is also used in request authorities, the certificate
SAN, catalog, scoped grants, task policy and circuit checks. These are test
bindings; the default ports remain ephemeral. If `--origin-bind` differs from
the authority, the HTTP fixture also acts as its owned parent, tunnels only
the selected TLS origin and forwards refresh calls to the separate OAuth
fixture. This lets the authority remain `127.0.0.2`, which
counts in the circuit probe, while the listeners bind to `127.0.0.1`.
Each procedure keeps its own
state and verifies owned cleanup before another procedure runs.

`SAFEYOLO_TEST_SOCKET_DIR` selects an existing short, writable directory for
native contract sockets when the default temporary directory is unavailable.
The harness creates a private temporary directory there and removes it after
each case.

`installed_host_smoke.py --mode discover` identifies prerequisites;
`--mode attached` authenticates an already running installed proxy without
restarting it. Their JSON statuses and limitations must be read; merely writing
a report is not a pass. Discovery/attached guest claims require their actual
substrate and listener; the host-only smoke does not claim one.

## Owned origins and observation fidelity

The native runner routes synthetic hosts through its owned parent and sinkhole,
chains other destinations through the instance's configured parent, adds its
owned test CA to upstream trust and restores the previous route/trust. Host-side
control inspection is separate from guest traffic. Guest traffic uses the real
localhost UDS (gVisor) or vsock (VZ) bridge; direct host/control reachability tests
do not open a second authorized egress path.

Linux full/installed lanes use proxy/admin/web ports 8180/9190/8181, HTTP origin
18080, TLS fixtures 18443–18452 and control 19999. Physical VZ uses only
46370–46375: Coord client/admin/Coord monitor on 46370/46371/46372, combined
parent/HTTP/control on 46373, SNI-selected HTTPS variants on 46374, and the
lifecycle owner admin on 46375. TCP proxy/web listeners are unbound in that VZ
configuration. Precheck the actual host ports, refuse occupied fixtures, and
stop only owned processes with verified identity. A Linux fixture's cleanup
does not prove that a physical Mac port is free.

The sinkhole retains UTF-8 replacement `body` and lossless `body_hex`;
`CapturedRequest.body_bytes` checks arbitrary bytes including invalid UTF-8.
`raw_target`, `raw_query` and ordered `header_items` preserve exact targets,
queries and duplicate fields. `body_received_bytes`, `body_expected_bytes`,
`body_complete` and `connection_closed` distinguish complete fixed/chunked
receipt from early close. A connection with no request is not a delivery.
Receiver readiness requires a direct probe observed through the control API,
then clears that separate observer increment before negative assertions.

Fixture private keys stay in the disposable config outside the repository;
only public certificates are exposed read-only to guests. Test-only interception
roots and isolated test-context configuration never change an operator's live
CA or policy. Approved writable mounts remain operator data; these tests do not
create a new restriction on what an operator may mount.

## Native component development and adding tests

From the repository root, prepare the locked development environment and native
binary, then select a relevant test module:

```sh
uv sync --frozen --group dev
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh build --locked --manifest-path proxy/Cargo.toml
SAFEYOLO_RUST_PROXY="$PWD/proxy/target/debug/safeyolo-proxy" \
  uv run --frozen pytest -q tests/proxy_contracts/test_https_contract.py --proxy-backend rust
```

Component fixtures run separate real native processes, UDS, origins, policy,
audit and cleanup. They make no guest isolation claim. Put a native protocol/API
contract there; retain installed/guest/approval compositions here. Add meaningful
negative controls and exact origin observations, use the production API rather
than reimplementing decisions, and declare Title/What/Why in blackbox pytest
class/method docstrings. Update procedure docstrings for their real observations.
Run `python3 tests/blackbox/gen_docs.py` after changing maintained selections.
Update the existing [assurance map](../../docs/assurance-map.toml) for moved owners;
do not create another coverage ledger or change a protected baseline to clear a badge.
