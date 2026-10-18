# Installed blackbox tests

Use this suite to check the installed SafeYolo package, real guest isolation,
agent workloads, access approvals and lifecycle. Rust proxy process and
protocol contracts live in [`tests/proxy_contracts`](../proxy_contracts/).
A hosted process or package result does not prove KVM or Apple VZ isolation.

## Test retained nightly inputs

The [nightly workflow](../../.github/workflows/blackbox.yml) runs at 03:17 UTC.
It installs existing default-branch production bundles and the newest complete,
successfully staged compatible guest. Product, rootfs, kernel and helper
builders run in separate producers. The test jobs never replace a missing input
with a source build or an older passing test candidate.

The host producer must first retain a complete bundle for the platform. The
guest must have the completed-staging attachment described in the
[guest OCI contract](../../docs/guest-oci.md#nightly-consumer-staging-receipt).
That staging input is supplied by #1104; historical layouts and publication
dates do not establish it. Until both inputs exist, selection fails visibly.
Source tests alone do not establish end-to-end retention or hardware readiness.

For a local retained run, use a disposable supported host, a clean pinned test
checkout, its frozen development Python environment, GitHub CLI (`gh`) with
repository Actions read access, and ORAS. No product compiler is required.
Linux needs the [host prerequisites](../../docs/installation.md#guest-prerequisites)
and noninteractive sudo. The archive installer checks and explains host setup;
`--yes` below accepts those changes on this disposable host.

From the checkout root on Linux AMD64, replace both `/owned/` paths with new,
private disk-backed directories. Use `linux-arm64` for an ARM64 host.
The first command downloads and freezes the selected inputs. The second command
installs that exact host archive and guest index, then runs all maintained
systrap sections with separate writable state and owned cleanup.

```sh
.venv/bin/python scripts/select_blackbox_artifacts.py --platform linux-amd64 --output /owned/blackbox-inputs
.venv/bin/python tests/blackbox/retained_inputs.py run --lane systrap --yes --selection /owned/blackbox-inputs/selection.json --artifacts /owned/blackbox-reports
```

`selection.json` records the captured default-branch head, selected host build
age, host/helper source and profile, producer workflow/run/attempt/job, artifact
ID and checksum, and guest index/child/archive descriptors. It records the test
controller separately. An older retained build does not test today's head.
There is no new age cutoff. A guest still inside its 48-hour promotion
quarantine is valid input. Test success does not move a production tag.

`installed-inputs.json` records the actual installed host/helper hashes and
guest descriptors before any section starts. `retained-run.json` records the
actual test controller, platform, input mode, test provisioning mode and exit.
Sections retain their existing reports. Missing, expired, partial, incompatible,
wrong-source/profile/platform or checksum-mismatched selected inputs fail the
attempt. Retry with new directories; failed attempts are preserved. Raw logs
and instance state stay private. Hosted report artifacts remain for 30 days.

Trusted dispatch can set `host_run` and `guest_index` to exact producer and
staged-index identities. The selector accepts the same choices through
`--host-run` and `--guest-index`. These choices still require trusted default-
branch production inputs. For an exact release, verify that all required lanes
use that release's host archive bytes and the exact compatible guest digest.
Independent nightly selections are not a combined release pass. Public-install
smoke selects the promoted compatibility channel separately.

The [hardware deployment guide](hardware/README.md) uses the same selector and
installed runner for independent KVM and physical VZ execution. Craig owns cron
installation; the source scripts and examples do not establish deployment.

## Build and test a contributor checkout

For source-based acceptance, use a disposable supported host and a clean checkout
of the exact commit being tested. Install uv and select Rust 1.94.0 from
[`proxy/rust-toolchain.toml`](../../proxy/rust-toolchain.toml); Cargo must be on
`PATH`. Linux preparation needs noninteractive host sudo, subordinate IDs
covering 100000–165535, and the [guest prerequisites](../../docs/installation.md#guest-prerequisites). The workloads
section additionally needs `dpkg-deb` and `openssh-server` on its host. KVM
requires a fresh libvirt guest with usable `/dev/kvm`. VZ requires physical
Apple Silicon and the Swift helper build prerequisites in the
[installation reference](../../cli/README.md#installation).

### Run installed sections with one preparation

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
`run-lane.sh --prepare-only` once: the supported `install.sh`, locked
host test dependencies and verified NATS input. Supply prepared bundles
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
CLI/executable. Each gets a fresh agent, config, data, logs, public and
private fixture certificates, overlay, origins, captures, approvals, tokens,
Coord test instance and writable state. The lifecycle section's separate live
owner also gets its own instance. Sharing preparation does not share live
scenario state. NATS executable bytes are prepared once and reverified by the
installed launcher in each instance; credentials and JetStream data are private.
Individual procedural compositions remain intact.

For a guest without Debian or Python Package Index (PyPI) network access, first
stage verified offline test inputs under the test checkout's `offline/`
directory. Supply `debs/*.deb` for Python, pip and all their Debian dependencies,
matched to the selected guest's architecture and installed packages. Supply `wheels/*.whl` for the
unchanged [`guest-requirements.txt`](guest-requirements.txt), including its
interpreter-specific dependencies. Verify the input archive against the
supplier's checksum before extracting it. Keep the host's proxy and certificate
settings.

Set `SAFEYOLO_GUEST_TEST_INPUTS` to the absolute path **inside each guest**.
The test checkout is mounted at `/workspace` for the subject, peers and lifecycle
owner. From the same repository root on the physical Mac, run:

```sh
SAFEYOLO_GUEST_TEST_INPUTS=/workspace/offline ./tests/blackbox/run-installed.sh vz --section isolation --section access --section lifecycle
```

Each boot, including a restart, installs the local Debian archives without
repository access. It then installs Python test packages with index access
disabled and required lock hashes, and checks imports. Missing inputs or failed
package checks exit 2 as failed fixture preparation. With
`SAFEYOLO_GUEST_TEST_INPUTS` unset, setup uses the normal online
package path. This selection prepares test dependencies only; host preparation
still needs its usual prepared inputs or network access.

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

For the continuous Ubuntu or physical Mac operator/guest path, select the
prepared bundle and a desktop-capable `SAFEYOLO_PLATFORM_ASSETS` tree. The guest must already
contain Xvfb, x11vnc, a supported window manager and noVNC web assets. Use the
graphical builders or the [desktop rootfs instructions](../../contrib/ROOTFS_SCRIPT_GUIDE.md#optional-desktop).
The installed guest helper supplies the HTTP/WebSocket-to-VNC bridge;
the procedure checks these inputs and does not install guest packages. No proxy
or guest needs to be running. From the clean test checkout on Ubuntu, run:

```sh
./tests/blackbox/run-installed.sh systrap --section access --operator-journey
```

On a physical Apple Silicon Mac, the platform assets must include the kernel,
initramfs and desktop-capable `rootfs-base.ext4`. Verify that the selected shell works under the test account before the journey. The VZ fixture uses
46370/46372 for owned NATS, 46371 for Admin, 46373/46374 for HTTP/HTTPS and
46375 for desktop presentation. Those TCP ports must be permitted and free.
From the clean test checkout on that Mac, run:

```sh
./tests/blackbox/run-installed.sh vz --section access --operator-journey
```

This selection uses one installed instance and agent for access, terminal
attachment plus an independent shell, Admin desktop presentation and
missing-target reporting, then stop/restart and fresh traffic. It runs an owned
shell marker command, with no model or simulated login. Desktop observations
cover the unlocked noVNC page and a live VNC banner; they do not prove visual
interaction. HTTP export remains `raw_request`. The runner stops its agents,
proxy, Coord and fixture processes.
`access/installed-access.json` retains reached access observations if a later
operator step fails; `operator_incomplete` is not a completed journey. When only
test inputs changed, use `--install-checkout` and `--install-commit` to name the
clean source of the supplied package and retain both actual source revisions.

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

## Journey with Python unavailable

This bounded R5 preparation exercises installation, start/status/doctor,
the installed host Coord identity, one systrap guest's boot-helper identity and
authenticated Agent API health, then owned stop. It also keeps a second
disposable proxy live through the subject's
stop and checks its process receipt, policy and Admin response. It uses
the ordinary bundle installer and agent shell. The ordinary guest has
`/safeyolo/safeyolo-guest`; it does not stage `/safeyolo/safeyolo-coord`.
Harness setup stages Coord at `/home/agent/.safeyolo/safeyolo-coord` through
`contrib/lib/stage-coord-native.sh`. The existing installed Factory staging
test in `tests/proxy_contracts/test_native_factory_cli.py` covers that producer.
This journey does not select a harness, final candidate F or the full release lanes.

Use an owned, isolated Ubuntu host provisioned without Python interpreters or
embedded Python libraries, and a separate prepared guest `rootfs-tree` with the
same property. Preserve the guest prerequisites and UID 100000 ownership.
The normal [guest builder](../../guest/build-rootfs.sh) includes Python; its
unchanged output does not supply this input. Stage matching bundles and
only the required shell/tools. Do not mount development environments,
Python caches or operator homes into either boundary. Provisioning and package
metadata must establish the filesystem boundary; changing `PATH` or searching
for `.py` files does not establish it. This preparation does not remove Python
from a working host or edit the shared guest tree.

The shell entry runs inside that disposable host. Python test drivers and the
trace reader run on the external harness host, outside both product filesystems.
The runtime owner must bind a noninterfering host execution observer before
claiming Python absence. Its scope must include the launched descendants:
installation, CLI, proxy, Coord and host launch tools.
The separate guest trace covers the selected shell/helper/API lineage.
The guest trace does not cover PID-1 boot, supervision/recovery, models, ordinary
workloads or launches delegated to an existing systemd owner. A tracer that cannot decode executable filenames is unavailable
evidence. In particular, nested ARM64 gVisor can return an address instead of
the `execve` filename; the reader refuses that log.

On the disposable Ubuntu host, use its ordinary account and a clean checkout.
Supply the unpacked bundle at `/home/agent/r5/bundle`, prepared assets at
`/home/agent/r5/platform`, and an absent state directory
`/home/agent/r5/state`. Replace `FULL_SOURCE_COMMIT` with the bundle's recorded
full source commit, which may differ from this test entry's revision. Both
host and guest need Bash and curl; the guest also needs `strace`. The host needs
the Linux prerequisites above. Permit the configured pinned NATS acquisition route, or
set `SAFEYOLO_COORD_NATS_BINARY` to an already checked binary. Preserve
the proxy and certificate environment. Keep execution logs private; they can
contain command arguments. The following commands are the control and product
entries to observe. The host control deliberately exits 97; its stderr must
report `interpreter_available=0` on this host. The product entry below runs
without host tracing unless the runtime owner has bound that observer.
Observe the host control before the product window so its deliberate Python
attempts remain separate. Use a fresh private log directory; retain the host
observer's logs and matching filesystems for external inspection.

```sh
umask 077
./tests/blackbox/attempt-python.sh
./tests/blackbox/native-python-journey.sh /home/agent/r5/bundle /home/agent/r5/platform /home/agent/r5/state FULL_SOURCE_COMMIT
```

On the [selected Ubuntu/gVisor setup](https://github.com/craigbalding/safeyolo/issues/822#issuecomment-6054864737),
privileged host `strace -u` interfered with startup and cleanup. Do not reuse
that tracing recipe for this journey. The runtime owner supplies the host
observer through the existing owned Ubuntu route. The retained Berkeley Packet
Filter (BPF) controls recover cold successful and failed
`execveat` filenames and track selected descendants. They do not establish
complete lifetime, argv, shebang, empty-path, loss/truncation handling or guest
compatibility. Raw BPF records are not inputs to the strace-format reader below.
The observer output/reader binding remains an execution prerequisite; do not
convert a blank or unmatched record into a clean result. An untraced successful
entry establishes only the reached functional path.

The journey's guest control must exit 127 and retain a nonempty
`state/instance/agents/r5check/home/r5-control.exec`. Its clean guest window is
`r5-guest.exec` in the same directory. `cleanup.txt` preserves the original exit
and cleanup result. Nonzero execution, failed cleanup or a missing trace is
incomplete; retain the stopped state and private logs for diagnosis.

Use the existing harness transfer to read the two guest traces and the host
observer results on the external Python test host. For each strace-format
trace, run `python tests/blackbox/check_python_execution.py TRACE` there.
Exit 1 reports Python attempts; exit 0 requires decoded, finished observation
with no named Python attempt. Exit 2 reports unavailable or incomplete
observation. Both controls must report the Python violation, and both product
windows must have complete observation with no Python attempt. For absolute script/shebang lookup,
provide `--filesystem-root DIRECTORY` with the retained matching filesystem;
without it, `shebang_lookup` is false and only executable names are checked.
An explicitly supplied missing path or ordinary file returns exit 2.
Do not replace an unreadable filename with `argv[0]`.

Reconcile this reached path with the existing [production-use map](../../docs/settings.md#operator-entry-responsibilities),
bundle `package-info`/`SHA256SUMS`, producer/installer, staged guest
scripts and OCI mounts, Cargo lockfiles and resolved ELF dependencies. The
reader detects named Python/PyPy paths and Python shebangs in readable retained
files. Renamed interpreters, embedded libraries and unobserved guest paths
remain static review obligations. Source preparation or an exit code alone
does not accept R5. Remaining child demonstrations, final package/dependency
reconciliation and three final platform lanes remain open.

## Cadence and hardware evidence

Normal PRs run quick checks and relevant platform tests for platform changes.
Complete retained Python/CLI and component families run overnight on
supported hosts. The full Mac proxy protocol family runs once, in
[`proxy-rust.yml`](../../.github/workflows/proxy-rust.yml). The separate hosted
Mac installed job runs the short package witness below. Full-suite success is
not a routine PR gate; discovering regression the next morning is accepted.

The approved overnight scope includes systrap, KVM-backed gVisor and physical
Apple Silicon VZ. Current GitHub automation schedules systrap and hosted
package/component checks. Hardware scheduling/publication remains
[#889](https://github.com/craigbalding/safeyolo/issues/889); this restructuring
supplies its maintained runners without claiming that automation is complete.
The [independent hardware entries](hardware/README.md) consume retained inputs;
they do not build on Tart during the nightly invocation.

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
exact selected host/helper artifacts and compatible guest digest, separate
controller source, actual platform identity, observed result,
owned cleanup and sanitized publication. Public PR code must not execute on a
persistent hardware host through an untrusted trigger. A stale ref or another
owner's live resource does not satisfy those prechecks. Before release, retain
exact-release-commit results for all three actual isolation mechanisms.
Historical #640 receipts remain historical acceptance; #320 does not reopen them.

## Connected public onboarding observation

`ubuntu_onboarding.py` retains its unattended signed-out observation. Its
`--connected` mode observes one authorized Ubuntu AMD64 first task and one live
return. This is operator test tooling, not another user setup command or a
product acceptance result.

Use one newly owned OS-only Ubuntu 24.04 AMD64 host as its ordinary user.
No SafeYolo proxy or sandbox must already run. Stage only this observer and
`harness/process_identity.py` outside the product checkout, as in the
`public-install` job in `.github/workflows/installed-arm64.yml`. Python and any
outer terminal tooling are observer inputs. Preserve the product's normal
PATH, proxy, CA settings, HOME and shipped launcher. Do not prepare product
packages, guests, runtimes or vendor caches.

The operator provisions the already authorized test account into the user's
normal `.claude.json` and `.claude/.credentials.json` host locations. The
operator keeps source selection, credentials and transport private. Select the
current profile at actual use. A stored expiry or `loggedIn` value does not
prove provider authentication. The product asks for consent and performs its
own supported host-state copy. An ordinary user with existing supported host
authentication does not run the test account's encryption/transport recipe.
The browser-login path without existing host authentication is outside this
connected witness.

Before product execution, record the preparation already performed in a small
nonsecret JSON input. `required_user_commands_complete` and
`required_user_reading_complete` must be true. `commands` lists each actual
invocation as an argument array in `command`, with `role` set to `required-user`,
`fixture` or `observer`. Each entry needs a `reason` grounded in the ordinary
caller or fixture recipe. Use `started_at` and `ended_at` for observed UTC
times, or null for unknown times. Replace private operands with named inputs;
include no credential values. `required_reading` lists objects whose `text`
contains all required preparation prose. Record its UTC `seen_at` start or null
if unknown. Missing starts leave the complete cold elapsed time unknown.
Use explicit empty lists when no commands or preparation reading were needed.
Do not classify a real user
prerequisite as fixture work. A required command increases the total even when
the installer still uses two product commands.

`decisions` lists each preparation decision with its `role`, a nonsecret
`description`, and the observed UTC `seen_at` and `answered_at` times. Use null
for unknown times and an explicit empty list when there were no decisions.
Include any required browser or account interaction in the ordinary-user
category. Stored authentication metadata does not replace that accounting.

From the staged observer directory on that host, replace `OWNED_HOSTNAME` with
its exact hostname. `host-preparation.json` must contain those actual operands.
Replace `FULL_OBSERVER_COMMIT` with the full commit of the staged observer.
The observation directory must be new. Run in an attached foreground terminal:

```sh
python3 -I -B ubuntu_onboarding.py --host OWNED_HOSTNAME --platform linux-amd64 --connected --preparation host-preparation.json --observation-dir private-observation --observer-source FULL_OBSERVER_COMMIT
```

The observer uses bootstrap `45d8853a` and public host release
`host-c5ce76019b6c997e282ab05cea0212b492e945d2`. It counts the displayed normal-path
prose and setup consent, then forwards ordinary foreground input. Complete any
vendor display choice. For a pending request, use Ctrl-b then d, `a`, the current
request number and the displayed scope before entering `approve`. Press Enter
to leave the picker, then Enter to return to the agent. These are interactions
in the same product command. Do not use another CLI to inject policy or grants.

When the live input display is ready and pending approvals are resolved, press
Ctrl-] once. This is an observer trigger. The observer sends the fixed
`index.html` task literally, waits 0.3 seconds, checks input readback, and sends
one Enter. It then requires one saved user turn, a matching Write/tool result,
the host file and the returned input display. It detaches and uses `q` normally,
then repeats the launch command once and checks the same live task/session/file.
Do not enter another task. A failed or uncertain input is preserved without
retransmission. Authentication failure does not start login or warm retries.

Only `result.json` is shared. Account screens, history contents and state hashes
stay private. The result records preparation, command/decision/reading counts,
sampled cold/warm boundaries, measured input/observer/provider intervals,
actual package/guest identities and selected state comparisons. Unknown wait
attribution stays unknown. Reading counts include whole decision screens,
recorded output before consent or host-control input, and repeated text.
The counts exclude the known task and command echoes. They are a
conservative displayed-token count. The private screens allow later inspection.
The observer reports changes to vendor usage metadata or renewed tokens without
requiring whole vendor files to stay identical. Whole-home/cache equality and
uncaptured-process cleanup are not claimed. The 15-second target remains unmet pending actual
evidence and operator disposition.

Normal cleanup stops the installed agent, proxy and Coord and checks captured
process births/listeners. After interruption, use `--cleanup-only` with the same
host, platform and observation directory; it does not replay product input.
The operator then removes only the new private credential copies, stops the
exact outer fixture and releases its owned lease. Preserve the original login.

## Existing single-section entry points

`run-lane.sh` remains the supported installation plus one test selection
entry point, including the full installed isolation lane used by acceptance
hosts. From the repository root on the matching disposable host, set
`SAFEYOLO_CONFIG_DIR` to a fresh installation root and supply the and
platform inputs above before running:

```sh
./tests/blackbox/run-lane.sh systrap --verbose
```

If SafeYolo and platform inputs are already prepared, run a section without
reinstalling. `SAFEYOLO_CONFIG_DIR` names the prepared source instance;
`SAFEYOLO_TEST_CONFIG_DIR` names the separate live test instance:

```sh
SAFEYOLO_CONFIG_DIR=/path/to/prepared \
SAFEYOLO_TEST_CONFIG_DIR=/path/to/disposable-test \
  ./tests/blackbox/run-tests.sh --expect-platform systrap --verbose
```

The Rust package is the default. The runner refuses to use its source
instance, the operator's normal instance or an ambiguous live config as test
state. It links compatible `share/` and `bin/` inputs, creates fresh writable
state, verifies actual guest metadata for platform selection, and records the
installed source/profile, packaged executable, actual process/start identity, authenticated Admin
runtime identity and per-agent listener before guest assertions. `--workloads`,
`--access`, `--lifecycle` and KVM `--ingress` select procedures and exit before
the full pytest phases. `run-lane.sh` supplies their selected source checkout.
For a direct prepared procedural run, also set
`SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT` to the checkout that produced the installed
layout and executable. The runner resolves its HEAD; `--install-commit FULL_SHA`
must match that checkout before setup. The installed executables, package metadata and live runtime
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
commits, including the five unexecuted isolation assertions. Fresh installation and direct recovery commands are in the
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

**Access** stays one composition with two live guests, an operator, Rust proxy,
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
host instance without booting guests. Four identified processes write,
replace, revoke and deliberately recover access. Return processes must retain
SQLite ownership, exact bodies, tags and correlated audit; enforce an open
circuit before operator reset and avoid resurrecting it afterward; retain
catalogue, policy, grants and scoped host/service revocations; preserve Coord
messages/attention and the provider-owned lease snapshot; the fresh process must report unknown lease state without inventing held ownership.
It retains approved Plumb messages before close returns 403. The same sequence
checks stored OAuth refresh/use, trusted upstream TLS, stable CA/HMAC identity,
0600 private state and process-local task reset. Each process, listener, NATS
server and owned origin must stop. The historical cross-backend executor was
retired after [Lens verified the Linux replacement](https://github.com/craigbalding/safeyolo/issues/320#issuecomment-5951336164).
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

This installs the current layout without a guest rootfs build, uses the
normal launcher/configuration, authenticates exact running identity, observes
allow/deny at two authorities on one owned HTTP listener and verifies
stop/cleanup. The allowed IP and denied localhost authorities both reach that
known-live fixture before the policy probe. Success
is for this host-package claim; no guest boots and guest isolation is explicitly
unproved. It then runs the three existing `test_https_origin_verification` nodes
against the packaged executable: trusted localhost reaches the origin, wrong
SAN and untrusted origin return 502 without origin delivery. It does not repeat
the complete component matrix against the package.
The same prepared product then runs the separate host-continuity
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
contract sockets when the default temporary directory is unavailable.
The harness creates a private temporary directory there and removes it after
each case.

`installed_host_smoke.py --mode discover` identifies prerequisites;
`--mode attached` authenticates an already running installed proxy without
restarting it. Their JSON statuses and limitations must be read; merely writing
a report is not a pass. Discovery/attached guest claims require their actual
substrate and listener; the host-only smoke does not claim one.

## Hosted Linux ARM64 archive qualification

The manual [installed-arm64 workflow](../../.github/workflows/installed-arm64.yml)
uses the repository's `ubuntu-24.04-arm` pool for real systrap guests.
The default `retained` mode uses the shared selector and installed runner above.
It accepts `host_run` and `guest_index` for trusted exact selection. The separate
explicit historical `draft-offline` mode tests the published production host
from `c9ecb66b462c2ba0c499f2322f6cfc5c142012da`. It retains its original name and selects original
guest `guest-2026-10-12.1` from `8234a047d810d543d8c4d1cb1fa9859987be035b`.
Select `guest=reduced-33224` to test the reduced `guest-2026-10-16.1082` guest
from `33224c9fc14beeb00be30eb71bdc09f91c5aa58b`. The separate `public-install`
mode uses the published default guest and ignores this selection.

The acquisition job uses a read-only repository token for fixed release and
asset GET requests. Release `414106024` must be published with tag
`host-c9ecb66b462c2ba0c499f2322f6cfc5c142012da`, ARM64 production asset
`644683987` and checksum asset `644683989`. The job has no checkout and runs no
product, verifier, guest or publication command. It transfers only the
hash/size-bound host archive, checksums and release metadata through an Actions
artifact. The qualification job keeps `contents: read` and `actions: read`.
It downloads that artifact by ID from the same run and rechecks the host inputs.

The original G1 layout is retained in run `38248401312`, artifact `11747551391`,
which expires on 10 January 2027. The reduced layout is retained in normal guest
build `38975155518`, artifact `12079186556`, which expires on 14 January 2027.
Both selections verify the pinned logical index, source, version and archive
before extraction. Extraction preserves Linux ownership and permissions.
The released host then selects safe subordinate IDs for the runner account.
Its existing ownership helper maps only this run’s fresh extraction to those
IDs, preserving modes and cache paths. Other accounts and prepared trees stay
unchanged. The installer accepts the required host setup on this disposable
runner through `--yes`.

From an authenticated operator terminal in this checkout, dispatch the reduced
guest qualification at the reviewed workflow ref:

```sh
gh workflow run installed-arm64.yml --ref master -f mode=draft-offline -f guest=reduced-33224
```

For a lifecycle-only correction with unchanged installed inputs, add
`-f section=lifecycle`. Retain earlier isolation/workload results with their
original test-source identities. The report lists the sections that actually ran.

The default reduced selection runs the maintained isolation, workloads and lifecycle
sections. These include authorized and unknown-key guest SSH checks, a pinned
SSH client command, package installation and removal, mediated traffic,
direct-egress refusal, restart/state checks and owned cleanup. The original G1
selection keeps its isolation/lifecycle smoke. After the selected sections pass,
both run the existing installed host, HTTPS and continuity checks.
`run-installed-package.sh --section`
can select maintained sections for an explicit `--lane`; omitted sections retain
the wrapper's previous defaults.

The `installed-arm64-RUN_ID` artifact contains individual isolation/root/home
test outcomes, guest metadata, section reports, installed host/HTTPS/continuity
reports and owned cleanup observations. Read each result and any skips before
claiming coverage. A failed acquisition stops before installation. The run
builds only the existing OCI verification tool; product files come from the
retained archives. Python and uv provide test observers. This staged result does
not establish anonymous public OCI acquisition, Python-free installation, guest
updates, matched acquisition-through-first-task timing or a transfer exceeding
2 GiB. The workflow publishes no host or guest artifacts.

## Owned origins and observation fidelity

The runner routes synthetic hosts through its owned parent and sinkhole,
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

## Component development and adding tests

From the repository root, prepare the locked development environment and binary, then select a relevant test module:

```sh
uv sync --frozen --group dev
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh build --release --locked --manifest-path proxy/Cargo.toml
SAFEYOLO_RUST_PROXY="$PWD/proxy/target/release/safeyolo-proxy" \
  uv run --frozen pytest -q tests/proxy_contracts/test_https_contract.py --proxy-backend rust
```

Component fixtures run separate real processes, UDS, origins, policy,
audit and cleanup. They make no guest isolation claim. Put a protocol/API
contract there; retain installed/guest/approval compositions here. Add meaningful
negative controls and exact origin observations, use the production API rather
than reimplementing decisions, and declare Title/What/Why in blackbox pytest
class/method docstrings. Update procedure docstrings for their real observations.
Run `python3 tests/blackbox/gen_docs.py` after changing maintained selections.
Update the existing [assurance map](../../docs/assurance-map.toml) for moved owners;
do not create another coverage ledger or change a protected baseline to clear a badge.

## Installed shared-approval witness

This contributor procedure exercises the shared-approval protocol. Worker is
the requesting test guest; Helper is the separate assisting guest. The driver's
default names are `worker` and `helper`. If the owned setup uses other names,
add `--worker NAME --helper NAME` to the invocations below. For ordinary access
decisions, use the [operator guide](../../docs/operator-guide.md).

Run from this checkout on the existing owned Ubuntu/systrap fixture. The selected
Rust proxy and two guests must already be running. The marked disposable root
must expose each guest's existing read-only `config-share` mount. Supply the
full product commit and installed CLI/proxy/guest assets with matching source
and build profile. Keep the installation's `package-info` beside its `bin`
directory. The driver checks the process receipt, kernel process birth,
selected executable/configuration and authenticated runtime identity before
guest work. It resolves readiness and Admin token paths from `config.toml`.
Missing, stale or foreign ownership refuses the run. `TRANSPORT_CLI` is the
maintained test transport that already controls those guests; it needs `agent
shell` and `agent stop`. Those host entries remain #817's responsibility.

For the real Helper mode, Helper must already have its ordinary Codex launcher,
model access and guest authentication. The probe imports no host credential and
does not select another model. It preserves the configured model route and
credential controls. Start Helper's sandbox with `agent start helper
--sandbox-only`; the probe launches its one Codex command through `agent
start helper --foreground`. It preserves an already active coding session by
refusing to replace it. Before the run, verify the ordinary launcher version and
login status inside Helper. An operator may privately copy an existing
provisioned Codex token into this owned test home under the standing test
authority. Keep the managed configuration and proxy/CA settings. Do not copy
the Admin API credential into Helper.

`TRANSPORT_CLI` is the installed CLI for this root. `FULL_COMMIT` identifies
the installed CLI/proxy/guest source, separately from the checkout containing
the test driver. `ROOM` is an existing ordinary Coord room in this disposable
instance, with Helper send/receive and Worker receive permission. Keep it
separate from a running factory's work room. Both guests use the ordinary staged
`/home/agent/.safeyolo/safeyolo-coord` binary with their own Agent API identities.
The real run saves raw Codex events and stderr before parsing them, including
when the command fails. `--helper-events FILE` selects the events file in
an existing host-owned directory outside guest writable mounts. The default
is a unique file in the root's logs directory; stderr uses `FILE.stderr`.
Both files have private permissions. Preserve a failed run's events
for diagnosis instead of starting another model session to recover its operands.

Replace these operands before running as the disposable instance's owner.
Connect the approved Tart Commander client to this Ubuntu instance before the
decision. Use its existing remote connection settings and separate Admin API
and SSH credentials. For an SSH tunnel, loopback HTTP and WebSocket endpoints
are supported; the event path is `/admin/events`. This command changes the
disposable policy, invokes one Codex session and waits up to 600 seconds for a
human decision through CLI or Commander:

```sh
uv run --frozen --no-sync python tests/blackbox/installed_shared_approvals.py \
  --config-dir ROOT --transport-cli TRANSPORT_CLI \
  --native-cli ROOT/bin/safeyolo --native-proxy ROOT/bin/safeyolo-proxy \
  --commit FULL_COMMIT --interfaces --real-helper --shared-room ROOM \
  --operator-timeout 600 --reconcile-seconds 120
```

The result requires diagnostic/show/preparation commands executed by
Codex, a canonical Helper-attributed typed preparation, unchanged network
permission before the human decision, two exact Worker marker deliveries,
refusal for Helper and the second port, and owned cleanup. The driver prints
the trusted scope and separately quoted Helper diagnosis before the
human decides. Helper's successful preparation does not grant network
permission. Rejection, an expired decision window or a changed action stops
the journey without a Worker retry. Model prose and a successful process exit
do not establish U3.

The fixed disclosure inputs place a synthetic secret in selected raw evidence
and a separate peer record outside Helper's reads. Helper responses, routine
logs and the shared-room notification must exclude both. A deterministic
Helper call appends the fixed terminal-control/Markdown/HTML reason to the
real diagnosis on the same typed action. The display quotes that reason;
the shared notification carries only the permitted canonical projection.
Raw evidence remains available to its authorized owner.

When `client_reconciliation` appears, the same action has its canonical CLI
outcome and two exact Worker marker deliveries. The proxy and guests remain
live for the selected 120 seconds. Reconnect the other client during this window
and observe the same terminal state and reusable Worker/host/port effect.
Record the actual Commander display and backend/source separately. The driver
does not infer a GUI result. Its teardown then stops both guests, proxy,
listeners and origins, and restores the saved fixture policy after proxy exit.
An inactive process receipt or an inert socket file does not fail cleanup.
The driver checks actual process exit, withdrawn readiness and closed listeners.
Cleanup errors remain failures.

Omitting `--real-helper` selects deterministic preparation. Add
`--wait-for-operator` to use the same human/client window without a model turn.
These controls do not establish the real U3 action or isolated model failure in
a running Helper. That U6 failure observation remains separate from tool/login
readiness. Reuse the accepted lost-reply, authority and race controls at their
tested revisions.

For the separate U6 model failure case, use the same owned Ubuntu/systrap setup
with both sandboxes and the proxy running. Helper's ordinary Codex command must
be stopped before the probe. Verify its installed launcher version and login
status. Replace `ROOT`, `TRANSPORT_CLI` and `FULL_COMMIT` with the installed
instance operands described above. Run from the checkout containing the probe:

```sh
uv run --frozen --no-sync python tests/blackbox/installed_shared_approvals.py \
  --config-dir ROOT --transport-cli TRANSPORT_CLI \
  --native-cli ROOT/bin/safeyolo --native-proxy ROOT/bin/safeyolo-proxy \
  --commit FULL_COMMIT --interfaces --model-unavailable
```

The probe prepares the selected pending action with deterministic Helper
calls. It uses its second owned listener at `127.0.0.3` as a model endpoint
returning HTTP 503. Only Helper receives fixture access to that listener. A
command-scoped Codex provider override selects that endpoint without changing
the saved model configuration or credentials. HTTP and stream retries are zero;
no paid model request or repeat U3 witness is needed.

Before returning the 503, the endpoint records Helper's running sandbox,
coding-agent and launch identities, the same pending action, unchanged policy
and zero Worker deliveries. The probe requires an actual model request naming
the selected request, an initialized Codex thread and the matching failed-turn
diagnosis. A missing launcher, authentication failure or successful process exit
cannot supply this result. The printed `model_unavailable` phase contains the
diagnosis and pending action. Raw events and stderr retain private permissions.
The CLI then displays the trusted scope and directly approves through
the common resolver. The final result requires the approved canonical action,
exact Worker marker deliveries, refused Helper/second-port controls and owned
cleanup. The model failure itself must leave the action pending and policy
unchanged. Add `--wait-for-operator --reconcile-seconds 0` when a human should
make the direct decision instead of the fixture's explicit operator call.

Commander can run on approved Tart against the same Ubuntu pending item.
Physical-host GUI placement is not a prerequisite. A client source test does
not establish the actual cross-client journey.
See the [entry responsibility map](../../docs/settings.md#operator-entry-responsibilities)
for the retained component boundaries.
