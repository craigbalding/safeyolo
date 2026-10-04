# Hardware blackbox deployment

Run fresh Linux Kernel-based Virtual Machine (KVM) acceptance on devstack and
physical Apple Silicon Virtualization.framework (VZ) acceptance through
Bristol's `sy-agent` account independently. Tart builds, signs and packages
the macOS inputs. Bristol verifies transferred inputs and executes offline.
Each lane selects and records its own full source commit. Before release,
both lanes must pass at the exact release commit.

Craig's [3 October scope correction](https://github.com/craigbalding/safeyolo/issues/889#issuecomment-5971434225)
calls for a small wrapper around the existing harness and suites.
`run-hardware-lane.sh` checks an explicitly selected full commit in a clean
checkout and invokes `run-installed.sh`, retaining its exit status and reports.
The existing operator-owned Rundeck and Bristol routes invoke it in their
respective prepared environments. It allocates no host or guest and installs
no schedule. Craig's [4 October independent-script correction](https://github.com/craigbalding/safeyolo/issues/889)
requires two independent scripts and independently installed cron entries.
Those complete deployment scripts and their publication/email bindings remain
unfinished. The prepared-environment commands below are on-demand suite
invocations, not the complete scheduled path.

From a separate pinned trusted checkout, with `SELECTED_CHECKOUT` and a new
`RUN_ARTIFACTS` directory supplied by that lane's existing harness:

```sh
# Through Rundeck, inside the fresh devstack acceptance guest:
./tests/blackbox/hardware/run-hardware-lane.sh \
  "$SELECTED_CHECKOUT" "$SELECTED_SHA" kvm "$RUN_ARTIFACTS/kvm"

# Through Bristol SSH, after verified Tart inputs have been transferred:
./tests/blackbox/hardware/run-hardware-lane.sh \
  "$SELECTED_CHECKOUT" "$SELECTED_SHA" vz "$RUN_ARTIFACTS/vz" \
  --staged-inputs "$STAGED_INPUTS" --staged-sha256 "$STAGED_SHA256" \
  --python "$STAGED_PYTHON" --state-parent "$STATE_PARENT" \
  --vz-test-runner /Users/sy-agent/bin/run-vz-test \
  --vz-test-timeout-seconds "$VZ_TIMEOUT_SECONDS"
```

Each lane's trusted caller refreshes `origin/master` and resolves its full SHA
before an overnight run, or supplies an explicitly authorized full SHA on
demand. Neither lane waits for or triggers the other. Keep selection,
control/publication credentials, result collection and owned host teardown in
the existing harness. The wrapper filters
the environment before source checks or candidate commands; build/network and
CA settings remain available, while VZ package installation stays offline.
The unused paired controller, host process managers, configuration and cron
installer have been removed from this proposed merge. Their implementation
and findings remain at `3e163f36857c09a7bd3532f0e60de452c2702466`. The standalone
input producer and allowlisted publication helpers remain available.

If the maintained runner receives `SIGHUP`, `SIGINT` or `SIGTERM`, it stops
and reaps its launched preparation or section child before ownership-checked
instance cleanup. Offline preparation uses the same child lifetime. Cleanup
also checks product and helper identities retained before stopping the child.
The runner saves a nonzero `installed-summary.json` with the cancellation
signal, cleanup outcome and unexecuted remaining sections. A cleanup failure
keeps exit 2; established cleanup keeps exit 128 plus the signal number. No
later section starts after cancellation. The direct VZ deadline runner still
owns each VM helper.

If a remote observer connection is lost, treat the attempt's state as unknown.
Reconcile the retained local reports and owned processes through the existing
host harness. The observer's loss does not cancel a healthy independently
scheduled local attempt. `SIGKILL` or host death cannot execute runner cleanup.
An SSH or cron exit alone does not establish owned host teardown. Deployed
scheduling, publication, email delivery and independent hardware teardown
remain open before either cron command is ready.

Input packaging and identity checks retain the filtered build environment's
mediated-network and certificate settings. Bristol candidate commands use
the existing offline environment. The maintained lifecycle section retains
the independent owner's NATS identity before preparation, stages its offline
binary and passes its separate environment to both cleanup callers. Primary
NATS uses client/monitor ports 46370/46372; the independent lifecycle owner
uses 46377/46378. Any outer host reconciliation must preserve those identities
and the selected CLI's server-ownership checks.

Deployment and complete hardware acceptance remain open. The local
process, filesystem and service-protocol controls do not establish a hardware
pass or an installed schedule. The approved operator-side routes support
deployment; a pre-existing paired installation is not a prerequisite.
The [blackbox guide](../README.md) owns the maintained section selections and
the historical hardware observations and limitations.

## Use the existing KVM harness through Rundeck

The 3 October 2026 read-only deployment inspection verified Rundeck project
`acceptance` on devstack. The approved transport submits a Bash script to
`POST /api/59/project/acceptance/run/script` with
`scriptInterpreter=/bin/bash`. The response identifies the execution. This
interface has no fixed job ID. The execution account is `rundeck`, user ID 112.
Hardware-control and publication credentials stay outside candidate commands.
The existing harness jobs provide provisioning, guest execution, bounded
report retrieval and teardown. They do not provide a whole-attempt ownership
receipt or reconciliation command for interrupted provisioning.

The following host commands run through that approved Rundeck invocation as
`rundeck` on devstack. Before allocation, inspect current inventory, lease
ownership, defined domains and available capacity. The inspection's earlier
free-capacity result is not a reservation.

```sh
bash /var/lib/rundeck/harness/jobs/list_guests.sh
```

Before provisioning, the trusted caller must supply `ISSUE889_RUN_OWNER`, a
unique owner for this attempt, and `SELECTED_SHA`, the full selected commit
already available on origin. Release acceptance also requires VZ at that
exact commit.
Use `--reuse`: the default `--clean` mode removes unrelated inactive unleased
`sy-*` domains. Allocate a fresh guest for the unique attempt owner while
preserving those foreign resources.

```sh
bash /var/lib/rundeck/harness/jobs/provision.sh \
  --scenario "$ISSUE889_RUN_OWNER" --safeyolo-ref "$SELECTED_SHA" \
  --flavor full --distro ubuntu --reuse --vcpus 4 --mem 10240 --disk 90
```

The provisioner holds `/var/tmp/harness-vms/.provision.lock`. It refuses an
existing defined lease owner or any active `sy-*` domain. Its
`/var/tmp/harness-vms/.guest-lease` survives process exit and power loss.
Only a lease without a corresponding defined domain self-heals. Preserve
inactive leased experiments. For a stale automation-owned resource,
independently verify its recorded owner, domain and disk. Confirm that both
the owner and the owned domain/resource are inactive before reclamation.
A controller's exit does not establish that its domain stopped. This stale
reclamation precondition is separate from teardown of the current owned
attempt after success, failure or cancellation.

The existing Secure Shell (SSH) transport uses these host scripts with the
allocated guest's Internet Protocol (IP) address:

| Script under `/var/lib/rundeck/harness/jobs/` | Arguments |
|---|---|
| `ssh_exec.sh` | Allocated guest IP, Base64-encoded guest script, timeout in seconds |
| `ssh_fetch.sh` | Allocated guest IP, exact guest report path, maximum bytes |

Use the allocated guest address from this attempt. Supply a positive execution
deadline and a bounded report fetch. In the fresh guest, verify usable
`/dev/kvm` and the [blackbox guide's prerequisites](../README.md) before running
the lane. From the clean source checkout at `SELECTED_SHA`, with
`RUN_ARTIFACTS` set to this attempt's new private result
directory, the guest script invokes:

```sh
./tests/blackbox/run-installed.sh kvm --install-commit "$SELECTED_SHA" \
  --artifacts "$RUN_ARTIFACTS/kvm"
```

The maintained runner prepares the installed product once and executes all
default KVM sections. Its runtime observations must establish actual KVM
selection. A guest name, provisioning result or forced platform label does
not establish KVM-backed isolation.

Before host teardown, independently verify the exact owned guest, domain and
disk. Invoke `/var/lib/rundeck/harness/jobs/teardown.sh` through Bash with that
verified exact guest name as its sole argument. Then verify inventory, domain, volume and lease
state independently. The teardown script suppresses destroy/undefine errors
and reports success booleans in JavaScript Object Notation (JSON); those
booleans alone do not establish cleanup. Cancellation or lost guest SSH still
requires this host-side verification.
An unestablished cleanup outcome remains a visible failure.

Devstack reported Central European Summer Time (CEST), two hours ahead of
Coordinated Universal Time (UTC+02:00). The deployed schedule must state its
timezone explicitly. The read-only inspection found an active cron service
and permitted `crontab -l` for `rundeck`, with no
account crontab. It did not verify cron installation rights or install a
schedule. Private writable harness evidence and Rundeck output retrieval do
not establish durable discoverable publication. Independent deployment
scripts, cron entries and publication/email wiring remain unfinished.

## Prepare the macOS payload on Tart

On the approved arm64 macOS build host, use a clean checkout at `SELECTED_SHA`.
Build the release native proxy and wheel through the maintained installation
path. Build and sign the matching VM helper through `vm/Makefile`. Prepare the
compatible boot inputs and the selected verified NATS executable once.
The preparation also builds private tmux from the selected source's pinned
tmux, libevent and utf8proc releases when the installed CLI has no private
runtime. Tart needs Command Line Tools (C compiler, make, yacc and macOS
ncurses headers). The producer checks release hashes before extraction,
links libevent and utf8proc statically, signs the binary, and rejects
dependencies outside macOS system libraries. Compilation belongs on Tart.

Before the command below, the trusted build invocation must supply these paths:

| Input | Meaning |
|---|---|
| `SELECTED_SHA` | The full selected 40-character source commit |
| `BUILD_WHEEL` | That commit's wheel, containing its source stamp and release native proxy |
| `WHEELHOUSE` | Offline wheels for the runtime and development dependency closures exported from `uv.lock` |
| `PREPARED_INPUTS` | Prepared `bin/`, `share/`, private tmux with license notices, and verified `data/coord/nats/bin/` inputs |
| `BOOT_PROVENANCE` | Original source revision and SHA-256 for each boot file, as described below |
| `STAGED_OUTPUT` | A new disk-backed directory outside the checkout for this attempt's payload |

The execution host needs an already installed Python 3.12 or 3.13 interpreter
compatible with the transferred wheels. Retain the existing proxy and CA
environment when resolving build dependencies. The wheelhouse must supply both
frozen exports: `uv export --frozen --no-dev --no-emit-workspace` for the product,
and `uv export --frozen --group dev --no-emit-workspace` for host tests.
Missing wheels are a build/staging failure; Bristol must not fetch them.

From the selected checkout root on Tart:

```sh
python3 tests/blackbox/installed_staging.py \
  --checkout . --install-commit "$SELECTED_SHA" \
  --wheel "$BUILD_WHEEL" --wheelhouse "$WHEELHOUSE" \
  --prepared-config "$PREPARED_INPUTS" \
  --boot-provenance "$BOOT_PROVENANCE" --output "$STAGED_OUTPUT"
```

The command prints the `staged-inputs.json` path and its SHA-256. The payload
contains only the selected wheel, original release native binary, dependency
wheels, frozen requirements, signed helper, `vsock-term`, boot inputs, NATS,
signed private tmux and its third-party license notices. It copies no live
configuration, vault, token, private key, certificate
or Coord stream. Keep the input index digest in the trusted caller's
attempt result, separately from the transferred payload.

`BOOT_PROVENANCE` is a JSON mapping with exactly the keys `Image`,
`initramfs.cpio.gz` and `rootfs-base.ext4`. Each value supplies
`source_revision` (the file's original full source commit) and `sha256` (the
file's actual content hash). Reused images retain their original provenance;
the selected candidate does not become their build source. Each file can have
a different origin. Staging verifies those hashes. The hardware run must
establish compatibility. Staging and retained preparation use only each file's
`source_revision` and `sha256`; other source annotations are omitted.

## Consume the verified payload on Bristol

Before execution, the trusted caller must reserve the physical host,
verify capability and ownership, and transfer the source checkout and payload
through the approved SSH-stdin route. Run the source checkout at the same
`SELECTED_SHA`. The `sy-agent` account must already have uv and the compatible
Python interpreter; dependency installation is offline.

Preserve the configured inherited `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`NODE_EXTRA_CA_CERTS` values. A confined Bristol native attempt failed because
its environment lacked usable CA trust; the offline payload was not the
failure. The operator's retry at `3d9992e0` passed after supplying the existing
public certifi bundle, with SHA-256
`4f3975ff30abbf35443b486064ae8bcb41dff707ffdf576c76d292fb458aa0a9`,
through `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`. For either absent setting,
supply the readable bundle from the verified offline installation explicitly
through the trusted SSH invocation. Do not overwrite an inherited trust
setting.
That observation proves the native prerequisite, not a guest or full suite.

The trusted caller must also supply these values before invoking the runner:

| Input | Meaning |
|---|---|
| `STAGED_INPUTS` | The verified transferred payload directory in the isolated run tree |
| `STAGED_SHA256` | The input index digest received through the trusted caller path |
| `STAGED_PYTHON` | The absolute path of the existing compatible Python interpreter |
| `STATE_PARENT` | A short, private, disk-backed parent outside the checkout for new section state |
| `RUN_ARTIFACTS` | A new private result directory for this attempt; retain earlier attempts on retry |
| `VZ_TIMEOUT_SECONDS` | A positive per-helper deadline selected by the trusted test invocation |

The installed runner accepts the existing host deadline runner and a positive
per-helper deadline. Both CLI and native lifecycle launches invoke
`/Users/sy-agent/bin/run-vz-test --timeout-seconds N -- /absolute/path/to/safeyolo-vm run ...`
directly. The host runner stops and reaps its own child. The section state records
the supervisor process identifier (PID) and start token separately in
`vm-supervisor.json`; `vm.pid` and
`vm.token` identify the actual helper. Snapshot signals continue to target the
helper. Section cleanup checks both recorded processes and retains a failure
if owned cleanup cannot be established. Independent host teardown remains a
deployment prerequisite.
Public stop also consumes the supervision receipt after a deadline or helper
exit, even when the helper PID file is absent.
If a recorded runner or helper is still active, a new launch preserves its
receipt and fails before spawning another process. A stopped receipt can be
reclaimed; a reused PID with a different start token remains untouched.

Once those prerequisites are established, from the transferred source checkout
root as Bristol `sy-agent`:

```sh
./tests/blackbox/run-installed.sh vz --install-commit "$SELECTED_SHA" \
  --staged-inputs "$STAGED_INPUTS" --staged-sha256 "$STAGED_SHA256" \
  --vz-test-runner /Users/sy-agent/bin/run-vz-test \
  --vz-test-timeout-seconds "$VZ_TIMEOUT_SECONDS" \
  --python "$STAGED_PYTHON" --state-parent "$STATE_PARENT" \
  --artifacts "$RUN_ARTIFACTS/vz"
```

The staged path verifies hashes, frozen dependencies, wheel/source/native
identity, VM-helper source/signature and the installed NATS pin. It creates
separate installed CLI and host-test environments once. It restores the
verified source release binary to the checkout's maintained ignored build
location for the existing installed identity checks. It does not invoke
`install.sh`, Cargo, `uv sync`, `make` or bootstrap on Bristol.

Sections keep separate writable state and reuse only the prepared binaries and
boot inputs. VZ sections check ports 46370–46375 before execution and after
owned cleanup. The lifecycle section also checks owner NATS ports 46377/46378.
Before owner preparation can fail, the runner retains the owner's independent
test-instance identity for both cleanup callers and stages its offline NATS
binary. Continuity uses the existing `127.0.0.2` authority through its
owned `127.0.0.1` parent, HTTP port 46373, TLS port 46374, OAuth port 46375 and
admin port 46371. Each primary NATS instance uses 46370/46372. Continuity
observes host state and does not establish VZ isolation.

Read `installed-sections.json` and the section reports. The isolation section
retains pytest collection and actual pass/fail/skip/unexecuted outcomes from
host and guest calls, without captured output, tracebacks or parameter values.
Missing, stale, mismatched or incomplete pytest observations produce an
`evidence_failure` when the command would otherwise pass. Recorded skips
remain limitations. A retained failed outcome or nonzero pytest exit also
prevents a zero section exit from becoming a pass. An earlier assertion or
infrastructure failure keeps its exit classification. The reader rejects
symlinks and special files before opening pytest reports.
A cleanup failure stops continuation. A port preflight
failure leaves the section explicitly unexecuted and never signals a foreign
listener.

Each guest section also retains an installed runtime observation in the
summary. The attached probe reads the selected installed wheel's source stamp,
checks its packaged native executable and authenticates the running process.
The section reader binds that observation to this invocation's run identifier,
selected source commit, section interval and prepared source binary hash. It
also checks the execution host's system and architecture. It reuses the
platform check from `doctor.json`. Missing, stale, malformed or mismatched
runtime/platform reports produce an `evidence_failure` when the section would
otherwise pass. An earlier assertion or cleanup failure keeps its precedence.
After established cleanup, an evidence failure allows independent sections to
continue and leaves the lane failed.

The runner also writes `installed-summary.json` before product preparation,
after each section and at completion. This separate summary selects the source
commit, run ID, timestamps, requested and unexecuted sections, preparation exit
and verified input identities, section exits and cleanup results, failure counts
and sanitized pytest observations. It omits instance paths, raw diagnostic
text, captures, raw flow/inspector exports and arbitrary additional fields.
Boot entries retain only their original source revision and hash. The private
report and logs remain available for diagnosis.
The installed runtime projection contains the installed wheel source revision,
native binary hash, capture time, reported isolation platform, host system and
architecture, process PID/start token and authenticated instance ID. It omits
the CLI/package/executable paths, native configuration, listener paths,
readiness files and added nested fields. Continuity remains host composition
evidence; its report is not a guest runtime or physical-host observation.

An unfinished summary has null `exit` and `finished_at`. A finished partial
selection has `full_section_selection: false`, even when its commands exit
zero. Summary writing failure returns exit 2 and stops continuation after owned
section cleanup. Reusing an artifact directory containing either
`installed-sections.json` or `installed-summary.json` returns exit 2 before
preparation and preserves the original reports. Give a retry a new
`RUN_ARTIFACTS` directory.

The publication adapter must explicitly select `installed-summary.json`; it
must not upload the artifact directory or select files by extension. Bind its
run ID and source commit to the trusted attempt, check completion and every
required section and observation, and preserve reported skips as limitations.
This summary does not establish independent host allocation/teardown, a paired
hardware success or durable publication. The trusted caller still needs its own
attempt result before preflight or source fetch and must publish failures from
those earlier steps and from the publication operation itself.

## Missing host commands

Before completing the independent deployment scripts, Relay and Sylab must
identify the existing command that owns KVM allocation through interrupted
provisioning and verifies exact domain, disk, seed and lease reconciliation.
The command must establish that provisioning can no longer allocate before
teardown can be treated as final. The current `provision.sh` result and the
error-suppressing `teardown.sh` result do not establish that property.

The physical-Mac path also needs an approved local whole-attempt launch and
reconciliation command. It must keep a healthy attempt running after its
remote observer is lost, retain its owner and results, and independently
verify owned cleanup before reuse. The current `run-vz-test` command accepts
one `safeyolo-vm` invocation; the maintained suite owns preparation and
section cleanup. Neither supplies the outer host-attempt command. Do not
expand the deadline helper grammar or restore a host process manager to fill
that gap without resolving the command/capability with Relay.

No independent cron entry has been installed or demonstrated. Credentials,
mail transport and cron installation remain separate operator deployment
inputs. All six [#889 acceptance criteria](https://github.com/craigbalding/safeyolo/issues/889)
and the whole-PR/hardware holds remain open. These missing commands are source
integration prerequisites, not a request to install cron or supply credentials.
