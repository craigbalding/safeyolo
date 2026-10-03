# Hardware blackbox deployment

The hardware path pairs fresh Linux Kernel-based Virtual Machine (KVM)
acceptance on devstack with physical Apple Silicon Virtualization.framework
(VZ) acceptance through Bristol's `sy-agent` account. Tart builds,
signs and packages the macOS inputs. Bristol verifies transferred inputs and
executes offline. Both lanes must use one selected full source commit.

This directory documents the staged runner inputs and verified Rundeck
harness interface. The paired controller, cron deployment, ownership recovery
and durable report publication still need their remaining deployment bindings.
These runner commands do not establish working scheduling or complete
[#889](https://github.com/craigbalding/safeyolo/issues/889).
The [blackbox guide](../README.md) owns the maintained section selections and
the historical hardware observations and limitations.

## Use the existing KVM harness through Rundeck

The 3 October 2026 read-only deployment inspection verified Rundeck project
`acceptance` on devstack. The approved transport submits a Bash script to
`POST /api/59/project/acceptance/run/script` with
`scriptInterpreter=/bin/bash`. The response identifies the execution. This
interface has no fixed job ID. The execution account is `rundeck`, user ID 112.
Hardware-control and publication credentials stay outside candidate commands.

The following host commands run through that approved Rundeck invocation as
`rundeck` on devstack. Before allocation, inspect current inventory, lease
ownership, defined domains and available capacity. The inspection's earlier
free-capacity result is not a reservation.

```sh
bash /var/lib/rundeck/harness/jobs/list_guests.sh
```

Before provisioning, the trusted caller must supply `ISSUE889_RUN_OWNER`, a
unique owner for this attempt, and `SELECTED_SHA`, the full selected commit
already available on origin. Use that same commit for the paired VZ lane.
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
independently verify its recorded owner, domain and disk. Confirm that the
owner is inactive before reclamation.

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
not establish durable discoverable publication. The remaining bindings are
listed in [Complete the external deployment](#complete-the-external-deployment).

## Prepare the macOS payload on Tart

On the approved arm64 macOS build host, use a clean checkout at `SELECTED_SHA`.
Build the release native proxy and wheel through the maintained installation
path. Build and sign the matching VM helper through `vm/Makefile`. Prepare the
compatible boot inputs and the selected verified NATS executable once.
Compilation belongs on Tart.

Before the command below, the trusted build invocation must supply these paths:

| Input | Meaning |
|---|---|
| `SELECTED_SHA` | The full selected 40-character source commit |
| `BUILD_WHEEL` | That commit's wheel, containing its source stamp and release native proxy |
| `WHEELHOUSE` | Offline wheels for the runtime and development dependency closures exported from `uv.lock` |
| `PREPARED_INPUTS` | Prepared `bin/`, `share/` and verified `data/coord/nats/bin/` inputs |
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
wheels, frozen requirements, signed helper, `vsock-term`, boot inputs and NATS
binary. It copies no live configuration, vault, token, private key, certificate
or Coord stream. Keep the input index digest in the trusted controller's
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

Before execution, the trusted controller must reserve the physical host,
verify capability and ownership, and transfer the source checkout and payload
through the approved SSH-stdin route. Run the source checkout at the same
`SELECTED_SHA`. The `sy-agent` account must already have uv and the compatible
Python interpreter; dependency installation is offline.

The controller must also supply these values before invoking the runner:

| Input | Meaning |
|---|---|
| `STAGED_INPUTS` | The verified transferred payload directory in the isolated run tree |
| `STAGED_SHA256` | The input index digest received through the trusted controller path |
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
owned cleanup. Continuity uses the existing `127.0.0.2` authority through its
owned `127.0.0.1` parent, HTTP port 46373, TLS port 46374, OAuth port 46375 and
admin port 46371. Each isolated NATS instance uses 46370/46372. Continuity
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
hardware success or durable publication. The controller still needs its own
attempt result before preflight or source fetch and must publish failures from
those earlier steps and from the publication operation itself.

## Complete the external deployment

The operator-side inspection verified the Rundeck script interface, execution
account and harness commands in the [KVM harness procedure](#use-the-existing-kvm-harness-through-rundeck).
The operator-side handoff must still establish the actual
paired controller path, its independent ownership
and teardown checks, and its recovery after cancellation or lost SSH.
It must also establish the cron owner and rights, timezone,
authorized on-demand admission, Tart staging
route and permitted durable publication destination and principal.

Once verified, put the actual cron entries, host/account, timezone, paired
selected-SHA invocation, on-demand command, result links and recovery commands
here. Demonstrate the deployed schedule and on-demand wiring and one complete
successful paired hardware run at the same selected SHA. Keep failed attempts
and their cleanup outcomes visible. The publication step must select reviewed
report fields and diagnostics; file extensions do not make private instance
data safe to publish. Until that deployment and demonstration work, the
hardware cadence tables remain unscheduled and their drift check remains active.
