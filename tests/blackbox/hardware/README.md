# Hardware blackbox deployment

The hardware path pairs fresh Linux Kernel-based Virtual Machine (KVM)
acceptance on devstack with physical Apple Silicon Virtualization.framework
(VZ) acceptance through Bristol's `sy-agent` account. Tart builds,
signs and packages the macOS inputs. Bristol verifies transferred inputs and
executes offline. Both lanes must use one selected full source commit.

`paired.py` selects one full commit, runs both maintained installed lanes,
retains each attempt before selection, and publishes allowlisted results as
read-back-verified [#889](https://github.com/craigbalding/safeyolo/issues/889)
comments. `install_schedule.py` installs and reads back one account cron entry.
Use a separately pinned, clean trusted checkout for these commands; selected
candidate code receives neither the control configuration nor its credentials.

Deployment and complete paired hardware acceptance remain open. The local
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

## Deploy the paired invocation

Sylab owns operator-side installation, scheduling and Rundeck execution. Relay
serializes Tart production builds and the physical host. Start this procedure
only for the reviewed exact controller commit and authorized selected source,
after Relay confirms those resources are ready. Installing a cron entry does
not prove either hardware lane.

Use ordinary operator-approved paths outside candidate, input and section-state
trees. Install the same clean trusted controller revision on the control host,
devstack, Tart and Bristol. Their locations may differ. The control host must
already have the approved Rundeck route, foreground Tart mailbox client,
Bristol SSH binding and authenticated GitHub CLI (`gh`) with permission to
read source and write/read #889 comments. Devstack's `rundeck` account does not
need copied Tart or Bristol private keys. Do not install cron on Bristol;
`sy-agent`'s cron inspection is denied by its existing seatbelt.

On each installation host, set `CONTROLLER_DIR` to a new approved checkout path
and `CONTROLLER_SHA` to the independently reviewed full controller commit.
Run these commands with that host's approved source transport. Use the SSH-stdin
transfer route for Bristol's checkout when it cannot fetch public source.

```sh
git clone https://github.com/craigbalding/safeyolo.git "$CONTROLLER_DIR"
git -C "$CONTROLLER_DIR" checkout --detach "$CONTROLLER_SHA"
git -C "$CONTROLLER_DIR" status --porcelain
```

The final command must print nothing. The invocation rechecks the exact HEAD
and clean state on every host. Use Python 3.12 or 3.13 for the control command
and both Mac installations. Devstack's host adapter uses `python3` and only
standard-library dependencies from the trusted checkout.

Copy [deployment.example.json](deployment.example.json) to a private operator
configuration file. Replace every example with the observed deployment binding.
Set `CONFIG_FILE` to its absolute path and `CONTROL_PYTHON` to the absolute
compatible interpreter. Keep the configuration outside all tested trees.

| Binding | Required observation |
|---|---|
| `controller_revision` | Same full, reviewed controller commit on every installation |
| `attempts` | Private disk-backed control-host directory; permanent attempt records, bounded transport logs and publication retries |
| `rundeck_url`, optional `rundeck_token_file` | Existing approved service URL and existing principal; omit the file if the transport supplies authentication |
| `rundeck_controller` | Trusted checkout readable by `rundeck` on devstack |
| `tart_client`, `tart_mailbox` | Existing foreground client and its requests/responses directories on the control host |
| `tart_controller`, `tart_runs`, `tart_python` | Trusted Tart checkout, existing disk-backed build parent, compatible arm64 Python with pip |
| `tart_boot_inputs`, `tart_boot_provenance` | Verified original cached boot inputs and their original per-file revisions/hashes |
| `bristol_ssh_config` | Existing control-host configuration containing the `seatbelt-mac` binding |
| `bristol_controller`, `bristol_python` | Trusted sy-agent checkout and already installed compatible Python |
| `bristol_runs`, `bristol_states`, `bristol_journal` | Existing short, private sy-agent parents and a journal outside every tested tree |
| `lane_timeout_seconds`, `vz_helper_timeout_seconds` | Positive outer lane and direct native-helper deadlines |

Tart needs the maintained build/install prerequisites, signing identity,
`vsock-term` and boot inputs. Bristol needs uv, compatible offline wheels,
verified NATS, the existing direct deadline runner and the supported private
tmux runtime or an independently verified supported host prerequisite. The
current staging allowlist does not transfer tmux. [#909](https://github.com/craigbalding/safeyolo/issues/909)
owns that installed-runtime repair; establish its supported path before claiming
VZ readiness. [#908](https://github.com/craigbalding/safeyolo/issues/908) separately
owns the Darwin parent-reaping cleanup fixture. Its known fixture failure does
not establish failed physical cleanup or permit weaker survivor checks.

Before allocation, refresh devstack inventory, lease, running work and capacity.
The adapter checks usable KVM API 12, four CPUs, 10 GiB available memory and
90 GiB free pool space. It provisions a unique owner with `--reuse`, checks the
exact source and domain/disk bindings, and runs in a fresh guest directory.
The physical adapter checks Darwin arm64 on a Mac model, two CPUs, 8 GiB
available memory for the maintained two-VM lifecycle scenario, 10 GiB free
space and all six fixed fixture ports. These are current capability checks,
not capacity reservations. Preserve foreign active or leased resources.

With `SELECTED_SHA` set to the full commit explicitly authorized by the operator,
run one paired on-demand attempt from the control host:

```sh
"$CONTROL_PYTHON" "$CONTROLLER_DIR/tests/blackbox/hardware/paired.py" \
  on-demand --config "$CONFIG_FILE" --authorized-commit "$SELECTED_SHA"
```

Overnight selection resolves the repository's current default branch once and
uses that same selected full SHA in both lanes. It accepts no supplied ref,
public PR event or external dispatch input:

```sh
"$CONTROL_PYTHON" "$CONTROLLER_DIR/tests/blackbox/hardware/paired.py" \
  overnight --config "$CONFIG_FILE"
```

Both commands print the attempt ID, selected source, index link and result.
Exit 0 requires complete same-SHA installed summaries, independent owned
teardown and publication readback. Exits 2 and 130 require inspection of the
failed attempt; a transport's successful exit does not make a lane pass.
The initial #889 index precedes source selection. The final linked JSON report
selects installed source/native/process identities, platform and boot origins,
section exits, pytest outcomes/skips, unexecuted sections, failure stages,
trusted host capacity and cleanup. Raw logs, instance directories, keys,
configuration, vaults and flow/inspector exports are never uploaded.

## Install and observe cron

Use the operator account that owns all four control-host transport bindings.
Retain its existing proxy and CA route and confirm those bindings work in its
cron environment. The installer retains the current tool PATH on the one
command and uses an absolute interpreter. It preserves unrelated entries.
Set `CRON_RECEIPT` to a private output path outside the trusted checkout.

```sh
"$CONTROL_PYTHON" "$CONTROLLER_DIR/tests/blackbox/hardware/install_schedule.py" \
  --config "$CONFIG_FILE" --cron-file "$CRON_RECEIPT" --hour 2 --minute 17
crontab -l
```

The default entry runs at 02:17 in the control host's local timezone every day.
The installer prints and retains the exact read-back entry, hostname, account,
installation-time timezone and controller revision. Do not infer that the
actual deployment uses devstack's last observed CEST+0200 or `rundeck` UID 112:
the 3 October read-only inspection found no `rundeck` crontab and installed
nothing. The control host may be the existing approved transport host while
KVM execution remains on devstack through Rundeck.

After observing a scheduled invocation and on-demand wiring, copy the actual
read-back marked entry into `tests/blackbox/hardware/deployed.cron`, record its
host/account/timezone and result links here, and update the existing cadence
tables in the [blackbox guide](../README.md) and
[security-testing design](../../../docs/security-testing-design.md).
Run the existing drift check from the repository environment:

```sh
uv run python scripts/check_blackbox_cadence.py
```

Until those real transitions, `deployed.cron` is absent and both hardware lanes
remain unscheduled in the tables. A source command or cron receipt alone does
not establish the complete automated hardware result. One successful complete
same-SHA run per lane is needed; wiring both triggers does not require repeating
the full suites for each trigger. Retain all earlier skips and acceptance limits
at their observed revisions, including the five unproved VZ isolation assertions.

## Inspect failure and recover this attempt

Each control-host attempt lives in `attempts/<32-character-attempt-id>/`. Inspect
its `attempt.json` and bounded private logs. KVM retains exactly named raw
reports under `/var/lib/rundeck/harness/evidence/<owner>/` before guest teardown.
Bristol retains private `results/` and `execution.log` in this attempt's short
run directory. Successful cleanup releases owned input copies and overlays;
private failure reports remain available. Do not treat these private files as
publication or upload their directories.

Set `ATTEMPT_DIR` to the original private attempt directory. Recover with its
original trusted controller revision and configuration:

```sh
"$CONTROL_PYTHON" "$CONTROLLER_DIR/tests/blackbox/hardware/paired.py" \
  recover --config "$CONFIG_FILE" --attempt "$ATTEMPT_DIR"
```

Recovery acquires the paired lock, aborts still-pending recorded Rundeck calls,
checks the original host owner is inactive, then stops only this attempt's
independently identified owned resources. It never starts another test. It
retries publication and preserves the original failure stages and reports;
exit 2 after successful recovery is expected for an originally failed attempt.
If only publication needs retry, use the original trusted checkout as cwd:

```sh
"$CONTROL_PYTHON" -m tests.blackbox.hardware.publish_results --attempt "$ATTEMPT_DIR"
```

Stale automatic reclamation separately requires independently inactive owner
and resources. Unknown identity or a live foreign owner remains untouched.
Cleanup of a current failed/cancelled attempt still stops its verified owned
resources. A lost SSH response triggers a second owner-bound host inspection;
unknown teardown never passes and prevents additional hardware use.

An interrupted or failed Tart build retains its exact build root and marks
cleanup unverified. Confirm that recorded mailbox job and its actual owned
compiler processes have stopped before operator removal; a timeout response
alone does not authorize deleting a live build. Completed build inputs can be
released by the original attempt's recovery command after canonical completion.
A new test retry gets a new attempt ID and directories. It cannot erase the
original failed index or turn its failure into a pass.
