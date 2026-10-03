# Hardware blackbox deployment

The hardware path pairs fresh Linux KVM acceptance on devstack with physical
Apple Silicon VZ acceptance through Bristol's `sy-agent` account. Tart builds,
signs and packages the macOS inputs. Bristol verifies transferred inputs and
executes offline. Both lanes must use one selected full source commit.

This directory currently documents the staged runner inputs. The trusted
external controller, cron deployment, ownership recovery and durable report
publication still need the verified Rundeck deployment values. These runner
commands do not establish working scheduling or complete
[#889](https://github.com/craigbalding/safeyolo/issues/889).
The [blackbox guide](../README.md) owns the maintained section selections and
the historical hardware observations and limitations.

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
the supervisor PID/start token separately in `vm-supervisor.json`; `vm.pid` and
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
remain limitations. A cleanup failure stops continuation. A port preflight
failure leaves the section explicitly unexecuted and never signals a foreign
listener.

The runner also writes `installed-summary.json` before product preparation,
after each section and at completion. This separate summary selects the source
commit, run ID, timestamps, requested and unexecuted sections, preparation exit
and verified input identities, section exits and cleanup results, failure counts
and sanitized pytest observations. It omits instance paths, raw diagnostic
text, captures, raw flow/inspector exports and arbitrary additional fields.
Boot entries retain only their original source revision and hash. The private
report and logs remain available for diagnosis.

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

The operator-side Rundeck handoff must establish the existing job ID and
invocation, execution account, inventory, lease/capacity checks, allocation and
owned teardown. It must also establish the actual trusted controller path,
cron owner and rights, timezone, authorized on-demand admission, Tart staging
route and permitted durable publication destination and principal.

Once verified, put the actual cron entries, host/account, timezone, paired
selected-SHA invocation, on-demand command, result links and recovery commands
here. Demonstrate the deployed schedule and on-demand wiring and one complete
successful paired hardware run at the same selected SHA. Keep failed attempts
and their cleanup outcomes visible. The publication step must select reviewed
report fields and diagnostics; file extensions do not make private instance
data safe to publish. Until that deployment and demonstration work, the
hardware cadence tables remain unscheduled and their drift check remains active.
