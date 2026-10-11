# Hardware deployment inputs and reference

Start with [the setup path](README.md). This reference supplies configuration,
cron/mail recipes, Tart preparation and retained-attempt recovery.

## Host configuration

Install the reviewed script checkout at `/usr/local/lib/safeyolo-hardware`.
Protect that checkout and `/etc/safeyolo-hardware` from candidate writes.
The `.env` files below are shell files sourced by the wrappers; create them
with the required values supplied by the host operators, and keep them private.
The wrappers do not provision accounts, credentials, Secure Shell (SSH)
bindings or mail.

Both trusted cron accounts need Python 3.12 or 3.13, Bash, Git, `gh` and `jq`
in their cron PATH. Configure `gh` with the existing approved principal that
can read `craigbalding/safeyolo` source and create/read #889 comments.
Keep GitHub, Rundeck and SSH credentials outside candidate authority.
No GitHub hardware runner is used.

### Devstack KVM configuration

The devstack `rundeck` account owns this crontab. Its wrapper sources
`/etc/safeyolo-hardware/kvm.env`; the Rundeck script must read the same file.

| Variable | Value and source |
|---|---|
| `RUNDECK_URL` | Approved Rundeck service base URL from its operator. The adapter adds `/api/59/` and submits to project `acceptance`. Do not embed a credential in the URL. |
| `RUNDECK_TOKEN_FILE` | Optional private file for the existing Rundeck principal, supplied by its operator. Omit only when the approved transport already authenticates requests. |
| `HARDWARE_PYTHON` | Trusted account's installed Python interpreter; defaults to `python3`. Use its actual executable path when setting the value. |
| `HARNESS_JOBS` | Deployed `safeyolo-harness` job directory; defaults to `/var/lib/rundeck/harness/jobs`. Obtain the installed helpers from the devstack operator. |
| `KVM_ATTEMPTS` | Private result parent; defaults to `/var/lib/rundeck/harness/evidence/issue889`. The supplied cron recipe uses that default. |

The existing harness must supply `_common.sh`, `list_guests.sh`, `provision.sh`,
`ssh_exec.sh`, `ssh_fetch.sh` and `teardown.sh`. The account needs libvirt/pool,
`flock`, capacity, network and helper access. The wrapper checks KVM capability,
four CPUs, 10 GiB available memory and 90 GiB pool space before allocation.
Before enabling the schedule, deploy the independently reviewed console-lock
correction in [harness PR #6 at e9ad4f8](https://github.com/craigbalding/safeyolo-harness/pull/6/commits/e9ad4f8fabfa723e388cbfd8f01a8ac54f1046f3).
The provision helper's detached console children must close its lifetime lock.
The prior source observation does not prove that helper is deployed.

### Bristol VZ configuration

Bristol's existing trusted operator account owns this crontab. Record its
actual name at installation. Its wrapper sources
`/etc/safeyolo-hardware/vz.env`; candidate execution remains in `sy-agent`.

| Variable | Value and source |
|---|---|
| `VZ_ATTEMPTS` | Required private result parent outside `sy-agent` authority. Set it to `$HOME/hardware-attempts` in the trusted account for the supplied cron recipe. |
| `VZ_SSH_CONFIG` | Absolute path to the trusted account's working SSH configuration, with alias `seatbelt-mac` targeting Bristol `sy-agent` in batch mode. Obtain its endpoint, verified host key and authorized identity from the Bristol operator. |
| `VZ_TART_INPUTS` | Required trusted parent of commit-addressed Tart outputs; populate it from [the approved Tart producer](#prepare-selected-tart-inputs). |
| `VZ_PYTHON` | Absolute path to the already installed, compatible offline Python interpreter in `sy-agent`, supplied by the Bristol operator. |
| `VZ_RUNTIME_PATH` | Verified PATH containing that account's offline Python, uv and required command-line tools, supplied by the Bristol operator. |
| `VZ_LOCK` | Persistent host-local lock file, readable by `sy-agent` and protected from replacement by that account. The Bristol operator provisions the file and its access. |
| `VZ_CA_BUNDLE` | Readable public certificate authority (CA) bundle from the verified offline runtime installation, used for absent trust settings. |
| `HARDWARE_PYTHON` | Trusted account's installed Python interpreter; defaults to `python3`. |

The [Seatbelt SSH setup](../../../contrib/macos-seatbelt-agent/README.md#3-give-the-connection-instructions-to-your-agent)
explains the connection output from the installed `configure-ssh` helper.
Its [SSH identity reference](../../../contrib/macos-seatbelt-agent/REFERENCE.md#ssh-identities)
explains authorizing another client: give the operator only the public key;
the corresponding private key stays in the trusted cron account, selected by
its SSH `IdentityFile`. Use the existing verified server host key and deployed
endpoint. The generated agent instructions use a proxy transport; the Bristol
operator must bind the trusted host-local cron client to the same Mac instead
of copying a factory agent's configuration unchanged.

Before scheduling, from any directory in Bristol's trusted cron account,
replace `SSH_CONFIG` with the configured absolute file path and check the
binding without allocating a guest:

```sh
ssh -F SSH_CONFIG -o BatchMode=yes seatbelt-mac hostname -s
hostname -s
```

Both commands must report the same Bristol hostname. This verifies the SSH
binding only. The wrapper also checks physical arm64 Mac/hypervisor capability
and all eight allocated fixture ports before execution.

`sy-agent` must be able to read the pinned checkout and lock file, execute
`/Users/sy-agent/bin/run-vz-test`, inspect its own process arguments and bind
ports 46370–46375 plus 46377–46378. The script preserves inherited
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`.
It does not compile or download packages on Bristol.
Candidate state defaults to short `/Users/sy-agent/hw` and `/Users/sy-agent/s`
parents. Optional `VZ_RUNS` and `VZ_STATES` must keep the longest maintained
agent socket below macOS's 104-byte path limit.
`VZ_HELPER_TIMEOUT` selects a positive per-helper deadline; the default is
120 seconds. Keep GitHub credentials out of `sy-agent` and its candidate tree.

## Install the two cron entries

Craig installs each entry in its own trusted host account after configuring
[the required inputs](#host-configuration). Set the crontab PATH to the installed
tools' actual directories. Replace `REPLACE_WITH_OPERATOR_EMAIL` with the real
recipient in `MAILTO`, and establish working `/usr/bin/mail` transport in each
account before enabling the entry. Create the private log directories first.
The mail command below sends the private cron log to that trusted recipient
when the wrapper exits nonzero; `MAILTO` alone does not implement that check.

On devstack as `rundeck`, use the default `KVM_ATTEMPTS` result root.
For an approved custom root, change the log redirects to match the configured
path. Create the directory from any working directory:

```sh
mkdir -p /var/lib/rundeck/harness/evidence/issue889
chmod 700 /var/lib/rundeck/harness/evidence/issue889
```

Run daily at 03:17 in devstack's current Central European local timezone
(CEST, UTC+02:00, at the deployment inspection). Verify the host's timezone at
installation; the schedule follows host local time, including seasonal changes.
Add this recipe through that account's `crontab -e`:

```cron
MAILTO=REPLACE_WITH_OPERATOR_EMAIL
17 3 * * * /bin/bash /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh overnight >> /var/lib/rundeck/harness/evidence/issue889/cron.log 2>&1 || /usr/bin/mail -s 'SafeYolo KVM failed or incomplete' "$MAILTO" < /var/lib/rundeck/harness/evidence/issue889/cron.log
```

On Bristol as its trusted operator account, set `VZ_ATTEMPTS` to
`$HOME/hardware-attempts` for this recipe. For an approved custom result parent,
change the log redirects as well. Create the private directory:

```sh
mkdir -p "$HOME/hardware-attempts"
chmod 700 "$HOME/hardware-attempts"
```

Run daily at 03:43 in Bristol's host timezone (UTC, observed 4 October).
BSD cron uses the host timezone; recheck it at installation.
Record the actual account name and add this recipe through its `crontab -e`:

```cron
MAILTO=REPLACE_WITH_OPERATOR_EMAIL
43 3 * * * /bin/bash /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh overnight >> "$HOME/hardware-attempts/cron.log" 2>&1 || /usr/bin/mail -s 'SafeYolo VZ failed or incomplete' "$MAILTO" < "$HOME/hardware-attempts/cron.log"
```

Read back each account's entries with `crontab -l`. Installation does not
prove email delivery or successful hardware execution. The entries are
independent: neither wrapper waits for or triggers the other.
Overnight mode resolves GitHub's current default branch once before candidate
execution. On-demand mode accepts only the operator-authorized full commit
shown in [the README](README.md#run-once-and-find-the-result); public
pull-request/ref dispatch cannot select hardware code.

## Prepare selected Tart inputs

Obtain a clean checkout at the selected full commit from
`craigbalding/safeyolo` and use the approved arm64 Tart build route.
The existing [build_inputs.py](build_inputs.py) producer performs one maintained
`run-lane.sh --prepare-only` preparation, builds the selected wheel, downloads
the two frozen dependency closures and calls the staging verifier.
Supply the operator's retained boot files and original build provenance;
reused boot bytes keep their original source revisions and hashes.
The build host needs Python 3.12 or 3.13 with pip, uv and macOS Command Line
Tools (C compiler, make, yacc and ncurses headers). Preserve its configured
proxy and CA environment.

### Boot provenance

`BOOT_PROVENANCE` is a JSON mapping with exactly the keys `Image`,
`initramfs.cpio.gz` and `rootfs-base.ext4`. Each value supplies
`source_revision` (the file's original full source commit) and `sha256` (the
file's actual content hash). Reused images retain their original provenance;
the selected candidate does not become their build source. Each file can have
a different origin. Staging verifies those hashes. The hardware run must
establish compatibility. Staging and retained preparation use only each file's
`source_revision` and `sha256`; other source annotations are omitted.

### Build on Tart

From the selected checkout root on Tart, set `SELECTED_SHA` to its authorized
full commit, `BOOT_INPUTS` to the retained boot-file directory,
`BOOT_PROVENANCE` to the original-source JSON specified above, and
`BUILD_PYTHON` to the existing compatible interpreter with pip.
Set `BUILD_OUTPUT` to a new disk-backed directory outside the checkout.
This command builds and downloads inputs on Tart, with a one-hour default
deadline; it does not execute a physical hardware lane:

```sh
python3 tests/blackbox/hardware/build_inputs.py \
  --checkout . --install-commit "$SELECTED_SHA" \
  --boot-inputs "$BOOT_INPUTS" --boot-provenance "$BOOT_PROVENANCE" \
  --python "$BUILD_PYTHON" --output "$BUILD_OUTPUT"
```

The producer prints JSON with `source_revision`, `staged_inputs` and
`input_index_sha256`. Its output contains `prepared/`, `wheels/`, `wheelhouse/`
and the verified `payload/`. In the trusted Bristol account, store the verified
outputs under `VZ_TART_INPUTS/FULL_SHA`:

| Path | Source |
|---|---|
| `source/` | Clean Git checkout at that full selected commit. The wrapper checks its HEAD and clean status. |
| `payload/` | The producer's `staged_inputs` directory, including `staged-inputs.json`. |
| `staged-sha256` | A file containing the producer's trusted 64-character `input_index_sha256` value, kept separately from the payload. |

The trusted VZ wrapper checks the matching source and index, transfers only
source Git objects and indexed payload files through SSH stdin, and invokes
the offline lane. Missing or mismatched inputs fail before candidate execution.
Preparing future default-branch inputs remains an operator deployment
prerequisite; there is no automatic Tart feed.

### Stage already prepared inputs

For already prepared inputs on the approved arm64 macOS build host, use a
clean checkout at `SELECTED_SHA`. The maintained preparation supplies the
release native proxy and wheel, the matching VM helper built and signed through
`vm/Makefile`, compatible boot inputs and the selected verified NATS executable.
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
| `BUILD_WHEEL` | Selected wheel from the Tart producer's `wheels/` directory, containing its source stamp and release native proxy |
| `WHEELHOUSE` | The producer's `wheelhouse/`, containing both frozen dependency closures exported from `uv.lock` |
| `PREPARED_INPUTS` | The producer's `prepared/`, containing `bin/`, `share/`, private tmux with license notices and verified `data/coord/nats/bin/` |
| `BOOT_PROVENANCE` | Original source revision and SHA-256 for each boot file, specified in [Boot provenance](#boot-provenance) |
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

## Offline execution on Bristol

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

## Execution and acceptance limits

The wrappers use the maintained default `run-installed.sh` sections once, with
one preparation and separate section state. The [blackbox guide](../README.md)
owns the section map and platform limitations. Before release, both complete
hardware lanes must pass at the exact release commit.
The held paired controller is excluded; its code and findings remain at
`3e163f36857c09a7bd3532f0e60de452c2702466`.

Cron installation, publication credentials, mail delivery and complete hardware
acceptance remain operator deployment inputs or unproved results under
[#889](https://github.com/craigbalding/safeyolo/issues/889).
Source commands and cron examples do not establish a deployed schedule or a
hardware pass. Prior independent results retain their actual tested revisions.
The VZ runner verifies wheel/native/helper source, hashes, frozen dependencies,
strict helper signature, NATS and private tmux.
One local detached session retains its lock, owner, exit and reports. Losing
an external observer does not cancel that session.

The attempt's GitHub index links its selected commit and sanitized JSON report
parts. Publication selects `installed-summary.json`; it never uploads arbitrary
files, raw logs, inspector exports, vaults, tokens, keys or instance state.
Every comment is read back. Nonzero execution, missing/partial reports, unknown
cleanup or publication failure keeps the attempt failed or incomplete.
Raw reports remain private.

## Inspect or recover a retained attempt

KVM uses the existing lifetime provision lock, early lease and unique scenario.
It waits/reaps its started provision or SSH command before exact owned teardown.
Reconciliation holds that same provision lock. It verifies domain, disk, seed
and lease absence after teardown; suppressed helper errors do not prove cleanup.
A foreign lease/domain/disk is retained. The run uses `--reuse` to avoid broad
inactive guest removal. The host's Rundeck invocation survives observer loss.
The observer has a three-hour wait by default; its exit alone proves nothing.

If an old KVM attempt is inactive, use its printed trusted directory on devstack
as `rundeck`. This command also requires an inactive exact guest before stale
reclamation. Unknown state or an active owner remains a blocker.

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh reconcile ATTEMPT_DIRECTORY
```

VZ checks the actual physical host and all eight fixture ports. After local
execution ends, it inspects account processes for this attempt's exact paths
and checks port availability. It never signals a foreign process or listener.
If observation was lost, recover the same local exit/reports from Bristol's
trusted account; this command does not rerun the suite or stop a healthy run.

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh collect ATTEMPT_DIRECTORY
```

A surviving or uninspectable owned process keeps cleanup failed. Retain that
attempt and have the existing host operator inspect its exact argv/start
identity and instance receipts before using maintained owned stop/cleanup.
`SIGKILL` or host death cannot promise shell cleanup. Do not delete receipts,
reuse unknown state, or signal by broad process name. Retry execution in a new
attempt; publication can replay the old trusted outbox without executing code:

```sh
python3 -I -B /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/publish_results.py --attempt ATTEMPT_DIRECTORY
```

After actual installation and successful/failing publication readback are
verified, retain the two account crontab readbacks at the existing optional
`deployed.cron` path with `# Host:` and `# Account:` annotations. The existing
cadence checker reads those entries; README examples leave scheduling unproved.
Keep the cadence tables at `no` until that deployment evidence exists. Lens
independently accepts source and hardware criteria; this change alone does not
clear the whole-candidate hold or the six open criteria.
