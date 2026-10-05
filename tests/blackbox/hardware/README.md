# Independent hardware blackbox runs

Run Linux Kernel-based Virtual Machine (KVM) tests on devstack through Rundeck,
and physical Apple Silicon Virtualization.framework (VZ) tests on Bristol.
`run-kvm.sh` and `run-vz.sh` select and record their own full source commit.
Neither script waits for or triggers the other. Before release, both complete
lanes must pass at the exact release commit.

The scripts use the maintained default `run-installed.sh` sections once, with
one preparation and separate section state. The [blackbox guide](../README.md)
owns the section map and platform limitations. The held paired controller is
excluded from this change; its code and findings remain at
`3e163f36857c09a7bd3532f0e60de452c2702466`.

Cron installation, publication credentials, mail delivery and complete hardware
acceptance remain operator deployment inputs or unproved results under
[#889](https://github.com/craigbalding/safeyolo/issues/889). These source commands
and cron examples do not establish a deployed schedule or a hardware pass.

## Install the trusted scripts

Craig installs a reviewed, pinned checkout at
`/usr/local/lib/safeyolo-hardware` on each host. Protect that checkout and its
configuration from candidate writes. Record its full Git commit separately
from the selected test commit. Install the existing Python 3.12 or 3.13, Bash,
Git, `gh`, and `jq` in the trusted account's cron PATH. Configure its GitHub
principal for source lookup and #889 comments. Keep that principal and the
Rundeck/SSH credentials outside candidate authority.

On devstack, the `rundeck` account owns the KVM crontab. Its private
`/etc/safeyolo-hardware/kvm.env` is a shell environment file containing
`RUNDECK_URL`, optional `RUNDECK_TOKEN_FILE`, and `HARDWARE_PYTHON`.
The default existing jobs are `/var/lib/rundeck/harness/jobs`; results use
`/var/lib/rundeck/harness/evidence/issue889`. `HARNESS_JOBS` and `KVM_ATTEMPTS`
can select other approved paths. Both cron and the Rundeck script must read
this same configuration. The Rundeck account needs existing libvirt/pool,
`flock`, capacity, network and helper access. No GitHub hardware runner is used.
The deployed provision helper must close its lifetime lock in detached console
children, as in [harness PR #6](https://github.com/craigbalding/safeyolo-harness/pull/6/commits/e9ad4f8fabfa723e388cbfd8f01a8ac54f1046f3).
Use the independently reviewed helper correction before enabling the schedule.

On Bristol, the existing trusted operator account owns the VZ crontab.
Candidate execution uses the confined `sy-agent` account through its existing
SSH binding. Do not put GitHub credentials in `sy-agent` or its candidate tree.
Its protected `/etc/safeyolo-hardware/vz.env` supplies:

| Variable | Deployment input |
|---|---|
| `VZ_ATTEMPTS` | `$HOME/hardware-attempts` in the trusted account, outside `sy-agent` authority |
| `VZ_SSH_CONFIG` | Existing SSH configuration whose `seatbelt-mac` target is Bristol `sy-agent` |
| `VZ_TART_INPUTS` | Trusted commit-addressed Tart outputs described below |
| `VZ_PYTHON`, `VZ_RUNTIME_PATH` | Existing compatible offline interpreter and verified Python/uv PATH in `sy-agent` |
| `VZ_LOCK` | Persistent host-local lock file readable by `sy-agent` and protected from replacement by that account |
| `VZ_CA_BUNDLE` | Readable public CA bundle from the verified offline installation, used only for absent trust settings |
| `HARDWARE_PYTHON` | Trusted account's existing Python interpreter |

The `sy-agent` account must be able to read the pinned checkout and lock file,
execute `/Users/sy-agent/bin/run-vz-test`, inspect its own process arguments and
bind all eight allocated fixture ports. The script preserves inherited
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`. It does not
compile or download packages on Bristol. Candidate state defaults to short
`/Users/sy-agent/hw` and `/Users/sy-agent/s` parents; optional `VZ_RUNS` and
`VZ_STATES` must keep the longest maintained agent socket below macOS's
104-byte path limit. The per-helper deadline defaults to 120 seconds;
`VZ_HELPER_TIMEOUT` selects another positive deadline.

## Supply the selected Tart inputs

Before a VZ attempt can execute, prepare and verify that full commit on Tart
with the [existing input producer and staging rules](INPUTS.md).
At `VZ_TART_INPUTS/FULL_SHA`, supply a clean `source/` checkout, the produced
`payload/`, and a `staged-sha256` file containing the trusted input-index digest.
Keep reused boot bytes at their original source revisions and hashes. Missing
or mismatched inputs produce a visible failed attempt before candidate
execution. Preparing future default-branch inputs remains a deployment
prerequisite; a source example does not prove an automatic Tart feed.

The VZ script selects the commit through GitHub, checks the matching Tart source
and index, transfers only source Git objects and the payload through SSH stdin,
and invokes the offline lane. The runner verifies wheel/native/helper source,
hashes, frozen dependencies, strict helper signature, NATS and private tmux.
One local detached session retains its lock, owner, exit and reports. Losing
an external observer does not cancel that session.

## Install the two cron entries

Before installing, configure the inputs above, the actual recipient in
`MAILTO`, and working `/usr/bin/mail` transport in each trusted account.
Create each private log directory. Craig installs each entry in its own host
account; copying these examples into this repository does not install them.
The nonzero-exit email command is part of each cron entry.

Devstack, `rundeck`: run daily at 03:17 in the host's current Central European
local timezone (CEST, UTC+02:00, at the deployment inspection).

```cron
MAILTO=REPLACE_WITH_OPERATOR_EMAIL
17 3 * * * /bin/bash /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh overnight >> /var/lib/rundeck/harness/evidence/issue889/cron.log 2>&1 || /usr/bin/mail -s 'SafeYolo KVM failed or incomplete' "$MAILTO" < /var/lib/rundeck/harness/evidence/issue889/cron.log
```

Bristol, trusted operator account: run daily at 03:43 in the host's UTC timezone
(observed 4 October). Record the actual account name when Craig installs the
entry. BSD cron uses the host timezone; recheck that timezone at installation.

```cron
MAILTO=REPLACE_WITH_OPERATOR_EMAIL
43 3 * * * /bin/bash /usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh overnight >> "$HOME/hardware-attempts/cron.log" 2>&1 || /usr/bin/mail -s 'SafeYolo VZ failed or incomplete' "$MAILTO" < "$HOME/hardware-attempts/cron.log"
```

The overnight mode resolves GitHub's current default branch once before candidate
execution. For a trusted on-demand run, on the matching host/account with the
same prerequisites, replace `FULL_SHA` with the explicitly authorized 40-character
lowercase hexadecimal commit. Public pull-request/ref dispatch cannot select hardware code.

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh on-demand FULL_SHA
```

On Bristol in its trusted operator account:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh on-demand FULL_SHA
```

Each command prints its private attempt directory. The attempt's GitHub index
links its selected commit and sanitized JSON report parts. Publication selects
`installed-summary.json`; it never uploads arbitrary files, raw logs, inspector
exports, vaults, tokens, keys or instance state. Every comment is read back.
Nonzero execution, missing/partial reports, unknown cleanup or publication
failure keeps the attempt failed or incomplete. Raw reports remain private.

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
