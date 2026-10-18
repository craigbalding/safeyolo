# Run independent retained-artifact hardware tests

Run Kernel-based Virtual Machine (KVM) tests on devstack through the existing
Rundeck acceptance harness. Run Apple Virtualization.framework (VZ) tests on
physical Bristol through `sy-agent`. Each entry selects existing production
host/helper and staged guest artifacts once. It uses the same installed runner
as hosted blackbox. Neither entry builds SafeYolo, a rootfs, kernel or helper.

The entries adapt the independently reviewed #889 wrappers at
`4fc6e11c07ea308d053873bbec59a07baa43e1a7`. That source review remains separate
from the retained-consumer results and deployment. The held paired controller
is not used.

Qualifying production bundles and completed guest staging now have end-to-end
proof. Lens accepted complete [three-section KVM](https://github.com/craigbalding/safeyolo/issues/1105#issuecomment-6244175979)
and [four-section physical VZ](https://github.com/craigbalding/safeyolo/issues/1105#issuecomment-6243765595)
consumers at controller `8a2d28aa3fe1871161883bd630dd7e7a9f34ee3a`.
Those receipts qualify different explicit host selections. They preserve the
failed VZ sampler, missing original KVM after-run metadata and separate stopped
cleanup inspections. They do not establish a combined exact-release pass.

The [hosted 64-bit Arm (ARM64) consumer](https://github.com/craigbalding/safeyolo/issues/1105#issuecomment-6244450863)
selected the newest successfully staged compatible guest during quarantine,
without input overrides.
Its installed host and controller have separate source identities. That hosted
result does not prove either hardware entry.

The full consumers do not prove the complete cron entries. Automatic selection
through these hardware entries, deployed schedules, sanitized deployed
publication and failure email remain unproved. Craig owns installation.
Prepare the verified
[offline test inputs](INPUTS.md#bristol-trusted-account-and-confined-execution)
before using the VZ entry. Do not install the superseded nightly build-on-Tart
payload.

## Configure the existing hosts

Install a reviewed, pinned controller checkout at
`/usr/local/lib/safeyolo-hardware` on each host. Protect that checkout,
configuration, GitHub principal, harness and SSH keys from candidate writes.
The controller source is separate from the selected host package source.
Follow [the configuration and cron reference](INPUTS.md) before enabling either
entry. Tart can produce host bundles and test instruments separately; the
nightly VZ invocation only acquires retained product artifacts.

| Host | Scheduled account | Entry | Daily host-local time |
|---|---|---|---|
| devstack | `rundeck` | `run-kvm.sh` | 03:17 |
| Bristol | Existing trusted operator account; record its actual name | `run-vz.sh` | 03:43 |

The two schedules remain independent. Devstack's last recorded timezone was
Central European local time; Bristol's was UTC. Craig must check the current
timezone, account, mail transport and prerequisites at installation. Source
commands and cron examples do not prove a deployed schedule.

## Run and inspect one attempt

From any directory, in the matching trusted account with the configuration
complete, run its entry. These commands allocate owned execution state and
publish selected attempt fields to issue #889. They retain raw logs privately.

On devstack, invoke through the existing Rundeck script interface as `rundeck`:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh overnight
```

On Bristol, as its trusted cron account:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh overnight
```

Each command prints `Attempt: ATTEMPT_DIRECTORY`. The private `attempt.json`
contains the run ID, controller revision, input tuple, outcomes and read-back-
verified GitHub comment link. `inputs/selection.json` records actual artifact
identities and age. The controller publishes only selected fields; raw logs,
vaults, keys, tokens and instance state remain private. Failed attempts remain
in their original directories. Cleanup or publication failures return nonzero
and activate the configured cron failure email.

`result.complete` means all maintained section commands finished successfully
with their owned cleanup. Missing section names are explicit. The current
runner retains per-assertion pass/fail/skip output in the private execution
log; the public projection leaves `skipped_assertions` unknown. It does not
invent a zero count or convert command success into full release acceptance.

For trusted exact selection, replace `HOST_RUN` with that platform's exact
default-branch production run ID and `GUEST_INDEX` with the full staged
`sha256:` index digest. Use the same configured account and prerequisites as
its overnight entry. On devstack:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-kvm.sh on-demand HOST_RUN GUEST_INDEX
```

On Bristol:

```sh
/usr/local/lib/safeyolo-hardware/tests/blackbox/hardware/run-vz.sh on-demand HOST_RUN GUEST_INDEX
```

A guest in quarantine is eligible for testing. These entries do not change
production tags. Missing, expired or invalid selected artifacts fail visibly;
the entries do not rebuild or select an older passing input.

Before release, all required lanes must consume that release's exact host
archive bytes and the same recorded compatible guest digest. Compare the full
input tuple. Separate nightly selections, a hosted Mac package witness or a
host-continuity pass cannot establish a combined real-hardware release pass.

For a lost observer or stale owned resource, use the
[retained-attempt recovery instructions](INPUTS.md#recover-an-attempt).
