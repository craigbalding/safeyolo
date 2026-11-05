# Devstack storage protection

Devstack's existing `rundeck` account runs this maintenance mechanism. It protects
the harness's allocation and transfer entry points. An independent user crontab
releases emergency space and removes abandoned transport scratch files. The cron
action does not call Rundeck or require a job to start.

## Consumers and response

The supplied host binding for issue #1420 identifies these actual entry points.
The pool `/var/tmp/harness-vms`, harness `/var/lib/rundeck/harness`, evidence,
Rundeck data and logs share the root ext4 filesystem on `/dev/sda2`. The installer
verifies the four job sources against that binding before changing them.

| Existing consumer | Storage effect | Protection |
| --- | --- | --- |
| `_common.sh` `ensure_base_img` | Downloads a cached cloud image into the pool | Check available bytes and inodes before each 64 KiB write. Stop only the new download on pressure; remove its private partial file. |
| `provision.sh` | Creates a sparse guest disk and seed | Before taking the guest lease, require the full requested virtual disk size, 1 GiB for qcow2 metadata, and the free-space floor. Existing provision locks and leases remain in use. Automatic deletion of inactive guests is removed. `--clean` refuses; exact retirement requires owner and next-use selection. |
| `_common.sh` `harness_scp_to` | Copies a known file into an existing guest disk | Check host capacity for the payload and observe bytes and inodes on the actual guest destination filesystem before `scp`. |
| `_common.sh` `harness_scp_from` | Copies a guest file onto the host | Observe the remote size and require that capacity above the host floor before `scp`. |
| `ssh_exec.sh` | Captures a guest command's stdout and stderr | Retain at most 1 MiB per stream in memory. Drain excess output so the remote command can finish. The receipt preserves its exit and reports `stdout_truncated` and `stderr_truncated`. The existing timeout still applies. |
| `ssh_fetch.sh` | Returns a file prefix with the full file's size and SHA-256 | Apply the caller's existing `MAX_BYTES` before transfer. Do not copy the entire file to the host first. A complete returned file must match its hash. |

The default floor is 10 GiB and 4,096 available inodes. The byte floor follows
the existing build reserve and gives a substantial margin on the observed
approximately 200 GiB root filesystem. These host operations create few files;
the inode floor leaves room for service records and recovery. Filesystems that
report no fixed inode total use the byte check. Missing paths, failed remote
observations and failed status writes refuse new children with exit 75.

The installer also allocates a private 2 GiB emergency file with
`posix_fallocate`. Sparse file length is insufficient. Normal admission requires
that file to be fully allocated **and** the configured floor to remain free.
For example, a new 20 GiB guest requires 31 GiB available after the emergency
file is allocated. A thin initial qcow2 file does not waive its later growth.
The 1 GiB metadata margin covers disks that fit on this observed host; this is
not a general disk-sizing rule for other hosts.

Each minute, cron checks the same backing filesystems. If space is low or
unknown, cron unlinks only the dedicated emergency file. This returns its
allocated blocks to ongoing writers, including the Rundeck database and logs,
without stopping those writers. New consumers remain refused while the reserve
is absent. When sufficient space returns, a check or cron invocation allocates
the emergency file again, leaving the floor free, and normal work resumes.

Cron also removes only `storage/temporary/transfer-*` directories with a regular
lock file owned by the harness account and an obtainable exclusive lock. A
creator publishes its directory only after taking that lock. Scratch files
have zero retention and no later consumer; they contain only a transport's
decoded script or unfinished download. Running owners keep their directories.
Age does not select cleanup. Reports, selected inputs, VM disks, source,
credentials, original execution results and database history are never scanned
or selected for deletion.

The response time is one cron interval plus scheduler delay. The emergency
file provides 2 GiB of additional headroom, not an unlimited growth guarantee.
The 10 GiB floor must last until the next tick. A burst that consumes the floor
before that tick, or continuing unrelated writes after the emergency release,
can still exhaust the filesystem. The mechanism does not impose a VM quota,
interrupt existing guest work, compact the database, or delete service history
or logs. Rundeck input scripts and its internal records can still grow the
database. Their separate qualified-history maintenance remains operator-owned.
`scp` preflight budgets a file's observed size; it cannot reserve space against
unrelated concurrent writers or guarantee that a changing source stays that size.

## Deploy the reviewed candidate

On Devstack as `rundeck`, use a clean checkout of the exact reviewed candidate.
The commands below run from its repository root. Python 3.11 or later, `curl`,
OpenSSH, `timeout`, `flock` and user `crontab` must already be available. No root
access, guest boot, model run or Rundeck execution-list query is needed.

First copy the operator's nonsecret `host-bindings-14047.json` to the owned
`/var/lib/rundeck/harness/storage-bindings.json`. It must describe the current
four job files. Preserve its existing evidence copy. If a hash differs, inspect
the current source and obtain a matching binding before installation.

The installer preserves original job files under
`/var/lib/rundeck/harness/storage/original-jobs`. It then writes the private
configuration, verifies capacity and installs guarded entry points. With
`--install-cron`, it preserves other user crontab entries and installs one
minute-based storage entry. It creates no growing cron log; current observations
are atomically replaced in private `storage/status.json`.

```sh
python3 scripts/devstack_storage/install.py \
  --bindings /var/lib/rundeck/harness/storage-bindings.json \
  --python /usr/bin/python3 \
  --install-cron
```

Expected result: JSON identifies the installed guard hash, configuration, job
hashes and cron entry. Installation fails before changing job files if the
bound sources differ or initial capacity is insufficient. Installation does
not run a guest or reclaim existing persistent data. Repeating the same
installation preserves the backups and keeps one cron entry.

## Verify the deployed effect

Sylab supplies the live receipt for Lens's independent acceptance. Bind the
candidate commit, installed source/configuration, actual consumer entry points,
crontab entry and a scheduler-driven effect. Keep private scripts, credentials
and raw guest output out of the receipt.

Use synthetic observation thresholds to exercise pressure without filling the
disk. While no protected allocator is running, temporarily set
`minimum_free_gib` just above the measured available space. A guarded command
must refuse before its child runs. Leave the emergency file intact for the
next real cron tick. The tick must release the file and record
`released_emergency_bytes`; measure the actual free-space change. This action
must run independently of Rundeck job admission. Do not stop Rundeck, invoke its
failed execution-list route, or stop protected work to create that condition.

Restore the reviewed configuration. Once capacity permits re-arming, the next
check or tick must recreate the allocated reserve and a small existing consumer
must run normally. Use inode and missing-path controls for their refusal and
recovery cases. Retain source proof at its actual limits: local execution of a
cron command does not prove installation or execution by Devstack's scheduler.

For repeatable local source controls, use the repository's locked development
environment. The supplied nonsecret host-job copies and their sibling binding
receipt exercise the actual four entry points without a VM or network request:

```sh
DEVSTACK_STORAGE_JOB_SOURCES=/evidence/operator/devstack-storage/host-jobs-14047 \
  uv run --frozen --no-sync pytest -q tests/test_devstack_storage.py
```

The control uses an 8 KiB emergency file, a local SSH stand-in and a user-crontab
stand-in. It tests the actual source transformations and installed cron body,
including refusal/recovery and independent space release. It does not establish
the live SSH, cron or Devstack deployment result.
