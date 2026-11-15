# Rootless published-guest preparation: current proof

This is the bounded feasibility work for [#1553](https://github.com/craigbalding/safeyolo/issues/1553).
The complete go/no-go result remains **unproved**. Native macOS extraction of
one published Kali image bundle passed. The same files started a
Virtualization.framework (VZ) virtual machine (VM) with working root and
user-1000 read/write/execute. Native Ubuntu import and systrap startup
passed with the ordinary mapping, including guest identity and read/write/execute.
The native supplementary canonical specimen matches the privileged baseline,
including kernel runtime-map access, ACL inheritance and capability effects.
Candidate and baseline backend observations are characterized below, including
unsupported metadata cases. The native distinct-map witness and final independent
go/no-go remain pending. This candidate changes no production installer.
#1554 owns production integration; #1563 owns maintained blackbox coverage.

The trusted starting source is `6ee7e8bb308fcd865fa0a244b455c7dcc86b9bb6`.
The assignment is [comment 6888425057](https://github.com/craigbalding/safeyolo/issues/1553#issuecomment-6888425057).
Lens independently accepted criteria 1, 2 and 5 at `ea1040df` in
[comment 6892180913](https://github.com/craigbalding/safeyolo/issues/1553#issuecomment-6892180913).
Criteria 3, 4, 6 and 7 remain open. Preserve those decisions and the M/High
estimate; the cumulative 60-minute reassessment has already been reached.

## Reached result

[`macos-observed.json`](macos-observed.json) retains the actual archive inventory,
numeric host metadata, sparse allocation, commands and exact input identities.
The ordinary account was Bristol's dedicated `sy-agent`, user ID (UID) 502,
group ID (GID) 20. The host was Apple Silicon macOS 26.6.2/build 25G83, with
Apple File System (APFS). The tools were native bsdtar 3.5.3/libarchive 3.7.4
and Zstandard 1.5.7.

The retained published input was `guest-2026-10-31.274`, profile `kali-pentest`,
compatibility `v1`, from `ghcr.io/craigbalding/safeyolo-guest`. The index,
manifest and compressed archive hashes were checked. The retained config blob
was absent, so this was not a new full Open Container Initiative (OCI) admission.
The inspected compatible package was debug source
`c6dd3b8bfef1a2e5f49e1fbc273c4b2ac2b46a52`. The later retained-image runtime
below uses that unchanged installation.

The prototype used the existing macOS `tar -xpf - -C STAGE -- Image
initramfs.cpio.gz rootfs-base.ext4` extraction path. It preserved the three
regular files and their modes. It omitted the unselected `build-inputs.json`.
Extraction took 12.198 seconds, after archive verification. The ext4 image had
3,387,375,616 logical bytes and 2,335,162,368 allocated bytes. The archive's sparse
extents contained 2,326,806,528 data bytes; APFS allocation is not byte-identical
to that extent sum. No Linux special files were materialized on APFS.

The candidate PATH contained only tar, zstd and rm. `sudo` was absent from that
PATH. Parent and child recorded UID 502/GID 20. This records the actual commands
and account; it does not claim a syscall trace or system-wide sudo revocation.
The account's confinement and policy were unchanged. That extraction operation
started no VM or model; the separate runtime operation is recorded below.
The same prototype also removed a cancelled private stage on native macOS
using a small synthetic three-file archive. This did not test a usable guest.

## Linux prototype

`import_guest.py` reuses the maintained `linux_host::namespace_command` rule and
the runtime's unshare-holder, `newuidmap`/`newgidmap`, and nsenter sequence.
It uses the existing prepared namespace entry when AppArmor requires it.
No new profile, global namespace setting, privileged helper or sudo fallback
is installed by the candidate.

The import namespace uses archive coordinates directly. UID and GID bases
are independent. For either kind of ID:

| Import-namespace ID | Host ID | Purpose |
| --- | --- | --- |
| 0 | selected base+1000 | Import process root; the runtime leaves this delegated ID unused. |
| 100000..100999 | selected base..base+999 | Canonical guest 0..999. |
| 101000 | operator ID | Canonical guest 1000. |
| 101001..165535 | selected base+1001..base+65535 | Remaining canonical guest IDs. |

Host UID/GID 0 is absent. Do not run the current host-coordinate remapper inside
this namespace. The prototype retains the existing selected tar members and
confinement switches, verifies one open archive descriptor, creates private
staging, and reaps extraction before cleanup in the same namespace.
Existing output directories are refused before mutation.

The rootfs is extracted with numeric owners, access control lists (ACLs) and
extended attributes in the import namespace. A second pass reads the same
verified archive descriptor and extracts only `cache-paths.txt` as the ordinary
host account, with `--no-same-owner`. The producer writes that file as text;
`host_boot.rs` reads its lines to select package-cache mounts. Its build-account
owner is not guest metadata. The rootfs pass keeps its existing ownership and
metadata options.
This bounded prototype uses two decompression passes; performance and production
integration are not established by this correction.

The 20 focused Linux-worker controls pass. They cover all 65536 canonical IDs
with ordinary and distinct nondefault bases, embedded metadata inventory,
descriptor replacement, selected members, failed tar, cancellation, external
symlink-target preservation and existing-directory preservation. GNU tar reads
the supplementary GNU 1.0 sparse fixture with the expected contents.
The new real-tar control preserves rootfs modes and executable content while
extracting a cache list whose UID/GID 1001 differ from the ordinary account.
The former combined extraction at `bcde3993` fails that control with tar exit 2
because it cannot assign the cache owner. Separate missing-cache and cancellation
controls remove the private stage and preserve the external target's content,
owner, mode and inode. Their namespace is replaced by the worker account for
these controls; they do not establish native multi-ID cleanup.
These controls alone do **not** prove native namespace entry, kernel metadata writes,
an existing usable guest, native macOS failure cleanup, or backend behavior.
Worker tar reports that ACL writes are unsupported on this filesystem. Passing
worker controls do not establish ACL preservation on the required native host.
The prototype is not a replacement for production's inode/mount/hardlink
validation. Production integration must preserve those existing checks.

From the task checkout on Linux, use the locked development environment with
GNU tar and zstd to rerun the focused controls. Select a disposable disk-backed
scratch directory for pytest:

```sh
uv run --frozen pytest -q experiments/rootless_guest/test_import_guest.py --basetemp /disk/backed/1553-pytest
```

Expected result: 20 passed. This command starts no guest or namespace.

Two controls send SIGTERM and SIGINT while real GNU tar is stopped after its
first extracted block and real zstd is blocked on the pipe. Both children are
reaped before the private stage is removed. The external target retains its
contents, owner, mode and inode. Only namespace entry is replaced by the worker
account. These controls establish active-child cancellation locally; native
mapping and preservation of an existing usable guest remain separate proof.
The control isolates each child process group so its deliberate SIGSTOP does
not deliver an unrelated orphan-group SIGHUP to the driver.

`make_fixture.py` now assigns the link name and device pair separately. This
preserves the default `(0, 0)`, character `(1, 3)` and block `(7, 0)` headers
while avoiding the repeated CodeQL tuple-inference diagnostic. The existing
real archive control checks those generated device headers. No scanner rule or
archive support requirement changes.

## Native execution packet

Sylab owns protected Ubuntu execution. Relay has selected the bounded Bristol
slot for #1553; Forge owns ordinary preparation and execution through UID 502.
Run native commands only as the selected ordinary account, in a new
owned proof directory, with the verified compatible package and archive already
bound. Retain original preparation failures before changing prerequisites.
Use user-writable command locations. No guest build is needed.

The inventory and ordinary mapping operation has completed as native execution
18403, using the immutable `bcde3993` packet. The complete readable receipts are
`/evidence/operator/1553/native-first-18403.json`,
`/evidence/operator/1553/18403-archive-inventory.json` and
`/evidence/operator/1553/18403-normal-mapping.json`. Their hashes match canonical
operator direction backlog:16101. This candidate consumed those ordinary reads.
The packet exited 0 in 2.218 seconds and reaped its namespace holder. The normal
UID/GID maps match the table. No extraction or backend ran. Preserve observer
compile failure 18402, which occurred before guest effects.

The actual archive has 7,737 records: 1,011 directories, 831 symbolic links,
5,893 regular files and two hardlinks. All 7,736 rootfs records use UID/GID
100000. The only other owner is UID/GID 1001 on regular `cache-paths.txt`
(mode 0644, 34 bytes). No sparse map, device, FIFO, ACL or extended-attribute
header is present. PAX headers contain only modification times and paths.
This inventory does not cover supplementary metadata or runtime enforcement.

Native execution 18405 completed `ubuntu_import_probe.sh` from immutable
`70f3d40a30838f4837a13aa5ec87c19d42c0c05b`, as ordinary UID/GID 1000.
Its original command and all twelve result, preparation, metadata and log files
are retained at `/evidence/operator/1553/native-import-18405`. The source hashes,
command stdout, separate result and preparation files agree. Forge consumed all
twelve original files. Lens independently consumed their byte-for-byte mirror
under `/home/agent/acceptance/1553-operator-receipts/native-import-18405`.
The mirror resolves that review's input gap; the original shared-view fault
remains Sylab-owned. Reuse these results without replaying import or inventory.

The packet ran from 05:04:07.515798 to 05:04:13.101603 UTC on 15 November 2026.
Extraction took 4.296972 seconds. The candidate PATH contained no sudo.
The namespace observer checked 7,736 rootfs records with zero mismatches for
type, numeric owner, mode, regular-file size, symlink target and hardlink inode.
The host rootfs was 100000:100000/0755. The readable cache was 1000:1000/0644,
with the expected text. This observer does not compare file contents,
allocation or runtime metadata. Lens's equal-size mutation control demonstrates
that limit; it is not an established extraction defect.

The small missing-cache and explicit-cancellation specimens each exited 1,
removed their private stages and preserved the external target's content,
owner, mode and inode. The original missing-cache error records tar exit 2
and zstd exit 0. Cancellation occurred after extraction children completed.
Asynchronous published-archive cancellation and preservation of an existing
usable guest remain unproved.

### Native Ubuntu retained-tree runtime

The successful import remains at
`/home/agent/1553-native-import-b/published/extract-5ls7iw5p` on
`sy-1050-connected-8029-amd64`. The exact source inputs remain under
`/home/agent/1553-native-inputs-70f3d40a`. Preserve both.
The independently retained #1562 receipt
`/evidence/operator/1562/mounts-18389.json` identifies a compatible production
runtime at `/home/agent/1562-b682-installed`, source
`b6821094322e4ab261f4c149029839037fe43631`, using the same published archive.
The reached execution used `/usr/bin/python3` 3.12.3 with the required helper
imports. The earlier supplied controller virtual environment was absent on this
execution host. No product build or new host prerequisite was needed.

Original nonsecret records are retained at
`/evidence/operator/1553/runtime-18413`: `result.json`,
`setup-failure-18410.json`, `operator-continuation.py`, `prepare.log` and
`operator-result.json`. Forge consumed all five files and confirmed the original
action prefix and restored helper identity. Lens's supplied mirror is
`/home/agent/acceptance/1553-operator-receipts/runtime-18413`.
The 23,340-byte `result.json` has SHA-256
`1b38f5722734b744fdfa06ef3714e34b9d4ac7a52deb93ef90e63d11e8690546`.
Canonical operator direction backlog:16106 binds these files to source
`9b25f7062ce1333ba47d1ebc60a84033410960ac` and the retained import.

This was a resumed execution, not one uninterrupted successful command.
Operator setup 18407 failed before guest execution because its wrapper was too
large. Setup 18408 found the missing controller environment; 18409 verified the
actual Python and imports. Execution 18410 passed content comparison, agent
creation and proxy startup, then stopped before guest startup because the reduced
source transfer omitted `tests/blackbox/harness/process_identity.py`.
The preserved setup record contains exactly the first six actions of the final
result. The operator restored that helper's exact `9b25f706` bytes. Operator
compilation and source-hash checks 18411/18412 failed before guest execution.
Execution 18413 resumed only the original driver's remaining actions, using its
unchanged guest commands and original `finally` block. The retained continuation
source makes that boundary reviewable. Import, content comparison and proxy
bootstrap were not replayed.

The read-only content observer checked all 5,892 regular rootfs payloads
(429,073,907 bytes) against the verified archive and existing prepared baseline.
It reported zero mismatches in 9.437 seconds. The baseline is the retained
`1436-operator/guest-store/trees/sha256/` tree for this archive and mapping.
The observer neither extracted the archive nor repeated its header inventory.
Four local controls cover valid bytes, equal-size mutations in either tree and
a compressed frame-checksum failure, including the direct command-line entry.
No allocation, ACL or capability comparison is inferred from matching contents.

The disposable `/home/agent/r1553a/instance` explicitly selected the retained
stage through `installed_assets`. Its actual systrap run was
`44805481760047fda27eeb52ad36eab5`, with holder PID 64446 and backend PID 64479.
The result retains both process birth tokens and verifies them against the
running processes. The UID and GID maps were each `0 -> 100000` for 1,000 IDs,
`1000 -> 1000` for one ID, and `1001 -> 101001` for 64,535 IDs.
Host UID/GID 0 remained outside those maps.

Guest user 1000 and guest root each passed numeric identity and read/write/execute
in `/home/agent` and `/workspace`. The four host marker files had mode 0700;
ordinary-user markers mapped to 1000:1000 and root markers to 100000:100000.
Guest root used the maintained guest sudo wrapper. Host sudo was absent from
the candidate PATH. This is a PATH witness, not a syscall trace or system-wide
sudo revocation. Guest output identified Debian 13.7 and gVisor Linux 4.19.0.
Both guest commands reported `/usr/bin/id` as a regular empty file while the
identity checks passed. Preserve that observation; no regression or complete
runtime metadata comparison is established by it.

Agent, proxy and Coord stop commands each returned 0. The original result has
no cleanup failures. The operator's post-shutdown observation found no tracked
process survivors, matching Unix listener rows or retained failure paths.
The private whole instance remains on the native host; no credential bytes were
copied into these records. The packet downloaded and built nothing, and changed
no host policy, delegation, package or other instance.

This successful run did not trigger or repair Lens finding F1 in
`work-6460c275ae88410a88b9afed14fc435b@3`. The original observer falsely treated
every retained proxy socket or stopped NATS process record as cleanup failure.
The corrected `ubuntu_runtime_probe.py` reports those files as diagnostics.
It retains the maintained process-birth survivor checks and the existing
container/user-namespace PID and readiness-state checks. It also reads actual
Unix listeners under the owned instance. Real survivors, listeners, retained
active state, stop failures and inspection failures still fail cleanup.
The separate `guest_result` field preserves the result before cleanup inspection.
No diagnostic record is removed to manufacture success.

Sixteen focused observer controls pass, including real closed/listening sockets,
an unrelated listener, real live/stopped child processes, retained active state
and an unreadable listener table. The content controls remain included.
Run these controls from the task checkout using the locked development Python
environment and a disposable disk-backed pytest directory:

```sh
uv run --frozen pytest -q experiments/rootless_guest/test_ubuntu_runtime_probe.py --basetemp /disk/backed/1553-runtime-pytest
```

Expected result: 16 passed. No guest or namespace starts. The native result is
reused after this observer correction; no product replay is needed.

### Native supplementary comparison

Native execution 18414 completed `ubuntu_metadata_probe.py` from
`0aa7b825107d9469da0f5a224825920ad818b315` on 15 November 2026. Canonical
operator direction backlog:16111 supplies the reached observation and read-only
collection recovery 18415. Forge verified all 12 original file sizes and hashes
against `/evidence/operator/1553/metadata-18414/manifest.json`, then compared the
complete actions, preparation records, host metadata and namespace observations.
The original `result.json` is 120,817 bytes, SHA-256
`a7ea2a4b1067a47ae7053390e28005c8db76245055690dbd84a97c4236e0a84a`.
It equals original `caller.stdout`. The complete originals remain beside that
manifest; Lens's mirror is
`/home/agent/acceptance/1553-operator-receipts/metadata-18414`.

The host was the retained native Ubuntu 24.04.4/x86_64/kernel 6.8.0-147/ext4
consumer, `sy-1050-connected-8029-amd64`. The ordinary account was UID/GID 1000,
using `/usr/bin/python3` 3.12.3 and the installed production package
`/home/agent/1562-b682-installed` at
`b6821094322e4ab261f4c149029839037fe43631`. Namespace-entry and all three source
hashes match the selected packet. The actual UID/GID bases were both 100000;
this is not distinct-base proof. The command ran from 07:05:08.982559 to
07:05:12.430889 UTC, a 3.448330-second observation, and exited 0. This exit does
not establish that every specimen or observation succeeded.

Preflight found no active owned consumer and no existing output directory.
Free space was 5,656,707,072 bytes before and 5,655,658,496 bytes after the
operation. Admission preserved the 5 GiB floor plus the 192 MiB forecast.
The candidate PATH contained no sudo. Host sudo was used separately for the
baseline tar extraction, installed `host remap-rootfs` and raw host metadata
observation. All four baseline tar, decoder and remapper operations exited 0.
These privileged comparison operations were not a candidate fallback.

For reproduction on that host, the three source files must retain their relative
layout and recorded hashes. Use ordinary UID/GID 1000, the package and entry
above, native GNU tar 1.35, zstd, delegated-ID helpers and `/bin/cat`.
The selected output must be absent, and current consumers/capacity must permit
the operation. The recorded command from the staged source root was:

```sh
/usr/bin/python3 experiments/rootless_guest/ubuntu_metadata_probe.py run /home/agent/1553-native-metadata-g5
```

Expected output is a set of observations with each exit and stderr preserved,
including unsupported cases. Reuse the completed records; this command does not
select a replay. The operation creates private synthetic specimens and baseline
stages. It changes no published imported tree, existing runtime, delegation,
namespace/AppArmor policy or installed package. Host UID/GID 0 remains outside
both import and runtime maps.

The canonical import exited 0. All 15 host snapshot entries match the baseline
in every recorded field except inode numbers. Each tree's regular/hardlink pair
shares one inode, and its symlink targets `regular`. Numeric host owners include
root 100000:100000, guest user 1000 at 1000:1000, daemon 100033:100033 and the
range boundary 165535:165535. Modes, contents, FIFO type, `user.safeyolo.fixture`,
and access/default ACL bytes match. The sparse file has 67,108,864 logical bytes,
8,192 allocated bytes and identical contents in both trees. The mode-06751
set-ID specimen is preserved.

Canonical raw host capabilities are revision 3 (V3), rooted at 100000 in both
trees. The kernel runtime map exposes revision 2 (V2), rooted at namespace 0.
For all three tested UID/GID pairs, native `cat` execution grants permitted and
effective capability mask `0x400` in both trees. Set-ID execution changes
effective/saved/filesystem UID/GID to 0 and gives the same `0x1ffffffffff`
permitted/effective mask. These are namespace-root effects; host root is unmapped.
Every access child first drops supplementary groups. Before specimen execution,
its permitted/effective/inheritable/ambient capability masks are zero; its
bounding mask is retained. The canonical results are identical for both trees:

| Runtime UID/GID | Private read | ACL directory list | ACL path search | ACL create |
| --- | --- | --- | --- | --- |
| 1000:1000 | `private` content | `inherited` listed | EACCES | EACCES |
| 33:33 | EACCES | EACCES | Success, child owner 0 | EACCES |
| 65535:65535 | EACCES | EACCES | EACCES | EACCES |

The ACL names runtime user 1000 with read permission and group 33 with search
permission; its mask is read/search and other permissions are empty. Default
inheritance under namespace root with umask 0077 creates the same mode-0640
file and access ACL, with mask read-only, in each tree. Before/after namespace
snapshots match except inode numbers. Access starts from an already opened
specimen root. It does not broaden or prove unrelated host-parent traversal.

Three separate unsupported characterizations retain material failures:

- `devices` exits 1 with tar exit 2 and zstd exit 0. Both character 1:3 and block
  7:0 creation fail with EPERM; namespace capabilities do not permit these host
  device creations. The candidate removes its private failed stage. The explicit
  privileged baseline creates both nodes. Neither node is opened by the observer.
- `raw-acl42` exits 0 but tar reports `Invalid argument` while setting its ACL.
  The candidate directory has no ACL. The baseline preserves raw host principal
  42, outside the import/runtime maps; its namespace read exposes unmapped
  principal 4294967295. Exit 0 does not mean this ACL was preserved.
- `v2-capability` imports with exit 0. Its raw candidate xattr becomes V3 rooted
  at host 101000, the import namespace's root, while the baseline remains V2 with
  implicit host root 0. Candidate runtime snapshots fail twice with EOVERFLOW
  while reading that xattr. Real execution still runs but has permitted/effective
  masks 0; the baseline grants `0x400` for each of IDs 1000, 33 and 65535.
  This is an observed effect difference, not merely a different encoding.
  ENOENT access results for private/ACL paths in this one-file specimen indicate
  absent paths, not permission enforcement.

The source explains why V2 is a separate case. The producer's
`linux_host/ownership.rs::shift_attribute` converts V2 to canonical V3 when
`source_base == 0`. The privileged importer shifts explicit canonical V3 roots,
but does not convert the standalone synthetic V2 input. The prototype preserves
canonical V3 correctly; its different import-root mapping changes synthetic V2.
The verified published Ubuntu archive contains no xattr, ACL, sparse, FIFO or
device header. These synthetic differences establish no regression for that
archive and supply no authority to add arbitrary-archive support or new input
restrictions. No repair or archive-contract change is established for canonical
V3 by this comparison.

All runtime-map effects above are Linux kernel observations, not gVisor
observations. gVisor capability/ACL/set-ID behavior, including any pre-existing
limitation, remains unqualified. An isolated backend comparison is useful only
for a still-required effect; retain the actual baseline comparison before
classifying any backend difference as a candidate regression.

The operator's first recursive collector hit EACCES on a private baseline
descendant after the observation completed. Execution 18415 only read the named
original files. `operator-result.json` retains that error and source/command
bindings; `collection-result.json` records all files present, free space and
absent namespace holder 65091. No observation was repeated for collection.
The top-level result string also does not establish success of the two candidate
xattr snapshots; their original exit-1 records remain authoritative.

The prior 26 focused controls and their independent interpretation carry
forward. The current source correction adds active-child cancellation controls
and prepares the isolated backend packet below. The
worker controls used controlled xattr bytes and credential-drop calls; those
controls alone do not prove native enforcement. Lens's complete
output-5 check `work-aeac4cf2781840ff93efa43bee252df2@3`, all 16 evidence references
and its full prior checks carry forward. Its pending-native-comparison gap is
now supplied; its remaining limits and full-issue abstention persist.

The following steps describe remaining full-issue proof. Completed inventory,
import and ordinary-map startup observations carry forward. The selected
continuation prepares the next isolated Ubuntu operation; no new native result
is claimed here.

1. Reuse the reached Ubuntu inventory, import, contents and ordinary-map runtime.
   Before a further native operation, inspect its actual retained inputs,
   effective delegation, active consumers and capacity. A distinct mapping
   needs genuinely delegated, different nondefault UID/GID bases. Record
   legitimate prerequisite preparation separately; do not weaken global policy.
2. Reuse the completed supplementary comparison. Any selected isolated gVisor
   observation should use the retained candidate and baseline canonical trees
   under `/home/agent/1553-native-metadata-g5`, with the same installed runtime.
   Compare required ACL/private access, capability/set-ID effects and identities
   33/65535 without repeating import or the completed guest journey. Do not add
   previously unsupported backend behavior merely to match kernel observations.
3. Resolve asynchronous cancellation and existing usable-guest preservation.
   Carry forward the completed small missing-cache/after-extraction cancellation
   controls. Inspect an incomplete or failed attempt before selecting any retry.
4. Follow each remaining successful **published** preparation into the backend.
   Reuse `tests/blackbox/installed_sections.py::prepare_native_instance`, the
   existing installed-host/lifecycle fixtures and `guest_exec.py` commands.
   Bind the newly prepared assets explicitly and capture current guest identity,
   read/write/execute, metadata, and owned shutdown. Do not replace this step
   with a synthetic guest, a worker namespace or a broad unrelated suite.

### Isolated Ubuntu backend and cancellation packet

Sylab runs this packet on `sy-1050-connected-8029-amd64` as UID/GID 1000.
Use `/usr/bin/python3` 3.12.3, the retained `b6821094` package at
`/home/agent/1562-b682-installed`, the existing published import and the complete
`/home/agent/1553-native-metadata-g5` directory from execution 18414.
Stage this candidate's `experiments/rootless_guest` and the existing blackbox
helpers with their repository layout, including `harness/process_identity.py`.
Before execution, verify the immutable source, current maps, live owned consumers,
and absent output directory. The backing filesystem must have the existing
5 GiB floor plus 640 MiB: 512 MiB bounds a partial published import even if it
finishes before the signal; 128 MiB retains the previous runtime allowance.
Do not remove active inputs to make this check pass.

From the staged source root, run once:

```sh
/usr/bin/python3 experiments/rootless_guest/ubuntu_runtime_probe.py \
  /home/agent/r1553g7 \
  --metadata /home/agent/1553-native-metadata-g5
```

The packet creates one disposable instance and mounts the original canonical
candidate and baseline trees at `/candidate` and `/baseline`. It skips the
completed content comparison and ordinary-map I/O journey. The guest shell
records numeric metadata, contents, links, sparse allocation, capability labels,
and actual private/ACL access and capability/set-ID execution for IDs 1000, 33
and 65535. Each command's exit is retained. Missing `getfacl` or `getfattr` is
reported as unavailable coverage; no guest package installation is hidden in
the observation. A collection exit of zero is not a parity verdict.

While that owned guest is running, the packet refuses an import onto its
existing stage. It then interrupts a new published-archive import only after
observing a rootfs and live tar child. An external-target symlink in that new
private stage tests cleanup confinement. The original archive is unchanged.
The packet checks the extraction result, stage removal, exact child birth tokens
and external target. A completed or failed import before the signal is an
incomplete cancellation observation, never a pass or an automatic retry.
Two focused controls verify that distinction with real child exits 0 and 7.
After both operations, the live guest must pass the existing ordinary-user
identity and home/workspace read/write/execute command. Reusing that command
tests preservation across the cancellation, rather than repeating the original
journey for bookkeeping. The existing
finally block stops its agent, proxy and Coord and retains genuine cleanup
failures and inert diagnostic paths separately.

Return the original `result.json`, `prepare.log`, `cancellation.json`,
`cancellation.stdout`, `cancellation.stderr` and cancelled attempt's
`preparation.json` through the existing readable operator handoff. Do not copy
the private instance or credentials. Retain reached failures and inspect effects
before a retry. Existing 18414 stages, original 18413 results and the successful
published import remain current inputs. This packet adds no privileged setup,
delegation, host policy change, production integration or new acceptance gate.

Native execution 18425 completed this packet using `351b4d95` and product
`b6821094`. The eight original files are retained under
`/evidence/operator/1553/g7-351b-runtime-18425/`, with the ordinary worker/reviewer
mirror `/home/agent/acceptance/1553-operator-receipts/g7-351b-runtime-18425/`.
The complete result is SHA-256
`37f1974ef9c72674a30653b6550ca0a2bf71d1b03429b9ca7dda6e90b948881f`.
Candidate and corresponding gVisor baseline agree on 16 metadata entries,
11 content hashes and effective operations for IDs 1000, 33 and 65535.
Both gVisor trees deny the ACL operations and set-ID execution and suppress
capability effects. These differ from the native-kernel baseline, so they
do not establish a candidate regression or new required backend support.
Missing `getfacl` and `getfattr` remain unknown coverage.

Active-tar cancellation removed the private stage, left no survivors among
three recorded child births and preserved external content, owner, mode and
inode. The existing Ubuntu guest then passed ordinary identity and
home/workspace read/write/execute. All owned stops returned zero; cleanup
failures were empty. Preserve the original source binding and reuse this
proof without running the ordinary-map packet again.

Local validation for that packet was 44 focused controls:
20 import, 16 runtime-observer and 8 metadata-observer cases. The two new
runtime controls check early completion and failure reporting; they do not
establish the protected cancellation result. Local CodeQL remains unsupported
on Linux aarch64. Hosted CodeQL passed on the independently reviewed fixture
correction at `351b4d95`; this publication's new hosted checks are separate.

### Native macOS retained-image runtime

On 15 November, the selected physical Bristol operation ran from 08:27:00.033
to 08:27:11.669 UTC, including image checks and owned shutdown. The executed
controller and guest script are retained at source
`6ebd2f96f71a79b7ecc619e96304f9fa0aeb366b`.
[`macos-observed.json::runtime_witness`](macos-observed.json) contains the
original result, helper/serial/guest output and post-shutdown host read.

The ordinary UID 502/GID 20 process reused the prepared Kali files at
`/Users/sy-agent/f1553-20261115/native/prepared/extract-kiyduh7b` and the complete
compatible installation at `/Users/sy-agent/h1552`, source `c6dd3b8b`.
All three image hashes equalled that installation's existing
`share-kali-failed-1050` files before startup. The prepared image hash remained
`5d2286d5deb330073b9af96b54a62ee1982707308a52223e2e714fc642f0063f` after shutdown.
No extraction, complete installation copy, product build or acquisition ran.
The directory name of the existing files supplies no startup diagnosis.

The maintained kernel observers found no active VM consumer before effects.
The held #500 NATS/proxy births were recorded and remained unchanged afterward.
Only authorized ports 46372/46374 were available in the preceding bind-and-close
read; this fixture required no host TCP listener. The helper used the existing
`/Users/sy-agent/bin/run-vz-test` wrapper, a new private `runtime-g8` parent,
four owned VirtioFS shares and a new 256 MiB sparse overlay. It copied only the
installed guest assets. The normal installed two-phase init ran unchanged;
a wrapper around its static phase started the Linux observation script.
The candidate host PATH contained only the wrapper's Python interpreter.
The helper was mode 0700, and no host sudo command ran. This is an account,
command and byte-bound observation, not a syscall trace or global sudo revocation.

The VM reported Kali 2026.1, Linux 6.12.17/aarch64. Root and UID/GID 1000 passed
the required identity and actual read/write/execute checks. Ordinary-user data
and executables reached both the new home and workspace shares. The subsequent
host read found all four files owned by 502:20, with modes 0644/0755 and the
expected contents. The output parent remained 0700.

Published guest observations preserve root ownership, ordinary and set-ID modes,
`/bin` and `/lib` links, and guest character/block devices. The small specimen
inside the disposable overlay preserved a hardlink inode, symbolic-link target,
FIFO and character/block nodes. Its 64 MiB sparse file used 4 KiB allocation and
returned its written tail. UID 1000 read its private file; IDs 33/65535 were
denied. Each identity executed the specimen. The separate set-ID executable
reported effective UID 0 for all three identities. These Linux devices were
created inside the VM, not on APFS.

`getfacl`, `getfattr`, `setfacl` and `setfattr` were absent, with exit 127 retained.
The ACL-labelled directory therefore used ordinary permissions; its successful
reads are not ACL proof. `setcap cap_net_bind_service=ep` returned
`Operation not supported`, exit 1. The subsequent executable had no file
capability, and its zero effective masks do not establish capability behavior.
The later baseline operation below records the same tool absence and capability
failure. Their precise causes remain unknown. Neither observation establishes
a candidate regression. Missing guest tools were not installed.

The wrapper received the requested SIGTERM and returned 143 after reaping its
helper. The helper log records its five-second grace followed by a forced VM
stop. Final kernel enumeration found no VM processes. This proves owned teardown,
not graceful guest shutdown. No foreign process was stopped.
Free space was 23,107,645,440 bytes before the operation, 23,073,927,168 after
shutdown and 22,974,439,424 on the later read. These endpoints exceed the existing
20 GiB operator-home reserve; no continuous peak measurement is claimed.
The overlay allocated 1,052,672 bytes after shutdown. The three prepared files
retained their hashes, modes, owners and sparse allocation.

For reproduction on the same authorized host/account, keep the verified
installation and prepared inputs above, retain the two maintained kernel
observers under the checkout's `tests/blackbox/harness`, and select an unused
disk-backed output. From a checkout with this packet, run:

```sh
/Users/sy-agent/f1104-8744/source/.venv/bin/python experiments/rootless_guest/macos_runtime_probe.py /Users/sy-agent/f1553-20261115/runtime-next
```

Expected result: `guest_probe_exit` is `0`, guest and helper logs retain individual
metadata failures, and no owned VM birth survives cleanup. A previously used
output is refused before another run. Do not repeat this successful journey
solely to reformat its evidence.

After the reached run, the observer was corrected to retain stop errors and
check exact owned births separately from a later foreign VM consumer. Six local
controls cover early exit, successful teardown, stop/inspection failures and
owned versus foreign survivors. They replace the native boundary with controlled
inputs and start no VM. The original run remains bound to `6ebd2f96`; it was not
replayed for the observer correction.

The reached reassessment supplies Mac startup and useful Linux metadata evidence.
No asynchronous or failed import ran while this guest was live. That preservation
criterion, capability/ACL comparison, the protected Ubuntu packet and genuinely
different delegated bases remain open. No new host policy decision or default
guest is required for this Kali result. The separate original default-manifest
refusal still requires its canonical approval and effective-access reads before
any decision or retry. Bristol root, elevation, personal-account access and
held #500/#1104 changes remain unauthorized.

## Matrix and remaining interpretation

| Case | Expected and observed result | Limit or remaining observation |
| --- | --- | --- |
| Ordinary/private files, directories, executable and set-ID modes | Native Ubuntu host/kernel owners and access match its privileged baseline. Corresponding gVisor candidate/baseline trees also agree, including their set-ID refusal. Mac candidate/baseline ownership, private access, executable and set-ID effects agree. Both platforms reached root/user-1000 read/write/execute. | The full native distinct-map run remains pending. |
| Symbolic links and hardlinks | Published Ubuntu links and hardlink identity matched. Mac candidate/baseline links and hardlink identity agree. Native failed/cancelled stages preserve the external target and a usable guest on each platform. | Mac cancellation followed extraction-child completion; Ubuntu cancellation interrupted active tar. No blanket arbitrary-archive claim. |
| Sparse files | Ubuntu canonical kernel contents and 64 MiB logical/8 KiB allocation match baseline. gVisor reports the same logical block accounting for both mounted trees; that is not host physical allocation. Mac candidate/baseline specimen uses 4 KiB for 64 MiB logical contents; the unchanged outer disk remains sparse. | Different backend allocation reports do not prove loss of host sparseness. |
| First in, first out (FIFO), character and block nodes | Ubuntu FIFO matches baseline. Device creation fails EPERM and cleans its stage; privileged baseline succeeds. The published Ubuntu archive requires neither device nor FIFO creation. Mac candidate/baseline VM specimens create FIFO and devices with matching numeric metadata. | These Linux devices are inside the VM. No APFS materialization or arbitrary host mknod support is required. |
| Extended attributes (xattrs) and capabilities | Canonical Ubuntu V3 root identity and kernel effects match baseline. Synthetic V2 differs and causes EOVERFLOW. Both corresponding gVisor trees suppress capability effects. Mac candidate/baseline both reject setcap as unsupported. Published Ubuntu headers have no xattrs; Mac carries its Linux filesystem inside the unchanged ext4 image. | Missing Mac xattr tools remain unknown coverage; zero masks for an unlabelled executable are not a capability pass. No arbitrary V2 support is inferred. |
| Access/default access control lists (ACLs) | Canonical Ubuntu kernel principals, masks, inheritance and actual access match baseline. Corresponding gVisor trees both deny ACL operations. Raw UID42 loses its ACL despite import exit0. Mac candidate/baseline both lack ACL tools and observe only ordinary permissions. | Missing Mac tools and pre-existing backend behavior remain explicit. Raw42 is characterization, not a host-ID passthrough requirement. |

The actual Linux cache list uses build-account coordinates; split extraction
removes that incidental owner from the namespace requirement. The tested
ordinary-map import and runtime are viable. The smallest implementation path
remains archive-coordinate namespace extraction plus ordinary host-cache
extraction, preserving production's existing inode/mount/hardlink validation
and confinement. The observed unsupported synthetic cases do not authorize new
metadata rewrites, arbitrary-device support or input restrictions.

Current native Ubuntu evidence is the ordinary import/runtime, canonical
comparison and execution18425 described above. The host is Ubuntu 24.04.4,
x86_64, kernel 6.8.0-147, ext4, UID/GID 1000, with GNU tar 1.35 and Python 3.12.3.
The existing installed namespace entry is used with the unchanged AppArmor
restriction. Permitted prerequisite execution 18426 preserved the original
agent 100000 and ubuntu 165536 ranges and added distinct agent UID 231072 and
GID 296608 ranges, each 65536 IDs. Its actual namespace/id consumer passed.
That prerequisite alone does not establish the full distinct import/runtime
witness. The command below uses those real ranges without changing the original
installation config. Sylab owns its protected execution and original return files.

The actual `compat-v1` discovery tag was resolved on15November to that same
`67bcb6c5...` default index. The public index bytes are retained locally at
`/home/agent/1553-native-inputs/default-index.json`. The darwin/arm64 manifest is
`sha256:25a17227648078261bc331f751e5e11a33d4525cdaabeb9d3f64a0faec6c8ea1`.
Fetching that immutable manifest returned HTTP 428 through the proxy.
Canonical operator backlog:16102 and the retained
`/evidence/operator/1553/registry-refusal-0354.json` correlate the original refusal
with the outer credential guard. Its private outer decision remains pending
with Sylab/Craig. The separate #1560 refusal has its own disposition.
No identical request was retried. Read the exact canonical approval and effective
access before any future decision or retry. Network allow alone grants no
credential or route permission. Do not change package metadata or classify the
retained Kali archive as the default to compensate.

The reached feasibility conclusion is positive for the tested pinned
ordinary-map Ubuntu payload and Mac image bundle. Their actual backends agree
with the corresponding existing-path observations at the recorded scope.
Native failed/cancelled preparation preserved external targets and usable guests.
The distinct published/specimen imports completed in execution 18428. Its
private-access observer failed before runtime because the dropped identity
could not execute `id` through the private host PATH. Correcting that observer
and resuming the retained imports supplies the remaining native witness;
no ordinary journey or successful import needs replay. Complete issue
acceptance and the final independent go/no-go remain pending. Production
integration belongs to #1554 and is not implemented here.

Lens accepted criteria 1/2/5 in comment 6892180913. Criteria 3/4/6/7 remain
unchecked until Lens judges the coherent result. Full Lens check
`work-5034ffe2c9004d5a9a63ad2383c0ec33@3` and all 16 evidence references were
consumed, including its complete prior lineage and repaired F1. The M / High
estimate and already reached cumulative 60-minute reassessment carry; there is
no fresh allowance. Missing Mac tools and pre-existing unsupported runtime
metadata effects require honest characterization, not another implementation.

At the executed source `5aeb1f51`, hosted Lint, Test CLI, Analyze, Blackbox
assurance and CodeQL 132767789334 pass; Test Addons 132767577475 was still running
at collection. Proxy assurance 43699588728/job 132767576998 fails and remains
unwaived, as did prior source-data drift. This result's final report needs its
own exact-head checks; prior passes do not establish a new pass. Local CodeQL
is unsupported on Linux aarch64. Configured Ruff, full pre-commit and existing
graph source-hash assertions passed. The 23 affected local controls passed:
16 Ubuntu observer cases and 7 Mac cases, including real failed/cancelled
extraction with external preservation. These controls do not substitute for
the native operations. Focused complexity findings in the experimental drivers
cover the added bounded mapping/guest/preservation branches; no new production
abstraction or dependency was introduced. Relay owns CI and integration.
No merge approval or additional criterion acceptance is asserted.

### Remaining distinct-map witness

Sylab executes this operation as ordinary UID/GID 1000 on the retained native
Ubuntu host. The published archive, compatible `b6821094` installation and
existing namespace entry are the operands already described above. Native
prerequisite execution 18426 added UID base 231072 and GID base 296608, each
with 65536 IDs. Original delegations and the prepared installation's config
were preserved. The exact 1806-byte prerequisite receipt has SHA-256
`44d56fdecd5b1a2ce43f57488c50aaf0fb0e917d6e435cddbaa6ec1f2f00f7ca`.

The initial exact command was:

```sh
/usr/bin/python3 experiments/rootless_guest/ubuntu_runtime_probe.py \
  /home/agent/r1553g9 --distinct-maps
```

Execution 18428 completed both imports, then failed before the first private
access observation and before runtime startup. Preserve its original six files
under `/evidence/operator/1553/g9-5aeb-runtime-18428/` and the ordinary mirror
`/home/agent/acceptance/1553-operator-receipts/g9-5aeb-runtime-18428/`.
The original result is SHA-256
`9de27a4ec5463a8103d2ac641e9521f98ed29f697e29f26e7c877212a6deeb65`.
The importer source remains `5aeb1f51`.

The reached published stage is
`/home/agent/r1553g9/published/extract-ojthe36y`; the specimen is
`/home/agent/r1553g9/specimen/extract-ykf3jnwx`. Numeric owners are correct:
root 231072:296608, guest 1000 mapped to 1000:1000, daemon 231105:296641 and
boundary 296607:362143. Both private parent and stage remain 1000:1000/0700.
The failed observation's shell could execute after `setpriv`, but its bare
`id` commands resolved through the private command directory and returned
Permission denied. This is an observation failure, not an isolation verdict.
Use absolute `/usr/bin/id`; do not broaden traversal permissions or the PATH.

Sylab resumes only the remaining observation/runtime in a new absent output:

```sh
/usr/bin/python3 experiments/rootless_guest/ubuntu_runtime_probe.py \
  /home/agent/r1553g9resume --resume-distinct /home/agent/r1553g9
```

This reads both retained `preparation.json` files and the original result.
It creates a new owned runtime/report and never invokes extraction or the
specimen producer. The original output and imports remain unchanged. The
resumption input must be the selected pre-runtime failure; the probe refuses a
record that already contains a guest/runtime identity. Cleanup stops only the
new owned agent, proxy and Coord. Return its original `result.json`,
`prepare.log` and caller output, preserving the initial failure/source binding.
The current backing filesystem must have at least 5435817984 bytes free:
the 5 GiB floor plus 64 MiB for the runtime, against prior observed 24,436,736-byte
growth. No second 429 MB import or copy is needed. The initial operation ended
with 5,545,783,296 bytes free. Refresh actual capacity before effects; do not
remove protected inputs to meet the forecast.

The initial probe imported one published tree and the existing small canonical
specimen with those distinct bases; resumption reuses them. It changes only its disposable instance's
mapping. The original `b6821094` config, existing imports and baseline remain
unchanged. It checks host owners for root, 1000, 33 and 65535; private staging
stays operator-owned 0700. Mapped identities 33 and 65535 must be unable to
traverse that private host parent. Explicit runtime mounting must still allow
guest root/1000 read/write/execute and other/boundary identity execution and
writes, with the expected distinct host owners. Host UID/GID zero remains
outside both import and runtime mappings. The existing finally block stops
only its owned agent, proxy and Coord and retains failures and exact births.

The initial import allowance was 576 MiB above the 5 GiB floor: 512 MiB for the
429,073,907-byte published payload, filesystem overhead and tiny specimen,
plus 64 MiB for the runtime whose preceding observed growth was 24,436,736
bytes. Check current backing capacity before effects; do not reuse the older
640 MiB cancellation forecast or discard active inputs. Return original
`result.json`, `prepare.log`, and both import `preparation.json` files through
the existing readable handoff. Keep credentials and the private instance remote.
A failure is retained for interpretation, not automatically retried.

### Native Mac baseline and preservation comparison

The recorded operation ran as Bristol UID 502 from the staged source root,
after inspecting current VM consumers. It used the unchanged `c6dd3b8b` helper,
original baseline Kali images, the existing wrapper and a fresh sparse overlay.
The original output must be inspected rather than overwritten or replayed:

```sh
/opt/homebrew/bin/python3 experiments/rootless_guest/macos_runtime_probe.py \
  /Users/sy-agent/f1553-20261115/runtime-g9 --baseline-preservation
```

This selects the existing baseline image paths for an actual Linux metadata
comparison with the retained candidate `6ebd2f96` result. The guest pauses
before its required root/user-1000 usability check. During that pause, the host
runs two tiny synthetic image-bundle preparations: a selected external symlink
fails regular-file validation; the other requests cancellation after extraction
children finish. Both must remove their private stage and preserve the external
target's bytes, owner, mode and inode. These are after-extraction cleanup cases,
not proof of cancellation during live tar. The same VM must then pass its
identity/read/write/execute checks. No published image is extracted or copied,
and no package, helper, host policy or privilege changes are made. Missing
Linux tools and unsupported capability effects remain recorded limitations.

The existing 384 MiB allowance covers the 256 MiB sparse overlay and small
assets above the 20 GiB operator-home reserve. Retain `result.json`,
`preservation.json`, guest/helper/serial output and exact owned teardown.
The prior candidate metadata prefix is unchanged apart from the optional wait;
its original source, result and accepted usability proof remain authoritative
at their actual revision. Reassess at the next native result or exact missing
operand and consolidate the final go/no-go, rather than adding another proof
framework or repeating accepted observations.


The selected native baseline operation completed on 15 November 2026 from
09:30:45.867 to 09:30:58.554 UTC, source `5aeb1f51`, UID 502/GID 20.
[`macos-observed.json::baseline_preservation_witness`](macos-observed.json)
retains the original result/logs, post-shutdown marker/image reads and comparison.
The actual runtime selected `h1552/share-kali-failed-1050`, not the candidate
path. Both sets of three image hashes matched before and after the operation.
No complete guest image was copied or extracted.

All 27 comparable guest observation sections match the retained candidate:
numeric published/fixture metadata, links, sparse tail, each command's exit,
missing-tool and unsupported-capability errors, and private/set-ID effects for
1000/33/65535. Comparison excludes inode numbers, process-specific status
fields, new specimen timestamps and directory enumeration order. The transient
mount listing is retained but not counted as a matching section. ACL/xattr tool
absence and setcap failure agree in both paths; their causes remain unproved.

During the guest pause, both tiny preparations exited 1, removed their private
stages and preserved the external target. Their original errors distinguish
regular-file validation failure from requested cancellation after child
completion. The same VM then passed required root/user 1000 R/W/X. Four host
markers have the expected contents, owner 502:20 and modes 0644/0755 under 0700.
Wrapper 93645 and helper 93646 births are retained; wrapper 143 followed the
helper's five-second grace/forced stop. Final enumeration is empty, owned
survivors are empty and held #500 births are unchanged. Endpoint free space was
22,928,183,296 then 22,919,311,360 bytes; overlay allocation was 1,052,672 bytes.
These results supply the new Mac comparison/preservation evidence for Lens;
they do not independently mark a criterion accepted.


## Output retention

The Bristol 1553 characterized Kali stage occupies about 2.35 GB. It supplied
the completed Kali runtime and remains an input to its exact review. It is not
the default guest. `/Users/sy-agent/f1553-20261115/runtime-g8` contains small
reproducible guest assets, a sparse overlay and compact original results.
`/Users/sy-agent/f1553-20261115/g8-source` is the small source packet.
No runtime remains active. These output groups become disposable after their
reviewers stop reading; retain the source, compact results and input identities
under the existing policy. The new `runtime-g9` and `g9-source` groups have the same small reproducible
role; their original compact results are retained in `macos-observed.json`.
No VM remains. The local `/home/agent/1553-macos-g9-results` and
`/home/agent/1553-macos-g8-results` originals
and `/home/agent/1553-macos-pytest` controls are also small reproducible groups.
Local supplementary archives,
`/home/agent/1553-pytest`, and successful duplicate fixture attempts are
reproducible disposable outputs. The source and this compact external-platform
result remain review inputs. No additional queue, proof service or guest image
is introduced.
The native `/home/agent/1553-native-import-b` group contains one reproducible
imported tree, two tiny specimens and compact results. Its tree supplied the
completed ordinary-map runtime. `/home/agent/r1553a` contains small disposable
instance state, copied NATS bytes, workspace markers and compact results;
no second guest image was created. Local `/home/agent/1553-runtime-pytest`
contains disposable observer controls. Retain source, results and input
identities under the existing storage policy; Sylab owns output retirement.
The actual `/home/agent/1553-native-metadata-g5` group contains small native
specimens, candidate imports and privileged baseline stages. Its current consumer
is interpretation/review of 18414; retain these operands for any selected isolated
backend comparison. The original records and manifest are retained under
`/evidence/operator/1553/metadata-18414`; no new guest image was created. Local
`/home/agent/1553-metadata-pytest` contains disposable observer controls. Keep
the original M / High estimate and reached cumulative 60-minute reassessment;
select only a decision-changing remaining operation before further execution.
