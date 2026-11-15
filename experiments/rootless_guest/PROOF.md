# Rootless published-guest preparation: current proof

This is the bounded feasibility work for [#1553](https://github.com/craigbalding/safeyolo/issues/1553).
The complete go/no-go result remains **unproved**. Native macOS extraction of
one published Kali image bundle passed. Native Ubuntu import and systrap startup
passed with the ordinary mapping, including guest identity and read/write/execute.
The native supplementary canonical specimen matches the privileged baseline,
including kernel runtime-map access, ACL inheritance and capability effects.
The macOS backend journey remains unproved. This candidate changes no production
installer.
#1554 owns production integration; #1563 owns maintained blackbox coverage.

The trusted starting source is `6ee7e8bb308fcd865fa0a244b455c7dcc86b9bb6`.
The assignment is [comment 6888425057](https://github.com/craigbalding/safeyolo/issues/1553#issuecomment-6888425057).
Keep all issue criteria unchecked until independent review accepts their proof.

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
`c6dd3b8bfef1a2e5f49e1fbc273c4b2ac2b46a52`; no runtime executable was exercised.

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
The account's confinement and policy were unchanged. No virtual machine (VM)
or model was started.
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

The 18 focused Linux-worker controls pass. They cover all 65536 canonical IDs
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

Expected result: 18 passed. This command starts no guest or namespace.

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

Fourteen focused observer controls pass, including real closed/listening sockets,
an unrelated listener, real live/stopped child processes, retained active state
and an unreadable listener table. The content controls remain included.
Run these controls from the task checkout using the locked development Python
environment and a disposable disk-backed pytest directory:

```sh
uv run --frozen pytest -q experiments/rootless_guest/test_ubuntu_runtime_probe.py --basetemp /disk/backed/1553-runtime-pytest
```

Expected result: 14 passed. No guest or namespace starts. The native result is
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

The prior 26 focused controls, configured Ruff, complexity checks and hooks
remain valid because this continuation changes only this report. The
worker controls used controlled xattr bytes and credential-drop calls; those
controls alone do not prove native enforcement. Lens's complete
output-5 check `work-aeac4cf2781840ff93efa43bee252df2@3`, all 16 evidence references
and its full prior checks carry forward. Its pending-native-comparison gap is
now supplied; its remaining limits and full-issue abstention persist.

The following steps describe remaining full-issue proof. Completed inventory,
import and ordinary-map startup observations carry forward. These steps do not
select their replay or another platform attempt.

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

For Bristol, the characterized Kali assets are retained at
`/Users/sy-agent/f1553-20261115/native/prepared/extract-kiyduh7b`.
The source prototype is retained beside `macos_prepare.py` under that 1553 parent.
Do not repeat its extraction for bookkeeping or call it the default guest.
The current default input must be bound before the next runtime attempt. Use
a fresh 1553 instance and the existing `/Users/sy-agent/bin/run-vz-test`.
Check current capacity first: preparation left 22,567,608,320 free bytes; the
operator-home reserve is 20 gibibytes (GiB). Record actual peak headroom for the
runtime. Preserve `/Users/sy-agent/s500d`, both held 1104 roots and unrelated processes.
No Bristol root, elevation, personal account or policy change is permitted.
The canonical readiness input found only ports 46372/46374 free. This does not
prove a port blocker: the helper's shell/control transport uses Unix sockets,
and the selected runtime/configuration must determine actual listener needs.

## Matrix and remaining interpretation

| Case | Specimen / reached observation | Native comparison still required |
| --- | --- | --- |
| Ordinary/private files, directories, executable and set-ID modes | Native canonical host/kernel observations match baseline, including IDs 33/65535, private access and set-ID execution. Mac outer modes/owners and Ubuntu ordinary-map root/user-1000 I/O passed. | Distinct delegated bases, applicable gVisor metadata/access/identity observations and full Mac runtime. |
| Symbolic links and hardlinks | `canonical`, `escaping-link`; local external target and existing directory survived. Native published link targets/hardlink inode matched. | Supplementary confinement and existing **usable** guest preservation. |
| Sparse files | Native canonical contents and 64 MiB logical/8 KiB allocation match baseline; real Mac image remained sparse. | Applicable image/VM contents. |
| First in, first out (FIFO), character and block nodes | Native FIFO matches baseline. Candidate device creation fails EPERM and cleans its stage; privileged baseline succeeds. Published Linux archive requires neither. | Applicable Linux special-file results inside the Mac image/VM. No arbitrary host mknod support is required. |
| Extended attributes (xattrs) and capabilities | Canonical user xattr/V3 roots and kernel execution masks match baseline. Separate synthetic V2 has different raw root, EOVERFLOW reads and capability effects. Published Ubuntu archive has no xattrs. | Applicable gVisor and Mac VM effects against existing behavior; no inferred arbitrary V2 support. |
| Access/default access control lists (ACLs) | Canonical host/runtime-map principals, masks, inheritance and actual access match baseline. Raw 42 fails ACL restoration despite import exit 0. | Applicable gVisor/Mac VM behavior. Raw 42 remains characterization, not a passthrough requirement. |

The actual Linux cache list uses build-account coordinates; the split extraction
above removes that incidental owner from the namespace requirement. Native
ordinary-map import passed. Canonical V3 preserves the correct runtime root;
the separate synthetic V2 difference is now observed. No new
delegated range or required arbitrary-archive compatibility is inferred.

The current Ubuntu reads are
`/evidence/operator/1553/native-preflight-18397.json` and
`/evidence/operator/1553/native-operands-18398.json`. They identify native
Ubuntu 24.04.4/x86_64/kernel 6.8.0-147/ext4, UID/GID 1000, GNU tar 1.35, the
delegated 100000:65536 UID/GID ranges and enabled AppArmor namespace restriction.
The queried old default root lacked `host/namespace-entry`. Its selected archive
`sha256:1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe`
was absent from that queried blob cache. Execution 18403 found and hash-verified
the same archive in the retained `1436-operator/guest-store` path. The index is
`sha256:67bcb6c51460619d3c021414961cd42b1f9751adc07f69d212a1d6485b1f132a`.
A single-ID direct `unshare -Ur` failure is readiness evidence only. The later
`/evidence/operator/1553/namespace-entry-18400.json` proves that the existing
entry under `/home/agent/1562-b682-installed` succeeds for a single-ID namespace.
Its SHA-256 is checked by the Ubuntu packet. No prerequisite is inferred from
the earlier absent path. Execution 18403 later established the normal multi-ID
namespace, followed by the successful 18405 import. A distinct nondefault
mapping remains unproved.

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

The reached reassessment supports ordinary-map Ubuntu rootless preparation and
kernel canonical-metadata parity. No canonical candidate regression is established
by the supplementary comparison. Full feasibility remains **unproved**;
production integration is not selected. Its smallest known implementation path
remains archive-coordinate namespace extraction plus separate ordinary host-cache
extraction, while preserving production's existing validation and confinement.
No new capability rewrite, arbitrary-device support or policy restriction is
justified by these observations.

Remaining inputs are genuinely delegated different nondefault UID/GID bases;
any necessary isolated gVisor baseline/candidate metadata/access comparison;
complete pinned macOS preparation/runtime with Linux metadata inside the VM;
and asynchronous cancellation with external-target/existing usable-guest
preservation. The native canonical stages and unchanged runtime supply operands
for a selected backend comparison; current equal delegations do not supply the
distinct-map operand. The original Mac registry disposition must be resolved
and effective access read before a future retry. These gaps require scoped
operations or changed inputs, not replay of the successful import or journey.
Sylab retains precisely identified protected operations; no new Craig input is
needed to interpret 18414. This continuation selects no further native effect.
M / High and the already reached cumulative 60-minute reassessment remain;
there is no fresh allowance. Full independent go/no-go and all seven criteria
remain open.
Lens's complete checks `work-02b994e476b24b1ab60d8a287a60b041@3` and
`work-ae9f361020754ce1ade43d65075f9f11@3` and `@5` retain prior controls and limits.
The complete output-3 rejection `work-6460c275ae88410a88b9afed14fc435b@3`
supplies F1 and carries those reviews forward. Its earlier pending-runtime
observation is superseded by the original 18413 receipts, not by a replay.

At `0aa7b825`, Lint, Test CLI, Test Addons, Analyze and Blackbox assurance pass.
Separate CodeQL check 132728825636/alert 567 and Proxy assurance workflow
43686729911/job 132728651745 fail and remain unwaived. The executed producer/caller
analysis supports a false-positive interpretation of the tuple assignment,
not a waived or passing check. The Proxy assurance artifact compares against
accepted source `8ba22365616d83b8b8b18b87781f0e9b9ad1e439` and reports 55 changed
mapped decisions and 10 stale symbols. This is unresolved drift, not an accepted
baseline update. Local CodeQL is unsupported on this Linux aarch64 worker.
This report-only correction does not claim its new hosted checks passed.
Relay owns CI and integration.
This candidate establishes no merge approval or issue acceptance.

## Output retention

The Bristol 1553 characterized Kali stage occupies about 2.35 GB. It is a
reproducible comparison input, not the selected default-runtime operand.
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
