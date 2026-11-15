# Rootless published-guest preparation: current proof

This is the bounded feasibility work for [#1553](https://github.com/craigbalding/safeyolo/issues/1553).
The complete go/no-go result remains **unproved**. Native macOS extraction of
one published Kali image bundle passed. Native Ubuntu import and both backend
journeys remain to run. This candidate changes no production installer.
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
These controls do **not** prove native namespace entry, kernel metadata writes,
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

The next protected operation is the script below. On the existing native
Ubuntu host, Sylab stages `ubuntu_import_probe.sh` and `import_guest.py` from
the same immutable candidate in one source directory. Run as UID/GID 1000 from
that directory. The archive and inventory already exist at the shown paths;
the output directory must be absent. The script checks the selected hashes,
existing namespace entry and current capacity against the existing 5 GiB floor
plus its archive-based growth forecast before extracting anything.

```sh
bash ubuntu_import_probe.sh \
  /home/agent/1436-operator/guest-store/blobs/sha256/1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe \
  /home/agent/1553-native-first-a/archive-inventory.json \
  /home/agent/1553-native-import-b
```

Expected observations are a fresh published import, an operator-owned readable
cache list, and a namespace comparison of all rootfs header types, owners,
modes, regular-file sizes and links. Two small specimens then test a missing
cache and explicit cancellation, stage removal and external-target preservation.
The candidate PATH has no sudo. Only the successful new stage remains for a
later backend operation; there is no backend, download, host setup, policy
change or different delegated range in this packet. Preserve each original
failure and inspect partial output before any retry. The packet has passed
Bash syntax and both embedded Python compilation checks; native execution is
still pending.

Return `result.json`, `published-metadata.json`, each `preparation.json`, and
the corresponding stdout/stderr through the existing readable operator handoff.
An import failure must retain its original logs even if no preparation report
was created. Ordinary owner-home paths were unreadable to Lens on output 1;
source controls and owner logs alone do not supply native proof.

1. Run `python3 experiments/rootless_guest/inspect_host.py --root PREPARED_ROOT`.
   Record the current package, selected guest, delegated ranges, namespace entry,
   tools, filesystem and capacity. The root is a separately owned prepared
   installation; do not mutate another active instance.
2. Use the maintained acquisition consumer to pin and verify a compatible
   published archive. Run `import_guest.py inventory --archive ARCHIVE --sha256
   DIGEST` and save its complete output. Inspect **all** selected rootfs header
   owners, top-level cache-file owners, xattrs, capabilities, ACLs and special
   files before interpreting a prototype failure.
3. On Ubuntu, prepare the issue's permitted host prerequisites separately.
   Reuse the existing namespace-entry/AppArmor mechanism. Record its effective
   entry and delegated UID/GID ranges; do not weaken global policy. A second
   mapping needs genuinely delegated, different nondefault UID/GID bases.
4. With sudo unavailable to the candidate, run `import_guest.py prepare
   --platform linux --archive ARCHIVE --sha256 DIGEST --host-root PREPARED_ROOT
   --uid-base UID_BASE --gid-base GID_BASE --output NEW_ATTEMPT` for each mapping.
   The prototype records namespace maps and the retained stage. Compare with
   the separately recorded existing privileged extraction/remapping baseline.
   Baseline or prerequisite privilege is not a rootless pass.
5. Create the supplementary specimens with `make_fixture.py --output
   NEW_FIXTURE_DIRECTORY`. Its JSON output supplies each path and digest.
   Generate them on Ubuntu: the capability and set-ID specimens copy that host's
   `/bin/cat`, which must match the intended guest architecture.
   Import each specimen independently through the same prototype. Compare the
   matrix below with the existing path. Observe numeric host metadata, namespace
   metadata, contents and effective access. A failed unsupported specimen must
   remain a failed observation; do not strip it from a successful archive.
6. Exercise failed extraction and `--cancel-after-extract` in fresh attempts.
   Verify stage absence and the unchanged external target and existing usable
   guest. An incomplete/failed attempt must be inspected before any retry.
7. Follow every successful **published** preparation into the existing backend.
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
| Ordinary/private files, directories, executable and set-ID modes | `canonical`; exhaustive mapping controls. Mac outer files preserved modes and mapped 1000:1000 to 502:20. | Ubuntu host/runtime root, user 1000, another identity, boundary 65535; private staging and effective access. |
| Symbolic links and hardlinks | `canonical`, `escaping-link`; local external target and existing directory survived. | Native link identity/confinement and existing **usable** guest preservation. |
| Sparse files | `canonical` GNU 1.0 map/content control; real Mac image remained sparse. | Ubuntu allocation relative to baseline and image/VM contents. |
| First in, first out (FIFO), character and block nodes | FIFO in `canonical`; `devices` contains character 1:3 and block 7:0. Archive headers only. | Actual published inventory, kernel privilege outcome and runtime requirement; do not assume mknod works in a user namespace. |
| Extended attributes (xattrs) and capabilities | `canonical` has `user.*` and revision-3 (V3) capabilities rooted at 100000; revision-2 (V2) is separate in `v2-capability`. | V2/V3 root identity and capability effect in the intended runtime versus the existing path; other namespaces actually published. |
| Access/default access control lists (ACLs) | Canonical principals/mask in `canonical`; out-of-range 42 in `raw-acl42` separately. | Host/runtime principals, masks and effective access. Raw 42 is characterization, not a host-ID passthrough requirement. |

The actual Linux cache list uses build-account coordinates; the split extraction
above removes that incidental owner from the namespace requirement. Native
import remains pending. V2 capability root identity also needs observation:
import root and runtime root intentionally have different mappings. No new
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
namespace. A distinct nondefault mapping and actual import remain unproved.

The actual `compat-v1` discovery tag was resolved on15November to that same
`67bcb6c5...` default index. The public index bytes are retained locally at
`/home/agent/1553-native-inputs/default-index.json`. The darwin/arm64 manifest is
`sha256:25a17227648078261bc331f751e5e11a33d4525cdaabeb9d3f64a0faec6c8ea1`.
Fetching that immutable manifest returned HTTP428 through the proxy. Its error
body/header were not retained, so no approval state or refusal cause is claimed.
No identical request was retried. Effective network lookup allows `ghcr.io`;
that does not grant credential or route access. Sylab must inspect the original
private refusal at03:54UTC and effective access, or supply the verified default
input through the existing authorized acquisition route. Do not change package
metadata or classify the retained Kali archive as the default to compensate.

The selected continuation resolves only the current selected-member import
uncertainty. The original 60-minute reassessment has been reached; it is not
restarted. Resume on the same work/branch with the protected import result.
The original registry-refusal inspection remains separately pending and no
retry is selected. The existing namespace entry and selected Bristol slot need
no new permission or discovery; ordinary Bristol operations remain Forge-owned.
The full privileged-use witness, failure cleanup, metadata comparison and both
guest journeys remain unproved. No independent acceptance is claimed.

## Output retention

The Bristol 1553 characterized Kali stage occupies about 2.35 GB. It is a
reproducible comparison input, not the selected default-runtime operand.
Local supplementary archives,
`/home/agent/1553-pytest`, and successful duplicate fixture attempts are
reproducible disposable outputs. The source and this compact external-platform
result remain review inputs. No additional queue, proof service or guest image
is introduced.
The proposed native `/home/agent/1553-native-import-b` group contains one
reproducible imported tree, two tiny specimens and compact results. If execution
succeeds, the tree is an actual input for the remaining guest-startup step.
Retain original results and input identities under the existing storage policy.
