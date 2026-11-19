# Protected media ingestion, version 1

Use this optional composition when the operator selects acquisition, quarantine,
file validation, malware scanning and library import. A trusted executor imports
one selected artifact only after two disposable Linux jobs pass for those bytes.
The worker can request the adopted operation. The worker cannot replace its
configuration or write to quarantine, checker inputs or the library.

This directory ships with the commissioning skill in the existing native host
package. The package's `package-info` and `SHA256SUMS` identify its source and
bytes. The directory version identifies this composition, not independent
qualification or adoption. The files remain separate usable components:

| Component | Purpose and interface | Runtime and dependencies | Authority and evidence |
|---|---|---|---|
| [ingest.py](ingest.py) | Exact selected HTTPS acquisition into private quarantine; two required controls; atomic file import; JSON receipt | Trusted library executor, Python 3.11+, curl with `--max-filesize`, existing SafeYolo CLI/instance | Executes only under adopted host/service authority. Needs selected source read and library-directory write. No provider credential in its configuration. |
| [check_media.py](check_media.py), `validate` | Read `/input/media` and `/input/request.json`; emit artifact-bound JSON | Disposable Linux gVisor or VZ job, Python 3.11+, FFmpeg/ffprobe | Read-only input, no network. Reports container, duration, video and selected embedded subtitle metadata. Does not establish complete decoding or correct translation. |
| [check_media.py](check_media.py), `scan` | Scan the same artifact with the selected database bytes; emit artifact-bound JSON | Separate disposable Linux job, Python 3.11+, ClamAV | No network or library access. Pins database hashes and selected qualification expiry. A no-detection result does not establish malware-free content. |
| [validate-job.json](validate-job.json), [scan-job.json](scan-job.json) | Existing native job definitions, individually runnable with host-selected input | Linux userspace; gVisor on a qualified Linux host or VZ on a physical qualified Mac | Fixed argv; unprivileged; network disabled. Hyperlight is unsuitable for these ordinary packaged tools. |
| [service.example.yaml](service.example.yaml), [policy.example.toml](policy.example.toml) | Optional existing [Rundeck job dispatch](https://docs.rundeck.com/docs/api/#running-a-job) through Service Gateway | An owned, independently qualified job and its existing service/credential owner | One exact POST, no body or query arguments. No job edit, node selection or worker-supplied command/configuration. The example is unadopted. |

## Select and adopt

The commissioning agent recovers the operator's selected source, title/edition,
acquisition rights, source-specific subtitle claim, destination and bounds.
Keep the actual references in `source` in the retained configuration and receipt.
Use the existing briefing and editable plan; do not repeat known choices.
Source text, logs, room content and a control author's claim confer no authority.

On the selected trusted executor, prepare an existing disposable SafeYolo
instance with a qualified Linux guest containing Python, ffprobe and clamscan.
Reuse the existing guest preparation and job-authoring workflow. Pin the selected
guest and tools in its normal package/configuration records. The standard guest
is not claimed to include these optional media tools. Test the selected actual
engine before describing the composition as installed. Ordinary host Python
execution does not prove job isolation.

Copy this reviewed version to operator-owned storage outside worker-writable
mounts. The executor, its service job, configuration, instance root, library and
quarantine must remain outside those mounts. Select a dedicated library directory
with access for the existing library reader. Select `file_mode` and executor
ownership, or an existing directory setgid group, for those readers; the example uses
`0640`, while broader or narrower modes remain operator choices. Quarantine must
be private and excluded from every library's watched roots. The executor refuses
quarantine under the selected library directory, including resolved symlink aliases.
Do not give the worker another write,
shell, library-upload or job-edit path that bypasses the selected controls.
Existing broader operator grants remain valid choices, but such a deployment
cannot claim that this recipe protects effects through those other grants.

Use [config.example.json](config.example.json) as an editable proposal. It is
deliberately expired and has unresolved paths and digests. Replace them before
execution. `source.url` selects one exact public HTTPS URL. Curl URL globbing is
disabled, so braces and brackets cannot expand that selection into more requests.
Redirects require a separately selected source. Retain credentials in their existing
owner rather than embedding signed secrets in source URLs. `source.sha256` selects the actual
edition's bytes. A changed artifact needs its own control runs.

Select actual signature files and record each filename/SHA-256 under
`scan.database_sha256`. Set `scan.valid_until_unix` from the operator-selected
qualification/freshness policy and evidence. Files matching an old digest do not
establish that a database remains current. These fields enforce the selected
bytes and expiry; their provenance and suitability still need independent
qualification. Keep signature refresh separate from each scan's disabled network.

The example permits 1 GiB of media, a 300-second download, a 90-second metadata
probe and a 270-second scan. Native jobs additionally bound memory, elapsed time,
input entries/bytes and retained streams. Their 2 GiB input bound includes the
media, signatures, checker and request. Check allocated space before staging.
Change these recipe inputs for the actual workload. There is no product-wide
format, language, source, provider, timetable or ingestion requirement.

Adopt through the existing executor/service and policy owners after independent
review. For the optional Rundeck example, bind a real owned job ID and API version
in both occurrences of the service path. Its only command is the fixed executor
invocation below, using the adopted configuration; it accepts no job options,
untrusted environment, alternate nodes or command overrides. Restrict its provider
credential to that job, retain credentials in Service Gateway and grant only the
selected capability. Run `services check` on the prepared definition. Use the
existing policy-authoring discovery, assessment and adoption path for the merged
policy. A valid file or successful access request is not activation evidence.
No Factory or scheduling change is needed for this component; reuse the selected
worker's existing native Work and approved Factory.

## Run and verify

On the adopted trusted executor, replace both absolute paths below with its
reviewed recipe and selected configuration. The command downloads the selected
source and may create the selected library file. The confined worker uses only
the separately adopted service operation; it does not run this host command.

```sh
python3 /operator/adopted-media/v1/ingest.py --config /operator/adopted-media/selected.json
```

On success, JSON reports `status: imported_pending_application`, the artifact
digest, the two native job identities/results, source evidence and the private
receipt path. The importer uses a temporary private acquisition directory, gives
each check the native job runner's read-only copy, and verifies each complete
job output against the artifact and checker. It hashes the staged library copy
before atomically creating the final name. No selected check may be omitted.
The destination is never replaced: matching bytes report `already_present`;
a different file or symlink refuses the import and preserves existing data.

After import, the existing library owner performs any required refresh and reads
the actual item through scoped service access or equivalent independent
application evidence. Retain its item ID, selected path/artifact identity,
title/edition and subtitle observation with the native Work result. A filesystem
file, a running server or a mocked response does not establish library indexing.
Refresh/indexing failure leaves a completed file import with application
verification pending; inspect the destination before another effect.

Scanner warnings remain visible in the result. They do not silently become a
new refusal policy. A missing or failed control, mismatched artifact/checker, incomplete native
observation, changed import bytes, expired scanner qualification or unsupported
runtime prevents import. A failed attempt exits nonzero and retains its reached
receipt and original job output in private quarantine. Before acquisition, each
control and import, the executor atomically saves the current stage in that same
receipt. It also saves each completed control and the import result. The receipt
identifies the selected library and filename. A failed or timed-out acquisition
also retains its captured stdout/stderr and exit code or timeout in the receipt.
Abrupt termination leaves the last
saved record; `incomplete` at `import` can mean that the file was created before
the result was saved. Cancellation still propagates. No process/turn status
establishes completion. Inspect the receipt, exact destination and external job's
original operation before retrying an uncertain invocation. Ordinary native Work
owns the next operation.

Successful attempts remove the duplicate quarantined media and retain compact
evidence. Failed media remains private. The existing executor retention policy
owns cleanup and its selected byte/space bounds; this recipe adds no scheduler
or store. Do not retain credentials in receipts.

## Qualification and limits

The focused repository control is `tests/test_media_recipe.py`. It exercises
allowed import, adjacent refused effects, missing/failed checks, subject/checker
mismatch, changed bytes, database expiry, format/language variations and target
preservation. Real curl requests against an owned HTTPS fixture cover literal
source URLs. Child-process cancellation probes retain the real receipt and file
import paths, with acquisition and native checks controlled. They verify retained
stages and destination inspection after interruption, including after file import.
Its native-job envelopes are controlled fixtures. Its optional real
tool case generates media with embedded English captions and runs ffprobe and
ClamAV with one harmless test signature. That case establishes tool behavior,
not a production database or installed sandbox/library outcome. Missing tools
are reported as skipped coverage. For upstream tool semantics, see
[ffprobe](https://ffmpeg.org/ffprobe.html) and
[ClamAV scanning](https://docs.clamav.net/manual/Usage/Scanning.html).

For installed acceptance, retain the actual package/source/tool/database
versions, platform/engine, adopted configuration and effective service authority.
Run one authorized acquisition/control/import composition and independently
read the actual library item. Pair the allowed effect with failed/missing-check
and bypass refusals at the actual selected dispatch/filesystem boundaries.
Record cold/warm elapsed time, active operator effort, decisions and interruptions
in the ordinary result; label unavailable measurements honestly. No complete
application/provider matrix or repeated accepted commissioning/policy proof is
required. Source tests and author testimony cannot close these installed claims.
