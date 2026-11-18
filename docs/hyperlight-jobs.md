# Hyperlight jobs

Use core Hyperlight for a purpose-built Rust guest. Use Hyperlight-Unikraft for
a Python checker that fits its Linux compatibility subset. Both use the
[existing job command](operator-guide.md#run-a-disposable-sandbox-job), trusted
job definitions and captured-stream evidence. Engine selection does not grant
service or network access.

For the installed GitHub-author/factory and generated-artifact examples, use
the [job-authoring walkthrough](../cli/src/safeyolo/agent_context/skills/job-authoring/references/walkthrough.md).
The [engine-selection guide](../cli/src/safeyolo/agent_context/skills/job-authoring/references/engines.md)
compares these runtimes with existing gVisor/VZ jobs and states measurement limits.

## Install and select a runtime

Use the [normal published-package installation](installation.md).
The production host-package workflow builds and bundles the matching Hyperlight
helper, core guest, Unikraft Python runtime, examples and license notices.
Installation puts them in the selected instance's `assets/hyperlight`; it needs
no source checkout, Rust, LLVM or upstream runtime build tools. Installing the
bundle does not adopt policy or grant service access.

For execution, select an existing SafeYolo instance with `--root`. Linux needs
accessible Kernel-based Virtual Machine (KVM). Apple-silicon macOS needs
Hypervisor.framework (HVF) support and the signed helper. A macOS VM without
nested hypervisor support can build the
bundle but cannot run these jobs.

The commands below assume the instance is `$HOME/.safeyolo`. For another
instance, replace that path throughout. With
`/absolute/path/to/input/request.json` containing the selected input, validate
and run the installed core definition:

```sh
safeyolo --root "$HOME/.safeyolo" job validate "$HOME/.safeyolo/assets/hyperlight/hyperlight.json"
safeyolo --root "$HOME/.safeyolo" job run "$HOME/.safeyolo/assets/hyperlight/hyperlight.json" --input /absolute/path/to/input
```

The example's decoded stdout is `{"input_bytes":N}`, where `N` is the byte
length of `request.json`. The command prints the complete execution result as
JSON, with bounded retained output encoded in Base64. Use
`hyperlight-unikraft.json` to run the equivalent Python workload. These examples
measure a small offline workload; they are not authoritative policy predicates.

For either Hyperlight engine, append `--console-file /absolute/path/to/new.console`
to `job run` to observe stdout while that invocation runs. The command creates
the file with mode 0600 and refuses an existing path. It copies at most
`retain_bytes` into that file; the final JSON result still includes the output
count, digest and retained bytes. Console text comes from the guest. It does not
establish authority or successful execution. A diagnostic workload can emit an
entry marker so a caller can select cancellation after that workload begins,
instead of assuming entry after a fixed delay.

The bundle also includes `hyperlight-service.json`,
`hyperlight-unikraft-service.json` and `service_checker.py`. These use the same
bounded GitHub issue-author predicate in the core `ServiceCheck` function and
Python guest. The selected instance must grant `github` to
`gate:hyperlight-service-check`. Supply this shape in `request.json`, replacing
the repository, issue number and expected stable GitHub user ID:

```json
{"subject":{"kind":"value","value":"1550"},"inputs":{"repository":"craigbalding/safeyolo","expected_author_id":"12345"}}
```

The checkers fetch the exact issue through the mediated service, read the full
bounded capture and compare `user.id`. An author mismatch or a pull-request
record returned by the issues endpoint produces a negative
typed finding. A denied call, oversized response, incomplete JSON or mismatched
issue identity fails execution. The host retains the capture digest and actual
upstream metadata; the checker supplies no identity or observation timestamp.
These job definitions are examples. Adopting a named check also fixes its inputs
and expected author in the host policy; invocation supplies only its subject.

The package also includes `hyperlight-artifact.json`,
`hyperlight-unikraft-artifact.json` and `artifact_checker.py`. These check the
small JSON output retained by native Work against the adopted `expected_status`.
The walkthrough binds that predicate to output acceptance automatically.

For integrated runtime verification, `tests/blackbox/host/hyperlight_services.py`
drives both engines with matching candidate binaries and a bundle built for the
selected host. Its `--help` lists the required existing GitHub credential and
owned instance paths. It changes only that disposable instance's test grants
and retains private results before assertions. It needs real KVM or HVF;
source tests and bundle preparation do not establish VM behavior.
After a partial Unikraft warm run, `--unikraft-remaining-only` selects spin
cancellation and recovery, concurrent calls, changed-artifact refusal,
corrupt-template fallback and held-call lifetimes. It first constructs and
restores one template in the new disposable instance. It skips Core, the
Unikraft cold comparison, failed predecessor and completed spin deadline case.
To exercise the remaining authority, retention and comparison boundaries, use
`--template-boundaries-only` with the same prerequisites. Run it separately on
each selected KVM or HVF host. It uses the installed diagnostic workloads and
the loopback provider; it makes no GitHub request. Keep the supplied credential
input private as required by the existing instance setup.

This mode compares identical input, principal, artifact pins and limits for
construction, restore and explicit cold execution. It records full command
latency, the existing stage reports, zero offline provider latency, sampled
CLI/helper/proxy resident memory and idle proxy memory after reaping. Record
the installed build profile alongside the run. Sampling can miss short peaks;
summed resident memory counts shared pages more than once and excludes the
file page cache. Process sampling adds observation overhead to the comparison.

Five additional memory layouts exercise the four-entry and one-GiB cache
limits. The driver expires one owned receipt and checks reconstruction. It
also checks normal shutdown removal. The service probe shares one template
across principals and policy changes, including overlapping work, a cancelled
predecessor, a foreign capture handle and removal of a service grant. This mode
skips the completed offline predecessor, corruption and held-lifetime matrices.
These selected controls do not establish initialization/load/restore phase
interruption or complete issue acceptance.

Discovery checks the selected artifact digests, host architecture, runtime
versions and hypervisor availability. A missing device, entitlement, artifact
or incompatible guest fails explicitly. Guest ABI validation also occurs in
the Hyperlight loader. No path silently selects a different engine.

The engine-selection guide records the support matrix and retained installed
execution evidence. Both engines have runtime proof on Linux x86_64/KVM and
physical Apple-silicon macOS/HVF. Linux aarch64 remains a build target with
unqualified runtime execution. Building a bundle or passing discovery does not
establish execution on another platform.

## Inspect and upgrade the installed bundle

The installed `package-info` identifies the source commit, platform and build
profile. `SHA256SUMS` covers the packaged Hyperlight files and examples.
`runtime.json` records protocol 4, the host architecture, Hyperlight 0.19.0 guest ABI,
Unikraft integration 0.21.0, embedded kernel contract, runtime source and helper
and Python runtime digests. Example definitions pin that manifest and their
checker/guest bytes. A release tag is never resolved during execution.

On the selected owning host:

```sh
cat "$HOME/.safeyolo/package-info"
cat "$HOME/.safeyolo/assets/hyperlight/runtime.json"
safeyolo --root "$HOME/.safeyolo" upgrade status
```

Use the [existing host upgrade](installation.md#upgrade-host-and-guest-components)
to acquire a compatible published package. Acquisition and verification finish
before selection; failure leaves the selected installation usable. After upgrade,
repeat this readback and validate both installed examples. The new examples may
select different pinned bytes. Adopted checks keep their own pins: the installed
preparation helper copies the selected bundle into `candidate/bundle`. Keep that
directory at its adopted path. Upgrading the host neither replaces this copy nor
reapproves a checker. Changes require an explicit proposal and owner adoption
through the walkthrough.

| Failure | Next action |
|---|---|
| Missing bundle, manifest, checker or helper | Check the instance path and install or upgrade to its matching complete host package. Do not mix files from different packages. |
| Digest, runtime/ABI or architecture mismatch | Restore the selected package's exact bytes or explicitly adopt a matching bundle for this host. Do not repin a changed file merely to pass validation. |
| KVM unavailable | Check access to `/dev/kvm` on the Linux host; gVisor alone does not supply KVM. |
| HVF unavailable or helper lacks its entitlement | Use a capable Apple-silicon host and its packaged signed helper; a Mac VM may lack nested virtualization. |

## Contributor bundle builds

Contributors building new runtime/checker bytes need a SafeYolo source checkout,
Rust 1.94, Clang/LLVM, Python 3.12 or newer, curl and cargo-hyperlight 0.1.15.
Build on Linux x86_64/aarch64 or Apple-silicon macOS as an ordinary user.
From the checkout root, with those tools on `PATH`:

```sh
python3 scripts/build_hyperlight_jobs.py --output /absolute/path/to/new-job-bundle
```

The builder downloads hash-locked Rust dependencies and a pinned Python runtime
layer from GitHub Container Registry. It creates the new output directory and
keeps reusable Cargo targets under `jobs/`. On macOS it signs the helper with
the Hypervisor.framework entitlement. It changes no installed instance or policy.
The host-package producer supplies this bundle through its existing
`--hyperlight-artifacts DIRECTORY` input. Relative artifact paths follow the
trusted definition, so copying the complete bundle preserves its bindings.

## Execution semantics

| Property | Core Hyperlight | Hyperlight-Unikraft |
|---|---|---|
| Guest entry | Named ABI function receiving `argv` as a JSON string | Pinned Python script with `sys.argv` |
| Selected inputs | `ReadInput(relative_path)` beneath a read-only capability | Read-only `/input` mount |
| Mutable state | Fresh guest memory | Fresh writable RAM filesystem and `/work` |
| Process model | No Unix process, PID, fork or guest-root authority | Single-vCPU cooperative Unikraft; `vfork`/PIE execution is a subset, `fork` is unsupported |
| Privilege | No Unix privilege model | Guest user IDs do not supply full Linux privilege semantics |
| Networking | No guest sockets; optional mediated service host call | Host-socket passthrough is disabled; the same optional mediated service host call |
| Memory | `memory_mb` selects scratch size | `memory_mb` selects scratch size |
| Cancellation | Kill the owning helper process group, then reap the helper | Same |
| State reuse | Clean initialized snapshots; fresh helper and sandbox per call | Clean initialized interpreter snapshots; fresh helper, mounts and sandbox per call |

Both engines reject `network=true` and `privilege=guest-root`. Core is not an
ordinary Linux executable environment. Unikraft does not implement every Linux
system call, signal, resource limit or Python extension. Neither scratch size
is a total host-process resident-memory limit. Use the existing gVisor/VZ
engine when the job requires those Unix or operating-system guarantees.

Each invocation copies and verifies adopted runtime/checker artifacts into
private transient storage. The helper inherits no provider credentials or host
environment. The guest receives only its artifact and selected inputs. Job
invocation data cannot change the adopted engine or nominate host mounts.
The execution deadline covers artifact preparation, VM startup and execution.
Bounded input copying happens first. Cleanup failures and incomplete observation
cannot report successful completion. No successful result is returned before
the helper has exited and the transient directory has been removed.

The helper also enforces the same monotonic deadline in an independent thread.
It exits without waiting for a guest callback when the deadline expires or its
caller disappears. An abrupt caller death can leave transient files for host
cleanup; it does not authorize continued guest execution.

## Interpret results

`engine` identifies the backend. With Hyperlight, `outcome_source=host_helper`
means an exit or signal in `outcome` is an OS observation of the helper.
`outcome_source=host_watchdog` identifies a deadline or cancellation decision.
`helper_process_status` retains the actual OS wait status after termination,
or is null if no helper started. `runtime_report` separately
records the library's VM completion or error. A guest function return or
guest-reported status is not promoted into an OS process exit or signal.
The typed check evaluator still validates the output's declared predicate;
text such as `PASS` cannot establish acceptance by itself.

The host hashes and counts every captured helper-stream byte, while retaining
at most `retain_bytes` per stream. Core's text ABI emits UTF-8. The upstream
Unikraft console decodes invalid UTF-8 with replacement before forwarding it;
`console_encoding` names that representation. Its counts and hashes cover the
forwarded bytes, not an assertion about original binary guest writes.

Measure full command latency and peak memory on the actual host. Separate
input preparation, artifact copying, template construction/save, load/restore,
payload execution and provider latency. Compare equivalent workloads on the
same host with the same authority and output retention. There is no universal
performance advantage. Prior cold measurements do not measure restoration.

## Reuse initialized workloads

Both Hyperlight engines default to `reuse_initialization=true` in the selected
`engine` object. The first call constructs a clean template and restores a new
sandbox from that initialization. Later calls load its verified snapshot and
restore another sandbox. Every call uses a new helper process. A completed,
failed or cancelled call is never the source of the next template.

Core freezes after the guest loader and `hyperlight_main` return. During that
phase, input, invocation context and service host calls return errors. Unikraft
freezes after its Python driver boots, imports the common standard-library
modules and prepares `/work`. It has no input/checker mounts or service callback
during construction. The checker script runs only after restoration. Template
construction never imports arbitrary checker code.

Each call attaches current input, identity, deadline and capability handles.
Unikraft refreshes its mounts, environment, clock and supported runtime random
generators on restore. `SY_INVOCATION_ID` and `SY_DEADLINE_MONOTONIC_MS` identify
the current call. Core's `InvocationContext()` host function returns the current
invocation ID, Unix time in milliseconds, deadline and 32 fresh random bytes.
Code that keeps a private generator or startup-time value in its own initialized
state must refresh that state from current context before use. The bundled core
checker retains no such generator. Python's custom generators and startup hash
seeds are not reseeded by this integration; construct invocation generators after
restore. The template contains no invocation credentials or usable delegation.

Template identity binds the selected runtime manifest, helper/kernel/runtime,
checker or guest digest, architecture and effective memory/transport layout.
The helper's digest binds its initialization code and configuration. Templates
are local to one host boot. The supported loader checks compatibility and all
snapshot blob digests against the retained manifest digest. Artifact verification
still runs for each call. Current policy is checked separately: changing a
principal or service grant does not itself change initialized bytes or preserve
the previous call's authority.

The private instance directory `data/hyperlight-templates` retains at most 4
idle templates within a 1 GiB byte budget. Selection removes entries older than
60 minutes and evicts older unused entries when capacity is needed. Expiration
is checked on cache access; no idle worker runs a timer. Reader leases protect
mapped blobs until their helper exits. Normal proxy shutdown removes idle
entries after check tasks drain. An independent CLI call that still holds a
reader lease keeps its files until a later access or shutdown can remove them.
No VM, interpreter, callback or delegated handle remains idle in the cache.
The operating system can retain file pages in its own page cache.
After saving a new snapshot, admission uses its measured size. The helper
evicts idle entries until the new snapshot fits. Active reader leases remain
protected. If the snapshot exceeds the whole budget, or active readers prevent
admission, the current call uses its initialized snapshot without retaining it.

`runtime_report.initialization` reports `constructed`, `restored` or `cold`, the
template key and snapshot digest, an explicit cold reason, and stage times in
milliseconds. A missing template is constructed. A busy cache, invalid or
incompatible template, or unavailable cache causes explicit cold execution of
the same engine. An oversized initialized template is used for the current
call without retention. No path changes engines or selects older approved code.
The existing deadline/watchdog covers construction, loading, resume, guest code
and host callbacks. `helper_max_rss_bytes` reports one helper's peak resident
memory; it excludes the CLI, proxy and file page cache.

To compare a cold call, set `"reuse_initialization": false` in a copy of the
same trusted job's `engine` object. Keep its artifact pins, input and limits
unchanged. The disabled option changes initialization reuse, not policy access.
The installed core `TemplateProbe` function and `template_probe.py` expose a
construction witness, per-call state, input and fresh context. They are
diagnostics, not adopted policy predicates.

On an owned Linux x86_64/KVM or physical Apple-silicon/HVF host, the existing
two-engine driver accepts `--warm-templates-only` with its normal prerequisites.
On a confined host, select authorized `--admin-port` and `--provider-port`
values and preserve its existing parent-proxy route.
That mode records cold and restored observations, corrupt-template fallback,
concurrent/failing predecessors and the existing held-call lifetime controls.
Its complete command interval starts at process launch and ends after reaping;
fixture input/spec preparation is outside that interval. The offline comparison
has no provider latency. Service evidence retains separate request spans.
Installed warm measurements and independent acceptance must identify the actual
runtime artifacts and build profile; source tests alone establish neither.

## Mediated service access

In a trusted Hyperlight job definition, keep `network=false` and add the
following field to select a bearer-authenticated Service Gateway service.
The selected instance must already grant that service to `gate:<gate_id>`.
This example permits up to four calls and retains at most 1 MiB per response:

```json
"mediated_services": {
  "services": ["github"],
  "max_calls": 4,
  "max_request_bytes": 49152,
  "max_response_bytes": 1048576
}
```

The guest supplies a named service, HTTP method and URL. The host supplies the
scoped gateway token and sends the request through the existing delegated
proxy listener. Destination, credential, operation, repository and dependency
policy still apply. The bridge does not follow redirects or retry requests.
The guest receives no gateway token, provider credential, proxy socket or host
path. This profile provides mediated service access. It does not support
arbitrary socket clients, guest DNS, CONNECT tunnels or Unikraft host sockets.

For core guests, import the supported Hyperlight host function:

```rust
#[hyperlight_guest_bin::host_function("SYCall")]
fn sy_call(request: alloc::string::String) -> hyperlight_guest_bin::error::Result<alloc::string::String>;
```

The argument and returned string contain JSON. In a Unikraft Python guest,
call `hyperlight.call("sy.call", request)` with a Python dictionary. The
registered embedding function returns the equivalent decoded JSON object.
Both use this logical request:

```json
{"kind":"service","service":"github","method":"GET","url":"https://api.github.com/repos/OWNER/REPOSITORY/issues/123"}
```

Replace the repository and issue with a target allowed by the standing grant.
An optional `body_base64` supplies bounded request bytes. A successful reply
contains `ok=true` and a `value` with `id`, `status`, `bytes` and `sha256`.
Failures contain `ok=false` and `error`. Responses stay in the host capture;
read the complete response with requests of this form:

```json
{"kind":"read","id":"RETURNED_ID","offset":0,"length":16384}
```

Each successful read returns `data_base64` and `total_bytes` under `value`.
Advance the byte offset until all bytes have been read. The guest must parse
the complete evidence before evaluating its predicate. Each invocation permits
one call in flight. The adopted call count and response limits bound retained
evidence. Messages larger than 48 KiB and reads larger than 16 KiB fail
explicitly. An oversized response is unavailable evidence; no truncated JSON
is returned as a successful capture.

The invocation deadline covers calls. Cancellation, an active proxy
configuration or policy replacement, shutdown and delegation loss close the
delegated connections and stop the owning helper. A completion from the old
delegation cannot restore authority. Effectful calls have no automatic retry.
Their `effect_outcome` distinguishes an unsent request, an uncertain effect
after sending, and an observed response. An observed response alone does not
prove that a remote effect completed.

The host's `service_evidence` records exact request/response bytes, digests,
request start, HTTP status, policy refusal, observation times, active policy
hash and serialized effective proxy configuration digest. The outer job result
binds the stable principal, transient invocation, input and adopted
checker/runtime digests. ETag, Date and Last-Modified headers are retained when
present. ETag is an opaque provider revision, not a promise of an immutable
source. A response Date does not prove the age of the underlying data. Absent
metadata remains absent.

The host-only job command returns the full capture. For named checks, the
existing host audit retains the capture bytes. Agent invocation responses and
policy explanations contain capture metadata and digests. Invocation authority
alone does not disclose the check's raw dependency data to the calling workload.

For [named checks](policy-checks.md#execute-adopted-checks), the shared evaluator
validates the typed result and binds its provenance to the host capture.
Guest-supplied revisions or collection timestamps cannot replace those
observations. Execution completion and effect uncertainty remain separate from
the predicate finding. Workflow enforcement belongs to the binding that
consumes the result; running a job alone creates no required workflow gate.

See the pinned upstream [core guest ABI guide](https://github.com/hyperlight-dev/hyperlight/blob/a03088470d822b538d2525ef9a5ae9e29daea1e8/docs/how-to-build-a-hyperlight-guest-binary.md),
[execution model](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/execution.md)
and [Unikraft concurrency limits](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/concurrency.md).
