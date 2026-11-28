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

For execution, select an existing SafeYOLO instance with `--instance-dir`. Linux needs
accessible Kernel-based Virtual Machine (KVM). Apple-silicon macOS needs
Hypervisor.framework (HVF) support and the signed helper. A macOS VM without
nested hypervisor support can build the
bundle but cannot run these jobs.

The commands below assume the instance is `$HOME/.safeyolo`. For another
instance, replace that path throughout. With
`/absolute/path/to/input/request.json` containing the selected input, validate
and run the installed core definition:

```sh
safeyolo job validate "$HOME/.safeyolo/assets/hyperlight/hyperlight.json"
safeyolo job run "$HOME/.safeyolo/assets/hyperlight/hyperlight.json" --input /absolute/path/to/input --json
```

The example's decoded stdout is `{"input_bytes":N}`, where `N` is the byte
length of `request.json`. The command prints the complete execution result as
JSON because this example selects `--json`, with bounded retained output
encoded in Base64. Without that option, the command prints a human-readable
execution summary. Use
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
safeyolo upgrade status
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

Contributors building new runtime/checker bytes need a SafeYOLO source checkout,
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
| Networking | Bounded byte I/O to the delegated proxy; optional separate mediated service host call | Same byte I/O; host-socket passthrough stays disabled |
| Memory | `memory_mb` selects scratch size | `memory_mb` selects scratch size |
| Cancellation | Kill the owning helper process group, then reap the helper | Same |
| State reuse | Clean initialized snapshots; fresh helper and sandbox per call | Clean initialized interpreter snapshots; fresh helper, mounts and sandbox per call |

Both engines reject `privilege=guest-root`. Core is not an
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

If group signalling returns `EPERM`, cleanup waits up to five seconds for the
owned helper to exit. Closing a proxy bridge can start helper exit before the
exit status is available. Cleanup succeeds only when the helper has exited and
the process group is absent after reaping. A helper that remains live at the
deadline or an unverified group produces a cleanup error and preserves the runtime.
After reaping, cleanup never sends another signal to the former group.
Errors identify the bridge, delegation, socket directory or helper operation.

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
generators on restore. Initialization imports Python's module-level `random`
generator. The restore probe compares its state with the frozen state before
drawing a value, as well as comparing values across calls. `SY_INVOCATION_ID`
and `SY_DEADLINE_MONOTONIC_MS` identify
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
still runs for each call. The cache and its receipts stay in the trusted host's
private instance directory, outside job mounts. Digest checks detect changed
bytes; they do not authenticate a cache supplied by an untrusted writer.
Current policy is checked separately: changing a
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

## Network access through the delegated proxy

Set `network=true` in an adopted job to use the existing `gate:<gate_id>`
network policy. That authority is independent of the invoking agent: a check
can reach a dependency its caller cannot reach. Invocation inputs and headers
cannot change the selected gate, run identity or dependency ancestry. Public
destinations need no Service Gateway definition or service grant. Gateway
credentials and capabilities remain separate requirements for protected services.

For the installed network examples, select the owning host's instance. Keep
its proxy running. Add the intended destination to its existing gate policy,
then apply that policy with the [normal policy workflow](installation.md#check-show-and-apply).
For example, the public HTTPS endpoint `https://example.com/` needs this gate
network permission and no service grant:

```toml
[agents."gate:hyperlight-network-check".hosts."example.com"]
egress = "allow"
```

Create `/absolute/path/to/input/request.json` on that host:

```json
{"subject":{"kind":"value","value":"https://example.com/"},"inputs":{"expected_status":200}}
```

From the same host, run either pinned example against that input directory:

```sh
safeyolo --instance-dir "$HOME/.safeyolo" job run "$HOME/.safeyolo/assets/hyperlight/hyperlight-network.json" --input /absolute/path/to/input
safeyolo --instance-dir "$HOME/.safeyolo" job run "$HOME/.safeyolo/assets/hyperlight/hyperlight-unikraft-network.json" --input /absolute/path/to/input
```

Both examples return a typed finding that compares the HTTP status with
`expected_status` (default 200). They issue one GET. They do not follow
redirects or retry. Every later request a workload makes still passes through
the delegated proxy. Removing the gate's permission denies the unchanged job.
The same JobSpec can be the source of an
[adopted named job check](policy-checks.md#adopt-an-installed-public-network-job-as-a-named-check).

Core's `NetworkCheck` uses reqwless for HTTP and Rustls/ring for TLS and
certificate validation. Its byte adapter, TLS buffers and client execute in
the Core guest. The guest obtains fresh clock and cryptographic entropy through
bounded host calls. The build uses the narrow ring
[Hyperlight target patch](../jobs/hyperlight-guest/vendor/ring/SAFEYOLO.md).
The Unikraft helper supplies `safeyolo_proxy.open_url` from its pinned bytes;
that adapter uses Python's `http.client` and OpenSSL `ssl.MemoryBIO` in the
guest. Other client libraries need a compatible adapter; ordinary Linux socket
APIs are not enabled. Both provided clients validate the server certificate
and hostname. Core includes public roots and the selected proxy CA; Python uses
its runtime roots and the selected proxy CA.
The bundle builder supplies the Python image's missing OpenSSL 3 libraries
from digest-pinned Debian 12 packages for the guest architecture. It keeps
the package's copyright and license and exposes the image's bundled public
CA roots at OpenSSL's default path. The completed CPIO image has its own
runtime-manifest digest; replacing it requires regenerating the job pins.

For HTTP, the guest sends an absolute-form proxy request. For HTTPS, the guest
performs CONNECT and TLS. DNS and destination connections remain with SafeYolo.
The host transports bytes only to the invocation's selected proxy Unix socket.
There is no guest-selected host path, general host dialer or host HTTP client
in this path. Calls carry at most 49152 bytes; each stream read/write carries
at most 16384 data bytes. Core's client bounds its TLS buffers at 65536 bytes.
Ordinary proxy method/path/redirect checks apply where the proxy can inspect
them; an opaque CONNECT tunnel does not expose those HTTP fields.

For a Gateway-backed dependency, separately authorize `github` for
`gate:hyperlight-network-check` using the existing
[service commands](credentials.md), and permit its destination in gate network
policy. The same examples accept this adopted input:

```json
{"subject":{"kind":"value","value":"https://api.github.com/repos/craigbalding/safeyolo/issues/1584"},"inputs":{"service":"github","expected_status":200}}
```

The guest receives only that gate's scoped Gateway tokens; provider credentials
stay on the host. Network capability alone supplies no service credential,
route capability or provider exception. The existing service examples below
remain the choice when the check requires independently captured source data.

Generic network findings remain guest-produced results. Normal proxy evidence
records reached traffic under the gate/run identity and check ancestry. Stream
bytes, a successful status, guest stdout or its hash do not establish an
independently captured response body. In particular, the GitHub checked-input
path still requires the host's `service_evidence`; missing capture cannot
satisfy that binding. Named service sources remain Gateway-backed.

Replacing the active policy closes each job's delegated network listener and
cancels its accepted connections without a graceful response drain. Platform
jobs recheck delegation authority before retaining a completed guest result.
Start a new job to use the updated policy. Cancellation,
expiry and teardown also close the delegation. The helper's existing deadline
and process-group cleanup still apply. No stream or token is donated to another invocation.
Offline validation and preview do not open a proxy stream or query a dependency.
CPU client checks and guest ELF builds alone do not establish installed VM
execution or isolation on a different host.

The existing `tests/blackbox/host/hyperlight_network.py` witness shares public
direct/named allow/removal cases across all four engines. Select a pinned
Hyperlight `--bundle`, or select `--engine gvisor`/`--engine vz` with that
host's prepared `--base-root`. Platform cases use its existing Bash and curl;
the adopted argv fixes the endpoint while the shared cases vary gate policy.
`--scope` adds destination/method/path refusal, a negative HTTP 302 finding
without automatic following, cache expiry and a
separately adopted gate without dependency access. `--caller-only` selects
caller and cycle checks and offline effects without repeating lifetimes.
Each selected mode retains its own contact counters and
execution facts; selecting another engine does not carry over a platform pass.
The 302 case records only the two original direct/named requests. It does not
prove that SafeYolo denied an attempted redirected or off-scope second request.
For that observation, `--redirect` selects a separate one-hop HTTP follow on
gVisor, VZ or Unikraft. The guest client first follows permitted path and
destination targets. The same adopted job then runs with only target access
removed. The witness requires a proxy-observed 403 under each denied run's
gate identity and no target contact, including TCP connections without HTTP.
This mode runs eight jobs and expects twelve origin requests and twelve TCP
connections if all controls pass. It reuses the prepared runtime;
Unikraft receives a pinned diagnostic Python checker using `safeyolo_proxy`.
Core's installed `NetworkCheck` does not follow redirects and cannot supply
this observation. A prepared mode is not evidence of an installed pass.
The platform job and isolation witnesses cover their retained connections,
direct-socket/DNS refusal and teardown. On a prepared gVisor or VZ host,
`--lifetimes-only` selects only the missing named-check observations. The origin
holds a response until the check deadline or gate revocation closes the
connection. The witness checks the selected input, run generation, live backend
birth, removed socket and stopped backend before releasing the late response.
The same subject must then acquire fresh evidence. Further calls check cache
reuse, policy invalidation, expiry and separation by subject and adopted gate.
This platform mode runs nine jobs and expects eight origin requests if all
controls pass. It does not repeat the direct-job or caller/cycle cases.
On Hyperlight, `--lifetimes-only` retains its direct and named lifetime cases.
Prepared selections and CPU observer controls do not establish an installed
pass, unrun warm-state behavior or checked-source capture.

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
