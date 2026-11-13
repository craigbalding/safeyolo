# Hyperlight jobs

Use core Hyperlight for a purpose-built Rust guest. Use Hyperlight-Unikraft for
a Python checker that fits its Linux compatibility subset. Both use the
[existing job command](operator-guide.md#run-a-disposable-sandbox-job), trusted
job definitions and captured-stream evidence. Engine selection does not grant
service or network access.

## Build and select a runtime

Build on Linux x86_64/aarch64 or Apple-silicon macOS as an ordinary user, from a
SafeYolo source checkout. Install Rust 1.94, Clang/LLVM, Python 3.12 or newer,
curl and cargo-hyperlight 0.1.15 first. The builder downloads hash-locked Rust
dependencies and a pinned Python runtime layer from GitHub Container Registry.
It creates the new output directory and keeps reusable Cargo targets under
`jobs/`. On macOS it signs the helper with the Hypervisor.framework entitlement.
It does not change an installed instance or its policy.

From the checkout root, with those tools on `PATH`:

```sh
python3 scripts/build_hyperlight_jobs.py --output /absolute/path/to/new-job-bundle
```

The bundle contains a helper, a core Rust guest, the Python checker/runtime,
their pinned job definitions and `runtime.json`. The manifest records the host
architecture, Hyperlight 0.19.0 guest ABI, Unikraft integration 0.21.0, embedded
kernel contract, runtime source and artifact digests. Build/package results
identify exact bytes; a release tag is never resolved during execution.

An installed host package can include that bundle through
`scripts/build_host_packages.sh --hyperlight-artifacts DIRECTORY`, alongside
the package builder's other required inputs. The bundle is installed under
`host/assets/hyperlight`. Relative artifact paths follow their trusted job
definition, so copying the complete bundle preserves its bindings.

For execution, select an existing SafeYolo instance with `--root`. Linux needs
accessible KVM. Apple-silicon macOS needs Hypervisor.framework support and the
signed helper. A macOS VM without nested hypervisor support can build the
bundle but cannot run these jobs.

With `/absolute/path/to/input/request.json` containing the selected input, run
the generated core definition:

```sh
safeyolo --root /absolute/path/to/instance job validate /absolute/path/to/new-job-bundle/hyperlight.json
safeyolo --root /absolute/path/to/instance job run /absolute/path/to/new-job-bundle/hyperlight.json --input /absolute/path/to/input
```

The example's decoded stdout is `{"input_bytes":N}`, where `N` is the byte
length of `request.json`. The command prints the complete execution result as
JSON, with bounded retained output encoded in Base64. Use
`hyperlight-unikraft.json` to run the equivalent Python workload. These examples
measure a small offline workload; they are not authoritative policy predicates.

Discovery checks the selected artifact digests, host architecture, runtime
versions and hypervisor availability. A missing device, entitlement, artifact
or incompatible guest fails explicitly. Guest ABI validation also occurs in
the Hyperlight loader. No path silently selects a different engine.

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
| State reuse | No snapshots or warm templates | No snapshots or warm templates |

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
input preparation and artifact copying from VM execution and any future
provider latency. Compare with the host's existing engine using the same input,
authority and output retention. Cold invocation currently starts a fresh
helper and VM each time; there is no implemented warm lane or universal
performance advantage.

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
