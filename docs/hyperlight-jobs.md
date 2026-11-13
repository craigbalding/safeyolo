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
| Networking | No socket or service host calls | Host-socket passthrough is disabled; no service host calls |
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

The helper's core `ReadInput` and Unikraft embedding are the extension points
for later mediated service calls. Those calls must use the existing job
delegation and Service Gateway authority. This engine implementation does not
establish live-provider provenance or workflow enforcement.

See the pinned upstream [core guest ABI guide](https://github.com/hyperlight-dev/hyperlight/blob/a03088470d822b538d2525ef9a5ae9e29daea1e8/docs/how-to-build-a-hyperlight-guest-binary.md),
[execution model](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/execution.md)
and [Unikraft concurrency limits](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/concurrency.md).
