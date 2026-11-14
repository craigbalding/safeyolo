# Choose an execution engine

Choose the smallest runtime that supplies the workload's actual semantics.
Core Hyperlight fits a small compiled predicate with explicit host calls.
Hyperlight-Unikraft fits the pinned Python checker and compatible libraries.
Use a Linux job when the program needs ordinary processes, a full packaged
Linux userspace, guest-root administration or a larger toolchain.

These are SafeYolo's current integration choices, not every capability offered
by the upstream projects.

| Property | Core Hyperlight | Hyperlight-Unikraft | Linux gVisor job | Linux VZ job on macOS |
|---|---|---|---|---|
| Supported host | Linux x86_64/aarch64; Apple-silicon macOS | Same | Linux x86_64/aarch64 with the matching packaged gVisor runtime | Physical Apple-silicon macOS with the signed VM helper |
| Virtualization | Accessible KVM on Linux; entitled Hypervisor.framework on macOS | Same | Existing gVisor platform selection; systrap requires no KVM | Virtualization.framework (VZ), matching prepared Linux kernel/rootfs; unsupported nested VZ fails |
| Guest artifact | Rust compiled to the matching Hyperlight guest ABI, not a host/Linux executable | Pinned Unikraft kernel/Python runtime plus checker script | Matching Linux guest image/userspace and fixed argv | Matching ARM64 Linux guest image/userspace and fixed argv |
| Ordinary Linux compatibility | No Linux system-call or process environment | Linux subset; Python/native extensions must fit the pinned runtime | gVisor implements Linux system calls in a userspace kernel; not every syscall/device is supported | Real Linux kernel in a VM; devices and mounts remain explicitly selected |
| Filesystem | Bounded `ReadInput` host function under selected read-only inputs; no arbitrary host path | Read-only `/input`; transient RAM root and `/work` | Selected read-only `/input`; disposable `/work` and `/home/agent` | Same job contract using guest mounts and disposable storage |
| Processes and privilege | No Unix PID, fork or guest-root semantics | One vCPU, cooperative threads; supported `vfork`/PIE exec subset, no `fork`; no full Linux privilege model | Linux process model within gVisor; explicit unprivileged or guest-root job selection | Linux process model within the VM; explicit unprivileged or guest-root job selection |
| Network/capabilities | No guest sockets; optional bounded mediated service host call | Same; upstream host-socket passthrough is disabled by this integration | Optional existing delegated proxy path with adopted service/network/credential rules | Same through the VZ guest's delegated proxy path |
| Persistent state | Fresh helper/guest for each invocation; no warm template | Fresh helper/guest for each invocation; no saved runtime snapshot | Disposable writable job state; prepared image/runtime reuse is separate | Disposable overlay/job state; prepared VM assets are separate |
| Memory setting | `memory_mb` selects scratch, not total host resident memory | Same | Existing sandbox resource controls; check actual enforcement for the selected platform | VM memory and existing job controls; host helper overhead remains separate |
| Deadline/cancellation | Owning helper process group is stopped and reaped; VM errors remain separate from OS helper status | Same | Existing job process/runtime cleanup | Existing VM/job cleanup |

The Hyperlight package includes `runtime.json`, helper, core guest, pinned
Python CPIO, checkers, JSON definitions and license notices. Runtime/guest/helper
digests and architecture must match. The source builder is
`scripts/build_hyperlight_jobs.py`; native packaging uses the
`--hyperlight-artifacts` input. Building and installing bytes does not adopt
a policy or make a selected runtime available on a different host.

For new code, start from the installed example's logical request/result
contract. Build Rust with the pinned `cargo-hyperlight` tool and matching guest
target; do not use the ordinary host target. Python runs inside the bundled
Unikraft runtime, so a successful host Python test does not prove its imports,
signals or subprocess behavior there. Keep inputs/effects/capabilities explicit
and test the selected real engine after source fixtures pass.

## Diagnostics and performance evidence

Use the selected instance's `job validate` before `job run`. Hyperlight results
identify `engine`, runtime/guest digests, `outcome_source`, actual helper wait
status, VM `runtime_report`, stream counts/hashes and `observation_error`.
A VM-reported return is not an OS guest-process exit. The typed evaluator
separately decides whether successful execution produced a qualifying finding.

There is no implemented warm VM/template lane for either Hyperlight engine.
Repeating a fresh invocation with cached files is a repeated cold-VM run, not
a restore measurement. Neither runtime is promised to be faster or smaller than
gVisor or VZ. Selected scratch sizes (16 MiB for the small core example and
256 MiB for Python) are configuration, not measured resident-memory peaks.

The current retained source/build controls do not supply a qualified
whole-command latency/peak-memory comparison for all supported hosts. Those
measurements remain unproved; build duration, a QEMU-user identity check and
nominal scratch allocation are not substitutes. Keep actual observations with
the component's independent acceptance evidence, including host/architecture,
virtualization, source and exact runtime/configuration bindings.

For a comparable run, use the same small offline input-byte-count workload,
input bytes, passive authority and stream retention through each installed
engine. Measure wall time from command invocation through completed cleanup and
the process-family peak resident memory with the host's native measurement
tool. Label whether that tool reports a maximum individual process or aggregate
memory. Record a first run and repeated fresh runs; report their observations,
not a universal bound. Measure the live GitHub example separately so network
and provider latency do not become VM-startup time. If any engine, host or
measurement is unavailable, leave that comparison unknown.

Pinned upstream references explain the
[core guest ABI](https://github.com/hyperlight-dev/hyperlight/blob/a03088470d822b538d2525ef9a5ae9e29daea1e8/docs/how-to-build-a-hyperlight-guest-binary.md),
[Unikraft execution model](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/execution.md)
and [cooperative scheduling/process subset](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/concurrency.md).
Upstream snapshots and sockets do not imply that SafeYolo adopts those features.
