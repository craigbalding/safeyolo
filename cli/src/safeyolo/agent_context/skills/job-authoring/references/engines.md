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

### Installed offline observations

On 14 November 2026, fifteen successful installed jobs ran the same offline
byte-count workload over 4096 bytes, with networking disabled and bounded
stream retention. Wall time covers command invocation through job completion
and cleanup. Build, installation, input preparation and `job validate` are
outside that interval. The already running proxy and prewarmer are excluded.
These observations measure complete jobs, including their workload, rather
than isolated VM startup or live GitHub latency.

The Linux x86_64 host ran Linux 6.8.0-137 with glibc 2.39, KVM for Hyperlight
and the packaged gVisor runtime. Its debug native executables came from
[`b8272ea8`](https://github.com/craigbalding/safeyolo/commit/b8272ea837a62240fec92a8f4e9263c2a650bbcd),
with example preparation at
[`c6dd3b8b`](https://github.com/craigbalding/safeyolo/commit/c6dd3b8bfef1a2e5f49e1fbc273c4b2ac2b46a52).
The physical Apple-silicon host ran macOS 26.6.2 with Hypervisor.framework
and the c6dd3b8b debug package. These are different hosts, architectures and
native revisions; compare engines within each host, not performance between
hosts.

| Host and engine | First job (ms) | Fresh job 2 (ms) | Fresh job 3 (ms) | Maximum individual RSS range (MiB) |
|---|---:|---:|---:|---:|
| Linux: core Hyperlight | 322.250 | 398.677 | 405.639 | 31.250–32.375 |
| Linux: Hyperlight-Unikraft | 10624.707 | 8646.953 | 10838.341 | 76.457–76.586 |
| Linux: gVisor | 29396.281 | 12384.282 | 7788.608 | 38.250–38.316 |
| macOS: core Hyperlight | 347.138 | 238.601 | 264.875 | 22.656–22.672 |
| macOS: Hyperlight-Unikraft | 393.703 | 473.134 | 536.391 | 74.813–74.859 |

Resident set size (RSS) comes from the host's `/usr/bin/time`. The reported
maximum includes waited descendants as individual processes; it is not their
aggregate memory and excludes the standing services. One MiB is 1048576 bytes.
The ranges cover the three jobs in each row, not a memory limit.

The first job used existing prepared files with unknown cache temperature.
Later jobs created fresh helpers and guests or sandboxes with previously read
files. They did not restore a warm VM or template. Prepared gVisor images and
VZ boot assets can be reused while each job gets disposable writable state;
that asset reuse is separate from preserving a running guest. No cold-cache
or warm-restore latency or aggregate-memory measurement is established here.

The macOS VZ comparison has no successful sample. Its first job exited 127
before the byte-count payload, reporting `/usr/sbin/pivot_root: No such file
or directory`. Subsequent read-only inspection confirmed that executable was
absent from the selected retained Kali Rolling 2026.1 rootfs. That fixture was
not an input from the current Trixie guest producer. Keep VZ latency and memory
unknown rather than treating that failed job as a comparable run or evidence
of a current producer defect.
The Linux gVisor samples followed repair of an instance runtime binding;
its earlier setup failures are also excluded from successful-job timings.

The retained [#1552 observation records](https://github.com/craigbalding/safeyolo/issues/1552#issuecomment-6870450206)
identify each input, specification, runtime, native executable and job, with
the original observations in `installed-operator-15980.json`,
`linux-comparison-15980.json` and `physical-mac-16006.json`. The table rounds
those observations to three decimal places. The later fixture diagnosis is in
`installed-authoring-and-vz-input-16013.json`. The measurements establish no universal
latency or memory bound, production-profile result, or result for an unmeasured
host/engine combination. Measure live service checks separately so network
and provider latency retain their meaning.

Pinned upstream references explain the
[core guest ABI](https://github.com/hyperlight-dev/hyperlight/blob/a03088470d822b538d2525ef9a5ae9e29daea1e8/docs/how-to-build-a-hyperlight-guest-binary.md),
[Unikraft execution model](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/execution.md)
and [cooperative scheduling/process subset](https://github.com/hyperlight-dev/hyperlight-unikraft/blob/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a/docs/concurrency.md).
Upstream snapshots and sockets do not imply that SafeYolo adopts those features.
