# gVisor shared-workspace ETXTBSY experiment

Date: 2026-08-20

This experiment investigated host-side `ETXTBSY` (`Text file busy`) after a
SafeYolo agent edited an executable file in a gVisor-backed host workspace.
It identified the responsible gVisor cache behavior, tested candidate runtime
settings, and exercised the recommended setting for correctness and obvious
side effects.

## Outcome

Use the per-mount option `dcache=0` on writable, operator-facing host content
whose contract includes immediate host execution after a guest edit:

- `/workspace`
- any writable extra host-folder mount that deliberately offers that workflow

Retain normal caching for read-only shares and internal mounts such as
`/home/agent`, package caches, status, configuration, certificates, and proxy
sockets. Do not apply this option indiscriminately to large writable data
shares. Keep DirectFS enabled. Leave global `--dcache` unset; any nonnegative
global value creates a shared cache and takes precedence over per-mount sizes.

The public extra-mount wiring must be traced separately before changing its
mount options. This experiment establishes the desired cache policy once a
writable extra share reaches the Linux OCI mount builder; it does not establish
which CLI path currently supplies that share.

The Linux OCI builder now implements the narrow production change by adding
`dcache=0` to `/workspace`. It does not add the option to `/home/agent`, cache
mounts, configuration/status mounts, or either writable or read-only extra
shares, and normal startup does not set global `--dcache`. The archived harness
uses the diagnostic value `SAFEYOLO_EXPERIMENT_WORKSPACE_DCACHE=default` when
it needs to reproduce the old cached baseline.

## Root cause

The default `/workspace` mount used gVisor's per-mount dentry cache with a
capacity of 1000. After a guest write closed, gVisor retained the dentry and its
shared writable host file descriptor. A direct host `execve()` then correctly
failed with `ETXTBSY` because the host kernel still saw a writable opener.

Three observations isolate this mechanism:

1. The privileged host diagnostic found the exact target inode open writable
   by `gvisor_sentry` with flags such as `02500002` (`O_RDWR`).
2. The default configuration continued returning `ETXTBSY` after a two-second
   polling window, then succeeded after creation of 1200 other dentries forced
   cache eviction.
3. Setting `dcache=0` on `/workspace` released writable descriptors when the
   guest closed them and made direct host execution succeed immediately.

This disables gVisor's cache of otherwise-unused dentries, not the host Linux
VFS or page caches. DirectFS remains enabled, so reconstructed workspace
entries still use local host file operations rather than adding gofer RPCs.

gVisor describes global `--dcache` as coarse control over the number of host
FDs kept open; a negative global value preserves per-mount cache selection:
<https://github.com/google/gvisor/blob/master/runsc/config/flags.go>.

## Experiment matrix

The matrix tested in-place truncation and atomic replacement, direct host
execution, interpreter execution, writable FD attribution, two-way content
coherence, inotify, cache churn, startup time, file metadata workloads, and a
smaller `/home/agent` control workload.

| Variant | In-place host exec | Atomic host exec | Writable holders | Interpretation |
|---|---:|---:|---:|---|
| Baseline | `ETXTBSY` | `ETXTBSY` | Present | Reproduces defect |
| `/workspace dcache=0` | Pass | Pass | 0 | Narrow fix |
| Global `--dcache=0` | Pass | Pass | 0 | Works, but affects all mounts |
| `--directfs=false` | `ETXTBSY` | `ETXTBSY` | Present | Not the controlling setting |
| `/workspace dcache=0`, DirectFS off | Pass | Pass | 0 | Cache policy remains controlling |

Disabling DirectFS also made the synthetic filesystem workloads substantially
slower, so it is neither a fix nor a useful mitigation.

## Deep `dcache=0` result

The focused run completed:

- 6000 guest write/close cycles
- 1500 direct host executions
- 0 execution failures
- 0 writable workspace holders in all three rounds
- 9581 regular workspace-file inodes checked after the larger workloads, with
  0 writable holders
- 2000-file Git repository with five clean and five dirty `git status` runs
- open-descriptor, mmap, inode replacement, hardlink, symlink, rename, unlink,
  truncation, append, sparse-file, Unicode-path, mode, ownership, timestamp,
  hash, and bidirectional visibility checks

All content and namespace semantics matched. In particular:

- in-place edits preserved the inode and an already-open host descriptor saw
  the new content;
- atomic replacement produced a new inode while an already-open descriptor and
  mmap retained the old content;
- hashes, sizes, modes, ownership, timestamps, hardlinks, symlinks, names, and
  expected absence matched in both directions.

### Performance

The deeper run used five repetitions over 4000 workspace files. Compared with
the earlier baseline sample, median results were:

| Operation | `dcache=0` | Baseline | Change |
|---|---:|---:|---:|
| Create | 667.9 us/file | 692.9 us/file | -3.6% |
| `stat` | 162.3 us/file | 159.8 us/file | +1.6% |
| Open/read | 360.3 us/file | 405.9 us/file | -11.2% |
| Negative lookup | 224.2 us/file | 234.4 us/file | -4.3% |

The runs were not randomized interleaved benchmarks, so small differences
should be treated as indicative rather than precise. They show no obvious
performance regression from workspace-only `dcache=0` for these workloads.

Clean Git status over 2000 files took 141-177 ms. Dirty status with 100 modified
files took 191-232 ms and consistently reported all 100 entries.

### Runtime resources

- The gofer remained at 46 FDs and approximately 30.7 MiB RSS.
- The sentry reached 830 FDs after round one and remained at 830 after rounds
  two and three; there was no per-round FD accumulation.
- Sentry RSS moved from approximately 57.5 MiB before the rounds to 59.6 MiB
  after round three.
- The later combined workload measurement reached 2819 sentry FDs and 67.3 MiB
  RSS. That measurement also intentionally populated the normally cached
  `/home/agent` mount with 1000 files and exercised rootfs/Git paths, so it
  cannot be attributed to the zero-cache workspace. The complete workspace
  tree still had zero writable holders.

## Baseline control and pre-existing limitations

A short default-cache control was run to classify two initially suspicious
deep-test observations.

- All four direct host executions failed with `ETXTBSY`.
- Four unique probe inodes remained writable; the scanner reported 128
  task/FD views because sentry tasks share the descriptor table.
- Host and guest advisory `flock` locks were not coordinated.
- Guest `st_blocks` values were synthetic. Small files generally appeared as
  one block inside gVisor and eight allocated 512-byte blocks on host ext4; an
  8 MiB sparse file appeared fully allocated inside gVisor while ext4 reported
  eight allocated blocks.

The lock and block-accounting behavior was identical with the default cache,
so neither is a `dcache=0` regression. Tools inside the guest must not assume
that `st_blocks` reflects host sparse allocation, and workflows must not rely
on advisory `flock` coordination between host and sandbox.

The matrix also found that guest inotify did not report host changes under any
variant, including baseline, while host inotify did report guest changes. This
is another pre-existing shared-filesystem limitation rather than a cache-zero
side effect. gVisor's non-root shared mounts revalidate external changes, but
that does not imply host-kernel notification or lock equivalence:
<https://github.com/google/gvisor/blob/master/runsc/config/config.go>.

## Boundary conditions and focused follow-up

`dcache=0` releases an *idle cached* writable host descriptor. It is not meant
to make a legitimately active guest writer executable from the host. The
initial deep run did not keep guest references alive: its host-side descriptor
and mmap checks exercised replacement semantics from the opposite side of the
boundary.

The `edge` subcommand therefore uses a synchronized protocol. The guest edits
the executable, closes or deliberately retains the selected reference, emits
a readiness marker while remaining alive, and waits for a host-created release
marker. The host executes and attributes descriptors during that held state,
releases the guest, and executes again. It covers:

- an idle closed file, with 32 parallel host executions;
- a watch on the parent directory;
- an inotify watch directly on the executable;
- a live writable file description;
- a live shared writable mapping after its ordinary FD is closed;
- a live read-only file description opened through a hard-link alias.

Only the idle-cache and ordinary active-writer outcomes are normative. Direct
watch, mapping, and hard-link-alias cases are characterization tests because
their purpose is to determine the exact current gVisor retention boundary.
Every target must execute after its guest reference is released.

The controller samples sentry CPU ticks, `/proc` I/O counters, FD counts, and
exact writable holders around these cases. It intentionally does not attach
`strace`, `perf`, or another syscall tracer: stopping or slowing the sentry
would create an observer effect in the close-to-exec timing under test. A
separate randomized performance run should measure open/close rate and large
real workloads if the basic boundary test passes.

An inotify watch is relevant because gVisor dentries expose watch state and an
evictability decision:
<https://pkg.go.dev/gvisor.dev/gvisor/pkg/sentry/vfs#Dentry>.

The conclusion also assumes the current shared bind-mount model. It must be
re-evaluated if `/workspace` is later converted to an overlay or external
mounts are switched to exclusive file-access mode.

### Focused boundary result

The corrected synchronized run completed successfully. Its first host
`execve()` occurred before descriptor scanning, between 0.70 and 2.69 ms after
the controller observed the guest readiness marker.

| Guest state after edit | First host exec | Delay after readiness | Writable sentry FD group |
|---|---:|---:|---:|
| File closed, guest still alive | Pass | 2.38 ms | 0 |
| Parent directory watched | Pass | 2.69 ms | 0 |
| Executable directly watched | `ETXTBSY` | 0.84 ms | 1 |
| Writable FD still open | `ETXTBSY` | 0.71 ms | 1 |
| Shared writable mmap, ordinary FD closed | `ETXTBSY` | 0.70 ms | 1 |
| Read-only FD held through hard-link alias | `ETXTBSY` | 0.86 ms | 1 |

All 32 parallel executions of the closed idle file returned the correct
payload. All four retained-reference targets executed successfully after the
guest released the relevant watch, FD, or mapping. `/proc` displayed the one
shared sentry FD through 43 or 44 task views; these are not 43 or 44 distinct
open file descriptions.

This establishes the practical boundary: `dcache=0` deterministically removes
the idle-cache failure without overriding legitimate live inode retention.
Watching a parent directory is compatible with host execution, while watching
the executable itself is not. A read-only open through a hard-link alias is
sufficient to retain the inode and its shared writable host FD after an
in-place guest edit.

The sentry rose from 492 to 862 FDs during the first inline Python helper and
then remained at 862 through all six scenarios; there was no per-scenario FD
accumulation. RSS rose from approximately 54.3 to 57.4 MiB. These samples
include Python startup and repeated full `/proc` scans and are resource
observations, not a performance benchmark.

The first archived edge run (`edge-20260820T075835Z`) tested the same reference
states and reached the same classifications, but performed the approximately
19-second descriptor scan before its first execution. It remains useful for
reference-retention replication but must not be used as the close-to-exec
timing result. `edge-20260820T080437Z` is the corrected definitive run.

## Archived-verdict caveat

`results/deep-dcache0-20260820T073129Z-summary.json` contains valid raw
measurements, but its original automatic `all_correctness_checks_passed` value
is false. That harness version compared `st_blocks` as ordinary portable
metadata and required host/guest `flock` propagation. The subsequent baseline
control proved both observations are invariant gVisor behavior. The archived
harness now reports allocation differences separately from core file
semantics.

## Files

- `diagnose-etxtbsy.sh`: direct-exec reproduction and privileged `/proc` FD
  attribution.
- `experiment-etxtbsy.py`: matrix, deep-run, and baseline-control harness. It
  sends its guest helper inline; it does not stage helper scripts.
- `results/initial-host-diagnostic.log`: original conclusive inode/FD capture.
- `results/matrix-20260820T070237Z-*`: five-variant matrix summary and log.
- `results/deep-dcache0-20260820T073129Z-*`: full focused run summary and log.
- `results/baseline-control-20260820T073758Z-*`: classification control summary
  and log.
- `results/edge-*`: synchronized live-reference result directories created by
  the focused edge subcommand. The definitive timing run is
  `results/edge-20260820T080437Z`; the earlier ordering-control run is retained
  as described above.

Summaries deliberately retain the tested host paths, runtime command lines,
PIDs, mount options, inode identities, timing samples, and FD flags needed to
audit the interpretation. No credentials or SafeYolo tokens are included.

## Reproduction

Run from the repository's parent directory on a Linux SafeYolo host. The
controller invokes SafeYolo as the normal user and uses `sudo` only for
read-only `/proc` attribution. It leaves the selected agent stopped.

```bash
# Single-target diagnostic; use bash because direct exec is the behavior under test.
sudo bash safeyolo/tests/rootless-experiments/etxtbsy-dcache/diagnose-etxtbsy.sh --watch 30

# Full candidate matrix.
python3 safeyolo/tests/rootless-experiments/etxtbsy-dcache/experiment-etxtbsy.py \
  run kali-template-v2

# Focused workspace dcache=0 run.
python3 safeyolo/tests/rootless-experiments/etxtbsy-dcache/experiment-etxtbsy.py \
  deep kali-template-v2

# Short default-cache classification control.
python3 safeyolo/tests/rootless-experiments/etxtbsy-dcache/experiment-etxtbsy.py \
  deep kali-template-v2 --variant baseline --rounds 1 --handoffs 2 \
  --cycles 1 --benchmark-files 1 --repetitions 1 --skip-workloads

# Synchronized watched/live-reference boundary test. Results are written
# directly into the shared archive's results/edge-<timestamp>/ directory.
python3 safeyolo/tests/rootless-experiments/etxtbsy-dcache/experiment-etxtbsy.py \
  edge kali-template-v2
```
