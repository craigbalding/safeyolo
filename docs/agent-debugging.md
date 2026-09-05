# Agent debugging facilities

What an agent can observe about itself and the processes it owns inside a
SafeYolo sandbox — and what it deliberately cannot.

## Philosophy

The sandbox is the security boundary. Processes *inside* one agent's
sandbox are not separate trust domains: they all belong to the same
agent, cooperating on the same task. Preventing them from tracing each
other's memory buys nothing and breaks debugging, test instrumentation,
and crash analysis. Preventing them from tracing anything the *host*
runs — that is the actual boundary and it stays hard.

So the default posture is:

1. **Same-uid, in-sandbox debugging is a first-class agent facility.**
   `py-spy`, `rbspy`, `strace`, `gdb`, `/proc/$pid/mem` samplers, and
   `pprof`-style attach paths should Just Work against any process the
   agent's own uid started, regardless of parent relationship. No sudo
   dance, no capability discovery, no operator ticket.

2. **Cross-boundary debugging is out of scope.** The agent cannot address
   host PIDs, cannot read host `/proc`, cannot enter another agent's
   sandbox, cannot install a host-side tracer against a guest PID, and
   should not ask the operator to do any of those things on its behalf.
   That last one — "please attach a debugger from the host side" — is
   boundary erosion masquerading as delegation, and SafeYolo exists to
   prevent it.

3. **Kernel-observability tooling is not a promise the sandbox makes.**
   `perf record`, `bpftrace`, ftrace, kprobes and uprobes need real
   kernel subsystems exposed to the container. Some SafeYolo runtimes
   expose none of that. If a triage genuinely needs kernel-side
   observability, the correct move is to reproduce the workload against
   a real-kernel microVM, not to widen the sandbox.

The design rationale — YAMA emulation, `CAP_SYS_PTRACE`, and the gVisor
guest-ptrace implementation — is captured in the same-UID ptrace commit
history (PR #295) and the guest-side tests. This document is the
user-facing "what you get today" counterpart.

## What the sandbox provides

The picture varies by host platform because the sandbox substrate does.

### Linux host (gVisor microsandbox)

Runtime: `runsc` with `--platform=systrap` (default) or `--platform=kvm`
when `/dev/kvm` is available on the host.

| Facility                                    | Status                                                    |
|---------------------------------------------|-----------------------------------------------------------|
| YAMA `ptrace_scope=0` inside sandbox        | set by `guest-init-static.sh` at boot                     |
| `CAP_SYS_PTRACE` in `root_caps`             | granted; reached only via `setpriv --reuid=0` (guest root)|
| `/proc/$pid/mem` sampler (py-spy, rbspy)    | works same-uid, any relationship, no elevation            |
| `process_vm_readv` / `process_vm_writev`    | works same-uid                                            |
| `ptrace()` attach (strace -p, gdb -p)       | works on both platforms; gVisor's Sentry implements guest `ptrace(2)` including `PTRACE_ATTACH` and `PTRACE_SEIZE` |
| `strace -f cmd` (launch under strace)       | works                                                     |
| `perf_event_open`                           | not exposed by gVisor                                     |
| eBPF / bpftrace                             | not exposed by gVisor                                     |
| ftrace / `/sys/kernel/tracing`              | not exposed by gVisor                                     |
| Guest sudo helper (`sudo -n`)               | rootless-gVisor shim via `setpriv` — see [`guest-tools.md`](../cli/src/safeyolo/agent_context/skills/safeyolo/references/guest-tools.md) |

Debian and Ubuntu ship Linux YAMA at `ptrace_scope=1` by default, which
blocks non-parent same-uid attach even though the guest `ptrace()`
syscall is implemented. safeyolo's `guest-init-static.sh` sets guest
YAMA to `0` at boot (#295), which restores conventional same-UID
tracing. Attach paths that were previously failing with
`ptrace(PTRACE_SEIZE, ...): Operation not permitted` work after that
sysctl is honoured. `CAP_SYS_PTRACE` in `root_caps` is a backstop for
runs where the guest-init sysctl write did not land (kernels compiled
without YAMA, or where the sysctl view is not writable).

### macOS host (Apple Virtualization microVM)

Runtime: a real Linux kernel booted as an Apple Virtualization guest.
See [`microvm-architecture.md`](./microvm-architecture.md) for the wider
architecture.

Because this is a real kernel rather than gVisor's sentry, the ptrace
surface is native Linux: `ptrace()` works on any platform, `perf_event_open`
and eBPF may work depending on kernel config and how the guest exposes
`/sys/kernel/tracing` and `/sys/fs/bpf`.

**Platform asymmetry to be aware of:** the guest-root plumbing is
mostly *shared* — the `/usr/local/bin/sudo` shim
([`guest/rootfs/safeyolo-sudo`](../guest/rootfs/safeyolo-sudo)), the
`NOPASSWD:ALL` sudoers drop-in, the `guest-init-static.sh` YAMA sysctl,
and the passwordless-guest-root policy all live in the shared rootfs
layer. The shim probes at runtime: if `setpriv --reuid=0` works it uses
that (the rootless-gVisor path); otherwise it delegates to the ordinary
setuid `/usr/bin/sudo` (the real-kernel path used on the macOS microVM).

What *is* platform-specific is how the shim's preconditions get
satisfied. `platform/linux.py` explicitly seeds `CAP_SETUID`,
`CAP_SETGID`, and (now) `CAP_SYS_PTRACE` in the OCI `root_caps` list,
because rootless gVisor needs them stated. `platform/darwin.py` doesn't
manage caps at all — the real Linux kernel inside the microVM does that
work, and the ext4 rootfs image is mounted with suid honoured. So the
two platform modules look asymmetric even when the guest-facing
behaviour lines up. Genuine parity gaps show up as agent-visible
differences (a command works on one platform and not the other); report
those as bugs rather than working around them.

**Explicit unsupported branch to know about:** the shim installer
([`guest/install-guest-common.sh`](../guest/install-guest-common.sh)) skips
itself if a custom rootfs has no `/usr/bin/sudo`. Such an image is not
sudo-capable and must not claim the documented `sudo -n` facility; agents see
`sudo: command not found`. Images that do include sudo must also provide the
account tools and `visudo`: construction provisions the `sudo` group, adds
`agent`, writes the direct user-scoped rule needed by pre-existing shells,
sets it `root:root`/0440, and fails closed if validation cannot pass. This
keeps Alpine's conventional `wheel` naming from changing the SafeYolo
contract. Distinguish the unsupported branch from a runtime drift with
`ls /usr/bin/sudo /usr/local/bin/sudo` and the rootfs build output.

## What debugging *looks like* in practice

The two most common flows work with no ceremony:

```sh
# Sample a running Python process the agent started earlier.
mise use -g python@3.12
python -m pip install --user py-spy
py-spy dump   --pid $(pgrep -f my_worker)
py-spy record --pid $(pgrep -f my_worker) -o out.svg -d 30
```

```sh
# Trace a running process, whether or not it's a descendant.
sudo -n apt-get install -y strace   # Debian/Ubuntu/Kali rootfs
strace -f -p $(pgrep -f my_worker)
```

Launch-under-strace is an alternative when you want the full syscall
history from process start rather than from attach time:

```sh
strace -f -o /tmp/tr.log ./my_worker
```

## What it will not do

- **Kernel-side observability.** No agent-facing `perf record`, no
  `bpftrace`, no ftrace, no kprobe/uprobe. If the triage requires these,
  reproduce the workload against a real-kernel microVM outside SafeYolo.
- **Cross-agent debugging.** Each agent's sandbox is opaque to every
  other agent. There is no "attach to that other agent's Python for me"
  facility and there will not be one — that is a trust-domain boundary
  by design.
- **Host-side debugging on the agent's behalf.** Do not ask the operator
  to attach a debugger from the host, run a host-side tracer against a
  guest PID, or move a target process out of the sandbox. When no
  in-sandbox facility exists for a specific triage, report the
  limitation and pick the closest workable alternative.
- **`CAP_SYS_PTRACE` for the agent uid directly.** Ordinary agent
  processes (uid 1000) do not hold it. On Linux gVisor the cap sits in
  the bounding set and reaches an elevated process only through
  `setpriv --reuid=0`. Weakening this so the agent uid holds it
  directly is not on the roadmap.

## Failure triage

The agent-facing skill graph `triage-guest-tools-and-sudo` covers the
`ptrace / py-spy / rbspy denied` failure modes and routes each symptom
to the correct fix (YAMA scope stale, gVisor syscall unsupported,
proc/mem readable, etc.). See
[`cli/src/safeyolo/agent_context/skills/safeyolo/references/graph/triage-guest-tools-and-sudo.yaml`](../cli/src/safeyolo/agent_context/skills/safeyolo/references/graph/triage-guest-tools-and-sudo.yaml).

For everything else about the guest tooling surface — package install,
runtime managers, sudo semantics, what persists across restarts —
see the agent skill reference [`guest-tools.md`](../cli/src/safeyolo/agent_context/skills/safeyolo/references/guest-tools.md).
