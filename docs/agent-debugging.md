# Agent debugging facilities

What an agent can observe about itself and the processes it owns inside a
SafeYolo sandbox — and what it deliberately cannot.

For a stopped coding harness inside a ready sandbox, use `safeyolo agent diag
NAME` to inspect its recorded launch. `agent shell NAME` opens an independent
guest shell; `agent attach NAME` reconnects to the existing coding-agent
terminal. See [agent launchers](agent-launchers.md) for persistent runs and
temporary interactive debugging of managed agents.

For a shell that survives loss of the operator connection, use
`safeyolo agent shell NAME --persistent`. Repeating the command reattaches to
the same independent shell through host tmux. You can still run guest tmux
inside that shell and start the coding agent manually for guest-side lab work.
The plain `agent shell NAME` command keeps its direct-shell behavior.

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

### Inspect a macOS VM helper from the host

Run these commands from the host operator account after installing the current
VM helper and restarting the agent:

```sh
safeyolo agent diag NAME
safeyolo agent vm status NAME
safeyolo agent vm relays NAME --json
safeyolo agent diag NAME --hang
```

`agent diag` reports the installed helper and the running helper separately.
The running identity includes its PID, source revision and dirty state, build
profile, architecture and debugger authority. `vm status --json` also includes
start time, uptime, cached Virtualization state, queue heartbeat and relay-loop
heartbeats. See [VM helper development](DEVELOPERS.md#macos-vm-helper-development)
for production/development signing and symbol bundles.

The shell check first connects to the shell UDS, then requires an SSH
identification within one three-second deadline. No SSH authentication is
attempted. A successful UDS connect alone does not prove that the helper,
vsock, guest bridge or sshd is making progress. The separate egress checks
continue if the shell check fails.

The helper control socket is under the configured data directory at
`vm-control/NAME.sock`. Its directory is mode 0700, its socket is mode 0600,
and the helper checks the local peer UID. The directory is host-only and is
not added to the guest's shares. Control uses a dedicated nonblocking thread;
status and dumps read cached state without waiting on VM or relay executors.
Responses identify stale heartbeats and accepted shell connections still
awaiting execution. VM state with an old heartbeat is an observation from
that time, not evidence of current queue responsiveness.

`vm relays` lists flow IDs, types, phases, transferred bytes and buffered bytes.
Its JSON records also include acceptance/progress times and endpoint FDs.
`relay_fd_count` counts tracked data endpoints; control listener/client FDs are
reported separately. These are relevant owned-descriptor counts, not a scan of
every FD opened internally by Virtualization. Listings use bounded pages and
one client deadline. Flow IDs belong to one helper instance; they cannot be
carried across a restart.

`agent diag NAME --hang` and `agent vm dump NAME` save a mode-0600 JSON dump at
`vm-control/NAME.hang.json`. `agent vm dump NAME --output PATH` selects another
artifact path. The dump includes identity, cached VM state, executor health,
counts, the oldest 256 active flows, and up to 64 recent completed/error records
and control events. It marks flow-list truncation explicitly. No debugger,
shell relay or proxy relay is needed to generate it.

To recover a pathological connection, list it first, then cancel its flow ID:

```sh
safeyolo agent vm relays NAME
safeyolo agent vm cancel NAME 42 --reason 'stalled download'
safeyolo agent vm cancel NAME --all --kind proxy --dry-run
safeyolo agent vm cancel NAME --all --kind proxy --reason 'recover stalled proxy flows'
```

Cancellation terminates the associated network or shell connection. It does
not stop the VM. Bulk selection requires both `--all` and `--kind proxy|shell`,
and captures existing IDs before sending cancellation batches. `--dry-run`
only lists that selection. The helper rejects a stale instance ID and records
the operator UID, helper instance, selected IDs, reason and action ID in
`NAME.sock.audit.jsonl` before queuing cancellation. If it cannot write that
private audit, it refuses the operation.

The CLI reports closure only after observing that the selected IDs have left
the active ledger. If the deadline expires, cancellation may already be queued;
the command reports the unverified outcome and the audit retains the action.
Inspect the relay list before taking another recovery action.

Use these observations to narrow a shell incident:

| Observation | Evidence and next check |
|---|---|
| Shell UDS missing/refused | The host listener is unavailable; inspect helper identity/state and startup logs. |
| UDS connected, shell accepts pending, stale relay heartbeat | The helper recorded acceptance without executor progress. Save a hang dump. |
| Recent shell establishment timeout/error | The host-to-guest vsock connection did not establish; inspect guest bridge readiness through the shared-home recovery path. |
| Shell relay active, no SSH banner | Bytes did not reach an SSH identification. Guest bridge/sshd checks are still needed; the banner probe alone cannot distinguish them. |
| Banner received, a subsequent shell command fails authentication/session setup | Transport reached sshd; inspect that SSH error and guest service logs. The diagnostic did not authenticate. |

### Probe the guest through PID 1 when SSH is unavailable

The host operator can use the existing command supervisor over the shared home
to run a fixed guest health probe. PID 1 must still be responsive, and the
guest must still see its home and configuration shares. This path does not
use the helper control socket, shell relay or proxy relay.

From a checkout of the matching SafeYolo version on the host, run the recipe
below. Replace `NAME` with an existing, booted agent. The checkout needs its
usual Python dependencies; `uv run` uses the project environment.

```sh
uv run python contrib/vm-guest-probe.py NAME
```

The recipe is intended for a sandbox started with `agent run NAME
--sandbox-only`, or another running sandbox whose command supervisor is idle.
It also works alongside a normal interactive/terminal launcher if that launcher
does not occupy the command supervisor. It refuses an active, starting or
restarting supervisor, including one that has a stop fence but has not yet
reported termination. It also refuses an in-progress launcher transition.
Do not clear another command's state to make the probe run.

The recipe takes the existing host setup and launch locks before checking and
publishing state. Concurrent normal launch/stop operations use those same locks.
Guest PID 1 launches the probe through the normal `agent` account. The probe
records its UID, selected bridge/service process names and PIDs, and a bounded
SSH banner check against guest loopback port 22. It does not collect process
arguments or environment variables. A missing process name is only a clue;
the loopback banner is the direct sshd transport check.

Guest health collection has an eight-second deadline and a one-second banner
deadline. Publishing the result and exiting has a separate one-second hard
deadline. The host waits at most fifteen seconds, including lock acquisition.
Output uses the supervisor's existing 16-KiB stderr limit. The probe writes a
stop fence before exiting so the supervisor does not restart it. During that
final publication, the probe blocks the supervisor's SIGTERM and exits directly
after flushing its result. This preserves its exit status if the stop watcher
reacts before the process exits. The hard deadline still applies. The host
reports completion only after observing a terminal supervisor state and the
matching probe result. On timeout it publishes a stop fence for its own command
and reports that completion is unverified. A stop request alone is not proof
that the guest has stopped the command.

Each invocation creates a private directory under the configured data directory
at `vm-recovery/NAME-*`. It contains the invocation ID, operator UID, payload
hash, deadline, prior terminal state when present, and the observed supervisor
state and result or error. The recipe prints that evidence path. It removes
its supervisor-enabled marker after completion or timeout and leaves the stop
fence in place. The next ordinary agent launch uses the existing startup path
to replace terminal state and clear the fence. Saved previous state is evidence;
the recipe does not automatically restart a prior command.

If the guest loopback banner succeeds while the host shell banner fails, inspect
the recorded guest bridge processes and helper vsock errors to separate those
remaining hops. If this recovery path also times out, the result cannot
distinguish a guest/PID-1 failure from a failed shared-filesystem path.

### Guest tooling triage

The agent-facing skill graph `triage-guest-tools-and-sudo` covers the
`ptrace / py-spy / rbspy denied` failure modes and routes each symptom
to the correct fix (YAMA scope stale, gVisor syscall unsupported,
proc/mem readable, etc.). See
[`cli/src/safeyolo/agent_context/skills/safeyolo/references/graph/triage-guest-tools-and-sudo.yaml`](../cli/src/safeyolo/agent_context/skills/safeyolo/references/graph/triage-guest-tools-and-sudo.yaml).

For everything else about the guest tooling surface — package install,
runtime managers, sudo semantics, what persists across restarts —
see the agent skill reference [`guest-tools.md`](../cli/src/safeyolo/agent_context/skills/safeyolo/references/guest-tools.md).
