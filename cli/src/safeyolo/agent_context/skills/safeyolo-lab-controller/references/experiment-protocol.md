# Experiment protocol

Use this reference for multi-phase tests, reversible fault injection, crash
boundaries, or comparisons between normal and failed behavior.

## Baseline card

Write down before mutation:

- objective and pass condition;
- explicit non-goals and forbidden actions;
- product/version and instance paths;
- actors, workers, rooms, sessions, or services in scope;
- expected healthy process and service state;
- authentication provider/type without credential values;
- authoritative success signal;
- expected idle/timeout behavior;
- recovery command for every planned fault;
- evidence root and UTC clock source.

Prove the baseline using the same path the fault probe will exercise. A broad
health command is useful but is not a substitute for an end-to-end baseline.

## One-fault cycle

For every scenario:

1. **Known good:** prove the end-to-end baseline and record its cursor/session
   or equivalent continuation state.
2. **Recovery prepared:** resolve the exact target and record the reversible
   restoration command before mutation.
3. **One fault:** inject only the selected condition and record the UTC time.
4. **Smallest probe:** exercise only enough behavior to expose the fault.
5. **Evidence before repair:** retain stdout/stderr, exit code, structured tool
   result, processes, product health/audit, and domain state.
6. **Restore:** undo only the injected fault.
7. **Recovery proof:** rerun the meaningful baseline before the next scenario.

Do not immediately repair an unexpected condition merely to keep moving. First
capture what a future supervisor or operator could actually observe.

## Layered observations

Distinguish at least the layers that exist in the experiment:

- parent shell and command wrapper;
- model/provider harness;
- continuation/session storage;
- MCP registration, adapter process, and outstanding tool call;
- coordination API and backend;
- worker/container runtime;
- local proxy and explicit upstream proxy;
- provider authentication;
- operator UI and observer processes.

An exit code, a model summary, or a generic tool error usually identifies only
one layer. Do not infer the failed layer without corroborating evidence.

## Timeline record

Use UTC and retain both wall-clock times and measured durations where useful.
Use the same actor, process, pane, service, and tmux-layer names throughout the
run. Write observations as facts. Put interpretations in a separate finding or
inference field.
For each transition record:

| Time | Actor/process | Action or state | Exit/result | Cursor/sequence | Evidence |
| --- | --- | --- | --- | --- | --- |

For long waits, distinguish start time, timeout/result time, process exit time,
external event arrival time, and continuation start time.

Use `../assets/lab-log.md` as a copyable starting point when the experiment
needs a persistent pane registry, baseline card, fault catalogue, or handoff.
Record an inner command's explicit marker separately from the exit status of an
attachment or shell wrapper; do not assume the wrapper propagates it.

## Crash-boundary tests

Resolve the exact target PID and parent/child relationship immediately before
termination. Kill only the requested layer. Capture process state before and
after, and prove that adjacent layers survived.

For narrow boundaries such as “after delivery but before completion,” prefer a
deterministic pause or test hook. Model-requested sleeps can be useful during
manual discovery but are less reproducible.

Treat delivered work without an authoritative completion signal as uncertain.
Do not reconstruct or replay it manually unless the experiment specifically
tests operator-assisted recovery.

## Stopping conditions

Stop fault injection and diagnose the baseline when:

- the known-good path no longer works;
- restoration cannot be proven;
- a mutation would cross the outer SafeYolo boundary;
- the next action requires authority not already granted;
- credential values would need to be exposed;
- the target of a destructive action cannot be resolved unambiguously.

Manual execution is preferable for the first successful baseline and first
observation of each important boundary. Automate repetitions only after the
semantics and useful evidence are understood.

## Teardown

Restore all faults, prove final health, capture artifacts, list intentionally
running state, and only then close authorized panes or services. A clean lab is
not evidence that every recovery path succeeded; retain the pre-repair record.
