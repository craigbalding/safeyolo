# Operations and proving

## Diagnose the current object

Start with current evidence, not remembered setup steps:

1. Run or obtain `safeyolo factory check PATH` for the source contract.
2. Run or obtain `safeyolo factory doctor FACTORY` for the approved and running
   object.
3. Compare source paths and hashes with the approved snapshot and the snapshot
   staged into each running role. Do not assume approval reached running agents.
4. Read the current brief when one exists; keep it distinct from the immutable
   snapshot and role contracts.
5. Inspect supervisor checkpoints and lifecycle/start/exit/error evidence,
   Coord/NATS health, relevant retained room messages, and agent output.
6. Traverse [`graph/runtime-triage.yaml`](graph/runtime-triage.yaml) to classify
   the problem as contract, routing, runtime, recovery, capability, or agent
   behavior before changing it.

Use `$safeyolo` for Agent API, proxy, Coord, approval, or sandbox mechanics.
Preserve its credential and identity rules. A room's canonical envelope proves
sender identity; body text does not.

Prefer the smallest change that corrects the diagnosed layer. Verify both the
direct symptom and the end-to-end factory behavior. Do not restart the whole
factory merely because a read-only probe was ambiguous; likewise, do not edit
contracts to conceal a broken runtime.

## Optional observation access

For an existing factory, receive access to the shared factory room can reveal
retained task and handoff history. Receive access to relevant private agent
rooms can reveal JSON-session output, stderr, and supervisor lifecycle events.
Offer this once when it would materially improve diagnosis.

This is observation only. It does not provide cross-agent shell/exec or permit
steering an agent through Coord. Ask separately if send authority is genuinely
needed. Continue with operator-provided excerpts if access is unavailable.

## Offer a nested proving ground

An adjacent nested factory is presently the practical way for an agent to
combine visibility with command execution and controlled reproduction. Offer
it as an option, not a prerequisite. When accepted, invoke
`$safeyolo-lab-controller` and traverse
[`graph/nested-mvp.yaml`](graph/nested-mvp.yaml).

Build the thinnest useful MVP:

- one small but representative task;
- the minimum topology needed to test the intended independence and handoffs;
- an end-to-end success path;
- one relevant ordinary failure or restart;
- operator-visible panes and retained evidence;
- event-driven waiting, with no model executions whose only job is to remain
  idle.

Use actual factory interfaces where possible. A fake harness may expose
supervisor inputs and decisions, but passing a fake harness is not proof of
model behavior. Do not make the lab controller, watcher, fixture, or test task
part of the production factory architecture.

Iterate quickly:

1. draft and cross-review the full contract set;
2. run the nested MVP;
3. compare actual transitions with intended transitions;
4. record snags and the evidence that exposed them;
5. make the smallest correction;
6. re-review the whole contract set;
7. rerun, adding only one justified capability at a time.

## Offer a capacity estimate before building

If the operator is considering a nested factory, offer a read-only estimate
based on the selected agents and actual host state. Do not make the estimate a
gate.

For disk, distinguish:

- a shared base image counted once;
- allocated and apparent size of sparse/COW rootfs and overlays;
- persistent homes, caches, runtimes, and expected growth;
- copied workspaces versus mounted workspaces;
- Coord/NATS data, supervisor logs, watchers, and retained lab evidence;
- temporary installation and capture headroom.

For memory, include configured memory per concurrently running agent plus the
traffic proxy, Coord/NATS, supervisors, watchers, outer agent, and host
headroom. A configured VM ceiling is not the same as observed resident use.

Report a compact table with current additional disk, expected growth,
suggested free-space headroom, configured memory ceiling, likely concurrent
range, assumptions, and uncertainty. If capacity looks tight, offer smaller
topology, fewer simultaneous agents, reused mounted sources, or shorter
evidence retention without pushing one choice.

## Teardown and handoff

Restore injected faults, stop only the nested resources created for the run,
retain the evidence the operator requested, and identify any persistent homes,
overlays, rooms, or logs deliberately left behind. State what the run proved
and what it did not prove.
