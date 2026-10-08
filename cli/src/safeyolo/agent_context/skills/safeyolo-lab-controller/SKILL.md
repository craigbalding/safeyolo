---
name: safeyolo-lab-controller
description: Run controlled, operator-visible experiments from inside a SafeYolo Codex agent using persistent tmux shell panes, reversible fault injection, UTC evidence capture, baseline restoration, and explicit teardown. Use when the operator asks to set up, drive, observe, or retain evidence from an interactive lab; do not use for ordinary one-command shell work or SafeYolo troubleshooting that does not need a tmux lab.
---

# SafeYolo lab controller

Use tmux as an inspectable Codex lab UI while SafeYolo remains the security boundary.
Keep the operator able to watch, intervene, authenticate interactively, and
inspect every transition.

When the work touches SafeYolo health, proxying, TLS, policy, credentials,
coord, guest privilege, or agent lifecycle, invoke the installed `safeyolo`
skill and follow its current guidance. This skill controls the experiment; it
does not replace SafeYolo's operational rules.

Lab is independent from the SafeYolo Demo. If an experiment needs a narrative
or source surface, use the generic Lab panes and evidence helpers described
below; do not invoke a Demo-specific workflow.

## Respect the controller bootstrap

The operator runs the installed native `safeyolo lab` entry. It asks for the
objective, provisions or selects the owned guest, checks Codex authentication,
and enters the viewer. Repeating the command reattaches to the same controller
and evidence. `--recover` restarts an owned dead controller; `--relaunch`
explicitly replaces it. No pane discovery or guest-shell bootstrap is required.

The guest `safeyolo-lab` helper remains internal terminal plumbing. It starts
one persistent controller shell and injects the recorded objective with the
base instructions. It does not adopt an unrelated session. A reconnect does
not start another controller or repeat the initial objective prompt.

Use the same guest tmux profile for a direct terminal and for a guest displayed
inside host tmux. Its `C-a` prefix avoids the common host `C-b` prefix.

Read [bootstrap.md](references/bootstrap.md) when starting, reconnecting, or
relaunching a controller.

## Preserve scope and authority

- Treat the requested experiment, mutations, and teardown as separate grants.
- Do not modify product code unless the operator explicitly includes that work.
- Keep lab configuration changes temporary, narrow, recorded, and reversible.
- Fault injection never authorizes weakening the outer SafeYolo boundary.
- Never print, inject, capture, or archive credential values. Record credential
  paths, ownership, mode, existence, provider, and authentication state only.
- Pause for operator interaction when a subscription login is required. Do not
  log that pane while login material or device codes may be visible.

## Establish the lab

1. Confirm the controller is inside tmux. Read `TMUX_PANE`, record the tmux
   socket/server identity, enumerate that server, and identify the controller
   pane before changing panes. A title alone is not identity.
2. Record the objective, pass condition, forbidden actions, expected long
   waits, instance paths, and starting health.
3. Establish a mode-0700 evidence root before the first mutation. Take an
   initial snapshot with `scripts/lab-snapshot.sh` when useful.
4. Create a pane registry containing tmux layer, server/socket, pane ID, mutable
   title, pane-local lab role, purpose, shell state, and any service or agent it
   attaches to.
5. Create each experimental pane as a normal persistent interactive shell and
   inject commands into it. Never create a pane whose shell is replaced by a
   one-shot command.
6. Run the adaptive layout helper after pane changes. Keep the controller pane
   focused unless the operator must type in another pane. A resize hook will
   adapt the layout while the operator changes terminal size.

Read [tmux-ui.md](references/tmux-ui.md) before creating, injecting into,
styling, capturing, or closing panes.

## Run experiments visibly

- Keep the parent shell alive after commands under test finish.
- Give panes short purpose-based titles. Keep raw process panes alive and
  inspectable. Use ordinary shell panes for source, requests, policy and logs
  only when the objective needs them.
- Keep raw output unchanged. Use the responsive annotation rail for an ad hoc
  observation with a stable ID, state, exact evidence fragment and explanation.
- Return focus to the controller after command injection and observation.
  Set another explicit temporary focus target for interactive login, prompts,
  or direct operator intervention. Do not steal focus while the operator uses it.
- Inject simple commands literally. Put complex or multiline command sequences
  in a reviewed script, then inject only the script path and arguments.
- Never construct a tmux command containing a credential value. Read secrets at
  use time inside the target process without echoing or persisting them.
- Add an explicit completion marker and exit-code marker when the command's
  natural output does not make completion unambiguous.
- When a command can run more than once in the same pane, give each invocation
  a unique completion marker. Wait for that exact marker as a standalone output
  line; the shell can echo marker text from the injected command before the
  command finishes. Do not count matching markers from retained scrollback.
- Run long waits inside experimental panes, not in the controller process.
  Continue concise operator updates during long experiments.
- Capture observable state before interpreting it: stdout/stderr, exit code,
  structured tool results, process tree, service health, audit/coord evidence,
  and relevant configuration.
- Do not treat model prose or exit code zero as proof of success when a more
  authoritative signal exists.

## Use controlled operator language

Use Simplified Technical English principles for live updates, pane labels,
instructions, logs, and reports. Compliance with ASD-STE100 is not required.

- Use short sentences and active voice.
- Put one action in each instruction.
- Name the actor, target, tmux layer, pane, process, and unit when ambiguity is
  possible.
- Use one stable term for each object. Do not alternate between synonyms such
  as worker, guest, agent, and pane when they identify different layers.
- Put a warning or prerequisite before the action that it controls.
- State the expected observable result after an instruction when it matters.
- Label observations, inferences, deviations, and unknown states separately.
- Avoid unclear pronouns, idioms, figurative language, and unexplained
  abbreviations.

## Use the baseline/fault/recovery cycle

For multi-phase work or fault injection, read
[experiment-protocol.md](references/experiment-protocol.md).
Copy [lab-log.md](assets/lab-log.md) into the lab workspace when a structured
run log will improve attribution or handoff.

For each fault:

1. Prove the known-good baseline.
2. Record the exact recovery action before injecting the fault.
3. Inject exactly one fault and record its UTC time.
4. Run the smallest probe that exposes it.
5. Capture evidence before repair.
6. Restore the baseline.
7. Prove recovery before proceeding.

If the baseline itself fails, diagnose it before starting further fault
injection. Do not silently work around a failed prerequisite.

## Preserve evidence

Read [evidence-retention.md](references/evidence-retention.md) before starting
continuous pane logging or packaging the lab. Use
`scripts/capture-evidence.sh` for selected text files and pane scrollback, and
use `scripts/lab-snapshot.sh` for timestamped environment snapshots.

Capture raw evidence except for credentials when the operator permits it.
Prefer metadata-only exports or product APIs for stores that can contain raw
authorization headers, cookies, request bodies, or response bodies. Take
consistent database/service snapshots rather than blindly copying active
storage.

## Coordination invariant

A coordination cursor records which attention has been exposed to the caller.
It does not prove the associated work completed. When completion matters,
observe and persist the workflow's separate authoritative completion signal.

Read [coord-liveness.md](references/coord-liveness.md) only when an experiment
uses coord waits, attention cursors, continuation turns, or work arriving while
the harness is absent. Its factory-agent section is an illustrative example,
not a prescribed workflow.

## Finish deliberately

1. Capture final health, processes, pane inventory, transcripts, and hashes.
2. Restore every reversible fault and prove the final baseline.
3. Report deviations, uncertain outcomes, and any state intentionally left
   running.
4. Close panes only when the operator authorizes teardown. Protect the
   controller pane by explicit ID. Closing a pane does not imply permission to
   stop the service or agent it was observing.
5. Return clickable evidence and report paths with integrity information when
   an archive was requested.
