---
name: safeyolo-demo-lab
description: Guide operator-visible, hands-on demonstrations in a SafeYolo Codex tmux lab that teach how SafeYolo works, including its boundary, request path, agents, guest tools, coord, addons, and recovery behavior. Use when the operator asks to learn, tour, demonstrate, or explore SafeYolo through experiments, or to test a SafeYolo addon change as a learning exercise; do not use for ordinary troubleshooting or a lab unrelated to SafeYolo.
---

# SafeYolo demo lab

Teach SafeYolo through visible evidence and small experiments that matter to
the learner. Keep the operator in control of the pace, depth, participation,
and mutations.

## Layer the demo on the lab

Use the installed `safeyolo-lab-controller` skill for tmux, evidence,
reversible changes, and teardown. Use the installed `safeyolo` skill for the
current security boundary, operational interfaces, and topic-specific
references. This skill supplies the teaching flow; it does not duplicate or
override either skill.

Confirm that the controller runs in the intended guest tmux session before the
first demonstration action. If it does not, ask the operator to enter the agent
and run the single `safeyolo-lab` command. Do not create a second lab UI.

## Lead with enablement

Use this product premise at the start of a learning experience: SafeYolo gives
an agent a real Linux environment and normal tools so it can do useful work,
while the operator controls what crosses the boundary and remains able to
steer. The sandbox limits the blast radius; it is not intended to hobble the
agent.

Show that premise before explaining architecture. Choose one small result that
matters to the learner. Let the agent use an ordinary CLI, SDK, browser, test,
debugger, package, local service, or web service as the task requires. Then
show the SafeYolo control or evidence that mattered to that result.

Do not present SafeYolo as a collection of warnings or as a replacement for
normal software with a small approved tool set. A learner's first question is
usually "How can my agent do useful things?" Answer it with visible work.

## Fit the lab to the learner

Form a working learner profile from the conversation before asking a question.
Keep these factors separate:

- the outcome the learner wants, such as using an agent, understanding a
  decision, operating or recovering SafeYolo, testing an addon, or evaluating
  the security boundary;
- SafeYolo familiarity;
- Linux and command-line familiarity; and
- whether the learner wants to watch, drive, or alternate; and
- the experiment intensity the operator accepts: observe, exercise, change, or
  deliberately break and recover.

Do not ask the learner to score their expertise. Do not repeat questions that
the conversation already answers. When a missing detail changes the first
experiment, ask at most one natural question. For example: "What would you
like SafeYolo to help you do, and would you prefer to watch or drive?"

Adapt the experience without making the adaptation conspicuous:

- For a new SafeYolo user, show a useful result first. Introduce one product
  term at a time and connect it to evidence that is already visible.
- For a familiar operator, skip basic definitions and focus on decisions,
  controls, evidence, and recovery.
- For a Linux beginner, use one command at a time, explain its purpose in
  plain language, and do not make command syntax the lesson.
- For a command-line expert, keep explanations compact and preserve useful raw
  output.

Never infer SafeYolo familiarity from Linux skill, or Linux skill from product
vocabulary.

The operator owns experiment risk inside the fixed SafeYolo security boundary.
Do not silently reduce an authorized change or fault drill to a read-only tour.
Use a read-only default only when the conversation gives no stronger signal.

If the learner has no specific topic, offer at most three outcome-shaped
starting points. Default to the smallest useful result that fits the known
operator scope. Use a read-only result only when the conversation gives no
mutation authority. Do not open with a system inventory, health checklist, or
architecture lecture unless the learner asks about the boundary or the action
needs prerequisite diagnosis.

Read [demo-catalog.md](references/demo-catalog.md) when selecting or structuring
a demonstration. Choose one module, not the complete catalog.

Read [structured-lessons.md](references/structured-lessons.md) when the learner
will benefit from an ordered lesson, several related evidence records, or a
stable page that puts evidence beside its meaning. Keep tmux as the process
substrate. Do not make tmux or lesson navigation a learner prerequisite.
Presenterm is optional. If a structured lesson needs it and it is absent, use
the checksum-pinned installer described in that reference. State the persistent
user tool installation before you run it.

For the follow-one-request module, run
[`scripts/request-story.sh`](scripts/request-story.sh) visibly in a persistent
pane. Use `--brief` for a new learner and `--full` for an experienced operator.
Pass a relevant host when one is already in scope; otherwise the script uses
`example.com`. Do not rebuild its credential-safe request and trace sequence.
The script keeps the trace values as observed, then renders a separate teaching
view. The teaching view explains `state=evaluated` once and gives every returned
step an `observed` line and a nearby `meaning` line. Treat the first as evidence
and the second as an interpretation of SafeYolo's stable trace vocabulary.

For the optional boundary and orientation module, run
[`scripts/boundary-orientation.sh`](scripts/boundary-orientation.sh) visibly in
a persistent pane. Do not rebuild its credential-safe probe as an injected
multiline command.

## Use an observation cycle

For each small demonstration:

1. Connect the experiment to the learner's desired outcome.
2. State the plain-language question that the action will answer.
3. Name the pane and action.
4. State the expected observable result without claiming it will occur.
5. Run the action visibly in a persistent shell pane, or invite the learner to
   run it when they chose to drive.
6. Show the relevant evidence.
7. Separate observation from inference.
8. Explain what the evidence teaches about SafeYolo at the selected depth.
9. Offer to zoom in, try one variation, or move to the next useful question.

Keep explanations close to the evidence. Prefer a small live result over a
long architecture lecture. Explain a Linux command only to the depth that
helps this learner understand or control the experiment. Show ordinary public
content and relevant non-credential security evidence instead of replacing it
with vague summaries. Explain what is sensitive and what is not. Do not hide
setup, failures, retries, or recovery actions from the operator.

When one output contains several related evidence records, use a structured
lesson page or put a compact teaching view immediately after the raw records.
Label observations and explanations separately. Keep real values visible. Use
the tmux annotation rail only for an ad hoc point in raw output. Do not make it
the primary navigation method for an ordered lesson.

## Keep the boundaries clear

Distinguish three boundaries once, then refer to them only when they affect an
action:

- **Product boundary:** the agent works inside its SafeYolo guest and external
  access uses SafeYolo's mediated path. Do not weaken or bypass this boundary,
  request the admin token, or use the host admin API from the guest.
- **Experiment scope:** the operator owns targets, permitted reads and
  changes, fault intensity, evidence retention, and teardown. Treat agent or
  room lifecycle, addon or product changes, host actions, and fault injection
  as separate grants. Do not narrow a grant because of the controller's own
  risk preference.
- **Evidence boundary:** show real evidence and explain it. Never expose actual
  bearer or token values. This includes the agent token, literal `sgw_`
  capability tokens, authorization values, session cookies, and raw token
  fields. Show field names, token type and length, ownership, scope, presence,
  counts, bindings, and enforcement results when useful.

Do not repeat generic security warnings during ordinary steps. Put a warning or
approval request immediately before the action it controls.

Do not over-sanitize evidence. Hostnames, request IDs, policy effects, budgets,
credential fingerprints, addon outcomes, and ordinary public website content
are not credentials merely because they are security related. Show them when
relevant. A `/policy` lesson can show its real non-credential rules and
structure; omit and label only actual capability-token and raw-token values.

Teach the `sgw_` distinction precisely when scoped service access is relevant.
An `sgw_` value is a scoped bearer capability credential, not the upstream
service credential. Do not hide the gateway section or describe the mechanism
as an opaque secret. Show the `sgw_` token type without its bearer suffix, the
owning agent, service, capability, account, permitted route, risk grant,
contract binding, grant state, and the observed allow or deny result. This is
the evidence that lets a learner understand and evaluate the scope.

For a destructive or fault-injection demo, prefer a disposable or nested
target. Never use the controller pane as the fault target. Establish the
baseline and exact recovery first, then restore and prove the baseline before
moving on.

If a capability needs an operator-side command or approval, explain why, give
the narrow action, and state the expected result.

An unavailable capability can be a useful observation. Report the exact
boundary or blocker. Do not silently replace the intended demonstration with a
different mechanism.

## Complete one learning unit

End a module with a short recap:

- what the operator observed;
- which SafeYolo mechanism the evidence supports;
- what remains unknown;
- which state changed and whether it was restored; and
- one optional next experiment.

Do not turn the recap into a command diary. Preserve evidence only to the level
the operator requested.
