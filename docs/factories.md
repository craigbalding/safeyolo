# Supervised factories

For GitHub release planning, use the [issue-planning guide](issue-planning.md).
Factory checkpoints still identify active assignments.

SafeYolo factory files are small, explicit bindings for existing supervised
agents. Markdown remains the role contract; TOML says which approved agent has
each role, which one coord room the factory uses, and which exact handoffs may
wake each worker. Factory v1 does not interpret role prose at runtime and has
no scripts, conditions, regex routes, hooks, discovery, inference, or live
reload.

## File format

The shipped backlog example is
[`docs/factories/backlog.toml`](factories/backlog.toml). Core bindings look like
this excerpt:

```toml
schema = "safeyolo.factory/v1"
name = "backlog"
room = "backlog"

[operator_input]
to = "coordinator"
types = ["ACTIVATE", "PAUSE", "RESUME", "PRIORITY", "NEXT", "DIRECTION"]

[roles.owner]
agent = "forge"
harness = "pi"
args = ["--provider", "openai-codex", "--model", "gpt-5.6-luna", "--thinking", "xhigh"]
contract = "../agent-roles/issue-owner.md"

[[handoffs]]
request = "TASK"
from = "coordinator"
to = "owner"
responses = ["DONE", "BLOCKED", "FAILED"]
response_to = ["coordinator"]
```

Contract paths are explicit and relative to the TOML file. Every role and
message type is declared literally. `TASK` retains its generic delegation
meaning, but its first line must be exactly
`TASK target=<absolute-url> assignee=<agent>`; text such as `TASK UPDATE` is
data, not a task. Other request and response bodies must begin with their exact
declared type and target. Canonical envelope identity and the configured
room—not names written in the body—authorize a handoff.

`harness` selects the supervised coding harness for that role. The supported
values are `codex` and `pi`; omission means `codex`. Harness selection changes
the execution adapter, not the factory graph, role contract, Coord identity,
checkpoint rules, handoffs, or observability.

Optional `args` are exact command arguments for the selected harness. They are
bound into the approved snapshot and override the agent's mutable default
arguments for that factory run. When omitted, the configured agent defaults
retain their existing behavior. This makes a harness switch explicit instead
of accidentally passing Codex flags to Pi (or vice versa). Credentials remain
in the harness's agent-local login state, not in factory arguments.

Optional `[[updates]]` tables declare informational message types, their `from`
and `to` roles, and exact first-line `fields`. They do not create tasks or
require terminal responses. The backlog example declares `CONTEXT target=<url>`
from the coordinator to each worker. Unknown or malformed targeted agent
messages remain visible with a protocol warning; they are not accepted as
work transitions.

An optional `[roles.NAME.repair]` table binds one stronger set of harness
`args`, its selecting `from` role and `request` type, the `after_rounds` and
`max_rounds` policy, and the outbound `release_on` handoff. The coordinator
counts repair rounds from Coord. The supervisor applies a selection to the
named active task, then returns to normal arguments at its next review handoff
or terminal result. The selection cannot choose another harness or alter
saved agent defaults. See the [supervisor protocol and repair
details](codex-coord-supervisor.md#context-messages-and-protocol-warnings).

`response_to` names every role that the destination must notify when it sends a
declared response. The source role must be included. Old v1 contracts and
snapshots without this field retain the original source-only response route.

`operator_input` is the one explicit direction edge into the graph. It admits
bounded natural-language messages only when the canonical sender kind is
`operator`, routes them only to the named role, and never treats them as agent
handoffs. The declared types are optional operator shorthand rather than a
natural-language parser; they cannot overlap a handoff request or response.
`factory check`, `approve`, and `run` reject a graph in which any role is
unreachable from that operator edge; old source-only v1 snapshots therefore
fail closed instead of starting an inert factory.

The native operator entry targets the coordinator selected by this approved
Factory. Use `factory send NAME TEXT` for natural-language direction and
`factory history NAME` for retained replies. Send requires an active,
receive-authorized room member; unknown, revoked and send-only targets fail
before acceptance. Targeting changes attention delivery. Confirmation and
history retain canonical attribution and message IDs. See the commands under
[operator direction](#operator-direction-and-ordinary-restart).

Interactive operator chat automatically resolves the coordinator bound by an
approved factory snapshot for that room. `coord chat ROOM --to AGENT` overrides
that selection. Without `--to`, a room with no approved factory keeps its
room-wide wake behavior. If multiple approved factories bind different coordinators to one
room, chat fails visibly instead of guessing. The target must be an active,
receive-authorized room member; unknown, revoked, and send-only targets fail
before the message is accepted. Targeting changes only attention delivery.
Send confirmation and operator-visible retained history show the canonical
attention mode (`targeted`, `room`, or `none`) without exposing recipient IDs
or unrelated membership. See [native operator chat](native-coord.md) for the
interactive controls.

The room brief is a separate operator-authored standing-context channel.
Canonical `brief_changed` attention updates every receive-authorized factory
role's bounded checkpoint, and preflight refreshes the current brief after a
restart. Brief updates are not handoffs: they create no in-flight request,
need no terminal response, and cause no automatic runtime transition.

## Authority and intake

An approved factory retains the following state:

- The approved immutable snapshot binds the room, operator edge, role and agent
  bindings, handoffs, context routes, repair policy, and exact bytes and SHA-256 of every Markdown
  role contract. Approval selects the snapshot that the next `factory run`
  will use; it does not alter running agents.
- Each running role uses the exact snapshot last staged into that agent by
  `factory run`. Until the next run, this can differ from the newly approved
  snapshot.
- `factory doctor` compares each staged role, supervisor, command and harness
  adapter with the selected approved content. It shows a valid retained staged
  binding separately. A mismatch prevents readiness
  for that selection. Approval does not establish the running process's identity.
- The canonical trusted room brief is live operator-authored state. The brief
  is not part of the snapshot and can change by revision while the snapshot
  stays the same.

The declared operator types admit messages to the coordinator. The types do
not define a workflow. Read the exact bound coordinator contract to determine
what `ACTIVATE`, `RESUME`, `NEXT`, and `PRIORITY` mean. `factory check` prints
the source path and hash for every role contract. Read each file directly;
SafeYolo does not generate an interpretation of contract text.

For the shipped backlog factory, `ACTIVATE` and `RESUME` start continuous
intake. Relay proactively discovers and prioritizes work in the
operator-authorized repositories. `NEXT` and `PRIORITY` can override ordinary
ordering for eligible work. A trusted brief may refine standing priorities or
constraints, but the backlog factory does not require one.

## Fresh setup, check, approve, and run

Use the [installed native product](native-policy.md#install-and-start) on the
owning host account. Its guest runtime must be prepared for that host.
Preparation requires a running proxy; the `start` command below starts it.
Select an operator-authored Factory TOML and the workspaces for its roles.
Each role keeps its own home and authentication;
SafeYolo does not copy the host's login or credentials.

The commands in this guide use the installation at `$HOME/.safeyolo`. If your
installed instance uses another root, replace that path in both the executable
and `--root` argument. Keep using the same host account and instance.

Run the example from the SafeYolo repository root containing
`docs/factories/backlog.toml`. The example uses that contract and three existing
owned repository workspaces at `/work/relay`, `/work/forge` and `/work/lens`. Replace
those paths with your selected directories. Keep the installation outside the
agents' writable workspaces. The contract selects the role agents, harnesses,
models, instructions and allowed handoffs.

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory check docs/factories/backlog.toml
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory approve docs/factories/backlog.toml
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" start
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory prepare backlog --workspace coordinator=/work/relay --workspace owner=/work/forge --workspace reviewer=/work/lens
```

`check` validates the contract and displays each role's exact content identity.
`approve` asks for operator approval and selects that immutable snapshot; use
`--yes` for an explicit noninteractive approval. Neither command starts a
Factory. `prepare` creates or checks the declared agents and their staging,
shared room, private agent rooms and required send/receive grants. Existing
room history and unrelated memberships remain. It starts no model.

Establish each role's own login through the native entry. For the shipped
contract, authenticate the coordinator, owner and reviewer:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory login backlog coordinator
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory login backlog owner
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory login backlog reviewer
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory run backlog
```

Codex uses its device login and explicit agent-local adoption. Pi opens its
normal interactive client; use `/login` for its selected provider, then exit.
The entry stops the login sandbox afterward and keeps that role's installed
tools and login. Provider configuration remains an operator choice. An
existing supported external-provider configuration can supply authentication
without another login.

`run` stages the approved supervised roles, provisions missing declared room
access and starts them through the existing native agent lifecycle. It reports
`Started Factory` only after observed runtime, role binding, executable,
authentication, checkpoint and room checks pass. Approval alone is not
readiness. If a role is already running, its staging must match the selected
snapshot; run reuses its existing launch. Stop the Factory before changing a
workspace or selecting different role instructions.

Native preparation checks workspace ownership. Use
`--dangerously-allow-unowned` only when you intentionally share an unowned
workspace. Agent memory, additional mounts and direct recovery remain available
through the native `agent` commands; the Factory does not grant itself host
privileges.

## Operator direction and ordinary restart

After readiness, send natural-language direction to the role selected by the
approved `operator_input` binding. The message is canonically attributed to the
local operator and wakes that role only:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory send backlog 'Inspect the disposable repository and repair its failing fixture test.'
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory history backlog
```

For an interactive terminal conversation in the same instance, use native
chat. The approved snapshot selects the coordinator without pane discovery:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" coord chat backlog
```

History returns canonical message IDs, senders and sequences. Use
`--since SEQUENCE` to read the next retained page. Reading history does not
assign work. Work completion comes from the correlated handoff and its
independent result, together with the changed artifact and test.

Stop and restart the same newly created Factory:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory stop backlog
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory run backlog
```

Stop affects the selected role runtimes. It retains the approved contract,
agent identities, role homes, supervisor checkpoints and existing Coord
messages. It leaves the instance proxy, Coord transport and unrelated agents
running. Restart uses those same records; completed work is not a new task.
This is continuity within fresh native state. Old Python state is not imported
or converted.

## Direct diagnosis and recovery

Use the read-only diagnosis when readiness fails:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory doctor backlog
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" agent diagnostics forge
```

Doctor names the failed role or room and reports its actual runtime and
checkpoint. A valid older staged binding is shown separately from the approved
selection. A missing model executable or room permission is a readiness
failure. Correct that input, stop affected roles, then repeat `factory run`.
Use `factory prepare` with the selected workspace arguments to repair declared
agents and grants. Failed startup retains reached role state and evidence for
diagnosis; it does not report a running Factory or delete unrelated work.
Pending human decisions remain visible through the normal operator approval
commands and [native inspect](native-operator.md). Doctor reports pending
Factory decisions as warnings; they do not prevent readiness or instruct the
operator to approve them.

The snapshot stores every role contract's exact UTF-8 bytes, byte count and
hash under `ROOT/factories/NAME/snapshots/`. The `approved` pointer selects the
next run. Editing a source TOML or Markdown file does not change that snapshot
or a running worker. Check and approve the changed content explicitly.

## Release stuck work after stopping its agents

Use `factory release` when a stopped supervisor still holds an assignment that
the operator wants to abandon. Stop each affected agent with `safeyolo agent
stop NAME` first. Select the exact target URL from the retained assignment:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory release backlog --target https://github.com/craigbalding/safeyolo/issues/123
```

The command shows the selected targets and matching record counts for each
agent, then asks for confirmation. `--yes` confirms that same selection without
prompting. Repeat `--target` to include related review targets. SafeYolo does
not infer relationships between an issue URL and a pull-request commit URL.
If the records belong to a previous room, use `--room ORIGINAL_ROOM`; the
approved factory still selects which agents to inspect.

Only matching records in the selected room are released. Other work, attention
cursors, briefs, files, and room history remain. Released inbound attention IDs
remain in the existing duplicate-detection history. Affected harness sessions
start fresh on their next invocation, using the remaining checkpointed work.
The command neither reports `DONE` nor starts an agent.

Each changed checkpoint has a byte-for-byte backup beside it, named
`coord-supervisor-state.before-release-OPERATION_ID.json`. Coord records
the operator's request before checkpoint changes and completion afterward,
with no agent notification. If the request cannot be recorded, no work is
released. If a later write or completion message fails, the command reports
which agents changed and the backup paths. Keep them stopped, inspect the
checkpoints, and repeat the same selection if records remain. Do not restore
a whole backup after agents have resumed: it can restore already completed
work or discard newer state.

This is checkpoint recovery, not live cancellation or a durable Coord work
object. It does not consume assignments still waiting in the attention feed,
stop external jobs, or undo published changes. Resume only the intended agents
after recovery. Stop the roles before changing their staged instructions or workspaces.

## Diagnose an approved or running factory

Use the [native diagnosis and recovery commands](#direct-diagnosis-and-recovery).
The approved snapshot and each staged role binding are checked separately.
A stopped Factory has retained configuration and checkpoints, but is not ready.
A trusted room brief carries operator-owned live context; it does not approve
new role contracts or establish runtime readiness.


## Optional backlog eligibility brief

The following short template records the operator's standing selection rules.
Replace every placeholder with an exact value. The template is Markdown for
the operator and coordinator; SafeYolo does not parse it as workflow
configuration.

```markdown
# Backlog eligibility

- Repository: `<owner>/<repository>`
- GitHub identity: login `<exact-login>`, stable user ID `<exact-id>`
- Required identity relationship: `<issue author, assignee, or other exact relationship>`
- Include: `<exact issue state, labels, or other required filters>`
- Exclude: `<pull requests, tracking issues, blocked work, and other exclusions>`
- Maximum concurrent work: `<number>`
- Immediate revalidation: Recheck every required fact immediately before delegation.
- Ordering: `<exact default order>`
- `NEXT` override: `<exact filters that NEXT may override, or none>`
- `PRIORITY` override: `<exact filters that PRIORITY may override, or none>`
- Fail-safe: If any required fact cannot be established, do not delegate. Wait for operator direction.
```

State the identity relationship, not only the identity. State override
semantics separately for `NEXT` and `PRIORITY`. An override does not bypass an
unstated filter. Keep no more work in flight than the stated maximum.

## Reconfigure a native Factory

Stop the Factory before selecting changed role contracts or workspaces. Check
and approve the changed TOML and role Markdown, then run the same Factory. The
entry preserves existing role homes, identities, checkpoints and Coord history.
It does not convert old Python product state or legacy supervisor checkpoints.
A refused checkpoint remains available for direct inspection and recovery.

To restore an earlier native contract, stop the roles, check and approve that
contract and its exact role Markdown, then run again. Approval selects content;
it does not cancel outstanding work or grant a different role authority over it.
Resolve any affected assignments through their existing handoffs or explicit
stopped-work release before changing their authority.
