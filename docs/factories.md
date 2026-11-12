# Supervised factories

For GitHub release planning, use the [issue-planning guide](issue-planning.md).
Native Work records identify native assignments; supervisor checkpoints retain
delivery and session recovery state.

SafeYolo factory files are small, explicit bindings for existing supervised
agents. Markdown remains the role contract; TOML says which approved agent has
each role, which one Coord room the factory uses, and which message handoffs
or native work policy apply. Factory v1 does not interpret role prose at runtime and has
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
For a message-only Factory, `factory check`, `approve`, and `run` reject a graph
in which any role is unreachable from that operator edge. A Factory with
`[work]` can receive native assignments without a message route to every role.

The operator entry targets the coordinator selected by this approved
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
or unrelated membership. See [operator chat](coord-operations.md) for the
interactive controls.

The room brief is a separate operator-authored standing-context channel.
Canonical `brief_changed` attention updates every receive-authorized factory
role's bounded checkpoint, and preflight refreshes the current brief after a
restart. Brief updates are not handoffs: they create no in-flight request,
need no terminal response, and cause no automatic runtime transition.
Use [the brief commands](coord-operations.md#read-and-update-a-trusted-brief)
to read or replace that context with an explicit expected revision.

## Authority and intake

Use native work claims for durable ownership and `publish_work_output` for the
holder's exact output and attributed execution outcome. The producer retains
the external artifact first. Reassignment and cancellation fence uncommitted
publication attempts; an operation-ID retry recovers a previously committed
receipt. See [work publication and recovery](coord-reference.md#claims-outputs-and-attestations).
These operations are also available to an operator-directed interactive worker
through that worker's authenticated Coord client.

Native output publication does not send a message handoff. With `[work]`, the
approved snapshot enables [native work delivery](codex-coord-supervisor.md#native-work-delivery)
for its supervised roles and selects the policy described below. Native Work
mutations settle that lifecycle; no parallel `TASK` or `REVIEW_READY` record is
required. A Factory without `[work]` retains its declared message protocol.
An explicitly configured message assignment still requires its declared reply.

Native checks and peer challenges retain the selected participants and enforce
independence from the actual producer. The [public review loop](coord-reference.md#assigned-checks-and-peer-challenges)
also supports work created outside a Factory with explicitly selected
[requirements and deciding participants](coord-reference.md#select-requirements-and-decide-output-acceptance).
Direct callers use the same authority. Execution completion, challenge
resolution and attestation counts do not substitute for an eligible acceptance
decision about the current output.

### Select native work policy

For the existing backlog instance, the
[native adoption proposal](factories/backlog-native-adoption.md) supplies a
complete TOML/role set and stopped-boundary application and rollback steps.
It is a review candidate, not a claim that the live factory uses that selection.

For a new or stopped Factory, add `[work]` to its operator-authored TOML before
approval. The following complete example supervises only Bob as reviewer.
Alice is an ordinary interactive agent with send/receive access to the same
room. Alice has no Factory supervisor. Supply `reviewer.md` beside this file
with instructions to inspect exact artifacts, answer assigned checks, dispose
of challenges explicitly and decide acceptance from current native evidence.

```toml
schema = "safeyolo.factory/v1"
name = "reports"
room = "reports"

[roles.reviewer]
agent = "bob"
contract = "reviewer.md"

[operator_input]
to = "reviewer"
types = ["DIRECTION"]

[work]
authorities = ["reviewer"]
deciders = ["reviewer"]
independent = true

[[work.checks]]
reviewer = "reviewer"
criterion = "Verify the exact report against the requested result"
independent = true
```

`creators`, `authorities` and `deciders` name declared roles, not supplied actor
IDs. The server resolves them from the instance's configured durable agent
identities. Omitted `creators` allows only the operator to create work with this
selection. Omitted `authorities` reserves amendments to the operator. At least
one `decider` is required. Both independence flags default to `false`; each
check selects its own independence separately from output acceptance.
`handoffs` can be omitted when all assignments use native work.
Selected policy and generated requirements use the existing 32 KiB serialized
review-record limit. An oversized mutation is refused atomically; retained
external artifacts remain available.

After approval, use the exact selected snapshot hash with `create_work`:
`factory={"name":"reports","snapshot_id":"HASH"}`. On the owning host, use
`coord work create ROOM TITLE --factory JSON --assignee JSON`. Obtain the hash
from `ROOT/factories/reports/approved` and Alice's durable ID from her grant
receipt. The operator can create from the owning host. An agent needs room send
and receive access and one selected creator role. A stale snapshot or wrong room
is refused.
Omitting `factory` creates generic work; it does not modify an existing selected
work item or satisfy an application's selected Work ID.

Creation retains the snapshot reference, resolved participants, check templates
and versioned acceptance requirements in native Work. Each output publication
atomically creates and selects an exact-output check for every template. The
publication receipt includes those IDs in `factory.current_checks`. Retrying
the same operation returns that receipt without creating more checks. A
replacement output creates new checks and replaces only the previous generated
requirements. Earlier checks and all explicitly selected challenges remain
recorded. Additional explicitly selected checks remain required.

Existing selected authorities or the operator can amend requirements with a
reason, including explicit delegation to a worker. Ownership alone grants no
amendment authority. An amendment affects current acceptance; the next output
publication applies the retained check templates again. Approving a new Factory
snapshot does not silently change existing Work policy. Optional checks and
advisory challenges remain optional until an authorized requirements amendment
selects them. There is no universal objection veto.

Publication can retain a correction even when a configured reviewer is
unavailable or is its actual producer. The independent check remains pending
and cannot be answered by that producer. The operator can reassign review work
or recover selected authority through the existing native commands. Read
`acceptance_status` for the unmet obligation. An interactive worker uses its
own authenticated client while the reviewer uses its one supervisor; assignment
never starts a second controller. See the [executable interactive example](coord-operations.md#share-work-with-an-interactive-producer).

An approved factory retains the following state:

- The approved immutable snapshot binds the room, operator edge, role and agent
  bindings, handoffs, native work policy, context routes, repair policy, and exact bytes and SHA-256 of every Markdown
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
  stays the same. `factory doctor NAME` reports `room-brief` as `none`, or
  `present` with its exact revision and content hash. Doctor does not print
  or interpret the Markdown. No brief is a valid state and does not prevent
  readiness. If the store or room cannot be read, doctor reports `unavailable`
  with a warning instead of claiming absence.

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

## Guided setup

Use `factory setup` on the owning host account with a prepared, installed
SafeYolo instance. Supply your operator-authored Factory TOML. The entry uses
the declared agents, harnesses, contracts and room permissions. It does not
write Factory policy or change the supervision protocol.

The following example runs from the SafeYolo repository root. It selects the
installation at `$HOME/.safeyolo`, the shipped backlog contract and three owned
repository directories. Replace `/work/relay`, `/work/forge` and `/work/lens`
with your selected workspaces. Keep the installation outside those workspaces.
If you use another instance, change both the executable and `--root` path.

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" start
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory setup docs/factories/backlog.toml --workspace coordinator=/work/relay --workspace owner=/work/forge --workspace reviewer=/work/lens
```

Setup shows the selected root, exact snapshot, role identities and workspaces.
Before a new approval, it shows the previous and selected contract content,
including exact role instructions and harness arguments. The approval selects
that immutable snapshot. Approval alone does not establish readiness.

In a terminal, setup asks for missing workspaces and the existing snapshot
approval. It prepares declared roles and room grants through `prepare`, then
checks the existing checkpoint prerequisite. For missing checkpoints, confirm
fresh identities only when those identities or memberships have never received
targeted attention in any configured room. Clearing messages does not reset
attention. A valid checkpoint needs no fresh-identity confirmation.

Setup checks each role's own installed harness and authentication in a sandbox
without running a model turn. If a role needs authentication, choose its own
login, or return and configure its supported external provider. No host or peer
credentials are copied. A valid supported external-provider configuration is
reused. Setup then starts supervised roles through `run` and reports `running`
only after the existing doctor checks observe all roles ready.

Repeat the same setup command after an interruption. Saved workspaces, agent
identities, homes and valid staging are reused. Setup leaves healthy running
roles running. If a role's workspace or staging differs, setup uses the existing
stopped-role preparation checks. It refuses to replace live bindings. Stop the
affected roles before changing their instructions or workspace.

### Automation and recovery

For a read-only JSON preview, append `--preview` to the setup command. The
preview includes exact previous and selected contracts and current role
observations. It does not approve, stage, authenticate or start roles, even if
action flags are also supplied. Authentication is `unverified` until the
role's actual preflight succeeds.

For noninteractive setup, supply every missing `--workspace ROLE=PATH`.
Use `--yes` for explicit snapshot approval. This option does not confirm fresh
identities. Supply `--confirm-fresh-identity` separately only under the condition
described above. Use `--login ROLE` to select an explicit role-local login;
interactive authentication still needs a terminal. Each login stops its
authentication sandbox afterward. The separate `factory login` commands remain
available.

Setup reports completed observations and an outstanding prerequisite when it
cannot continue. Earlier role preparation or starts can remain complete; the
operation is not an atomic multi-role transaction. Use the reported root and
source path for recovery:

| Report | Next action |
|---|---|
| `approval-required` | Inspect the exact preview and use the existing approval decision. A changed source is not silently selected. |
| `workspace-required` | Repeat setup with the named role's workspace. |
| `preparation-incomplete` | Inspect the named staging, identity or runtime difference. Preserve unknown live state and use the existing stop or agent recovery path. Approval can select future instructions while roles run; staging changed instructions still requires the affected roles to stop. |
| `checkpoint-required` | For a missing checkpoint, satisfy the existing fresh-identity rule. For an invalid retained checkpoint, inspect the named agent; do not delete history to manufacture freshness. |
| `authentication-required` | Correct the named harness, authentication or Coord preflight failure. Use that role's login or supported provider configuration, then repeat setup. This report does not prove provider access. |
| `start-incomplete` | Inspect `factory doctor NAME` for the same instance. Preserve started roles and checkpoints, correct the failed prerequisite, then repeat setup. |

If setup reports that the instance proxy is stopped, start that instance and
repeat setup. A failed observation remains an error, rather than evidence of
an absent or stopped runtime. Use [agent recovery](operator-guide.md#recover-from-a-failed-operation)
for the specific agent when needed. The explicit operations below remain
available for detailed control and diagnosis.

## Fresh setup, check, approve, and run

Use the [installed product](installation.md#install-and-start) on the
owning host account. Its guest runtime must be prepared for that host.
Preparation requires a running proxy; the `start` command below starts it.
Select an operator-authored Factory TOML and the workspaces for its roles.
Each role keeps its own home and authentication;
SafeYolo does not copy the host's login or credentials.

For a first supervised start, each role with a missing checkpoint must use a
fresh agent identity or fresh room memberships that have never received
targeted attention in any configured room. Existing-identity migration is
unsupported. Prepare and activate supervision before sending the first
targeted task or operator direction. Clearing room messages does not reset
the identity-wide attention feed.

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

Establish each role's own login through the entry. For the shipped
contract, authenticate the coordinator, owner and reviewer:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory login backlog coordinator
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory login backlog owner
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory login backlog reviewer
```

Codex uses its device login and explicit agent-local adoption. Pi opens its
normal interactive client; use `/login` for its selected provider, then exit.
The entry stops the login sandbox afterward and keeps that role's installed
tools and login. Provider configuration remains an operator choice. An
existing supported external-provider configuration can supply authentication
without another login.

For the first run, explicitly confirm that the roles with missing checkpoints
are fresh as described above. On the same host account and instance, run:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory run backlog --confirm-fresh-identity
```

The confirmation applies only to this launch; it is not stored in the
contract or supervisor configuration. Without confirmation, a missing
checkpoint refuses startup before any role starts, makes supervisor Coord
calls, performs model work or saves an initial checkpoint. Refusal leaves no
checkpoint that could bypass confirmation on retry. Valid checkpoints resume
without this option, and preparation reapplication preserves their state.

`run` stages the approved supervised roles, provisions missing declared room
access and starts them through the existing agent lifecycle. It reports
`Started Factory` only after observed runtime, role binding, executable,
authentication, checkpoint and room checks pass. Approval alone is not
readiness. If a role is already running, its staging must match the selected
snapshot; run reuses its existing launch. Stop the Factory before changing a
workspace or selecting different role instructions.

Preparation checks workspace ownership. Use
`--dangerously-allow-unowned` only when you intentionally share an unowned
workspace. Agent memory, additional mounts and direct recovery remain available
through the `agent` commands; the Factory does not grant itself host
privileges.

## Operator direction and ordinary restart

After readiness, send natural-language direction to the role selected by the
approved `operator_input` binding. The message is canonically attributed to the
local operator and wakes that role only:

```sh
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory send backlog 'Inspect the disposable repository and repair its failing fixture test.'
"$HOME/.safeyolo/bin/safeyolo" --root "$HOME/.safeyolo" factory history backlog
```

For an interactive terminal conversation in the same instance, use chat.
The approved snapshot selects the coordinator without pane discovery:

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
This is continuity within fresh state. Old Python state is not imported
or converted.

### Delegate direction to an operator agent

A host operator can separately grant an agent permission to send selected
directions to an approved factory. The agent remains the canonical sender.
Room membership, a factory role and peer repair permission grant no direction
authority. The destination instance owns the grant and factory state.

For an operator agent on instance A and a factory on instance B, first
[configure scoped NATS connectivity](coord-reference.md#collaborate-through-a-home-safeyolo).
On B, approve the factory and obtain its snapshot ID from
`ROOT_B/factories/NAME/approved`. Obtain the operator-input agent's durable ID
from B's `agent status` command. In a [support proposal](peer-support.md), select
that agent as a target. Add this separate field to the proposal's `grant`.
Replace the factory name, snapshot ID and direction types with B's approved
selection:

```json
"factory_directions": [{
  "factory": "selected",
  "snapshot_id": "FULL_APPROVED_SNAPSHOT_ID",
  "types": ["DIRECTION"]
}]
```

Use B's `support preview` and `support apply` commands. A remote manager uses
the proposal's `support_instance_id` and its own durable agent ID. The preview
binds B's current peer trust epoch. An unrelated factory, changed snapshot or
unselected direction type is refused. Reapproving a changed factory requires
a new grant preview. Grant expiry and revocation use the existing support
commands.

Inside A's designated operator agent, call `support_grants(home="primary")`.
Use the returned B instance ID, target ID and grant name. Inspect the target's
current run with an ordinary support inspection. Submit the following typed
operation with `support_operation`, using that run as `expected_run`:

```json
{
  "action": "factory_direction",
  "factory": "selected",
  "snapshot_id": "FULL_APPROVED_SNAPSHOT_ID",
  "kind": "DIRECTION",
  "text": "Progress the original assignment and preserve its required checks."
}
```

Select `operation_id` before submission. After a lost reply, read the original
receipt with `read_support_operation` and the same home. A duplicate operation
does not publish another direction. An unconfirmed publication is not replayed.
The canonical envelope retains the initiating instance, agent, run, support
grant and approved snapshot. The supervisor admits that direction only for its
selected snapshot and operator-input role. It does not relabel the agent as a
human operator or require a protocol terminal reply for the direction.

The `factory_state` action takes the same `factory` and `snapshot_id` fields.
It reports the selected factory's role identities and observed runtime states.
Read inbound work and current assignments through separately authorized Coord
room access. Use the existing native work, check, challenge and acceptance
operations. Factory direction grants none of their actor privileges.

Approval decisions require a separate
[deciding delegation on B](delegated-approvals.md#remote-reviewers).
The existing [private attention interface](peer-support.md) can retain selected
operational and approval references from B alongside A's attention. Persist each
instance's verified cursor. After a manager restart, reconcile B's pending
approvals and original work ownership before another action. A missing source
is unavailable; it is not evidence that its worker stopped.

Guest administration can exercise a managed worker's own Coord and deciding
permissions. Administration of both producer and reviewer is common
administrative control. Keep any required independently controlled acceptance
decider outside the manager's administration. Exchange files through authorized
guest-file operations, a selected artifact mechanism or an explicitly shared
project directory. Do not share host administration state or an operator home.

Use the existing owners throughout the task:

1. Inspect inbound work, the current assignment and the factory state. Claim
   and progress work through the existing native Work operations. Preserve
   current ownership and configured actor checks.
2. Send a selected direction under the operator agent's own identity. Read and
   decide eligible approvals through B's separate deciding delegation. Keep
   exceptions available to B's human operator without making unrelated human
   exceptions a prerequisite of authorized work.
3. Receive selected operational events through the private attention path.
   Inspect an interruption through common support operations, repair its cause
   and verify the worker's current run and progress. Reconcile the original
   assignment before another action.
4. After restart or reconnect, retain the original task, operation IDs and
   verified per-instance cursors. Read uncertain operation receipts and current
   effects before any further mutation. An observation timeout leaves coverage
   unverified; it does not establish a product failure or justify repeating an
   effect.
5. Exchange the selected files, publish the result once and preserve required
   checks, challenges and acceptance decisions. Give the human a concise update
   from canonical state and attributable operation results. Keep sensitive
   worker output out of shared status messages.

### Tested operator journey

The 8 November 2026 installed journey used an actual native Codex 0.163.0
operator on A and factory `operator1449` with producer and reviewer agents
owned by B:

| Instance | Linux VM | Durable instance ID | Roles |
| --- | --- | --- | --- |
| A | `sy-1050-connected-8029-amd64` | `sy-1e6e5f245167414590a022a1e48bdd01` | `support1452` operator |
| B | `sy-239-clean-6728` | `sy-c0e0c53812754bb4b6a75b9bae0c6c9f` | `producer1449`, `reviewer1449` |

These were two distinct AMD64 Linux OS VMs on one Devstack physical hypervisor.
The instances used native TLS NATS request/reply and events, and gVisor systrap
guests. The journey reuses the accepted multi-instance transport and backend
proof for [#1452](https://github.com/craigbalding/safeyolo/issues/1452).
This observation does not establish two physical hosts, full factory nesting
or an additional macOS backend run.

The actual installed inputs were mixed source/debug fragments:

| Consumer | Source commit | Profile |
| --- | --- | --- |
| A and B host CLI/proxy; A MCP client | `e340a9340b3203219eccf4b01ccbaa6c751998c1` | debug |
| B producer and reviewer supervisor/MCP consumers | `a8f6c2dfe2d29c35e6185b915206a24b4ff76b93` | debug |
| Guest helper | `4ca3cafa995e47598d7bf39a2d64d786b81aceba` | debug |

The B consumer repair delivers private roomless approval references through
the existing supervisor checkpoint. The approval, support and native Work
owners are unchanged between the first two source revisions. These results
establish the exercised source behavior, not a complete shipping package.

A sent an attributed selected direction, decided B's artifact-access approval
and progressed the original Work. B's surviving operational observer delivered
the controlled supervisor failure to A through attention. A diagnosed and
restored the truncated configuration, then resumed the same producer sandbox
run. Independent B observation verified the restored configuration, live
consumer and subsequent output. The first 45-second collection expired before
the real five-retry terminal at 130.815 seconds; retained results supplied that
observation without another fault injection. Uncertain restart receipts stayed
`outcome_unknown` despite the separately observed recovery.

The fixture owner then restarted A's operator sandbox. A resumed the same
native model session with its original Work, claim and per-instance positions.
Input `[17,25,-6]` produced the 11-byte answer `{"sum":36}` followed by a newline.
The original
Work completed at version 5, claim generation 1 and output generation 1, with
one publication. The B reviewer read and hashed the actual input and output
through its read-only `/task` mount, computed the sum and supplied the current
required check and acceptance decision. A's grants excluded that reviewer
from direct and indirect administration; independence here is from A, not
from the human fixture owner.

Focused controls refused an ungranted agent, an unrelated factory, an
unselected direction type, a changed snapshot and out-of-scope approval
access. Post-revocation reads and operations were also refused. An out-of-scope
approval read returned HTTP 404; its valid decision request returned the
deliberate generic HTTP 409 without an effect. See the
[remote approval refusal behavior](delegated-approvals.md#remote-reviewers).

A published an attributable human update. Both test human exceptions remained
pending during the journey; B's owner rejected them during cleanup. Cleanup
revoked the two test scopes, removed the two added A memberships, stopped the
four owned test roles, and removed imported per-run credentials and three
copied role login files. Original logins, services, other grants, task bytes
and retained proof were preserved.

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
commands and [inspect](operator-guide.md). Doctor reports pending
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

Use the [diagnosis and recovery commands](#direct-diagnosis-and-recovery).
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

## Reconfigure a Factory

Stop the Factory before selecting changed role contracts or workspaces. Check
and approve the changed TOML and role Markdown, then run the same Factory. The
entry preserves existing role homes, identities, checkpoints and Coord history.
It does not convert old Python product state or legacy supervisor checkpoints.
A refused checkpoint remains available for direct inspection and recovery.

To restore an earlier contract, stop the roles, check and approve that
contract and its exact role Markdown, then run again. Approval selects content;
it does not cancel outstanding work or grant a different role authority over it.
Resolve any affected assignments through their existing handoffs or explicit
stopped-work release before changing their authority.
