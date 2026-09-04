# Supervised factories

SafeYolo factory files are small, explicit bindings for existing supervised
agents. Markdown remains the role contract; TOML says which approved agent has
each role, which one coord room the factory uses, and which exact handoffs may
wake each worker. Factory v1 does not interpret role prose at runtime and has
no scripts, conditions, regex routes, hooks, discovery, inference, or live
reload.

## File format

The shipped backlog example is
[`docs/factories/backlog.toml`](factories/backlog.toml). A v1 file contains
only:

```toml
schema = "safeyolo.factory/v1"
name = "backlog"
room = "backlog"

[operator_input]
to = "coordinator"
types = ["ACTIVATE", "PAUSE", "RESUME", "PRIORITY", "NEXT", "DIRECTION"]

[roles.owner]
agent = "forge"
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

Interactive operator chat automatically resolves the coordinator bound by an
approved factory snapshot for that room. An explicit target overrides that
resolution:

```sh
safeyolo coord chat backlog --to relay
```

Without `--to`, a room with no approved factory keeps its room-wide wake
behavior. If multiple approved factories bind different coordinators to one
room, chat fails visibly instead of guessing. The target must be an active,
receive-authorized room member; unknown, revoked, and send-only targets fail
before the message is accepted. Targeting changes only attention delivery.
Send confirmation and operator-visible retained history show the canonical
attention mode (`targeted`, `room`, or `none`) without exposing recipient IDs
or unrelated membership. The message remains canonically attributed.

The room brief is a separate operator-authored standing-context channel.
Canonical `brief_changed` attention updates every receive-authorized factory
role's bounded checkpoint, and preflight refreshes the current brief after a
restart. Brief updates are not handoffs: they create no in-flight request,
need no terminal response, and cause no automatic runtime transition.

## Authority and intake

An approved factory has three distinct state layers:

- The approved immutable snapshot binds the room, operator edge, role and agent
  bindings, declared handoffs, and exact bytes and SHA-256 of every Markdown
  role contract. Approval selects the snapshot that the next `factory run`
  will use; it does not alter running agents.
- Each running role uses the exact snapshot last staged into that agent by
  `factory run`. Until the next run, this can differ from the newly approved
  snapshot.
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

The shortest discoverable setup path is deliberately ordered. Before running
it, log in to Codex with a ChatGPT subscription on the host. Register every
agent with the ordinary bundled `@codex` host setup, which stages the host's
`~/.codex` authentication and config into the agent's persistent home, then
validate the immutable contract, approve that exact snapshot, and only then run
the factory. `--no-run` leaves agent creation separate from factory startup;
the host setup cannot create a subscription login that is absent on the host.

```sh
safeyolo agent add relay "$PWD" --host-script @codex --no-run
safeyolo agent add forge "$PWD" --host-script @codex --no-run
safeyolo agent add lens "$PWD" --host-script @codex --no-run
safeyolo factory check docs/factories/backlog.toml
safeyolo factory approve docs/factories/backlog.toml --yes
safeyolo factory run backlog
```

Use the role agent names from the factory file for another contract. The
workspace argument may be changed per agent. `factory run` is the step that
creates or verifies the shared Coord room and each private agent room and
restores the required operator and role send/receive grants. It does this
before starting any role supervisor.

When a setup step fails, follow the commands printed by the CLI in order. The
read-only diagnosis is always available as:

```sh
safeyolo factory doctor backlog
```

Correct the specific component named by `factory doctor`, then rerun
`safeyolo factory run backlog`. A missing agent is recovered with
`safeyolo agent add NAME "$PWD" --host-script @codex --no-run`; a missing workspace is recovered
with `safeyolo agent config NAME --folder "$PWD"`. Room and grant recovery is
the idempotent `safeyolo factory run backlog` command itself. Factory run does
not claim success until every role supervisor passes the doctor checks for the
approved snapshot, agent identity/storage/workspace, rooms and grants, proxy,
NATS, staged supervisor/MCP/contract files, checkpoint, and process tree.

## Check, approve, and run

Inspect the resolved source path, exact UTF-8 byte count, and SHA-256 of every
Markdown contract, along with the operator edge and handoffs:

```sh
safeyolo factory check docs/factories/backlog.toml
```

The explanation also identifies the immutable snapshot boundary, the live
brief boundary, the role that receives operator input, and the complete
role/handoff graph. Static checking does not inspect live room state, grants,
brief revision, or worker health.

Approve prompts for explicit operator approval, stores the resolved manifest
plus exact role-contract contents in an immutable, content-addressed snapshot
under `~/.safeyolo/factories/`, and selects that snapshot for the next run.
It does not change a running factory. `--yes` is the non-interactive form of
the same explicit approval:

```sh
safeyolo factory approve docs/factories/backlog.toml
safeyolo factory approve docs/factories/backlog.toml --yes
```

Run loads and verifies only the approved snapshot, configures the already-created
agents through the existing `@codex-coord` host setup, stages each approved
role contract, provisions the declared shared Coord room and its required
operator and role grants, starts all roles detached, and waits for operational
preflight:

```sh
safeyolo factory run backlog
```

`factory run` never creates agents. Create the named agents first with their
normal workspace and credentials. Room provisioning is idempotent: an existing
room keeps its history and unrelated observer grants, while missing
send/receive grants for the operator and bound role agents are restored. The
declared shared room cannot reuse a bound agent's private `<agent>-agent` room.
If Coord provisioning fails, no role is started. If a role launch or
operational preflight fails, the command returns an actionable doctor and
rerun sequence instead of printing `Started factory`. A factory does not
live-reload: editing the TOML or Markdown files changes nothing in running
workers.

The stored snapshot binds each Markdown file's exact bytes, byte count, hash,
and decoded text. `factory run` prints the bound snapshot path, byte counts,
hashes, and operator edge before it starts agents, so the operator can compare
the running object with the approved check output.

## Diagnose an approved or running factory

Inspect the approved snapshot and current runtime before you rely on them:

```sh
safeyolo factory doctor backlog
```

The doctor reports the current canonical brief as `state=none` or as its exact
revision and content hash. It does not print or interpret the brief body. When
the brief is absent, the doctor reports the intake behavior bound by the shipped
coordinator contract. The output also gives the exact read and
optimistic-concurrency update commands:

```sh
safeyolo coord brief show backlog
safeyolo coord brief set backlog --file BRIEF.md --expected-revision REVISION
```

Use revision `0` for the first brief. For an existing brief, use the current
revision reported by `brief show` or `factory doctor`. SafeYolo accepts
operator-authored Markdown. SafeYolo does not claim that the Markdown contains
a valid eligibility policy.

The command reads existing host and sandbox state. It does not start, stop,
repair, approve, or change the factory. Each output line has one status:

- `PASS` means that the component has the expected state.
- `WARN` means that a role is stopped. A stopped role is valid persistent
  state, but the factory is not fully running.
- `FAIL` means that a required component is missing, corrupt, mismatched, or
  not running. Each failure names a narrow recovery command or file category.

The command checks the approved snapshot and role bindings, agent identity and
storage, workspaces, room membership and grants, the traffic proxy, and the
managed Coord NATS runtime. It also checks each staged command, supervisor
configuration, role contract, Codex Model Context Protocol (MCP) binding,
checkpoint, and running process tree. A healthy traffic proxy does not hide a
stopped NATS runtime. A running sandbox fails the check if its supervisor or
active-turn Coord MCP process is absent. Between bounded turns, the checkpoint
normally records `owned_process=null`; the running supervisor is then reported
as healthy without requiring a Codex process. A PID that disappears while the
read-only process probe runs is likewise reported as a non-disruptive turn
transition. Doctor validates checkpoints through the same bundled supervisor
decoder that runs them, so checkpoint migrations have one implementation.

The summary is `PASS`, `WARN`, or `FAIL`. `FAIL` returns a nonzero exit status.
`WARN` returns zero so that an operator can distinguish a deliberately stopped
factory from corrupt state. The command reports checkpoint counts and process
identity, but it does not print message bodies, role-contract contents,
credentials, or inspected payloads.

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

## Live upgrade

There is no backward-compatible parser or completion path for the old
`TASK task=<id> assignee=<agent>` protocol. Before changing a running legacy
factory, drain it at a verified safe boundary:

1. Keep the existing role supervisors running and let every in-flight request
   and awaiting handoff reach its terminal response.
2. Run `safeyolo factory doctor backlog` repeatedly. Do not continue until the
   checkpoint line for every role reports `in_flight=0 awaiting_handoffs=0`.
3. Stop the drained roles, for example with `safeyolo agent stop relay`,
   `safeyolo agent stop forge`, and `safeyolo agent stop lens`.
4. Add or update the explicit `operator_input` table, then run
   `safeyolo factory check docs/factories/backlog.toml` and verify the agents,
   room, operator shorthand, reachable handoffs, paths, byte counts, and hashes.
5. Run `safeyolo factory approve docs/factories/backlog.toml --yes` for that
   exact resolved snapshot.
6. Run `safeyolo factory run backlog`.

The supervisor applies the same verified drain precondition to supported
version-1 through version-5 checkpoints before upgrading them to the target-only
version. A checkpoint with pending work is rejected without mutation and prints
the recovery procedure; do not edit its messages or invent target URLs. An
empty checkpoint upgrades to a clean Codex thread while retaining only its safe
cursor, recent attention IDs, and trusted room brief context. New work must use
target URLs.
The running Markdown contract and routing table come from the immutable
snapshot. To change either, stop the agents, check and approve a new snapshot,
then run the factory again.

Rollback is also snapshot-based: stop all roles, restore or re-approve the last
known-good factory file and role Markdown, verify the newly produced exact
snapshot details, then run it. A legacy snapshot without `operator_input`
cannot be restarted. If Relay cannot receive the operator edge, keep the
factory stopped and operate the issue manually; do not inject a peer-authored
message that merely looks like an operator control.
