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
`TASK task=<id> assignee=<agent>`; text such as `TASK UPDATE` is data, not a
task. Other request and response bodies must begin with their exact declared
type. Canonical envelope identity and the configured room—not names written in
the body—authorize a handoff.

`response_to` names every role that the destination must notify when it sends a
declared response. The source role must be included. Old v1 contracts and
snapshots without this field retain the original source-only response route.

`operator_input` is the one explicit direction edge into the graph. It admits
bounded natural-language messages only when the canonical sender kind is
`operator`, routes them only to the named role, and never treats them as agent
handoffs. The declared types are optional operator shorthand rather than a
natural-language parser; they cannot overlap a handoff request or response.
`factory check`, `apply`, and `run` reject a graph in which any role is
unreachable from that operator edge; old source-only v1 snapshots therefore
fail closed instead of starting an inert factory.

Interactive operator chat automatically resolves the coordinator bound by an
applied factory snapshot for that room. An explicit target overrides that
resolution:

```sh
safeyolo coord chat backlog --to relay
```

Without `--to`, a room with no applied factory keeps its room-wide wake
behavior. If multiple applied factories bind different coordinators to one
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

An approved factory has two different state layers:

- The immutable snapshot binds the room, operator edge, role and agent
  bindings, declared handoffs, and exact bytes and SHA-256 of every Markdown
  role contract.
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

Apply prompts for explicit operator approval and stores the resolved manifest
plus exact role-contract contents in an immutable, content-addressed snapshot
under `~/.safeyolo/factories/`. `--yes` is the non-interactive form of that
explicit approval:

```sh
safeyolo factory apply docs/factories/backlog.toml
safeyolo factory apply docs/factories/backlog.toml --yes
```

Run loads and verifies only the active snapshot, configures the already-created
agents through the existing `@codex-coord` host setup, stages each approved
role contract, and starts all roles detached:

```sh
safeyolo factory run backlog
```

`factory run` never creates agents. Create the named agents first with their
normal workspace and credentials. A factory does not live-reload: editing the
TOML or Markdown files changes nothing in running workers.

The stored snapshot binds each Markdown file's exact bytes, byte count, hash,
and decoded text. `factory run` prints the bound snapshot path, byte counts,
hashes, and operator edge before it starts agents, so the operator can compare
the running object with the approved check output.

## Diagnose an active factory

Inspect the complete active factory before you rely on it:

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
repair, apply, or change the factory. Each output line has one status:

- `PASS` means that the component has the expected state.
- `WARN` means that a role is stopped. A stopped role is valid persistent
  state, but the factory is not fully running.
- `FAIL` means that a required component is missing, corrupt, mismatched, or
  not running. Each failure names a narrow recovery command or file category.

The command checks the active snapshot and role bindings, agent identity and
storage, workspaces, room membership and grants, the traffic proxy, and the
managed Coord NATS runtime. It also checks each staged command, supervisor
configuration, role contract, Codex Model Context Protocol (MCP) binding,
checkpoint, and running process tree. A healthy traffic proxy does not hide a
stopped NATS runtime. A running sandbox fails the check if its supervisor or
active-turn Coord MCP process is absent. Between bounded turns, the checkpoint
normally records `owned_process=null`; the running supervisor is then reported
as healthy without requiring a Codex process. A PID that disappears while the
read-only process probe runs is likewise reported as a non-disruptive turn
transition.

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

For a running legacy backlog factory:

1. Stop the existing `relay`, `forge`, and `lens` agents at a safe boundary.
2. Add the explicit `operator_input` table, then run `factory check` and verify
   the agents, room, operator shorthand, reachable handoffs, paths, byte counts,
   and hashes.
3. Run `factory apply` and approve that exact resolved snapshot.
4. Run `factory run backlog`.

The supervisor upgrades its existing checkpoint in memory and keeps the
thread, safe cursor, recent attention IDs, in-flight canonical objects, and
current trusted room brief context.
The active Markdown contract and routing table come from the immutable
snapshot. To change either, stop the agents, check and apply a new snapshot,
then run the factory again.

Rollback is also snapshot-based: stop all roles, restore or re-apply the last
known-good factory file and role Markdown, verify the newly produced exact
snapshot details, then run it. A legacy snapshot without `operator_input`
cannot be restarted. If Relay cannot receive the operator edge, keep the
factory stopped and operate the issue manually; do not inject a peer-authored
message that merely looks like an operator control.
