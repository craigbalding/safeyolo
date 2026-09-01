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
```

Contract paths are explicit and relative to the TOML file. Every role and
message type is declared literally. `TASK` retains its generic delegation
meaning, but its first line must be exactly
`TASK task=<id> assignee=<agent>`; text such as `TASK UPDATE` is data, not a
task. Other request and response bodies must begin with their exact declared
type. Canonical envelope identity and the configured room—not names written in
the body—authorize a handoff.

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

## Check, approve, and run

Inspect the resolved source path, exact UTF-8 byte count, and SHA-256 of every
Markdown contract, along with the operator edge and handoffs:

```sh
safeyolo factory check docs/factories/backlog.toml
```

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
