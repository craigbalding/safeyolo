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

## Check, approve, and run

Inspect the fully resolved bindings and SHA-256 of every Markdown contract:

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

## Live upgrade

For a running legacy backlog factory:

1. Stop the existing `relay`, `forge`, and `lens` agents at a safe boundary.
2. Run `factory check` and verify the agents, room, handoffs, paths, and hashes.
3. Run `factory apply` and approve that exact resolved snapshot.
4. Run `factory run backlog`.

The supervisor upgrades its existing version-1 checkpoint in memory and keeps
the thread, safe cursor, recent attention IDs, and in-flight canonical objects.
The active Markdown contract and routing table come from the immutable
snapshot. To change either, stop the agents, check and apply a new snapshot,
then run the factory again.
