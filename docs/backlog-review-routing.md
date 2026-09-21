# Backlog review routing

This is the supervised backlog-factory workflow for the remaining #620 work.
The approved factory snapshot, not an agent's mutable default configuration,
binds the routine role models.

## Roles and provider pinning

- Relay is the coordinator. It uses `gpt-5.6-sol` at medium reasoning and owns
  GitHub intake, dependency sequencing, assignments, integration state and
  recovery. It does not implement or independently accept candidates.
- Forge is the implementation owner. It uses `gpt-5.6-terra` at max reasoning
  for routine issue implementation, focused tests, candidate commits and
  corrections requested by Lens.
- Lens uses the `opencode-go-review` Codex profile with provider
  `opencode_go_review`, model `deepseek-v4.1-flash`, and max reasoning. These
  values are also explicit factory arguments so mutable defaults cannot route
  review to another model or provider.
- DeepSeek is the independent reviewer and acceptance authority for each
  routine issue. It inspects the execution paths and callers, runs required
  builds and focused tests or probes, verifies retained evidence, reports
  findings, verifies corrections, and writes the acceptance receipt. Its
  `READY` receipt satisfies the independent-review requirement for issue and
  integration acceptance under the existing rules.
- After two `CHANGES_REQUIRED` dispositions for the same task still leave
  material findings, Relay may issue the factory's existing `REPAIR` handoff. The next
  Forge repair invocation uses `gpt-5.6-sol` at high reasoning. At most one
  stronger repair round is available, and the role returns to Terra max when
  it sends `REVIEW_READY`.
- Astra has no factory role, handoff or automatic fallback. Emergency Astra
  use requires a separate explicit operator decision.
- If the requested provider, model, or reasoning level cannot be proven at
  launch, stop and report the missing credential or configuration. Never
  silently substitute another model or provider.

## Review continuity and visibility

Lens reviews the exact immutable candidate named by each `REVIEW_READY` and
returns one independent disposition. The existing supervisor retires that
harness session when the disposition settles the request. A later correction
review starts a fresh session and recovers still-valid evidence and findings
from the retained Coord disposition. A `READY` disposition is the routine
independent acceptance decision; it is not followed by another per-issue Sol
gate.

Run `scripts/watch_backlog_factory.sh start` from an existing tmux session to
open one `factory-watch` window with equal-width Relay, Forge and Lens panes.
Each pane runs `contrib/watch-agent-room.py` against the corresponding retained
agent room. The launcher waits for rooms to be provisioned and restarts a
viewer if it exits. It does not start or resume the factory.
