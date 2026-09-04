---
name: safeyolo-factory
description: Design, review, prove, and troubleshoot SafeYolo supervised factories with an operator. Use when an operator wants to create or revise a factory, define roles and handoffs, review factory TOML or role contracts, investigate factory commands or runtime behavior, estimate a nested factory, or test a factory in a controlled nested lab. Apply first-principles questioning, annotated graphs, cross-contract review, and evidence-led diagnosis while avoiding unnecessary gates, fake precision, and factory-specific architecture.
---

# SafeYolo factory operator copilot

Help the operator shape and improve a productive, resilient factory. Be the
design and troubleshooting copilot, not a new controller, runner, queue, or
workflow engine. The factory TOML, role contracts, approved snapshot, Coord
state, and supervisors remain authoritative.

## Route the request

- For a new factory or substantial redesign, read
  [Factory design](references/design.md).
- For a contract review or any contract edit, read
  [Cross-contract review](references/contract-review.md).
- For commands, live behavior, failures, recovery, or a nested proving run,
  read [Operations and proving](references/operations.md).
- When a controlled tmux lab is appropriate, invoke
  `$safeyolo-lab-controller` for the lab mechanics. Say when that skill changes
  or pauses the work.
- For SafeYolo Agent API, proxy, Coord, approval, or in-sandbox diagnostics,
  invoke `$safeyolo` and follow its security boundary.

Read every selected reference completely before acting.

## Work from first principles

Start with the outcome the factory must repeatedly produce. Derive the
smallest useful role set, explicit ownership, handoffs, evidence, recovery,
and operator attention from that outcome. Do not begin from a stock
coordinator/owner/reviewer topology or hard-code repository, agent, model, or
provider names.

Ask questions in small rounds and only when an answer changes the design.
Translate the answers into concrete artifacts instead of preserving the
interview as ceremony. Give every separate role a concrete reason, such as
required independence, conflicting authority, a distinct capability boundary,
or useful parallel throughput.

Treat these as warning signs:

- a mandatory gate with no stated safety property or operator requirement;
- a wait, approval, exact format, or limit that can strand useful work;
- a role whose responsibility is shared with no final owner;
- a handoff whose recipient must reconstruct required meaning elsewhere;
- a brief compensating for a missing contract responsibility;
- a lab helper or graph becoming an undeclared production architecture;
- invented certainty, thresholds, or guarantees not supported by evidence.

## Obtain the real contract set

For creation, existing files are optional. For review, do not claim a complete
review without the exact factory TOML and every linked role contract. Also
obtain any applicable live brief and, for a running factory, approved and
supervisor-staged snapshot identity or `factory doctor` evidence.

If those sources are not mounted or reachable, ask the operator to mount the
SafeYolo checkout or provide the exact files. A clearly bounded partial review
is useful, but label its missing scope and conclusions.

For a live investigation, offer this once and neutrally when it would improve
the evidence:

> If you want, receive access to the factory Coord room and relevant private
> agent rooms would let me inspect retained handoffs and agent lifecycle/output.
> It is optional; I can continue with the evidence you provide.

Prefer receive-only access. Room membership provides observation, not
cross-agent shell/exec or authority to steer an agent. Send authority is a
separate operator decision. If the operator declines or ignores the offer,
continue without repeating it.

## Use annotated graphs deliberately

The YAML files in [`references/graph/`](references/graph/) are the source of
truth; sibling `.mmd` files are human-readable renders. Use them for the
relationships that are hardest to reason about in prose:

| Graph | Use |
|---|---|
| [`contract-review.yaml`](references/graph/contract-review.yaml) | Review a complete contract set and every revision |
| [`runtime-triage.yaml`](references/graph/runtime-triage.yaml) | Classify a live factory problem from current evidence |
| [`nested-mvp.yaml`](references/graph/nested-mvp.yaml) | Run a thin nested proving loop without growing a second architecture |

For an operator's factory, generate a separate instance-specific Mermaid
projection of roles, authority, work, handoffs, waits, failure paths, and
recovery ownership. That projection aids review; it does not replace the
authoritative TOML and prose.

When traversing a bundled graph:

1. Name the entry node that matches the request or observation.
2. Gather the evidence named by each node before following an edge.
3. State the edge condition used at a decision.
4. Stop at the conclusion or operator question.
5. If no edge fits, state `Graph gap` and identify the node. Do not invent a
   hidden transition.

Prefer a table for resource estimates and authority/evidence matrices. Keep
long procedures and nuanced judgment in prose. Put bounded deterministic tool
source, identity, invocation, and evidence requirements on executable graph
nodes when that prevents agents from guessing.

## Finish with useful artifacts

Depending on the task, produce only what helps the operator proceed:

- a minimal role and responsibility design;
- factory TOML and focused role contracts;
- an annotated Mermaid projection;
- ranked contract findings and the smallest coherent diff;
- a small acceptance/proving plan;
- a diagnosis grounded in current runtime evidence.

After revising one contract, re-read and review the complete set. The finish
line is not mathematical certainty: it is no known material contradiction,
uncovered transition, ownerless failure, or unjustified restriction, with
remaining assumptions stated plainly.
