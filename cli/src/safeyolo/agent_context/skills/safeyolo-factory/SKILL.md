---
name: safeyolo-factory
description: Design, review, prove, and troubleshoot SafeYolo supervised factories with an operator. Use before changing a running factory's brief, contract, routes, supervisor, capabilities, recovery, or agent direction, and when an operator wants to create or revise a factory, define roles and handoffs, review factory TOML or role contracts, investigate runtime behavior, estimate a nested factory, or test a factory in a controlled nested lab. Apply annotated graphs, cross-contract review, and evidence-led diagnosis without unnecessary gates or factory-specific architecture.
---

# SafeYolo factory operator copilot

Help the operator shape and improve a productive, resilient factory. Be the
design and troubleshooting copilot, not a new controller, runner, queue, or
workflow engine. The factory TOML, role contracts, approved snapshot, Coord
state, and supervisors remain authoritative.

## Select the workflow

Read the selected TOML and role contracts before assigning or completing work.
With `[work]`, supervised roles receive native participant actions and settle
them through their named canonical mutations. Do not mirror that lifecycle in
`TASK`, `REVIEW_READY` or terminal messages. Still-supported message assignments
use the handoffs and responses declared by their selected contract. A generic
message convention does not add responses to that contract. Preserve the
original protocol of in-flight work across a later snapshot change.

Keep runtime primitives, domain responsibilities, instance bindings and one
item's assignment separate. [Factory design](references/design.md#keep-each-instruction-in-its-own-place)
defines their maintained homes and brief variations. Coord does not prescribe
a software workflow, a repository host, a programming language or a role set.

### Native work and review

For native output publication, the producing worker retains its immutable
artifact first, then calls `publish_work_output` with current work version,
claim generation and target generation. Retry an interrupted publication with
the exact original operation ID and inputs. Read current work separately from
the recovered receipt. Cancellation and reassignment can reject an uncommitted
stale publication; they do not remove the external artifact or stop an external
effect. Producer identity comes from the authenticated route and cannot be
supplied by a bridge. Publication does not establish acceptance.

`request_check` and `raise_challenge` return ordinary work IDs with exact
subjects and named participants. The assigned participant claims that work.
`answer_check` records and settles a check; corrections preserve earlier answers
on the same work ID. `respond_challenge` completes response work while leaving
the challenge unresolved. Only named deciding participants or the operator can
call `resolve_challenge`, subject to the selected independence flag and current
work/response expectations. Read `list_work_reviews` and immutable `read_work`
versions for current obligations and history. Checks and challenges remain
advisory unless selected in native acceptance requirements.

Use an exact-subject check for a proposition with a meaningful verdict.
An independent check requires an attributed subject producer distinct from
the reviewer. Publish the retained output before requesting its independent
check; an arbitrary reference or unpublished investigation has no attributed
output producer. An answered check revision can also be an attributed subject.
Use ordinary Work for open-ended research or investigation, then check a
resulting proposition separately when useful. Do not select a policy that
requires an investigator to independently check its own report.

The work creator or operator can select native acceptance context with
`set_work_requirements`. Use that operation for initial or deliberate full-policy
selection. For a routine manual amendment, use `select_work_review` to add one
existing check/challenge or replace an explicitly named selected review of the
same kind. Supply current work, claim, requirements and new-review versions,
`review_kind`, the `review` reference, a reason and an operation ID. Omit
`replace_work_id` to add, or name the selected review to replace or deliberately
reselect. The operation preserves unrelated stored selections, authorities,
deciders and independence. A changed unrelated definition stays inconsistent
until explicitly reselected. Do not create an empty initial selection to use
the amendment. For corrected code, replace its implementation check while
retaining a release/security challenge. For a corrected report, replace its
report review while retaining an unresolved coverage challenge. See the
[API examples](https://github.com/craigbalding/safeyolo/blob/master/docs/coord-operations.md#amend-one-required-review).
Amendments require a recorded authority or the
operator; ownership and production alone grant no policy authority. An explicit
authorized delegation can name a worker. Selected checks and challenges govern
`decide_work_acceptance`.
Only named deciders may decide, and approval validates the exact current output
and required review outcomes atomically. Read `acceptance_status` for pending
obligations, stale approvals and conflicting decisions. Execution completion
and check conclusions remain separate from output acceptance. An approved
Factory's `[work]` selects creator and policy authority roles, deciders,
independence and required check templates. Create Work with its exact approved
`{name,snapshot_id}` reference. Publication atomically creates exact-output
checks and selects their requirements. Later Factory approval does not alter
that retained policy. Native participant actions use the existing supervisor;
no duplicate message workflow is needed for native assignments. Explicit
message assignments retain their declared replies. Keep interactive workers
outside the supervised roles, with their own authenticated client and room
access. Do not change a running Factory merely to exercise this path.

For a selected next attempt with the same retained participant, use
`continue_work` on completed assigned execution or an answered exact-subject
check. Supply current work version/claim generation, a bounded reason,
recoverable findings or changed-input references and a chosen operation ID.
Ordinary work permits its creator or the operator. A currently required check
permits the root's current acceptance-amendment authority or the operator;
an advisory check permits its requester or the operator. No recipient change
is accepted. The generation advances and the existing supervisor delivers an
action. The participant reads `work.continuation`, reuses its retained active
claim and settles with `complete_work` or `answer_check`. A renewed required
check is pending; its historical answer and old approval cannot satisfy fresh
acceptance. A replacement output needs a new exact-subject check. For example,
continue the same code item for an in-scope correction, or ask the retained
report author to narrow or withdraw a finding after new evidence. Reassignment
remains operator-owned for unassigned work, different participants and abandoned
assignments. Continuation grants no access or permission to repeat an uncertain
external effect; reconcile that effect before retrying. Nothing automatically
selects another attempt after rejection, a signal resolution or an approval.

## Route the request

- For a new factory or substantial redesign, read
  [Factory design](references/design.md).
- For a contract review or any contract edit, read
  [Cross-contract review](references/contract-review.md).
- For commands, live behavior, failures, recovery, or a nested proving run,
  read [Operations and proving](references/operations.md).
- Before any change to a running factory, read Operations and enter
  [`sym.runtime_operator_intervention`](references/graph/runtime-triage.yaml).
  Complete that graph path before changing a brief, contract, route,
  supervisor, capability, recovery action, or agent direction.
- When a controlled tmux lab is appropriate, invoke
  the `safeyolo-lab-controller` skill for the lab mechanics. Say when that
  skill changes or pauses the work.
- For SafeYolo Agent API, proxy, Coord, approval, or in-sandbox diagnostics,
  invoke the `safeyolo` skill and follow its security boundary.

Use each harness's native skill invocation: `$skill-name` in Codex or
`/skill-name` in Claude Code. Both discover the same bundled skill trees.
Using this operator skill from Claude does not require Claude as a supervised
Factory worker. Keep the factory's configured role and harness contracts.

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

- a mandatory gate with no operator requirement, established security
  requirement, or evidenced technical necessity;
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
