# Operator interaction contract

This is the authoritative product contract for operator interactions in the
command-line interface (CLI), Command Centre and browser pages. Apply each
clause only where relevant to the journey being changed. The interfaces need
consistent meaning, not identical presentation or implementation.

Keep ordinary output concise. Put material decision information before the
decision; offer supporting detail progressively. Read-only operations need no
mutation preview. Work within existing authority must not gain recurring
confirmation prompts. Preserve explicit commands, noninteractive use and
structured output alongside interactive assistance.

## Required behavior

1. **Context.** Identify and preserve the selected host, instance/root and agent
   where they matter. Carry known target identifiers through actions, recovery
   and handoffs. Do not make the operator reconstruct context the system already
   holds. A selection does not establish access to that target.
2. **Decision.** Before a relevant decision, expose its material effects,
   authority, scope and lifetime. Include credential custody, disruption and
   retention when they affect the choice. Distinguish system-derived facts from
   agent-supplied explanations; agent prose cannot change authority. Use the
   existing policy and approval owners, including their concurrency checks.
3. **Activation.** Distinguish saved configuration, effective state and changes
   awaiting restart or another explicit action. Name the affected target and
   the action needed for activation. Saving a value alone does not establish
   that the running system uses it.
4. **Evidence.** Distinguish current observations, recorded facts,
   successful-empty results, unavailable information and unknown state. Identify
   the source and freshness when they affect interpretation. A stale record is
   not a current observation. A failed or incomplete read must not appear as
   evidence that nothing exists.
5. **Outcome.** Report success, failure or partial completion accurately. When
   recovery is needed, say what completed, what failed or remains uncertain,
   and give a specific next action for the correct target. Success needs no
   extra recovery boilerplate.
6. **Continuity.** Reuse valid saved choices and completed work. For example,
   returning to an existing agent must not repeat a known, still-valid harness
   choice. Preserve identity across interrupted operations. Before retrying a
   possibly completed effect, reconcile current state or the original operation
   and result through the existing owner. If the outcome remains unknown,
   report that uncertainty and the targeted inspection or recovery action.

## Representative examples

These examples illustrate required interactions, not claims that every current
path already complies. Only the clauses relevant to each interaction apply.

| Journey | Before | Required result |
|---|---|---|
| Read pending approvals for a selected agent | An empty panel can mean no approvals or a failed load. | A successful read with no entries says there are no pending approvals for that target. An unavailable read says it could not load them and offers a retry for the same target. Neither read needs a mutation preview. |
| Decide a pending approval | An agent's reason obscures what access the decision grants. | Show the approval's fixed target, effects, scope and offered lifetime before the decision. Label the agent's explanation separately. Preserve the existing decision options; an explanation or notification grants no permission. |
| Change a saved setting that requires restart | “Saved” leaves the operator unsure whether the running instance changed. | Identify the selected host and instance/root. Report that the setting is saved, the running value is unchanged and restart is needed. If a restart reply is lost, report the partial outcome and inspect that instance before retrying. Reuse the saved value. |

Reuse the existing [approval controls](operator-guide.md#inspect-a-pending-approval),
[configuration owners](settings.md) and
[recovery paths](operator-guide.md#recover-from-a-failed-operation).
This contract adds no response schema, workflow engine, state store or transport.
It does not create a new review role or approval gate, or require a graphical
control for every CLI capability.

## Apply and review

For each increment, the owner provides a concise before/after journey, the
existing mechanism reused, the applicable clauses and focused proof in the
normal pull request or handoff. The independent reviewer assesses the claimed
outcome, relevant-only application and unnecessary scope through the existing
review process. Each substantial addition must identify the operator behavior
or essential evidence that would be lost if removed.

Apply the contract to future changes within the journeys they touch. Keep
adjacent discoveries as separate follow-ups. The
[adoption issue](https://github.com/craigbalding/safeyolo/issues/1468) fixes the
initial eight-row coverage and identifies its owning outcomes. Contract adoption
alone does not establish implementation acceptance or close that issue. Keep
detailed requirements and acceptance evidence in their owning issues.
