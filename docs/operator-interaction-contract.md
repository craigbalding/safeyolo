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
   Make approval, refusal and deferral choices clear. Extra confirmation must
   address a concrete accidental effect; typing an opaque identifier does not
   establish that the operator understands the decision.
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
7. **Workflow.** Let operators complete ordinary actions in the interface they
   are already using. An interactive live approvals view must offer review and decision
   actions in place. If a task needs a handoff, explain why and carry the known
   target and necessary context into the next step. Reuse the same validation,
   authorization, concurrency and audit owners across interactive and explicit
   interfaces. Easier interaction must not introduce an authorization bypass.
8. **Input.** Prefer selection, completion or stable short references to
   transcription of long identifiers. Bind each selection to the exact object
   and reviewed content; new arrivals or reordered results must not retarget
   an action. Refuse an effect through an ambiguous or stale selection and show
   how to refresh the review.
   Generate and retain bookkeeping identifiers the system can supply, including
   the original operation identity needed to reconcile a lost reply.
9. **Discovery.** Lead prompts, help and examples with the easiest supported
   human workflow. Use consistent action names and show how to cancel or return.
   Keep material information readable without colour. Offer interactive
   assistance in a terminal; explicit noninteractive modes must not wait for
   prompts. Preserve complete commands, application programming interfaces (APIs)
   and structured output for automation.

## Representative examples

These examples illustrate required interactions, not claims that every current
path already complies. Only the clauses relevant to each interaction apply.

| Journey | Problem to prevent | Required result |
|---|---|---|
| Read pending approvals for a selected agent | An empty panel can mean no approvals or a failed load. | A successful read with no entries says there are no pending approvals for that target. An unavailable read says it could not load them and offers a retry for the same target. Neither read needs a mutation preview. |
| Decide a pending approval | An agent's reason obscures what access the decision grants. | Show the approval's fixed target, effects, scope and offered lifetime before the decision. Label the agent's explanation separately. Preserve the existing decision options; an explanation or notification grants no permission. |
| Review a policy change in live approvals | The operator must copy a long ID into another command to act on a displayed request. | In interactive `safeyolo watch`, select the displayed request number, review the consequences and exact diff, then decide inline. New arrivals cannot change the selected request. Keep explicit commands available. |
| Recover an interrupted human operation | The operator must invent a bookkeeping ID or start another operation after a lost reply. | Generate and retain the operation identity through the existing owner. Inspect that operation's outcome before offering a retry. Do not create another effect while the outcome is unknown. |
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
normal pull request or handoff. Both owner and independent reviewer must use
the [operator-ux skill](../cli/src/safeyolo/agent_context/skills/operator-ux/SKILL.md).
The reviewer checks the claimed outcome, relevant-only application and
unnecessary scope through the existing review process.

For changed interactions, exercise the actual human interface and the affected
noninteractive path. Cover cancellation, new arrivals, stale state or interrupted
operations when they could change the outcome. An API test alone does not prove
the terminal or browser journey. Use focused existing tests or a direct trial;
record the actions, observed result and material limits. For guidance-only
changes, check the instructions against the source and walk through the affected
examples. State when evidence is source inspection rather than runtime proof.
Each substantial addition must identify the operator behavior or essential
evidence that would be lost if removed.

Apply the contract to future changes within the journeys they touch. Keep
adjacent discoveries as separate follow-ups. The
[adoption issue](https://github.com/craigbalding/safeyolo/issues/1468) fixes the
initial eight-row coverage and identifies its owning outcomes. Contract adoption
alone does not establish implementation acceptance or close that issue. Keep
detailed requirements and acceptance evidence in their owning issues.

## Sources

These requirements apply established guidance to SafeYolo's operator journeys:

- [Command Line Interface Guidelines](https://clig.dev/): human-first defaults,
  discoverability, concise feedback, interactive assistance and scriptability.
- [NCSC: Usability of the product](https://www.ncsc.gov.uk/collection/technology-assurance/principles-product-design-and-functionality/1-usability-of-the-product):
  intuitive, unobtrusive security functions, meaningful recovery and usability
  checks with representative roles, tasks and contexts.
- [Heroku CLI Style Guide](https://devcenter.heroku.com/articles/cli-style-guide):
  interactive selection alongside explicit command arguments for automation.

The sources explain the design principles. This contract defines the project
requirements; external examples do not grant authority or prescribe new flags.
