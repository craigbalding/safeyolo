# Agent and operator dogfooding

Use the installed product to accomplish useful goals. Capture difficulties even
when the goal succeeds. Keep normal factory work productive while deliberate
exercises cover features and combinations that ordinary work does not reach.

## Contents

- [Adopt the responsibility](#adopt-the-responsibility)
- [Choose a journey](#choose-a-journey)
- [Preserve the first attempt](#preserve-the-first-attempt)
- [Look for human conveniences](#look-for-human-conveniences)
- [Record and follow findings](#record-and-follow-findings)

## Adopt the responsibility

Put the standing duty in the actual manager's operating instructions. Use
[Factory design](design.md#keep-each-instruction-in-its-own-place) to place
responsibilities, instance choices and individual assignments. The manager of
an outer instance need not be the nested factory's coordinator.

Bind these choices through the existing instructions and brief:

- Capture friction encountered during normal work.
- Give deliberate exploration a small recurring allowance and priority relative
  to delivery. Do not leave every exercise conditional on an idle factory.
- Name the installed targets, permitted actions, resource allowance, evidence
  location, reporting destination and useful baseline.
- Select one complete journey at a time. Keep unrelated work moving while an
  exercise waits for a real dependency or decision.

Use the existing management turns and work mechanisms. A skill supplies the
procedure; it neither schedules itself nor grants access. Preserve live work
and the selected native or message protocol when adopting the duty. Apply the
factory skill's existing intervention procedure if adoption changes a running
factory's contract, capabilities or direction.

Verify adoption through an actual manager-run exercise. Record the installed
product and skill revisions, the retained result and any linked finding.
Distinguish a prepared instruction, a staged instruction and observed use.

## Choose a journey

| Mode | Purpose |
|---|---|
| Ordinary use | Notice confusion, repeated approvals, extra steps, delays, recovery and undocumented knowledge during useful work. |
| Deliberate feature exercise | Discover and complete a useful goal involving a recent change, underused feature, interaction between features or reported difficulty. |
| Human persona | Attempt the goal as a technically experienced, busy operator who knows the desired outcome but has not followed the implementation. |

Specify the goal, starting state and observable result. Let the actor discover
the route; do not supply a command-by-command answer. Reuse a few recurring
journeys for comparison and vary the exploratory ones. Include useful work
beyond software delivery when the selected instance supports it.

Prefer the existing installation and its realistic state, pending work and
history. Select a clean-install, version-gap upgrade or longer-running exercise
when relevant to the goal and within the available allowance. Do not rebuild
every installation on every commit. Use an owned disposable target when the
selected experiment would disrupt normal work.

## Preserve the first attempt

1. Record the goal, installed revision, relevant configuration and selected
   interface. Identify the actor's prior knowledge and any material model or
   harness difference from the comparison run.
2. Start the available passive observer before the first action. Follow
   [Request timings](request-timings.md) for every request, including retries,
   denials and failures. Keep timing completeness separate from task success.
3. For discovery testing, use a fresh-context actor when practical. Supply the
   goal, authority, installed help and ordinary user documentation. Keep the
   implementation, builder conversation and intended solution out of that
   attempt. Preserve normal sandbox instructions and required operational help.
4. Exercise the actual human interface for the persona: its terminal, browser
   or supported agent conversation. Do not replace an awkward interaction with
   a hidden application programming interface (API) call. Record machine-client
   success separately when testing the agent path.
5. Retain the original actions, output and difficulty before compensating.
   Supported recovery can continue the attempt. Record every workaround and
   extra piece of knowledge it needs. If insider knowledge supplied a step,
   report that fact instead of claiming first-use discovery.
6. Verify the requested effect and relevant retained restrictions from observed
   state. A successful command or the actor's final message is insufficient
   when another authoritative observation is available. Record failure,
   interruption and uncertain effects accurately before retrying.

After retaining the first attempt, use the
[operator-ux skill](../../operator-ux/SKILL.md) for informed assessment. Its
implementation-inspection step belongs after the discovery attempt. Apply the
target checkout's operator interaction contract as the single requirements
source. Label persona judgments about human understanding as hypotheses;
observed steps, output, timings and effects are evidence.

## Look for human conveniences

Inspect what the person must discover, remember, choose, type, edit and verify.
Pay particular attention to locating configuration files, learning their syntax,
copying identifiers, switching tools and discovering how to activate a change.
An edit that is easy for an agent can still expose a missing human path.

Look for the easiest supported route for the goal:

- A direct command-line interface (CLI) interaction can carry context, offer
  selection and sensible defaults, and explain the result.
- An agent-assisted interaction can prepare the change for an informed human
  decision. The proposal must identify the target and concrete change, explain
  material effects and activation, and use the existing approval controls.
  Preserve decisions already made and existing authority; do not introduce
  recurring confirmation for work that is already authorized.

Exercise the applicable route from discovery through its observed effect.
Where both routes are supported and relevant, record their results separately.
A generic suggestion to "ask an agent" is not proof that the assisted journey
works. Do not require a new direct CLI command for every capability.

For example, adding a service might work after the actor finds and edits a
configuration file. Record the functional success. Then check whether a human can discover a
convenient CLI path or ask an agent to prepare that exact change for review.
Verify the approval, application and effective state where those steps apply.
If manual editing is the only supported path, record the concrete human burden
and the missing convenience even though the file edit succeeded.

## Record and follow findings

Retain one compact result in the existing evidence and reporting locations:

| Field | Content |
|---|---|
| Goal and context | Mode/persona, starting state, installed revision, interface and material environment differences. |
| Attempt and result | Expected versus observed behavior; succeeded, succeeded with friction, failed or incomplete. |
| Evidence | Original interaction and effect observations; timing records, measurement scope and coverage gaps. |
| Compensation | Workaround, extra knowledge, assistance and recovery, including successful compensation. |
| Finding | Demonstrated defect, observed convenience gap, performance suspicion or other explicitly qualified judgment; practical impact. |
| Disposition | Existing issue, new actionable issue, bounded investigation or no finding, with relevant links. |

Keep individual timing records as supporting evidence. Report material changes
concisely instead of narrating every request or repeating unchanged findings.
Retain successful runs too, so later comparisons have a baseline. Reuse the
lab-controller's applicable capture and snapshot helpers; invoke the full lab
workflow only when the selected experiment needs it.

Search the durable issue tracker before creating a defect. Add material new
evidence to the same issue when it concerns the same failure. Preserve distinct
causes or user outcomes rather than merging them solely by similar wording.
Follow the existing publication and assignment route. Native Work and Coord
remain the execution record; issue state remains in the durable issue tracker.
A run log is evidence, not another defect-status or ownership ledger.

Keep the original finding when a workaround succeeds. When a repair reaches
the tested installation, repeat the affected journey and record the actual
revision and result. A merged fix alone is not an installed retest. Add focused
regression coverage through the existing process when useful. Dogfooding
observations and retests do not replace required independent acceptance.
