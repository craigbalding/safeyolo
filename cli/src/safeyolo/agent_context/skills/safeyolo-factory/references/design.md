# Factory design

## Start with the product

Establish the repeated outcome before discussing agents:

1. What does the factory produce, for whom, and what makes one output useful?
2. Where does eligible work originate, and who decides priority?
3. What mistakes are tolerable, what would be a disaster, and what must remain
   an operator decision?
4. What evidence makes an output credible enough to hand off or finish?
5. What external tools, environments, credentials, and approved resources are
   available?
6. What must happen after ordinary failure, agent restart, partial completion,
   or a slow operator response?
7. What throughput or parallelism is actually useful now?

Ask these in small rounds. Do not force answers that are irrelevant to the
operator's outcome. When a risk choice is a design hinge, ask a concrete
deal-breaker question rather than imposing a general risk appetite.

## Derive the topology

Use the smallest role set that can own the work. Give each additional role a
concrete reason. Common reasons are:

- its judgment must be independent of the work producer;
- its authority conflicts with another role's authority;
- it needs a distinct approved capability or execution environment;
- parallel work materially improves useful throughput.

For every role, state:

- outcome owned;
- work it may select or accept;
- authority and prohibited mutations;
- required inputs and self-contained handoff outputs;
- evidence it creates or verifies;
- ordinary recovery responsibility;
- when it asks another role or the operator;
- what productive backfill it owns when its main lane is waiting.

Do not assume every factory needs a coordinator. If coordination exists, give
it a concrete mission such as keeping useful work flowing, unblocking workers,
and surfacing material operator choices. Do not turn it into a generic state
store. Likewise, a reviewer owns credible validation and selection of the
right approved testing tools; lack of an immediately convenient harness is a
problem to solve, not automatically a blocker.

An operator who is slow or asleep has not denied a request. Define what useful
work continues while awaiting input. Reserve `BLOCKED` for a genuine impasse,
not ordinary dwell time.

## Design the handoffs

For each handoff, record:

- canonical sender and recipient roles;
- exact work identity and version when staleness matters;
- minimum self-contained context;
- evidence or artifact needed by the recipient;
- response recipients;
- retry, rejection, supersession, and restart behavior;
- who notices if the handoff does not progress.

Coord envelope identity proves the sender. Names written inside message bodies
do not. Avoid duplicate protocol forms for the same semantic transition.

A brief is optional live operator direction. Use it for priorities or changing
constraints and instance bindings as described below. Keep ownership, handoff,
liveness and recovery responsibilities in the domain contracts.

## Keep each instruction in its own place

| Home | Responsibility |
|---|---|
| Coord and Factory runtime | Domain-neutral identities, ownership, versioned output references, checks/challenges, selected acceptance, authorized transitions, delivery and recovery. |
| Domain contract and TOML | Responsibilities, role bindings, authority, handoffs and quality expectations for that kind of work. Software delivery can require implementation, independent review and integration without selecting a language or repository host. |
| Instance brief and referenced project guidance | Purpose, priorities, repositories or targets, environments, concrete tool inventories/procedures, resource locations and deliberate variations of declared defaults. Repository instructions remain discoverable project defaults. |
| Native Work and linked assignment | One outcome, exact inputs, constraints and applicable requirements. Link the full assignment through `external_ref` when it does not fit the native record. |

Bind role names to actual identities through the selected TOML and canonical
membership. Keep agent names and project commands out of reusable domain
responsibilities. A brief can link one maintained project/tool guide instead
of copying its procedures into every role. The consuming role must be able to
locate and read the guide from its actual context.

### Brief variations

Within existing authority, ordinary brief changes can reorder priorities,
bind a different test environment or approved tool guide, choose a reporting
format, or vary a declared working default. For example, a software instance
can bind Cargo tests in one repository and pytest in another. A report instance
can request a short decision table instead of narrative findings. These changes
need no new approval when the operator has already authorized them.

An authorized brief can also direct a change to role authority, required
acceptance or capabilities. Prose alone does not apply that change. For example,
adding a decider requires the corresponding selected native requirements;
changing future Factory defaults requires coherent TOML approval and staging;
and a new service capability requires its effective grant. Existing Work
retains its policy. Use current authorized controls for the affected records,
preserve in-flight work, and verify effective access before relying on it.
Do not ask again for an already authorized change. Ask only for genuinely
missing authority or a material undecided choice.

## Walk the separation across domains

These are illustrative bindings, not new inventories or mandatory topologies.
During review, trace each example from its selected responsibilities through
readable instance inputs to one complete assignment and result.

| Example | Domain responsibilities | Instance inputs | One item and its review |
|---|---|---|---|
| Rust proxy repository | Selected software owner implements; independent reviewer challenges; coordinator integrates. | Repository instructions and brief bind the default branch, Cargo/Clippy and scanner guidance, allowed environments and repository host. | Linked assignment supplies the defect, starting commit and criteria. Owner publishes an immutable candidate; selected check and acceptance govern integration. |
| Python library repository | The same software responsibilities apply. | That repository's instructions and brief bind its different default branch, pytest/Ruff, access and publication route. Rust procedures do not carry over. | Linked assignment supplies the API change and exact inputs. Review uses that repository's tools and immutable candidate, including when its host is not GitHub. |
| Assessment/report factory | An analyst produces findings; an assessor judges the specified proposition. No coordinator is required when direct authorized assignment suffices. | Brief binds the evidence collection, readable sources, report format and publication destination. | Ordinary Work asks an open-ended question and publishes a retained report. A separate exact-subject check can judge a conclusion after publication; independent review needs the attributed producer. |

The runtime supplies identity, versions and authorized transitions in all three
examples. It does not decide whether software is correct or a report's evidence
supports its conclusion. Those judgments remain with the selected domain roles.

## Prefer a thin first design

Produce a minimal topology and an annotated Mermaid graph before long prose.
Keep each role contract focused on responsibility and collaboration. Express
only restrictions that follow from an operator requirement, a real safety
property, or an external technical constraint.

The first acceptance plan should prove:

- one representative item travels end to end;
- required evidence is independently challenged where intended;
- an ordinary failure or restart recovers without losing or duplicating work;
- waiting roles remain useful or genuinely quiescent;
- the operator can understand progress and material attention needs.

Do not treat an initial passing run as proof of all concurrency, long-duration,
or production failure behavior.
