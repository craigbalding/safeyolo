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
constraints, not to patch missing ownership, handoff, liveness, or recovery
rules in the contracts.

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
