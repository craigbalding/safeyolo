# Cross-contract review

Review a factory as one distributed behavioral contract. A polished role file
can still contradict another role or create a dead end at an edge.

## Establish scope and authority

Read, in full:

1. the factory TOML;
2. every role contract it links;
3. the applicable live operator brief, if one exists;
4. for a running factory, the approved snapshot and supervisor-staged snapshot
   identity and hashes reported by `safeyolo factory doctor FACTORY` or
   equivalent exact evidence.

Distinguish source files from the approved immutable snapshot, the snapshot
last staged into each running role, and the live brief. Approval selects the
next run; it does not alter a running factory. If a required source is missing,
request it or declare a partial review boundary.

## Build the review model

Extract an authority/evidence matrix and an instance-specific Mermaid graph.
At minimum capture:

- each role's owned outcome, authority, and forbidden actions;
- work discovery or inputs and completed outputs;
- each request and response route, including all required recipients;
- artifact or exact version identity crossing each edge;
- independent evidence and who judges it;
- waits, timeouts only where real, rejection and retry paths;
- failure, restart, recovery, and escalation ownership;
- operator inputs and attention points;
- useful backfill or quiescence when a lane is waiting.

Use exact message types and canonical role bindings from the TOML. Do not infer
authority from role names or from prose-like message bodies.

## Run all passes

Traverse [`graph/contract-review.yaml`](graph/contract-review.yaml), then test
the model from these perspectives:

1. **Outcome and responsibility:** Every necessary result and ordinary failure
   has one final owner. Responsibilities do not silently overlap or disappear.
2. **Reachability and liveness:** Useful work can enter, every intended role can
   be reached, responses return to everyone who must act, and no normal wait
   strands the factory.
3. **Authority and mutation:** Discovery, implementation, review, merge or
   publication, and operator-only choices have explicit owners and boundaries.
4. **Evidence:** The reviewer can obtain credible evidence independently;
   success does not depend circularly on the producer's assertion.
5. **Handoff integrity:** A recipient gets the exact work identity/version and
   enough context to act without reconstructing a hidden conversation.
6. **Concurrency and recovery:** Duplicate delivery, concurrent tasks,
   rejection, supersession, process failure, and restart have coherent owners.
7. **Runtime feasibility:** The roles can actually use the approved tools,
   environments, data, and message routes their responsibilities require. For
   each required resource, distinguish existence, intended permissions and
   content, and consumer discoverability: the consuming role can locate it
   from its actual injected context or an ordinary inventory. Controller-only
   metadata does not establish usable access.
8. **Operator experience:** Material decisions surface clearly; silence does
   not falsely mean health; slow operator response is not treated as refusal.
9. **Simplicity:** The same behavior is not represented twice, and machinery is
   not being added for speculative control.

## Audit restrictions separately

List every `MUST`, gate, approval, exact format, numerical limit, eligibility
rule, and condition that can cause `BLOCKED`. For each, identify its basis:

- an explicit operator requirement;
- a concrete safety property;
- an external or technical necessity.

If none applies, remove it or demote it to guidance. If precision is real but
the value is not known, ask the operator; do not invent a threshold. Check that
several individually reasonable restrictions do not compose into an
accidental deadlock.

## Revise iteratively, then globally

Rank findings by material effect: disaster exposure, stranded work, wrong
authority, false success, lost recovery, avoidable throughput loss, then
clarity. Propose the smallest coherent diff rather than a parallel design.

After any file changes, re-read the exact TOML and all role contracts and run
the full set review again. Report:

- material findings fixed;
- remaining material findings;
- assumptions or unavailable evidence;
- intentionally advisory observations.

Do not claim the contracts are contradiction-free in an absolute sense. Say
there are no *known material* contradictions or gaps after the stated review.
