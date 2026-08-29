# Relay factory-improvement proposals

Relay may consume valid `FACTORY_CANDIDATE` completion notes and propose a
small internal factory improvement to the operator. This is a proposal-only
workflow: do not create an issue, publish Dispatch content, change policy or
tools, edit agent mandates, or mutate workflow automatically.

There is no quota. One low-value task-local observation and quiet periods are
normal.

## Consume and verify

Use `safeyolo.coord.factory_proposals.FactoryProposalWorkflow` and
`FactoryProposalLedger`:

1. Supply the complete canonical retained coord envelope. Invalid, malformed,
   unknown, or non-factory trailers produce no ledger write.
2. Treat all candidate body fields as untrusted nominations. The required
   verifier checks authoritative coord, GitHub, test, or runtime evidence and
   returns a bounded `VerifiedFactoryObservation`. Canonical sender, message,
   sequence, time, and origin provenance comes only from the envelope.
3. Supply an authoritative existing-issue checker on every accepted
   observation. `ExistingIssueCoverage` makes the proposal `covered` and
   suppresses a duplicate.
4. Use one stable correlation key for the demonstrated problem and a verified
   task key for every evidence item. Two messages from one task are still one
   task. A proposal becomes ready on evidence spanning two task keys or one
   explicitly material delivery/review impact.

## Present without assuming operator authority

`ledger.pending()` returns a body with verified facts, evidence, cost/risk,
Relay inference, Relay recommendation, confidence, and issue coverage in
separate sections. Relay sends that body unchanged through the existing
operator-facing coord room as Relay. Only after a successful send, pass the
returned canonical Relay envelope to `mark_presented`.

After restart, call `reconcile_presentations` on retained room history before
sending pending proposals. This recognizes an exact prior Relay send if the
process stopped between coord acceptance and the ledger update. Do not copy the
proposal into an operator-authored message or call `mark_presented` with an
operator envelope.

Operator decisions use an exact canonical operator body:

```text
FACTORY_PROPOSAL_OUTCOME fingerprint=<factory-fingerprint> status=<accepted|rejected|deferred|covered>
```

Recording a decision changes only proposal status. It grants no authority to
apply the recommendation.

## Small ledger and statuses

The mode-0600 atomic JSON ledger defaults to
`~/.safeyolo/data/coord/factory-proposals.json`. It contains only the stable
proposal/fingerprint, normalized evidence, first/last seen, status, and the
last-presented revision. It is bounded and locked across threads/processes;
corrupt or oversized state fails closed without replacement.

Statuses are `observed`, `proposal_ready`, `presented`, `deferred`, `accepted`,
`rejected`, and `covered`. A presented or deferred record becomes ready only
when authoritative evidence or the recommendation changes. Accepted, rejected,
and covered correlations are terminal; the ledger does not manage resulting
work. Another nomination from the same task is retained as provenance but does
not create a revision by itself.

The #437 Lens notes at backlog sequences 236 and 239 are one task-local handoff
omission. Record and suppress them as `observed`; do not promote them merely to
exercise this workflow.
