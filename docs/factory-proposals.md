# Relay factory proposals

Relay can turn verified `FACTORY_CANDIDATE` nominations into concise internal
improvement proposals. Relay proposes; the operator decides. This workflow does
not create issues, publish Dispatch material, change policy or tools, edit agent
mandates, or mutate the software-factory workflow.

There is no proposal quota. A quiet period is correct. In particular, one
low-value task-local observation is recorded as `observed` and produces no
operator message.

## Trusted workflow

Use `safeyolo.coord.factory_proposals.FactoryProposalWorkflow` with a
`FactoryProposalLedger`:

1. Pass the complete canonical retained coord envelope to `consume_envelope`.
   The #437 parser accepts only a valid completion-note trailer and attaches
   sender identity, coord sequence, message ID, send time, and origin from the
   envelope.
2. Treat every candidate field as an untrusted nomination. The verifier must
   check cited coord state, issues, PRs, exact commits/trees, tests, or runtime
   evidence and return a bounded `VerifiedFactoryObservation`. It also supplies
   the authoritative task key used to distinguish recurrence from two messages
   about one task and a stable recommendation key that changes only when the
   proposed intervention materially changes.
3. Search authoritative issue state through `find_existing_issue` before any
   ledger write. Return `ExistingIssueCoverage` when an open or otherwise
   relevant issue already covers the intervention; the record becomes
   `covered` and is not proposed again.
4. Call `pending`. A proposal becomes ready after verified evidence spans two
   task keys, or after the verifier explicitly identifies one material delivery
   or review impact. Repeated messages from one task do not establish
   recurrence.
5. Relay sends the returned body unchanged over the existing operator-facing
   coord room as Relay, never as the operator. Pass the canonical envelope
   returned by the successful send to `mark_presented`.
6. On restart, call `reconcile_presentations` with retained operator-facing room
   history before sending pending work. It closes the crash boundary where
   coord accepted a proposal but Relay stopped before recording the returned
   envelope.

No component in this module sends a message or performs a proposed change.
Rendering is deliberately separate from Relay's attributed coord send.

## Correlation and presentation

The verifier assigns a narrow correlation key for the demonstrated problem.
SafeYolo normalizes that key and hashes it into a stable `factory-...`
fingerprint. Recommendation wording is not part of the fingerprint, so related
evidence remains one proposal. A `rev-...` digest covers verified facts,
verified evidence, distinct nomination task keys, and the verifier's stable
recommendation key. Confidence punctuation, explanatory inference, and other
presentation-only wording do not create a new revision.

Evidence is deduplicated and sorted. Every accepted nomination also gains a
coord evidence reference built from canonical envelope provenance; authored
candidate provenance is never used. A revision already presented remains
quiet after restart. New authoritative evidence or a materially changed
recommendation creates a new revision that can return a presented or deferred
proposal to `proposal_ready`. A repeated nomination from the same task is
retained for provenance but does not by itself create a new revision. Canonical
send time and message ID select proposal wording deterministically, so replay or
out-of-order catch-up cannot restore an older recommendation.

Rendered text separates:

- verified observed facts and authoritative evidence;
- observed cost or risk;
- Relay inference;
- Relay recommendation;
- confidence and uncertainty;
- existing-issue coverage.

Every proposal ends by stating that operator action is required and no change
has been applied.

## Status semantics

The ledger is proposal deduplication, not work management:

- `observed` — verified but still task-local or below the materiality bar.
- `proposal_ready` — repeated or material evidence supports operator review.
- `presented` — the exact current revision was returned in a canonical Relay
  agent envelope.
- `deferred` — the operator deferred the presented revision; it remains quiet
  until its revision changes.
- `accepted` and `rejected` — terminal immutable operator decisions for the
  exact presented proposal snapshot.
- `covered` — authoritative issue lookup or the operator found existing
  coverage; the snapshot is terminal and no duplicate proposal is rendered.

Operator outcomes are accepted only from a canonical operator envelope whose
body is exactly:

```text
FACTORY_PROPOSAL_OUTCOME fingerprint=<factory-fingerprint> status=<accepted|rejected|deferred|covered>
```

Recording an outcome changes ledger status only. `accepted` does not apply the
recommendation or create follow-up work.

## Deliberately small persistence

The default ledger is
`~/.safeyolo/data/coord/factory-proposals.json`. Each entry stores only the
stable proposal and fingerprint, normalized evidence set, first/last canonical
send times, status, last-presented revision, and the minimal canonical source
marker needed for deterministic proposal selection. It is a bounded atomic JSON
file, not a database, daemon, scheduler, observation archive, or retrospective
framework.

Writes take an in-process lock and an inter-process `flock`, stage a mode-0600
file, `fsync`, and atomically replace the ledger. Malformed, duplicate-key,
oversized, or schema-invalid state fails closed and is not overwritten. The
ledger is bounded to 256 proposals, 64 evidence references and 16 facts per
proposal, and 2 MiB total.

The real #437 Lens completion notes at backlog sequences 236 and 239 describe
one handoff omission in one task. They correctly correlate to one `observed`
record and remain suppressed; two dispositions from the same task are not a
factory-wide pattern.
