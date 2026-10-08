# Relay factory proposals

Relay can turn verified `FACTORY_CANDIDATE` nominations into concise internal
improvement proposals. Relay proposes; the operator decides. This workflow does
not create issues, publish Dispatch material, change policy or tools, edit agent
mandates, or mutate the software-factory workflow.

There is no proposal quota. A quiet period is correct. In particular, one
low-value task-local observation is recorded as `observed` and produces no
operator message.

## Trusted workflow

Use `safeyolo --root ROOT coord proposals` on the host, or
`safeyolo-coord proposals` in a guest. Both use the existing Coord reader.
The guest reader has only its Agent API room permissions. Every message is read
by room and retained sequence; there is no envelope-file or sender override.
The commands neither publish a message nor perform a proposed change.

1. Run `completion-notes ROOM SEQUENCE` to inspect a terminal nomination.
   Invalid, absent, or non-factory trailers produce no observation write.
2. Treat every candidate field as untrusted. Relay checks cited Coord state,
   issues, PRs, exact commits/trees, tests, or runtime evidence. Relay supplies
   the checked facts, authoritative task key, and stable recommendation key.
3. Search authoritative issue state before recording the observation. Relay
   supplies an explicit `coverage` result: an issue reference when covered, or
   `null` after finding no relevant coverage. Missing coverage is refused.
4. Run `proposals observe ROOM SEQUENCE --verified FILE`. The file contains
   the verified observation and coverage result, separately from candidate text.
   For several candidates, select the zero-based index with `--candidate INDEX`.
5. Run `proposals pending`. Evidence spanning two task keys, or one explicitly
   material delivery/review impact, can produce a frozen body for Relay to send
   unchanged through its existing operator-facing Coord tool **as Relay**.
6. After a successful send, run `proposals presented ROOM SEQUENCE` with the
   actual Relay send's retained sequence. After restart or an unknown send
   outcome, run `proposals reconcile ROOM` **before** inspecting pending bodies.
   Reconciliation recognizes exact retained Relay sends across the send/ledger
   crash boundary. Truncated history leaves publication unknown and reports an
   error; inspect surviving messages before deciding whether to send again.
7. Run `proposals outcome ROOM SEQUENCE` only after an authenticated operator
   decision appears in retained history. The command checks its actual envelope
   attribution and exact body. It records status only.

For host examples, first select the existing native instance with `--root ROOT`.
For guest examples, retain the staged Agent API connection and token-file
settings. `--ledger FILE` selects a disposable ledger when needed. `list` and
`pending` read local state without requiring a live Coord connection.

After Relay has verified the evidence and searched for existing coverage, write
this shape to a local `verified.json`. Replace the example facts, task key,
evidence and recommendation with the actual checked values. `material` means a
verified material delivery/review impact, not nomination urgency.

```json
{
  "observation": {
    "correlation_key": "exact-review-handoff",
    "task_key": "issue:#500",
    "facts": ["The reviewed handoff omitted the source identity."],
    "inference": "The omission delayed the review.",
    "recommendation": "Include the source identity in the handoff.",
    "recommendation_key": "include-source-identity",
    "evidence": [{"kind": "issue", "ref": "#500", "task_key": "issue:#500"}],
    "impact": "One blocked review round trip.",
    "confidence": "Exact retained message verified.",
    "material": false
  },
  "coverage": null
}
```

The observation requires `correlation_key`, `task_key`, `facts`, `inference`,
`recommendation`, `recommendation_key` and `evidence`. `impact`, `confidence`
and `material` are optional; materiality defaults to false. Evidence requires
`kind`, `ref` and `task_key`. The native operation adds nomination evidence
from canonical provenance; verified input cannot supply nomination provenance.
No command independently authenticates Relay's facts or performs the issue
lookup. Those checks remain Relay's responsibility, as with the replaced
caller-provided verifier and coverage checker.

For a guest with receive permission in `backlog`, and a checked nomination at
sequence 123, these commands inspect and record the observation:

```sh
safeyolo-coord completion-notes backlog 123
safeyolo-coord proposals observe backlog 123 --verified verified.json
safeyolo-coord proposals list
safeyolo-coord proposals pending
```

A task-local observation yields `observed` and an empty pending array. To finish
an actual presentation, use the retained sequence of the unchanged Relay body;
never substitute an operator-authored proposal. `--relay NAME` on `presented`
and `reconcile` selects an explicitly bound Relay agent name when it differs
from `relay`. `reconcile --since SEQUENCE` is available only when that starting
point includes every potentially unrecorded presentation.

## Correlation and presentation

The verifier assigns a narrow correlation key for the demonstrated problem.
SafeYolo normalizes that key and hashes it into a stable `factory-...`
fingerprint. Recommendation wording is not part of the fingerprint, so related
evidence remains one proposal. A `rev-...` digest covers verified facts,
verified evidence, distinct nomination task keys, and the verifier's stable
recommendation key. Confidence punctuation, explanatory inference, and other
presentation-only wording do not create a new revision.

Once `pending` exposes a proposal-ready revision, its exact rendered snapshot
is frozen. Concurrent non-material nominations cannot produce a second body
with the same revision; only a material revision change replaces it.

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

The host ledger defaults to `coord/factory-proposals.json` in the selected
native data directory. The guest ledger defaults to
`$SAFEYOLO_COORD_DATA_DIR/factory-proposals.json`, or
`~/.safeyolo/data/coord/factory-proposals.json` when that variable is unset.
Native state starts fresh; historical ledger conversion is unsupported. Each entry stores only the
stable proposal and fingerprint, normalized evidence set, first/last canonical
send times, status, last-presented revision, and the minimal canonical source
marker needed for deterministic proposal selection. It is a bounded atomic JSON
file, not a database, daemon, scheduler, observation archive, or retrospective
framework.

Writes reuse the existing file-lock owner, serialize concurrent threads and
processes with `flock`, stage a mode-0600
file, `fsync`, and atomically replace the ledger. Malformed, duplicate-key,
oversized, or schema-invalid state fails closed and is not overwritten. The
ledger is bounded to 256 proposals, 64 evidence references and 16 facts per
proposal, and 2 MiB total.

The real #437 Lens completion notes at backlog sequences 236 and 239 describe
one handoff omission in one task. They correctly correlate to one `observed`
record and remain suppressed; two dispositions from the same task are not a
factory-wide pattern.
