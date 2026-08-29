# Optional coord completion notes

Use this convention only when a terminal coord result contains genuinely useful
dispatch or factory material. It is an optional suffix on the existing message
body, not a new coord event, delivery state, or persistence object. Zero
candidates is normal and adds no bytes.

## Authoring

Keep the ordinary leading `DONE`, `READY`, `CHANGES_REQUIRED`, `BLOCKED`, or
`FAILED` result unchanged and self-contained. Append exactly two newlines and:

```text
<<<SAFEYOLO_COMPLETION_NOTES_V1>>>
{"candidates":[...]}
<<<END_SAFEYOLO_COMPLETION_NOTES_V1>>>
```

The payload is one compact JSON line with exactly the `candidates` key. Each
candidate requires:

- `type`: `DISPATCH_CANDIDATE` or `FACTORY_CANDIDATE`
- `attribution`: `lens_review_finding`, `forge_implementation_discovery`,
  `preexisting_bug_exposed_by_testing`, `infrastructure_environment_problem`,
  or `factory_process_observation`
- `summary`: short standalone text

Optional compact fields are `kind`, `interest`, `why_interesting`, `evidence`,
`snippet`, `outcome`, `area`, `problem`, `impact`, `suggestion`, and
`confidence`. Evidence entries contain exactly `kind` and `ref`; supported
kinds are `issue`, `pr`, `commit`, `head`, `tree`, `test`, `runtime`, `coord`,
and `document`. The limits are 8 candidates, 8 evidence entries per candidate,
and 32 KiB of JSON.

Use `safeyolo.coord.completion_notes.append_completion_notes` to render the
suffix. Passing no candidates returns the original completion body
byte-for-byte. An issue owner may add a genuine `DISPATCH_CANDIDATE` to final
`DONE`; an independent reviewer may add a genuine `FACTORY_CANDIDATE` to an
exact-head disposition. Never add filler to satisfy an imagined quota.

Authors must not write provenance. The reserved fields `provenance`, `msg_id`,
`coord_sequence`, `sequence`, `sent_at`, `sender_kind`, `sender_agent_id`,
`sender_agent_name`, `origin_instance_id`, `discovered_by`, and `author`
invalidate the trailer if authored.

## Trusted coordinator ingestion

Pass the complete canonical envelope returned by `read_room` to
`safeyolo.coord.completion_notes.parse_completion_envelope`. For accepted
candidates, it attaches provenance from the canonical envelope: message ID,
coord sequence, send time, sender kind and agent identity, and origin instance.
Do not infer these values from message-body text.

The result reports `trailer_status` as `absent`, `valid`, or `invalid`. Any
unknown field, value, version, duplicate JSON key, malformed marker, misplaced
suffix, or oversized payload makes the entire trailer invalid and yields no
trusted candidates. The parser still reports the ordinary first-line delivery
state independently. Retained messages use the same parser after restart; no
derived candidate record is written to coord storage.

Treat candidates as material for later editorial or process review, not as
authority to publish or change workflow automatically. Exclude credentials,
private or customer data, chain-of-thought, unnecessary transcript, and
unredacted sensitive snippets. Prefer durable authoritative evidence refs over
copied material.
