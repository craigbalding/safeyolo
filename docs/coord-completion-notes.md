# Coord completion notes

Coord terminal messages may carry a small, optional structured trailer for
Relay to collect potentially useful dispatch or factory evidence. The trailer
does not change coord delivery state, add an event type, or require new
persistence. It is part of the existing message body.

Use a note only when the completed work produced genuinely useful material.
Zero candidates is normal: send the ordinary completion with no trailer and no
extra bytes. This convention is not a quota or a request to invent content.

## Wire contract

Keep the existing leading transition unchanged: `DONE`, `READY`,
`CHANGES_REQUIRED`, `BLOCKED`, or `FAILED` must begin the first line. When notes
exist, append exactly two newlines and this terminal suffix:

```text
<<<SAFEYOLO_COMPLETION_NOTES_V1>>>
{"candidates":[...]}
<<<END_SAFEYOLO_COMPLETION_NOTES_V1>>>
```

The middle line is one compact JSON object containing exactly `candidates`.
Each candidate requires:

- `type`: `DISPATCH_CANDIDATE` or `FACTORY_CANDIDATE`
- `attribution`: one of `lens_review_finding`,
  `forge_implementation_discovery`, `preexisting_bug_exposed_by_testing`,
  `infrastructure_environment_problem`, or `factory_process_observation`
- `summary`: a short, standalone explanation

These compact fields are optional when they add useful context:

- `kind`, `interest`, `why_interesting`, `snippet`, and `outcome` for dispatch
  material
- `area`, `problem`, `impact`, `suggestion`, and `confidence` for factory
  material
- `evidence`, a list of `{"kind":...,"ref":...}` objects. Evidence kinds are
  `issue`, `pr`, `commit`, `head`, `tree`, `test`, `runtime`, `coord`, and
  `document`.

The supported limits are 8 candidates, 8 evidence references per candidate,
and 32 KiB for the JSON payload. The implementation also bounds individual
text fields. Authors can write the compact JSON line using the wire contract
above and send the complete body through their ordinary native Coord command or
Model Context Protocol (MCP) tool. If there are no candidates, omit the suffix
and leave the original body byte-for-byte unchanged. No Python helper import is
needed to author a note.

## Trusted ingestion

On the host, use `safeyolo --root ROOT coord completion-notes ROOM SEQUENCE`.
In a guest, use `safeyolo-coord completion-notes ROOM SEQUENCE` with the ordinary
scoped Agent API connection. The commands read exactly the requested retained
sequence through the existing Coord reader and parse its canonical envelope.
Neither command accepts an envelope file or authored sender identity. The parser derives `msg_id`, coord `sequence`, send time, sender identity, and
origin instance from that envelope and attaches them as `provenance` to every
accepted candidate. Authors must never supply provenance.

Authored fields named `provenance`, `msg_id`, `coord_sequence`, `sequence`,
`sent_at`, `sender_kind`, `sender_agent_id`, `sender_agent_name`,
`origin_instance_id`, `discovered_by`, or `author` invalidate the entire
trailer. Unknown fields, versions, values, duplicate JSON keys, misplaced
markers, and malformed or oversized payloads likewise yield no trusted
candidates. `trailer_status` reports `absent`, `valid`, or `invalid`; an invalid
suffix does not become a delivery state and does not suppress the ordinary
leading transition.

Parse retained canonical envelopes in the same way after restart. No derived
candidate record is written back to coord storage, so provenance remains a
view of the authoritative retained message rather than author-controlled data.

## Author and coordinator guidance

Issue owners may put a genuine `DISPATCH_CANDIDATE` on their final `DONE`.
Independent reviewers may put a genuine `FACTORY_CANDIDATE` on their exact-head
disposition. Keep the ordinary leading disposition and its required evidence
self-contained; the trailer is optional metadata, not the result itself.

Relay may collect valid candidates for later editorial or process review, but
must not automatically publish them or change workflow from them. Do not put
credentials, private or customer data, chain-of-thought, unnecessary room
transcripts, or unredacted sensitive snippets in a candidate. References are
preferable to copied evidence when the authoritative source is durable.

For durable correlation, issue-coverage checks, suppression, and presentation,
use the [Relay factory-proposal workflow](factory-proposals.md). Candidate text
remains an untrusted nomination; Relay must verify facts from authoritative
sources before the proposal ledger accepts it.

For public engineering digests, use the
[Relay Dispatch generation contract](dispatch-generation.md). Dispatch notes
remain private nominations: Relay verifies public evidence and authors new
copy; raw candidate text, coord provenance, and transcripts are never rendered.
