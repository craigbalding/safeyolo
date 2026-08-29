# Relay Dispatch generation

Use the Dispatch generator only for evidence-backed public editorial work.
Relay is the editor; generation writes repository Markdown and never deploys,
schedules, changes policy, creates an issue, or approves publication.

## Final manifest path

1. Treat worker observations as leads and verify every material claim against
   authoritative public evidence.
2. Author the item independently with its final attribution and evidence. Raw
   candidate text, message IDs, coord sequences, envelopes, and transcripts
   never become publication copy.
3. Give the generator the final JSON manifest. It does not consume coord
   envelopes or perform candidate verification.

## Operator editorial interaction

Before drafting a substantive public item:

1. Tell the operator in normal language what SafeYolo was trying to do, what
   happened, and why it may be interesting. Give enough technical context for
   an informed reaction; do not send publication copy as the prompt.
2. When the significance needs operator judgment, ask one focused question.
   Do not turn this into a questionnaire, writing assignment, or repeated draft
   loop.
3. Use the response as source material and author one item. If the material is
   not worth publishing, omit it instead of manufacturing a takeaway or hook.

Orient the resulting item around what SafeYolo is doing and why before
introducing internal mechanisms. Keep evidence and attribution traceable
without making the prose read like an audit record.

## Editorial contract

- Group `shipped` items by theme.
- Use `lens_caught` only for actual independent Lens findings, with a bounded
  snippet, mechanism, lesson, and public evidence.
- Omit empty `worth_knowing` and `factory_pulse` sections. A fully quiet source
  emits no Dispatch.
- Expand SafeYolo-specific terms for a generally software/security-literate
  public audience; do not explain ordinary concepts without a mechanism-specific
  reason.
- Link every material claim to authoritative public evidence. Match known
  GitHub issue, pull-request, commit, document, and test URL shapes to the
  declared evidence kind. Keep internal coord provenance private.
- Preserve exact Lens, Forge, testing, infrastructure, factory-observation, and
  Relay-synthesis attribution.

Use the repository's strict public source and deterministic command documented
in `docs/dispatch-generation.md`. Daily, weekly, and monthly output share one
content model. Topic updates require a new semantic `state_key`; same-key copy
and evidence corrections are allowed when the material state is unchanged.

The generator rejects obvious secrets, credentials, private coord identifiers,
raw completion trailers, host-private paths, and raw-reasoning labels. Relay
still owns claim verification and editorial judgment. Initial publication is a
separate manual operator-approved pull-request flow.
