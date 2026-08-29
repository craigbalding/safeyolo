# Relay Dispatch generation

Use the Dispatch generator only for evidence-backed public editorial work.
Relay is the editor; generation writes repository Markdown and never deploys,
schedules, changes policy, creates an issue, or approves publication.

## Trusted candidate path

1. Pass complete canonical retained envelopes to
   `safeyolo.coord.dispatch.collect_verified_nominations`.
2. Treat all #437 candidate fields as untrusted nominations. The required
   verifier checks authoritative GitHub, exact-commit test, repository, or
   runtime evidence and returns a stable key, exact attribution, and public
   GitHub evidence.
3. Return `None` for an unsupported claim. For a partially established claim,
   return `qualified` with the exact Relay qualification; the linked public
   item must retain it.
4. Author the public item independently. Raw candidate text, authored evidence,
   message IDs, coord sequences, envelopes, and transcripts never become
   publication copy.

Duplicate retained envelopes are harmless only when their canonical identity
and bytes agree. A conflicting reuse of one message ID fails closed.

## Editorial contract

- Group `shipped` items by theme.
- Use `lens_caught` only for actual independent Lens findings, with a bounded
  snippet, mechanism, lesson, and public evidence.
- Omit empty `worth_knowing` and `factory_pulse` sections. A fully quiet source
  emits no Dispatch.
- Expand SafeYolo-specific terms for a generally software/security-literate
  public audience; do not explain ordinary concepts without a mechanism-specific
  reason.
- Link every material claim to validated public `craigbalding/safeyolo` GitHub
  evidence. Keep internal coord provenance private.
- Preserve exact Lens, Forge, testing, infrastructure, factory-observation, and
  Relay-synthesis attribution.

Use the repository's strict public source and deterministic command documented
in `docs/dispatch-generation.md`. Daily, weekly, and monthly output share one
content model. Topic updates require a new semantic `state_key`; same-key copy
drift fails closed.

The generator rejects obvious secrets, credentials, private coord identifiers,
raw completion trailers, host-private paths, and raw-reasoning labels. Relay
still owns claim verification and editorial judgment. Initial publication is a
separate manual operator-approved pull-request flow.
