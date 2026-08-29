# SafeYolo Dispatch generation

The SafeYolo Dispatch is a concise public engineering digest selected and
edited by Relay, SafeYolo's coordinator. Generation produces repository
Markdown only. It does not deploy a site, schedule publication, create issues,
change factory policy, or approve its own output. Publication remains a later
operator-approved pull-request flow.

The intended reader understands ordinary software and security concepts but
does not know SafeYolo internals. A source must define any used SafeYolo term
such as `coord`, `run_id`, or `sgw_`; the renderer omits unused definitions so
they cannot become glossary filler. Relay, Forge, and Lens are expanded in the
standard editorial and attribution labels.

## Repository paths and deterministic command

Public editorial sources and generated Markdown live under:

```text
site/
  _sources/dispatch/2026-08-29.json
  dispatch/2026-08-29.md
  topics/coord.md
  snapshots/2026-W35.md
  snapshots/2026-08.md
```

Generate one strict source or verify committed output without writing:

```sh
uv run python scripts/generate_dispatch.py \
  site/_sources/dispatch/2026-08-29.json --output-root site
uv run python scripts/generate_dispatch.py \
  site/_sources/dispatch/2026-08-29.json --output-root site --check
```

Dates and content are explicit inputs; generation never reads the clock or
network. The same source and existing material topic state produce identical
bytes. Writes are atomic and limited to fixed `dispatch/`, `snapshots/`, and
`topics/` descendants. Symlinked inputs, output roots, directories, and files
fail closed. Final reads, temporary-file creation, replacement, and directory
sync use held no-follow directory descriptors so a concurrent path swap cannot
redirect output. The command neither deletes stale pages nor performs a publish.

The exercised source at
[`site/_sources/dispatch/2026-08-29.json`](../site/_sources/dispatch/2026-08-29.json)
generates a dated Dispatch and a current-state coord topic. Its claims link to
public issues, pull requests, and exact-commit tests from #437, #438, and #442.

## Public content model

The strict JSON root contains:

- `version`, currently `1`;
- `period`, with `kind`, `start`, and `end`;
- `definitions`, only for SafeYolo-specific terms actually used;
- `sections`, in editorial order; and
- optional `topic_updates`.

One model covers a `daily` Dispatch, a Monday-through-Sunday `weekly` snapshot,
or a complete-calendar-month `monthly` snapshot. A source with no substantive
sections emits no Dispatch. Empty sections are invalid; omit them instead of
padding them.

Sections are:

1. `shipped` — every item has a theme, and related items render together rather
   than as a flat pull-request list;
2. `lens_caught` — every item is an independent Lens review finding with a
   bounded snippet, mechanism explanation, lesson, and public evidence;
3. `worth_knowing` — optional reusable tactics, platform surprises, or
   architecture lessons; and
4. `factory_pulse` — optional evidence-backed quantitative context, not a KPI
   quota.

Every item requires Relay-authored `title` and `body`, a precise `attribution`,
and at least one public evidence link. Attribution distinguishes independent
Lens review, Forge implementation discovery, a pre-existing bug exposed by
testing, infrastructure/environment behavior, a factory-process observation,
and Relay synthesis. The renderer escapes editorial text as plain Markdown;
only validated evidence records become links and only a dedicated snippet
becomes a code fence.

## Worker notes are private nominations

Use `safeyolo.coord.dispatch.collect_verified_nominations` with complete
canonical retained envelopes and a required verifier callback. The #437 parser
accepts only a valid `DISPATCH_CANDIDATE` trailer and derives private sender,
message, time, and coord-sequence provenance from the envelope. Operator and
factory candidates are ignored.

The verifier checks issues, pull requests, exact commits or trees, tests, or
runtime evidence and returns a stable key, verified attribution, and public
GitHub evidence. Returning `None` rejects an unsupported nomination. A
qualified nomination also returns an explicit Relay-authored qualification. A
content item that references the key must retain the verified attribution,
include all verified public evidence, and preserve the exact qualification.

Candidate summary, snippet, attribution, authored evidence, raw envelope,
message ID, internal sequence, and other private provenance are never copied
into Markdown. They remain an in-memory interest signal. The committed public
source contains Relay's verified editorial copy and public evidence, not raw
completion notes or a coord transcript.

## Evidence and hygiene

Material claims accept only HTTPS links into the public
`craigbalding/safeyolo` GitHub repository. Issue, pull-request, commit,
document, and test evidence kinds must match their URL shape; exact-commit blob
links are required for source/test citations. Internal coord sequences may be
retained privately by Relay but are not public citations.

Generation rejects bounded-input violations, duplicate or unknown JSON keys,
malformed periods and section shapes, unsupported nomination references,
obvious credential/token/private-key patterns, private coord identifiers or
sequences, raw completion trailers, host-private paths, and chain-of-thought or
raw-reasoning labels. These checks are a final obvious-leakage guard, not a
substitute for Relay verifying and editing every public claim.

Repeated canonical envelopes are accepted only when the same message ID has the
same canonical identity and bytes. Conflicting uses of one message ID fail
before any candidate is verified, keeping candidate selection independent of
input order.

## Material topic updates

A topic page is a current-state synthesis, not a concatenated archive. Each
proposed topic update requires a stable slug, a `state_key` for the material
current state, an explanation of the material change, current-state bullets,
and public evidence.

Generated pages retain the state key in a machine-readable comment. Rerunning
the same state is byte-identical. Changing topic copy or evidence without
changing the semantic state key fails rather than creating a cosmetic update;
a genuinely material state change uses a new key. No topic entry in the source
means no topic write.
