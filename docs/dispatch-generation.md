# SafeYolo Dispatch generation

The SafeYolo Dispatch is a concise public engineering digest selected and
edited by Relay, SafeYolo's coordinator. The generation command produces
repository Markdown only: it does not deploy, schedule, create issues, change
factory policy, or approve its own output. Scheduling, operator approval, CI,
and Pages deployment are separate plumbing described in
[Dispatch delivery and publication](dispatch-publication.md).

The intended reader understands ordinary software and security concepts but
does not know SafeYolo internals. Sources own their terminology definitions;
the renderer supports any concise defined term and emits it only where the
content uses it. Relay, Forge, and Lens are expanded in the standard editorial
and attribution labels.

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
network. The same source produces identical bytes. Writes are atomic and
limited to fixed `dispatch/`, `snapshots/`, and `topics/` descendants. The
command rejects symlinked inputs, output-root symlinks, output symlinks, and
directory symlinks that escape the selected output root. Temporary files stay
beside their target and are atomically replaced. The command neither deletes
stale pages nor performs a publish.

The exercised source at
[`site/_sources/dispatch/2026-08-29.json`](../site/_sources/dispatch/2026-08-29.json)
generates a dated Dispatch and a current-state coord topic. Its claims link to
public issues, pull requests, exact-commit tests, and live-trial evidence.

## Operator editorial interaction

Before Relay drafts a substantive item, Relay gives the operator a short,
normal-language account of what SafeYolo was trying to do, what happened, and
why it may be interesting. When the significance needs operator judgment,
Relay asks one focused question—not a questionnaire, writing assignment, or
request to review repeated drafts. The response becomes source material for one
authored item, or Relay omits the material if it is not worth publishing.

The resulting item establishes what SafeYolo is doing and why before it
introduces internal mechanisms. Public evidence and attribution remain
traceable without structuring the prose like an audit record.

## Public content model

The strict JSON root contains:

- `version`, currently `1`;
- `period`, with `kind`, `start`, and `end`;
- `definitions`, a content-owned map of concise terms actually used;
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

## The final manifest is the publication input

Private worker observations may nominate a topic for Relay to investigate.
They do not establish a public claim. Before generation, Relay independently
writes each claim and supports it with public evidence. The command consumes
only that final JSON manifest. Raw completion notes, coord envelopes,
transcripts, and other private text are neither copied nor cited, and they are
never generator inputs.

## Evidence and hygiene

Material claims accept public HTTPS evidence, including authoritative upstream
sources. Credentials, query data, malformed Markdown-breaking destinations,
private or noncanonical numeric addresses, and internal hostnames are rejected.
On GitHub, issue, pull-request, commit, document, and test evidence kinds must
match their URL shape. Relay remains responsible for establishing that each
public source is authoritative for its claim. Internal coord sequences may be
retained privately but are not public citations.

Generation rejects bounded-input violations, duplicate or unknown JSON keys,
malformed periods and section shapes, obvious credential/token/private-key
patterns, private coord identifiers or sequences, raw completion trailers,
host-private paths, and chain-of-thought or raw-reasoning labels. These checks
are a final obvious-leakage guard, not a substitute for Relay verifying and
editing every public claim.

## Material topic updates

A topic page is a current-state synthesis, not a concatenated archive. Each
topic update requires a stable slug, a `state_key` for the material current
state, current-state bullets, and public evidence.

Generated pages retain the state key in a machine-readable comment. Copy and
evidence corrections may keep the same key; a genuinely material state change
uses a new one. No topic entry in the source means no topic write.

Generated Markdown includes fixed Jekyll front matter and canonical
permalinks. `scripts/check_dispatch_site.py` regenerates every retained source
in memory and checks committed bytes, metadata, duplicate periods and paths,
obvious leaks, local and HTTPS links, and publication-branch path scope. The
check is mechanical; it does not judge Relay's prose or evidence quality.
