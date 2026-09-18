# Backlog review routing

This is the ordinary coordinator workflow for the remaining #620 backlog. It
does not use the factory supervisor pattern.

## Roles and provider pinning

- The coordinator remains Terra medium.
- Implementation workers remain `gpt-5.6-luna` at `xhigh` reasoning.
- Routine candidate review runs in the background through
  `scripts/codex_deepseek_review.sh`, using the existing `ds-review` profile:
  OpenRouter provider `openrouter_review`, model
  `deepseek/deepseek-v4.1-flash`, and `max` model and plan reasoning.
- Final acceptance remains an independent Sol review at `gpt-5.6-sol` with
  high reasoning. A background review never replaces that acceptance.
- If the requested provider, model, or reasoning level cannot be proven at
  launch, stop and report the missing credential or configuration. Never
  silently substitute another model or provider.

## Session and candidate rules

Start a fresh reviewer session for each issue and stable candidate commit:

```sh
scripts/codex_deepseek_review.sh start 627 <candidate-sha> \
  'Review the retained facade workflow and route ledger against issue #627.'
```

The launcher writes JSONL, stderr, last-message and metadata files under the
evidence root and prints the background PID. Extract the explicit session id
from the JSONL log:

```sh
scripts/codex_deepseek_review.sh session-id <jsonl-log>
```

Correction rounds must resume that exact id:

```sh
scripts/codex_deepseek_review.sh resume 627 <session-id> \
  'Recheck the repaired findings against the same stable candidate.'
```

`--last` is intentionally rejected. The reviewer is read-only, does not run
Cargo builds/tests, and does not integrate commits. The coordinator records
its findings, hands concrete repairs to a Luna worker, and asks the same
review session to recheck the repaired candidate before requesting final Sol
acceptance.
