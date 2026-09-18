# Backlog review routing

This is the ordinary coordinator workflow for the remaining #620 backlog. It
does not use the factory supervisor pattern.

## Roles and provider pinning

- The coordinator remains Terra medium.
- Implementation workers remain `gpt-5.6-luna` at `xhigh` reasoning.
- Routine issue review and acceptance run through
  `scripts/codex_deepseek_review.sh`, using the `opencode-go-review` profile:
  OpenCode Go provider `opencode_go_review`, model
  `deepseek-v4.1-flash`, and `max` model reasoning. The previous
  `openrouter-ds-review` profile remains available as an explicit rollback
  override through `SAFEYOLO_REVIEW_PROFILE`.
- DeepSeek is the independent reviewer and acceptance authority for each
  routine issue. It inspects the execution paths and callers, runs required
  builds and focused tests or probes, verifies retained evidence, reports
  findings, verifies corrections, and writes the acceptance receipt. Its
  `READY` receipt satisfies the independent-review requirement for issue and
  integration acceptance under the existing rules.
- Sol at `gpt-5.6-sol` with high reasoning is reserved for an explicitly
  escalated concrete problem or the integrated final-release acceptance
  milestone. There is no additional per-issue Sol gate.
- If the requested provider, model, or reasoning level cannot be proven at
  launch, stop and report the missing credential or configuration. Never
  silently substitute another model or provider.

## Session and candidate rules

Start one fresh reviewer session for each issue. Keep that session for every
candidate correction round:

```sh
scripts/codex_deepseek_review.sh start 627 <candidate-sha> \
  'Review the retained facade workflow and route ledger against issue #627.'
```

The launcher writes JSONL, stderr, last-message, acceptance-receipt and
metadata files under the evidence root and prints the pane details. Extract
the explicit session id
from the JSONL log:

```sh
scripts/codex_deepseek_review.sh session-id <jsonl-log>
```

Correction rounds must resume that exact id:

```sh
scripts/codex_deepseek_review.sh resume 627 <session-id> \
  'Recheck the repaired findings against the same stable candidate.'
```

`--last` is intentionally rejected. The reviewer runs the required validation
within its contained, no-approval session but does not edit product source or
configuration, integrate commits, or change issue state. The coordinator
records its receipt, hands concrete repairs to a Luna worker, and asks the
same explicit review session to recheck the repaired candidate. A separate
Sol review is started only for a bounded escalation or the final integrated
release acceptance. The launcher grants write access only to the configured
evidence root for disposable output; each issue reuses its
`targets/<issue>` directory across correction rounds and concurrent issues use
distinct target directories.

The visible pane reuses the factory timeline renderer in
`contrib/watch-agent-room.py` with its local `--jsonl -` input. It shows
bounded session, tool, agent, completion and error lines while the raw JSONL
remains the retained source of truth. A successful `READY` pane closes after
its receipt is copied; a failed or non-READY pane remains for inspection.
