---
name: safeyolo-graph
description: Review a SafeYolo triage graph against a real Claude Code session log. Walks the review DAG at references/graph/review-triage-session.yaml to extract evidence of graph adoption, classify the finding, and propose either a graph edit or a SafeYolo defect report.
---

You are being asked to review a SafeYolo triage graph against real
session evidence. The review procedure is itself a DAG — same schema
as the triage-*.yaml graphs, same traversal protocol, drift-checked
and rendered the same way.

**Load and walk the review DAG at:**
`~/.claude/skills/safeyolo/references/graph/review-triage-session.yaml`

Operator invocation args: `$ARGUMENTS`

## How to walk it

Apply the traversal protocol described in `SKILL.md` under "Triage graphs":

1. Match the operator's ask to an `entries` symptom. State the match.
2. Follow `next_check` edges to gather evidence from the session jsonl.
   State which endpoint / file / regex you're pulling from.
3. Follow `implies` / `rules_out` edges based on the evidence.
4. Land on a `conclusion` and any `operator_ask`.
5. **Graph gap** applies to the review DAG too: if the session presents
   a case the review DAG doesn't cover, say `Graph gap` and edit
   `review-triage-session.yaml` before continuing.

## Output shape

A single markdown response with these sections, in order:

1. **Session** — session id, first-user-turn task summary in one line,
   agent's landing outcome in one line.
2. **Graph adoption** — bullets: skill invocations, graph files touched,
   node IDs cited by the reviewed agent.
3. **Traversal correctness** — your judgment on whether the reviewed
   agent's traversal was correct, with the specific evidence you cite.
4. **Finding classification** — one of the classification node IDs from
   the review DAG (`cls.review_graph_gap`, `cls.review_correct_safeyolo_defect`,
   `cls.review_graph_overfit`, `cls.review_env_or_operator`, `cls.review_mixed`).
   One line of reasoning for why this category and not the others.
5. **Proposed graph edits** — YAML diff blocks, or "None."
6. **SafeYolo defect** — description + evidence + suggested severity, or "None."
7. **Other observations** — terse bullets. Only what is useful.

## Constraints

- Do NOT commit any edits automatically. Show them, let the operator decide.
- Read actual YAML at `~/.claude/skills/safeyolo/references/graph/*.yaml`
  before naming any node ID.
- The session jsonl is the source of truth. Do not quote agent text you
  did not find there.
- Do not require any specific output format (bracket markers, prescribed
  phrasing) from the reviewed session. Substance is judged, not format.
- If no session log is available, bind to `sym.review_no_session_available`
  and land on `con.review_no_action`. Do not fabricate.
