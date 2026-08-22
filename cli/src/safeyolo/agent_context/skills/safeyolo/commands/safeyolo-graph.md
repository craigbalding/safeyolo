---
name: safeyolo-graph
description: Review a SafeYolo triage graph against a real Claude Code session log. Extract evidence of graph adoption, judge whether the graph earned its keep, propose YAML edits where it fell short, and note other useful session observations.
---

You are reviewing SafeYolo triage graphs (`~/.claude/skills/safeyolo/references/graph/triage-*.yaml`)
against the evidence in a real Claude Code session log.

Operator invocation args: `$ARGUMENTS`

The **source of truth** is the session jsonl. The command below helps you
parse the graph-relevant signal quickly, but it does not constrain what
else you may observe. Note anything in the session that would help improve
SafeYolo or the graphs — repeated dead-ends, workarounds the agent
invented, defects surfaced, cases where the operator had to intervene.

## 1. Pick the session log

- If the operator's args name a jsonl path or session id, use that.
- Otherwise use the most recent jsonl:

  ```bash
  find ~/.claude/projects -name "*.jsonl" -type f -printf "%T@ %p\n" \
    | sort -n | tail -1 | awk '{print $2}'
  ```

- Parse it as line-delimited JSON. The events you care about are
  `type in {user, assistant}`. Inside `message.content` blocks look for
  `type: text` (prose) and `type: tool_use` / `type: tool_result`.

## 2. Extract graph-usage evidence

Look for:

- **Skill invocations** — `tool_use` blocks where `name == "Skill"` and args
  reference `safeyolo`.
- **Graph selection** — any assistant text or tool_use naming a
  `triage-*.yaml` file.
- **Node ID citations** — regex `\b(sym|ev|cls|con|ask)\.[a-z0-9_]+`
  appearing in assistant text.
- **Traversal terminals** — did the agent name a `con.*` conclusion or an
  `ask.*` operator ask at the end of the reasoning?
- **Graph gaps** — did the agent narrate the phrase "Graph gap" and propose
  a specific missing node/edge?

Do not require any specific output format from the reviewed session
(bracket markers, prescribed phrasing, etc). Graph adoption in natural
prose is just as valid — you are judging **substance**, not format.

## 3. Judge whether the graph earned its keep

Given what the failure actually was and what a senior SafeYolo operator
would conclude:

- Was the graph selection correct for the observed symptom?
- Was the entry-symptom bind reasonable?
- Did the traversal reach a diagnosis a senior operator would agree with?
- If the agent hit a Graph gap, was the proposed edit good?

You are qualified to make these judgments; you have the same graphs and
the same evidence the reviewed agent had.

## 4. Propose graph edits where warranted

- If the traversal was correct and clean: say so. No edits.
- If a node or edge was missing: produce a concrete YAML diff for the
  affected `references/graph/triage-*.yaml`. Reference real node IDs by
  reading the YAML directly — never invent an ID that would collide.
- If the graph is over-fitted (nodes never visited across observed
  sessions): flag pruning candidates but treat this as lower priority
  than gap-fill.

## 5. Beyond graph evidence

The session log is rich data. Surface anything else useful:

- Repeated dead-ends, or workarounds the agent invented.
- Real defects surfaced (skill misalignments, policy oddities,
  dead-lettered rules, structural traps that only agents ever hit).
- Cases where the operator had to intervene manually — those are
  candidate scenarios for future graph coverage.

## Output shape

A single markdown response with these sections, in order:

1. **Session** — session id, first-user-turn task summary in one line,
   agent's landing outcome in one line.
2. **Graph adoption** — bullets: skill invocations, graph files touched,
   node IDs cited.
3. **Traversal correctness** — your judgment with the specific evidence
   you're citing.
4. **Proposed edits** — YAML diff blocks, or "None." Never both.
5. **Other observations** — bullets. Terse. Only what is useful.

## Constraints

- Do NOT commit any edits automatically. Show them. The operator decides.
- Read actual YAML at `~/.claude/skills/safeyolo/references/graph/*.yaml`
  before naming any node ID.
- The session jsonl is the source of truth. Do not quote agent text you
  did not find there.
- If no session log is available, say so and stop. Do not fabricate.
