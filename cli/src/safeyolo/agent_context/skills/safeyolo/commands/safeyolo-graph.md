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

**Do this step before classifying the finding.** A rushed
"the graph is fine, it's a safeyolo bug" verdict is the fastest way to
miss a genuine graph gap or over-fit. Walk the traversal explicitly
before you jump to what kind of finding this is.

## 4. Disambiguate what the finding actually is

Only after step 3, classify the finding into one of these categories
(a single session can produce more than one — say so if it does):

- **`graph_gap`** — the graph did not cover this failure mode. Agent had
  to guess or work around the missing edge. Propose YAML edits (step 5a).
- **`graph_correct_safeyolo_defect`** — the graph led to a correct
  diagnosis, and the diagnosis names a real SafeYolo defect (dead-lettered
  policy clauses, missing credential classifiers, structural traps that
  only agents hit, addon behavior contradicting documentation, etc).
  Report the defect (step 5b), no graph changes.
- **`graph_overfit`** — the graph forced the agent down a wrong or overly
  long path when a shorter/simpler diagnosis existed. Propose pruning or
  edge-condition tightening (step 5a).
- **`environment_or_operator_issue`** — nothing in graph or safeyolo needs
  changing; user misread a normal behavior, or the environment was in a
  transient state. Say so and stop.
- **`mixed`** — combinations of the above. Break out each.

Be honest. If the graph led correctly and the finding is a safeyolo
defect the graph surfaced, that is a *win* for the graph — not a reason
to invent an edit for it.

## 5a. Propose graph edits (only if classification requires)

- If a node or edge was missing: produce a concrete YAML diff for the
  affected `references/graph/triage-*.yaml`. Reference real node IDs by
  reading the YAML directly — never invent an ID that would collide.
- If the graph is over-fitted: flag pruning candidates or edge-condition
  tightening, but treat as lower priority than gap-fill.

## 5b. Report a SafeYolo defect (only if classification requires)

Give the operator what they need to file or fix:

- Symptom in one sentence.
- Concrete evidence quoted from the session (event id, request id,
  policy fragment, log excerpt — whatever is definitive).
- Minimum reproduction if you can identify one from the session.
- Where in the SafeYolo source (paths + rough location) the fix would
  likely live, if you can tell.
- Suggested severity: low / medium / high, with reasoning.

Do not open issues or push changes. Report to the operator.

## 6. Other observations

The session log is rich data beyond graph adoption and defect reports.
Note anything else useful — repeated dead-ends, workarounds the agent
invented, cases where the operator had to intervene manually (those are
candidate scenarios for future graph coverage).

## Output shape

A single markdown response with these sections, in order:

1. **Session** — session id, first-user-turn task summary in one line,
   agent's landing outcome in one line.
2. **Graph adoption** — bullets: skill invocations, graph files touched,
   node IDs cited.
3. **Traversal correctness** — your judgment with the specific evidence
   you're citing.
4. **Finding classification** — the category from step 4 (one of
   `graph_gap`, `graph_correct_safeyolo_defect`, `graph_overfit`,
   `environment_or_operator_issue`, `mixed`). One line of reasoning
   for why this category and not the others.
5. **Proposed graph edits** — YAML diff blocks, or "None." Never both.
6. **SafeYolo defect** — description + evidence + suggested severity,
   or "None."
7. **Other observations** — bullets. Terse. Only what is useful.

## Constraints

- Do NOT commit any edits automatically. Show them. The operator decides.
- Read actual YAML at `~/.claude/skills/safeyolo/references/graph/*.yaml`
  before naming any node ID.
- The session jsonl is the source of truth. Do not quote agent text you
  did not find there.
- If no session log is available, say so and stop. Do not fabricate.
