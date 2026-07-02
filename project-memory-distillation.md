# Project Memory and Decision Distillation

## Summary

SafeYolo needs a lightweight way to preserve durable decisions without stuffing
future agent context with chat transcripts.

Most important decisions are not made inside agent-to-agent plumb chats. They
are made in the coding harness between the operator and an LLM agent while code
is being designed, reviewed, corrected, or committed. Agent-to-agent chat is a
valuable additional source, but it should not be the only source.

The right model is loosely coupled:

- conversations are evidence
- memory is distilled ground truth
- provenance links memory back to the conversation or task where the decision
  was made

## Goals

- Preserve decisions, invariants, and working preferences that future agents
  should rely on.
- Keep the durable context small enough to read at the start of work.
- Avoid treating raw chat logs as operational truth.
- Support decisions made in operator-agent coding sessions, plumb chats,
  reviews, commits, and investigations.
- Keep the first version simple enough to use without new SafeYolo machinery.

## Non-Goals

- Do not summarize every conversation.
- Do not automatically promote chat text into future agent instructions.
- Do not create a second audit log.
- Do not require plumb for project memory to work.

## Sources

Memory entries may come from:

- operator-to-agent coding harness discussions
- agent-to-agent plumb conversations
- code reviews
- debugging sessions
- blackbox test investigations
- explicit operator decisions
- accepted implementation tradeoffs

Plumb can provide searchable provenance, but it is only one source.

## Storage

For repo-specific decisions, store memory in the repo:

```text
.safeyolo/memory.md
```

This file is intentionally small and human-readable. It should be suitable for
agents to read before working in the repo.

Other scopes can use different homes later:

- agent-specific memory: agent home
- global ways of working: SafeYolo config/data directory
- organization/team memory: external docs or a shared repo

The first implementation should focus on repo-local memory.

## Entry Shape

Entries should be short and specific:

```markdown
## 2026-07-03: Plumb Chat Log Is Durable

Scope: `cli/src/safeyolo/core/plumb_service.py`, plumb collaboration

Decision: Plumb conversations are durable append-only logs. Do not cap messages
per conversation. Bound individual reads with pagination instead.

Rationale: Operators need long-running collaboration, auditability, and later
reference. A hard conversation cap makes the feature annoying and loses useful
context.

Source: operator-agent coding harness discussion during plumb implementation.
```

Useful entry types:

- decision
- invariant
- preference
- open question
- handoff note
- rejected approach

## Agent Instruction

Projects can add a short instruction to `AGENTS.md`, `CLAUDE.md`, or equivalent:

```markdown
## Project Memory

When a durable decision, invariant, or working preference is established, update
`.safeyolo/memory.md`.

Only record information likely to remain useful across sessions. Do not
summarize ordinary chat. Prefer updating an existing entry over adding a
duplicate.

Each entry should include date, scope, decision, rationale, and source or
provenance.
```

This is the lightweight ground-truth mechanism. The memory file is the thing
future agents should read and rely on, not the raw transcript.

## Relationship To Plumb

Plumb and memory are complementary:

- Plumb records conversations, approvals, messages, and audit evidence.
- Memory records distilled decisions and durable guidance.

The coupling should be provenance, not dependency.

A memory entry may cite:

- a plumb conversation ID
- relevant message IDs
- an operator-agent session
- a commit or PR
- a test run or investigation

But memory must still work when no plumb conversation exists. This matters
because many decisions are made directly in the coding harness.

## Promotion Flow

The basic workflow:

```text
conversation happens
agent identifies durable decision
agent updates or proposes update to .safeyolo/memory.md
operator reviews as part of normal code/doc review
future agents read memory before working
```

Later SafeYolo features could formalize this:

- `safeyolo memory propose`
- `safeyolo memory approve`
- `safeyolo plumb distill`
- watch prompts for memory promotion
- links from memory entries back to plumb conversations

Those features should preserve the same principle: agents may propose memory,
but durable ground truth should remain visible and reviewable by the operator.

## Guardrails

- Keep entries concise.
- Do not record secrets.
- Do not record speculative conclusions as decisions.
- Mark unsettled items as open questions.
- Prefer concrete scope over broad rules.
- Update stale entries when decisions change.

## Core Rule

Chats are evidence.

Memory is distilled ground truth.
