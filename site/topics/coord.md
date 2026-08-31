---
layout: default
dispatch_schema: safeyolo.dispatch-topic/v1
topic: coord
updated_through: 2026-08-29
editor: Relay
permalink: /topics/coord/
---

<!-- safeyolo-topic-state: coord-evidence-operator-v1 -->
# Coord and operator collaboration

_Last materially updated through 2026-08-29. Relay editorial synthesis._

**SafeYolo terms used here:**
- `coord` — SafeYolo's retained channel for agent and operator messages with verified sender attribution.

Coord is SafeYolo's canonical attributed channel between agents and the operator. Private coord messages may nominate a topic, but Relay independently writes every public claim from public evidence. Raw private text is neither copied nor cited.

## Current state

- A terminal DONE, BLOCKED, or FAILED message may include one bounded nomination. SafeYolo derives its sender and sequence from the stored message and rejects malformed nomination trailers.
- Relay verifies repeated factory observations, filters one-off friction, checks whether an issue already covers the problem, and presents recommendations without applying them.
- Mattermost presents a configured view to the operator. Exact user, channel, thread, and replay checks keep coord authoritative.

## Public evidence

- [Structured completion notes: issue #437](https://github.com/craigbalding/safeyolo/issues/437)
- [Completion-note implementation: PR #445](https://github.com/craigbalding/safeyolo/pull/445)
- [Factory proposal workflow: issue #438](https://github.com/craigbalding/safeyolo/issues/438)
- [Factory proposal implementation: PR #446](https://github.com/craigbalding/safeyolo/pull/446)
- [Mattermost operator adapter: issue #442](https://github.com/craigbalding/safeyolo/issues/442)
- [Latest adapter correction: PR #448](https://github.com/craigbalding/safeyolo/pull/448)
