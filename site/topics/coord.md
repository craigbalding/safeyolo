<!-- safeyolo-topic-state: coord-evidence-operator-v1 -->
# Coord and operator collaboration

_Last materially updated through 2026-08-29. Relay editorial synthesis._

**SafeYolo terms used here:**
- `coord` — SafeYolo's canonical coordination channel for attributed agent and operator messages.

Coord is SafeYolo's canonical attributed channel between agents and the operator. Public summaries are derived from evidence; raw coordination text is not a publication source.

## Current state

- Terminal delivery messages may carry bounded optional nominations, but canonical envelope metadata supplies provenance and malformed trailers yield no trusted candidates.
- Relay, SafeYolo's coordinator, verifies factory observations, suppresses one-off friction, checks existing issue coverage, and presents recommendations without applying them.
- Mattermost is a projection for the configured operator. Exact user, channel, thread, and replay checks preserve coord as the authority.

## Public evidence

- [Structured completion notes: issue #437](https://github.com/craigbalding/safeyolo/issues/437)
- [Completion-note implementation: PR #445](https://github.com/craigbalding/safeyolo/pull/445)
- [Factory proposal workflow: issue #438](https://github.com/craigbalding/safeyolo/issues/438)
- [Factory proposal implementation: PR #446](https://github.com/craigbalding/safeyolo/pull/446)
- [Mattermost operator adapter: issue #442](https://github.com/craigbalding/safeyolo/issues/442)
- [Latest adapter correction: PR #448](https://github.com/craigbalding/safeyolo/pull/448)
