# Coord stage-0 test report (#371)

Tested by agent `bob` against the live SafeYolo Agent API, room `stage0`,
with agent `claude` and the operator as peers. Commits under test:
`8b70bcc` (v0 substrate) + `fa72c77` (identity via Agent API + unified registry).

Method: direct `curl` against `/api/coord/rooms/{room}/{join,send,messages,wait}`
through the sandbox proxy. MCP adapter explicitly out of scope per operator.

## Verdict

The substrate works. The identity model — the load-bearing claim of `fa72c77` —
holds under direct attack. Every finding below is a gap or a rough edge, not a
break in what stage 0 set out to prove.

## PASS

| Area | Result |
|---|---|
| join / send / read | roundtrip clean; envelope fields all SafeYolo-generated |
| Pagination | `limit=1` walk, cursors 0->1->2->3, `has_more` correct, clean terminate |
| Long-poll timeout | asked 4s, returned 4.03s, empty page, cursor preserved |
| Long-poll wake (peer) | operator->bob 197s; claude->bob 78.4s |
| Long-poll fan-out | 3 waiters armed together, all woke within ~110ms of the write, none starved |
| Concurrent writes | 12 simultaneous sends: 12 unique seqs, 12 unique msg_ids, 0 drops, 0 gaps |
| Auth | 401 on missing header / bad token / non-Bearer scheme |
| Envelope validation | bad content_type, empty/missing/non-string body, invalid JSON -> 400 |
| Routing | unknown room 404, `GET /send` 405, `POST /messages` 405, unknown op 404 + hint |
| **Identity spoof** | **POST body carrying `sender_agent_id` + `sender_kind` ignored; envelope carried transport-derived id** |
| Operator envelope | `sender_kind=operator` with `sender_agent_id` JSON `null`, not the internal `"operator"` principal_id |
| Per-agent identity | bob `ag-280746d1...` vs claude `ag-a94101b1...` — distinct, no token on either side |

Concurrency result matters beyond itself: the entire cursor/pagination contract
rests on `rowid` monotonicity and had no direct coverage. It holds.

## NOT TESTED — blocking

**No-grant 403.** The only authorization case with zero live coverage. Every
other identity result is about correctly *granting* access; nothing tests
correctly *denying* it. Needs a room the tester is not a member of:

    safeyolo coord room create locked --member claude

Stage 0 should not be called done without this.

## Findings

### P0

1. **Uncaught exceptions in the async dispatch escape to the network.**
   `agent_api.py:132` (`_handle_plumb`) and `:138` (`_handle_coord`) are
   unwrapped; the sync handler table has `try/except -> 500` at `:234`.
   `_handle_coord` catches only `NotFoundError`/`GrantError`/`ValueError`/
   `TypeError`. Anything else leaves the request hook and mitmproxy forwards
   the flow **upstream** — observed live as `502 nodename nor servname
   provided` for `_safeyolo.proxy.internal`. An Agent API request that should
   never leave the box becomes a real outbound DNS lookup. Boundary escape,
   not a status-code bug.
   *Fix:* wrap the whole dispatch in `except Exception -> 500` with a generic
   message (see #7 — do not echo exception text).

2. **`_handle_coord` never bootstraps.** `api.bootstrap()` is idempotent but
   only called from CLI commands. On a host without `coord init`, every call
   raises `sqlite3.OperationalError: no such table: rooms` -> finding #1 ->
   502. Reproduced locally against a fresh data dir. This was the original
   stage-0 blocker.

### P1

3. **Blocking flock + double TOML parse per coord call, on the proxy event
   loop.** `_handle_coord` does `load_all_agents()` (full tomlkit parse) then
   `get_or_mint_agent_id()` -> `_locked_mutate` -> blocking
   `fcntl.flock(LOCK_EX)` + a second parse — even when `agent_id` already
   exists and nothing is written. Same lock `safeyolo agent add`/`start` take;
   contention stalls the shared loop for all agents' traffic.
   *Downgraded to latency, not correctness*: the 12-way concurrent write test
   showed no sequence corruption, and the fan-out test showed concurrent
   long-polls do not block each other, so the risk is confined to the
   flock/TOML section.
   *Fix:* try lock-free `get_agent_id()` first; run the mint path via
   `asyncio.to_thread` (claude's improvement on the original suggestion).

### P2

4. **No revocation path exists.** `memberships.revoked_at` is read-filtered in
   `_check_grant` and `join_room` but never written by any command or API
   function. Grants are permanent.
5. **`history_visibility` is dead.** Schema default only; never written by
   `grant()`, never read by `read_room()`; `join_room` returns a hardcoded
   `"retained"`. An agent granted after 1000 messages silently gets full history.
6. **No cap on `body` length.** Neither `api.send()` nor the handler bounds it
   (handler checks only `isinstance(body, str) and body`). Unbounded writes
   into shared SQLite.
7. **Raw Python exception text leaks in 400s**, e.g. `invalid literal for
   int() with base 10: 'abc'`, `could not convert string to float: 'abc'`.
8. **`sequence` is the global `messages.rowid`**, shared across rooms. An agent
   can infer message volume in rooms it has no grant on by watching gaps.
9. **No self-exclusion in `read_room` / `wait_for_message`.** `WHERE room_id = ?
   AND rowid > ?`, no sender filter — an agent always receives its own traffic.
   An agent whose cursor lags its own last send self-wakes instantly; with an
   ack-on-wake loop that is a runaway at zero think-time delay. Also means "did
   my message get out" and "did a peer speak" are the same signal.
   *Fix (claude's, better than the original):* skip caller-owned messages by
   default, opt in with `include_self=true`. Opt-out beats opt-in for isolation
   leaks.
10. **No read tracking or server-side cursors.** `memberships` has no
    cursor/last_read column; nothing persists an ack. The server never learns
    what anyone has read, so "did X see this" is structurally unanswerable. A
    restarted agent silently resumes from wherever it guesses; a wedged agent
    and a quiet agent are indistinguishable from outside.
11. **No addressing.** `@name` is plain body text; the envelope has no recipient
    field and no mentions. Every message is a room broadcast.
12. **`wait` accepts no `limit` param.** `agent_api.py:360-372` parses only
    `since` and `timeout`; `wait_for_message` hardcodes `limit=READ_PAGE_MAX`
    (200) at `api.py:277`. Wake-path page size is fixed at 200 and callers
    cannot tune it. **For LLM agents this is a context-blowout risk the caller
    cannot prevent** — the one v0 limit not to carry into v1 unchanged.
    Suggested default 50.
13. **No message deletion or retention path.** `history_truncated` and
    `oldest_available_at` are returned but hardcoded `False`/`None`. Deliberate
    and commented, listed only because it lands in the same category as #4/#5.

### Semantics question, not a bug

14. **Sequence order is arrival-at-writer order, not client-issue order** —
    even from a single sender. Measured: probes issued 1..12 landed in order
    `1 3 6 2 5 7 10 9 12 8 11 4`; probe 4 landed twelfth. `rowid` is monotonic;
    assignment order is whatever reaches the SQLite writer first.
    Right default for chat semantics; wrong for anything that grows into typed
    protocol messages. *Suggested v1:* keep arrival-order, carry an optional
    `client_seq` the server does not enforce.

## Cross-cutting theme

Findings #1, #4, #5, and #13 share one shape: **the code reads as though a
control exists when nothing enforces it.** `_handle_coord` catches four
exception types and looks like it handles errors. The `revoked_at IS NULL`
filter looks like revocation. `history_visibility` and `history_truncated` look
like retention policy. A reviewer skimming for whether #371's authorization
model is covered gets the wrong answer in each case.

This is worth stating in #371 in those terms rather than as separate bullets.
Explicit `# v0: not enforced` markers would cost nothing and stop v1 inheriting
a false sense of coverage.

## Attention-model findings (for the 3-agent dogfood)

- **The cursor model saves you, not the long-poll.** `wait_for_message` only
  covers the window you are armed for. Anything arriving between wake and
  re-arm — i.e. during think-time — never hits the wake path. Observed live:
  an operator `ping` took seq=8 in that gap and was found only on catch-up read.
- **This looks identical to the runbook's "one-shot" FAIL mode but is healthy.**
  `docs/coord-wake-test.md` pass criteria should check cursor continuity, not
  ack latency.
- **Agent loops should read before re-arming**: wake -> catch-up `read_room`
  from your own cursor -> respond -> re-arm at your own highest sequence
  *including your own sends*.
- **The wake mechanism used here was not MCP.** Backgrounded `curl` + the
  harness's background-task completion notification. The runbook's assumption
  that MCP provides attention is not what was exercised; the attention
  mechanism is harness behaviour, not substrate behaviour.

## Room vs audit

Agents coordinated successfully on a detail the room never carried — the
operator relayed it out of band. Reconstructing that from room history alone
yields nothing.

Off-room operator content *does* traverse SafeYolo as LLM-API payloads and is
retained in flow bodies, so it is archived — but attributed as a request body,
not as a coordination event with sender/room/sequence. Forensically
recoverable, not coordination-legible.

Conclusion (bob + claude agreed): **the coordination plane is not the audit
surface.** Room answers "how did the agents coordinate"; JSONL cross-referenced
with per-agent flow bodies answers "what did the operator instruct". Two
archives, two questions, neither complete alone. #371 should say so plainly.

Note: this could not be verified from inside a sandbox — `_resolve_agent_id`
scopes flow search to the calling agent, so a peer cannot read another agent's
traffic. That isolation working is why cross-agent forensic reconstruction
needs an operator with unscoped access.

## Environment note

Partway through the session `/workspace/.venv/bin/python` became a symlink to
`.../cpython-3.13.0-macos-aarch64-none/bin/python3.13`. That path does not
exist in a Linux guest, so the shared checkout's venv is unusable from inside
any sandbox — it broke mid-test and testing continued with `jq`. If agents are
meant to run the repo's tests during the dogfood, a host-built `.venv` on a
cross-platform mount is a hazard.

## Test suite

`cli/tests/test_coord_v0.py` (8) + `tests/test_agent_api_coord.py` (9) — 17
passed. Note none of them cover findings #1, #9, or #12; the upstream-escape
case in particular deserves a regression test.
