# Coord stage-0 test report (#371)

Tested by agent `bob` against the live SafeYolo Agent API, room `stage0`,
with agent `claude` and the operator as peers. Commits under test:
`8b70bcc` (v0 substrate) + `fa72c77` (identity via Agent API + unified registry).

Method: direct `curl` against `/api/coord/rooms/{room}/{join,send,messages,wait}`
through the sandbox proxy. MCP adapter explicitly out of scope per operator.

## Status

Stage-0 patches applied by agent `claude` and re-tested by `bob`.
See **Patch verification** below for what is confirmed fixed, what is
still unverifiable, and three findings the patch round itself produced.

#16 (`wait` returning 400) is **resolved** — proxy restarted, endpoint healthy.
#9 and #12 now verified live and both PASS.

**Open security issue: `revoke_grant` reports success without removing access.**
See #18. Reachable by an ordinary operator command sequence.

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
| No-grant 403 | operator manually revoked claude's `stage0` grant via `UPDATE memberships SET revoked_at = ...`; claude then got 403 on all four ops (join / send / read / wait) with the expected error shape. Added to the record after this report's original writing. |

Concurrency result matters beyond itself: the entire cursor/pagination contract
rests on `rowid` monotonicity and had no direct coverage. It holds.

The no-grant test was the only untested authorization case at report time.
The operator drove the revocation via manual SQL (no `coord revoke` command
existed yet) and claude ran the four operations from a still-live sandbox
session. The `revoked_at IS NULL` filter in `_check_grant` correctly rejected
the revoked membership on every op. Grant→revoke→re-grant contract now has
end-to-end coverage.

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

## Environment note

Partway through the session `/workspace/.venv/bin/python` became a symlink to
`.../cpython-3.13.0-macos-aarch64-none/bin/python3.13`. That path does not
exist in a Linux guest, so the shared checkout's venv is unusable from inside
any sandbox — it broke mid-test and testing continued with `jq`. If agents are
meant to run the repo's tests during the dogfood, a host-built `.venv` on a
cross-platform mount is a hazard.

## Test suite

`cli/tests/test_coord_v0.py` (8) + `tests/test_agent_api_coord.py` (9) — 17
passed at report time. Note none of them cover findings #1, #9, or #12; the
upstream-escape case in particular deserves a regression test. Addressed in
the follow-up fix commit which raises the total to 39 tests including
multi-point upstream-escape, wait-only self-exclusion, wait limit, revoke
roundtrip, body cap, and stable-validation-error coverage.

---

# Patch verification

Patches applied by agent `claude`; verified live by `bob` against the running
proxy. Read-only on code throughout.

## Confirmed fixed

| # | Finding | Evidence |
|---|---|---|
| 1 | Async dispatch boundary escape | `agent_api.py` now wraps both `/plumb` and `/api/coord/` in `except Exception -> 500`, and only synthesises if `flow.response is None` so handler-set statuses survive. No 502 observed on any path since. |
| 2 | Never bootstraps | `_COORD_BOOTSTRAPPED` process flag added; addon works without a preceding `coord init`. |
| 6 | No body cap | 300KB -> `413 request body too large, max_bytes=262144`. **Also correct on multibyte**: 200K chars of 2-byte UTF-8 (400KB) rejected on *byte* length, not character count — the right measure and an easy one to get wrong. 413 rather than 400 is more accurate than what was originally suggested. |
| 7 | Raw exception text in 400s | `_CoordValidationError` + `_parse_qs_int/_float` -> `invalid since` / `invalid limit` / `invalid timeout`. No Python internals leak. |
| 4 | No revocation | `api.revoke_grant()` + `safeyolo coord revoke` added; idempotent, returns whether anything changed, and does not erase history (correct #371 room semantics). **Not exercised live — requires operator.** |

## Verified live after the proxy restart

- **#9 self-exclusion — PASS.** Armed at since=50, sent own seq=51 at t=2s: did
  not wake, blocked the full 10s, `n=0`. Returned `next_cursor=51`, skipping the
  caller's own message so it cannot re-arm into a self-spin. With
  `include_self=1`: woke in **2.04s**, `n=1 seqs=[52]`. `read_room` stays
  inclusive for canonical history — the right split, wake is attention, read is
  history.
- **#12 wake limit — PASS.** 3 pending (53,54,55). Default: `n=1 seqs=[53]
  has_more=true`. With `limit=10`: `n=3 seqs=[53,54,55] has_more=false`.

  Default is **1**, stronger than the suggested 50, on the reasoning that a wake
  is an attention edge rather than a bulk fetch. Correct call, but it changes the
  contract: **the catch-up `read_room` stops being good practice and becomes
  mandatory.** Any agent loop that reads only what the wake handed it now falls
  behind by design. This belongs in `docs/coord-wake-test.md`.

## Still open from the original list

#3 (P1 event-loop flock), #5 (`history_visibility` dead), #8 (global rowid
leak), #10 (no read tracking), #11 (no addressing), #13 (no retention),
#14 (arrival-order semantics). None regressed.

## New findings from the patch round

### 15. Internal `TypeError` is misclassified as a 400 client error

`_handle_coord`'s `except (ValueError, TypeError) -> 400` catches type errors
raised by SafeYolo's own code. A signature mismatch between the addon and
`coord.api` is a **500** — the caller did nothing wrong and can do nothing
about it. Reporting 400 asserts "your request was bad" when the truth is "our
code is inconsistent with itself".

This is not hypothetical: it is exactly how #16 hid. A 400 on `wait` with a
plausible message reads as a caller mistake, so the instinct is to check query
params rather than suspect a stale module. As `500 Internal error: TypeError`
the diagnosis would have been immediate.

*Fix:* keep `ValueError` for caller input — it is what `_CoordValidationError`
and envelope validation raise — and let `TypeError` fall through to the new 500
boundary. This is the same defect as #1 in a different place: **the handler
describes a case it is not actually handling.**

### 16. Coord changes need a full proxy restart, not an addon reload — and nothing detects the mixed state

**RESOLVED** by a full proxy restart. Retained because the failure mode will
recur on every coord change. Every `wait` call was returning:

    400 {"error": "wait_for_message() got an unexpected keyword argument 'limit'"}

`join`, `send`, `messages` all return 200. Only `wait` is down.

The running `agent_api.py` is patched — verified via the sanitised 400s and the
413 body cap. The running `safeyolo.coord.api` is not: it has no
`limit`/`exclude_self` kwargs. `_handle_coord` does
`from safeyolo.coord import api as coord_api` at call time, but `sys.modules`
caches the first import for the process lifetime, so an addon hot-reload
re-executes the addon and keeps the stale callee.

Impact beyond the immediate outage: **any agent armed on a long-poll is not
armed.** It receives an instant 400 and, depending on its loop, either spins or
goes silently deaf — and per #10 nothing outside can tell the difference.

*Fix:* full proxy restart for coord changes. Longer term this deserves a
version or schema handshake between the addon and `coord.api`, because the
failure mode is a plausible-looking 400 rather than anything that looks like a
deployment problem.

### 17. `wait`'s exclusion filter can starve on a fixed window

`wait_for_message` reads a wide window (`limit=READ_PAGE_MAX`, 200) from
`since_sequence`, applies self-exclusion, then trims to `limit`. If all 200
messages in that window are the caller's own, `candidates` is empty and the
loop sleeps and re-reads **the same window** — `since_sequence` never advances.
Peer messages sitting beyond position 200 are invisible until the caller's
cursor moves by some other means.

Requires 200+ consecutive own messages after the caller's cursor, so it needs a
burst plus a stale cursor. Low probability, and the fix is cheap: advance an
internal scan cursor past the filtered window rather than re-reading from
`since_sequence`.

## Method note

Every "confirmed fixed" row above was tested against the running proxy, not
read off the diff. That distinction earned its keep this round: reading the
diff alone would have scored #9 and #12 as delivered, when in fact neither can
execute — the code is correct and the deployed system cannot run it.

---

# Findings from revoke verification

### 18. `revoke_grant` reports success without removing access — SECURITY

**`revoke_grant` revokes the most recent grant *row*, not the principal's
access.** With two active grants it returns `True` — signalling success — while
`join`, `send` and `read` all continue to work.

Reproduced against a scratch coord DB (`SAFEYOLO_COORD_DATA_DIR` in a temp dir;
no repo code modified):

    two active grant rows created
    revoke_grant -> True
      !! join STILL SUCCEEDS after revoke
      !! send STILL SUCCEEDS after revoke
      !! read STILL SUCCEEDS after revoke
    rows (granted_at, revoked_at): [(...721, None), (...732, ...732)]

    -- second revoke --
    revoke_grant -> True
      join denied after second revoke

Mechanism: `grant()` **appends** a membership row and never supersedes prior
ones. `revoke_grant` selects `ORDER BY granted_at DESC LIMIT 1` and revokes
exactly that row. `_check_grant` then finds the older row, still
`revoked_at IS NULL`, and allows access. It takes N revokes to undo N grants.

Reachable by an ordinary command sequence, not a contrived one:

    safeyolo coord room create stage0 --member bob      # grant row 1
    safeyolo coord grant stage0 bob --perm send,receive # grant row 2
    safeyolo coord revoke stage0 bob                    # prints "revoked" — access intact

The severity is in the reporting as much as the logic. An access-removal
control that **returns success while access persists** is worse than one that
errors: the operator gets positive confirmation and no signal that anything is
wrong. Note this was the fix for finding #4 — the control went from absent to
present-but-silently-incomplete, which is the same category the report's
cross-cutting theme describes.

*Fix:* revoke **all** active rows for the principal —
`UPDATE memberships SET revoked_at = ? WHERE room_id=? AND principal_kind=?
AND principal_id=? AND revoked_at IS NULL` — and return the affected row count.
Alternatively make `grant()` supersede prior grants so only one is ever active,
which also fixes #19.

### 19. Duplicate grant within the same millisecond is an uncaught crash

    sqlite3.IntegrityError: UNIQUE constraint failed:
      memberships.room_id, memberships.principal_kind,
      memberships.principal_id, memberships.granted_at

`memberships`' primary key includes `granted_at` at millisecond resolution, and
`grant()` has no `except IntegrityError` — unlike `create_room`, which
correctly maps it to `ConflictError`. Two grants inside the same millisecond
traceback.

CLI-only today because `grant` is not exposed on the Agent API. If it ever is,
it becomes a 500 — and it is the same shape as #1 and #15: a handler that
describes a case it does not handle.

## Coverage note

Findings #15, #17, #18 and #19 are all absent from the 17-test suite. #18 in
particular deserves a regression test asserting that access is actually denied
after a single revoke, given the control's whole purpose is removing access.
