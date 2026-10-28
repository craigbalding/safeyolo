# Proposed Coord attention retention

This is the design and executable challenge for [#394](https://github.com/craigbalding/safeyolo/issues/394).
The proposal describes a possible native implementation. It does not enable
cleanup, change the operational schema, or select retention policy for an
operator. The inspected base is `d05446671ae6edfd7a4e9a8bf1e5267c92bfba11`.

The proposed operator workflow is:

1. Inspect the current attention and hint counts. Preview a proposed per-agent
   edge cap and the feed ranges that activating that cap would discard.
2. Select the cap deliberately. Activation requires the operator's policy
   decision in a subsequent implementation assignment.
3. Current callers continue to resolve retained attention normally. A caller
   behind the discarded prefix receives an explicit loss response.
4. The caller preserves its saved cursor and pending work until the operator
   reconciles that loss. Restart and cleanup preserve the discarded prefix.

## Current owners and behavior

The following are current source facts, rather than proposed behavior.

| Owner | Relevant behavior |
| --- | --- |
| [Native schema](../proxy/src/coord_schema.sql) | `coord_attention_feeds.last_sequence` allocates a separate sequence for each recipient. `coord_attention_edges` has stable attention identity and captures `membership_granted_at`. There is no discarded-prefix field. |
| [Agent API](../proxy/src/agent_api/coord.rs), `read_attention_feed` | A SQLite snapshot contains the allocator, authorized rows and resulting cursor. A full page ends at its last edge. A shorter page advances to the allocator high-water mark. Removing rows without recording loss would silently advance stale callers. |
| Agent API, `attention_object` | The API resolves message bodies from JetStream and brief revisions from SQLite. It checks current edge authorization after provider I/O. Raw-message lookup errors currently become availability errors, including expired messages. |
| Agent API, `project_attention_prefix` | Edge creation, feed allocation, hint enqueue and room projection advancement share `BEGIN IMMEDIATE`. The room frontier prevents replay of already examined stream sequences. |
| Agent API, `advance_over_retention_gap` | Loss **before projection** has a stable audit event and an atomic room-frontier update. `projection_sequence_was_lost` reads those audit outbox rows as correctness state. |
| [Brief writes](../proxy/src/coord_rooms/brief.rs), `set` | Brief revision, current brief, edge, allocator, hint and operator ledger writes share one transaction. Brief history is immutable. |
| [Room creation and grants](../proxy/src/coord_rooms.rs) | Each room stream retains at most 100,000 messages and seven days, with a 2 MiB message-size limit. Grant generations increase using the retained maximum `granted_at`. Permission changes can leave older rows active; receive queries select only the newest active generation. |
| [MCP client](../proxy/src/coord_tools.rs), `Client::call` | `wait_for_coord` resolves every edge before returning `next_cursor`. One failed resolution returns no later cursor. |
| [Supervisor](../proxy/src/coord_supervisor.rs), `accept_page` | The supervisor saves `safe_cursor` with its accepted objects. Returning a page does not acknowledge consumption to the server. |

Both native edge writers enqueue `attention-nats` rows. Message publication also
sends a direct NATS hint. Source inspection at this base finds no native outbox
drainer or update of `delivered_at`. Thus pending hint rows already matter to a
bound; pruning only delivered rows would not solve native growth. No native
attention or hint-row deletion path was found.

Room history is a different sequence space. `read_messages_with_timeout`
already reports `history_truncated` from JetStream state and currently returns
`oldest_available_at: null`. A room sequence cannot replace an attention
cursor. An attention floor cannot establish a room-history floor.

## Policy proposed for operator selection

Use one positive integer: **maximum retained edges per recipient**. The
suggested initial value is **100,000**, matching one current room stream's
message-count bound. This is a proposal, not a newly effective default. The
value is a starting capacity choice, not a measured workload requirement.

Apply the cap across all rooms, edge kinds and membership generations for that
recipient. For `A` retained recipient identities and cap `E`, at most `A × E`
edge rows remain after each successful materialization/cleanup transaction.
No additional wall-clock edge lifetime is proposed. Canonical messages still
have their existing independent age/count limits.

The benefit is a finite number of attention rows even during provider outages
or while a caller never reconnects. The cost is explicit: a burst in one room
can retire another room's older attention, including attention whose canonical
object is still present. A cap does not promise seven days of attention.
Operators should preview counts and recent traffic before choosing it.
Increasing the cap cannot recover a previously discarded prefix.

| Stored data | Proposed treatment |
| --- | --- |
| Durable attention edges | Retain a suffix of at most `E` rows per recipient. Retire an additional confirmed-expired prefix when possible. Do not delete interior rows independently. |
| Delivered attention hints | Retain no delivery receipts. Remove the row in the delivery-completion transaction. This applies only to destination `attention-nats` and event type `coord.attention_hint`. |
| Pending attention hints | Keep at most one per retained edge, using the existing stable `evt-<attention suffix>` key. Delete a retired edge's pending hint in the same transaction. Thus pending hints are also bounded by `A × E`. |
| Feed and room projection watermarks | Keep them after their last edge disappears. Never reset or recycle a sequence because cleanup emptied a feed. These rows grow with identities/rooms, rather than traffic. |
| Membership generations, brief revisions, operation records and audit rows | Preserve their current retention. Attention cleanup has no authority to delete these records. |

A successful hint publish/flush means only that the wake hint was submitted.
It says nothing about caller consumption. A crash before recording completion
can repeat a hint. A crash after completion can lose a hint at its subscriber.
Both cases remain recoverable from the durable feed and its explicit floor.
Brief and message writers must follow the same bound. A future hint-delivery
repair must use those owners; this proposal adds no queue or drainer.

This bounds the requested attention and hint buckets. It is not a claim that
the entire Coord database, identity inventory or filesystem has a fixed byte
limit. Audit and canonical retention are separate requirements described below.

## One durable discarded prefix

Add `discarded_through`, initially zero, to the existing per-agent feed row.
Require `0 <= discarded_through <= last_sequence`. Let `F` be that value and
`H` the allocator high-water mark. Retained feed positions form `(F, H]`.
The proposed count cut is `max(F, H - E)`. The floor only increases.

Keep one scalar instead of per-edge tombstones or an interval ledger. This is
sufficient because cleanup removes only a prefix. Membership filtering can
still hide rows within the suffix; those rows remain part of the cap. Returning
or resolving an edge, delivering a hint, or observing a caller's cursor never
moves `F`.

### Caller behind the floor

Before selecting edges, read the floor, high-water mark and edge page on one
SQLite snapshot. If supplied cursor `S < F`, return HTTP 409 with this proposed
body shape. Return no edges and no `next_cursor`:

```json
{
  "error": "coord_attention_truncated",
  "requested_cursor": 41,
  "discarded_through": 47,
  "highwater": 52,
  "unavailable_range": [42, 47],
  "retry_since": 47
}
```

The inclusive range reports discarded **feed positions**, not a count of
unhandled tasks or proof that every canonical object is gone. Some positions
can belong to an old grant. Return no old room, sender, object or membership
metadata in this response. Derive the recipient identity from transport as
today. A principal cannot query another principal's floor.

`retry_since` is a recovery suggestion, never an acknowledged cursor. At
`S == F`, return the retained page normally. Preserve the current numeric input
range and future-cursor behavior; do not clamp a cursor to `H`. Empty feeds must
retain and disclose their floor. Long polls must return truncation immediately,
including when the retained suffix is empty (`H == F`). They must not wait for
a new hint to report loss.

Non-success HTTP status is necessary for compatibility. Existing clients may
ignore extra success fields. A successful empty page with an added loss flag
could still make those clients silently advance.

### Canonical expiry while an edge is retained

An edge can survive its message. A feed page can also race canonical expiry.
On an authoritative JetStream `NO_MESSAGE_FOUND` response for that edge's
room/sequence, recheck its current authorization before returning HTTP 410:

```json
{
  "error": "coord_attention_canonical_missing",
  "edge": {"attention_id": "attn-…", "room_id": "rm-…", "kind": "message", "object_id": "msg-…", "revision_or_sequence": 901},
  "feed_sequence": 48
}
```

This means that the canonical message is no longer available. It does not
assert whether age, count retention or operator deletion caused its absence.
Timeouts, connection failures and a missing stream are availability failures,
not evidence of message expiry. A conflicting object/manifest remains an
integrity failure. A missing brief revision remains an integrity failure;
immutable SQLite brief history does not follow JetStream expiry.

The authorized edge and `feed_sequence` must come from the same post-provider
SQLite snapshot. The current grant must still match the captured generation.
For revoked, superseded, unknown or other-recipient IDs, preserve the generic
404 without an expiry report. If cleanup removes an edge between its page and
object read, return the same generic failure and refetch from the caller's
original cursor. The fresh feed read will disclose truncation where applicable.
No failed resolution exposes a later `next_cursor`.

### Recovery belongs to each caller

The MCP adapter must propagate the 409/410 facts without turning them into a
successful empty page. The supervisor must preserve `safe_cursor`, pending
requests and downstream handoffs. It should surface the loss through its
existing failure/status path and require an explicit operator recovery decision.
An older client will stop on the non-success response; a production assignment
must update native callers together to make the recovery usable.

For the 409 example, the operator can inspect authorized retained room history
and current briefs/state. History may recover useful facts but does not restore
the original attention feed or assign work. If the operator accepts the missing
range, the caller records that decision with its existing checkpoint and
expected old cursor, then retries at 47. A new 409 means cleanup advanced again;
it requires a new disclosed decision, not automatic repeated acceptance.

For a 410 at feed position 48, the caller must first resolve any earlier retained
edges. A concrete bounded procedure is to read with `limit=1` from the saved
cursor, resolve that edge, and repeat. Only after preceding edges are handled
can an explicit loss decision skip position 48. Do not adopt a full page's
cursor merely because its first expired object is known. If a task's canonical
content cannot be recovered, ask its authoritative sender/operator to reconcile
the task. Do not automatically resend an uncertain external write.

The recovery checkpoint transition must compare instance identity and the
expected saved cursor. It must save the disclosed range/position and deliberate
decision atomically with the changed cursor. This is caller-owned recovery,
not a server-owned consumed position or a second task store. The server keeps
no list of callers and cannot infer which caller handled a discarded edge.

## Cleanup, restart and concurrent activity

Use the existing native SQLite owners and WAL transactions:

1. Outside a write transaction, optionally probe old message edges for canonical
   absence. Bind each observation to instance, room, attention ID, canonical
   sequence and membership generation. An unavailable provider gives no expiry
   evidence. Do not probe while holding a SQLite write lock.
2. Start `BEGIN IMMEDIATE`. Read the current `F` and `H` and recompute the count
   cut. A dry-run result is not deletion authority against a later snapshot.
3. From the count cut, extend through consecutive message edges with matching
   authoritative absence observations. Stop at a live message, an unknown
   result or a brief. Interior orphans stay as bounded rows and return 410 when
   read; no interval/tombstone machinery is needed.
4. Update `discarded_through`. Delete the matching hints and edge prefix in
   that transaction. Match hint keys using the existing `attention_event_id`
   convention; never delete all rows with non-null `delivered_at`.
5. Commit before reporting removed counts. Preserve both allocator and room
   projection frontier. Retrying after a crash re-reads durable state.

A later schema/activation change must initialize existing feeds at `F = 0`
without changing their allocators or rows. Deploy explicit loss responses and
caller recovery support before activating deletion. Inspection must distinguish
an unselected policy from the proposed cap. This design authorizes no migration
or activation against an installed store.

The count cut belongs in both edge materialization transactions. This enforces
the cap even if cleanup never runs again or NATS is unavailable. A recipient
fan-out must apply the same rule to every affected feed before commit. A busy
database or failed deletion rolls back materialization/cleanup as appropriate;
it must not commit a deletion without its floor or a floor without its deletion.
The existing JetStream-accepted/SQLite-pending recovery path still owns an
accepted message whose materialization transaction fails.

Startup and explicit operator cleanup can reclaim confirmed-expired prefixes
and residual delivered hints. A long-running read/wait can use the same bounded
cleanup step at its existing boundary. No new background scheduler is required.
An offline/idle instance has no wall-clock deletion deadline under this policy.

Keep the existing projection compare-and-swap and baseline. Deleting an edge's
unique-key row must not cause recovery to import an old room sequence again.
The current send path creates fresh message identities; Dispatch reconciliation
also preserves its separate no-automatic-resend rule. Cleanup must not reset
either owner or reinterpret missing edge rows as permission to publish again.

Concurrent readers can finish from an older coherent WAL snapshot. A subsequent
object read rechecks authorization and may find compaction. Concurrent writers
serialize their current count cuts; neither may replace a newer floor with a
stale value. A higher cap never lowers an existing floor.

## Membership, audit and observable storage

Revocation remains immediate at each read boundary. Regrant does not make an
old generation's edges visible. Permission changes must retain the newest-active
grant check, including when older rows remain active. Cleanup does not erase
generation history or derive authority from a hint, expired payload or floor.
Keep the latest generation even for a revoked membership: deleting generation
state could allow reuse if the clock moves backward.

Preserve audit outbox rows, `coord_operations`, membership rows and immutable
brief revisions. In particular, delivered
`coord.attention_projection_lost` rows are still read by the native projection
owner. Moving those rows to a rotated file and deleting them would change
correctness. An attention cleanup operation cannot do that safely.

The existing [audit writer](../proxy/src/audit/writer.rs) defaults to a 50,000,000
byte rotation threshold and five backups. Rotation does not define the SQL
outbox's retention or guarantee an audit time horizon. This proposal preserves
that policy, rather than inventing a new audit lifetime. If an operator needs a
different audit horizon or a bound on all audit/operation/membership storage,
that decision must specify the retained evidence and replace correctness
lookups before deleting their source records. No such deletion is proposed
here. Do not create an audit row per cleanup pass as another unbounded ledger;
the durable floor itself records the cumulative discarded feed prefix.

Inspection/preview and committed cleanup results should expose:

- selected cap; per-recipient `H` and `F`; retained edge counts by kind;
- pending/delivered hint counts, separately from pending/delivered audit rows;
- proposed/committed floor, actual removed edge/hint counts, and remaining counts;
- expiry observations used, unknown provider results, and transaction failures;
- SQLite database/WAL sizes, freelist pages and checkpoint-busy status.

Counts returned for a failed transaction are not removal counts. If the commit
response is lost, read back the floor and remaining rows before another action.
`F` survives restart and is the cumulative retired-position count for the dense
native feed; per-call hint-removal counts are not a permanent delivery audit.

Deletion makes SQLite pages reusable; it does not shrink a previously large
database file. A long reader can also pin WAL pages. A later implementation must
observe those sizes and use the existing SQLite checkpoint facility at bounded
operation boundaries. Do not report a row cap as a total disk quota or promise
that a busy checkpoint reclaimed bytes. Offline file reclamation and changes to
audit retention require their own explicit operator action.

## Executable challenge and its limits

[The focused fixture](../tests/test_coord_retention_design.py) loads the native
schema unchanged, then adds the proposed floor only to its disposable database.
It extracts and runs the current native feed and object authorization SQL. Its
cleanup, HTTP response shapes and provider-error classification are executable
models, not a native implementation. The fixture also drives the pinned NATS
server to observe count eviction, age expiry and missing-stream errors.

| Challenge | Evidence |
| --- | --- |
| Silent deletion; delivery mistaken for consumption | The current query skips manually deleted edges. Delivered hint removal and one caller's advance leave another caller's edge available. |
| Stale floor and independent cursors | Exact inclusive lost range, equality boundary, pagination, empty suffix, future cursor and different room/feed sequence spaces. |
| Canonical absence and uncertain provider | Real NATS returns `NO_MESSAGE_FOUND` for both age/count removal. A missing stream has a different error. Modeled timeouts/integrity failures cannot authorize expiry deletion. |
| Orphan cleanup | Only an identity-matched expired prefix can extend the cut. A live brief blocks selective removal; the count cap still bounds interior orphans. |
| Revocation and regrant | Current native queries deny old/superseded grants and recheck after provider I/O. Loss metadata contains no old room details. |
| Restart and rollback | Injected SQLite deletion failure and child-process exit before/after commit preserve the floor/edge/hint relationship. Audit rows and room frontier remain intact. |
| Concurrent readers/writers | A held WAL reader sees a coherent old page. Two writers and a cleaner retain exactly the bounded suffix, checked against the set of all allocated positions. |

On Linux or macOS, run from the repository checkout with its locked Python
3.12/3.13 test environment. The existing `_binary_cache` fixture uses
`SAFEYOLO_COORD_NATS_BINARY` when supplied, or acquires the already pinned NATS
input through the configured route. The test checks its digest against the
native owner's pins. Choose a disposable **disk-backed** directory for pytest's
`--basetemp`; pytest replaces its contents. The following repository-local
directory is disposable and is not a live Coord store:

```sh
uv run --locked pytest -q tests/test_coord_retention_design.py --basetemp=.pytest_cache/coord-retention-design
```

The expected result is that every focused case passes without a native rebuild.
These cases do not prove performance at 100,000 rows, a native HTTP/client
rollout, audit export, a byte quota or safe deletion of installed data. Those
claims require the subsequent implementation and its affected real native
boundaries. No new dependency, framework, production task record or factory
change is part of this proposal.
