# Operator event stream and current pending work

## Live operator events

The authenticated `/admin/events` WebSocket serves Commander and native
`safeyolo watch`. Event records come from complete records in the shared
canonical JSON Lines (JSONL) audit log. The host follows the audit writer's
effective destination and rotation settings. Host commands and the proxy use
that same writer. These operator consumers do not subscribe to NATS.

The stream selects approval-required events, agent events, selected Admin and
operations events, Coord signal metadata, and high or critical security and
gateway events. Ordinary traffic bodies and credentials are not selected.
Signal prose comes from the canonical Admin API, with trusted author attribution.

Messages with `type: "operator_state"` are current-state controls. They have no
`event` field and are not audit records. `signals` and `approvals` report whether
the host can read those stores. `log: "following"` means the log reader is
available; it does not prove that every producer recorded its events. A non-null
`history_gap` reports skipped or unavailable history. Refreshing current work
does not replay or reconstruct that history.

One host check reads local canonical pending state each second for all viewers.
Relevant log delivery also requires a later host reconciliation, even when a
brief creation and resolution leave the pending-state fingerprint unchanged.
A delivery that overlaps a host read remains due for the next check.
These controls wake clients even if the final audit notification was
lost and no later business event occurs. With healthy state/API and client
connectivity, the target is visibility within five seconds. After relevant log
activity is reconciled, unchanged healthy state generates no refresh controls
or periodic viewer network requests.
Controls coalesce to the latest state separately for each attached observer.

Default watch shows current pending signals and approvals. It subscribes before
reading the initial snapshots, then refreshes on relevant events and controls.
Reconnect reads current state again. Changes and removals print once; unchanged
items stay quiet. Clearing an attributed signal does not independently verify
that its underlying claim was resolved. `watch --once` reads current pending
work. `watch --jsonl FILE` renders exact immutable historical signal revisions;
it does not present them as current pending work.

Commander refreshes its existing canonical approval list on controls and
reconnect. Discovery does not resubmit requests. Existing attention claims,
deduplication, suppression and decision authority still apply. A failed state
read retains the previous view and reports it as unavailable/stale. After a
failed canonical read, watch retries attachment with one-second pacing.

The host reader retains at most an 8 MiB partial record and reads at most 1 MiB
per turn. It follows renamed files and up to 64 retained rotation positions.
Truncation, unavailable retention, invalid or oversized records, and partial
records lost during rotation produce explicit status. Each attachment has a
bounded 64-record buffer. Overflow closes that attachment with code 1013;
WebSocket writes have a one-second timeout. A stalled client cannot block the
writer, other clients or operator decisions. Authentication precedes attachment;
invalid credentials receive HTTP 401. Ping, close and owned shutdown remain
supported.

The recorded feed has no replay service or exactly-once guarantee. A new
attachment can receive records still queued in the shared host reader. A
truncated file can cause repeated event IDs. JSONL file order is the recorded
feed order. General audit admission can be lossy and write failures
remain visible. Coord audit uses its durable outbox and can repeat the same event
ID after an ambiguous append. A successful state read is independent of JSONL
delivery. Pending recovery can work while recording is impaired. FlowStore
remains traffic history. NATS/JetStream still carries Coord and private approval
results; stopping it does not disable operator attachment or existing state reads.

## Focused validation

On a development host, select the repository's Rust toolchain. From the
repository root, run these controls with sufficient disk reserve:

```sh
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --lib operator_events::
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --test operator_controls
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --test command_centre_installed
```

For the broker-outage and canonical signal/watch controls, set
`SAFEYOLO_COORD_NATS_BINARY` to the verified NATS 2.14.5 executable. Add
`-- --include-ignored` to the operator control command and run:

```sh
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --test native_coord signals::native_ -- --include-ignored
```

On macOS, run the Commander controls from the repository root:

```sh
SAFEYOLO_COMMAND_CENTRE_TEST_FILTER=operator-recovery command-centre/macos/test.sh
```

The native watch control also creates and resolves signals and approvals
between host checks, observes creation through JSONL and drops the final
resolution frames on a healthy authenticated viewer connection. Both removals
must appear within five seconds with no later business event. It then checks
that idle viewers make no repeated state requests.

The Commander controls cover pending recovery, attention suppression, stale reads,
attachment/reconnect and idle network behavior.
These controls use synthetic credentials and isolated state. They do not
establish #869's outstanding installed, Tailnet or SSH observations, private
approval-result delivery, or automatic model wakeups.
