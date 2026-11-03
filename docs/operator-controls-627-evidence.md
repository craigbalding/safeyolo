# Native operator controls and live events

The native Admin API (application programming interface) owns operator state and
decisions. Authenticated consumers can read runtime identity, agents, pending
approvals, policy and control modes. Policy mutations use the existing atomic
policy helpers and the runtime's policy reload boundary. Mode mutations update
process state used by live enforcement.

## Live operator events

`GET /admin/events` is an authenticated WebSocket upgrade on the loopback Admin
listener or the configured Command Centre event port. The shared audit writer
publishes eligible events through the selected instance's local NATS runtime.
Proxy operations, short host commands and Coord metadata use that writer.
Short host commands wait for bounded publication completion before exiting.
The subscriber completes its NATS subscription before returning HTTP 101, so
publication during the WebSocket handshake is eligible for delivery.

The WebSocket retains its event filter: approval-required events, agent events,
the selected Admin, Plumb and operations events, and high or critical security
and gateway events. Ordinary traffic bodies are not published. Coord signal
metadata also uses the common live path. `safeyolo watch` consumes that metadata
and fetches canonical pending signal revisions through the Admin API. The
WebSocket keeps its existing filter rather than forwarding all Coord metadata.
Broker credentials stay on the host; agents use their authorized Agent API.

Live publication uses bounded memory and a separate worker. It cannot wait
indefinitely on a request or audit write. Each publication attempt has a
two-second timeout. Publication failure, buffer overflow and incomplete shutdown
drain produce diagnostics. JSON Lines (JSONL) remains the forensic archive, and
FlowStore remains traffic history. Live success does not confirm archive
durability. Archive failure does not suppress the independent live attempt.
Canonical state, audit writes, `/explain`, policy enforcement and traffic recording
remain independent of broker availability.

There is no live event replay or exactly-once promise. A new subscription receives
publications after its subscription is established, including an event that was
already queued in its producer. Each publisher preserves its admitted event
order; separate publishers have no common publication order. Recovery of
pending Coord outbox metadata after a worker restart can repeat an event ID. Canonical object IDs and revisions remain
authoritative. Watch suppresses unchanged pending revisions per attachment.

If the broker is unavailable at attachment, `/admin/events` returns HTTP 503.
Invalid credentials receive HTTP 401 before any broker access. Broker loss or
NATS subscriber overflow closes an attached WebSocket with code 1013. A stalled
WebSocket has a bounded write timeout and cannot block other subscribers or
operator decisions. Reconnect establishes a fresh subscription and does not
replay missed publications. Ping, close and owned listener shutdown remain
supported. The configured NATS payload limit also bounds live publications.

If the watch feed fails, `safeyolo watch` reports the failure and exits. Restart
watch to read current canonical pending state and attach again. `watch --once`
reads pending state without NATS. `watch --jsonl FILE` reads retained metadata
and resolves its immutable revisions; it does not follow an audit file for live
updates. Unresolved operator needs remain in canonical state while detached.

## Focused validation

The producer controls are in `proxy/src/operator_events.rs` and
`proxy/tests/native_coord/signals.rs`. The authenticated WebSocket, reconnect,
slow-consumer, broker-outage and operator-decision controls are in
`proxy/tests/operator_controls.rs`. These controls use synthetic credentials
and owned loopback NATS servers. They do not use the operator's live Coord data.

On a development host, select the repository's pinned Rust toolchain and set
`SAFEYOLO_COORD_NATS_BINARY` to the verified NATS 2.14.5 executable. From the
repository root, run the focused controls with sufficient disk reserve:

```sh
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --lib operator_events::tests -- --ignored
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --test operator_controls -- --include-ignored
CARGO_BUILD_JOBS=1 scripts/cargo_with_space.sh test --locked --manifest-path proxy/Cargo.toml --test native_coord signals::native_signals_author_page_watch_replay_and_restart -- --exact --ignored
```

These are local producer and consumer controls. They do not establish physical
Tailnet forwarding, Mac application behavior, private approval-result delivery,
or the other separately owned integration outcomes.
