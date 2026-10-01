# #627 native operator controls evidence

This candidate is based on integration commit
`46681aa7a23d58bdaffec6f631cb7e9227b2241a` on branch
`feat/issue-627-facade-resume`. It keeps the operator listener, audit writer,
policy owner, agent discovery state, service mutation owner, and gateway store
already supplied by the native runtime. The test fixture uses only synthetic
tokens, policy identifiers, and loopback endpoints.

The reviewable slice has a real consumer boundary at the native admin TCP
listener. Authenticated consumers can read `/admin/runtime-identity`,
`/admin/instance`, `/admin/approvals`, `/admin/agents`, `/admin/policy/baseline`,
`/modes`, and `/plugins/{name}/mode`. They can use `/admin/policy/validate`,
`/admin/policy/baseline/approve`, `/admin/policy/baseline/deny`,
`/admin/policy/baseline`, and the host allow, deny, rate, and bypass routes.
Mode writes update retained process state used by live network, credential, and
pattern enforcement. Policy writes use the existing atomic policy helpers and
are consumed at the existing policy reload boundary; the wire test drives that
boundary through `Proxy::reload_policy_if_changed` after a durable write.

`GET /admin/events` is a native authenticated WebSocket upgrade on the same
loopback admin listener. It starts at the current audit-file end, tails only
canonical operator-relevant events, handles ping, close, and listener shutdown,
and does not replay old rows. A real TCP test opens the upgrade, performs a
second authenticated policy denial through a separate TCP connection, and
observes the resulting `admin.denial` JSON frame. Invalid event-stream
credentials receive 401 before upgrade. The canonical audit writer remains the
only event producer; the stream does not create a second log or coordinator.

Approval reconstruction is chronological and request aware. A denial closes
the prompt that precedes it (and may carry that prompt's `approval_request_id`),
while a later retry with the same credential and destination creates a new
pending prompt. A real native agent Unix-socket request test proves the full
prompt → `/admin/policy/baseline/deny` → retry path: both attempts return 428,
the controlled loopback origin receives zero requests, and
`GET /admin/approvals` retains only the second request ID.

The owned native wire tests are
`proxy/tests/operator_controls.rs::native_operator_consumer_controls_and_event_stream_are_live`,
`native_operator_approval_denial_then_retry_is_resolved`,
`native_operator_event_reconnect_does_not_replay_old_events`,
`native_operator_stalled_event_subscriber_does_not_block_controls`,
`native_operator_invalid_mutations_are_terminal_and_state_preserving`, and
`native_operator_mutations_keep_committed_state_when_audit_sink_fails`.
The retained Python consumers are
`tests/proxy_migration/test_operator_consumer_approval.py`,
`test_operator_task_api.py`, and
`test_operator_modes_and_listeners.py`. The latter drives the existing mode
and listener consumers against live enforcement and records the exact
ignore-host publication and clearing events while #631 retains matching
semantics. From `candidate/proxy`, the exact guarded commands and results were:

```text
SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/facade-resume-work/target ../scripts/cargo_with_space.sh check
PASS

SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/facade-resume-work/target ../scripts/cargo_with_space.sh test --test operator_controls -- --nocapture
PASS: 6 passed, 0 failed

SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/facade-resume-work/target ../scripts/cargo_with_space.sh build --bin safeyolo-proxy
PASS

SAFEYOLO_DATA_DIR=/tmp/safeyolo-facade-py-data SAFEYOLO_RUST_PROXY=/home/agent/safeyolo-rust-620-evidence/facade-resume-work/target/debug/safeyolo-proxy SAFEYOLO_RUST_NATIVE_ONLY=1 uv run --frozen pytest -q tests/proxy_migration/test_operator_modes_and_listeners.py --proxy-backend rust
PASS: 3 passed, 0 failed

SAFEYOLO_DATA_DIR=/tmp/safeyolo-facade-py-data SAFEYOLO_RUST_PROXY=/home/agent/safeyolo-rust-620-evidence/facade-resume-work/target/debug/safeyolo-proxy SAFEYOLO_RUST_NATIVE_ONLY=1 uv run --frozen pytest -q tests/proxy_migration/test_operator_consumer_approval.py tests/proxy_migration/test_operator_task_api.py --proxy-backend rust
PASS: 3 passed, 0 failed

uv run --frozen pytest -q cli/tests/test_api.py cli/tests/test_ignore_hosts.py
PASS: 62 passed, 0 failed

cargo fmt --all -- --check
KNOWN BASELINE DIFF: proxy/src/trace/tests.rs and proxy/tests/credential_http.rs

SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/facade-resume-work/target ../scripts/cargo_with_space.sh clippy --lib --tests -- -D warnings
KNOWN BASELINE FAILURE: existing dead-code, clippy style, and too-many-arguments findings in agent_api/plumb.rs, admin_api.rs, admin_listener/mutation_tests.rs, grants.rs, and policy.rs
```

The existing `admin_transport` source-parity test remains a known inherited
failure on this integration base: it expects four request rows but the current
runtime also emits startup `ops.policy_reload` and `ops.startup` rows before
the authenticated requests, so it observes six rows. This candidate does not
change that unrelated startup audit behavior or its fixture.

The following acceptance work remains with the existing owners and is not
claimed by this slice: native agent start, stop, and desktop presentation;
passthrough matching and reload/removal semantics owned by #631; web-tailnet
controls; plumb approval and conversation routes; full live agent
approval/retry flows; gateway grant and contract-binding mutations already
owned by the retained #624/#625 handlers; and Python CLI selection of the
native event URL. Those routes require their existing lifecycle, gateway,
plumb, presentation, or collaboration owners. No duplicate state store or
alternate service client was added here.
