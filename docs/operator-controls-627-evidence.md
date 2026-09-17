# #627 native operator controls evidence

This candidate is based on integration commit
`fe3df9c5f5a907a9505396c9f68e1d2bc7b11e6e` on branch
`feat/issue-627-candidate`. It keeps the operator listener, audit writer,
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

The owned wire test is
`proxy/tests/operator_controls.rs::native_operator_consumer_controls_and_event_stream_are_live`.
From `candidate/proxy`, the exact guarded commands and results were:

```text
SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/623-http-work/target ../scripts/cargo_with_space.sh check
PASS

SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/623-http-work/target ../scripts/cargo_with_space.sh test --test operator_controls -- --nocapture
PASS: 1 passed, 0 failed

SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/623-http-work/target ../scripts/cargo_with_space.sh test --test admin_budgets -- --nocapture
PASS: 4 passed, 0 failed, 1 ignored (source-Python oracle)

SAFEYOLO_CARGO_RESERVE_GIB=20 CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/623-http-work/target ../scripts/cargo_with_space.sh clippy --lib --tests -- -D warnings
PASS

cargo fmt --all -- --check
PASS
```

The existing `admin_transport` source-parity test remains a known inherited
failure on this integration base: it expects four request rows but the current
runtime also emits startup `ops.policy_reload` and `ops.startup` rows before
the authenticated requests, so it observes six rows. This candidate does not
change that unrelated startup audit behavior or its fixture.

The following acceptance work remains with the existing owners and is not
claimed by this slice: native agent start, stop, and desktop presentation;
proxy listener mode, ignore-host, and web-tailnet controls; plumb approval and
conversation routes; task activation/deletion; full live agent approval/retry
flows; gateway grant and contract-binding mutations already owned by the
retained #624/#625 handlers; and Python CLI selection of the native event URL.
Those routes require their existing lifecycle, gateway, plumb, presentation,
or collaboration owners. No duplicate state store or alternate service client
was added here.
