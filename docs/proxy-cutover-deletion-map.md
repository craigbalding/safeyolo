# Proxy cutover deletion map

This existing ledger accounts for the 41 pre-cutover owners at the isolated
#640 B1 draft. Its states describe source changes in this candidate, not
independent B1 acceptance or the exact post-deletion release F. The original
replacement gates and retained checks stay visible for Lens's review and later
release checks. A removed row can still have a final installed, rollback, or
platform gate outstanding under #640 B2–B7.

## Responsibility groups

- **Process and ingress (M7-01–M7-05):** the CLI `proxy.py` facade now launches
  only the packaged Rust executable and reports its path. The native process
  owns the listeners and readiness. `traffic_master.py` and Python Unix mode
  registration are removed. `traffic_session.py` remains because Rust still
  uses the private terminal for process lifetime and diagnostics.
- **Flow and audit (M7-06–M7-08):** native flow and audit writers own proxy
  records. Python addon integration, flow queue code, and the unused Python
  `storage/flow_store.py` writer are removed.
  `core/audit_writer.py` remains for Python CLI service configuration events.
- **Proxy hooks (M8-01–M8-28):** the mitmproxy addon chain and its policy,
  inspection, Agent API, gateway, logging, and transport hooks are removed.
  The accepted native implementations supply those proxy responsibilities;
  the old process-local `core/plumb_service.py` and mitmproxy timing hooks are
  removed. Retained shared CLI modules under `core/` remain where callers use them.
- **Package and comparator (M8-29–M8-31):** the Python PDP package and
  mitmproxy dependency are removed from the current wheel and lockfile. The
  installer builds Rust; its wheel audit rejects old proxy code. Historical
  comparisons select a pinned prior Python checkout and environment
  explicitly. An ordinary package rollback installs that prior package; the
  current CLI has no Python backend selection or automatic fallback.
- **Traffic view (M8-32–M8-33):** mitmproxy console patches are removed. The
  retained read-only terminal inspector and selected native exports own the
  supported traffic view.

The same cutover also removes Python-only early-response, WebSocket close,
Python policy-engine, and temporary policy-adapter code that the 41 path rows
referenced but did not list as separate owners. Test and vendor sources are
accounted for separately in the B1 review handoff.

The Python policy-chaos runner, its pytest module, and its scheduled workflow
are retired with the old policy engine. The acceptance graph no longer selects
that runner. The pinned pre-cutover checkout retains the historical experiments.
Native generated policy sequences, concurrency, failure stages, and abrupt
disposable-VM recovery remain open release assurance checks; focused CLI and
native Rust policy tests do not establish those broader claims.
Engine-only policy, budget, loader, mutation, sensor, and Unix-mode pytest
modules moved out of current collection with their removed owners. Tests for
retained compiler, list loading, TOML round trips, CLI mutation, and endpoint
keys remain in this tree.

## Path-level ledger

`Replacement gate` records the obligation associated with the former owner.
`Current or historical checks` names the original check family. Checks marked
`historical` remain in the pinned pre-cutover checkout at
`2ca598ce11d7c375a024b38eb3e7b4104a795d84`; they are not collected from
this branch. Unmarked checks remain in this branch. The B1 draft state records
what this branch changes; it does not assert that later B2–B7 gates passed.

| ID | Original path | Former responsibility | Replacement gate | Current or historical checks | B1 draft state |
|---|---|---|---|---|---|
| M7-01 | `cli/src/safeyolo/proxy.py` | Backend selection, Python process lifecycle, readiness, status/stop, and explicit rollback | Installed Rust start/status/stop, failure cleanup, source identity, and Python rollback on Linux and macOS | `cli/tests/test_rust_proxy.py`<br>`cli/tests/test_lifecycle_rust.py`<br>`cli/tests/test_doctor.py` | retained: native CLI facade |
| M7-02 | `cli/src/safeyolo/traffic_master.py` | Python production process owner and addon registration order | Native process owner publishes equivalent readiness, shutdown, event ordering, and listener lifecycle | historical: `cli/tests/test_traffic_master.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M7-03 | `cli/src/safeyolo/traffic_session.py` | tmux/session process coupling and Python proxy child launch | Native launcher uses the retained private session for process lifetime and restart; explicit rollback still starts Python | historical: `cli/tests/test_proxy.py`<br>`cli/tests/test_lifecycle_rust.py` | retained: native session |
| M7-04 | `cli/src/safeyolo/proxy_modes/unix_listener.py` | Per-agent UDS ingress and listener mode adaptation | Native listeners preserve agent identity, live add/remove, restart cleanup, and supported host/guest bridges | historical: `tests/test_unix_listener.py`<br>`cli/tests/test_sockets.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M7-05 | `cli/src/safeyolo/proxy_modes/__init__.py` | Python UDS mode package boundary; runtime registration is owned by `proxy_modes/unix_listener.py::ensure_registered()` | Native ingress replaces the `unix_listener.py` registration owner and no Python mode import remains on the selected Rust path | historical: `tests/test_unix_listener.py` | removed in B1 candidate |
| M7-06 | `cli/src/safeyolo/core/base.py` | Python flow integration and shared flow metadata dispatch | Native flow ownership and metadata preserve authorized evidence, redaction, and failure boundaries | historical: `tests/test_flow_recorder.py`<br>historical: `tests/test_flow_store.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M7-07 | `cli/src/safeyolo/core/audit_writer.py` | Durable audit queue, ordering, shutdown drain, and failure reporting | Native writer preserves ordering, ownership, rollback/retention semantics, and graceful drain | `tests/test_audit_writer.py`<br>`tests/test_audit_schema.py`<br>`tests/proxy_migration` | retained: shared CLI audit |
| M7-08 | `cli/src/safeyolo/core/flow_writer.py` | SQLite flow persistence, body indexing, and transaction boundaries | Native store preserves schema interchange, evidence scope, rollback, and restart reads | historical: `tests/test_flow_writer.py`<br>historical: `tests/test_flow_store.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M8-01 | `cli/src/safeyolo/mitm_addons/__init__.py` | Production addon chain construction and ordering | Native chain replaces every retained hook with equivalent ordering and failure containment | historical: `cli/tests/test_traffic_master.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M8-02 | `cli/src/safeyolo/mitm_addons/pid_writer.py` | Atomic readiness marker publication and cleanup | Native readiness is published only after required listeners/state are ready and is removed on graceful exit | historical: `cli/tests/test_proxy.py`<br>historical: `cli/tests/test_traffic_master.py` | removed in B1 candidate |
| M8-03 | `cli/src/safeyolo/mitm_addons/file_logging.py` | Startup logging setup and routine-log secret boundaries | Native logging is ready before security hooks and preserves diagnostics without secret leakage | `tests/test_utils_logging.py`<br>`tests/test_audit_writer.py` | removed in B1 candidate |
| M8-04 | `cli/src/safeyolo/mitm_addons/memory_monitor.py` | Connection/WebSocket memory and process statistics | Native counters report equivalent measurements and reclaim per-connection state under failure | historical: `tests/test_memory_monitor.py` | removed in B1 candidate |
| M8-05 | `cli/src/safeyolo/mitm_addons/admin_shield.py` | Protected host-local management endpoint and CONNECT blocking | Native egress boundary blocks configured protected ports before DNS/socket effects | historical: `tests/test_admin_shield.py` | removed in B1 candidate |
| M8-06 | `cli/src/safeyolo/mitm_addons/agent_api.py` | Authenticated reserved-host API and scoped evidence/coordination routes | Native local routes preserve authentication, trusted ingress identity, state access, and response contracts | historical: `tests/test_agent_api.py`<br>historical: `tests/test_agent_api_coord.py`<br>historical: `tests/test_agent_token.py` | removed in B1 candidate |
| M8-07 | `cli/src/safeyolo/mitm_addons/agent_api_guard.py` | Local containment when the normal Agent API handler is missing or fails | Native dispatch remains local for import, route, and handler failures with no upstream resolution | historical: `tests/test_agent_api.py`<br>historical: `tests/test_transport_guard.py` | removed in B1 candidate |
| M8-08 | `cli/src/safeyolo/mitm_addons/loop_guard.py` | Via pseudonym loop detection and forwarding header handling | Native ingress/egress preserves loop containment and nested proxy identity | historical: `tests/test_loop_guard.py`<br>historical: `cli/tests/test_proxy.py` | removed in B1 candidate |
| M8-09 | `cli/src/safeyolo/mitm_addons/request_id.py` | Request correlation, trace opt-in, and spoofed-header cleanup | Native request/connection IDs preserve attribution and internal-header boundaries across CONNECT and inner traffic | historical: `tests/test_request_id.py`<br>historical: `tests/test_connect_policy.py`<br>historical: `tests/test_trace_wire_vocabulary.py` | removed in B1 candidate |
| M8-10 | `cli/src/safeyolo/mitm_addons/operator_provenance.py` | Operator edit/replay/kill/resume/revert observations and flow relationships | Native operator operations preserve trusted initiation, evidence owner, and resulting-flow provenance | historical: `tests/test_operator_provenance.py`<br>historical: `tests/test_agent_identity_resolution.py` | removed in B1 candidate |
| M8-11 | `cli/src/safeyolo/mitm_addons/service_discovery.py` | Cached agent-map resolution and trusted UDS attribution | Native listener identity and external map behavior preserve conflict fail-closed semantics and lifecycle events | historical: `tests/test_service_discovery_file.py`<br>historical: `tests/test_agent_identity_resolution.py` | removed in B1 candidate |
| M8-12 | `cli/src/safeyolo/mitm_addons/sse_streaming.py` | SSE/NDJSON/selected JSON streaming behavior and limits | Native incremental bodies preserve configured streaming, inspection coverage, and explicit bypass reporting | historical: `tests/test_sse_streaming.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M8-13 | `cli/src/safeyolo/mitm_addons/policy_engine.py` | Python PolicyClient lifecycle, policy reload, and cache ownership | Native policy state and reload preserve TOML/YAML semantics, budgets, rollback, and remaining CLI consumers | historical: `tests/test_pdp_client.py`<br>historical: `tests/test_policy_engine.py`<br>historical: `tests/test_policy_loader.py`<br>historical: `tests/test_toml_policy_loader.py`<br>historical: `tests/test_budget_tracker.py`<br>historical: `tests/test_policy_chaos.py` | removed in B1 candidate |
| M8-14 | `cli/src/safeyolo/mitm_addons/service_gateway.py` | Service tokens, contracts, grants, vault injection, and OAuth refresh | Native service authorization covers route/injection/OAuth/catalog writes and cross-runtime rollback, including installed rollback | historical: `tests/test_service_gateway.py`<br>historical: `tests/test_contract_enforcement.py`<br>`tests/test_oauth2_flow.py`<br>`tests/test_service_loader.py`<br>`proxy/tests/gateway_contract_workflow.rs` | removed in B1 candidate |
| M8-15 | `cli/src/safeyolo/mitm_addons/network_guard.py` | HTTP/CONNECT policy decisions, budgets, and fail-closed errors | Native policy runs before outbound effects with matching decision/effect and port/agent scope | historical: `tests/test_network_guard.py`<br>historical: `tests/test_connect_policy.py`<br>`tests/test_agent_scoped_egress.py`<br>historical: `tests/test_destination_ports.py`<br>`tests/test_destination_keys.py` | removed in B1 candidate |
| M8-16 | `cli/src/safeyolo/mitm_addons/circuit_breaker.py` | Circuit state, persistence, reset, and force-open controls | Native circuit lifecycle preserves thresholds, persistence, reload, reset, and restart behavior | historical: `tests/test_circuit_breaker.py` | removed in B1 candidate |
| M8-17 | `cli/src/safeyolo/mitm_addons/credential_guard.py` | Credential detection, policy decisions, and block/warn outcomes | Native header/body credential coverage preserves ordering, fingerprints, budgets, and raw-secret boundaries | historical: `tests/test_credential_guard.py`<br>`tests/test_credential_catalog.py`<br>`tests/test_policy_budget_contract.py` | removed in B1 candidate |
| M8-18 | `cli/src/safeyolo/mitm_addons/pattern_scanner.py` | URL/header/body and complete WebSocket pattern inspection | Native scanner preserves source decoding, ordering, large-message behavior, and explicit unsupported grammar outcomes | historical: `tests/test_pattern_scanner.py`<br>`tests/test_shipped_security_config.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M8-19 | `cli/src/safeyolo/mitm_addons/test_context.py` | Test-context parsing, declaration scope, TTL, and evidence ownership | Native context state preserves malformed-header, cross-agent, expiry, and streamed-body outcomes | historical: `tests/test_test_context.py`<br>`tests/test_test_context_contract.py`<br>`cli/tests/test_test_context_cli.py` | removed in B1 candidate |
| M8-20 | `cli/src/safeyolo/mitm_addons/flow_recorder.py` | Flow recording, redaction, late attribution, and persistence failures | Native recorder preserves schema, scope, backpressure, and transaction rollback | historical: `tests/test_flow_recorder.py`<br>historical: `tests/test_flow_writer.py`<br>historical: `tests/test_flow_store.py` | removed in B1 candidate |
| M8-21 | `cli/src/safeyolo/mitm_addons/request_logger.py` | Structured request/response events and quiet-host behavior | Native event writer preserves correlation, decision attribution, ordering, and failure isolation | historical: `tests/test_request_logger.py`<br>`tests/test_audit_schema.py`<br>`tests/test_audit_writer.py` | removed in B1 candidate |
| M8-22 | `cli/src/safeyolo/mitm_addons/ignored_host_logger.py` | Passthrough connection lifecycle evidence | Native passthrough recorder distinguishes tunnel metadata from inspected application evidence | historical: `tests/test_ignored_host_logger.py` | removed in B1 candidate |
| M8-23 | `cli/src/safeyolo/mitm_addons/metrics.py` | Domain counts, outcome rates, latency, JSON, and Prometheus reports | Native counters/renderers preserve actual outcomes and API availability under load | historical: `tests/test_metrics.py` | removed in B1 candidate |
| M8-24 | `cli/src/safeyolo/mitm_addons/traffic_scope.py` | Agent/test/intent/role scope combined with operator display filters | Native inspection scope preserves authorization boundaries and retained UI controls | historical: `tests/test_traffic_scope.py`<br>`cli/tests/test_commands_traffic.py`<br>historical: `cli/tests/test_traffic_master.py` | removed in B1 candidate |
| M8-25 | `cli/src/safeyolo/mitm_addons/flow_pruner.py` | Bounded interactive view and WebSocket history pruning | Native retained-evidence limits preserve durable records and bounded display state | historical: `tests/test_flow_pruner.py`<br>historical: `cli/tests/test_websocket_console.py`<br>historical: `cli/tests/test_websocket_body_filter.py` | removed in B1 candidate |
| M8-26 | `cli/src/safeyolo/mitm_addons/admin_api.py` | Host-local policy, budget, approval, service, listener, and operator APIs | Native operator routes preserve authentication, transactional policy activation, and state rollback | historical: `tests/test_admin_api.py`<br>`tests/test_policy_transaction_regressions.py`<br>`cli/tests/test_api.py` | removed in B1 candidate |
| M8-27 | `cli/src/safeyolo/mitm_addons/probe_sink.py` | Reserved diagnostic probes and local success synthesis | Native probe path reports only reached steps and never sends reserved probes upstream | historical: `tests/test_probe_sink.py`<br>historical: `tests/test_trace_chain_regression.py`<br>`proxy/src/http/probe/tests/` | removed in B1 candidate |
| M8-28 | `cli/src/safeyolo/mitm_addons/transport_guard.py` | Reserved CONNECT containment, late probe fallback, and connection backstops | Native outbound boundary retains local classification and prevents handler failures from creating upstream effects | historical: `tests/test_transport_guard.py`<br>historical: `tests/test_agent_api.py`<br>historical: `tests/test_probe_lifecycle.py` | removed in B1 candidate |
| M8-29 | `pdp/` | Python policy client/schema package retained by the comparator, CLI, and wheel | Native policy replacement plus all remaining CLI consumers pass; wheel/import and Python comparator rollback remain green | historical: `tests/test_pdp_client.py`<br>`cli/tests/test_runtime_identity.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M8-30 | `pyproject.toml` | mitmproxy and Python runtime package declarations, including retained `pdp` packaging | Consumer search and frozen install prove no Python path is needed by the selected native runtime while Python rollback still installs and starts | `tests/test_install_sh.py`<br>`cli/tests/test_cli_imports.py`<br>`tests/proxy_migration` | updated: native package |
| M8-31 | `uv.lock` | Reproducible Python comparator and rollback dependency graph | Replacement environment is attested and comparator jobs remain reproducible before dependency removal | `tests/test_install_sh.py`<br>`tests/proxy_migration` | updated: native lock |
| M8-32 | `cli/src/safeyolo/websocket_console.py` | Python mitmproxy ConsoleMaster renderer patch and retained console flow details | Equivalent native console/detail outcomes are demonstrated before removing the mitmweb/ConsoleMaster glue | historical: `cli/tests/test_websocket_console.py`<br>`tests/proxy_migration` | removed in B1 candidate |
| M8-33 | `cli/src/safeyolo/websocket_body_filter.py` | Python WebSocket body-filter and display rendering patch | Equivalent native WebSocket body filtering, display, and unsupported-outcome behavior are demonstrated before removal | historical: `cli/tests/test_websocket_body_filter.py`<br>`tests/proxy_migration` | removed in B1 candidate |

## Current disposition

This is a review candidate from integrated head `2ca598ce11d7c375a024b38eb3e7b4104a795d84`
on an isolated branch. Normal installed launch selects Rust, and a missing or
failing native executable reports an error without starting Python. Explicit
rollback is a package change to the selected prior Python release, followed
by a deliberate return to the new package. Existing CA, HMAC, credential,
policy, service, audit, and flow files are not converted by this source change.

The pre-deletion installed Linux/import results referenced in [#640](https://github.com/craigbalding/safeyolo/issues/640)
retain their original scope. B1 needs Lens review of this exact candidate;
physical macOS/VZ, final systrap/KVM/VZ lanes, package rollback, and release F
remain #640 gates. No acceptance state is inferred from this map.
