# Proxy cutover deletion map

This ledger is the path-level removal plan for the Rust proxy cutover. It is
deliberately a preparation artifact: every row is currently **retained**. A
row may be removed only after the replacement gate in that row has evidence
from the same candidate, and after the affected Python checks still pass.

The ledger is narrower than a list of files that happen to import mitmproxy.
It names the old runtime owner, the behavior that owner supplies, the proof
needed before removal, and the checks that exercise the affected contract.
The full behavior descriptions remain in the [parity inventory](proxy-parity.md)
and the source-level writer/state requirements remain in
[state compatibility](state-compatibility.md).

## Cutover and rollback rules

The following rules apply to every row:

1. Keep `proxy.backend: python` as the default until the complete native
   lifecycle, ingress, state, rollback, platform, and retained-consumer
   evidence is accepted. An explicit `proxy.backend: rust` launch is not a
   default-switch proof.
2. Keep the Python comparator jobs, including `tests/proxy_migration`, while
   a row is being evaluated. A native test that passes in isolation does not
   authorize deleting the corresponding Python fixture or test.
3. Keep the source installer able to select Python and keep the prior Python
   environment usable. `SAFEYOLO_SKIP_RUST_BUILD=1` is an explicit artifact
   escape hatch; it is not a cutover approval.
4. Record a row's replacement evidence, affected-test result, and rollback
   result against one immutable candidate before removing the row. A failed
   native start or state write must return to the Python selector without
   changing the source policy, service, credential, audit, or flow files.
5. Removal of a shared library requires a separate consumer search. A row
   below can therefore remain retained after an addon wrapper is replaced.

The rollback owner for all rows is the Python production path selected by
`proxy.backend: python`. Native launch failures must not silently select that
path; the operator selects it explicitly. This preserves an observable
rollback decision and keeps comparator jobs meaningful during the pilot.

## Path-level ledger

`Retained checks` are affected source tests and comparator jobs. They are not
claims that the native replacement has passed. `Replacement gate` is the
minimum evidence required before the path can be deleted.

| ID | Current path | Retained responsibility | Replacement gate | Retained checks | State |
|---|---|---|---|---|---|
| M7-01 | `cli/src/safeyolo/proxy.py` | Backend selection, Python process lifecycle, readiness, status/stop, and explicit rollback | Installed Rust start/status/stop, failure cleanup, source identity, and Python rollback on Linux and macOS | `cli/tests/test_proxy.py`<br>`cli/tests/test_start_safeyolo.py`<br>`cli/tests/test_lifecycle_rust.py` | retained |
| M7-02 | `cli/src/safeyolo/traffic_master.py` | Python production process owner and addon registration order | Native process owner publishes equivalent readiness, shutdown, event ordering, and listener lifecycle | `cli/tests/test_traffic_master.py`<br>`tests/proxy_migration` | retained |
| M7-03 | `cli/src/safeyolo/traffic_session.py` | tmux/session process coupling and Python proxy child launch | Native launcher owns process lifetime and restart without tmux or Python child coupling; explicit rollback still starts Python | `cli/tests/test_proxy.py`<br>`cli/tests/test_lifecycle_rust.py` | retained |
| M7-04 | `cli/src/safeyolo/proxy_modes/unix_listener.py` | Per-agent UDS ingress and listener mode adaptation | Native listeners preserve agent identity, live add/remove, restart cleanup, and supported host/guest bridges | `tests/test_unix_listener.py`<br>`cli/tests/test_sockets.py`<br>`tests/proxy_migration` | retained |
| M7-05 | `cli/src/safeyolo/proxy_modes/__init__.py` | Registration of the Python UDS mode before mitmproxy startup | Native ingress owns registration and no Python mode import remains on the selected Rust path | `tests/test_unix_listener.py`<br>`cli/tests/test_cli_imports.py` | retained |
| M7-06 | `cli/src/safeyolo/core/base.py` | Python flow integration and shared flow metadata dispatch | Native flow ownership and metadata preserve authorized evidence, redaction, and failure boundaries | `tests/test_flow_recorder.py`<br>`tests/test_flow_store.py`<br>`tests/proxy_migration` | retained |
| M7-07 | `cli/src/safeyolo/core/audit_writer.py` | Durable audit queue, ordering, shutdown drain, and failure reporting | Native writer preserves ordering, ownership, rollback/retention semantics, and graceful drain | `tests/test_audit_writer.py`<br>`tests/test_audit_schema.py`<br>`tests/proxy_migration` | retained |
| M7-08 | `cli/src/safeyolo/core/flow_writer.py` | SQLite flow persistence, body indexing, and transaction boundaries | Native store preserves schema interchange, evidence scope, rollback, and restart reads | `tests/test_flow_writer.py`<br>`tests/test_flow_store.py`<br>`tests/proxy_migration` | retained |
| M8-01 | `cli/src/safeyolo/mitm_addons/__init__.py` | Production addon chain construction and ordering | Native chain replaces every retained hook with equivalent ordering and failure containment | `cli/tests/test_traffic_master.py`<br>`tests/proxy_migration` | retained |
| M8-02 | `cli/src/safeyolo/mitm_addons/pid_writer.py` | Atomic readiness marker publication and cleanup | Native readiness is published only after required listeners/state are ready and is removed on graceful exit | `cli/tests/test_proxy.py`<br>`cli/tests/test_traffic_master.py` | retained |
| M8-03 | `cli/src/safeyolo/mitm_addons/file_logging.py` | Startup logging setup and routine-log secret boundaries | Native logging is ready before security hooks and preserves diagnostics without secret leakage | `tests/test_utils_logging.py`<br>`tests/test_audit_writer.py` | retained |
| M8-04 | `cli/src/safeyolo/mitm_addons/memory_monitor.py` | Connection/WebSocket memory and process statistics | Native counters report equivalent measurements and reclaim per-connection state under failure | `tests/test_memory_monitor.py` | retained |
| M8-05 | `cli/src/safeyolo/mitm_addons/admin_shield.py` | Protected host-local management endpoint and CONNECT blocking | Native egress boundary blocks configured protected ports before DNS/socket effects | `tests/test_admin_shield.py` | retained |
| M8-06 | `cli/src/safeyolo/mitm_addons/agent_api.py` | Authenticated reserved-host API and scoped evidence/coordination routes | Native local routes preserve authentication, trusted ingress identity, state access, and response contracts | `tests/test_agent_api.py`<br>`tests/test_agent_api_coord.py`<br>`tests/test_agent_token.py` | retained |
| M8-07 | `cli/src/safeyolo/mitm_addons/agent_api_guard.py` | Local containment when the normal Agent API handler is missing or fails | Native dispatch remains local for import, route, and handler failures with no upstream resolution | `tests/test_agent_api.py`<br>`tests/test_transport_guard.py` | retained |
| M8-08 | `cli/src/safeyolo/mitm_addons/loop_guard.py` | Via pseudonym loop detection and forwarding header handling | Native ingress/egress preserves loop containment and nested proxy identity | `tests/test_loop_guard.py`<br>`cli/tests/test_proxy.py` | retained |
| M8-09 | `cli/src/safeyolo/mitm_addons/request_id.py` | Request correlation, trace opt-in, and spoofed-header cleanup | Native request/connection IDs preserve attribution and internal-header boundaries across CONNECT and inner traffic | `tests/test_request_id.py`<br>`tests/test_connect_policy.py`<br>`tests/test_trace_wire_vocabulary.py` | retained |
| M8-10 | `cli/src/safeyolo/mitm_addons/operator_provenance.py` | Operator edit/replay/kill/resume/revert observations and flow relationships | Native operator operations preserve trusted initiation, evidence owner, and resulting-flow provenance | `tests/test_operator_provenance.py`<br>`tests/test_agent_identity_resolution.py` | retained |
| M8-11 | `cli/src/safeyolo/mitm_addons/service_discovery.py` | Cached agent-map resolution and trusted UDS attribution | Native listener identity and external map behavior preserve conflict fail-closed semantics and lifecycle events | `tests/test_service_discovery_file.py`<br>`tests/test_agent_identity_resolution.py` | retained |
| M8-12 | `cli/src/safeyolo/mitm_addons/sse_streaming.py` | SSE/NDJSON/selected JSON streaming behavior and limits | Native incremental bodies preserve configured streaming, inspection coverage, and explicit bypass reporting | `tests/test_sse_streaming.py`<br>`tests/proxy_migration` | retained |
| M8-13 | `cli/src/safeyolo/mitm_addons/policy_engine.py` | Python PolicyClient lifecycle, policy reload, and cache ownership | Native policy state and reload preserve TOML/YAML semantics, budgets, rollback, and remaining CLI consumers | `tests/test_pdp_client.py`<br>`tests/test_policy_engine.py`<br>`tests/test_policy_loader.py` | retained |
| M8-14 | `cli/src/safeyolo/mitm_addons/service_gateway.py` | Service tokens, contracts, grants, vault injection, and OAuth refresh | Native service authorization covers route/injection/OAuth/catalog writes and cross-runtime rollback, including installed rollback | `tests/test_service_gateway.py`<br>`tests/test_contract_enforcement.py`<br>`tests/test_oauth2_flow.py`<br>`tests/test_service_loader.py`<br>`proxy/tests/gateway_contract_workflow.rs` | retained |
| M8-15 | `cli/src/safeyolo/mitm_addons/network_guard.py` | HTTP/CONNECT policy decisions, budgets, and fail-closed errors | Native policy runs before outbound effects with matching decision/effect and port/agent scope | `tests/test_network_guard.py`<br>`tests/test_connect_policy.py`<br>`tests/test_agent_scoped_egress.py`<br>`tests/test_destination_ports.py` | retained |
| M8-16 | `cli/src/safeyolo/mitm_addons/circuit_breaker.py` | Circuit state, persistence, reset, and force-open controls | Native circuit lifecycle preserves thresholds, persistence, reload, reset, and restart behavior | `tests/test_circuit_breaker.py` | retained |
| M8-17 | `cli/src/safeyolo/mitm_addons/credential_guard.py` | Credential detection, policy decisions, and block/warn outcomes | Native header/body credential coverage preserves ordering, fingerprints, budgets, and raw-secret boundaries | `tests/test_credential_guard.py`<br>`tests/test_credential_catalog.py`<br>`tests/test_policy_budget_contract.py` | retained |
| M8-18 | `cli/src/safeyolo/mitm_addons/pattern_scanner.py` | URL/header/body and complete WebSocket pattern inspection | Native scanner preserves source decoding, ordering, large-message behavior, and explicit unsupported grammar outcomes | `tests/test_pattern_scanner.py`<br>`tests/test_shipped_security_config.py`<br>`tests/proxy_migration` | retained |
| M8-19 | `cli/src/safeyolo/mitm_addons/test_context.py` | Test-context parsing, declaration scope, TTL, and evidence ownership | Native context state preserves malformed-header, cross-agent, expiry, and streamed-body outcomes | `tests/test_test_context.py`<br>`tests/test_test_context_contract.py`<br>`cli/tests/test_test_context_cli.py` | retained |
| M8-20 | `cli/src/safeyolo/mitm_addons/flow_recorder.py` | Flow recording, redaction, late attribution, and persistence failures | Native recorder preserves schema, scope, backpressure, and transaction rollback | `tests/test_flow_recorder.py`<br>`tests/test_flow_writer.py`<br>`tests/test_flow_store.py` | retained |
| M8-21 | `cli/src/safeyolo/mitm_addons/request_logger.py` | Structured request/response events and quiet-host behavior | Native event writer preserves correlation, decision attribution, ordering, and failure isolation | `tests/test_request_logger.py`<br>`tests/test_audit_schema.py`<br>`tests/test_audit_writer.py` | retained |
| M8-22 | `cli/src/safeyolo/mitm_addons/ignored_host_logger.py` | Passthrough connection lifecycle evidence | Native passthrough recorder distinguishes tunnel metadata from inspected application evidence | `tests/test_ignored_host_logger.py` | retained |
| M8-23 | `cli/src/safeyolo/mitm_addons/metrics.py` | Domain counts, outcome rates, latency, JSON, and Prometheus reports | Native counters/renderers preserve actual outcomes and API availability under load | `tests/test_metrics.py` | retained |
| M8-24 | `cli/src/safeyolo/mitm_addons/traffic_scope.py` | Agent/test/intent/role scope combined with operator display filters | Native inspection scope preserves authorization boundaries and retained UI controls | `tests/test_traffic_scope.py`<br>`cli/tests/test_commands_traffic.py`<br>`cli/tests/test_traffic_master.py` | retained |
| M8-25 | `cli/src/safeyolo/mitm_addons/flow_pruner.py` | Bounded interactive view and WebSocket history pruning | Native retained-evidence limits preserve durable records and bounded display state | `tests/test_flow_pruner.py`<br>`cli/tests/test_websocket_console.py`<br>`cli/tests/test_websocket_body_filter.py` | retained |
| M8-26 | `cli/src/safeyolo/mitm_addons/admin_api.py` | Host-local policy, budget, approval, service, listener, and operator APIs | Native operator routes preserve authentication, transactional policy activation, and state rollback | `tests/test_admin_api.py`<br>`tests/test_policy_transaction_regressions.py`<br>`cli/tests/test_api.py` | retained |
| M8-27 | `cli/src/safeyolo/mitm_addons/probe_sink.py` | Reserved diagnostic probes and local success synthesis | Native probe path reports only reached steps and never sends reserved probes upstream | `tests/test_probe_sink.py`<br>`tests/test_trace_chain_regression.py`<br>`cli/tests/test_doctor_traced_probe.py` | retained |
| M8-28 | `cli/src/safeyolo/mitm_addons/transport_guard.py` | Reserved CONNECT containment, late probe fallback, and connection backstops | Native outbound boundary retains local classification and prevents handler failures from creating upstream effects | `tests/test_transport_guard.py`<br>`tests/test_agent_api.py`<br>`tests/test_probe_lifecycle.py` | retained |
| M8-29 | `pdp/` | Python policy client/schema package used by the default proxy, CLI, and wheel | Native policy replacement plus all remaining CLI consumers pass; wheel/import and Python comparator rollback remain green | `tests/test_pdp_client.py`<br>`cli/tests/test_runtime_identity.py`<br>`tests/proxy_migration` | retained |
| M8-30 | `pyproject.toml` | mitmproxy and Python runtime package declarations, including retained `pdp` packaging | Consumer search and frozen install prove no Python path is needed by the selected native runtime while Python rollback still installs and starts | `tests/test_install_sh.py`<br>`cli/tests/test_cli_imports.py`<br>`tests/proxy_migration` | retained |
| M8-31 | `uv.lock` | Reproducible Python comparator and rollback dependency graph | Replacement environment is attested and comparator jobs remain reproducible before dependency removal | `tests/test_install_sh.py`<br>`tests/proxy_migration` | retained |

Rows M8-14 and M8-29 intentionally include OAuth/catalog, installed rollback,
and policy package consumers. Those requirements are not inferred from the
single bounded service-authorization workflow; they remain open until their
own writer and restart evidence exists.

## Current disposition

The accepted #640 preparation candidate proves locked Rust artifact
installation and explicit native launch while retaining the Python default and
rollback. This ledger records the next authorized increment: make each later
deletion reviewable against a concrete path and affected test set. It does not
authorize a default switch, a Python dependency deletion, or a comparator-job
change. A future deletion commit must update this ledger and its guard test in
the same candidate, retaining a readable rollback entry for every removed
owner.
