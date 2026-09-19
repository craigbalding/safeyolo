# Rust proxy capability inventory

This inventory supports [issue #620](https://github.com/craigbalding/safeyolo/issues/620).
The source baseline is `4116c7ee3d44c623e9d89ae60c14ce671d0f295d` on
`master`, inspected on 15 September 2026. Implementation starts on
`feat/rust-proxy-620`. The baseline lockfile selects mitmproxy 12.2.3.

**Status: M1 and the smallest M2 slice independently accepted at `c2afb9cf`; later policy, transport and state work continues.**
A named test below means an existing executable check was located. It does not mean the test ran,
passed, covered the production chain, or passed against Rust. Run manifests
must identify the source commit, backend, platform, dependency versions, exact
test selection and results. Future checks are marked **required**. No production
deletion is authorized by the inventory alone. Acceptance applies only to the reviewed revision and scope.

The Rust development slice covers trusted Unix domain socket (UDS) ingress,
HTTP and explicitly selected native network policy. The temporary Python network
policy adapter remains an explicit development option. An optional CA file enables
a development HTTPS path. Approval and service-contract modules are tested
separately and remain inactive in transport while their state contracts are implemented.
Unsupported internal APIs return a local error. That response proves
containment only; it does not establish API parity or a healthy inspection
pipeline. The production Python proxy remains necessary until the retained
contracts have replacement evidence.

The tables use these abbreviations: application programming interface (API),
command-line interface (CLI), Transport Layer Security (TLS), certificate
authority (CA), policy decision point (PDP), Server-Sent Events (SSE),
WebSocket (WS), and WebSocket over TLS (WSS). TLS server name indication is
abbreviated SNI.

## Authority and outstanding work

Issue #638's complete state reader/writer inventory and rollback sequence are
maintained in [state compatibility](state-compatibility.md). It records the
selected prior Python comparator, durable and ephemeral state families, and
the writer-owner dependencies that must be present before rollback is claimed.

The issue, [security model](../SECURITY.md), observable behavior and documented
public contracts establish the retained outcomes. The tables describe current
behavior unless they explicitly identify a discrepancy. Replacement paths name
responsibilities, not a required Rust module or callback hierarchy. Unless a
row says otherwise, its intended behavior change is **none**.

### First-release traffic scope

The operator narrowed traffic tooling to a read-only terminal inspector on
16 September 2026. For the first Rust release, this scope supersedes the broader
traffic viewing and manipulation obligations in issue #620. The source inventory
below still records those broader workflows; deferred features are not parity
claims or first-release acceptance requirements.

Retain live flow browsing, shared scope and supported filters, HTTP headers and
body details, WebSocket transcripts, and selected-flow `raw`, `raw_request`,
`raw_response`, `curl`, `httpie`, `har` and `zhar` exports. Read-only means the
inspector does not edit, replay, pause, resume or kill traffic. Display selection
can change, and exports can write local files. Generated commands remain text.

Defer flow-dump save/load, historical dump migration, HAR import, all-flow HAR
archives and continuous-save lifecycle, a web inspector, and traffic editing,
replay or interactive interception. Further mitmproxy filter-language and
display/export charset parity are also deferred. Existing supported operations
must remain correct, and unsupported representations must remain explicit.

The reduction applies only to traffic tooling. Forwarding, security inspection,
policy and credentials, authorized evidence access and retention, platform
validation, rollback and removal of the old proxy retain their requirements.
Shared matching or decoding needed by those paths is not deferred by this scope.

Local refs include proxy-related branches such as
`origin/feat/connect-policy-598` (`c19c0dc5`),
`origin/feat/connect-trace-evidence-598-599` (`2a4dc17e`),
`origin/agent/complete-flow-context` (`c0d384c1`),
`origin/fix/proxy-retained-bytes` (`4aec9006`), and
`origin/forge/issue-49-websocket-inspection` (`5a8dadc1`). Their responsibilities
are present in the inspected baseline. They are not ancestors of that baseline;
squash integration means that fact alone cannot establish outstanding work.
The integration owner's GitHub Connector search returned open pull requests
#574 (aggregate host resource protection) and #484 (demo lab), with no open
proxy, traffic or policy pull request returned. The local `gh` client lacked
authentication. Recheck open work before cutover; do not merge historical refs
solely because `git branch --no-merged` lists them.

## Production entry points and ordering

[proxy.py](../cli/src/safeyolo/proxy.py) starts the shared
[traffic master](../cli/src/safeyolo/traffic_master.py), which imports the UDS
mode before mitmproxy parses listener options. It registers the
[production chain](../cli/src/safeyolo/mitm_addons/__init__.py) once, at the
former script-loader position before later stock transformers. Production
Python source does not hot-reload. Policy and state have separate reload paths.
Only failure to import the normal Agent API handler is recoverable during
production registration; its independent containment guard must still load.
The production container shares one dispatcher exception boundary. An uncaught
child-hook exception skips later children for that hook; a later request or
response hook is dispatched separately. Standalone addon comparisons establish
only the behavior of the hooks they actually invoke.

Hook order is not simply table order: all `requestheaders` hooks run before
`request` hooks. CONNECT admission also runs independently of requests inside
an intercepted tunnel. Preserve these consequences:

1. Derive agent identity from the accepted host-controlled listener. Keep
   connection identity separate from request IDs and evidence ownership.
2. Recognize the Agent API before inspecting or logging its bearer token.
   Every failure path stays local. Recognize probes early, but report only
   inspection steps that actually ran.
3. Validate service tokens, routes, contract bindings and risky operations
   before credential injection. The current service gateway injects before
   network and credential checks; later checks see the authorized outbound
   representation. A rewrite needs both representations where required.
4. Apply network policy before delivery. Preserve independent admission for
   CONNECT and inner HTTP requests. Opening a socket and delivering a body
   are separate effects that tests must observe.
5. Inspect applicable content before delivery; record actual inspection and
   capture coverage. Streaming and configured passthrough have different
   coverage from buffered HTTP.
6. Attribute and record terminal results without turning a recorder failure
   into a false persistence claim.

## Full production chain

In this table, `addons/` means `cli/src/safeyolo/mitm_addons/`. Unqualified
test filenames are under `tests/`. Each listed addon file becomes a deletion
target only after its observable responsibility is replaced. Shared libraries
need a separate consumer check before deletion.

| Order and current source | Observable contract | Security or evidence property | Replacement and deletion condition | Existing checks |
|---|---|---|---|---|
| 1. `addons/pid_writer.py` | Atomically publish the configured PID readiness marker after listeners and required startup work are ready; remove on graceful exit. | An early process start is not readiness. Stale PID state must be reconciled. | Rust readiness/shutdown; then remove the lifecycle addon and Python bootstrap dependency. | `cli/tests/test_proxy.py`, `cli/tests/test_traffic_master.py` |
| 2. `addons/file_logging.py` | Configure file logging before production addons operate. | Preserve diagnostic availability and routine-log secret boundaries. | Rust logging initialization; remove addon. | `test_utils_logging.py`, `test_audit_writer.py` cover shared writers; dedicated startup equivalence required. |
| 3. `addons/memory_monitor.py` | Track active connections and WebSocket sessions; emit periodic process-memory and connection statistics. | Report actual measurements; reclaim per-connection state. | Rust process/connection counters; remove addon. | `test_memory_monitor.py` |
| 4. `addons/admin_shield.py` | Block agent proxy requests and CONNECT attempts to protected host-local management endpoints; guard connection setup too. | Agents cannot reach operator management through proxy egress. Preserve configured protected ports. | Early route validation plus the common egress boundary; remove addon. | `test_admin_shield.py` |
| 5. `addons/agent_api.py` | Serve authenticated reserved-host requests, including scoped evidence, policy queries, service access, declared test context, desktop presentation and coordination. | Shared bearer authentication does not identify the agent; sensitive operations also require trusted ingress identity. | Rust local routes with existing response contracts and state access; remove handler only when consumers pass. | `test_agent_api.py`, `test_agent_api_coord.py`, `test_agent_token.py` |
| 6. `addons/agent_api_guard.py` | If the normal handler is absent, disabled, import-failed or unhandled, synthesize a local diagnostic failure before downstream addons. | Internal bearer tokens and queries do not enter ordinary inspection/logging or external resolution. | Structurally local dispatch independent of route success; remove guard after fault tests pass. | `test_agent_api.py`, `test_imports.py`, `test_transport_guard.py` |
| 7. `addons/loop_guard.py` | Match this instance's RFC Via pseudonym and return 508 on a loop; otherwise append the pseudonym. | Nested legitimate proxies remain distinct; a loop does not recurse indefinitely. | HTTP ingress/egress header handling; remove addon. | `test_loop_guard.py`, `cli/tests/test_proxy.py` |
| 8. `addons/request_id.py` | Generate request IDs; consume trace opt-in; strip spoofed internal/hop headers; return correlation IDs; relate CONNECT admission and inner requests. | Client-supplied correlation values cannot impersonate trusted observations. | Typed connection/request correlation and header handling; remove addon. | `test_request_id.py`, `test_connect_policy.py`, `test_trace_wire_vocabulary.py` |
| 9. `addons/operator_provenance.py` | Observe duplicate, edit, replay, kill, resume and revert actions in the shared traffic view; audit source/resulting flow relationships. | Separate trusted operator initiation, original evidence ownership and transport identity. | Explicit operator operations and provenance; remove View observers after retained workflows pass. | `test_operator_provenance.py`, `test_agent_identity_resolution.py` |
| 10. `addons/service_discovery.py` | Read the mtime-cached agent map and stamp resolved attribution for HTTP and CONNECT. | UDS identity is authoritative; conflicting trusted sources fail closed. Cached metadata is not a new identity source. | Listener-owned identity and compatible external attribution fields; remove IP lookup from the Rust path. | `test_service_discovery_file.py`, `test_agent_identity_resolution.py` |
| 11. `addons/sse_streaming.py` | Stream `text/event-stream` and `application/x-ndjson`; stream JSON when explicitly configured; honor global/domain disablement. | Response-body streaming has an inspection/capture limitation. See discrepancy D2. | Incremental HTTP bodies with explicit coverage; remove callback. | `test_sse_streaming.py` checks hooks; wire timing required. |
| 12. `addons/policy_engine.py` | Configure and stop the global PolicyClient; actual policy lives in `policy/`, `pdp/` and shared caches. | Preserve a coherent active policy and failure behavior. | Temporary network-only adapter in M2; Rust policy/state in M3; remove configurator and adapter when no longer used. | `test_pdp_client.py`, `test_policy_engine.py`, `test_policy_loader.py` |
| 13. `addons/service_gateway.py` | Bind `sgw_` tokens to agent/service/capability; validate routes and contracts; obtain risk grants; inject authorized vault credentials; refresh OAuth credentials; consume applicable grants after responses. | A token cannot move to another agent, service, route or unsupported transport. Injected secrets must not appear in agent-readable evidence. | Rust service decisions and credential lifecycle; remove addon after route/injection/state tests pass. | `test_service_gateway.py`, `test_contract_enforcement.py`, `test_oauth2_flow.py`, `test_service_loader.py` |
| 14. `addons/network_guard.py` | Evaluate HTTP and CONNECT host/agent/port policy; map deny to 403, prompt to 428, exhausted budget to 429; preserve warn/block and homoglyph configuration. | No cross-agent/port approval leakage; missing or erroneous PDP fails closed. | Rust policy call before outbound effects; remove addon after decision/effect comparison. | `test_network_guard.py`, `test_connect_policy.py`, `test_agent_scoped_egress.py`, `test_destination_ports.py` |
| 15. `addons/circuit_breaker.py` | Maintain closed/open/half-open circuits, backoff, configured thresholds, persistence, reset and force-open operations; open circuits return 503. | Preserve configured fail-fast behavior and recovery without inventing lower limits. | Rust circuit state and API controls; remove addon after restart/reload checks. | `test_circuit_breaker.py` |
| 16. `addons/credential_guard.py` | Detect HTTP request-header credentials, evaluate destination-first permissions and budgets, and return configured block/warn outcomes. | Native H1 request-head and H2-inside-owned-TLS request-head integration run after network/circuit admission and before observation/body/dial; policy events use keyed fingerprints and identity conflicts fail closed. Bodies and WebSockets belong to the pattern scanner. | Native header detection/selection and policy evaluation are active for `policy_file`; malformed header bytes cross a reversible private source-text adapter and controlled H1/H2 wires prove matching warn/block plus nonmatching raw forwarding. Body/query scanning remains outside this adapter. D33 broader regex grammar and uncovered Unicode properties/casefold behavior, streaming/unsupported HTTP text and full production-chain integration remain open; the finite Python Unicode name and nesting domains are pinned in scanner tests/data. | `test_credential_guard.py`, `test_credential_catalog.py`, `test_policy_budget_contract.py`, `credential_http.rs`, `http::traffic::tests::ordinary_h2_inside_owned_tls_logs_inner_exchange_only` |
| 17. `addons/pattern_scanner.py` | Apply ordered URL/header/body rules and built-in sets; scan raw and once-decoded bounded URLs without rewriting them; inspect complete text/binary WebSocket messages in each direction. | Block/log modes and directional overrides remain; WebSocket inspection errors drop the message with content-free evidence. | Native HTTP request/response scanner calls use the parser-ordered byte adapter and existing content/text decoders; message-aware WS/WSS relay remains active. | `test_pattern_scanner.py`, `test_shipped_security_config.py`; compressed/fragmented wire cases required. |
| 18. `addons/test_context.py` | Parse/remove explicit test-context headers; enforce declared target rules; inherit valid agent/source-bound declarations with TTL; explicit valid headers win. | Malformed explicit context cannot borrow a declaration; cross-agent declarations cannot leak. | Rust context parsing, declaration state and evidence scope; remove addon. | `test_test_context.py`, `test_test_context_contract.py`, `cli/tests/test_test_context_cli.py` |
| 19. `addons/flow_recorder.py` | Record completed, blocked and failed test-context HTTP flows to SQLite through `core/flow_writer.py`; exclude probes/internal API and unresolved or conflicting owners. | Redact the injected gateway header; quarantine late identity changes; expose write/backpressure failures. | Rust recorder using retained schema and scope; remove addon after persistence/access checks. | `test_flow_recorder.py`, `test_flow_writer.py`, `test_flow_store.py` |
| 20. `addons/request_logger.py` | Emit structured request/response events, correlation and decision attribution; honor quiet-host configuration. | Logs are separate from authorized raw traffic evidence. Quiet behavior must not silently change. | Rust JSON Lines (JSONL) events; remove addon after consumer comparisons. | `test_request_logger.py`, `test_audit_schema.py`, `test_audit_writer.py` |
| 21. `addons/ignored_host_logger.py` | Emit connection lifecycle evidence for configured traffic that bypasses inspection. | Tunnel metadata must not claim observed HTTP bodies or a verified application protocol. | Tunnel/passthrough recorder; remove addon. | `test_ignored_host_logger.py` |
| 22. `addons/metrics.py` | Collect domain counts, success/error/block rates and latency; expose JSON and Prometheus renderings. | Metrics must represent actual outcomes and retain API availability under load. | Rust counters/renderers; remove addon. | `test_metrics.py` |
| 23. `addons/traffic_scope.py` | Combine pinned agent/unattributed/test/intent/role/expect scope with the operator's editable filter; expose facets and selection controls. | A display scope is not agent evidence authorization. Operator scope changes remain available. | Retained console/web inspection interface and scope API; remove filter composition around mitmproxy View. | `test_traffic_scope.py`, `cli/tests/test_commands_traffic.py`, `cli/tests/test_traffic_master.py` |
| 24. `addons/flow_pruner.py` | Bound the canonical shared interactive view by configured flow count and retained-body bytes; trim open WS history; do not prune durable FlowStore records. | Keep inspection state distinct from retained display history; do not claim bounded message assembly from display pruning. | Explicit retained-evidence limits; remove View pruning. | `test_flow_pruner.py`, `cli/tests/test_websocket_console.py`, `cli/tests/test_websocket_body_filter.py` |
| 25. `addons/admin_api.py` | Serve host-local management, modes, policy mutations, budgets, approvals, agents, service bindings, traffic scope, listener changes and operator event integration. | Bearer-authenticated management except health; protected host binding; transactional policy activation. | Rust operator routes or narrow compatible state boundary without Python; remove handler after CLI contracts pass. | `test_admin_api.py`, `test_policy_transaction_regressions.py`, `cli/tests/test_api.py`, `cli/tests/test_command_centre_admin_api.py` |
| 26. `addons/probe_sink.py` | Mark reserved diagnostic probes early, run applicable security checks, then synthesize a local 200 if no prior response exists. | Probe success proves observed steps only; suppress probe FlowStore pollution. | Local diagnostic path with real step evidence; remove addon. | `test_probe_sink.py`, `test_trace_chain_regression.py`, `cli/tests/test_doctor_traced_probe.py` |
| 27. `addons/transport_guard.py` | Contain reserved API CONNECT; provide late probe fallback and pre-resolution connection backstops with diagnostic events. | Handler failure never turns a local destination into upstream DNS or a socket. | Local route classification plus authoritative outbound connection boundary; remove compensating hooks after failure tests. | `test_transport_guard.py`, `test_agent_api.py`, `test_probe_lifecycle.py` |

There are **27** entries in the canonical chain. Stock mitmproxy HTTP/TLS/WS
transport, ConsoleMaster, web application, replay/export commands and their
integration are additional production responsibilities; the chain alone does
not describe the product.

## Contracts outside the chain

Paths below are relative to `cli/src/safeyolo/` unless prefixed otherwise.

| Behavior and current implementation | Observable contract and security property | Replacement / deletion target | Existing tests and missing proof |
|---|---|---|---|
| UDS ingress: `proxy_modes/unix_listener.py`, `sockets.py`, `proxy.py::_initial_mode_specs`, `sync_proxy_modes` | Each host-controlled private socket directory binds one agent. Parent-proxy mode is cloned per connection to avoid identity sharing. Live mode updates add/remove listeners; filesystem isolation belongs to the host ingress setup. | Rust listeners carry immutable agent identity. Delete `_PeeredStreamWriter`, synthetic-IP transport accommodation and mitmproxy mode registration only after supported bridges pass. Keep host/guest bridges. | `test_unix_listener.py`, `cli/tests/test_sockets.py`, `cli/tests/uds-networking/test_multi_agent_attribution.sh`; real two-agent UDS, restart and live-update tests required against Rust. |
| HTTP and parent egress: `proxy_modes/unix_listener.py`, `proxy.py::resolve_upstream_proxy` | HTTP forward proxy; HTTP(S) parent configured by environment then persistent config; reject authenticated parent URLs and URL path/query/fragment. Keep byte semantics, duplicate headers/query values, connection reuse and correct authority/port. | Hyper forwarding through one authorized dial path; delete native upstream-mode plumbing. | `test_http_integration.py`, `test_connect_live.py`, `cli/tests/test_proxy.py`; DNS/socket side-effect and real parent-hop assertions required. |
| TLS interception and trust: `proxy.py::_ensure_certs`, `_merge_system_cas_into_certifi`, `_build_combined_ca_bundle`, `resolve_upstream_ca_cert`; mitmproxy TLS | Reuse existing CA; validate upstream hostname/chain; combine configured extra roots with ordinary roots. Keep supported HTTP/2 and Application-Layer Protocol Negotiation (ALPN). | rustls/rcgen TLS path; delete CA-generation subprocess and mitmproxy TLS option plumbing after continuity tests. | `cli/tests/test_upstream_ca.py`, `cli/tests/test_proxy.py`, `test_http2_validation.py`, `tests/blackbox/host/proxy/test_upstream_cert_validation.py`; live CA rollback, private root, negative certificate and authority matrix required. |
| TLS passthrough: `ignore_hosts.py`, `commands/proxy.py` | Operator exact hostname/IPv4 endpoint entries and live sync; built-in `api.asterfold.ai:7000`; configured IPv4 CIDR environment exceptions. Current exact-host surface rejects regex/wildcards, IPv6 literals and trailing dots. Preserve existing validation; do not infer a ban on private destinations. | Explicit authorized passthrough route; delete mitmproxy regex compilation after matching/evidence tests. | `cli/tests/test_ignore_hosts.py`, `test_ignored_host_logger.py`, `test_connect_matrix_live.py`. |
| Opaque CONNECT and Secure Shell (SSH) | Destination/port admission precedes bytes; configured raw routes carry opaque traffic. A port or banner does not authenticate SSH. The issue requires server-first bytes, full duplex, half-close and real SSH through supported ingress. | Rust duplex tunnel and lifecycle evidence; delete framework tunnel hooks after real-client proof. | `test_connect_live.py` tests a client-first raw exchange; `test_connect_matrix_live.py` tests CONNECT combinations. These are not real SSH/half-close acceptance. |
| Policy: `policy/{toml_normalize,compiler,loader,engine,models,budget_tracker}.py`, `pdp/{client,core,schemas}.py`, `core/config_cache.py` | Preserve TOML/YAML vocabulary, baseline/task merging, lists, agent-scoped precedence before global rules, exact ports, credential and network approvals, expiry, generic cell rate algorithm (GCRA) budgets, config caches and reload transactions. Read-only policy lookups must not consume request budgets. | One Rust policy representation and explicit state effects. Delete duplicate Python policy request/decision representations only after proxy and remaining CLI consumers are accounted for. | `test_toml_policy_engine.py`, `test_toml_policy_loader.py`, `test_policy_compiler.py`, `test_policy_chaos.py`, `test_budget_tracker.py`, `test_policy_transaction_regressions.py`, `test_agent_egress_posture.py`. |
| Credential/service state: `core/{vault,service_loader,service_paths}.py`, `services/`, `policy/compiler.py`, `commands/vault.py` | Retain service-source precedence, authoritative registry snapshots, active token/binding/grant behavior and vault material; do not require credential re-entry. Vault is 16-byte salt followed by Fernet-encrypted YAML, using PBKDF2-HMAC-SHA256 with 480,000 iterations. | Rust-compatible vault and registry/state access. Remove proxy dependence on Python crypto/YAML only after round-trip/rollback tests; CLI may retain libraries. | `test_vault.py`, `test_service_loader.py`, `test_contract_enforcement.py`, `cli/tests/test_vault_cli.py`, `cli/tests/test_service_sources.py`; cross-runtime encrypted round-trip required. The bounded #638 service authorization transition is `proxy/tests/gateway_contract_workflow.rs::selected_python_native_python_service_authorization_rollback`. |
| Audit/trace/evidence: `core/{audit_schema,audit_writer,audit_stream,trace,flow_writer}.py`, `storage/flow_store.py` | Preserve request/connection relationships, evidence owner, transport identity, initiator, status/provenance, decision/approval/service details, body truncation and write failures. Existing SQLite stores remain readable. | Rust event and storage writers with existing consumers; remove proxy writers after schema/access/failure tests. | `test_audit_schema.py`, `test_trace.py`, `test_flow_store.py`, `test_flow_writer.py`, `test_trace_manifest.py`, `cli/tests/test_audit_stream.py`. |
| Interactive traffic: `traffic_master.py`, `traffic_session.py`, `commands/traffic.py`, `websocket_console.py`, `websocket_body_filter.py` | One persistent shared console/web view; attach/detach without stopping proxy; filtering, facets, request/response/WS detail, load/save/export, duplicate/edit/replay/intercept/resume/kill/revert. Web authentication and optional Tailnet publication remain operator workflows. | Retained inspection/operation interface, without requiring mitmweb internals. Delete ConsoleMaster/web glue and renderer patches only after equivalent outcomes are demonstrated. | `cli/tests/test_traffic_master.py`, `cli/tests/test_traffic_session.py`, `cli/tests/test_proxy_web.py`, `test_operator_provenance.py`; interactive export/replay and access-control acceptance required. |
| Lifecycle/configuration: `proxy.py`, `traffic_master.py`, `traffic_session.py`, `runtime_identity.py`, `config.py`, `commands/doctor.py` | Start/stop/restart, source identity, readiness, failure diagnostics, existing data/config paths, policy/list/service/vault refresh and listener synchronization remain usable. Python source reload requires restart. | Binary launcher and compatible lifecycle surfaces. Remove traffic-session process coupling only after CLI workflows and rollback pass. | `cli/tests/test_proxy.py`, `cli/tests/test_runtime_identity.py`, `cli/tests/test_start_safeyolo.py`, `cli/tests/test_doctor.py`; macOS and Linux cutover/rollback required. |

## Local API inventory

The route inventories come from the dispatch code, including parameterized
paths and non-read-only operations. An API replacement must preserve methods,
status/error semantics, scope and side effects used by current consumers.
Do not infer agent ownership from the shared bearer token or request fields.

### Agent API

The reserved hostname is `_safeyolo.proxy.internal`; requests remain local
regardless of method, authentication result or handler availability. The active
agent token is read from disk during authentication. CONNECT to the reserved
API is contained separately. Sources are `addons/agent_api.py`,
`core/internal_api.py`, `pdp/tokens.py` and the callees named below.

| Route family | Retained behavior and consumers |
|---|---|
| GET `/health`, `/status`, `/policy`, `/lookup`, `/budgets`, `/config`, `/explain`, `/trace`, `/memory`, `/agents`, `/circuits` | Self-service diagnostics and policy queries; `/lookup` accepts destination port; traces are requester-scoped. Health distinguishes handler status. Existing skills, doctor and API clients consume these responses. |
| `/api/flows/search`; POST `/api/flows/endpoints`, `/facets`, `/body-search`, `/diff`, `/request-body-search` | The short suffixes are relative to `/api/flows`. Search/filter/facets/diff are scoped to the trusted caller. FlowStore uses SQLite and body search indexes. |
| GET `/api/flows/{id}`, `/api/flows/{id}/request-body`, `/api/flows/{id}/response-body`; POST `/api/flows/{id}/tag`; DELETE `/api/flows/{id}/tag/{name}` | Ownership checked before returning details/body or changing tags. Unauthorized direct object reads return 404. Body responses include base64 and applicable text. |
| GET/POST/DELETE `/api/test-context/current` | Agent/source-bound declared context, validation, precedence and TTL in `addons/test_context.py`. |
| GET `/gateway/services`; POST `/gateway/request-access`, `/gateway/submit-binding` | Bound service discovery, risk approval and contract-binding lifecycle. |
| POST `/desktop/present` | Caller-authorized desktop presentation through `desktop_presenter.py`; preserve the existing host-side operation boundary. |
| POST `/plumb/request-chat`; GET `/plumb/conversations`; `/plumb/conversations/{id}/messages` and `/leave` | Approved legacy collaboration through `core/plumb_service.py`, with scoped participants and asynchronous waits. |
| `/api/coord/rooms/{room}/{join,send,messages,wait,members,brief,state,declarations}`; `/api/coord/attention/wait`; `/api/coord/attention/{id}/object` | Existing `coord/api.py`, store and NATS operations. Preserve trusted sender attribution, membership, attention resolution and ambiguous-publish/error semantics. A proxy rewrite does not remove coordination workflows. |

### Operator API and events

The host-local admin listener uses bearer authentication except GET `/health`.
Proxy ingress blocks agent access independently of token authentication.
Sources are `addons/admin_api.py`, `api.py`, `core/operator_event_server.py`
and `traffic_master.py`. Preserve configured binding/publication and event
access; do not substitute an agent-accessible management listener.

| Methods | Routes |
|---|---|
| GET | `/health`, `/stats`, `/debug/addons`, `/modes`, `/plugins/{name}/mode`, `/admin/policy/baseline`, `/admin/policy/task/{id}`, `/admin/budgets`, `/admin/traffic/scope`, `/admin/runtime-identity`, `/admin/instance`, `/admin/approvals`, `/admin/agents`, `/admin/gateway/grants`, `/admin/plumb/pending`, `/admin/plumb/conversations` |
| POST | `/admin/policy/validate`, `/admin/policy/baseline/approve`, `/admin/policy/baseline/deny`, `/admin/policy/task/{id}/activate`, `/admin/policy/host/{rate,allow,deny,bypass}`, `/admin/circuit-breaker/reset`, `/admin/budgets/reset`, `/admin/gateway/grant`, `/admin/gateway/contract-binding`, `/admin/plumb/{approve,deny,close}`, `/admin/agents/{agent}/services`, `/admin/agents/{agent}/desktop/present` |
| PUT | `/modes`, `/plugins/{name}/mode`, `/admin/policy/baseline`, `/admin/policy/task/{id}`, `/admin/proxy/mode`, `/admin/proxy/ignore-hosts`, `/admin/proxy/web-tailnet`, `/admin/traffic/scope` |
| DELETE | `/admin/policy/task/{id}`, `/admin/gateway/grants/{id}`, `/admin/agents/{agent}/services/{service}` |

The authenticated WebSocket `/admin/events` streams selected operator audit
events through `core/operator_event_server.py`. The web application's traffic
routes expose stock flow operations through the shared master. Compatibility
concerns the retained user workflows, not every undocumented mitmproxy endpoint.

The following is the compact status map for the retained operator operations.
It records the current native route owner and the remaining owner when Rust
does not yet implement an operation; a route marked implemented still needs
the issue's independent consumer and effect proof before its acceptance box is
checked.

| Operation | Status | Owner or evidence |
|---|---|---|
| GET `/health`, `/stats`, `/modes`, `/plugins/{name}/mode` | Implemented | Native `admin_api`; the retained `AdminAPI` mode workflow is covered by `tests/proxy_migration/test_operator_modes_and_listeners.py`. |
| GET `/admin/runtime-identity`, `/admin/instance`, `/admin/approvals`, `/admin/agents` | Implemented | Native `admin_api`; state and audit owners, with the native wire and retained approval workflows exercising identity, approval, and agent reads. |
| GET `/admin/policy/baseline`, `/admin/policy/task/{id}`, `/admin/budgets` | Implemented | Native policy, task registry and budget owners. |
| GET/PUT `/admin/traffic/scope` | Implemented | Native traffic-scope owner; traffic effect proof remains with the traffic lane. |
| GET `/admin/gateway/grants`, `/admin/plumb/pending`, `/admin/plumb/conversations` | Implemented | Native #625 gateway store and retained plumb owner. |
| POST `/admin/policy/validate`, `/admin/policy/baseline/{approve,deny}` | Implemented | Native policy file and canonical audit writer; approval and denial consumers are covered by `tests/proxy_migration/test_operator_consumer_approval.py`. |
| POST `/admin/policy/host/{allow,deny,rate,bypass}`, `/admin/budgets/reset`, `/admin/circuit-breaker/reset` | Implemented | Native approval, budget and circuit owners. |
| POST `/admin/gateway/{grant,contract-binding}` and DELETE `/admin/gateway/grants/{id}` | Implemented | Native #625 grant/binding store; resolved-key audit wiring is retained here. |
| POST `/admin/plumb/{approve,deny,close}` | Implemented | Native retained plumb owner; desktop/coordination host workflows remain separate. |
| POST `/admin/agents/{agent}/services` | Implemented | Native #624 service persistence owner. |
| DELETE `/admin/agents/{agent}/services/{service}` | Implemented | Native service mutation owner removes the binding, removes an empty `services` table, emits the canonical revocation audit, and lets the policy watcher publish the complete replacement snapshot; focused observer/control proof is in #627. |
| POST `/admin/agents/{agent}/desktop/present` and retained agent collaboration routes | Delegated | Retained-agent-workflows implementation and host boundary; no native fake endpoint. |
| PUT `/modes`, `/plugins/{name}/mode`, `/admin/policy/baseline`, `/admin/policy/task/{id}` | Implemented | Native state owners; task PUT remains registration-only until explicit activation. |
| POST `/admin/policy/task/{id}/activate` | Implemented | Native task activation publishes enforcement, `/config` and hash together; retained `AdminAPI` and live listener workflow prove the boundary. |
| DELETE `/admin/policy/task/{id}` | Implemented | Native task clear removes the registered document and selected overlay; retained `AdminAPI` and live listener workflow prove baseline restoration. |
| PUT `/admin/proxy/mode` | Retained consumer wiring | Rust listener updates use `rust_proxy.sync_listeners`: the existing agent lifecycle consumer edits only managed entries, sends SIGHUP, and waits for the exact readiness reload marker. Direct proxy-mode HTTP remains a Python-only route; the live mode consumer is covered by `tests/proxy_migration/test_operator_modes_and_listeners.py`. |
| PUT `/admin/proxy/ignore-hosts` | Delegated | The existing CLI normalizes entries and the live consumer publication is covered by `tests/proxy_migration/test_operator_modes_and_listeners.py`; passthrough matching, reload effect and removal remain owned by #631. |
| PUT `/admin/proxy/web-tailnet` and traffic flow/editor routes | Deferred | Traffic web inspector and editing are outside the first-release traffic scope. |
| Add/remove listeners through retained operator consumers | Implemented | `sync_proxy_modes` replaces only conventional managed sockets, preserves custom listeners, signals the native reload owner and confirms the resulting socket set. `tests/proxy_migration/test_operator_modes_and_listeners.py` adds Bob, removes Alice, and sends requests through the resulting sockets. |
| GET `/admin/events` | Implemented | Startup-owned native WebSocket stream; authenticated selected audit events, request/agent correlation, reconnect offset handling, and owned shutdown are covered by `proxy/tests/operator_controls.rs`; its stalled-client case observes bounded write-timeout closure before proving enforcement and origin isolation. |
| GET `/debug/addons` | Deferred | Diagnostic addon inventory is not a retained first-release workflow. |

The focused native facade and retained-client workflows are grouped by the
consumer that crosses the boundary. `proxy/tests/operator_controls.rs`
exercises authenticated native reads, policy and mode mutations, audit event
streaming, malformed mutation handling, and audit-sink failures over the real
admin listener. `tests/proxy_migration/test_operator_consumer_approval.py`
uses the existing `AdminAPI` and approval helpers for scoped network and
credential decisions. `tests/proxy_migration/test_operator_task_api.py`
uses the same client for task registration, activation, clearing, and reload
ownership. `tests/proxy_migration/test_operator_modes_and_listeners.py`
uses the existing mode and listener consumers against live enforcement and
also verifies exact ignore-host publication and clearing. The #631 owner
retains passthrough matching and its reload/removal semantics.

## TLS and WebSocket library risks

These are source-backed compatibility findings, not library acceptance tests.
Dependency selection must record versions, licenses, minimum Rust version and
the TLS cryptography backend. Build/runtime checks on supported Linux and
macOS targets remain required.

### Existing CA material

SafeYolo delegates creation to mitmproxy in the configured `certs` directory.
The locked mitmproxy 12.2.3 implementation writes an unencrypted RSA private
key in TraditionalOpenSSL/PKCS#1 format followed by the certificate in
`mitmproxy-ca.pem`. The public `.pem` and `.cer` files contain the same PEM
certificate. The private `.p12` includes the key; `-ca-cert.p12` is public-only.
The loader also accepts multiple certificates in the PEM file. These facts
come from [mitmproxy 12.2.3 certificate-store source](https://raw.githubusercontent.com/mitmproxy/mitmproxy/v12.2.3/mitmproxy/certs.py).

The [rcgen 0.14.8 KeyPair documentation](https://docs.rs/rcgen/0.14.8/rcgen/struct.KeyPair.html)
says its `ring` PEM import accepts PKCS#8, while `aws_lc_rs` also accepts
PKCS#1 and SEC1. A direct `ring` import of the current default key is therefore
not a sufficient migration path. Support the existing encoding with a
compatible backend or verified in-memory conversion. Do not replace the CA
or rewrite the operator's key to conceal an import failure.

Required fixtures include a generated baseline RSA CA, custom supported key
encodings, a chain, mismatched key/certificate, malformed files and incomplete
stores. Check leaf DNS/IP subject alternative names, CA constraints and key
identifiers. Verify the same root fingerprint before Rust startup, after
restart and after rollback. Preserve upstream trust configuration separately
from the interception CA. A successful CA parse proves none of these runtime
properties by itself.

### Compressed and fragmented WebSockets

The [locked mitmproxy WebSocket layer](https://raw.githubusercontent.com/mitmproxy/mitmproxy/v12.2.3/mitmproxy/proxy/layers/websocket.py)
uses wsproto per-message deflate when negotiated. It reassembles complete
messages before the pattern hook and forwards an allowed message afterwards.
The scanner treats text as strict UTF-8 and binary as Latin-1 for byte-stable
matching. It drops inspection errors and records direction, rule/type and
failure metadata without content.

The [tungstenite project](https://github.com/snapview/tungstenite-rs) currently
states that it does not support `permessage-deflate`. Choosing
`tokio-tungstenite` therefore does not prove compression compatibility. Never
forward or advertise that extension while inspecting compressed bytes as
plaintext. If the implementation declines the extension, record the transport
change and test retained clients and servers. Compression-dependent workflows
remain a gap until proven or deliberately resolved.

The native [WebSocket module](../proxy/src/websocket.rs) uses
tungstenite 0.30.0's frame-header and handshake helpers with flate2 1.1.10
and its explicit zlib-rs 0.6.7 backend. Its own message assembly retains
compression state across control frames and spills payloads and fragment indexes
to private anonymous files after 64 KiB. This threshold changes storage, not
accepted message size. memmap2 0.9.11 provides borrowed complete text for
inspection. Mapped pages and regex working memory still need measured bounds;
the spool does not establish a hard process-memory limit.

Native tests compare 84 messages in both directions with actual Python wsproto
across window sizes 9–15 and context-takeover modes. They also cover independent
outgoing dictionaries after a dropped message, malformed frames, subprotocols,
extension negotiation and RFC 7692 final-block examples. Receive failures return
content-free categories for protocol errors (1002), invalid payloads (1007),
transport loss and local storage failure (1011). Thirteen malformed-frame cases
match the Python close-code oracle. Storage failure cannot yield a partial
message.

The development [relay](../proxy/src/websocket_relay.rs) connects this codec to
HTTP/1 upgrades, including intercepted HTTPS. It retains listener identity and
the admitted destination, applies current scanner rules to each complete
message, and preserves separate outgoing compression dictionaries after drops.
An optional `inspection` object in the development configuration names the
existing policy file and request/response blocking flags. A successful reload
updates existing sessions; an invalid candidate retains the previous runtime.
This does not replace the production configuration or evidence interfaces.

The paired [wire fixture](../tests/proxy_migration/test_websocket_contract.py)
passed 104 Rust cases on Linux aarch64. Python passed 84 cases and reproduced
16 strict expected failures for D32. The matrix includes WS/WSS, text/binary,
compression and control frames, directional blocking, denied handshakes with
zero origin contact, reload retention, data followed immediately by Close,
protocol-error codes and shutdown. Four native lifecycle cases also verify
pending-message spool removal and cancellation of an executing VM search after
peer Close or shutdown. The old fixture uses actual Python addons
and policy code in a focused chain. These owner-run comparisons establish that
development path; they do not establish complete production-chain acceptance.

On closure, writers drain admitted messages before sending Close. Scanner VM
cancellation is per session, and the relay waits for running inspection before
reporting a clean drain. The existing ten-second closure grace can expire when
an opaque regex-library search does not return. Such delegated searches remain
a cancellation limitation. Content-free development events report message and
session outcomes; production traffic capture, evidence access and storage
failure integration still require work.

tungstenite, flate2 and memmap2 declare MIT or Apache-2.0 licenses; zlib-rs
declares Zlib. The scanner candidate uses MIT-licensed fancy-regex 0.19.2.
Its remaining Python-regex compatibility gaps are described in D33.

Required wire fixtures cover fragmentation across pattern boundaries, text
and binary directions, masked frames, subprotocols, compressed messages,
control frames between fragments, close/error handling and inspection faults.
Distinguish maximum frame/message assembly from retained-view limits. Measure
bounded memory under long-lived traffic and large fragmented messages; do not
silently reduce accepted message sizes to a library default.

## Discrepancies and unproven claims

| ID | Source-backed finding | Classification and required resolution |
|---|---|---|
| D1 | The baseline TLS document labels `mitmproxy-ca-cert.cer` as DER and describes `mitmproxy-ca.pem` only as the private key. The locked dependency writes PEM in `.cer`, and key plus certificate in `-ca.pem`. | Documentation corrected to the actual formats. Rust tests import a real mitmproxy RSA CA, issue a verified leaf, reload it in Rust and then reload it in mitmproxy. The opt-in `selected_python_native_python_native_ca_trust_transition` also completes native TLS handshakes before and after the old-Python reload, retaining root/key hashes and modes. The CA file remains byte-identical; PKCS#1 wrapping happens only in memory. |
| D2 | Production sets `stream_large_bodies=10m`; the SSE addon sets response streaming. Its docstring says request bodies remain fully inspected, but large-body transport streaming and scanner `get_text()` require separate examination. Buffered-body hooks cannot establish inspection of bytes already forwarded. | Coverage discrepancy requiring live request/response tests. Preserve configured streaming behavior and report actual coverage. A concrete bypass of an applicable blocking rule requires a regression and repair; do not claim full inspection from hook execution. |
| D3 | Raw CONNECT tests use a client-first `raw-hello` exchange with `--tcp-hosts`; HTTPS/WSS live fixtures set `ssl_insecure=true`. | Test coverage limits. These fixtures prove neither real SSH/server-first/half-close nor upstream certificate validation. Keep separate real-client and invalid-certificate tests. |
| D4 | CONNECT authority, inner Host/HTTP/2 authority, SNI and actual outbound target are represented separately by the framework. Existing admission tests do not establish the full mismatch matrix. | Unresolved authority-boundary coverage. Test each value independently. A changed inner authority must not inherit permission for another destination. Never fall back to opaque transport after parser/TLS failure. |
| D5 | Routine credential events use fingerprints; FlowStore retains request/response bodies and ordinary headers, redacting the gateway-injected header; the trusted operator's interactive view is broader. `SECURITY.md` uses an unqualified statement that raw detected credentials are never stored/logged. | Evidence-scope documentation discrepancy. Preserve authorized raw evidence and injected-secret protection; verify each surface with synthetic secrets. Do not implement global redaction as an assumed parity requirement. |
| D6 | Completed WS messages are inspected and retained/pruned, but the dependency assembles an incomplete message before the hook. | Memory/coverage limit requiring measurement. View pruning is not bounded transport assembly. Sol accepted the focused `afa279b1` regression: four sequential incomplete-fragment cancellations for both WS and WSS reclaimed all anonymous spools with zero origin frames. RSS/allocator retention, concurrent/compressed/completed workloads and large-pattern scans remain open before claiming a broader bound. |
| D7 | `flow_recorder.py` collapses query parameters into a dictionary for one evidence column, while the original URL remains available. | Representation limitation. Preserve outbound query order/duplicates and original URL evidence; do not compare only the lossy dictionary or normalize away signed-query behavior. |
| D8 | The default production command only explicitly selects lazy connections when sinkhole routing is enabled. The live denial fixtures vary eager/lazy for CONNECT, not every plain-HTTP security decision. | Side-effect coverage gap. Observe DNS and socket attempts independently for denied plain HTTP, CONNECT and malformed local requests. Do not equate an HTTP block response with zero egress. |
| D9 | Independent wire review found that the baseline's exact reserved-host matchers permit the DNS root-dot spelling, such as `_safeyolo.proxy.internal.`, to reach a configured parent with a bearer header. | Concrete containment defect. Rust now removes one DNS root dot only for reserved-name classification, before policy and at the shared egress boundary. It also refuses these names as configured parents. Original request bytes for other destinations are unchanged. The historical Python baseline retains the defect; its repair is tracked separately. |
| D10 | Hyper normalizes identical duplicate Content-Length fields and removes Content-Length when Transfer-Encoding controls framing. The old parser rejects those requests. Hyper rejects unequal duplicate lengths. The initial Rust slice also accepted duplicate Host fields. | Protocol difference requiring explicit wire tests. Rust rejects duplicate Host fields before policy or upstream contact. Do not equate normalization to a demonstrated smuggling flaw, or add a second HTTP parser solely to reproduce every rejection. Verify one unambiguous outbound framing and exact delivered bytes. |
| D11 | Independent review of `5b661dc9` sent 160 requests through the temporary serial Python adapter. At 8, 16 and 32 workers, 18, 10 and 62 requests returned unexpected 502 responses. The adapter socket backlog filled; no fail-open or cross-agent leak was observed. | Concrete availability defect. Repair `ffb189ca015a5e0074eb483675e818a18e49029e` serializes decision roundtrips with one async mutex shared across reload snapshots, without retrying policy decisions. The owner reports a passing 160-request, eight-worker regression for each backend. Independent recheck passed all 480 requests at 8/16/32 workers and 16 requests across reload. A subsequent client-disconnect crash in the adapter was repaired at `03437138` and independently rechecked with SIGSTOP/client cancellation/SIGCONT. The sustained Rust capture predates these repairs. |
| D12 | Full production SIGTERM at checkout `4586a127` exits with status zero and removes readiness, but leaves both agent UDS pathnames. Subsequent connects return `ECONNREFUSED`. `proxy.py::stop_proxy` describes socket-file removal. | Concrete cleanup discrepancy. `test_full_production_shutdown_removes_socket_files` records a strict expected failure. No live listener remains. Fixture-directory teardown removes the dead files; that teardown does not repair production shutdown. |
| D13 | Independent full-production CONNECT tests at `c2afb9cf` passed real SSH and generic server-first streams on arbitrary allowed ports, with and without an exact passthrough exemption. Both TCP half-close directions lose remaining bytes; direct controls pass. The dependency's HTTP tunnel layer deliberately converts half-closes to full closes. | Native CONNECT now supports opaque duplex streams and both half-close directions. Paired tests keep the two old failures explicit; real OpenSSH passes through both implementations with 1 MiB input and 512 KiB server-first output. No SSH port allowlist was added. The native extension still requires independent review. |
| D14 | The initial native policy parser accepted scalar `required`/`bypass` values that Python rejects, potentially allowing traffic with the network guard disabled. | Native schema repair requires arrays in these list-only fields and rejects malformed IAM tiers. Conditions that accept either a scalar or a list keep that syntax. Regression and Python-oracle checks accompany the repair; independent follow-up review remains required. |
| D15 | The Python expiry loader prunes only global hosts. An agent-scoped one-day denial remains active after its timestamp, including at reload. | Native load/reload and durable pruning honor expiry for agent hosts too. Tests explicitly identify this behavior change and verify agent/port scope and preserved reload budgets. There is no new clock-driven reload timer. |
| D16 | Contract enforcement compares raw query keys before decoding. `name=chosen&%6Eame=forbidden` passes a binding to `chosen`, while an origin receives both decoded values and can select `forbidden`. | Native contract enforcement rejects duplicate decoded keys as ambiguous encoding. A controlled origin proves the old bypass; differential tests identify the intentional rejection. Requests outside service contracts retain their query behavior. |
| D17 | Rust CONNECT metadata used the routing defaults `http` and `/`; production supplies an empty scheme and path. Slash-path conditions could therefore reverse CONNECT allow/deny decisions. | Repair `8413219` preserves authority-form metadata. Paired live tests prove both conditional allow and deny outcomes; the adapter validates the target form. After restoring production's eager CONNECT behavior, admission permits one target TCP contact and denial still permits none. |
| D18 | The initial native service YAML loader silently dropped merged binding constraints, allowing a forbidden value or an unbound operation. | Services now use the shared structural YAML frontend, including merge-list and explicit-key precedence. Native route-selection tests reject mismatched and unresolved values. Independent review confirmed the repair at `cc859353`. |
| D19 | The initial Rust HTTPS path canceled upgraded connections immediately at shutdown, truncating an active response that plain HTTP would drain. | Inner HTTP receives the listener shutdown signal and drains active responses under the ten-second transport shutdown grace. Idle TLS handshakes cancel promptly. Independent review at `cc859353` confirmed that a paused TLS response delivers its final bytes after shutdown begins. |
| D20 | Native JSON parsing rounded integers larger than `u64` to floating point. Different integer IDs could falsely satisfy a service `equals_var` binding. | JSON integers retain their exact decimal values; integer/float comparison uses the float's represented value. Strict body parsing also keeps authored private-number-marker objects as objects. The expanded contract oracle covers 2,218 outcomes, with only D16's 16 expected differences. Independent numeric and contract rechecks passed at `cc859353`. |
| D21 | Python can admit two risky requests using the same once grant before either receives a response. | Native grants reserve one request at a time, release on failure/cancellation, and consume after a successful response. A controlled Python oracle proves the old reuse; native concurrency and stale-lease tests enforce one reservation. Reservations remain process-local, without an exactly-once side-effect claim across persistence failure and restart. |
| D22 | Python tomlkit persists integers beyond TOML's signed 64-bit range exactly; toml_edit has only an i64 syntax node. | The native retained binding workflow masks out-of-range integer literals only while toml_edit edits the document, restores the original integer syntax before saving, and converts it back to an exact JSON number on load/reload. Focused grants and operator-route tests cover 2^63 and 2^64+1, structured values, exact persisted text, and rejection of a nested null without a second audit success. |
| D23 | Independent review at `cc859353` found that missing legacy grant IDs or creation times regenerate during each transaction. A held once reservation can disappear, allowing a second admission. Missing binding IDs also make revocation unstable. | The native store now persists generated defaults under the existing policy file lock before publishing the initial snapshot, and normalizes later legacy additions inside the transaction. Tests cover all combinations of missing grant fields, both TOML array forms, restart, consumption and rollback. The opt-in grants/bindings transition observes generated IDs in Python after native normalization, retains the legacy binding through the Python write, compares the legacy grant's creation/expiry/scope and both binding metadata sets across the Python write and fresh native reopen, and revokes the bindings in final native cleanup. Independent recheck passed at `d2f154b3`. |
| D24 | Rust's whitespace predicate omits four control characters that Python strips from host-list lines. A listed denial can therefore fall through to an allow rule. | The list reader now uses Python's whitespace set, including U+001C–U+001F. A 29-character denial matrix and live Python list-reload comparisons cover the repair. The independent 102-request recheck passed at `d2f154b3`. |
| D25 | The production HTTP/2 tunnel overwrites policy host/port with the admitted CONNECT destination while forwarding a changed inner `:authority`. A forbidden hostname or another port can inherit the tunnel's permission. | Rust pins the inner authority and any Host header to the admitted host/port. Paired tests retain the old bypass as two strict expected failures and verify no application request reaches either controlled origin after native rejection. The old stack sends a protocol error for Host disagreement; native returns 400. |
| D26 | Production TLS protocol negotiation depends on the origin. Rust negotiates HTTP/2 with a capable client before negotiating origin TLS and can translate that request to an HTTP/1 origin. | Paired tests verify delivered requests for HTTP/2-only and HTTP/1-only origins. The negotiation difference is explicit; no-ALPN traffic and cleartext UDS still use HTTP/1. Upstream protocol selection follows verified TLS negotiation, without fallback after a TLS or parser error. |
| D27 | Python's vault mutates live state before saving and can partially replace it during malformed reload. It also ignores an altered salt on live reload. | Native vault mutations and reload publish only a complete valid candidate, with encrypted-file rollback on activation failure. A changed salt requires unlock. Cross-runtime tests preserve existing encrypted data and no-TTL Fernet behavior. Independent writers still have no cross-process merge guarantee. |
| D28 | Independent full-production tests allow CONNECT but deny the inner GET. A complete HTTP request or TLS ClientHello stays inspected and returns 403. Sending a short first fragment can instead select raw TCP, delivering the same forbidden GET to the origin. One- or two-byte ClientHello fragments and several incomplete HTTP prefixes reproduce the bypass. | The native classifier retains undecidable prefixes across reads. Fragmented plaintext tests and paired TLS tests enforce the inner denial; the two old TLS cases remain strict expected failures. Classification and raw relay retain the production 600-second inactivity timeout, which closes rather than reclassifies. A method-like opaque prefix can remain undecided until a delimiter; an explicit passthrough entry can select uninspected transport for such an endpoint. |
| D29 | The dependency's ignore matcher considers the target, connected address, inner Host and TLS SNI. The native development path matches configured target entries and direct destination IPv4 ranges. | The existing CLI and native configuration boundary now normalize supported exact host forms (trimmed ASCII/IDNA2003 lowercase, explicit ports and deduplication). Exact-host/port, host-only address, builtin and constrained CIDR selection, original TLS certificates, canonical direct lifecycle events and removal at reload are covered by focused witnesses. A direct connection matched only by its resolved IPv4 peer now receives the same lifecycle owner after TCP succeeds, while the logical authority remains in the event. SNI/Host alias matching, parent-address exemption semantics and the remaining D29 matrix remain unresolved; this narrower development matcher is not full passthrough acceptance. |
| D30 | Independent review at `d2f154b3` found that native vault decoding rejects Python's accepted empty `credentials` mapping/string and floating-zero root values. A live reload therefore retains a credential that Python removes. | The decoder now accepts those empty representations and clears the active snapshot. A ten-case Python unlock/reload comparison also retains errors for null, numeric and nonempty invalid credential containers. Independent recheck passed at `682f622c`. |
| D31 | Independent review at `682f622c` found that both implementations classify any client prefix `SSH` as opaque. Valid HTTP methods such as `SSH`, `SSHGET` and `SSH-EXT` therefore bypass an explicit inner denial. | Native classification no longer treats three letters as a protocol exemption. Fragmented extension methods stay inspected. An identification line with a comment remains undecided until its first line finishes; HTTP request-line syntax takes precedence when ambiguous. Independent recheck passed at `06d7282c`, including 20 denied requests, 12 identification-line cases and real SSH. D35 records a separate whitespace finding. |
| D32 | Independent full-production WebSocket tests found that a control frame between compressed fragments resets the Python dependency's message compression flag. All 24 direct controls deliver exact bytes; eight proxy cases fail, covering Ping/Pong in both text/binary directions. Text closes with 1007; binary silently delivers incorrect bytes. | The native message reader keeps compression state until the data message finishes. Independent codec recheck at `19ff784e` passed all 24 wire cases, including exact re-encoding. The owner-run paired WS/WSS fixture now reproduces 16 old-proxy failures and passes every native counterpart. Complete native production-chain evidence remains required; this source defect is not a compatibility requirement. |
| D33 | fancy-regex does not reproduce all accepted Python regular expressions. Repairs cover scoped ASCII flags, octal escapes, Turkish-I literals, Python backreference comparisons and the finite Python 3.12 Unicode name/alias domain. Uncovered grammar differences remain explicit compatibility failures. Its original private one-million-entry stack limit also makes `(a\|aa)*\1$` fail on 1,000,100 `a` bytes where Python matches. The scanner's existing error rule then drops even a log-mode message. | A [pinned source patch](../proxy/vendor/fancy-regex/SAFEYOLO.md) removes that private cutoff with fallible VM growth and releases per-search buffers. Python/native log-mode matches now agree at 1,000,100, 4 MiB and 8 MiB. Generated Python 3.12 / Unicode 15 ranges pin `\w` and `\d`; 143,041 canonical scalar names and 473 verified scalar aliases lower `\N{...}`. Ordinary names and aliases are case-insensitive; algorithmic Hangul/CJK names require uppercase; named sequences and malformed/unknown names remain source-invalid, with invalid rules skipped individually. U+13460 and U+1E4F0 witnesses cover a newer-table category mismatch and a Unicode-15 decimal digit. Finite name/alias and nesting, backreferences and scanner error/warn/block semantics have focused witnesses. Native HTTP now invokes the same scanner through ordered byte/text decoding for completed request bodies and source-buffered responses. The native WS reader and scanner test fragmentation, control frames, per-message deflate and complete large-message relay. The vendored parser uses the measured Python boundary: depth 495 is accepted and depth 496 is rejected for both `(` and `(?:`; deep compilation runs on a bounded 8 MiB child stack so the ordinary worker stack is not exhausted. The traffic-view `~b` byte adapter enforces that boundary before either its regular or Fancy engine and uses the bounded child stack for deep Fancy fallback. Opaque delegated-search cancellation, streaming HTTP bodies, broader regex grammar and full production-chain acceptance remain explicit gaps. No message cap was added to hide those differences. |
| D34 | The native approval-key JSON helper copied U+007F directly while Python escapes it. A legacy trusted identity containing DEL therefore groups under a different approval key. | The ASCII fast path now escapes DEL. Independent recheck at `19ff784e` passed all 128 ASCII identities plus mixed Unicode cases. The actual guard oracle covers the accepted legacy identity source; UDS listener-name validation remains unchanged. |
| D35 | Independent review at `06d7282c` found that method tokens followed by HTAB, VT or FF select opaque CONNECT. An actual HTTP origin accepts those separators and receives a GET that inner policy denies. Direct and Python controls reproduce the behavior. | Native classification now keeps HTTP-like whitespace separators on the HTTP path. Hyper may reject the spelling with 400, but rejection cannot grant opaque transport. SSH identification waits for a complete first line and still gives HTTP request-line syntax precedence. Independent recheck at `19ff784e` passed 33 separator cases without origin application requests, plus the prior HTTP-method and SSH identification cases. D36 records the separate leading-whitespace finding. |
| D36 | Independent review at `19ff784e` found that whitespace before the HTTP method still selects opaque CONNECT. An actual Python HTTP origin accepts ten leading separators and receives a GET that inner policy denies. | Initial classification now keeps the same whitespace set on the HTTP parser's path. Independent recheck at `583d8978` passed 48 whitespace/fragment cases without forbidden origin requests, plus passthrough and real SSH. Native regression cases require a terminal 400 and zero application bytes, including one-byte and three-byte prefixes. The original Python proxy failures remain explicit comparisons. |
| D37 | Concurrent Python OAuth refreshes can post the same refresh token twice and let the older response overwrite the newer result. A completed request can also overwrite an intervening credential edit. Expiry or save failure can leave the access token changed in memory before publication succeeds. | The inactive native refresh module shares one attempt per credential across coordinator clones. Vault-bound revisions reject superseded responses. Full response validation and encrypted write rollback retain the previous record on failure. Real Python protocol and concurrency oracles establish the source behavior; independent native recheck and transport integration remain required. |
| D38 | A native rollback could mark stale memory as current: capture credential A, externally replace or remove it, then fail an unrelated local write's activation. Rollback restored the external file but associated its new file stamp with A. A later conditional publication could overwrite the external edit. | Rollback updates the active file stamp only when the restored bytes previously corresponded to the active snapshot. Otherwise it preserves the detectable stale state until reload. A regression reproduced the overwrite before repair and covers external edits/removals; ordinary rollback still preserves valid retry revisions. This is a native repair, without a cross-process locking guarantee. |
| D39 | The Python gateway can render an additional HTTP header from a credential value containing CRLF. A controlled gateway/Vault case demonstrates the extra field on the resulting request. | Native injection validates the replacement header name and value before removing the gateway token. Invalid material returns a content-free error and leaves input headers intact. A regression exercises the actual source defect and the native rejection; this malformed-header behavior is not a compatibility requirement. |
| D40 | The Python hostname sensor decodes lowercase ACE in absolute-form requests but preserves uppercase ACE and origin-form ACE. The same mixed-script DNS name therefore blocks in one spelling and reaches an owned parent in the other two. Uppercase ACE can also pass source validation when its decoded text fails IDNA2003 roundtrip checks. | Native network inspection decodes ACE consistently after configured bypass and identity checks. Policy matching and audit keep the source hostname. Raw-decodable mixed-script labels receive the existing homoglyph response; decoding failure receives the existing deny/warn response with a content-free inspection error. Explicit disable and configured bypass keep their order. The source's strict codec remains a separate tested primitive; this repair does not replace it with UTS46. |
| D41 | Python 3.12's search prefilter uses Unicode negative categories for some scoped-ASCII patterns. For example, search for `(?a:\W)` misses `é`, while fullmatch and anchored search match it. The actual matching instruction uses the correct ASCII category. | Native inspection follows the configured ASCII rule. A regression blocks these matching messages, and the source prefilter defect remains a separate classification in the differential matrix. This correction changes inspection results without adding a policy rule. |
| D42 | Native policy method conditions used Rust's newer Unicode uppercasing. An allow condition for U+1C89 therefore matched a lookup for U+1C8A, although the pinned Python engine denies it. The API's returned method was unchanged, hiding the comparison mismatch. | Policy conditions and API method normalization now share pinned Python 3.12 / Unicode 15 uppercase data. The regression compares the actual source denial with native evaluation. Host case conversion is separate and remains outside this repair. |
| D43 | After the last gateway grant is removed, the source gateway callback returns before clearing its previous token bindings. With a retained host binding and an authored gateway allow rule, an old token can still pass identity, service, capability, host and policy checks and reach vault selection. The compiled baseline already reports an empty token map. | The native gateway snapshot replaces the complete binding collection, including an empty collection. Its canonical view and selector revoke the old token together. Failed candidate construction retains the previous snapshot. The focused native UDS/origin workflow proves the stale token is rejected before origin delivery. |
| D44 | Normal source reload rotates gateway tokens without refreshing contract bindings. A changed body/query approval can keep its old value effective even with generated route permissions. Removed approvals also survive the explicit contract file loader and remain usable when an authored gateway permission permits the route. The stale approval uses the new current token, unlike D43. | Each accepted native snapshot replaces contract bindings together with tokens and permissions. The [gateway regression](../proxy/tests/gateway_snapshot.rs) checks alpha-to-beta replacement with unchanged generated routes, removal despite an authored allow, old-token rejection and retention after invalid TOML. The source witness exercised 32 actual request hooks across 16 observations with isolated in-memory injection and no egress. Native HTTP covers only the simple no-contract workflow; contract body/query approvals remain pending. |
| D45 | Source task clear removes the active task from PDPCore but does not invalidate the Agent API configuration cache. A populated `/config` response can retain the old task rules and hash until explicit invalidation, while direct core reads already show the baseline. This is an observed state-freshness defect; the witness does not establish an enforcement bypass. | The native projection reads the current immutable snapshot without a second cache. The [sensor configuration tests](../proxy/src/policy/sensor_config.rs) compare baseline, task replacement and the existing `without_task()` snapshot with actual source core responses, retaining the stale source handler response as evidence. HTTP task management and sensor enforcement integration remain pending; the component test does not establish a complete task-clear workflow. |
| D46 | The source admin shield checks textual hosts before DNS. Numeric aliases, a root dot, mapped IPv6 and a DNS alias can reach a protected loopback endpoint. Configured extra ports have the same hole. Malformed digit-only extra ports raise inside both hooks; the dispatcher swallows those failures and permits the connection. An ephemeral bind or a changed port option can also leave the running listener unprotected. Admin bearer authentication remains a separate boundary. | Native request and CONNECT checks retain the source host/port rules. Before connecting, the sole egress path checks each selected socket against the protected local addresses and the actual startup-owned listener. The same numeric port at a remote address or 127.0.0.2 remains allowed. Invalid numeric extra-port configuration rejects the candidate and preserves the previous live snapshot. The [shield tests](../proxy/tests/admin_shield.rs) retain actual source socket and dispatcher witnesses; the [operator transport tests](../proxy/tests/admin_transport.rs) exercise the integrated boundary. The proxy checks the immediate configured parent socket; origin resolution beyond that parent remains the parent's responsibility. |
| D47 | A malformed operator JSON or UTF-8 body makes the source task PUT handler write two final 400 responses for one request. Its Content-Length parser also accepts a negative length by reading until EOF, maps non-numeric lengths to a body error, and can disconnect on overflow. | The native operator facade sends one terminal malformed-body 400 with a native decoder diagnostic. Hyper rejects invalid framing before dispatch. Normal task responses retain exact source JSON bytes; decoder wording and transport rejection order are explicit differences. The [operator facade tests](../proxy/src/admin_api.rs) compare valid, auth, method, raw-document and failure contracts. These changes do not add an application body limit or a second HTTP parser. |
| D48 | The earlier native request cleanup skips an entire Connection value when HeaderValue::to_str rejects non-ASCII bytes. A valid UTF-8 whitespace token therefore leaves its nominated header on the upstream request, while Python removes it. HeaderMap deletion also changes the first-match order needed by credential inspection. | The [ordered header owner](../proxy/src/request_headers.rs) uses fields captured by the existing H1/H2 parsers, preserves first spelling and duplicate order, and applies source header hygiene before network evaluation. Native credential inspection and the pattern scanner now consume that ordered view before egress. The focused wire proof covers first spelling, duplicate grouping and D48 nomination. Invalid value bytes remain lossless through the private source-text adapter, with `\uDCxx` source-pattern escapes mapped to their one-byte identities and source regex backslash parity preserved; controlled H1/H2 wires prove matching warn/block, escaped-literal nonmatching and raw forwarding. HMAC fingerprints deliberately recover the source bytes before signing because strict source encoding rejects lone surrogates. D33 broader Unicode properties/parser depth, streamed/unsupported HTTP text, fragmentation/compression and cancellation gaps stay open. |
| D49 | A malformed JSON or UTF-8 budget-reset body makes the source parser send 400 and return None. The reset handler treats that result as an absent body, clears every budget, emits two success audit events and sends a second 200 response. | The native operator handler sends one terminal 400 and preserves the counters. Intentionally absent bodies and valid falsy JSON still reset all counters. The source handler/state probe and [operator workflow](../tests/proxy_migration/test_operator_budgets.py) retain this concrete defect separately from compatible reset behavior. |


| D50 | The source HTTP/1 parser raises NotImplementedError on nonempty response trailers and never runs the circuit response hook. Its HTTP/2 parser accepts valid trailers. | Native Hyper already supports both trailer forms; completion metadata retains that admission behavior. A valid native HTTP/1 trailer response therefore completes and counts. Source and native parser/transport controls retain this difference rather than adding a second parser or a new rejection. |
| D51 | Source cache loading accepts malformed state records and can fail later while reconciling or reading stats, after prior mutations. | The existing native cache restore validates structural records before publication. Typed numeric/JSON operations now preserve source kinds and reached errors, but structural malformed-cache publication and some Python sequence arithmetic remain unresolved. Valid Python/Rust cache interchange and restart behavior are tested separately. |
| D52 | Source circuit configure replaces its InMemoryCircuitState without stopping the former snapshot worker. Shutdown stops only the currently selected state worker. | Native uses one process-owned worker. Runtime publication and snapshot path selection share a lock; file changes attempt to save the former state before selecting new domains. A failed save is reported without preventing selection. Actual Proxy tests cover file switching, clearing persistence and final writer join. Abrupt process termination and blocked filesystem I/O remain outside graceful-shutdown evidence. |
| D53 | A malformed JSON or UTF-8 circuit-reset body makes the source operator parser and handler send two final 400 responses. No circuit mutation or reset audit follows. | Native sends one terminal 400 and retains state, following the same framing correction as task PUT in D47. Valid reset keys and source exception/audit behavior have separate actual-source comparisons. |
| D54 | An upstream HTTP/2 response with status 500, partial DATA and RST_STREAM(NO_ERROR) reaches the native downstream as status 500, the partial body and StreamEnded. Python sends a 502 error response. A retained binary from `d089f995` reproduces the native result before circuit completion metadata was added. | The application now keeps the upstream status and already-delivered DATA prefix, then fails the downstream body stream when the shared completion observer reports reset/truncation. A same-prefix END_STREAM control remains clean. Only validated parser completion reaches circuit counting: reset and downstream cancellation release a once grant and emit no circuit failure, while a complete 503 retains the grant and counts once. The live TLS/HTTP2 control is [`full_proxy_h2_partial_reset_fails_while_same_prefix_end_stream_is_clean`](../proxy/tests/transport.rs); the H2 grant/circuit/recording control is [`actual_h2_terminal_outcomes_release_once_grants_once_and_count_only_complete`](../proxy/src/http/circuit_completion.rs). Python's 502 formatting remains a documented wire difference. |
| D55 | With a request above 10 MiB, the source forwards the reserved test-context header before its late request hook removes it. A missing-context request sends all 10,485,761 bytes to the origin; the origin 200 then replaces the hook's attempted 428, despite a deny event. | Native test-context admission now rejects missing required context and strips the reserved field before origin contact. Completed streamed bodies retain the source's empty evidence snippet. The native HTTP regression separately checks blocking, stripping and complete payload forwarding. |
| D56 | The inherited native HTTP/2 parser accepted pseudo-header trailers and dropped those fields before publishing successful completion. It also ignored the decoder's existing oversized-header marker for trailers, which can hide discarded pseudo fields. | Shared request/response trailer admission now rejects retained pseudo fields with connection PROTOCOL_ERROR and the existing oversized marker with ENHANCE_YOUR_CALM. Valid ordinary trailers still complete. Actual Python execution confirms ordinary versus pseudo-header behavior; the oversized source error path has static evidence only. Existing configured size limits are reused; exact-limit differential parity is unverified. |
| D57 | A source flow-record tag failure can leave the inserted flow pending on its SQLite connection. A later successful operation commits that failed record. | Native recording rolls the row and provenance tags back together, while retaining separate best-effort body search indexing. The [storage comparison](../proxy/tests/flow_store.rs) preserves the source witness and checks that the failed record stays absent after another commit and reopen. |
| D58 | Direct source flow reads fall back to legacy agent_id when a schema-v2 row has no authoritative evidence_owner. An explicitly quarantined owner-null row is therefore readable by that legacy agent although scoped search excludes it. | Native direct reads require exact evidence_owner, matching collection scope. Foreign, unresolved, quarantined and missing records share the existing 404. [API tests](../proxy/tests/agent_api_flows.rs) prove denial before loading or decompressing a body. Existing version-1 migration still assigns owners; reads do not reattribute quarantined version-2 evidence. |
| D59 | If shutdown finds the source audit queue full, it removes and echoes queued events without releasing their pending reservations. After the active flush finishes, pending can remain permanently nonzero. | Native shutdown releases exactly the reservations for entries removed by this fallback. Pending then reaches zero after active work finishes. Echoed events are not claimed to have reached the file. The [writer tests](../proxy/src/audit/writer/tests.rs) preserve the held-flush/full-queue case and distinguish draining from persistence. |
| D60 | Source service discovery reconciles trusted UDS identity with the agent map. A disagreement removes the evidence owner, skips last-seen accounting and emits a conflict event. | The owned discovery reconciler compares the accepted listener, host map and pre-stamped metadata, removes the owner from a conflict result, suppresses last-seen updates and emits the source-shaped conflict/unavailable event. Matching, fallback, stale, unreadable, malformed and replacement outcomes have direct tests; the shared request snapshot carries the result through native consumers. |
| D61 | TraceStore does not enforce the per-agent cap when an initially ownerless record later acquires an owner. A capped append moves a record to the end without updating its retained timestamp; expiry stops at the first live record and can retain a later stale record. | Native owner assignment now applies the existing per-agent cap, and expiry scans all records so a stale record cannot survive behind a live record after append reordering. Capped appends retain their prior step timestamp, and the global and per-record step caps remain unchanged. The source rows remain finite witnesses for the repaired divergence. |
| D62 | A source MemoryMonitor request decode error retains earlier counters, then escapes the shared production addon container. Later request security hooks can be skipped while the HTTP layer resumes forwarding. The retained decoder fixture proves the child failure; the wider bypass path is established by static dispatcher/HTTP control flow, not a new full-chain execution. | Native memory observation errors retain partial state and produce categorical diagnostics, while existing security decisions continue. They do not skip inspection or introduce a new rejection rule. Focused HTTP and WebSocket failure controls verify that later native context/scanner decisions still run. At `34635393`, vendored allocation/cancellation tests also pass 43 deterministic injected failures, recovery and buffer release; delegated regex cancellation remains explicitly unsupported mid-search and its observed delay is run-specific. |
| D63 | Earlier native forced shutdown aborted outer connection tasks and dropped nested JoinSets or driver handles without joining their descendants. WebSocket close events and driver cleanup could then follow client removal or audit shutdown. | One accepted-connection task owner now retains explicit HTTP drivers, CONNECT/WS work, Hyper transport-executor jobs and actual WS scanner jobs through cancellation. Tasks registered after cancellation are dropped before their work runs. The client guard ends after that owner drains. Finite owner and owned H1/WS tests establish this transport scope; standalone API workers, anonymous spill-file jobs and ordinary process Drop remain outside the guarantee. |
| D64 | Source probes that cross the existing streaming threshold attempt transport before the request sink, even when that sink is installed. The transport guard refuses locally. Source HTTP/1 returns HTML 502 without a request-ID header; its error hook records `error_type: Error`. | Native preserves the buffered/streamed distinction and refuses streamed probes without draining the remaining upload or publishing sink success. Its existing error response is correlated JSON 502, with the native trace category `NativeProbeTransportRefused`. Earlier native network/circuit admission still has the request-head timing described for the HTTP pipeline. Source lifecycle evidence is static; owned native HTTP/1 controls verify the local behavior. |
| D65 | Source baseline loading publishes before its success audit submission. A synchronous submission failure attempts `ops.policy_error`, then returns false or raises even though the policy changed; subsequent callbacks are skipped. Catalog synchronization can then attempt a separate rollback and reload. | Native keeps policy, catalog, routes and tokens in one accepted snapshot. Audit failure attempts the source-shaped error event once and reports an evidence failure separately; it does not change a successful load result or roll back the catalog alone. A rejected load retains its original error if error-event submission also fails. The source failure behavior remains in the policy reload oracle. |
| D66 | Source baseline loading publishes its validated model, then advances file timestamps before rebuilding permission indexes. A later file-observation failure can leave the new model, old indexes and partially advanced timestamps together while reporting a load failure. | Native compiles and observes all baseline/addon/list timestamps before publishing the candidate. An observation failure retains the previous policy and all accepted timestamps and attempts the existing later-load error event. This preserves atomic policy/catalog ownership; it does not claim an atomic filesystem snapshot. |

## Development CLI process selection

The [CLI development workflow](DEVELOPERS.md#rust-proxy-development-backend)
selects a supplied Rust executable and native JSON configuration through
`proxy.backend: rust`. Python remains the default. Start, status and stop use
the native readiness marker and a separate process lifetime record; no launch
failure selects Python automatically. Rust shutdown waits for process exit.

The source installer now builds the locked release executable with the Cargo
space guard and packages it into the installed CLI. This closes the artifact
availability gap for an explicitly configured native launch while retaining the
Python default until the complete native lifecycle, ingress, rollback and
consumer evidence is rerun against one frozen candidate. It does not authorize
deleting the Python comparator or switching the default.

The shared CLI admin client selects the recorded native IPv4 loopback endpoint
and credentials. It verifies process identity before requests and follows a
new verified Rust process after restart. Once a client selects Rust, a missing
or stale native record does not fall back to the Python endpoint. Explicit
client URLs retain their existing
targeting and token behavior. This connects existing consumers to implemented
native routes; agent service authorization, traffic scope and other missing
management routes remain separate work.

[Mocked lifecycle tests](../cli/tests/test_rust_proxy.py) and
[command tests](../cli/tests/test_lifecycle_rust.py) cover selection, ownership,
failure cleanup, health and explicit rollback selection. They do not establish
installed tmux behavior, live native process startup, Linux/macOS ingress,
packaging or pilot acceptance.

Listener synchronization reconciles conventional CLI sockets at startup and
requests a full SIGHUP reload for map changes. A fresh
reload ID in accepted readiness confirms that update; timeout is unconfirmed.
Custom listeners are retained. [Mocked synchronization tests](../cli/tests/test_rust_listener_sync.py)
cover the CLI's configuration edits and acknowledgment decisions.
[Native library tests](../proxy/src/listener_reload_tests.rs) cover listener
publication and failed preparation with temporary files and Unix sockets.
The process-level `admin_service_shutdown` witness also starts the shipped
binary twice against the same disposable state and agent socket paths. It
waits for the first readiness marker and socket to be removed after graceful
shutdown, then sends a real request through the reopened socket and verifies
fresh readiness and cleanup. This establishes native process restart/socket
reuse for those paths; it does not establish installed host listener lifecycle,
macOS/Linux ingress, packaging or pilot acceptance.
Complete management and traffic UI workflows, credential inspection/injection,
and real host listener lifecycle proofs remain unfinished.
This development launcher does not complete M7 or authorize cutover.

## Deletion map and evidence still required

The path-level #640 review ledger is maintained in
[proxy-cutover-deletion-map.md](proxy-cutover-deletion-map.md). It keeps every
current Python runtime owner retained, names its affected checks and replacement
gate, and records the explicit Python rollback while comparator jobs remain
active. The ledger is a plan and testable inventory; it does not authorize a
default switch or deletion by itself.

Deletion is conditional on replacement, not movement behind an adapter.

| Milestone | Candidate removal after proof | Retained dependencies and boundaries |
|---|---|---|
| M1 | None. | Existing proxy remains the behavior source; tests and fixtures are additional code. |
| M2 | Rust-path UDS peer shim, custom mitmproxy mode and listener adapter. | Keep existing VM/guest/host bridges and production Python ingress until cutover. Track the temporary Python policy adapter explicitly. |
| M3 | Proxy use of `pdp/client.py`, duplicate request/decision schemas, addon policy configuration and temporary adapter. | Do not delete policy/TOML code still needed by the Python CLI. Preserve persistent policy and approval semantics. |
| M4–M5 | Proxy CA bootstrap subprocess, framework TLS options/store hooks, streaming/WS/tunnel adaptations. | Keep operator CA/vault files and trust roots. Remove a dependency only after checking remaining consumers. |
| M6 | Production addons, `core/base.py` flow integration, flow metadata dispatch, View/TUI/web monkeypatches and Python proxy lifecycle/writers. | Retain required CLI, traffic workflows, SQLite/JSONL formats, coordination and credential lifecycle. Python CLI dependencies may remain. |
| M7 | Obsolete launch plumbing after the corresponding lifecycle contract is replaced. | Keep explicit backend selection and the old release for the pilot and rollback; exercise both supported host platforms. |
| M8 | Old proxy entry point, mitmproxy runtime dependency, temporary adapters and backend selector after independent cutover acceptance. | Audit Python CLI imports before removing shared code. Report actual removals separately from acceptance-test additions. |

## Recorded baseline and M1 status

The [baseline manifest](../tests/proxy_migration/baseline.json) preserves the
initial capture unchanged: 45 existing live tests and six shared backend
scenarios passed, and smoke workloads were measured. Its original full-chain,
API and sustained-workload gaps describe that capture. Appended follow-up
records supply the measurements below. The
[harness contract](../tests/proxy_migration/CONTRACT.md) gives reproduction
commands. Denial-response and probe differences remain visible.

All these captures ran on Linux aarch64 with Python 3.12.14 and mitmproxy
12.2.3. The old production source remains the `4116c7ee` baseline. The later
Python runs executed checkout `4586a127b9b051a48757e96288b3087c5aec3d98`,
whose `cli/src/safeyolo` and `pdp` sources were unchanged from that baseline.
The sustained Rust run identifies checkout
`5b661dc9ce83514a0f1eabc90944b85efc09b49b` and a dirty worktree. The integration
owner identifies its binary as the transport repair at that revision, before
D11's adapter concurrency repair. These measurements are not results for a
later binary. Exact commands, artifact hashes and source qualifications are
in the appended manifest records.

RSS means resident set size. Combined process RSS double-counts shared pages.

| Capture and scope | Measured result | Memory and limits |
|---|---|---|
| Focused Python chain, 1,000 fresh HTTP connections | 577.3 requests/s; median 1.69 ms; 95th percentile 1.91 ms | RSS after workload 92,288 KiB; lifetime high-water 92,480 KiB. |
| Focused Rust transport plus temporary adapter, 1,000 fresh HTTP connections | 1,477.5 requests/s; median 0.64 ms; 95th percentile 0.85 ms | Combined RSS after workload 45,948 KiB, including 39,832 KiB for Python. Sequential load does not exercise D11's failure. |
| Focused Python SSE, 60-second requested stream | 49,152,000 bytes in 67.36 s; first chunk at 11.50 ms | Sampled peak RSS 89,920 KiB; second-half median 69,644 KiB. One paced stream, without inspection or a slow reader. |
| Focused Rust SSE, same stream size | 49,152,000 bytes in 67.92 s; first chunk at 12.71 ms | Combined sampled peak RSS 45,580 KiB; second-half median 36,308 KiB. Rust process RSS stayed 5,872 KiB in the samples. |
| Focused Python WS, 60-second session | 8,192 five-byte echoes; 136.5 messages/s | Sampled peak RSS 91,712 KiB; second-half median 72,576 KiB. No fragmentation, compression or inspection. Rust WS remains unsupported and was not measured. |
| Full production Python, four API workers and 30 network approvals | 1,600 authenticated API requests in 8.10 s; 197.6 requests/s; API median 17.51 ms and 95th percentile 31.56 ms; approval transaction median 96.34 ms | Sampled peak RSS 133,996 KiB; second-half median 129,644 KiB; lifetime high-water 152,812 KiB. Short run with growing approval and retained-traffic state. |

Second-half medians describe the recorded samples; they do not establish a
long-duration memory plateau. The focused chain omits most production addons,
so its rates cannot establish complete-production Rust performance.

The [full production fixture](../tests/proxy_migration/full_production.py)
starts the real traffic entry point and all 27 configured addons, with private
console, web and admin listeners. The service gateway remains disabled without
a synthetic vault. Configuration, state, logs, coordination storage and tokens
are isolated. The fixture checks healthy authenticated APIs, missing-token
401 responses, a durable 428 approval, exact agent/host/port grant scope and
one real delivery to its owned origin after approval. Concurrent transactions
create a pending network request, grant Alice's endpoint and check Alice allow
versus Bob prompt. Synthetic `.invalid` endpoints are not dialed after grants.
These checks do not establish expiry or one-shot service-grant consumption.

The final full-production workload has status `completed_with_gaps` because of
D12. Its separate smoke suite records one pass and one strict expected failure;
the expected failure must not be counted as a passing cleanup assertion.

M1 now has runnable current-production startup, baseline suite results,
representative measurements for every requested workload category, explicit
failures and a deletion map. **M1 and the smallest M2 slice passed independent review at
`c2afb9cfcb42107920aeaf9d687e2da6be74dc8c`.** The reviewer verified all eight referenced artifact hashes, the memory summaries,
and unchanged production sources; the full production smoke independently
reproduced one pass and the strict cleanup expected failure. D11 and the
subsequent adapter cancellation repair passed independent rechecks. Later
changes require review against their own immutable revision.

Later milestones still require approval expiry and one-shot consumption,
credential/service behavior, interactive traffic workflows, complete evidence
parity, TLS and authority boundaries, WS inspection, cancellation and bounded
memory under concurrent streams, and supported Linux/macOS host ingress.
Finite baseline workloads supply comparison data; they do not satisfy those
replacement acceptance requirements. No production code or dependency is
removed by these captures.

The differential harness must run each backend independently with the same
scenario inputs. Compare expected decisions as well as backend agreement.
Only timestamps, generated IDs and nondeterministic ordering may be normalized,
while preserving their relationships. Keep destinations, ports, approval
scope, delivered bytes, redaction, failure classes and evidence omissions.

Required performance workloads are request latency/throughput, long streams,
WebSocket traffic, repeated short connections, and concurrent approvals/API
activity. Record peak and steady memory, early chunk arrival, cleanup and API
responsiveness. No performance or complete-parity claim is made here.

## Run the initial development slice

These commands require a Linux or macOS checkout, `uv`, and the Rust toolchain
specified in [proxy/rust-toolchain.toml](../proxy/rust-toolchain.toml). Run from
the repository root. The fixtures create isolated policy files, sockets and
local upstream servers. They do not start an operator's configured instance.

```sh
uv sync --frozen --group dev
cd proxy
cargo build --locked
cargo test --locked
cd ..
uv run --frozen pytest -q tests/proxy_migration --proxy-backend python
uv run --frozen pytest -q tests/proxy_migration --proxy-backend rust
uv run --frozen pytest -q tests/test_rust_temporary_policy.py
```

The Rust fixture launches `safeyolo-proxy --config PATH`. The JSON configuration
provides `listeners` with `agent_id` and `socket_path`, `readiness_file` and
`event_log`. Select exactly one of `policy_file` for native network policy or
`temporary_policy_socket` for the separately named
[temporary network-policy adapter](../tools/proxy_migration/temporary_policy.py).
The native-policy fixture starts no Python adapter. Optional
`parent_proxy`, `upstream_ca_file` and `via_token` select upstream transport.
`tls_ca_file` selects an existing combined CA PEM for the development HTTPS path.
The listener configuration supplies identity; request headers cannot select it.
`SIGHUP` reads the configuration again. `SIGTERM` initiates shutdown.

The adapter socket is private host state and must remain outside agent mounts.
The adapter receives header names and request metadata, never header values or
body bytes. It uses the existing Python policy decision point in blocking mode.
It does not supply credential inspection, service operations or the complete
NetworkGuard response and approval workflow.

Native policy uses the existing Rust policy matcher and network guard once per
request. The source options `network_guard_enabled`, `network_guard_block` and
`network_guard_homoglyph` default to true. Valid reloads retain shared policy
budgets and guard counters; invalid configuration keeps the previous runtime.
Native guard responses preserve the source JSON bytes, status and headers.
The shared audit writer emits canonical `security.network_guard` records for
deny, warn, approval-required, budget and homoglyph decisions, plus allowed
CONNECT admission. Ordinary allowed HTTP emits no network security event.
Development `proxy.network_guard` diagnostics retain the guard intents without
raw queries or application bytes. Approval persistence and the remaining
production pipeline still require integration. The bounded local API reads are
described below.

Owner validation at `22c9a008` on Linux aarch64 passed all 36 native policy wire cases and
104 WebSocket regressions against one frozen binary. The native policy cases
verify the absence of an adapter process/socket, identity, bypasses, reloads,
shared budgets, exact deny bytes and denied-request containment. Separate source
selections passed 27 cases, recorded four strict historical D40 failures and
skipped five explicitly native-only inspection-error cases. Nine codec tests
include all Unicode scalar Nameprep outcomes and 155 source parser/sensor rows.
The native request constructor also matches those 155 rows. All 22 existing
Rust transport tests, strict all-target Clippy and selected hooks pass.
These are owner results, without independent acceptance or macOS/guest evidence.

The native operator route status is maintained in the compact
[operator operation map above](#operator-api-and-events). It records the
current authenticated read/control handlers, native `/admin/events` stream,
and the explicit missing, delegated, and deferred operations. An implemented
route still requires its issue-specific consumer and effect proof before
acceptance.
Development configuration opts in with `admin_port`; port zero binds
an ephemeral port reported as `admin_port` in readiness. The optional
`admin_api_token_file` contains the startup token. The listener reads and strips
that file once. Missing or empty tokens deny management access; health remains public.
Policy reload preserves the actual listener, startup token and task registry.
Listener or token changes require a process restart, matching the source server's
startup ownership.

A successful task PUT validates the existing model schema and stores the supplied
JSON in one process-local registry. It does not compile or activate task rules,
inject a task ID into the stored document, or change the active policy hash.
GET returns that raw document, including unknown fields and absent defaults.
Replacing an ID retains the registry count; an invalid update retains the prior
document. POST `/admin/policy/task/{id}/activate` is the explicit activation
boundary: it compiles the selected raw document against the accepted baseline,
prepares the existing credential detector, and publishes one Runtime snapshot.
DELETE on that path clears the document and, when selected, publishes the
baseline-only snapshot. A failed compile leaves both the registered document and
active policy unchanged. Enforcement, `/config`, policy hashes and operator
reads therefore switch together after activation; a replacement remains only a
registered candidate until that boundary. Restart starts a new empty registry.
Validation reuses the canonical loader's schema helpers without its matcher,
host expansion or token issuance. Source task-file activation is a
loader/engine library method; this native operator path keeps registration and
activation explicit rather than adding a task-file option.

Operator replies use Python's indented JSON presentation and the shared scalar
formatter. GET borrows the stored document into one sized, zeroizing response
allocation. Task document owners and API outcomes omit Debug and general serialization.
The shared canonical writer emits failed-authentication and accepted-task-update
events without raw task documents or bearer values. Separate development
`proxy.admin_api` diagnostics retain the intents. Diagnostic write failures
preserve the response and set `X-SafeYolo-Evidence-Error`. Synchronous canonical
submission exceptions terminate the operator handler before its response;
accepted task mutations remain committed.

The [native operator control workflow](../proxy/tests/operator_controls.rs)
also drives malformed baseline/task/mode/reset bodies and invalid baseline/task
documents over the real admin TCP listener. Each malformed request produces one
terminal response and leaves the prior document or mode unchanged. A read-only
policy directory makes the baseline and host transaction writes fail; both
routes retain the original policy bytes and return their stable 400 response.
The same workflow points the canonical audit writer at an actual failing sink
after `Writer::emit` has accepted the event while changing baseline policy, mode
and host state. This proves the asynchronous flush failure path: the writer
reports its failure through its bounded fallback, while each committed mutation
retains its normal 200 response and remains observable through a later read or
file check. A separate [crate-internal listener test](../proxy/src/admin_listener/mutation_tests.rs)
poisons the runtime writer so `Writer::emit` fails synchronously for each of
those three mutations. The real listener then closes the request without an
HTTP response, while the file or mode state remains committed. These two tests
cover distinct canonical audit failure boundaries.

The listener uses the first Authorization header and exact `Bearer ` prefix.
It adds no Origin, Host or CORS restriction. Origin-form targets retain the source
normalization of leading slashes; absolute-form paths remain distinct.
Non-ASCII authentication and a truthy
non-object request body retain the source connection-close behavior. Malformed
JSON or UTF-8 receives one terminal 400, preserving the source's first error
category with a native decoder diagnostic. The source writes a second response
on that connection; the native facade does not reproduce that defect. Hyper
rejects invalid, negative and overflowing Content-Length before dispatch. The
source can instead report a body error, disconnect, or read until EOF. These
framing differences and native HTTP version/banner headers remain explicit;
the normal task response fields and bytes have source comparisons.

The [admin shield](../proxy/src/admin_shield.rs) applies before policy or forwarding
and again at the sole outbound connection path. D46 records its concrete source
repairs. The integrated [operator transport tests](../proxy/tests/admin_transport.rs)
exercise real agent HTTP and CONNECT requests for management aliases and protected
ports while a separate loopback admin connection remains usable. They also cover
an occupied startup port, which publishes neither readiness nor agent sockets, and
an intentionally inconsistent temporary policy response through the real agent
HTTP listener; a controlled origin observes zero connections for that internal
handler failure. `admin_shield_extra_ports` retains the source's comma-separated grammar:
ordinary non-digit entries are ignored, while digit-only entries that Python
cannot convert reject the native configuration. Existing rules are retained on a
failed reload. The actual bound listener stays protected even if the configured
port option changes. Protected immediate routes resolve once and check each
selected socket before a connection or egress record. Enforcement records use the
local decision; an upstream response header cannot claim a local admin block.
Other routes keep their
existing connection behavior. Initial admin bind failure prevents readiness;
shutdown closes its listener and drains connections with the other proxy tasks.

Owner validation on Linux aarch64 passed 253 selected Rust tests, including the
live source oracles, 15 compile-fail documentation tests, strict all-target
Clippy, formatting and selected repository hooks. All 210 native wire cases
passed against one frozen executable: 69 Agent API, 36 network, 104 WebSocket
and one [operator client workflow](../tests/proxy_migration/test_operator_task_api.py).
The workflow uses the existing Python AdminAPI client with an owned listener
and synthetic token. It verifies registration remains inactive, explicit
activation changes enforcement and the `/config` hash, clear restores the
baseline, reload ownership retains the remaining registered task, and
proxy-to-admin containment still holds.

All 1,010 source blobs, 22 migration fixtures and the executable stayed unchanged
during that run. All configurations selected native policy without the temporary
adapter. All 153 egress records belonged to owned peers, with no unexpected
contact. Artifact scans found no raw or hex-encoded minted bearer patterns.
Readiness files, Unix sockets and proxy processes were cleaned up. Process
observations cover 179 cases; the remaining 31 have configuration, event and
cleanup evidence without a sampled-process claim. The four WebSocket lifecycle
witnesses pass; opaque regex delegate cancellation remains unproven.
These results are implementation evidence, without independent acceptance,
macOS or real-guest validation.

The native [Agent API](../proxy/src/agent_api.rs) serves authenticated `/health`,
`/lookup`, `/policy`, `/budgets`, `/config`, `/status` and `/circuits` on the
reserved hostname.
`agent_api_enabled` defaults to true.
Authentication reads `SAFEYOLO_DATA_DIR/agent_token` for every request, defaulting
to `/safeyolo/data/agent_token`. Method checks precede authentication; lookup uses
the trusted listener identity and current policy snapshot without spending
request budgets. Repeated Authorization fields retain the source comma-space
joining behavior. Root-dot aliases enter the same local API under D9.

The native `/status` report reads the current policy hash, the operator task
registry count and the policy engine's existing state. Its field order and
`pdp-0.1.0` engine version match the source. Engine statistics include the
baseline and task file paths, canonical permission counts, full required-addon
list, cumulative evaluations and ordered budget keys. File paths retain their
lexical spelling under the source's Path display rules; reporting does not
resolve filesystem paths. Uploaded task counts are separate from the active
file-task overlay. An operator PUT changes that count without activating a task
or changing the policy hash.

One shared counter increments at each of the four policy evaluator entry points.
Network evaluation validates the port first; later failures still count.
Credential, risk and gateway evaluations count at entry. Lookup previews count
without consuming quota. Ordinary API reads do neither. Accepted reloads retain
the counter and budget keys; failed reloads preserve the existing snapshot.
A fresh engine starts at zero. The transport and API do not add a second counter.

A missing policy client returns the existing local 503. Non-UTF8 native policy
paths and poisoned state locks retain typed reporting failures through the
local containment response; they are not renamed to Python exceptions. Python
can represent surrogate-escaped paths that the native report cannot encode.
The generic `NoEngine` development state still cannot distinguish a corrupted
local client from a remote client, whose source status results differ.
This provider distinction and source library task-file activation remain
unimplemented in the native process.

Owner validation on Linux aarch64 passed 268 selected Rust tests across 20
targets, including the live source oracles, plus 15 compile-fail documentation
tests, strict all-target Clippy, formatting and selected repository hooks.
The [status traffic fixture](../tests/proxy_migration/test_agent_api_status.py)
also passed against the actual Python proxy, with 50 source and helper files
unchanged. It checks exact report bytes through previews, allowed and denied
traffic, accepted and rejected reloads, and a fresh process.

All 211 native wire cases passed across 212 proxy instances against one frozen
executable. The operator workflow confirms real task counts of 0, 1, 1 and 2
without activation. The status workflow observes two counted previews without
quota consumption, five evaluations after allowed and budget-denied traffic,
and six after a policy denial. Reloads retain the count and stale budget keys;
a fresh process clears them.

All 1,018 source blobs, 23 migration fixtures and the executable remained
unchanged during native validation. Every configuration selected native policy
without an adapter. All 155 egress records belonged to owned peers, with no
unexpected contact. Privacy scans found no raw or hex-encoded minted bearer
patterns. Readiness files, sockets and processes were cleaned up. Process
observations cover 179 instances; the remaining 33 have configuration, event
and cleanup evidence without a sampled-process claim. The four WebSocket
lifecycle witnesses pass. These are implementation results, without independent
acceptance, macOS or real-guest validation.

These requests terminate locally before ordinary inspection and egress. Disabled
or failed handlers remain contained; CONNECT returns the source transport-guard
403. Development `proxy.agent_api` evidence records response and audit intents
without bearer values or URL queries. A failed evidence file write preserves the
response and sets `X-SafeYolo-Evidence-Error`; source production audit writes also
preserve responses when their sink fails. Native canonical producers now emit
auth failure, handler unavailable, declaration and clear events before traffic
hooks. A synchronous auth submission error uses the native local guard's 503
transition. The historical separate-addon source test does not establish the
production container's continuation after that exception.

Policy method comparison and API query formatting use [pinned Python scalar
data](../proxy/data/agent_api/README.md), including the D42 correction.
Operational routes without native implementations remain unavailable.
Python surrogate-escaped query values that cannot enter the native scalar-string
matcher produce a typed compatibility failure and local 503. The integer parser
matches Python's default 4,300-digit conversion limit; nondefault Python limits
remain outside the demonstrated contract. These gaps, audit producers for
unimplemented routes and global API counters still require integration before
complete API acceptance.

The authenticated `/explain?request_id=req-<32hex>` route reads canonical audit
events for the trusted caller. Request ID validation precedes identity checks.
The query's `agent` or client fields cannot select an owner. A foreign request ID
and a valid ID with no matching record both return an empty event list; the
response echoes the queried ID. The reader matches the recorded top-level
`agent` field exactly. The first query value wins, including an empty first
value. The source request ID expression accepts one terminal line feed; the
reader preserves that character for exact record matching.

Before listing retained files, the reader checks the shared writer and waits up
to 0.5 seconds for pending writes. It scans the current file followed by configured
backups, newest first, retaining the last 10,000 lines of each file. Within a file,
matching events keep line order. The source status precedence is `error`,
`pending`, `incomplete_search`, then `complete`. An incomplete result includes
`searched_lines_per_file`. These statuses describe the read attempt, not an
atomic snapshot or durable storage guarantee.

The reader uses the process writer's startup path and backup settings, including
the development audit-path override. Reload keeps the same writer and reader
source. File reads and the bounded drain run off async workers. Malformed JSON
lines are skipped; unreadable retained files mark the result as `error` while
other files can still contribute events. Exceptions from valid non-object JSON
or undecodable text remain handler failures. The trace and diagnostic probe
implementations are described separately below.

The [source controls](../proxy/tests/agent_api_explain_source.py) capture actual
handler, scanner and serializer results. The [reader tests](../proxy/src/audit/explain/tests.rs)
compare retained-file recipes and exercise the real writer's bounded drain.
The [API tests](../proxy/tests/agent_api_explain.rs) check authentication, identity,
query ordering and typed error responses. The [HTTP test](../proxy/src/http/agent_audit_tests.rs)
uses two private agent sockets and checks shared-writer continuity after reload.

Matching records retain NaN and integers larger than 64 bits. Escaped lone
surrogates remain unsupported by the existing native JSON representation and
produce a local compatibility failure. A missing reader preserves the previous
handler-owned development 503 without an additional guard event. The reader
preserves Python's empty-path and parent-directory suffix behavior; the existing
writer's parent-directory rotation behavior is unchanged. These controls do not
establish parity for arbitrary filesystem races. The native typed parser uses
iterative traversal and does not reproduce Python's JSON recursion limit.

Validation for this change passed 57 selected Rust tests and 22 actual-source
controls. The joined HTTP test passed with the process writer supplied by the
runtime. Four inherited opt-in source oracles remained ignored; existing live
audit oracles ran in their selected targets. These results are implementation
evidence and do not establish complete API or migration acceptance.

The authenticated `/budgets` response reads the existing shared rate-limit
timestamps and current policy matcher. It does not evaluate requests, spend
budgets or remove counters. Tracked keys include counters hidden by the current
rules; visible entries retain insertion order. Reporting rematches with an empty
agent, path and credential context. Scoped counters can therefore remain counted
without appearing in the response. Valid reloads retain those counters and use
the replacement rules for reporting. A task can lower the effective network
ceiling while the response's `global_budgets` field retains the authored baseline.
The shared destination parser normalizes IPv6 addresses and preserves admitted
scope identifiers before matching. Budget reports retain the original key and
resource spelling. Invalid retained destinations produce the source handler-owned
500 `Internal error: ValueError`.

Reporting preserves signed and arbitrary-size integer budgets on non-simple
permissions, including Allow, Deny and Prompt rules. Simple-rule stand-ins omit
their budgets as the source does. Numeric conversion failures produce the
source handler-owned 500 `Internal error: OverflowError` without changing state.
An unrelated timestamp in addon settings can make `/policy` fail while
`/budgets` remains available. Native charging still requires positive `u64`
Budget-effect and global network rates; source admission of other rates remains
a compatibility gap. Budget persistence remains unintegrated.

Operator GET `/admin/budgets` reads that same state. POST `/admin/budgets/reset`
supports the existing Python `AdminAPI.reset_budget` client. A truthy string
removes one exact key; wildcards are literal. An absent or falsy resource clears
all keys. Other truthy scalar resources are successful no-ops; truthy containers
return the source fixed 500 without mutation. The successful response retains
the source `reset_count` of zero. Reset does not evaluate policy or alter rules,
task registration, policy hashes or evaluation counts. Remaining keys keep
their order, and later charging reinserts a removed key at the end.

Reset and atomic budget charging use the same lock across live policy snapshots.
Reset commits before canonical `admin.budget_reset` and `admin.budgets_reset`
submission, in that order. A synchronous failure at the first submission returns
the source fixed 500 and suppresses the second event; a failure at the second
terminates the handler. Neither failure rolls back the reset. A failed diagnostic write sets
`X-SafeYolo-Evidence-Error` on the successful response; it does not roll back the
reset. The [operator transport test](../proxy/tests/admin_transport.rs) exercises
an actual failing diagnostic sink and recovery. Canonical worker sink failure
uses the writer's asynchronous fallback and preserves the producer result.

The operator report preserves the source connection termination on reporting
failure, while Agent `/budgets` retains its own error response. With the explicit
temporary Python policy adapter, both operator budget endpoints return 503
because that adapter has no budget-read/reset protocol. Process restart
persistence, remote PDP reset and native-to-adapter state continuity remain
unproved. No reset route is exposed through the Agent API.

The operator-budget candidate passed 145 affected Rust tests, including the
selected live source oracles, 15 documentation tests, strict all-target Clippy
and formatting checks on Linux aarch64. Its frozen binary passed 111 native
wire cases across 112 instances. All 68 recorded egress events targeted owned
peers; readiness, socket and process cleanup passed. The artifact scan found
no raw or hex minted-bearer patterns. Process observations came from the
fixtures; this run had no external process sampler.

The paired source run passed both normal operator workflows and an existing
budget-preview case. Its two malformed-body cases reproduced D49, including
the unintended clear, dual audit events and newly allowed retry, before their
strict historical expected-failure assertion. Native counterparts preserve
the exhausted state and denied retry. These are implementation results;
independent acceptance and the remaining migration work are pending.

Owner validation of `/budgets` on Linux aarch64 passed 201 wire cases against
one immutable binary: 61 API, 36 network-policy and 104 WebSocket cases. All
201 configurations selected native policy without an adapter. The eight new
budget cases also passed against Python. Staged-source checks passed 216 Rust
tests, including live Python oracles, and 12 compile-fail documentation tests.
Strict all-target Clippy, formatting and selected hooks passed. The
[budget fixtures](../proxy/tests/budgets.rs) compare 303 actual source-engine
cases; the shared destination parser has 37 source comparisons. Privacy and
shutdown checks found no minted tokens in artifacts or remaining fixture
processes, readiness files or socket directories. These are owner results;
independent acceptance, macOS, real-guest and CI validation remain pending.

The authenticated `/config` response projects `credential_rules`, `scan_patterns`,
`addons` and `policy_hash` from the current accepted snapshot. Baseline rules
precede task rules, retaining order and duplicates; addons come from the baseline
only, including disabled entries. Source defaults and whole-addon replacement
remain loader behavior. Reads neither evaluate policy nor consume budgets.
The transient response owns only the projected fields and uses the existing
zeroizing response owner.

The [policy hash writer](../proxy/src/policy/model_json.rs) streams baseline then
task model JSON into SHA-256 and returns the source's first 16 hexadecimal digits
with a `sha256:` prefix. It retains the existing canonical task model rather than
rebuilding policy. Compact model JSON has different float and temporal spelling
from ordinary API JSON. Parser-owned temporal provenance also preserves distinct
mapping entries whose JSON key spellings coincide. Extracted simple host rules
contribute their counts, so different host sets can have the same source hash.
A typed date and its quoted string can also have the same hash. This value is a
source cache identity, not an authorization signature over every native rule.

If a projected field contains an admitted typed temporal value, `/config` returns
the source 500 `Internal error: TypeError`. A date in an unused gateway field can
affect the hash while leaving `/config` available even when `/policy` fails.
An initialized policy with no baseline returns empty fields and the hash of empty
bytes; an explicitly loaded empty baseline includes model defaults in its hash.
Unavailable policy returns 503. Remote policy-client cache TTL, fallback and
previously populated cache behavior remain unintegrated. D45 records the source
task-clear cache defect and the native snapshot-level behavior. Operator task
registration is implemented separately; it does not activate sensor rules.

The [hash fixtures](../proxy/src/policy/model_json/tests.rs) retain 30 actual
source cases: 23 match native model bytes and hashes, while seven expose existing
frontend admission gaps. Those gaps cover literal JSON and TOML nonfinite values,
YAML non-string scalar keys, UTF-8 and non-UTF-8 binary, YAML sets and JSON lone
surrogates. The source serializes five of those seven; non-UTF-8 binary and lone
surrogates fail its model serializer. The finite-float comparison covers 1,015
samples and does not prove every binary64 value. The source's YAML set ordering
also depends on its hash seed; native set support remains absent.

Owner validation of `/config` on Linux aarch64 passed 209 wire cases against
one immutable binary: 69 API, 36 network-policy and 104 WebSocket cases. All
209 configurations used native policy without an adapter. The eight new config
cases also passed against Python. The frozen source passed 229 Rust tests,
including live Python oracles, and 12 compile-fail documentation tests. Strict
all-target Clippy, formatting and selected hooks passed. All 996 archived and
working-tree blobs, 21 migration fixtures and the binary stayed unchanged during
the wire run. Egress reached only owned test peers; artifact scans found no minted
bearer patterns. All fixture processes, readiness files and socket directories
were cleaned up. Process sampling or fixture process observations covered 172
cases; the other 37 retain configuration, native-event and cleanup evidence.
These are owner results, without independent, macOS, real-guest or CI acceptance.

The authenticated `/policy` response contains the complete compiled baseline,
shared across callers. It borrows the same immutable snapshot as the matcher:
source defaults, permission order, simple-rule counts, addon configuration and
gateway values are retained during loading. Reads do not reopen files, compile
rules, mint gateway tokens or consume budgets. Failed reloads retain the prior
snapshot. A successful reload replaces gateway bindings together with their
routes and canonical values; source-admitted grants mint tokens even when no
service registry is initialized. Native HTTP now selects accepted simple
service bindings and performs vault injection before the credential guard and
outbound dial. Contract body/query binding, OAuth refresh and risky-route
approval remain outside this first workflow.

### Service catalog and agent service discovery

The native development configuration accepts `gateway_builtin_services_dir`
and `gateway_services_dir` together with `policy_file`. Both directory options
must be present or absent. These are explicit native filesystem paths, relative
to the process working directory when not absolute; they do not apply Python's
`expanduser().resolve()` normalization. The builtin directory must exist. A
missing user directory contributes no definitions. This configuration publishes
the catalog for service discovery; it does not by itself enable HTTP credential
injection. Injection requires an accepted policy binding and the selected native
HTTP path.

The [catalog loader](../proxy/src/services.rs) reads top-level `*.yaml` entries
in filename order, including dotfiles. It ignores `.yml`, `.YAML` and nested
files. Duplicate service names within one directory reject the candidate. User
definitions replace builtin definitions without moving their catalog position.
Malformed or unreadable matched definitions also reject the candidate. As in
the source glob, directory-enumeration errors contribute no matched entries;
they are distinct from errors reading an already matched definition.

Startup, explicit reload and automatic service checks pass one accepted registry
to the native policy compiler. The runtime publishes the catalog, service routes, contracts
and token views in that same policy snapshot. A failed catalog, policy or later
runtime construction retains the prior published snapshot. Reads do not load
files, mint tokens, evaluate policy or consume budgets.

The native process checks configured service directories immediately after
startup, then waits two seconds after each check completes. The same process
control loop handles explicit reload and shutdown; it starts no watcher thread.
Embedded `Proxy` callers must drive `wait_for_service_catalog_check` and
`reload_services_if_changed`. Removing the directory options cancels subsequent
checks. An accepted explicit reload checks the new configuration immediately.

Checks compare full paths, modification times in nanoseconds and file sizes.
They detect additions, removals and metadata changes. They do not detect content
changes that retain both size and modification time, or the disappearance of an
empty directory. Each load captures its metadata before reading definitions.
A completed catalog attempt consumes that metadata, including file validation
or subsequent policy failure; unchanged files do not retry. Repairing only the
policy file therefore requires an explicit reload or another service-file
change. Failed loads retain the old published catalog, policy and tokens.
Accepted path changes replace the watched metadata together with the runtime.

Directory metadata checks preserve the source Python 3.12 error behavior.
Missing paths, non-directory parents, bad descriptors and symlink loops count
as absent paths. A path containing a NUL byte also counts as absent at this
check. Other metadata errors propagate without replacing the last attempted
file state. These errors remain retryable on the next check, after
the same two-second delay. They produce no per-file or baseline-policy event
before a file or policy load is reached. A later directory check can fail after
earlier file diagnostics were emitted; those diagnostics remain observable.
Directory-enumeration errors still contribute no entries, and failed metadata
reads for individual matched files still omit only those entries.

Automatic checks reload only the catalog and baseline policy. They retain
transport, inspection and evidence owners; they do not reread unrelated TLS or
inspection files, reopen logs, or change listeners and readiness. Explicit
configuration reload retains its existing full-runtime construction path.

The source watcher also attempts a configured task-policy file reload. The
native process has no active task-policy file configuration; its existing task
snapshot is retained. No shipped proxy caller of the source task-file activation
method was found; the library capability is tracked separately from registration.
The native process has no source watcher timeout-and-restart race because one
control-loop owner completes each check before admitting another reload.

The authenticated [services endpoint](../proxy/src/agent_api/gateway.rs) resolves
the trusted calling agent before reading bindings. It returns `agent`,
`authorized` and `available`. Authorized entries contain that agent's host,
token, capability and account; the available catalog excludes those service
names and preserves service and capability order and description values.
Repeated bindings keep the first service position and the final binding's fields.
Caller-supplied query or identity headers cannot select another agent. Source
GET, POST and DELETE behavior is retained: each reads the same view without
consuming the request body. Projection errors from source-unhashable binding
keys or non-JSON binding timestamps return the source TypeError response.
Existing native representation gaps use the local unavailable-handler response.

An unconfigured native catalog returns empty authorized and available views,
including with the temporary policy adapter. Canonical policy tokens alone do
not establish an active catalog view. Removing both directory options on reload
removes that view. This is native catalog configuration, not the source
`gateway_enabled` switch: disabling the source addon retains its previous
catalog/bindings, and an already registered policy callback can still update
them. The source's empty-token retention defect remains D43; native removal
continues to replace the complete binding collection.

The [source oracle](../proxy/tests/service_catalog_source.py) records strict
loader, actual AgentAPI dispatch and selected configure/read behavior using
owned synthetic data. Its disclosed lifecycle client and watcher seams do not
prove full startup. [API comparisons](../proxy/src/agent_api/gateway/tests.rs)
replay the response cases without polling a request body. Runtime and HTTP/1
controls exercise scoped reads and coherent publication through owned listeners.
The read owner and simple service request path are installed. The native
request-access route emits a pending approval event; the existing operator
route persists the selected vault entry name, and the process watcher publishes
the binding. The HTTP path consumes the published gateway token, injects the
selected vault credential and leaves the original request body and signed
query available to forwarding. The simple route has no contract body binding;
OAuth refresh, risky-route approval and broader HTTP/WS parity remain open.

Catalog loading inspects all matched files in source order even after a
failure. Each failed file attempts one `ops.config_error` event with addon
`service-loader`, severity `medium`, its basename, error class and sanitized
message. Directory problems reject the candidate without per-file events.
Synchronous audit submission failures do not mask the load rejection or stop
later-file inspection. Startup acquires the existing audit writer before loading
the catalog and attempts to drain it on construction failure. Failed reloads
keep the running writer. A failed or timed-out drain is reported separately and
does not replace the original construction error.

The existing service-definition YAML frontend still has temporal-value,
non-string-key and numeric representation gaps. Source filenames that require
Python surrogateescape are not representable in the current native string
provenance. Native parser/schema failures use explicit native error classes
where the current frontend cannot establish the source exception class. Exact
parser and operating-system message wording is not a parity claim. The installed
builtin-path resolver and packaging, and HTTP selection/injection remain required
migration work. Source task-file activation remains separately inventoried.
Initial path resolution,
including source symlink resolution before loading, remains separate from
metadata checks on already configured directories.

### Baseline file watching

With a configured native policy, the process checks the baseline, sibling
`addons.yaml` and referenced host-list files independently of service catalog
changes. It uses the existing process control loop, with an immediate first
check and a two-second wait after each attempt, including failure. Embedded
`Proxy` callers drive `wait_for_policy_check` and `reload_policy_if_changed`.
The separate catalog and policy deadlines do not suppress each other after an
error. Removing the native policy configuration cancels subsequent policy
checks; selecting another path makes its first check immediately eligible.
An accepted explicit reload of the same path retains its current deadline.

Each check compares modification times as floating-point seconds, as the source
does. Only a strictly newer timestamp triggers a reload. Deletion, equal or
older timestamps, and content changes with an unchanged timestamp do not trigger
by themselves. Adjacent nanosecond timestamps can compare equal after float
conversion. All three checks finish before a changed flag triggers loading;
a later check error can prevent a reload detected by an earlier check.

List observation re-reads the raw baseline on every check. It uses the maximum
timestamp across every string value in the raw `lists` mapping, including lists
unused by host rules. Relative paths use the baseline directory. Lists defined
only in addon defaults do not participate. Missing or unreadable lists contribute
no timestamp; an unrelated newer list can mask a change to an older list.
An invalid baseline read commonly produces a zero list maximum, while a truthy
nonmapping document or a NUL-containing list path can raise a check error.
Existing native parser representation limits remain: for example, native JSON
rejects `NaN` during decoding and returns a zero list maximum, while Python
decodes it and then raises when the watcher expects a mapping.

Successful file loads capture new baseline, addon and list timestamps after
compilation. The candidate retains the previous addon timestamp when that
sibling is absent and the baseline path is unchanged. An addon that later
reappears at an equal or older timestamp can therefore remain unnoticed. A new
baseline path starts new observation history. Source-string policy mutations
retain the previous file observations. Explicit and catalog-driven file reloads
refresh them, preventing a duplicate policy-watcher reload of the same state.

A policy-file reload uses the accepted service registry and retains existing
transport, inspection, audit and budget owners. It does not read catalog files
or rebuild unrelated configuration. The policy, routes, tokens and accepted
file timestamps publish together. Invalid newer candidates retain the old
timestamps and remain eligible for retry. D66 records the correction to source
partial publication after a late observation error. D65 still preserves an
accepted policy when audit submission fails.

The [source watcher oracle](../proxy/tests/policy_watch_source.py) captures nine
workflows and 34 finite iterations of the actual watcher closure. Native
[component tests](../proxy/src/policy/watch/tests.rs) replay six workflows and
28 iterations, comparing reached loads, accepted timestamps and selected policy
fields. The other three workflows inject source stat or audit failures; they
inform separate native error and publication tests without a nine-workflow
equivalence claim. The [Runtime tests](../proxy/src/service_catalog_tests/policy_watch.rs)
cover deadlines, retry, accepted registry reuse, authenticated HTTP/1 views and
retained budget state. These are implementation evidence, not independent
migration acceptance.

The observation is not a filesystem snapshot: a file can change between its
content read and subsequent stat. Native preserves the reached observation
phases without claiming the source's exact repeated-stat races or thread
interleaving. Task-file activation remains a separate library capability. Source
watcher restart races remain outside this native control-loop comparison. Time
passing without a file change does not itself trigger host-expiry pruning.
Native startup continues to reject an invalid initial configuration.

### Expired hosts in policy TOML

Runtime baseline loads now remove expired host entries from a configured TOML
file before addon merging, host-list expansion and policy compilation. This
applies to startup, explicit reload and both automatic reload paths. The source
performs the same early write for top-level hosts. D15 retains the native
correction for expired agent-scoped hosts as well.

The loader uses the names already removed from its parsed candidate. It rereads
the TOML with a comment-preserving parser and removes only those names. It does
not recompute expiry from that second read. An unchanged document is not written.
The existing low-level policy writer creates a mode-0600 temporary file, syncs
it, replaces the configured path and syncs the parent directory. A configured
symlink is replaced; its former target is unchanged. Public `Policy` file
constructors and reload methods remain read-only, and YAML/JSON loads do not
write their source files.

Read or save I/O failures report a diagnostic and allow the already-pruned
candidate to continue, as the source does. This includes a directory-sync failure
after replacement is visible. A second-read decoding or TOML parse failure
rejects the candidate at the later processing-error boundary. A successful
pruning write is not undone if later compilation or observation rejects the
candidate: the old policy remains active while the disk edit remains visible.
Successful observation captures the post-replacement timestamp, preventing an
extra watcher reload for that write.

This load-time cleanup uses the existing atomic file writer without the approval
transaction's lock, activation callback or rollback. It is not a transaction
across disk and Runtime. A concurrent edit between the first read and the pruning
read can still lose a renewed entry with the same name; source has the same race.
Native temporary-file ownership removes its temporary on an earlier write or
rename failure. Source's `delete=False` temporary can remain if write, flush or
file sync fails before its cleanup variable is assigned; that difference is a
static control-flow observation.

Native keeps atomic rename and does not reproduce `shutil.move`'s copy fallback
after a source rename failure. Arbitrary changes to document shape between the
two reads, directory replacement races and exact comment reattachment by two
different TOML parsers remain outside the comparison.

The [source oracle](../proxy/tests/policy_expiry_source.py) records ten workflows
and 17 load/watch steps. The [native replay](../proxy/src/policy/watch/expiry_replay.rs)
selects seven workflows and 12 steps, comparing reached loads, saved bytes,
mode, symlink and inode replacement, modification-time relationships, accepted
timestamps and selected policy fields. Six workflows compare exact source file
bytes. In the mixed-expiry workflow, source removes one space after a retained
date scalar; native preserves the authored line. The replay asserts that specific
formatting difference and equality of every other saved byte. The agent-expiry
row remains the D15 source witness; two source save-failure rows use disclosed move and directory-sync
seams. Native [helper tests](../proxy/src/policy/expiry/tests.rs) separately
exercise reached read/decode/parse errors and real rename-failure cleanup.
The [Runtime workflow](../proxy/src/service_catalog_tests/policy_expiry.rs) checks
startup, watcher, explicit and catalog loads, rejection/retry, HTTP/1 views and
retained budgets. This is finite implementation evidence; source fault seams,
bare-relative directory sync and arbitrary filesystem races are not a complete
native equivalence claim.

### Baseline policy reload events

The [runtime policy loader](../proxy/src/policy_runtime.rs) emits
`ops.policy_reload` for an accepted native baseline. Startup emits after complete
Runtime construction and before the memory startup event; this does not imply
listener readiness. Explicit and automatic reload emit after policy publication.
The event uses `kind: ops`, `severity: medium`, addon `policy-loader`, and ordered
details `policy_type: baseline` and `permissions_count`. That count comes from
the canonical permission array, after host-centric simple-rule extraction. It
does not count all matcher entries or copy a token-bearing policy document.

Rejected baseline loads attempt `ops.policy_error` with severity `high` and
ordered details `policy_type: baseline` and `error`. Read/decode failures and
JSON null use the source's fixed file-not-found-or-invalid summary and error.
Reached document, merge, compiler and validation failures use their native
error text in the source-shaped failure summary and details. Explicitly
unsupported native representations use their native error text. Existing parser
differences can also change the reached branch: Python accepts JSON nonfinite
constants that native rejects during decoding, and coerces falsy YAML scalars
to an empty policy where native can reject the document. These stages and error
strings do not establish Python/Pydantic equivalence. Neither event has request,
agent, host, decision or attribution fields.

Catalog rejection before policy loading, unchanged catalog checks, and the
temporary policy adapter emit no native baseline event. Later pre-publication
configuration failure emits no reload success. A readiness-write failure after
publication does not erase the event for the installed policy.

Audit submission failure is reported separately from policy acceptance. After
a failed success submission, native attempts the source-shaped policy error
once, then keeps the accepted snapshot and successful load result. A failed
error submission preserves the original rejected-load error. D65 records this
correction to source partial-publication and callback behavior. Queue-full or
stopped normal submissions and later asynchronous sink failure do not become
synchronous policy-load exceptions; a queued event is not a durability claim.

The [source oracle](../proxy/tests/policy_reload_source.py) records 18 selected
load workflows. Native comparisons pair eight complete event envelopes. The
remaining source observations inform component and Runtime controls or retain
explicit gaps; they are not an 18-case native parity claim. D65 keeps the source
audit-failure outcomes alongside the native correction.

The source loader also has task-file activation and task-specific event
behavior. Those library producers remain separate from the implemented operator
registration workflow; no shipped caller for that source task-file activation
method was found.
Source/native stat-error phase differences and existing YAML/TOML/JSON
representation limits remain explicit gaps; these events do not close them.

### Gateway representation and response encoding

Gateway primitives still have explicit compatibility gaps for partially loaded
source token maps, unhashable binding lookup keys, non-string vault/account
values, and structured temporal path values. A non-mapping contract value fails
only when a constraint attempts its lookup. Earlier denials keep their source
order. D44 records the separate repair for stale contract approvals. These
compatibility gaps and the remaining HTTP integration block production
gateway activation.

Native API responses omit Debug and general serialization implementations.
The explicit response encoder writes borrowed strings and keys into one sized
allocation, retained by a zeroizing Bytes owner until the last body reference
drops. Hyper and the operating system can make separate transport copies.
The shared [JSON formatter](../proxy/src/python_json.rs) preserves Python's
ASCII escaping, spacing, field order and floating-point presentation; exact
integer values retain their precision.

YAML and TOML temporal provenance follows the existing parsers and policy
compiler. Declared string fields reject typed values; dropped fields do not
affect the view. Retained dates, times and datetimes in arbitrary addon or gateway data
cause the source handler-owned 500 `Internal error: TypeError` on `/policy`.
The loaded policy continues enforcing requests. Quoted values and authored objects that
look like date representations remain ordinary data. Typed gateway values do
not become string matches. An initialized unconfigured Policy has a null view;
Runtime startup still requires its existing configured policy or temporary
adapter. An invalid configured policy stops native startup; the source's
initialized empty fallback remains unimplemented. A configured remote client's
baseline is also outside this local runtime slice.

Owner validation of the `/policy` expansion on Linux aarch64 passed all 193
wire cases against one immutable binary: 53 API, 36 network-policy and 104
WebSocket cases. The 89 API/network cases used native policy without an adapter;
the WebSocket cases in that run used the temporary Python policy bridge.
The unchanged health/lookup source baseline passed 35 cases with one strict
historical D9 failure. All 17 new policy/YAML cases also passed against Python.

The [WebSocket fixture](../tests/proxy_migration/test_websocket_contract.py)
now selects native policy for Rust. A separate run against the same immutable
binary passed all 104 cases without a policy adapter. All 151 request events
reported native network policy coverage. Each of the 100 upgrades and two
policy denials had a matching native guard event. Fixture processes, listener
paths and readiness files were removed after shutdown. Four Python comparison
cases also passed for denial and live scanner-rule reload over WS and WSS.
The existing 16 strict Python D32 failures remain recorded. The reload cases
change scanner rules; they do not prove reauthorization of an upgraded
connection after a network permission changes. D33's opaque-delegate
cancellation gap also remains.

Staged-source checks passed 188 selected Rust tests, including live Python
oracles, and 12 compile-fail documentation tests. Strict all-target Clippy,
formatting and selected hooks passed. Projection evidence covers 18 baseline
configurations, 87 YAML temporal cases and 30 actual-loader TOML cases.
Separate formatter checks cover 61,360 finite floating-point values and all
1,112,064 Unicode scalars. Request and Response compile-fail tests prevent
routine Debug/Serialize use. These results do not establish independent
acceptance, macOS, real-guest or CI validation, or the remaining production
API workflows.

The [host codec](../proxy/data/host_names/README.md) pins the source's IDNA2003
and Unicode data. Request-form validation preserves the source policy hostname;
the separate D40 inspection step decodes ACE consistently. UTF-8 origin-form
Host fields retain their original bytes. Native plaintext parent forwarding
uses an absolute URI with IDNA authority, while the source preserves origin-form
in this case. Wire fixtures assert both exact forms and the unchanged path/query.

The fixture checks decisions, delivered bytes, destination ports, generated
IDs and trusted attribution. Its `proxy.request` and `proxy.egress` events are
migration evidence, not replacements for production JSONL or traffic APIs.
Both reserved local destinations remain local. The Agent API implements the
bounded reads above. The diagnostic probe now runs the installed native request
checks; unimplemented producer stages remain visible as missing. Other Agent API
workflows still need integration. An allowed CONNECT now opens its authorized
destination before
protocol selection, matching production
and allowing a server greeting. Denied CONNECT still opens no destination.
The first allowed inner request reuses that connection. Its policy check
precedes delivery of application bytes. Changed inner authorities cannot select
another destination.

With `tls_ca_file`, detected TLS receives an interception endpoint using the
existing CA. Upstream TLS verifies names and trust chains, including through a
configured parent's CONNECT tunnel. TLS failure never selects an opaque fallback.
Negotiated HTTP/2 streams retain connection identity and independent request IDs.
Native tests cover response cancellation and shutdown drain; paired tests cover
concurrent agents, protocol negotiation and authority rejection.

`ignore_hosts` accepts canonical exact entries produced by the existing CLI
normalizer. `SAFEYOLO_IGNORE_CIDRS` supplies the existing constrained IPv4 ranges;
the builtin endpoint remains included. These exemptions select passthrough only
after network admission. Other recognized opaque traffic also retains arbitrary
permitted destination ports, full duplex and independent half-close. Tunnel
events report transferred bytes and actual termination, without claiming SSH
authentication or inspected payloads. Fragmented protocol prefixes remain on
their validating path. Production WebSocket integration, D29's passthrough
boundary and complete control/evidence integration remain required; this is not
M4/M5 acceptance.

The native operator listener now accepts the retained consumer's authenticated
`PUT /admin/proxy/ignore-hosts` request. It validates the canonical exact host
or host:port list, replaces the live matcher, and reports
`admin.proxy_ignore_hosts_update`. Existing admitted connections keep their
match; connections opened after an empty replacement are inspected again. The
route does not persist configuration or extend matching to aliases, parents,
SNI or inner Host. Direct IPv4 range matches discovered from the connected peer
retain the same lifecycle owner; parent-route addresses remain outside this
direct passthrough path.

The native [network policy](../proxy/src/policy.rs) runs without the temporary
adapter when selected. [Approval persistence](../proxy/src/approvals.rs),
[service selection](../proxy/src/services.rs) and
[contract enforcement](../proxy/src/contracts.rs) still need complete runtime
integration. The bounded gateway route now exercises one authenticated
contract binding, remembered grant and synthetic credential injection through
the native request path; the cross-runtime state and rollback witness is
described in the operator service-authorization section below.
Their differential tests cover authored precedence, scoped
mutations and rollback, reload budgets, service/capability routes and contract
request constraints. Local baseline host lists, IAM task overlays and network
condition defaults follow the existing loader and evaluation context. The shared
YAML frontend retains scalar style and merge precedence. Native
[service grants and bindings](../proxy/src/grants.rs) preserve persisted scopes,
configured TTLs, session lifetime, scoped mutations and rollback; once grants
add the reservation repair in D21 and stable legacy defaults in D23. The same
policy matcher now evaluates credential use, risky routes and service calls;
9,870 additional Python comparisons cover the existing contexts and effects.
The native [encrypted vault](../proxy/src/credentials.rs) reads and writes the
existing format without credential re-entry. Its secret type requires explicit
access and cannot be serialized into routine metadata. Remaining approval,
service and credential workflows are only partially integrated in transport.
OAuth refresh execution, complete control integration, TOML's large-integer
gap, and JSON body compatibility beyond the tested UTF-8 encodings still
require work.
Declared state and response-validator tiers are not promoted to implemented
enforcement.

The inactive [OAuth refresh lifecycle](../proxy/src/oauth.rs) produces a secret
form request for the host credential-management transport. One coordinator and
its clones share refresh attempts for an active vault. Conditional publication
preserves intervening edits and retains the exact prior encrypted file after
activation failure. The protocol oracle covers 64 Python cases, including
UTF-8/16/32 responses, duplicate keys and expiry rounding. Python JSON extensions,
lone surrogates and deeper nesting remain accepted-input gaps. HTTP routing,
URL userinfo, TLS, decompression, timeouts and gateway injection still need
integration; the module creates no network client or independent egress path.

The inactive [injection stage](../proxy/src/credential_injection.rs) takes the
existing service selection after contract and risky-route checks. It reads the
shared vault, preserves expiry/refresh/redirect ordering, and produces a validated
header change plus scoped evidence intents. A pending refresh consumes outcomes
from the existing OAuth coordinator. Successful refreshes re-fetch the current
record; cancellation, rejection and supersession return categorical errors.
Retained results require the captured vault revision to remain current.

The service selection preserves the exact auth kind, including unknown and
absent kinds with their source delete-only behavior. Ready replacements mark
header values sensitive and apply metadata only after header mutation succeeds.
Redirects retain the original URL, including signed queries, through explicit
secret access. Owner checks cover 57 Python gateway stage cases and composition
with service selection and credential detection. Six cases isolate the stage
after earlier selection/risk checks. Request header casing/order still needs the
transport adapter; grants, cancellation and audit publication need runtime wiring.

Native [circuit state](../proxy/src/circuits.rs) runs on the native-policy HTTP
path after network admission and before origin connections. Circuit state is
shared across trusted agents by the source hostname spelling. The global
`circuit_breaker_enabled` option defaults to true. The temporary network-policy
adapter does not activate circuits. After normal method, authentication and
body checks, its circuit read/reset endpoints report that the addon is unavailable. Existing policy addon bypasses
apply to requests; the source response hook checks only the global option.
Outer CONNECT has no circuit request or response hook. Inner HTTP and the HTTP
101 WebSocket handshake participate; subsequent WebSocket messages do not.

The existing HTTP parsers publish optional completion metadata. A response counts
only after the upstream message completes: final no-body headers, validated
body framing or valid close-delimited EOF. Partial bodies, early cancellation,
truncation and HTTP/2 resets do not count. A completion already observed survives
later cancellation. The connection driver applies the result once, without
reading another copy of the body. Upstream `X-Blocked-By` fields cannot impersonate
local enforcement or suppress counting. Native HTTP/1 trailer support remains
a source parser difference under D50.

The authenticated `/circuits` response reads that same owner. Existing operator
POST `/admin/circuit-breaker/reset` deletes an exact host key without clearing
lifetime counters or settings. Missing or falsy host fields return 400. Reads can
advance stale circuits and emit unscoped canonical transitions. Circuit operations
submit canonical events at their source mutation points. Development
`proxy.circuit` records remain separate diagnostics. Reset submits its ops event
before the separate admin event; a non-string host uses the source minimal
validation-fallback envelope for the ops event. Diagnostic write failure preserves committed state and valid response
bytes. A failure known before headers adds `X-SafeYolo-Evidence-Error`; a later
failure produces a content-free diagnostic.

Settings come from top-level `addons.circuit_breaker` fields. Refresh remains
lazy: an unchanged hash skips, omitted fields retain their values, and exclusions
accumulate. `/circuits` itself does not refresh settings. When globally enabled, an ordinary
local blocked response refreshes before the prior-block check. Current runtime ownership
serializes refresh with admission or response completion, so a delayed response
cannot reinstall the policy that originally admitted it.

Optional `circuit_state_file` selects persistence; absent or empty disables file
writes in the development configuration. A single process-owned worker attempts
a save every ten seconds and after graceful request shutdown. Changing the file
attempts to save the former file's domains, then loads/reconciles the new file
while retaining counters and settings. A failed former-file save is reported
and does not prevent selecting the new file. File replacement retains the state
lock through save/load, so a reset cannot interleave between saving the old state
and publishing the loaded state. Clearing the path selects fresh empty domain state.
Normal policy reload retains the existing domains. A fresh process reloads saved
domains and applies source stale-open/streak reconciliation with fresh counters.
Source worker replacement differs under D52.

Circuit arithmetic preserves bool, arbitrary-size integer and binary64 kinds,
including reached Python errors and pre-error mutations. Typed API/cache JSON
retains nonfinite constants; audit JSON converts nonfinite details to null as
the source writer does. Configuration preserves consumed temporal provenance.
These repairs remove the former exact-integer activation blocker. Generic
frontend temporal/nonfinite admission, lone-surrogate JSON strings, malformed
structural cache timing and unsupported Python sequence arithmetic remain
explicit compatibility gaps. They are not a complete production-parity claim.

The [operator workflow](../tests/proxy_migration/test_operator_circuits.py) covers
shared failures, pre-egress block, authenticated read/reset and recovery, with
global-disabled and prior-network-block controls. The
[completion workflow](../tests/proxy_migration/test_circuit_completion.py) checks
held fixed/chunked bodies, truncation, cancellation and forged block headers
against both backends. [Persistence tests](../proxy/tests/circuit_persistence.rs)
exercise actual Proxy startup, reload, the ten-second worker and shutdown.
The [reload workflow](../tests/proxy_migration/test_circuit_reload.py) verifies
current settings on delayed responses and recovery after a fresh process.
[Bypass controls](../tests/proxy_migration/test_circuit_bypass.py) retain source
request/response asymmetry and required-addon precedence.

The joined circuit candidate passed 207 tests across 15 selected Rust targets,
15 documentation tests, strict application Clippy, formatting and applicable
repository hooks. Its frozen executable passed 33 selected native-policy wire
tests across 34 configurations, plus three TLS/HTTP2 completion controls paired
with three actual Python runs. Seventeen existing HTTP/HTTPS/HTTP2 tests passed
through the temporary policy adapter as separate transport regression evidence.
The TLS/HTTP2 reset-response difference remains explicit under D54: the native
proxy preserves the committed status and body prefix, then reports a downstream
body error for reset/truncation. The `END_STREAM` control remains a clean body
completion. The completion application test also checks that reset and
cancellation release a once grant without circuit counting or duplicate gateway
recording, while the complete control counts the 503 exactly once.
These are implementation results; independent acceptance, supported-host pilots,
production evidence storage and cutover remain outstanding.

Native [test-context declarations](../proxy/src/agent_api/declarations.rs) now
serve authenticated GET, POST and DELETE on `/api/test-context/current` when
native policy is configured. One process-owned store survives configuration
reloads. The trusted listener supplies the source slot; a new connection UUID
does not change that slot. An explicit listener `source_id` supports arbitrary
socket paths. Otherwise, a source-valid `<IPv4>_<agent>/proxy.sock` path supplies
the source IP. Other existing paths remain valid and return source-unavailable
403 for declaration operations.

Method, bearer, trusted agent, source and owner checks precede POST body reads.
GET and DELETE ignore body content. The shared JSON byte decoder handles
UTF-8/16/32 detection, and the existing typed JSON parser preserves unused
nonfinite values and exact integer TTLs. The HTTP content decoder handles gzip,
deflate, Brotli, Zstandard and the source's binary codec aliases. Above the
existing 10 MiB encoded streaming threshold, source request content is absent;
the API treats it as an empty object. This threshold does not limit decoded
content or reject larger requests. A truncated body propagates its transport
error without replacing the declaration.

A successful reload changes current declaration defaults without rewriting
existing expiry or refreshing target hosts. A POST held across reload uses the
new maximum TTL. Reached integer-to-float overflow returns the source's 500 and
preserves the previous record. Mutation audits retain the trusted agent field
and have no decision or attribution object. Their source-stage request ID is
the existing request-context ID when local dispatch has one, and remains
optional for direct API callers. A synchronous
submission failure returns the handler's 500 after the declaration mutation,
without rollback. [Body ownership tests](../proxy/tests/agent_api_declarations.rs),
[core tests](../proxy/tests/test_context.rs), and
[content decoder comparisons](../proxy/tests/http_content.rs) cover these
boundaries. The [native socket regression](../tests/proxy_migration/test_agent_api_test_context.py)
checks source reassignment, current TTL across a held POST, mutation audits and
local containment. The shared decoder extraction also retains OAuth regressions.

Native HTTP now selects test context after network and circuit admission and
before origin contact. Explicit annotations take priority; malformed explicit
context cannot borrow a declaration. Trusted listener identity supplies the
evidence owner. Canonical target operands use the policy's typed view, including
temporal values and reached source errors. A required-context block returns 428
at the request head, correcting D55. Configured warnings still forward.

The [request application owner](../proxy/src/http/request_context.rs) waits for
the ingress parser's successful message completion. Small bodies are buffered
before origin contact; larger bodies stream with bounded evidence retention.
Neither a body stream ending nor a reset proves parser success. Request metadata
is installed before content decoding. A decode error preserves forwarding and
the metadata needed by a later response, while skipping the request event and
allowed counter. Ordinary evidence write failures do not roll back counters.

The existing connection driver applies request and response effects once.
Before releasing outgoing request frames, it checks validated completion. An
origin that waits for the full request therefore cannot overtake its request
hook. An already-observed early response uses only metadata applied at that time.
Parser response capture records accepted
bytes even if the downstream body is unread. Aborts discard pending capture.
The retained response-header decision honors global/domain SSE options; streamed
content yields an empty snippet. Content decoding does not change forwarded bytes.

[Native HTTP tests](../tests/proxy_migration/test_http_test_context.py) exercise
the complete forwarding path. Parser and application tests cover resets,
unread responses, body replay, counter ordering and evidence failures separately.
These are implementation evidence. TestContext security events still use the
development diagnostic sink. Non-string YAML target keys and lone JSON surrogates remain
frontend gaps. Late evidence failures cannot change headers already delivered.
Independent acceptance and production cutover remain outstanding.

Native [flow storage](../proxy/src/flow_store.rs) retains the version-2 SQLite
schema, version-1 migration, body compression, previews, truncation metadata,
provenance tags and separate request/response full-text indexes. Existing files
remain readable across Python and Rust. Storage gzip decoding follows Python's
strict member and trailer checks; HTTP content decoding retains its different
source behavior. Direct baseline flow-store settings are read once at startup.
Reload preserves the same store and writer and changes recording admission.
Enabling recording after a disabled startup does not create a new store.

The [HTTP recorder](../proxy/src/http/flow_recording.rs) now records eligible
contextual requests after validated request completion and makes one terminal
recording attempt. It retains original header order, accepted response status
and reason, decoded body sizes and configured body prefixes. Streamed bodies
remain absent. A transport error uses the actual upstream head when one exists;
a generated proxy 502 does not become an origin response. A pending application
guard records cancellation before the connection driver takes ownership.
If TestContext response decoding fails, the production dispatcher skips the
later recorder. Native completion releases the pending evidence without changing
recorder counters. A request decode failure keeps applied context available to
a later valid response hook. Direct recorder comparisons do not establish this
container ordering; the [actual source dispatcher comparison](../proxy/tests/production_dispatch.py)
and H1/H2 regressions cover it.
Parser aborts that erase their diagnostic cause can still produce a null reason.
Inactive service-gateway and replay producers remain outside this slice.
Reserved probes are excluded before capture and record building; reached
response/error recording still increments the skipped counter once.

[HTTP recording tests](../proxy/src/http/flow_recording/tests.rs) compare source
metadata and stored rows, then exercise real UDS forwarding, compressed content,
streaming, decode failure, refused connections and cancellation during an owned
TLS parent handshake. H2 tests cover an unread response and an early response
before request completion. The cancellation regression fails without the pending
guard and records one error after the repair. These tests use synthetic evidence
and owned peers; they do not establish full production-chain acceptance.

The [flow writer](../proxy/src/flow_writer.rs) queues owned records and performs
compression and SQLite writes on its worker. The queue grows with pending
records, preserves the configured bound, and counts full-queue drops separately
from write errors. Nonpositive queue settings remain unbounded. Recorder counts
measure enqueue attempts, including drops, rather than committed rows. Shutdown
stops admission and waits up to five seconds for draining; a timeout reports
failure and keeps the live store owned by the worker. Startup failures retain
the source's assigned or partly initialized store without installing a writer.

Authenticated [flow routes](../proxy/src/agent_api/flows.rs) share that
process-owned store. Search, endpoints, facets, both body searches, metadata and
request/response body reads, tags and diffs use the trusted ingress owner. SQLite queries and
storage decompression run outside async workers. Body reads check ownership
before decompression. The [runtime tests](../proxy/src/flow_runtime_tests.rs)
exercise contextual HTTP forwarding through real Alice/Bob Unix sockets, stored
body reads, cross-agent denial, a forged owner filter, authenticated operator
`/stats`, reload, partial startup, shutdown and reopening. The current
operator statistics expose the installed discovery, policy engine, network
guard, circuit breaker, TestContext, recorder and request logger owners. Other
source addon reports remain unfinished.

Authenticated `/stats` reads each installed owner in source order. It preserves
an individual reporting error in that component's result and continues to later
components. A policy-engine reporting error retains that source wrapper's empty
object. Reads do not evaluate permissions or refresh request-stage configuration.
Network and circuit `enabled` fields report the runtime option, independently of
per-request policy bypasses.

Statistics are not free of side effects: circuit reads can advance stale states
to half-open and submit unscoped canonical events; TestContext reads prune expired
declarations. Discovery reads can reload the map and emit discovery events.
Authentication precedes those reads. Synchronous circuit submission failure
preserves reached state and lets later component reports continue.
The typed operator response retains circuit scalar values, including nonfinite
numbers, through the existing Python-compatible JSON formatter. Shared owners
retain counters across reloads. These reports do not establish statistics for
inactive components or complete operator inspection.
With the temporary Python policy adapter, the report keeps an empty
`policy-engine` result and the discovery, recorder and logger results. It omits
the inactive native network guard, circuit breaker and TestContext owners.

[Source controls](../proxy/tests/admin_stats_source.py) establish exact aggregate
rendering and error continuation. [Owned runtime tests](../proxy/src/admin_listener/stats_tests.rs)
cover authentication before reads, counters, declaration expiry, circuit audit
failure and reload. The facade's frozen-body replay checks rendering only.
Some existing core errors still use categorical native messages: a scalar
TestContext target collection reports `target_hosts has no length`, and an
invalid circuit state reports `invalid persisted circuit state`. Their error
classes and continuation match the selected source cases; their message text
does not. Numeric core error messages also remain outside complete parity.

The [tag and diff store methods](../proxy/src/flow_store/details.rs) preserve
typed immediate tag values, SQLite readback, retained body sizes and Python's
default unified diff behavior. Their source comparisons cover clipping,
matching repeated lines, Unicode line boundaries and storage failures.
The [API comparisons](../proxy/tests/agent_api_flow_details.rs) check both
owners before diff decompression, source ID conversion order, typed tag replies,
persisted tag values and body failures before mutation. A canceled request
does not roll back a mutation already running on the database worker.
These are implementation results. Unpaired JSON surrogates and some direct
Python-only SQLite values remain representation gaps; a categorical local
compatibility error does not establish parity for those inputs. Complete
operator inspection, remaining audit producers and independent acceptance remain open.

### Canonical traffic audit and runtime ownership

The [audit writer](../proxy/src/audit.rs) emits schema-version-1 JSON Lines for
reached request logger hooks. Its typed envelope retains source field order,
optional fields, nested attribution, temporal values, nonfinite-number behavior
and minimal serialization fallback. The existing Python audit consumer reads
native output. These comparisons cover the represented native value domain;
arbitrary Python objects and lone-surrogate strings remain outside it.

One lazy writer belongs to the process and survives configuration reloads.
`audit_log_path` is a development startup override; otherwise the process uses
`SAFEYOLO_LOG_PATH` or `/app/logs/safeyolo.jsonl`. Existing audit queue, size and
backup environment settings are read at native startup. Source queue capacity
is read when its lazy writer first starts; in-process environment mutation
between startup and first emit is not compared. Reload keeps the startup sink,
queue and logger counters. A failed reload preserves them too.

The writer preserves nonblocking admission, overflow counts, queued-plus-flushing
pending counts, batch append, rotation names and stderr fallback. Queue admission
is not file persistence. A completed drain includes attempted writes and
fallback, without an fsync guarantee. Shutdown stops transport producers first,
then waits up to five seconds for sentinel capacity and a separate five seconds
for worker exit, matching the source's two waits. D59 records the pending-count
repair. [Lifecycle tests](../proxy/src/audit_runtime_tests.rs) hold the writer on
an owned FIFO across successful and failed reloads and through shutdown.

The [request logger](../proxy/src/request_logger.rs) reads quiet rules at the
reached request hook. It retains source hash-before-validation behavior, the
last good rules after malformed configuration, counter ordering and lazy body
decoding. The response hook uses the established quiet decision. Stable UDS
attribution belongs under `details.attribution`, with the compatible top-level
agent field. URL projection follows the source's presentation host and parsed
path, including final-segment parameter removal. Its finite source controls do
not prove exhaustive Unicode-version or glob equivalence. A known newer cased
Unicode scalar produces a categorical compatibility error; this does not
establish parity for that input. Invalid UTF-8 presentation fields remain a gap.

Ordinary HTTP shares the existing request buffer, independent parser completion
and response capture. Gzip sizes count decoded content; source-streamed bodies
report size zero. An early completed response can precede the request hook and
therefore omit its request ID and start time. Transport errors and cancellation
do not invent a response event. A circuit request exception skips later request
children; an independent valid response can still log. A circuit response
exception skips later response children while preserving the HTTP response and
already-committed state. TestContext response decoding errors have the same
continuation boundary. Ordinary audit sink failures do not become those hook
exceptions. The [source dispatcher oracle](../proxy/tests/production_dispatch.py)
retains both container and separately registered addon controls.

Local API requests use the existing reader's scalar encoded/decoded sizes.
RequestId header cleanup occurs after the API handler; if it removes
Content-Encoding, the logger uses the retained encoded size. Independent parser
success gates traffic hooks. A bodyless local denial logs only if parser
completion is already available. If an early denial wins with an unread body,
D55's immediate enforcement remains and no empty request or traffic response is
invented. Trusted local outcomes supply blocked attribution; an upstream
X-Blocked-By header cannot supply it. Parser validation before API mutations
under HTTP/2 resets remains unverified; the logging check alone does not prove it.

[HTTP traffic tests](../proxy/src/http/traffic/tests.rs) cover actual owned
HTTP/1 and HTTP/2 exchanges, compressed and quiet content, streaming, early
responses and cancellation. [Local tests](../proxy/src/http/traffic/local_tests.rs)
cover API body sizes and header cleanup, completed empty local denials, unsent
body omission and request-circuit exceptions. [Upgrade and operator tests](../proxy/src/http/traffic/upgrade_stats_tests.rs)
check one traffic response for a WebSocket 101 handshake, unchanged counts after
frames, and authenticated request logger statistics. These are implementation-team
evidence. The canonical security and administrative producers below share this
writer. Other producers, operator inspection, independent acceptance and cutover
remain incomplete.

### Canonical network security audit

NetworkGuard submits each reached security event through the same process-owned
writer as traffic logging. The event retains the source decision, severity,
summary, approval scope, method, port and connection ID. Trusted listener identity
supplies the same UDS attribution as traffic records. Request headers cannot
supply the agent or request ID. The ordinary allow path emits no event; CONNECT
allow emits its own event and correlation ID separately from inner HTTP traffic.

Submission occurs at the source counter boundary. Deny and warn submit before
their terminal counters and block metadata; rate-limited counters and policy
charges already made remain. CONNECT allow increments its counter before
submission. A synchronous submission error stops the later guard effects and
uses the native proxy's existing error path. A queue drop returns successfully
if its warning succeeds; worker sink failures do not raise on the producer.
The native proxy still enforces admission
before body completion under D55; this join does not establish source hook timing
for an unread request or exception continuation through the production container.

The [guard oracle](../proxy/tests/network_guard.rs) compares complete native
JSONL envelopes for resolved UDS identities and counters at submission with
actual source calls. Native
submission-failure cases check the retained partial effects.
[Owned HTTP tests](../proxy/src/http/traffic/tests.rs) check deny, warn, prompt
and homoglyph records, trusted identity, traffic ordering, denied-request
containment and separate CONNECT correlation. These checks do not prove approval
consumption, other security producers, file durability or independent acceptance.

### Canonical circuit, TestContext and API audit

Circuit request, response and Agent API reads now submit transitions at the
reached core operation. Open, reopen and close increment their counters before
submission and publish their new state afterward. Half-open publishes state
before submission; a synchronous failure then prevents the later admission slot
or next stats entry. Reset commits before its events. Successful returned
transition intents are already submitted and receive only separate diagnostics.
Ops events have no attribution or decision. Response transitions carry optional
request metadata only after its request hook has run; early responses do not
borrow the unconditional native diagnostic ID. Circuit denial events use trusted
UDS attribution. D55's early admission remains distinct from source body timing.

TestContext decision and applied request/response events now use the canonical
writer. Applied events have no decision or attribution object. Request metadata
is installed before decoding and submission; a synchronous failure retains that
metadata but stops the terminal context counters and later request logging.
A subsequent response can still use the metadata. Response decoding or
synchronous submission failure skips later recording and traffic logging.
Worker sink failures remain successful hook returns. No extra body read or drain
was added.

Agent API auth, guard, declaration and clear events retain their source field
omissions and precede later traffic events. Declaration mutations survive a
synchronous submission failure. The guard retains local containment even if
its audit submission fails. Operator events include failed authentication, task
updates and both budget/circuit reset events. Operator client text follows the
source first-header Latin-1 decoding and first-comma selection; it is not trusted
agent identity. Failed-auth audit retains the full request target independently
of route parsing. These operator call sites supply no agent attribution,
decision or approval.

The native `X-SafeYolo-Evidence-Error` header reports selected diagnostic failures.
It does not cover every canonical submission exception: circuit hook failures
and a TestContext head-hook failure can omit the header while preserving their
existing hook continuation.

[Circuit source controls](../proxy/tests/circuit_audit_order_source.py),
[TestContext source controls](../proxy/tests/test_context_audit_source.py),
[Agent API controls](../proxy/tests/agent_api_audit.rs) and the existing reset
oracles compare canonical fields and partial effects. [Owned circuit tests](../proxy/src/http/circuit_audit_tests.rs)
check response and denial ordering, early-response field omissions and later
response hooks after synchronous submission failure. [Owned Agent API tests](../proxy/src/http/agent_audit_tests.rs)
check actual shared-writer ordering through ordinary HTTP/1 dispatch.
[Operator tests](../proxy/tests/admin_transport.rs) compare parsed source auth
facts with owned listener records; their source parser control is not a source
listener comparison. This evidence does not establish OS thread-start exhaustion,
file durability, source-container auth exception continuation, rejected HTTP/2
API mutation-completion behavior, inactive service/credential producers or
independent acceptance.

The [network guard](../proxy/src/network_guard.rs) returns existing
warn/block responses and approval/audit intents around the same native policy
matcher. Its generated [Unicode data](../proxy/data/network_guard/README.md)
pins the shipped detector and Python 3.12 sanitizer, with an exhaustive scalar
oracle. The [pattern scanner](../proxy/src/inspection.rs) preserves rule order,
directional options, bounded URL inspection and complete-message decisions
within its documented regex compatibility scope. The scanner runs in the
development HTTP and WS/WSS paths; request URL/header inspection runs
before the outbound dial while request body inspection waits for validated
buffering. Response body inspection applies to known source-buffered responses
and leaves configured streaming responses uninspected. The network guard runs
when `policy_file` selects native policy. These paths do not establish complete
production control parity; the temporary adapter remains explicitly selectable.

The scanner now preserves Python's distinct literal and backreference case
rules. Unicode-insensitive literals and classes include all four I forms;
backreferences compare each scalar's pinned Python lowercase value. The latter
keeps dotless `ı` separate from `i` and advances by each subject scalar's UTF-8
width. ASCII references also match mixed text such as captured `äa` against
`äA`. These corrections use the same regex engine and cancellation flag.

Owner candidate checks cover the scanner behavior matrix, actual Python oracles,
315 inherited engine tests, allocation/cancellation regressions and a
46,593-comparison matrix with capture offsets. The new scalar comparison loop
allocates no buffer; later pool bookkeeping remains outside that measurement.
Generated ranges pin Python 3.12 / Unicode 15 `\w` and `\d` membership. The
scanner's generated name table contains 143,041 canonical scalar names and 473
verified scalar aliases. Ordinary names and aliases are case-insensitive;
algorithmic Hangul/CJK names require uppercase spelling. Named sequences and
malformed or unknown names remain source-invalid and are skipped individually,
as they are by Python's regular-expression parser. Uncovered properties and deeper grammar
remain explicit compatibility failures. Finite name/alias lowering, the
measured nesting boundary and bounded deep-parser stack handoff, scanner
error/warn/block behavior, compressed
fragmented messages with
control frames and cancellation before evidence publication have focused native
witnesses. Opaque delegated-search cancellation, streamed HTTP bodies and
unsupported text codecs remain explicit coverage limits. Python 3.12 accepts
both `(` and `(?:` nesting through depth 495 and rejects depth 496 with
`RecursionError`; the vendored parser retains that finite boundary and the
scanner compiles patterns deeper than its ordinary worker-stack handoff on an
8 MiB bounded child stack. This is a parser resource handoff, not an operator
pattern cap.
The traffic-view `~b` byte adapter applies the same source boundary before
its regular or Fancy engine; deep Fancy fallback uses that bounded child stack.
Full details and pinned data provenance are in the [engine patch](../proxy/vendor/fancy-regex/SAFEYOLO.md)
and [scanner data](../proxy/data/inspection/README.md).

The native [credential guard](../proxy/src/credential_guard.rs) uses that same
policy matcher and regex adapter. It preserves catalogue-first detection,
ordered headers, Bearer/Basic extraction, configured entropy checks, destination
decisions and warn/block responses. Private secret values become keyed
fingerprints in its output. The source evaluates network policy again, without
agent context, after each allowed credential decision; native comparisons retain
that ordering and its repeated budget charges. The shared addon-enable query
covers the network guard, credential guard and circuit breaker without a second
policy representation.

Owner checks compare 903 detector cases, the 17-rule generated catalogue,
112 actual Python addon/PDP operations, eight cached reload steps and 1,800
addon-enable queries. Native H1 and H2-inside-owned-TLS request-head activation
is covered by focused wire candidates; the parser-boundary subset (D48, ordered
duplicates and invalid-byte forwarding) is independently accepted at
`629e7754`, while full credential-path and production-chain acceptance remains
pending. Header values that contain invalid UTF-8 retain each source byte in a
private reversible security-text representation, and source `\uDCxx` patterns
match those bytes while parser-owned forwarding remains unchanged. Controlled
H1 and H2 origins cover matching warn/block and nonmatching forwarding. D33
broader regex grammar, uncovered Unicode properties, streamed/unsupported HTTP
text and full production-chain integration remain explicit compatibility gaps. Accepted
unusual scalar configuration forms remain a gap. A failed
native reload retains the prior complete snapshot; the source can partially
update configuration before failing.

The H1/H2 server parsers now retain original regular field order through narrow
local [Hyper](../proxy/vendor/hyper/SAFEYOLO.md) and
[h2](../proxy/vendor/h2/SAFEYOLO.md) patches. The private request owner joins
duplicate values with comma-space and preserves first name spelling. It removes
internal, hop-by-hop and Connection-nominated fields before network checks, with
the source WebSocket exception. Network development events retain the consumed
trace opt-in as `trace_requested`. Native NetworkGuard steps also reach the
shared trace store described below. The local Agent API releases captured bearer fields before
its response handling.

Header values remain raw bytes in a private wiping owner. The HTTP path releases
that header view before origin I/O; credential inspection consumes the ordered
request-head view at the native guard boundary.
Eligible flow recording keeps its own evidence copy until terminal submission.
Wiping these copies does not wipe the transport library's original buffers. Hyper
retains framing/body ownership, and the existing WebSocket validator still
checks actual handshakes. Body/query scanning remains outside the credential
adapter's scope. It does not add header admission rules or a second HTTP
parser. The source parser differences in the library patch notes remain
separate from metadata parity.

The header candidate passed 271 Rust tests, including the selected source
oracles, 15 documentation tests, strict all-target Clippy and formatting checks
on Linux aarch64. Its immutable binary passed 212 native-policy wire cases
across 213 proxy instances. The 162 recorded egress events reached owned peers;
cleanup checks passed. Fixture process proofs and external sampling cover 173
instances; the other 40 have configuration, native-event and final cleanup
evidence without a sampled-process claim. The regular nonbinary artifact scan
found no minted-bearer patterns.

Seventeen separate HTTP, HTTP/2 and HTTPS wire cases passed with the explicit
temporary Python adapter. Those checks found and verified the repair for a
strict-schema rejection: `trace_requested` stays local to native events and is
excluded from the adapter request. These checks are implementation evidence;
independent acceptance and the remaining production migration work are pending.

### Opt-in native security traces

An HTTP request or CONNECT can opt in with a nonempty `X-SafeYolo-Trace`
header. When request-header hygiene runs, the proxy consumes the header and
activates observation of reached native security hooks. The originating agent can then read
`GET /trace?request_id=<response-request-id>` with its Agent API bearer token.
The [trace store](../proxy/src/trace.rs) stays in memory and survives runtime
reload. The [API route](../proxy/src/agent_api/trace.rs) authenticates before
validating the request ID, then checks trusted caller identity. Foreign and
missing records return the same 404 response for the same queried ID. Header
and query hints cannot choose an owner. The component's conflict-identity
control does not resolve the separate runtime identity gap D60.

The store uses the source defaults: 300-second TTL, 1,000 global records,
200 records per agent, 128 steps per record and a 4,096-character serialized
details limit. It samples the existing `SAFEYOLO_TRACE_*` integer environment
settings at first runtime construction. Malformed values use the corresponding
default; there is no new positivity clamp. The details limit uses the source's
ASCII-escaped JSON length and applies when reading. Steps retain source order,
optional-field omission, scalar detail projection and truncation markers.
Reads do not refresh retention. Native late owner assignment applies the
per-agent limit, and TTL expiry scans past live records after append reordering
while preserving a capped record's retained step timestamp. Native reads return
a snapshot under the store lock; they do not reproduce Python's mutable-record
serialization races.

[NetworkGuard observation](../proxy/src/http/network_trace.rs) runs only at a
reached source step point. An allowed CONNECT records its allowance before
submitting its audit event. A subsequent synchronous audit failure adds an
error step. A denied request whose audit submission fails has no completed
block step. Store failures produce categorical diagnostics and do not change
the guard decision, counters, response or audit writes. Native guard failures
use `reason: GuardError`; that native category does not claim the source
Python exception class. Durations measure the native guard call. Native
admission can precede source request-body completion, as documented for the
existing HTTP pipeline.

[CircuitBreaker](../proxy/src/circuit_runtime.rs) records its reached request
and response decisions, including disabled or policy bypass, selected circuit
state, completed blocks and recorded response status. A core blocked decision
becomes a blocked trace only after canonical denial audit and response
construction succeed. An error records its typed category and preserves the
existing partial state. Diagnostic event-write failure remains separate from
hook failure. A circuit response exception still skips later response hooks.

[TestContext](../proxy/src/http/request_context.rs) records actual context
application, warning, block or nontarget outcomes. Deferred request timing
starts when the existing completion owner applies the hook; it excludes upload
time. Head-selected errors and blocks use their preparation interval. These
native intervals do not reproduce the source's single request-hook interval.
The existing [response capture](../proxy/src/http/test_context.rs) records
`response_recorded` after successful context audit, or `not_applicable` when no
context has been applied. A request decode or audit error can leave applied
metadata for a separately reached response. An aborted response has no response
step. A response that completes before request application can record
`not_applicable` without inventing a completed request hook.

Completed local denial/API replies carrying the existing traffic marker reach TestContext's
`not_applicable` response observation after circuit response succeeds and before
local recording and logging. Early local request returns still omit the native
request hooks they skip; they do not reproduce the source's later
`prior_response` request steps. Opt-in activation uses the existing local
header-hygiene boundary. The trace join adds no request drain or completion
observer. Typed source-compatible errors retain their class names; native-only
runtime, audit, allocation and poisoned-state errors remain native categories.
Trace-store failures cannot change hook continuation or evidence-error flags.

The source `not_loaded` field lists expected addon names absent from all retained
steps; it is not a runtime installation inventory. HTTP service gateway,
credential and pattern stages remain inactive. A stored CONNECT hook narrows
the source expected set to NetworkGuard. Outer CONNECT and enclosed HTTP retain
separate request IDs and share the transport connection ID. Reserved local
replies and the temporary Python policy adapter do not fabricate native guard
traces. The diagnostic probe uses the real native producers described below.

### Reserved probe and doctor diagnostics

The [probe route](../proxy/src/http/probe.rs) recognizes the exact
`_safeyolo.probe.internal` host without regard to ASCII case. Method, path and
port do not select the sink. Reserved CONNECT remains refused; a trailing-dot
spelling remains contained under the existing native rule and is not a positive
probe. Host-derived private state excludes probe records from FlowStore without
excluding their audit events, traces, logger, metrics or memory observations.

Buffered requests use the existing request-body preparation and independent
parser completion observer. The sink runs after the actual installed request
hooks complete. It constructs status 200 with the source JSON body and request
ID, then records `probe-sink / evaluated / probe_terminated`. No inactive
producer is reported as evaluated or disabled. A prior local reply whose empty
request and logger/metrics hooks completed retains its status and records
`probe_preempted`. Body-bearing early replies without that completion marker
still return before the sink. Neither path fabricates the later source security
request-hook observations skipped by native early returns.

The generated response uses the same memory, circuit, TestContext, recorder and
logger operations as a completed HTTP response. Applied context produces a real
response audit and `response_recorded` trace. A successful probe is not a prior
policy block: the circuit response reports its actual excluded-domain or
disabled decision. If JSON streaming is configured, source memory accounting
skips the response while provenance and logging retain its already constructed
body. The probe does not repeat request application or invent an upstream
response.

Unknown-length requests remain buffered until completion or the existing
encoded-body threshold is exceeded. Exactly 10 MiB remains buffered. When
preparation selects streaming, the native route refuses transport without
draining the rest, applying deferred context, or reporting probe success. The
independent outbound guard also refuses the probe before DNS or socket creation.
Canonical refusal evidence remains scoped to the trusted agent and contains no
invented request attribution. Diagnostic write failure cannot permit egress.
D64 records source/native failure-response differences; these tests do not
establish HTTP/2 probe behavior.

The [source oracle](../proxy/tests/probe_doctor_source.py) retains eight host
inputs, twelve actual selected sink-hook cases and twelve actual doctor
classifier cases. Classifier inputs are synthetic steps, not producer receipts.
The native [probe tests](../proxy/src/http/probe/tests.rs) compare source sink
bytes and steps and exercise owned HTTP/1 requests, context response evidence,
memory accounting and flow exclusion. [Upload controls](../proxy/src/http/probe/tests/body.rs)
cover held chunked input, threshold crossing, truncated requests and request-hook
errors. The opt-in [doctor/API test](../proxy/src/http/probe/tests/doctor_api.rs)
uses synthetic tokens and owned UDS listeners, fetches the actual native trace,
rejects a foreign agent's read, and feeds the fetched response to the source
doctor classifier. It requires the retained Python source environment; ordinary
probe tests use the pinned corpus without running Python.

The production six-name doctor manifest
remains unchanged. A native 200 with network, circuit and context receipts still
fails doctor while service-gateway, credential-guard and pattern-scanner are
missing. The source classifier inspects only the first request step for each
expected producer; a later error from the same producer can remain hidden from
its verdict. This consumer limitation is preserved in the oracle and does not
justify fabricating a passing pipeline.

The [source corpus](../proxy/tests/trace_source.py) exercises actual trace
storage and Agent API dispatch. [Native API tests](../proxy/tests/agent_api_trace.rs)
compare exact source response bytes, query ordering, identity and errors.
[Producer tests](../proxy/tests/network_trace.rs) verify reached trace/audit
order and single policy charging. [HTTP controls](../proxy/src/http/trace_tests.rs)
cover opt-in removal, agent scope, reload, CONNECT correlation, context request
and response effects, and failed observation. The [security-hook source corpus](../proxy/tests/security_trace_source.py)
uses 36 selected workflows and 47 actual decorated hook calls. Its ordered
audit and trace attempts retain partial effects and swallowed trace failures.
Native component comparisons and [HTTP circuit controls](../proxy/src/http/circuit_audit_tests.rs)
check the corresponding outcomes, open/deny sequence, early response and later
hook suppression. Source audit fault injection raises `RuntimeError`; native
poisoned-writer controls retain their separate native error categories. These
finite controls do not prove full container dispatch or transport parity.
Arbitrary Python objects, nonstring detail keys, lone-surrogate
strings and nonfinite record-creation timestamps remain outside the native
store representation. These checks are implementation evidence, not full
pipeline parity or independent acceptance.

### Memory, connection and WebSocket reports

The runtime installs one shared [memory monitor](../proxy/src/memory_monitor.rs),
independent of policy and Agent API availability. The owner retains its baseline,
connection state and counters across runtime reloads. Authenticated `GET /memory`
returns the global report; caller identity and query hints do not filter it.
Operator `/stats` includes `memory-monitor` immediately after `proxy`, including
when the temporary policy adapter is selected. Report sampling runs in the
existing request's blocking work after authentication. Report errors preserve
the source exception class when the native type establishes that class; native
failures use categorical names. Operator error messages remain content-free
and do not reproduce Python's original numeric exception text.

Each accepted agent connection creates one entry. CONNECT, intercepted inner
HTTP and WebSocket traffic retain that connection ID. Cleanup removes the entry
when its existing task finishes or is cancelled, including an unpolled task.
The native owner spans the existing upgrade drain; this does not reproduce the
source's exact disconnect timing relative to residual transport cleanup.
The [accepted-connection owner](../proxy/src/connection_tasks.rs) retains the
actual HTTP drivers, CONNECT/WS tasks, Hyper transport-executor jobs and blocking
WebSocket scanner jobs. One supervisor joins those tasks without holding the
registration mutex across an await. Normal CONNECT/101 completion retains the
adopted session. A failed main driver or CONNECT task cancels its descendants;
late registration drops captured work without starting it. Client removal
follows the final transport-task drain, before the proxy stops the audit writer.
D63 records the earlier forced-cancellation gap.

Each connection observes shutdown and allows ten seconds of transport grace.
After that grace, the supervisor cancels asynchronous or queued work and joins
actual task completion. An already-running blocking scanner, synchronous I/O or
a delayed task poll can extend cleanup beyond the grace period. The grace does
not impose a new message, CPU or connection-duration limit. Listener stop before
its first poll and direct listener drop retain their shutdown signals.
Standalone API authentication/report workers and anonymous WebSocket spill-file
creation and I/O still have separate task lifetimes. Their completion is outside
this transport drain. Ordinary `Proxy::drop` still starts shutdown without
awaiting tasks or audit drainage.

Finite owner tests cover forced cancellation, late registration, task failure,
running blocking work and the Hyper executor. Owned HTTP/1 tests cover direct
and CONNECT-nested WebSocket shutdown across reload, ordered memory close
records, an active response completing during shutdown, immediate listener stop
and direct listener drop. Those wire tests preserve normal behavior;
they do not execute forced wire shutdown or establish HTTP/2 protocol parity.

Reached request hooks count flows and retained decoded body bytes. The monitor
captures the original content encoding before header hygiene. Completed
nonstreamed responses contribute decoded bytes before the circuit response
hook, so a later circuit failure does not erase the memory observation.
Local JSON replies also honor the existing JSON streaming selection and domain
policy when deciding whether to count response bytes.
WebSocket counters observe complete data messages before inspection, including
messages later dropped by the scanner. Control frames and individual fragments
do not become message counts. The monitor retains no message payloads.

Memory errors keep mutations already made, including removal before a failed
close event submission. They cannot skip native security hooks or change a
WebSocket result to an inspection error. D62 documents the source containment
defect behind this deliberate difference. Memory observation alone does not
change HTTP evidence-error flags. Requests and responses still rely on their
existing parser completion owners; the monitor adds no drain or completion
observer. Aborted exchanges do not gain fabricated successful body hooks.

Native network, circuit and context admission can precede request-body
completion. Memory accounting at the existing completion point therefore does
not establish source-wide hook ordering. Completed local replies use their
existing reader or empty-request marker. The local Agent API handler still runs
before that observation, so `/memory` reports prior completed requests and does
not include its current request's flow count. Unmarked early replies can omit
source request accounting. These ordering and reachability gaps remain open;
the memory join does not change the Agent API completion boundary.

Reports show the ten busiest connections in stable order and all active
WebSocket sessions. The periodic event remains request-driven at the source's
60-second interval. There is no new timer, enable option, connection cap or
payload retention policy. Startup and report work use blocking workers. The
synchronous periodic hook yields a multithread Tokio worker while sampling;
synchronous and current-thread callers retain a direct sampler call.

The process sampler reads the serving process's `/proc/self/status`, with
current resident memory as a lower bound when the peak field is absent. A
missing procfs file retains the source zero result. The
[sampler controls](../proxy/tests/memory_sample_source.py) use owned in-memory
input and the pinned UTF-8 environment. They cover partial reads, malformed
values and text-decoding order; they are not measurements of a running proxy.
Source debug logging and the exceptional case where a close failure masks a
missing-token error remain outside the sampler's demonstrated behavior.

The [source oracle](../proxy/tests/memory_monitor_source.py) supplies explicit
memory samples and clocks while exercising actual callbacks, HTTP decoding and
canonical event construction. Its 24 source workflows and the thirteen separate
sampler controls establish the retained component contract. Native runtime
checks use deterministic synthetic samples, owned HTTP/WS peers and temporary
audit files. They exercise reload, body accounting, reports, cancellation and
security continuity, without reading operational process data. Actual RSS,
load behavior, supported-host validation and independent acceptance remain
unverified.

### Agent discovery reports

Authenticated `GET /agents` reads the [shared discovery owner](../proxy/src/agent_discovery.rs).
It returns the complete configured map with last-seen and idle fields for observed
entries. Query parameters and caller identity do not filter this report, matching
the source endpoint. Agent API authentication still precedes the read. Operator
`/stats` includes the same owner's `service-discovery` report before policy stats.

The development `agent_map_file` option defaults to the empty string. It selects
report metadata; trusted listener configuration continues to identify requests.
The owner caches the source floating-point modification time, preserves map order
and retains last-seen history across removal and reload. Clearing the configured
path retains the previous report. A newly published map stays published if a
later discovery-event submission fails. Malformed JSON and caught file errors
retain the reached source state. A configuration-hook failure is reported without
stopping the proxy; affected API reads retain their error response. No additional
map limit, expiry or address restriction is introduced.

Ordinary HTTP observations use the existing validated request-completion path.
The local Agent API observes the caller after producing its response, so
`/agents` reports the caller's previous last-seen value. CONNECT has a separate
observation before destination policy. Completed local replies can also update
last-seen. Early replies whose request never completes retain the existing native
completion differences. Native network decisions occur at headers, so a later
discovery refresh can follow their audit events even though source discovery
precedes the network request hook. Exact cross-hook event ordering remains
unverified. The owned discovery reconciler now exercises source identity
outcomes before the shared request-context snapshot is consumed by guards,
declarations, tracing and recording. Operator error reports retain source exception classes with native
content-free messages. The messages differ from Python error text. Existing
lone-surrogate and extreme JSON-depth differences also apply to map reads.
Filesystem fault and concurrent-reload equivalence remain bounded by the checks
described below.

The D60 source calls and native dispositions are:

| Map state at the request boundary | Source call and result | Native owned reconciler | Last-seen/event result |
| --- | --- | --- | --- |
| Matching entry (`alice`/`10.0.0.1`) | `_reload_map` → `get_client_for_ip` → resolved UDS identity | `reconcile` returns `resolved`, source `uds` | Updates `alice`; no identity event |
| Missing entry or map with a UDS owner | `get_client_for_ip` returns `unknown`; UDS remains authoritative | `reconcile` returns `resolved`, source `uds` | Updates the UDS owner; no identity event |
| UDS owner without a client IP | Listener identity is already resolved; no host-map lookup is needed | `reconcile` skips map reload and lookup, then returns `resolved`, source `uds` | Updates the UDS owner without map or discovery-audit side effects |
| Missing entry or map without a UDS owner | No trusted source resolves | `reconcile` returns `unavailable` | Suppresses last-seen and emits `security.agent_identity_unavailable`; an audit submission error remains a request error |
| Unreadable file or malformed JSON syntax | `_reload_map` catches `OSError`/`JSONDecodeError` and retains the prior reverse map | `reconcile` retains the prior map and returns its prior resolution | Only a resolved owner updates; otherwise the unavailable event is emitted |
| Invalid UTF-8 or valid JSON with a non-object top level | Request identity lookup catches its `UnicodeDecodeError`/`AttributeError`, while `/agents` retains the direct error | `reconcile` contains the reload error as `unavailable` with `lookup_error`; `/agents` retains the typed error | A trusted UDS owner remains resolved and updates only its own last-seen; without UDS no owner is published and the unavailable event is logged |
| Stale mtime after file replacement | `_reload_map` skips the unchanged mtime and retains the prior map | `reconcile` observes the same cached owner | Existing owner updates; a later mtime change can expose conflict |
| UDS `alice`, map `bob` for the same peer | Trusted sources disagree; owner is removed and conflict event is logged | `reconcile` returns `conflict` with no agent | Suppresses last-seen and emits `security.agent_identity_conflict` |
| Map changes after a flow starts | `flow_attribution` keeps the request snapshot; `detect_late_attribution_change` quarantines | The shared request-context snapshot is retained through completion and consumers cannot replace it with the later map result | No retroactive owner change; a late-change event records the quarantine |

The request snapshot has one projection for each existing consumer. This keeps
the accepted listener identity available as transport provenance while preventing
the map or a stale request field from becoming an evidence owner:

| Reconciled status | Network/credential guards | Reserved Agent API and gateway | Trace, traffic and recording |
| --- | --- | --- | --- |
| `resolved` | Receives the reconciled owner | Uses the same owner for scoped authorization and service selection | Carries the owner and attribution snapshot |
| `conflict` | Network guard fails closed when enabled; credential guard blocks | Scoped routes return `403`; reserved health/report routes stay local | Emits conflict attribution without an evidence owner; flow recording quarantines |
| `unavailable` | Receives no agent identity | Route handlers preserve source ordering: valid scoped operations return `403`, while caller-body/ID validation and direct evidence ownership retain their `400`/`404` outcomes; global/report routes remain local | Emits unavailable attribution and never creates an owner-bearing flow row |

The [source oracle](../proxy/tests/agent_discovery_source.py) uses owned maps,
synthetic identities and explicit clocks. The [API tests](../proxy/tests/agent_api_discovery.rs)
cover authentication, global reporting and unread bodies. The
[runtime checks](../proxy/src/http/agent_audit_tests.rs) cover two-agent reports,
local CONNECT containment, shared ownership, failed-reload recovery, caught
audit-submission failures and two concurrent persistent UDS connections across
a map replacement. Twenty source scenarios pass; five component tests
include replay of fourteen applicable source workflows. The joined native
selection passes 27 tests. The owned reconciler adds direct matching, fallback,
conflict, stale, unreadable, malformed and last-seen suppression witnesses.
The persistent two-agent fixture verifies the request-boundary snapshot and
ownerless conflict events through real host-owned listeners; independent
acceptance still needs the external black-box identity scenario.

### HTTP metrics in operator statistics

Authenticated operator `/stats` includes the shared [metrics collector](../proxy/src/metrics.rs)
after request-logger statistics. The collector retains its counters and uptime
origin across runtime reloads. It runs in both the native-policy and temporary
adapter lanes. It has no enable option, timer, persistence file or audit event.

Metrics observes reached request and response hooks after request logging returns
successfully. Quiet logging still reaches metrics. A logging exception skips
metrics for that hook; a later response hook remains independent. Metrics uses
the destination host and a separate timestamp taken after request logging.
Completed local responses count their actual block source. Source request
completion differences already described in this document still apply.

Successful responses include status 101 and redirects. Status 429 and 5xx have
separate domain counters; only status 504 increments the global error counter.
Transport failures do not fabricate response metrics. A valid early response
can count without a completed request. CONNECT, WebSocket messages and WebSocket
close events do not increment HTTP counters. Collection has no new domain limit
or ratio clamp.

The component also preserves the source JSON and Prometheus renderers. JSON
shows the twenty busiest domains in stable order, while problem-domain detection
and Prometheus cover all collected domains. The renderers retain source field
order, numeric forms, latency arithmetic and label sanitization. Source label
sanitization does not escape quotes or backslashes for Prometheus. Nonstring
block-source metadata remains a representation gap; the live native producers
use strings. Reports use a native owner lock; the source's concurrent partial
snapshots are not reproduced.

The Python client advertises `AdminAPI.metrics()`, but its server has no
`/metrics` route. The source renderers have no production caller. This change
exposes the existing basic `/stats` contract and adds no `/metrics` endpoint.
Renderer comparisons do not establish HTTP exporter availability.

The [source oracle](../proxy/tests/metrics_source.py) covers eighteen workflows,
and the [selected production-dispatch checks](../proxy/tests/metrics_dispatch_source.py)
cover eight logger/metrics ordering cases. The joined native selection passes
23 tests, including exact source report comparisons, owned HTTP traffic,
WebSocket upgrade counters, operator authentication and reload retention.
These checks are implementation evidence; they do not establish independent
acceptance or full production-chain equivalence.

### Configured passthrough connection events

For admitted direct CONNECT requests, the native proxy now emits canonical
`traffic.passthrough_start`, `traffic.passthrough_error` and
`traffic.passthrough_end` events when the logical destination matches the
existing passthrough configuration before dialing, or when a direct configured
IPv4 range matches the resolved peer after TCP succeeds. The [connection component](../proxy/src/ignored_host_logger.rs)
uses the shared audit writer. The events retain the source host, port, transport
and trusted listener agent/client facts. They contain no request ID, explicit
attribution, byte count or claim about inspected application content.

Logical matching happens before DNS and is retained for that physical
connection. A resolved-peer-only match is selected only after the successful
TCP connection; its event keeps the logical destination while the matcher uses
the physical IPv4 peer. Start follows successful TCP connection, before later protocol processing.
A final connection-attempt failure consumes the observation before reporting
the error. End follows release of the physical socket; one EOF or write
half-close does not end the session. Duration includes connection setup and
uses the source integer rounding. Existing sessions retain their match across
reload, while new connections use the new configuration.

Audit submission failures retain the source's reached state and do not deny an
otherwise allowed connection. A failed start submission still leaves an end
attempt due. Failed error/end submissions do not resurrect their sessions.
The [transport owner](../proxy/src/http/ignored_host.rs) closes its socket before
finalizing evidence and uses the existing shutdown lifetime. It adds no timer,
body reader or permission decision. Legacy `proxy.tunnel` diagnostics remain
separate from these canonical events.
Abrupt task teardown has no final-event drain guarantee.

The initial runtime scope excludes parent routes, ordinary HTTP connections and
SNI/Host aliases. Parent-address exemption semantics, the remaining lifecycle
matrix and full D29 acceptance remain unresolved. Earlier native reserved/admin containment can also
omit source connection observations; enforcement order remains unchanged.
Native connection-error wording and cancellation reasons can differ from the
Python stack. A canceled pending native attempt uses `connection cancelled`;
this does not establish source hook/semaphore cancellation equivalence.
A failure in the native pre-dial diagnostic write is reported as an attempt
error while retaining its existing transport failure; the source has no
identical diagnostic stage.

The [source oracle](../proxy/tests/ignored_host_source.py) passes eighteen
workflows. Four component tests include replay of all 71 lifecycle callbacks
from sixteen applicable workflows and comparison of 26 accepted canonical
records. Ten source matching observations remain separate from native matching.
The [eight connection controls](../proxy/src/http/ignored_host_tests.rs) cover
owned traffic, both half-close orders, refusal, negative controls, reload,
graceful shutdown and explicit ownership/failure boundaries. Writer poisoning
is tested at the already-admitted egress boundary because an earlier network
audit otherwise fails first. Pending cancellation bookkeeping is an in-memory
control, not a live cancellation equivalence test. The joined selection passes
18 native tests, including seven existing transport regressions. These are
implementation checks; full addon parity and independent acceptance remain
pending.

### Live operator HTTP and WebSocket inspection

The native [live view](../proxy/src/traffic_view.rs) retains ordinary HTTP
observations independently of the durable TestContext store. The authenticated
operator API exposes scope, flow lists, details, body snapshots and facets.
The existing `safeyolo traffic` command opens the native terminal inspector when
its admin client selects a verified Rust process. See the
[development workflow](DEVELOPERS.md#rust-proxy-development-backend) for controls and
the remaining scope/header projection differences.

A validated WebSocket upgrade promotes its HTTP row into an open session.
The [relay](../proxy/src/websocket_relay.rs) appends complete decoded data
messages before inspection and updates reached drop decisions before diagnostic
publication. The view retains dropped payloads. Control frames remain separate
from transcript messages. First-close facts are recorded before relay drain;
an unfinished upgrade or canceled relay becomes incomplete even while other
observers remain. Native failure categories do not claim a peer close reason.
The transcript uses the relay's immutable payload storage. Positional page reads
do not change the forwarding reader's offset. The private body endpoint returns
at most 64 KiB per page; offsets expose every retained byte without a new message
admission limit. An abandoned API read still releases its wiping response owner.

Retention counts HTTP bodies and complete WebSocket payloads globally, including
scope-hidden and dropped messages. It evicts eligible finished flows first,
using WebSocket end time where present. Remaining byte pressure removes older
nonempty messages from open sessions, preserving each latest message. The
[source fixture](../proxy/tests/traffic_websocket_source.py) and
[native replay](../proxy/src/traffic_view/tests.rs) compare six source pruning
cases. Native eager pruning still differs from the source hook/interval cadence.
The [owned duplex tests](../proxy/src/websocket_relay/tests/live_view.rs) verify
forwarding, dropped/spooled transcript content, open retention, close facts,
diagnostic failure and cancellation. Private API tests verify authentication,
paging and missing/trimmed results. Headless terminal tests cover selection,
page navigation, safe rendering and detach. These are implementation-team
checks; they do not establish independent acceptance or full M6 completion.

If native validation rejects a completed upstream 101, the view preserves the
observed status, headers, body and HTTP end time while displaying the reached
rejection error. No WebSocket session starts in that case. The focused controls
cover the actual handshake validator and retained model; they do not establish
an end-to-end rejected-upgrade exchange or Python invalid-handshake equivalence.
The [shared user filter](../proxy/src/traffic_view/filter.rs) is separate from
the six pinned scope fields. The authenticated `PUT /admin/traffic/filter`
accepts only `{"user_filter": expression}`; the terminal inspector's `f` prompt
uses that route. Compilation precedes publication, and failed edits preserve
the previous filter and pins. Retained-row snapshots share immutable HTTP and
WebSocket bodies. Regex execution, content decoding and spool reads occur
outside the observation lock on an API blocking worker. Direct authenticated
reads, facets and retention remain independent of this display filter.

Supported predicates and error behavior are listed in the
[development workflow](DEVELOPERS.md#rust-proxy-development-backend). Header and
body matching use byte patterns; URL and metadata matching use text patterns.
HTTP decoding uses the source's raw-content fallback for decoding value errors;
decoder type failures remain visible. WebSocket searches examine each retained
message separately, including dropped messages and bytes beyond a display page.
The shared setter validates the parenthesized user expression, preserving the
source distinction between explicit and implicit conjunction. Pinned-scope,
URL/header/metadata projections and native error categories retain the gaps
described above. Native regex compatibility and the remaining predicates are
incomplete.

Native scope always combines with the compiled user filter using AND. The
source's generated text permits a user expression such as
`~m POST) | (~m GET` to close its wrapper early. With an Alice pin, that source
expression also selects Bob's GET requests. Native matching keeps those rows
hidden and groups the effective display expression to reflect that behavior.
This is an intentional display-selection correction, not a new authorization
boundary.

The [source filter fixture](../proxy/tests/traffic_filter_source.py) records 130
parser/matcher observations and 26 shared setter steps. The
[native replay](../proxy/src/traffic_view/filter/tests/source_replay.rs) compares
125 observations and all 26 setter steps. Two regex observations return explicit
compatibility errors; three source URL-projection observations remain excluded.
Additional controls cover retained snapshots across replacement, eviction and
message trimming, searches across a spilled message's 64 KiB page boundary,
byte-identical forwarding after search, and filter error recovery through the
authenticated API. The joined selection passes 61 native and 104 CLI tests.
Strict all-target Clippy passes. These are implementation checks, not full
filter parity or independent acceptance.

### Selected-flow file export

The terminal inspector's `x` action selects `raw`, `raw_request`, `raw_response`,
`curl`, `httpie`, `har` or `zhar` and saves the selected flow to a local path. The authenticated
operator route receives the flow ID and format. The destination path stays with
the client. Command formats produce text and do not execute it.

The bounded runtime witness
[`live_operator_inspector_browses_scopes_and_exports_native_http`](../proxy/src/traffic_view_runtime_tests.rs)
drives one allowed HTTP request through the native agent listener while an
authenticated operator client lists the pending row, changes agent scope and
filter, reads detail and request/response snapshots, then exports every retained
format after completion. It checks HAR and ZHAR decoding and the command/raw body
bytes. This proves the joined native selection/export path for the controlled
HTTP case; it does not establish WebSocket, multi-row retention, terminal UI or
full inspector parity.

An export snapshots retained HTTP observations and WebSocket payload owners
under the live-view lock. Decoding and file-backed message reads occur after
that lock is released. Streaming retains those owners across later view changes
or pruning. A producer must explicitly finish the stream; losing the producer
before that completion produces an error rather than successful end-of-file.
HTTP decoding and command formatting still materialize complete decoded HTTP
bodies in memory. Output chunks and WebSocket payload reads are bounded.

Raw formats reconstruct HTTP messages using observed protocol, target, headers,
reason and available content. They do not preserve original wire bytes.
Captured trailer pairs preserve duplicate values, with normalized field names
and no original interleaving of different fields.
Combined raw output follows the source's available-side selection and includes
its direction-prefixed WebSocket payloads when both HTTP sides are present.
The raw transcript includes dropped messages and omits message type and drop
metadata. Those facts remain available in the inspector.

The [source export fixture](../proxy/tests/traffic_export_source.py) records
78 workflows and 390 formatter observations. Independent assertions cover
missing versus empty content, retained encoding headers for empty bodies,
repeated headers, command quoting, finite trailers, and full WebSocket bytes
across the display-page boundary. Added controls cover explicit default ports,
raw header bytes, valid ASCII, retained Unicode byte-order marks, and encoding
declarations in HTML, XML and CSS bodies. Command observations preserve exact
bytes even when the source string contains surrogateescaped header bytes.
Codec controls distinguish valid mappings, malformed byte sequences, unknown
labels and registered codecs that the native formatter has not implemented.
These source checks do not establish native formatter parity or independent
acceptance.

The native formatter replay checks 389 of those observations. It excludes
only curl's optional original-IP preservation output because the exporter
does not implement that option. The replay preserves the
input's explicit default ports and compares command bytes, including header
values that are not valid UTF-8. Some checks explicitly expect an unsupported
native representation for a source-supported codec; those checks record a gap
and do not establish equal output. The replay constructs retained observations
from the fixture; it does not establish complete runtime capture equivalence. Native
URL and header projections retain the differences documented in the development
workflow.
Command body decoding covers ASCII, Latin-1, UTF-8/16/32, 27 additional
single-byte families, and the implemented Shift_JIS, CP932, EUC-JP, GBK,
GB2312, GB18030, CP949 and Big5 paths. Source-derived validity and mapping corrections
account for differences in the encoding library. Team review compared all
single-byte inputs for those 27 families, all one- and two-byte inputs for the
reviewed multibyte paths, and all EUC-JP SS3 sequences. GB18030 four-byte evidence
includes the implementation comparison and independent boundary controls.

The Big5 decoder supports the four source registry aliases and preserves their
strict malformed-input behavior. It applies 260 source mapping corrections;
CP950 and Big5-HKSCS remain distinct codecs. Team review compared the final
Big5 decoder's validity and every output codepoint with CPython 3.12.14 for
all 65,792 one- and two-byte inputs, with no differences. The
[Big5 generator](../proxy/tools/generate_export_big5.py) validates the retained
correction mappings. Its check alone does not compare the encoding backend's
complete output domain.

The [registry generator](../proxy/tools/generate_export_codec_tables.py)
reproduces 420 normalized labels from pinned CPython 3.12.14 data. Unknown
labels return a decoding error. Registered but unimplemented codecs, including
CP950, Big5-HKSCS and transform codecs, return an unsupported representation. More codec
families, aliases and nontext transformations remain compatibility work; these
checks do not establish complete Python codec parity.

The [live view](../proxy/src/traffic_view.rs) now retains request completion,
first response-head observation and successful response completion separately
from exchange end. Missing observations remain null. It also retains upstream
connection identity, direct IPv4/IPv6 peer address and reached connection phases.
Parent connection facts do not become origin facts. These observations support
export formatting; original-IP curl export remains unimplemented.

The [row tests](../proxy/src/traffic_view/tests.rs) cover phase separation,
repeated callbacks, constructed address records and unavailable parent phases.
The [egress test](../proxy/src/http/ignored_host_tests.rs) checks an actual owned
direct IPv4 connection and transfers its owner through a tunnel slot. The
[HTTP runtime test](../proxy/src/traffic_view_runtime_tests.rs) holds the origin
response while checking the observed peer, connection phases and absence of
response phases. It then verifies preserved connection facts and reached response
phases across reload. CONNECT classification, failure retention, IPv6 transport,
parent routes and target TLS received static wiring review for these capture
fields; the tests do not establish their complete runtime capture equivalence.
The [HAR source fixture](../proxy/tests/traffic_har_source.py)
records 23 selections and two archive formats, including missing request-end
defaults and connection timing suppression within one archive. Byte-level
controls cover UTF-8 sampling, header decoding and size, query/form components,
charset fallback, Host-based display URLs and quoted cookies. Additional controls
separate an invalid MIME parameter from a valid charset, declared form charset
decoding from percent decoding, and an empty repeated Content-Encoding value
from an absent value. A separate control requires strict failure for invalid
WebSocket text. The generator also writes 28 deterministic
[input recipes](../proxy/tests/traffic_har_inputs.json) with original bytes,
body availability, phase observations and shared connection identity. These
inputs let native tests reconstruct the owned flows without deriving observations
from expected HAR output. These source observations alone do not establish native formatter parity.

Selected-flow HAR export now renders retained HTTP and WebSocket observations.
ZHAR streams the same archive through a level-9 zlib container. The HTTP response
remains an octet-stream attachment without Content-Encoding. Native creator
metadata identifies SafeYolo. Unknown charset failures follow the source text
fallback, while registered unimplemented codecs remain explicit errors. Big5
content uses the reviewed decoder and exports successfully.

The [HAR replay check](../proxy/tests/traffic_har_replay.md) compares complete
entries from all 27 owned HTTP recipes, including byte-aware surrogate escapes,
charset/form/encoding edges and standalone reused-connection timing. Its Python
command runs the Rust replay and performs the comparison; Cargo alone emits the
records without asserting full-entry equality. Focused tests also exercise large
file-backed text and binary WebSocket payloads in HAR and ZHAR, storage failures
in both formats, and retained-owner release after pruning. These are formatter
and ownership checks, not full production capture or archive-selection proof.

The [flow-dump source fixture](../proxy/tests/traffic_dump_source.py) records six
owned HTTP, WebSocket and TCP flows through the installed format-21 writer and
reader. It preserves binary fields, missing versus empty bodies, edit backups,
errors and WebSocket dropped/injected flags. Nine scalar controls distinguish
the typed-netstring byte and Unicode tags. Six reader controls include future
versions, unknown flow types and a valid record followed by corruption.
Temporary-file checks exercise overwrite, append, missing-parent failure and
the dump output produced even with a `.har` suffix. Console load adds fresh IDs
and retains records loaded before an error.

Seven source HAR-reader controls cover JSON and UTF-8 BOM detection, rejected
leading whitespace and zlib input, malformed JSON, an empty archive and a valid
entry before a corrupt entry. Imported HAR content is decoded, while request
versions, response reasons and WebSocket extensions can lose information.
The source importer supplies loopback client endpoints and derives connection
times from the HAR entry interval. It also assigns the scheme's default port
to the supplied server IP, even when the request URL has another port. These
are reconstructed compatibility fields, not observed transport facts. The
fixture retains those values and omits only generated IDs and flow creation
time; repeated reads must still produce fresh IDs. These checks do not establish
native dump or HAR import, historical-version migration, UDP/DNS import, startup
or addon lifecycle behavior, continuous save/rotation, or web import.

All-flow HAR archives and lifecycle behavior, flow-dump export and import, web
inspection and the exposed edit/replay workflows are deferred under the
[first-release traffic scope](#first-release-traffic-scope). The Python proxy has
not been removed or cut over.

[Rust migration CI](../.github/workflows/proxy-rust.yml) runs the focused native
checks on Linux and macOS. A workflow definition is not evidence that those
jobs, the macOS VM relay or the Linux guest mount have passed.


### Operator service authorization

The authenticated native operator route `POST /admin/agents/{agent}/services`
accepts the existing CLI's service, capability and vault credential names. It
validates against the service catalog in the accepted policy snapshot, then
updates the existing agent in the latest locked TOML file. Other policy fields
and service bindings remain intact. No vault lookup or immediate policy reload
occurs in the handler. The existing watcher owns later activation. A focused
native workflow covers the authenticated Agent API request, operator
persistence, running watcher, Agent API discovery, retry through two independent
UDS identities and a controlled HTTP origin. The origin sees the exact synthetic
vault credential, never the gateway token; unmapped destinations and stale
tokens are rejected before origin delivery. HTTP injection uses the explicit
service `auth.allow_http: true` exception; the default HTTPS refusal remains
covered by credential-injection tests.

A blocking worker owns both persistence and the subsequent canonical
`admin.agent_service_authorized` audit attempt. Canceling the request does not
cancel that worker or discard its audit responsibility. The process-owned
service-mutation drain closes admission before listener shutdown, joins every
admitted worker (including one whose request was canceled), and only then
stops the audit writer. The listener does not resubmit that event. A failure to
submit evidence after persistence does not undo the saved binding; an audit
attempt is not a durability guarantee.

The ownership chain is explicit: authenticated request validation owns
admission, `ServiceMutationOwner` owns blocking persistence execution, that
same worker owns the canonical audit submission, and `Proxy::shutdown` owns
the admission stop followed by the worker join. A worker rejected after the
admission stop performs no persistence. Blocking filesystem work can still
extend graceful shutdown; forced process termination and ordinary `Drop` do
not claim this drain.

The [operator route tests](../proxy/src/admin_api/services/tests.rs) cover
authentication before body/file access, validation order, absent runtime owners,
replacement and preservation, inline agent tables, changes made after the
accepted snapshot, lock failure, and audit failure after persistence. A held
file-lock control cancels the actual request future, then releases the worker
and observes the binding and exactly one event. The shutdown-owner control
closes admission, joins that canceled worker before stopping the writer, and
rejects later work. A later loader invocation checks the saved binding; this
does not prove a running watcher or the complete service authorization and
forwarding workflow.

The bounded #638 state transition
[`selected_python_native_python_service_authorization_rollback`](../proxy/tests/gateway_contract_workflow.rs)
adds the cross-runtime state exercise for one service route. The fixture
starts with no authorization, then native operator requests write the service
authorization, a contract binding, and a remembered grant. A real request
injects the synthetic vault credential at a controlled origin. The selected
Python comparator reads the native service record and IDs, removes the grant
and binding through its `ServiceGateway` writers, and removes the service
record through the locked TOML round-trip writer used by the source agent
store. A fresh native process reads that rollback with no authorized service
token and rejects the request with no additional origin contact. This is
bounded to one service and route; OAuth refresh, alternate catalog cases and
installed rollback remain separate gaps.

The native plumb owner applies the same process-lifetime rule to its blocking
SQLite calls, memory projections and conversation long polls. Agent request-chat,
message and leave operations, plus operator approval, denial and close, keep
their committed projection and canonical audit attempt inside the process-owned
operation. Shutdown closes plumb admission and wakes active polls before
listener drain, then joins admitted operations and their store calls; a
canceled caller drops only its response receiver. New calls return the existing
503 unavailable response after the stop fence. The focused plumb controls
`shutdown_wakes_waiters_and_closes_new_plumb_admission`,
`canceled_store_call_remains_owned_until_plumb_drain`,
`canceled_request_chat_keeps_projection_and_canonical_audit` and
`canceled_message_keeps_projection_and_canonical_audit`,
`canceled_leave_keeps_projection_and_canonical_audit` and
`canceled_approval_keeps_projection_and_both_canonical_audits` cover these
boundaries. `request_audit_submission_failure_keeps_committed_projection` and
`admin_audit_submission_failure_keeps_committed_projection` inject writer
failure and verify that committed state remains durable. The existing
persistence test opens a second owner on the same state directory and verifies
the projection; it does not claim a process restart. Blocking SQLite work can
still extend graceful shutdown, and abrupt termination or ordinary `Drop` do
not claim this drain.

Persistence uses the existing TOML transaction helper and its durability-failure
rollback behavior. Truthy non-string request fields remain native representation
errors; arbitrary source JSON values and non-TOML mutation parity are unproved.
The [request-access source fixture](../proxy/tests/gateway_access_source.py)
separately records ten owned source dispatcher cases, including contract
challenges and audit-before-pending response ordering. Native covers the
simple no-contract request-access path and trusted UDS identity; contract
request-access behavior remains an explicit compatibility response.
