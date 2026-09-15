# Rust proxy capability inventory

This inventory supports [issue #620](https://github.com/craigbalding/safeyolo/issues/620).
The source baseline is `4116c7ee3d44c623e9d89ae60c14ce671d0f295d` on
`master`, inspected on 15 September 2026. Implementation starts on
`feat/rust-proxy-620`. The baseline lockfile selects mitmproxy 12.2.3.

**Status: source inventory, awaiting independent review.** A named test below
means an existing executable check was located. It does not mean the test ran,
passed, covered the production chain, or passed against Rust. Run manifests
must identify the source commit, backend, platform, dependency versions, exact
test selection and results. Future checks are marked **required**. No production
deletion or milestone acceptance is established by this document.

The initial Rust development slice covers trusted Unix domain socket (UDS)
ingress and basic HTTP through a temporary Python network policy adapter.
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

The issue, [security model](../SECURITY.md), observable behavior and documented
public contracts establish the retained outcomes. The tables describe current
behavior unless they explicitly identify a discrepancy. Replacement paths name
responsibilities, not a required Rust module or callback hierarchy. Unless a
row says otherwise, its intended behavior change is **none**.

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
| 16. `addons/credential_guard.py` | Detect HTTP request-header credentials, evaluate destination-first permissions and budgets, and return configured block/warn outcomes. | Policy events use keyed fingerprints instead of raw credentials; identity conflicts fail closed. Bodies and WebSockets belong to the pattern scanner. | Credential detection/selection and policy evaluation; remove addon and flow-to-policy adapters when replaced. | `test_credential_guard.py`, `test_credential_catalog.py`, `test_policy_budget_contract.py` |
| 17. `addons/pattern_scanner.py` | Apply ordered URL/header/body rules and built-in sets; scan raw and once-decoded bounded URLs without rewriting them; inspect complete text/binary WebSocket messages in each direction. | Block/log modes and directional overrides remain; WebSocket inspection errors drop the message with content-free evidence. | HTTP inspection and message-aware WS/WSS relay; remove callback and message adaptation. | `test_pattern_scanner.py`, `test_shipped_security_config.py`; compressed/fragmented wire cases required. |
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
| Credential/service state: `core/{vault,service_loader,service_paths}.py`, `services/`, `policy/compiler.py`, `commands/vault.py` | Retain service-source precedence, authoritative registry snapshots, active token/binding/grant behavior and vault material; do not require credential re-entry. Vault is 16-byte salt followed by Fernet-encrypted YAML, using PBKDF2-HMAC-SHA256 with 480,000 iterations. | Rust-compatible vault and registry/state access. Remove proxy dependence on Python crypto/YAML only after round-trip/rollback tests; CLI may retain libraries. | `test_vault.py`, `test_service_loader.py`, `test_contract_enforcement.py`, `cli/tests/test_vault_cli.py`, `cli/tests/test_service_sources.py`; cross-runtime encrypted round-trip required. |
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
| POST | `/admin/policy/validate`, `/admin/policy/baseline/approve`, `/admin/policy/baseline/deny`, `/admin/policy/host/{rate,allow,deny,bypass}`, `/admin/circuit-breaker/reset`, `/admin/budgets/reset`, `/admin/gateway/grant`, `/admin/gateway/contract-binding`, `/admin/plumb/{approve,deny,close}`, `/admin/agents/{agent}/services`, `/admin/agents/{agent}/desktop/present` |
| PUT | `/modes`, `/plugins/{name}/mode`, `/admin/policy/baseline`, `/admin/policy/task/{id}`, `/admin/proxy/mode`, `/admin/proxy/ignore-hosts`, `/admin/proxy/web-tailnet`, `/admin/traffic/scope` |
| DELETE | `/admin/gateway/grants/{id}`, `/admin/agents/{agent}/services/{service}` |

The authenticated WebSocket `/admin/events` streams selected operator audit
events through `core/operator_event_server.py`. The web application's traffic
routes expose stock flow operations through the shared master. Compatibility
concerns the retained user workflows, not every undocumented mitmproxy endpoint.

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

Required wire fixtures cover fragmentation across pattern boundaries, text
and binary directions, masked frames, subprotocols, compressed messages,
control frames between fragments, close/error handling and inspection faults.
Distinguish maximum frame/message assembly from retained-view limits. Measure
bounded memory under long-lived traffic and large fragmented messages; do not
silently reduce accepted message sizes to a library default.

## Discrepancies and unproven claims

| ID | Source-backed finding | Classification and required resolution |
|---|---|---|
| D1 | `docs/TLS_CERTIFICATE.md` labels `mitmproxy-ca-cert.cer` as DER and describes `mitmproxy-ca.pem` only as the private key. The locked dependency writes PEM in `.cer`, and key plus certificate in `-ca.pem`. | Documentation discrepancy. Use actual formats for fixtures; correct the operator document when the TLS migration is implemented. No CA conversion or rotation is authorized by this discrepancy. |
| D2 | Production sets `stream_large_bodies=10m`; the SSE addon sets response streaming. Its docstring says request bodies remain fully inspected, but large-body transport streaming and scanner `get_text()` require separate examination. Buffered-body hooks cannot establish inspection of bytes already forwarded. | Coverage discrepancy requiring live request/response tests. Preserve configured streaming behavior and report actual coverage. A concrete bypass of an applicable blocking rule requires a regression and repair; do not claim full inspection from hook execution. |
| D3 | Raw CONNECT tests use a client-first `raw-hello` exchange with `--tcp-hosts`; HTTPS/WSS live fixtures set `ssl_insecure=true`. | Test coverage limits. These fixtures prove neither real SSH/server-first/half-close nor upstream certificate validation. Keep separate real-client and invalid-certificate tests. |
| D4 | CONNECT authority, inner Host/HTTP/2 authority, SNI and actual outbound target are represented separately by the framework. Existing admission tests do not establish the full mismatch matrix. | Unresolved authority-boundary coverage. Test each value independently. A changed inner authority must not inherit permission for another destination. Never fall back to opaque transport after parser/TLS failure. |
| D5 | Routine credential events use fingerprints; FlowStore retains request/response bodies and ordinary headers, redacting the gateway-injected header; the trusted operator's interactive view is broader. `SECURITY.md` uses an unqualified statement that raw detected credentials are never stored/logged. | Evidence-scope documentation discrepancy. Preserve authorized raw evidence and injected-secret protection; verify each surface with synthetic secrets. Do not implement global redaction as an assumed parity requirement. |
| D6 | Completed WS messages are inspected and retained/pruned, but the dependency assembles an incomplete message before the hook. | Memory/coverage limit requiring measurement. View pruning is not bounded transport assembly. Establish existing workloads before selecting a compatible bounded strategy. |
| D7 | `flow_recorder.py` collapses query parameters into a dictionary for one evidence column, while the original URL remains available. | Representation limitation. Preserve outbound query order/duplicates and original URL evidence; do not compare only the lossy dictionary or normalize away signed-query behavior. |
| D8 | The default production command only explicitly selects lazy connections when sinkhole routing is enabled. The live denial fixtures vary eager/lazy for CONNECT, not every plain-HTTP security decision. | Side-effect coverage gap. Observe DNS and socket attempts independently for denied plain HTTP, CONNECT and malformed local requests. Do not equate an HTTP block response with zero egress. |
| D9 | Independent wire review found that the baseline's exact reserved-host matchers permit the DNS root-dot spelling, such as `_safeyolo.proxy.internal.`, to reach a configured parent with a bearer header. | Concrete containment defect. Rust now removes one DNS root dot only for reserved-name classification, before policy and at the shared egress boundary. It also refuses these names as configured parents. Original request bytes for other destinations are unchanged. The historical Python baseline retains the defect; its repair is tracked separately. |
| D10 | Hyper normalizes identical duplicate Content-Length fields and removes Content-Length when Transfer-Encoding controls framing. The old parser rejects those requests. Hyper rejects unequal duplicate lengths. The initial Rust slice also accepted duplicate Host fields. | Protocol difference requiring explicit wire tests. Rust rejects duplicate Host fields before policy or upstream contact. Do not equate normalization to a demonstrated smuggling flaw, or add a second HTTP parser solely to reproduce every rejection. Verify one unambiguous outbound framing and exact delivered bytes. |

## Deletion map and evidence still required

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

The [initial baseline manifest](../tests/proxy_migration/baseline.json) records
45 existing live tests, six shared backend scenarios and measured smoke
workloads. The [harness contract](../tests/proxy_migration/CONTRACT.md) gives
replay commands and the exact limits of those measurements. It records
denial-response and probe differences instead of masking them. Full M1
acceptance still requires the missing production, API and sustained workloads.
Existing unit tests, live tests
with a partial addon chain, the production-chain launcher and full host/guest
black-box tests establish different claims. Preserve that distinction in run
manifests and differential results.

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

The Rust fixture launches `safeyolo-proxy --config PATH` and a separately
named [temporary network-policy adapter](../tools/proxy_migration/temporary_policy.py).
The JSON configuration provides `listeners` with `agent_id` and `socket_path`,
`temporary_policy_socket`, `readiness_file` and `event_log`. Optional
`parent_proxy`, `upstream_ca_file` and `via_token` select parent transport.
The listener configuration supplies identity; request headers cannot select it.
`SIGHUP` reads the configuration again. `SIGTERM` initiates shutdown.

The adapter socket is private host state and must remain outside agent mounts.
The adapter receives header names and request metadata, never header values or
body bytes. It uses the existing Python policy decision point in blocking mode.
It does not supply credential inspection, service operations or the complete
NetworkGuard response and approval workflow. The Rust binary therefore remains
a development slice; its Python dependency is explicit and temporary.

The fixture checks decisions, delivered bytes, destination ports, generated
IDs and trusted attribution. Its `proxy.request` and `proxy.egress` events are
migration evidence, not replacements for production JSONL or traffic APIs.
Both reserved local destinations remain local; the Rust slice returns an error
because their full workflows have not been implemented. It rejects CONNECT
and WebSocket upgrades until their transport and inspection contracts exist.

[Rust migration CI](../.github/workflows/proxy-rust.yml) runs the focused native
checks on Linux and macOS. A workflow definition is not evidence that those
jobs, the macOS VM relay or the Linux guest mount have passed.
