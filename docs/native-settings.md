# Native settings reference

Use `config.toml` for runtime settings and `policy.toml` for host policy and
named controls. Relative paths belong to the directory containing the selected
configuration or policy file. The native loader never reads `config.yaml`,
`addons.yaml`, or a generated `native.json` as a fallback. Unknown configuration
keys and old addon keys produce validation errors.

This inventory binds #816 P2 once to starting source
`4344e9928ac7808ec1d63aa071932a085ee0ce32`. It covers the effective inputs in
`cli/src/safeyolo/config.py`, `rust_proxy.py`, the native `Config`, detector
settings, and native host readers. It records remaining consumers owned by
#817/#818. The inventory does not claim those separate host/helper outcomes.
See [native policy commands](native-policy.md) for installation and use.

## Operator entry responsibilities

[Native operator commands](native-operator.md) use one selected instance and
session-local target. This map covers the reached entries for #821. It does not
claim #817 terminal proof, #820 workflow launch or the #822 package-wide audit.

| Entry | Native owner and retained boundary |
| --- | --- |
| Direct `traffic`, `approvals`, `logs`, `diagnose` | `proxy/src/bin/safeyolo.rs` dispatches to `operator_commands.rs`. `native_client.rs` shares the existing policy transport. Direct traffic reads carry explicit selection; they do not inherit or change a viewer's scope. Logs/diagnosis retain local access when the API is unavailable. |
| `inspect` | The same native dispatch reads configured identities and existing approved Factory role mappings. State/evidence/decisions use the current Admin owners. Selection belongs only to this terminal session. #820 owns provisioning and workflow launch. |
| Inspect `attach` | Fixed delegation to the same installed native CLI's `agent attach`, with the selected configuration/name. #817 owns that command, terminal transport and actual effects. This entry reuses that operation and adds no lifecycle implementation. |
| `helper show`, `diagnostic`, `prepare` | Native Agent API client, using Helper's existing proxy/token or its granted Unix socket. Shared identity, evidence and approval owners enforce selected reads and typed preparation. No operator credential enters Helper. |
| Commander decision/reconnect | Swift `MutationPlan`, `SafeYoloClient` and the common native resolver. The client's session projection rereads known request IDs after reconnect. An unavailable read stays unavailable; a lost mutation response is not reposted. |
| HTTP/WebSocket body and exports | Existing process-owned traffic view/exporter; retained `raw`, `raw_request`, `raw_response`, `curl`, `httpie`, `har`, `zhar`. Native selection/body/transcript/file consumers replace the Python presentation. One HTTP exchange and one WebSocket transcript supply the finite consumer checks. |
| Retired presentation | `commands/traffic.py`, `traffic_inspector.py`, the hidden `tmux traffic` / `return-to-agent` adapters and their UI-only tests are removed. Generated tmux configuration retains the status/watch integration. Pane navigation, tail/pins, formatting and marked batch exports belonged to that UI. The chosen native path retains selected evidence and all seven exports. Python API/blackbox transport remains test tooling at this boundary. |

The raw formats retain forensic observations, command formats retain displayed
requests, and HAR/ZHAR retain interoperable archives. The existing native exporter
already supplies them. Their cost here is native selection and one consumer check
per format; no exporter redesign is needed. This applies #821's operator-directed
first-handoff retention decision. The old keyboard UI is retired because the
chosen continuous path uses the same small native command session for state,
evidence and approvals. Capture, policy and canonical outcome owners are retained.

## Runtime settings

All entries below are retained. Configuration values override built-in defaults.
Native audit, trace, capture and Command Centre settings override the corresponding
legacy environment settings. Proxy/CA environment variables remain available to
host tools. File paths are strings; integer ports are in the existing 0–65535
range. Port zero selects an ephemeral Admin listener, while an enabled Command
Centre events listener requires a nonzero port.

The proxy loads these values through `native_config::read`. Audit, trace, capture
and operator listeners keep their startup settings; restart the process to change
those settings. Policy apply reloads policy controls without restarting. Storage
pruner limits retain the existing positive-value requirement.

Capture byte/preview limits retain the existing negative slice handling.
A nonpositive capture queue size retains unbounded mode. These values are
passed to the existing storage/queue owners without a new positive-only rule.

| New config.toml key | Type and default | Starting input and consumer |
| --- | --- | --- |
| `listeners` | Array of tables; `[]` | Generated native listeners; native UDS listener preparation. Each table has string `agent_id`, `socket_path`, and optional `source_id`. The listener supplies identity; `source_id` supplies the declaration slot. |
| `agent_map_file` | Path; empty | Generated discovery map path; native agent discovery. Empty uses listener identity alone. |
| `data_dir` | Path; `data` | Generated runtime directory; HMAC, Agent API and durable instance identity. |
| `policy_file` | Path; `policy.toml` | Policy path; shared native policy compiler and watcher. |
| `admin_port` | Integer; `9090` | `proxy.admin_port`; native loopback Admin listener. |
| `admin_api_token_file` | Path; `data/admin_token` | Generated operator token path; Admin authentication and native CLI. |
| `readiness_file` | Path; `data/ready.json` | Generated readiness path; accepted process/listener marker. |
| `audit_log_path`, `event_log` | Paths; `logs/audit.jsonl`, `logs/events.jsonl` | Generated log paths; canonical audit writer and separate runtime diagnostics. |
| `circuit_state_file` | Path; `data/circuits.json` | Generated circuit snapshot path; existing circuit state owner. Empty disables snapshots. |
| `gateway_builtin_services_dir`, `gateway_services_dir` | Paths; absent | Generated service directories; shared service registry. Set both together. Catalogue and delivery remain #819. |
| `parent_proxy`, `upstream_ca_file` | URL/path; absent | `proxy.upstream_proxy`, `proxy.upstream_ca_cert`; native upstream transport and trust loader. |
| `tls_ca_file` | Path; absent | Generated signing CA path; native TLS interception. |
| `ignore_hosts` | String array; `[]` | `proxy.ignore_hosts`; existing exact TLS bypass entries. |
| `via_token` | String; absent | `proxy.via_token`; existing Via-loop detection. Explicit values retain RFC-token validation. |
| `admin_shield_extra_ports` | String; empty | Generated/host input; existing local Admin endpoint shield. |
| `agent_api_enabled` | Boolean; `true` | Generated setting; native reserved-host Agent API. |
| `sse_streaming_enabled`, `sse_stream_json` | Booleans; `true`, `false` | Existing native streaming inputs; response streaming consumer. Host exceptions remain policy. |
| `flow_store_enabled`, `flow_store_db_path` | Boolean/path; `true`, `logs/flows.sqlite3` | Generated capture inputs; existing FlowRecorder and FlowStore. Context and evidence authority still govern capture. |
| `flow_pruner_max`, `flow_pruner_max_body_bytes` | Integers; `5000`, `1073741824` | Existing inspector inputs; existing FlowStore pruner. Active flows remain retained. |
| `plumb.max_participants`, `plumb.max_message_bytes` | Integers; `8`, `1048576` | Existing plumb settings; native conversation admission. A zero message-size limit disables that cap. |
| `plumb.message_page_limit`, `plumb.default_ttl_seconds` | Integers; `200`, `3600` | Existing plumb settings; native history read and conversation TTL. Existing zero/default handling remains. |
| `capture.max_request_body_bytes`, `capture.max_response_body_bytes` | Integers; `1048576`, `4194304` | Former flow-store tuning; FlowStore body limits. |
| `capture.preview_text_chars`, `capture.compress_bodies`, `capture.queue_max` | Integer/Boolean/integer; `8192`, `true`, `500` | Former flow-store tuning and `SAFEYOLO_FLOW_QUEUE_MAX`; native body preview/storage and recorder queue. |
| `trace.ttl_s`, `trace.global_max`, `trace.per_agent_max` | Integers; `300`, `1000`, `200` | Former trace environment inputs; existing TraceStore retention and capacity. |
| `trace.steps_max`, `trace.details_max_bytes` | Integers; `128`, `4096` | Former trace environment inputs; existing TraceStore step/detail bounds. |
| `audit.queue_max`, `audit.max_bytes`, `audit.backups` | Integers; `10000`, `50000000`, `5` | Former audit environment inputs; existing audit queue/rotation. `max_bytes` replaces the MB-valued environment input. Existing owner handling of zero/negative limits remains. |
| `agent_launcher.default`, `agent_launcher.tmux_session` | Optional string/string; absent, `safeyolo` | Former config.yaml readers; native host lifecycle now reads the same TOML loader. An explicit agent launcher wins, then the host default, then the existing built-in selection. #817 owns installed host launch preparation and root/asset binding. |
| `command_centre.enabled`, `command_centre.events_port` | Boolean/integer; `false`, `9091` | Former Command Centre inputs/environment; native Admin preparation and authenticated event listener. Fresh init creates `data/instance_id`. |
| `command_centre.share`, `command_centre.tailnet_admin_port`, `command_centre.tailnet_events_port` | String/integers; `local`, `9443`, `9444` | Former Command Centre inputs; existing native Tailnet publication. Share is `local` or `tailnet`; the Tailnet ports must be nonzero and distinct. #817 owns the complete operator sharing workflow. |
| `desktop.size`, `desktop.present_host_port` | String/integer; `auto`, `0` | Retained desktop inputs. The new loader preserves their values; #817 owns the remaining native presentation/remembered-size consumer. Existing Python presentation is outside this native policy entry point. |
| `web.host`, `web.port`, `web.tailnet_enabled`, `web.tailnet_port` | String/integer/Boolean/integer; `127.0.0.1`, `8081`, `false`, `443` | Former `proxy.web_*` inputs. The new loader preserves their values; #817 owns native web/share startup and helpers. |

`reload_id` is a string used by the existing host listener writer to correlate
an accepted reload. It is generated state, not a second policy input. The writer
preserves TOML settings when changing native listeners. #817 retains responsibility
for installed host lifecycle and helper provisioning.

Sandbox service inputs remain in their existing concrete owners: host-to-service
bindings in `policy.toml`, service definitions with route methods/paths, and agent
identity/runtime metadata. The proxy selects the provider agent from the shared
gateway snapshot and the guest port from the requested destination, then calls
`provider_stream::open`. There is no additional sandbox-service settings table.
#818 owns guest lifecycle/port access; #819 owns service delivery. #816 checks
binding/constraint/risk compilation and scope, without claiming those outcomes.

## Named policy controls

The following fields replace the effective detector settings. They use the shared
policy compiler and existing detector implementations. Explicit fields override
these defaults. `policy show` identifies each control field's source, including
nested credential settings. Native `/config`, `/trace`, `/stats`, audit envelopes
and runtime diagnostics use control names. The Agent API `/config` returns the
existing sensor rules and named controls; operator service bindings and agent
settings remain in `policy show`. Raw context and evidence values are preserved.

| New policy.toml key | Type and default | Starting input and consumer |
| --- | --- | --- |
| `controls.network.enabled`, `action`, `homoglyph` | Boolean/action/Boolean; `true`, `block`, `true` | Network enabled/mode/native flags; existing NetworkGuard. `action` is `block` or `warn`. |
| `controls.credentials.enabled`, `action` | Boolean/action; `true`, `block` | Credential enabled/mode/native flags; existing CredentialGuard. Network permission remains separate. |
| `controls.credentials.detection_level` | String; `standard` | Existing detection level; CredentialGuard recognizes `standard` and `paranoid`. |
| `controls.credentials.standard_auth_headers` | String array; authorization, x-api-key, api-key, x-auth-token, apikey, x-goog-api-key | Existing detector header names; CredentialGuard header detection. |
| `controls.credentials.use_default_credential_rules` | Boolean; `true` | Existing native detector input; CredentialGuard default rules. |
| `controls.credentials.safe_headers.safe_patterns` | String array; `[]` | Existing effective safe-pattern input; CredentialGuard exclusions. |
| `controls.credentials.entropy.min_length`, `min_charset_diversity`, `min_shannon_entropy` | Numbers; `20`, `0.5`, `3.5` | Existing entropy tuning; CredentialGuard heuristic. |
| `controls.patterns.enabled`, `builtin_sets` | Boolean/string array; `true`, `[]` | Existing scanner tuning; shared Scanner compilation. The empty builtin default preserves the accepted fresh native foundation. Select `secrets` explicitly to enable that existing set. |
| `controls.patterns.request`, `response`, `websocket_request`, `websocket_response` | Actions; all `block` | Existing inspection flags; independent directional scanner enforcement. |
| `controls.test_context.action`, `inject_declared`, `declared_ttl`, `target_hosts` | Action/Boolean/positive integer/string array; `block`, `false`, `900`, `[]` | Existing context enforcement, declaration and target inputs; shared native context owner. Target matching updates with the policy hash. |
| `controls.circuits.enabled`, `failure_threshold`, `success_threshold`, `half_open_max_requests` | Boolean/integers; `true`, `5`, `2`, `3` | Existing circuit enabled/tuning inputs; shared circuit owner. |
| `controls.circuits.timeout_seconds`, `max_timeout_seconds`, `streak_decay_seconds` | Numbers; `60`, `3600`, `3600` | Existing circuit timing inputs; shared circuit owner. |
| `controls.circuits.use_exponential_backoff`, `backoff_multiplier`, `jitter_factor` | Boolean/numbers; `true`, `2`, `0.3` | Existing circuit recovery tuning; shared circuit owner. |
| `controls.circuits.excluded_domains` | String array; `[]` | Existing extra circuit exclusions. Built-in local/probe exclusions remain in the circuit owner. |
| `logging.quiet_hosts.hosts`, `logging.quiet_hosts.paths` | String array/map of string arrays; `[]`, `{}` | Existing effective request-logger quiet rules; the existing logger suppresses matching traffic records. Security audit remains independent. |

Host/agent `exceptions` use `network`, `credentials`, `patterns`, `circuits`, or
`streaming`, compiled into the existing precedence rules. Named list references
use a local file in `[lists]` and `$name` in `[hosts]`. Advanced `[[permissions]]`,
`[[scan_patterns]]`, service bindings, contract bindings and `[[risk]]` retain
the shared evaluator and parser. Host expiry uses `expires`, evaluated at policy
load/reload. Context never supplies trusted identity or capture authority.

## Merged and removed inputs

| Starting input | Disposition |
| --- | --- |
| `modes`, network/credential/test-context/circuit native enforcement flags and `inspection` | Merged into named `policy.toml` controls. Their old configuration keys are rejected. |
| `addons`, `required`, old per-host `bypass`/`addons`, old `global_budget` and old internal host aliases | Removed from fresh authoring; named validation errors identify the replaced key. Use `budget`, `rate`, `allow`, `unknown_creds` and `exceptions`. |
| `proxy.backend`, `proxy.rust_config`, `proxy.image`, `proxy.container_name`, old host `proxy.port` | Removed from the native entry point. It selects installed Rust binaries and host-owned UDS listeners. The guest proxy port remains a guest/helper input owned by #818. |
| `version` in config.yaml, `notifications.method` | Removed: the existing native consumers do not use these settings. Source/profile identity belongs to the installed binary. Policy metadata remains `version`/`description`. |
| Old `test.enabled` and sinkhole router/host/HTTP/HTTPS/CA settings | Removed from product configuration. Test harnesses own origins and fixture routing; native upstream/CA settings remain above. |
| Credential `safe_headers.exact_names` and `safe_headers.patterns` | Removed from fresh settings: the starting native guard does not consume these template entries. Its effective `safe_patterns` input remains above. |
| Request-logger enabled flag and flow-store policy enabled flag | Removed as ineffective former detector flags. Logging retains its existing reached-hook behavior; runtime `flow_store_enabled` owns recorder activation. |
| Generated native.json and legacy environment detector overrides | Removed from normal native loading; typed TOML settings supply the existing runtime representation. Embedded development callers still own their internal JSON. |
| Python test-context command | Replaced by the installed native formatter/writer and declaration commands. The Python parser remains only as test tooling; #822 owns final production-package removal. |
