# State compatibility and rollback inventory

This inventory is the starting point for issue #638. It names every state
family consumed by the proxy migration, its source and native writers and
readers, the on-disk format, and the existing executable controls. A row is
not a rollback claim until a disposable fixture has written the state through
the named consumer and the selected prior release has read and used it.

## Comparator identity

The selected prior comparator is the Python proxy from repository commit
`7e934a5470f1aa9b74052fea08c6bae9b5f32e8a` (2026-09-16), the baseline named by
issue #638. It is a source checkout rather than a tagged wheel release. Its
runtime identity is Python 3.12.14, SafeYolo 0.1.0, and mitmproxy 12.2.3 from
the locked `uv.lock` (wheel SHA256
`df75ccd15ccb39ab55ce9dd4130312270e8ba208eb927a7cbe50cb52678ec722`). Native
candidate identity is recorded separately for each final integrated build;
the current inventory base is `4bf05bf232c843f04b9acf391fe097daac14776d`.

All fixture names and credential values are synthetic. Fixtures must record
file hashes, IDs, scopes, relationships, and effective decisions, while
excluding passphrases, bearer values, private keys, and raw credential
material from logs and evidence.

## Writer and reader matrix

| State family and lifetime | Source writer → reader | Native writer → reader | Format and security invariants | Existing controls and owner dependency |
| --- | --- | --- | --- | --- |
| Baseline policy, host/agent settings, lists and task policy (durable) | `cli/src/safeyolo/policy/engine.py` and `policy/toml_roundtrip.py` write the policy document; `policy/loader.py`, `mitm_addons/policy_engine.py` and task consumers read it. | `proxy/src/approvals.rs`, policy expiry and task writers update the existing locked policy file; `proxy/src/policy_runtime.rs` and `proxy/src/policy/{source,watch}.rs` read and publish one accepted snapshot. | TOML is canonical for mutations; JSON/YAML are accepted policy inputs where configured. Preserve comments, order, exact integers, timestamps, invalid-candidate retention, and file mode. | `proxy/tests/policy.rs`, `policy_expiry_source.json`, `policy_watch_source.json`, `tests/proxy_migration/test_native_network_policy.py`, `test_agent_api_policy*.py`. Root/policy writer owner must complete the integrated task and reload consumers. |
| Approvals (durable policy mutation) | `cli/src/safeyolo/policy/engine.py` approval mutation helpers write the policy TOML; policy loader and network consumers read the result. | `proxy/src/approvals.rs::save_policy` writes atomically under the existing policy lock; `policy_runtime.rs` and `policy.rs` read the accepted candidate. | Preserve scoped agent/host/port/action, expiry and rate values; failed activation leaves the previous bytes and decision active. | `proxy/tests/approvals.rs`, policy reload tests, `tests/proxy_migration/test_native_network_policy.py`. Approval writer owner supplies final consumer transition. |
| Service definitions/catalog (durable files, watched) | `cli/src/safeyolo/services/*.yaml`, `core/service_loader.py` and service commands write/read ordered YAML definitions. | `proxy/src/services/catalog.rs` reads builtin and user directories; `proxy/src/lib.rs` publishes the accepted catalog with policy/routes/tokens. No second service writer is introduced in this issue. | YAML source order, merge/override precedence, timestamps, malformed-file retention, and empty/removal semantics remain visible. | `proxy/src/services/catalog_tests.rs`, `proxy/tests/service_catalog_source.py/.json`, gateway workflow tests. #624 owner owns catalog/gateway writer integration. |
| Service authorization, contracts, grants and bindings (durable policy records; session leases ephemeral) | `cli/src/safeyolo/mitm_addons/service_gateway.py`, `commands/services.py`, and `commands/agent.py` author and consume policy records. | `proxy/src/grants.rs`, `contracts.rs`, `admin_api/gateway.rs` and existing policy transaction helpers write/read the same policy file; process-local once reservations are intentionally ephemeral. | Keep stable grant/binding IDs, scope, revocation and consumption state; preserve unrelated TOML; do not resurrect removed access or claim exactly-once across restart. | `proxy/tests/grants.rs`, `contracts.rs`, `gateway_snapshot.rs`, `gateway_workflow.rs`, `gateway_contract_workflow.rs`. The opt-in `selected_python_native_python_native_grants_bindings_transition` uses the real Python `ServiceGateway` writer/reader and native `Store` consumers across one policy file, including legacy default normalization and rollback. #624/#625 owners supply final live writers and gateway path. |
| Encrypted vault and OAuth credential state (durable) | `cli/src/safeyolo/core/vault.py` and `commands/vault.py` write the 16-byte-salt + Fernet-encrypted YAML; service gateway and OAuth code read/unlock it. | `proxy/src/credentials.rs` writes atomically and reloads the existing vault; `proxy/src/lib.rs` and `oauth.rs` read snapshots, while gateway integration selects entries. | Preserve salt, Fernet/PBKDF2 parameters, credential names/types, expiry and refresh fields, permissions, external-change detection, activation rollback, and no credential re-entry. Secret bytes remain in protected types and never ordinary evidence. | `proxy/tests/credentials.rs`, `oauth.rs`, `gateway_workflow.rs`; `native-credential-injection-contract.md`. The opt-in `selected_python_native_python_native_gateway_vault_transition` is the owned Python→Rust→Python→Rust transition: it records exact comparator/runtime/package identity, encrypted-file hashes and modes, Rust activation rollback, and real native gateway injection before and after Python's mutation. OAuth refresh failure/rollback remains owned by #626. |
| Credential guard fingerprint key (durable `data_dir/hmac_secret`) | `cli/src/safeyolo/core/utils.py::load_hmac_secret` reads `CREDGUARD_HMAC_SECRET` when set, otherwise creates or reloads `SAFEYOLO_DATA_DIR/hmac_secret`; `credential_guard.py` consumes it for sensitive-value fingerprints. | `proxy/src/credential_hmac.rs::load`, called by `proxy/src/lib.rs`, applies the same `CREDGUARD_HMAC_SECRET` override and otherwise creates or reloads `data_dir/hmac_secret`; credential guard and policy evidence consume its HMAC fingerprints. | Preserve the exact key bytes and `0600` mode across processes and rollback. The key is security-relevant: replacing it changes credential fingerprints and can break continuity even when the vault is unchanged. The key and raw credentials never enter ordinary evidence. | `proxy/src/credential_hmac.rs` unit tests, `proxy/tests/credential_guard.rs`, `proxy/tests/credential_http.rs`, source fingerprint controls, and the selected comparator's credential tests. #626 owns final live credential-guard transition; #638 records continuity once that writer is integrated. |
| Interception CA and key material (durable) | mitmproxy `CertStore` in `cli/src/safeyolo/mitm_addons` creates/reads the existing CA PEM and key files; TLS consumers reload them. | `proxy/src/tls.rs` reads and validates the supplied CA; it does not silently regenerate or replace it. | Preserve CA and key bytes, supported encodings, key match, validity, trust identity and file permissions. Generated leaves may differ; the root must not. | `proxy/tests/tls.rs`, `cli/tests/test_upstream_ca.py`, existing CA import oracle. The opt-in `selected_python_native_python_native_ca_trust_transition` runs the real Python writer and old consumer around two native TLS consumers, retaining root/key hashes and modes. #637 packaging/lifecycle owns installed-path execution; no native CA writer is introduced. |
| Circuit cache and counters (durable when configured; worker/process lifetime) | `cli/src/safeyolo/mitm_addons/circuit_breaker.py` and its snapshot worker write/read JSON state; operator circuit APIs consume it. | `proxy/src/circuits.rs` and its process-owned snapshot worker write/read the existing JSON state; `runtime.rs` and circuit APIs use the published domains. | Preserve host keys, counters, streak/open timing, settings and valid state. Malformed state is rejected without partial publication; absent/empty path is explicit no-write. | `proxy/tests/circuit_persistence.rs`, `circuit_persistence_close.rs`, `tests/proxy_migration/test_circuit_reload.py`, `test_operator_circuits.py`. The opt-in `test_selected_python_native_python_circuit_state_transition` is the owned Python→Rust→Python→Rust fixture: it records state hashes, proves Python open-state blocking, and proves final Rust reads Python's change, blocks first, then recovers. |
| Flow evidence (durable SQLite) | `cli/src/safeyolo/storage/flow_store.py` and `core/flow_writer.py` write; source flow APIs/readers and doctor tooling read. | `proxy/src/flow_store.rs` and `http/flow_recording.rs` write/read the retained version-2 SQLite schema, including version-1 migration. | Preserve owners/tags, request IDs, body presence/truncation, compression and transaction rollback; failed tags must not commit a row later. | `proxy/tests/flow_store*.rs`, `proxy/src/flow_store/details/tests.rs`, `tests/proxy_migration/test_http_test_context.py`. #635 owner supplies final integrated evidence writer/readers. |
| Audit, trace and metrics evidence (append-only files or process state) | `cli/src/safeyolo/core/{audit_writer,trace,flow_writer}.py` and readers/stream APIs write/read JSONL, trace and SQLite evidence. | `proxy/src/audit.rs`, trace/metrics modules and shared runtime writers write/read the retained schemas. | Preserve owner, correlation, decision, scope and failure attribution; no raw credentials; report write failure separately from application success. | `proxy/src/audit_runtime_tests.rs`, audit/trace/API tests, `docs/proxy-parity.md` evidence sections. Audit/evidence owners must supply final integrated readers. |
| Coordination/collaboration state (external service boundary) | `cli/src/safeyolo/coord/{store,nats_client,api}.py` and `core/plumb_service.py` write/read external NATS/SQLite state. | No proxy-owned replacement writer is claimed in this issue; native coordination work must use the existing external service boundary or explicitly remain unavailable. | Preserve trusted sender/room/attention ownership and ambiguity/error outcomes; do not copy service state into a new local format. | `cli/tests/test_coord*`, `tests/test_plumb*`, issues #628/#629. This is an integration dependency, not a new persistence layer for #638. |
| Readiness, runtime identity, listener registry and task registry (ephemeral) | Source startup/lifecycle writes readiness/PID markers and keeps listener/task state in process memory; restart intentionally creates a new process state. | `proxy/src/lib.rs` and `runtime.rs` own readiness/listeners and the process-local task registry; native admin/API writers do not persist these records. | Verify cleanup, identity attribution and restart reset. Do not treat an in-memory snapshot as durable rollback evidence. | `tests/proxy_migration/test_readiness.py`, `test_operator_task_api.py`, `test_agent_api_status.py`; #637 owns installed lifecycle and #627 owns retained operator controls. |

## Transition sequence and evidence

The eventual fixture runs sequentially on isolated directories:

1. The selected Python comparator writes each supported durable family with
   synthetic identities and records hashes and effective reads.
2. Native starts against those exact files, reads and uses them through its
   existing consumers, then performs one supported mutation per family.
3. Native stops cleanly. The selected Python comparator reopens the files and
   checks effective policy, authorization, credential selection, CA identity,
   circuit behavior, and flow evidence, rather than only parsing bytes.
4. Native starts again against the Python-readable post-native state and
   repeats the allowed/denied and scoped reads. Invalid candidates, external
   replacement/removal, salt changes, empty vault removal, failed row/tag
   transactions, and malformed circuit state are separate disposable cases.

The fixture must retain a manifest containing the two exact implementation
identities, package/tool versions, per-family before/after hashes, IDs and
scopes, commands, exit statuses, and effective observations. It must not claim
rollback until the final integrated writer set from #624–#629 and #635–#637 is
available. Until then, this document records the owned inventory and the
unresolved dependencies explicitly.

The currently executable owned transitions are the circuit, encrypted-vault,
interception-CA/key and grants/bindings rows. With
`SAFEYOLO_PYTHON_SOURCE` set to the clean comparator checkout and
`SAFEYOLO_RUST_PROXY` set to the candidate binary, the migration test writes an
open circuit and proves a Python open-state block, reads and recovers it in
Rust, reopens and mutates it in Python, then returns to Rust for another
open-state block and recovery. Its manifest contains exact runtime and launch
identity, SHA-256 state hashes, and effective origin-contact counts; it contains
no secret material. The remaining rows require their final integrated writer
owners before they can be promoted to the same process sequence.

The encrypted-vault row now has a separate opt-in native gateway transition.
`selected_python_native_python_native_gateway_vault_transition` runs the exact
prior Python comparator, then native vault/gateway, then the comparator again,
and a fresh native vault/gateway. It records encrypted-file SHA-256 values,
`0600` mode, credential names, activation rollback retention, and one origin
contact for each native injection without recording passphrases or credential
values. OAuth refresh-specific transition coverage remains dependent on #626's
final integrated writer and gateway controls.

The interception-CA/key row has a separate opt-in trust transition.
`selected_python_native_python_native_ca_trust_transition` runs the selected
old Python comparator to create the real mitmproxy CA bundle, loads it in native
Rust and completes a TLS handshake, reopens it with Python, then loads it in a
fresh native consumer for another handshake. It compares every generated CA/key
file's SHA-256 and mode, compares the root certificate trust identity, and
proves a missing native root is rejected without creating a replacement. Leaf
bytes remain generated per consumer and are not treated as durable state.

The grants/bindings row has a separate opt-in transition.
`selected_python_native_python_native_grants_bindings_transition` uses the old
Python `ServiceGateway` to consume one grant, persist another grant and binding,
and append legacy records without IDs or creation metadata. Native opens the
same policy, preserves the Python IDs, normalizes the legacy defaults, consumes
and revokes records, and rejects a failed activation while retaining exact
policy bytes. Python reloads the native state, observes the generated legacy
ID, revokes that binding, and writes a new grant; a fresh native store consumes
the new grant and revokes the remaining binding. The Python and fresh-native
snapshots also compare the normalized legacy grant creation/expiry/scope and
retained primary binding creation/template, proving the Python write does not
regenerate or drop those defaults. The manifest retains policy
hashes, file mode, IDs, the supported signed-64-bit binding value and only
secret-free state.
