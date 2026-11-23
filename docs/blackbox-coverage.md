# SafeYolo Blackbox Test Coverage

Generated from authored control metadata, maintained Python/Rust witnesses and installed runner selections. Do not edit this document by hand.

## Regenerate and check

From the repository root with the frozen development environment, run:

```sh
uv run --frozen python tests/blackbox/gen_docs.py
uv run --frozen python tests/blackbox/gen_docs.py --check
uv run --frozen python tests/blackbox/_docstring_lint.py
uv run --frozen python scripts/check_blackbox_cadence.py
```

The checks reject unresolved identities, unclassified assurance tests, unwired selectors and stale output. Installed runs retain `pytest-PHASE.json` and `procedure.json` beside section reports. Each pytest report records the collected and selected parameter cases, numeric UID/GID, observed guest/backend lifetime, run identity and setup/call/teardown outcomes. The section and hardware readers recompute completeness against the maintained selections. Missing reports, missing or deselected required cases, required skips, failed preparation, partial procedures and failed cleanup remain incomplete. Named platform exclusions retain their reasons. Existing opt-in checks retain their explicit selection; a selected opt-in check must pass. Arbitrary skips are not exclusions. Product source, controller source and selected guest artifact identity remain separate.

Installed section reports include a per-control `controls` view for BB-18/19/20/23/24/25/26. The view separates selected and executed sections, reached checkpoints and independent observations. The maintained drivers record canary states, origin counts, destination provenance and viewer cessation only after their assertions pass. Missing observations leave the section incomplete even when the process exits successfully. Curated native authority runs retain an aggregate `result.json` with selected and executed cases, controller identity and executable/broker digests. A failed prerequisite or timeout preserves unexecuted controls. The separate two-host tailnet verifier records its paired observations and cleanup in `procedure.json`. `run-controls.sh native-authority` and `run-controls.sh tailnet` forward explicit inputs to those maintained drivers. These are execution receipts; independent control acceptance and deployed cadence remain separate.

A source inventory does not establish deployed cadence or a passing installed run. [#1559](https://github.com/craigbalding/safeyolo/issues/1559) owns material assertion-change notification; [#889](https://github.com/craigbalding/safeyolo/issues/889) owns hardware deployment; [#838](https://github.com/craigbalding/safeyolo/issues/838) owns protected acceptance.

## Focused policy, job and installation controls

From a Linux or macOS test checkout, prepare the frozen development environment and the pinned Rust toolchain. Use an ordinary account and a new disk-backed result directory. Set `SAFEYOLO_BLACKBOX_ARTIFACTS_DIR` to that directory. Native selections build through the existing Cargo space guard with one job. Set its reserve and target directory for the actual host; `--cargo-profile release` selects optimized tests. These commands create owned process fixtures and retain reports/build logs; they do not qualify an installed guest.

```sh
./tests/blackbox/run-controls.sh named-checks
./tests/blackbox/run-controls.sh managed-feeds
./tests/blackbox/run-controls.sh before-after
./tests/blackbox/run-controls.sh mediated-services
```

Each native report records the selected and observed exact Cargo test names, executable digest, command, controller revision, working-tree state, profile, host architecture and numeric identity. A failed build, absent test, ignored case or failed observer leaves the phase incomplete. The named-checks selection includes the accepted prepared-job case. Without its explicitly supplied `SAFEYOLO_POLICY_CHECK_PREPARED` instance and `--include-ignored`, that phase remains incomplete. Use the existing authorized host execution route for that case; do not substitute a mock or acquire privilege through the runner.

With the matching native CLI/proxy/Coord binaries and existing fixture inputs prepared, `./tests/blackbox/run-controls.sh policy-recipe` selects deterministic preview/composition/redirect cases. It defaults to the accepted installed layout. `SAFEYOLO_AUTHORING_LAYOUT=source` explicitly selects source-layout proof, which proves neither package integrity nor installer behavior. `./tests/blackbox/run-controls.sh sudo-disclosure` selects current host disclosure/consent cases and early rootless preparation. That Linux fixture needs its documented guest sudo, ACL and archive tools; authentication modes are controlled. Guest preparation itself uses no sudo; its metadata, failure/cleanup and usability controls belong to BB-33. Its tiny metadata stages need the [native guest filesystem](../tests/test_linux_host.py); a nested 9p workspace cannot supply ACLs. Keep bulk inputs, pytest scratch and reports on disk. Use `SAFEYOLO_NATIVE_ARTIFACTS`, `SAFEYOLO_BUILD_PROFILE` and `SAFEYOLO_NATIVE_CLI` as their fixtures require. Both selections reuse named pytest receipts; required skips and teardown failures remain incomplete.

For BB-31's real engine boundary, use `./tests/blackbox/run-controls.sh hyperlight-services --help` and the existing [two-engine driver](../tests/blackbox/host/hyperlight_services.py). It requires a matching protocol-3 artifact bundle, accessible Linux KVM or entitled Apple-silicon HVF, a new owned instance, empty private disk-backed scratch, authorized ports and a privately supplied scoped GitHub read credential. Its `procedure.json` records permitted/scope/lifetime cases per engine, host-observed invocation/artifact/authority identities and cleanup. A lifetimes-only run cannot complete the two-engine receipt. The mediated-services native phase uses controlled adapters and does not prove that either engine ran. These focused selectors are manual. Existing workflow selectors below retain their actual conditions; no recurring real-engine deployment is inferred. Accepted product evidence and its platform limits remain linked in the catalogue; a complete phase does not establish whole-control acceptance.

On an authorized prepared Linux AMD64 host, `rootless-preparation --execute` runs the maintained install/update/cache, failure/cancellation and existing-install controls plus the production metadata witness. Run as UID/GID 1000. Preparation must already provide the namespace entry, delegated UID/GID ranges 100000/100000 and 231072/296608, newuidmap/newgidmap, nsenter, GNU tar and zstd. The fixture reuses preparation and makes sudo unavailable through the candidate's PATH. The sudo recorder is not process tracing. The selected installed CLI must match the prepared package; the checkout's four import/mapping source files must match that package's source commit. The retained #1553 baseline and canonical, device, V2-capability and raw-ACL42 specimens are verified against their accepted digests. These are fixture prerequisites, not additional product restrictions. Obtain those inputs from the existing product acceptance records. From this checkout, set the following paths to those local inputs and new disk-backed output/scratch locations:

```sh
export SAFEYOLO_ROOTLESS_PREPARED_CONFIG=/path/to/prepared-instance
export SAFEYOLO_NATIVE_CLI="$SAFEYOLO_ROOTLESS_PREPARED_CONFIG/bin/safeyolo"
export SAFEYOLO_ROOTLESS_BASELINE=/path/to/metadata-18414/result.json
export SAFEYOLO_ROOTLESS_SPECIMENS=/path/to/retained/specimens
./tests/blackbox/run-controls.sh rootless-preparation --execute \
  --output /path/to/new/rootless.json -- -q --basetemp=/path/to/new/scratch
```

The existing pytest receipt records the installed binary hash, controller revision, selected inputs, parameter cases and setup/call/teardown results. Metadata command output and comparison operands are retained in scratch before assertions; owned remapped trees are removed through the delegated namespace. A missing prerequisite, skipped/unselected obligation, observer failure or cleanup failure cannot complete the phase. Exit 0 and `complete=true` cover only the executed native process/kernel boundary; `control_complete=false` preserves the separate booted-guest phase and independent control acceptance. Native capability, ACL and set-ID parity does not establish new gVisor enforcement. The selector is manual and establishes no deployed recurring cadence. Reuse existing installed and platform proof; do not repeat a completed product journey for bookkeeping.

Use `rootless-preparation --boot` for the maintained guest-usability phase on the same authorized Linux host. Keep the prepared-instance and native-CLI variables above. The prepared package must include runsc, the selected public guest and a prepared NATS binary. Supply the retained archive and its verified digest/index from the product acceptance record. The procedure verifies those inputs, reuses the existing lower tree and creates fresh instance state. It performs no download, import or reinstall. From this checkout, set these local paths and immutable identities before selecting a new disk-backed result directory:

```sh
export SAFEYOLO_ROOTLESS_GUEST_ARCHIVE=/path/to/retained/guest.tar.zst
export SAFEYOLO_ROOTLESS_GUEST_SHA256="<verified-archive-sha256>"
export SAFEYOLO_ROOTLESS_GUEST_INDEX="sha256:<verified-index-sha256>"
./tests/blackbox/run-controls.sh rootless-preparation --boot \
  --output /path/to/new/rootless-guest.json -- -q --basetemp=/path/to/new/guest-scratch
```

The boot receipt requires successful setup/call/teardown for its guest-usability test. The storage report in scratch retains package/controller identities, executable hashes, actual runtime and UID/GID maps, two distinct guest lifetimes, root/user 1000 file effects in home/workspace, persistence and fresh-overlay checks, and owned cleanup. Host sudo is recorded and unavailable through PATH; guest sudo remains available for the root workload. Each phase keeps `control_complete=false`: carry matching process/native-kernel evidence alongside this boot result for independent BB-33 acceptance. A missing input, omitted case, failed observer or cleanup cannot complete the phase. This Linux usability phase adds no gVisor ACL/capability enforcement, macOS normal-shutdown, changed-public-guest upgrade or deployed-cadence claim.

For BB-33, #1553 feasibility and all seven #1554 product criteria have independent acceptance at [607d8488](https://github.com/craigbalding/safeyolo/issues/1554#issuecomment-6899892091). The combined maintained process/native-kernel and booted-guest phases at `cb04eb10` have [independent BB-33 acceptance](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6901362593). Each phase retains its separate boundary and incomplete-control flag; that judgment accepts their combined proof. The read-only `rootless-preparation` selector checks the retained native Linux storage receipt. Obtain its sanitized report, SHA-256 and exact candidate revision from the execution owner's canonical result. Keep the report private and choose a separate disk-backed output path. From this checkout, inspect the options before supplying those inputs:

```sh
./tests/blackbox/run-controls.sh rootless-preparation --help
```

Supply `--source-report`, `--source-sha256`, `--install-commit` and `--output`. The selector uses the existing bounded report reader and checks the digest before interpreting the report. It recomputes the named storage actions, cache/upgrade operands, persistence, reported host-sudo result and cleanup. Its output retains the original candidate, platform, prerequisites, execution identity, commands, setup failures and limits. A missing field, failed action, changed selection/inode, observer error or cleanup failure produces exit 2 and `complete=false`. Exit 0 means only that this selected retained witness is complete; `control_complete` remains false. The selector does not execute recorded commands, authenticate an arbitrary report author or independently accept the product. Installation/repeat/upgrade invocation remains attributed to the execution owner, outside the 32 storage actions. This selected receipt does not establish changed guest bytes, distinct mappings, extended/special metadata, failure/cancellation, existing-install preservation, macOS production or deployed recurring cadence. To collect new storage evidence on an authorized prepared Linux host, use the storage driver from the matching product revision. The [accepted #1554 driver](https://github.com/craigbalding/safeyolo/blob/607d8488a7fdc5c0c6ada605077ca99b4cb21682/tests/blackbox/installed_storage.py) carries the prepared instance's namespace authorization through acquisition. This checkout includes that driver interface; retained receipts keep their original candidate identity. Do not replay a completed operation for report formatting.

## Complete control catalogue

The authored meaning and dispositions preserve [all 37 agreed controls](https://github.com/craigbalding/safeyolo/issues/1557). The audit baseline is 13 November 2026. Current existence and exact identities below come from source. Conformance is an authored boundary judgment, not a fresh passing result. Planned repairs remain with their named owners.

Metadata lives in [`controls.toml`](../tests/blackbox/controls.toml). The [assurance map](assurance-map.toml) retains the implementation decision IDs. Controlled adapters, host-only tests and real-guest procedures have different evidence levels. AST/attribute discovery does not prove assertion semantics.

### BB-01 — Direct network egress

**What and why:** TCP, IPv6 and metadata routes cannot bypass the proxy.

**Audit coverage:** Guest BB; nightly.

**Conformance / action:** Repair uncontrolled endpoints and curl-exit-code oracles: use live owned receivers and prove zero unauthorized delivery.

**Effort:** M. **Comments:** Exercise ordinary agent and guest root.

**Owner / remaining work:** [#1560](https://github.com/craigbalding/safeyolo/issues/1560). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/isolation/test_vm_isolation.py).

**Assurance decisions:** `authorization`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/isolation/test_vm_isolation.py](../tests/blackbox/isolation/test_vm_isolation.py#L84) — Linux guest; gVisor systrap/KVM or VZ; ordinary user and setpriv subprocesses. Evidence: Real guest; audited uncontrolled network endpoints remain under #1560.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-vm-isolation-py).
- [tests/blackbox/isolation/test_runtime_capabilities.py](../tests/blackbox/isolation/test_runtime_capabilities.py#L18) — Guest; gVisor systrap/KVM or VZ; ordinary user. Evidence: Real guest; dependency and SSH limitations remain visible in outcomes.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-runtime-capabilities-py).
- [tests/blackbox/isolation/test_guest_ssh.py](../tests/blackbox/isolation/test_guest_ssh.py#L17) — Guest; gVisor systrap/KVM or VZ; ordinary user. Evidence: Real guest; dependency and SSH limitations remain visible in outcomes.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-guest-ssh-py).
- [tests/blackbox/host/security/test_firewall_structural.py](../tests/blackbox/host/security/test_firewall_structural.py#L28) — Installed host and guest configuration; Linux/macOS; host identity. Evidence: Structural checks; no independent delivery oracle.
  Exact identities: [source inventory](#witness-tests-blackbox-host-security-test-firewall-structural-py).
- [tests/blackbox/host/lifecycle/test_home_persistence.py](../tests/blackbox/host/lifecycle/test_home_persistence.py#L141) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-home-persistence-py).
- [tests/blackbox/host/lifecycle/test_token_lifecycle.py](../tests/blackbox/host/lifecycle/test_token_lifecycle.py#L84) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-token-lifecycle-py).
- [tests/blackbox/host/lifecycle/test_host_listener.py](../tests/blackbox/host/lifecycle/test_host_listener.py#L29) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-host-listener-py).
- [tests/proxy_contracts/test_outbound_effects.py](../tests/proxy_contracts/test_outbound_effects.py#L83) — Native process; Linux; host tracer selection. Evidence: Independent syscall/DNS observation; tracer unavailable remains a required skip unless explicitly excluded.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-outbound-effects-py).

### BB-02 — DNS/UDP egress

**What and why:** Queries/datagrams cannot leak even when no response returns.

**Audit coverage:** Guest BB; nightly.

**Conformance / action:** Repair NXDOMAIN/gaierror/no-reply oracles with owned receivers, unique markers and positive controls.

**Effort:** M. **Comments:** Share receiver infrastructure with BB-01.

**Owner / remaining work:** [#1560](https://github.com/craigbalding/safeyolo/issues/1560). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/isolation/test_vm_isolation.py).

**Assurance decisions:** `authorization`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/isolation/test_vm_isolation.py](../tests/blackbox/isolation/test_vm_isolation.py#L84) — Linux guest; gVisor systrap/KVM or VZ; ordinary user and setpriv subprocesses. Evidence: Real guest; audited uncontrolled network endpoints remain under #1560.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-vm-isolation-py).
- [tests/proxy_contracts/test_outbound_effects.py](../tests/proxy_contracts/test_outbound_effects.py#L83) — Native process; Linux; host tracer selection. Evidence: Independent syscall/DNS observation; tracer unavailable remains a required skip unless explicitly excluded.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-outbound-effects-py).

### BB-03 — Guest-root containment

**What and why:** Guest administration cannot modify host configuration or access host processes/devices.

**Audit coverage:** Guest BB; nightly; partly conformant.

**Conformance / action:** Retain live UID mapping/read-only checks; replace invalid syscall arguments and host-PID-1-name assumptions with valid probes and host canaries.

**Effort:** M. **Comments:** Guest root is intentionally allowed; device-node creation and device use are different claims.

**Owner / remaining work:** [#1560](https://github.com/craigbalding/safeyolo/issues/1560). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/isolation/test_vm_isolation.py).

**Assurance decisions:** `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/isolation/test_vm_isolation.py](../tests/blackbox/isolation/test_vm_isolation.py#L84) — Linux guest; gVisor systrap/KVM or VZ; ordinary user and setpriv subprocesses. Evidence: Real guest; audited uncontrolled network endpoints remain under #1560.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-vm-isolation-py).
- [tests/blackbox/isolation/test_root_containment.py](../tests/blackbox/isolation/test_root_containment.py#L50) — Linux guest; gVisor systrap/KVM or VZ; guest root. Evidence: Real guest root with host-prepared controls.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-root-containment-py).
- [tests/blackbox/isolation/test_runtime_capabilities.py](../tests/blackbox/isolation/test_runtime_capabilities.py#L18) — Guest; gVisor systrap/KVM or VZ; ordinary user. Evidence: Real guest; dependency and SSH limitations remain visible in outcomes.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-runtime-capabilities-py).
- [tests/blackbox/isolation/test_guest_ssh.py](../tests/blackbox/isolation/test_guest_ssh.py#L17) — Guest; gVisor systrap/KVM or VZ; ordinary user. Evidence: Real guest; dependency and SSH limitations remain visible in outcomes.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-guest-ssh-py).
- [tests/blackbox/host/security/test_firewall_structural.py](../tests/blackbox/host/security/test_firewall_structural.py#L28) — Installed host and guest configuration; Linux/macOS; host identity. Evidence: Structural checks; no independent delivery oracle.
  Exact identities: [source inventory](#witness-tests-blackbox-host-security-test-firewall-structural-py).

### BB-04 — Agent identity / peer isolation

**What and why:** Forged claims cannot select another agent; peer sockets/private files remain inaccessible as user and root.

**Audit coverage:** Strong two-guest BB exists but is optional; basic peer checks run by default.

**Conformance / action:** Wire the existing ingress-pair witness into nightly selection; retire guessed-neighbour probes and SSH checks accepting either outcome.

**Effort:** S. **Comments:** Existing pair covers guest root and proxy restart; retain its actual platform scope.

**Owner / remaining work:** [#1560](https://github.com/craigbalding/safeyolo/issues/1560). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_ingress_pair.py).

**Assurance decisions:** `identity`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_local_api_authorization.py](../tests/proxy_contracts/test_local_api_authorization.py#L18) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-local-api-authorization-py).
- [tests/proxy_contracts/test_agent_api_contract.py](../tests/proxy_contracts/test_agent_api_contract.py#L82) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-contract-py).
- [tests/proxy_contracts/test_agent_egress_scope.py](../tests/proxy_contracts/test_agent_egress_scope.py#L76) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-egress-scope-py).
- [tests/proxy_contracts/test_agent_api_test_context.py](../tests/proxy_contracts/test_agent_api_test_context.py#L175) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-test-context-py).
- [tests/blackbox/isolation/test_vm_isolation.py](../tests/blackbox/isolation/test_vm_isolation.py#L84) — Linux guest; gVisor systrap/KVM or VZ; ordinary user and setpriv subprocesses. Evidence: Real guest; audited uncontrolled network endpoints remain under #1560.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-vm-isolation-py).
- [tests/blackbox/isolation/test_agent_api_scope.py](../tests/blackbox/isolation/test_agent_api_scope.py#L84) — Guest; gVisor systrap/KVM or VZ; ordinary user. Evidence: Real Agent API; no host Admin credential.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-agent-api-scope-py).
- [tests/blackbox/host/identity/test_agent_identity.py](../tests/blackbox/host/identity/test_agent_identity.py#L36) — Installed host/guest mapping; Linux/macOS; host identity. Evidence: Real runtime state; gVisor-only UID-map exclusion on VZ.
  Exact identities: [source inventory](#witness-tests-blackbox-host-identity-test-agent-identity-py).
- [tests/blackbox/host/lifecycle/test_home_persistence.py](../tests/blackbox/host/lifecycle/test_home_persistence.py#L141) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-home-persistence-py).
- [tests/blackbox/host/lifecycle/test_token_lifecycle.py](../tests/blackbox/host/lifecycle/test_token_lifecycle.py#L84) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-token-lifecycle-py).
- [tests/blackbox/host/lifecycle/test_host_listener.py](../tests/blackbox/host/lifecycle/test_host_listener.py#L29) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-host-listener-py).
- [tests/blackbox/installed_ingress.py::main](../tests/blackbox/installed_ingress.py#L195) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: optional `systrap` section `ingress`; default `kvm` section `ingress`.
- [tests/blackbox/installed_ingress_pair.py::main](../tests/blackbox/installed_ingress_pair.py#L112) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: optional `systrap` section `ingress`.

### BB-05 — Agent/Admin API authorization

**What and why:** Missing/wrong tokens, foreign records and operator-only controls are refused.

**Audit coverage:** Guest and proxy BB; nightly.

**Conformance / action:** Conformant: retain.

**Effort:** —. **Comments:** Includes populated peer data and reserved API containment.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/proxy_contracts/test_local_api_authorization.py).

**Assurance decisions:** `authorization`, `management_evidence`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_local_api_authorization.py](../tests/proxy_contracts/test_local_api_authorization.py#L18) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-local-api-authorization-py).
- [tests/proxy_contracts/test_agent_api_contract.py](../tests/proxy_contracts/test_agent_api_contract.py#L82) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-contract-py).
- [tests/proxy_contracts/test_agent_egress_scope.py](../tests/proxy_contracts/test_agent_egress_scope.py#L76) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-egress-scope-py).
- [tests/proxy_contracts/test_agent_api_test_context.py](../tests/proxy_contracts/test_agent_api_test_context.py#L175) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-test-context-py).
- [tests/blackbox/isolation/test_agent_api_scope.py](../tests/blackbox/isolation/test_agent_api_scope.py#L84) — Guest; gVisor systrap/KVM or VZ; ordinary user. Evidence: Real Agent API; no host Admin credential.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-agent-api-scope-py).
- [tests/blackbox/host/native/test_installed_native.py](../tests/blackbox/host/native/test_installed_native.py#L38) — Installed host proxy; Linux/macOS; host identity. Evidence: Real selected native executable and owned origin.
  Exact identities: [source inventory](#witness-tests-blackbox-host-native-test-installed-native-py).
- [tests/proxy_contracts/test_agent_api_config.py](../tests/proxy_contracts/test_agent_api_config.py#L64) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-config-py).
- [tests/proxy_contracts/test_agent_api_status.py](../tests/proxy_contracts/test_agent_api_status.py#L33) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-status-py).
- [tests/proxy_contracts/test_operator_modes_and_listeners.py](../tests/proxy_contracts/test_operator_modes_and_listeners.py#L36) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-modes-and-listeners-py).
- [tests/proxy_contracts/test_operator_task_api.py](../tests/proxy_contracts/test_operator_task_api.py#L25) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-task-api-py).
- [tests/proxy_contracts/test_outbound_effects.py](../tests/proxy_contracts/test_outbound_effects.py#L83) — Native process; Linux; host tracer selection. Evidence: Independent syscall/DNS observation; tracer unavailable remains a required skip unless explicitly excluded.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-outbound-effects-py).
- [tests/proxy_contracts/test_single_event_log.py](../tests/proxy_contracts/test_single_event_log.py#L33) — Native scoped evidence API; host identity. Evidence: Real policy traffic and scoped evidence readers.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-single-event-log-py).
- [proxy/tests/native_coord/diagnostics.rs](../proxy/tests/native_coord/diagnostics.rs#L123) — Native Agent API/MCP; host process; controlled HTTP failures. Evidence: Actual native client and scoped audit reader; canned body/deadline variants. These tests do not establish an installed guest or real-agent journey..
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-diagnostics-rs).

### BB-06 — Destination policy / reload

**What and why:** Agent/destination rules govern real requests; invalid reload retains valid policy.

**Audit coverage:** Proxy and representative guest BB; nightly.

**Conformance / action:** Conformant: retain.

**Effort:** —. **Comments:** Existing precedence, forged identity and failed-reload cases.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/proxy_contracts/test_native_network_policy.py).

**Assurance decisions:** `authorization`, `policy_publication`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_network_policy.py](../tests/proxy_contracts/test_native_network_policy.py#L191) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-network-policy-py).
- [tests/proxy_contracts/test_agent_api_policy.py](../tests/proxy_contracts/test_agent_api_policy.py#L121) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-policy-py).
- [tests/proxy_contracts/test_agent_api_policy_yaml.py](../tests/proxy_contracts/test_agent_api_policy_yaml.py#L51) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-policy-yaml-py).
- [tests/proxy_contracts/test_policy_authoring.py](../tests/proxy_contracts/test_policy_authoring.py#L93) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-policy-authoring-py).
- [tests/proxy_contracts/test_native_policy_cli.py](../tests/proxy_contracts/test_native_policy_cli.py#L54) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-policy-cli-py).
- [tests/proxy_contracts/test_service_effect_assessment.py](../tests/proxy_contracts/test_service_effect_assessment.py#L36) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-service-effect-assessment-py).
- [tests/blackbox/installed_ingress.py::main](../tests/blackbox/installed_ingress.py#L195) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: optional `systrap` section `ingress`; default `kvm` section `ingress`.
- [tests/proxy_contracts/test_agent_api_config.py](../tests/proxy_contracts/test_agent_api_config.py#L64) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-config-py).
- [tests/proxy_contracts/test_agent_api_status.py](../tests/proxy_contracts/test_agent_api_status.py#L33) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-status-py).
- [tests/proxy_contracts/test_operator_modes_and_listeners.py](../tests/proxy_contracts/test_operator_modes_and_listeners.py#L36) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-modes-and-listeners-py).
- [tests/proxy_contracts/test_operator_task_api.py](../tests/proxy_contracts/test_operator_task_api.py#L25) — Native process; Linux/macOS; host identity. Evidence: Real native policy and scoped API requests.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-task-api-py).
- [tests/proxy_contracts/test_outbound_effects.py](../tests/proxy_contracts/test_outbound_effects.py#L83) — Native process; Linux; host tracer selection. Evidence: Independent syscall/DNS observation; tracer unavailable remains a required skip unless explicitly excluded.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-outbound-effects-py).

### BB-07 — Credential authorization / redirects

**What and why:** Vault secrets reach only approved destinations, including cross-authority redirects.

**Audit coverage:** Proxy BB; nightly; guest credential injection also exists.

**Conformance / action:** Conformant: retain wire/origin observations.

**Effort:** —. **Comments:** No need to duplicate every redirect variant in every VM.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/proxy_contracts/test_gateway_redirect.py).

**Assurance decisions:** `credentials`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_gateway_redirect.py](../tests/proxy_contracts/test_gateway_redirect.py#L186) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-gateway-redirect-py).
- [tests/proxy_contracts/test_coding_client_auth.py](../tests/proxy_contracts/test_coding_client_auth.py#L88) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-coding-client-auth-py).
- [tests/proxy_contracts/test_native_credentials_cli.py](../tests/proxy_contracts/test_native_credentials_cli.py#L134) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-credentials-cli-py).
- [tests/proxy_contracts/test_native_onepassword_cli.py](../tests/proxy_contracts/test_native_onepassword_cli.py#L39) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-onepassword-cli-py).
- [tests/proxy_contracts/test_codex_approval_fallback.py](../tests/proxy_contracts/test_codex_approval_fallback.py#L132) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-codex-approval-fallback-py).
- [tests/blackbox/installed_workloads.py::main](../tests/blackbox/installed_workloads.py#L286) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `workloads`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `kvm` section `workloads`.
- [tests/blackbox/installed_state_transition.py::main](../tests/blackbox/installed_state_transition.py#L503) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `continuity`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `continuity`.
- [tests/proxy_contracts/test_github_git.py](../tests/proxy_contracts/test_github_git.py#L49) — Native gateway; owned Git server; host identity. Evidence: Real Git and owned gateway origin.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-github-git-py).
- [proxy/tests/credential_http/boundary.rs](../proxy/tests/credential_http/boundary.rs#L55) — Native HTTP; host process; controlled credentials and upstream origins. Evidence: Real proxy wire with controlled credential/provider adapters.
  Exact identities: [source inventory](#witness-proxy-tests-credential-http-boundary-rs).
- [proxy/tests/credential_http/ghcr.rs](../proxy/tests/credential_http/ghcr.rs#L287) — Native HTTP; host process; controlled credentials and upstream origins. Evidence: Real proxy wire with controlled credential/provider adapters.
  Exact identities: [source inventory](#witness-proxy-tests-credential-http-ghcr-rs).

### BB-08 — Service capabilities / contracts / risk grants

**What and why:** Only authorized operations cause effects; binding constraints and one-use grant consumption hold.

**Audit coverage:** Guest and proxy BB; nightly.

**Conformance / action:** Conformant: retain.

**Effort:** —. **Comments:** Exact origin effects and stolen-token rejection already covered.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_access.py).

**Assurance decisions:** `credentials`, `authorization`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_gateway_scope.py](../tests/proxy_contracts/test_gateway_scope.py#L82) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-gateway-scope-py).
- [tests/proxy_contracts/test_gateway_risk_approval.py](../tests/proxy_contracts/test_gateway_risk_approval.py#L224) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-gateway-risk-approval-py).
- [tests/proxy_contracts/test_service_route_challenge.py](../tests/proxy_contracts/test_service_route_challenge.py#L125) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-service-route-challenge-py).
- [tests/proxy_contracts/test_shared_operator_approval.py](../tests/proxy_contracts/test_shared_operator_approval.py#L133) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-shared-operator-approval-py).
- [tests/proxy_contracts/test_operator_consumer_approval.py](../tests/proxy_contracts/test_operator_consumer_approval.py#L171) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-consumer-approval-py).
- [tests/proxy_contracts/test_installed_shared_approvals.py](../tests/proxy_contracts/test_installed_shared_approvals.py#L32) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-installed-shared-approvals-py).
- [tests/proxy_contracts/test_guard_approval_audit.py](../tests/proxy_contracts/test_guard_approval_audit.py#L39) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-guard-approval-audit-py).
- [tests/proxy_contracts/test_control_updates.py](../tests/proxy_contracts/test_control_updates.py#L111) — Native signals process; optional prepared Linux sandbox jobs. Evidence: Signed native candidates, owned NATS and controlled route requests; real isolated checks require the selected installed host.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-control-updates-py).
- [tests/blackbox/installed_access.py::main](../tests/blackbox/installed_access.py#L635) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `access`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `access`.
- [proxy/tests/credential_http/boundary.rs](../proxy/tests/credential_http/boundary.rs#L55) — Native HTTP; host process; controlled credentials and upstream origins. Evidence: Real proxy wire with controlled credential/provider adapters.
  Exact identities: [source inventory](#witness-proxy-tests-credential-http-boundary-rs).

### BB-09 — Host-secret custody

**What and why:** Guest and guest root cannot directly read host CA/vault secrets.

**Audit coverage:** Scans and injection checks exist; partial.

**Conformance / action:** Extend with unique synthetic secret canaries across relevant guest files, environment and scoped APIs.

**Effort:** M. **Comments:** Preserve deliberately provisioned client credentials and authorized operator views.

**Owner / remaining work:** [#1560](https://github.com/craigbalding/safeyolo/issues/1560). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/isolation/test_key_isolation.py).

**Assurance decisions:** `credentials`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/isolation/test_key_isolation.py](../tests/blackbox/isolation/test_key_isolation.py#L72) — Linux guest; gVisor systrap/KVM or VZ; user and private-key root selection. Evidence: Real guest scans; synthetic canary extension remains #1560.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-key-isolation-py).

### BB-10 — Subscription credential adoption / renewal

**What and why:** Refresh/import cannot change identity or resurrect revoked authority.

**Audit coverage:** Strong native HTTP tests; run-lifetime backend is synthetic.

**Conformance / action:** Extend with one real guest and controlled provider: adoption, refresh, restart, revocation and wrong guest.

**Effort:** M. **Comments:** No paid model service needed; retain existing native cases.

**Owner / remaining work:** [#1560](https://github.com/craigbalding/safeyolo/issues/1560). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/proxy/tests/credential_http/codex.rs).

**Assurance decisions:** `credentials`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_gateway_redirect.py](../tests/proxy_contracts/test_gateway_redirect.py#L186) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-gateway-redirect-py).
- [tests/proxy_contracts/test_coding_client_auth.py](../tests/proxy_contracts/test_coding_client_auth.py#L88) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-coding-client-auth-py).
- [tests/proxy_contracts/test_native_credentials_cli.py](../tests/proxy_contracts/test_native_credentials_cli.py#L134) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-credentials-cli-py).
- [tests/proxy_contracts/test_native_onepassword_cli.py](../tests/proxy_contracts/test_native_onepassword_cli.py#L39) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-onepassword-cli-py).
- [tests/proxy_contracts/test_codex_approval_fallback.py](../tests/proxy_contracts/test_codex_approval_fallback.py#L132) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-codex-approval-fallback-py).
- [tests/blackbox/installed_state_transition.py::main](../tests/blackbox/installed_state_transition.py#L503) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `continuity`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `continuity`.
- [tests/blackbox/claude_smoke.py::run](../tests/blackbox/claude_smoke.py#L258) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: manual; no recurring selector resolved.
- [proxy/tests/credential_http/codex.rs](../proxy/tests/credential_http/codex.rs#L275) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Controlled OAuth provider and run-lifetime adapter; native HTTP.
  Exact identities: [source inventory](#witness-proxy-tests-credential-http-codex-rs).

### BB-11 — TLS / guest trust separation

**What and why:** Guest CAs cannot widen host upstream verification; bad TLS cannot fall through.

**Audit coverage:** Guest and proxy BB; nightly.

**Conformance / action:** Conformant: retain.

**Effort:** —. **Comments:** Negative certificate tests, persisted trust and scoped exceptions exist.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/isolation/test_root_containment.py).

**Assurance decisions:** `interception_tls`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_https_contract.py](../tests/proxy_contracts/test_https_contract.py#L84) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-https-contract-py).
- [tests/proxy_contracts/test_https_trust_continuity.py](../tests/proxy_contracts/test_https_trust_continuity.py#L152) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-https-trust-continuity-py).
- [tests/blackbox/isolation/test_root_containment.py](../tests/blackbox/isolation/test_root_containment.py#L50) — Linux guest; gVisor systrap/KVM or VZ; guest root. Evidence: Real guest root with host-prepared controls.
  Exact identities: [source inventory](#witness-tests-blackbox-isolation-test-root-containment-py).
- [tests/blackbox/installed_workloads.py::main](../tests/blackbox/installed_workloads.py#L286) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `workloads`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `kvm` section `workloads`.
- [tests/blackbox/installed_lifecycle.py::main](../tests/blackbox/installed_lifecycle.py#L395) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `lifecycle`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `lifecycle`.

### BB-12 — HTTP framing / authority / transitions

**What and why:** Parsing, normalization, reuse, WebSocket and CONNECT cannot authorize one target and forward to another.

**Audit coverage:** Extensive proxy BB nightly; representative guest HTTP/WSS/SSH.

**Conformance / action:** Conformant layered coverage: retain.

**Effort:** —. **Comments:** Keep full wire permutations at the proxy boundary.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/proxy_contracts/test_raw_http_gateway_boundary.py).

**Assurance decisions:** `authorization`, `interception_tls`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_raw_http_gateway_boundary.py](../tests/proxy_contracts/test_raw_http_gateway_boundary.py#L216) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-raw-http-gateway-boundary-py).
- [tests/proxy_contracts/test_allowed_chunked_framing.py](../tests/proxy_contracts/test_allowed_chunked_framing.py#L187) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-allowed-chunked-framing-py).
- [tests/proxy_contracts/test_authority_consistency.py](../tests/proxy_contracts/test_authority_consistency.py#L356) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-authority-consistency-py).
- [tests/proxy_contracts/test_authority_parent_fixture.py](../tests/proxy_contracts/test_authority_parent_fixture.py#L59) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-authority-parent-fixture-py).
- [tests/proxy_contracts/test_http1_handoff_contract.py](../tests/proxy_contracts/test_http1_handoff_contract.py#L294) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-http1-handoff-contract-py).
- [tests/proxy_contracts/test_http2_contract.py](../tests/proxy_contracts/test_http2_contract.py#L531) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-http2-contract-py).
- [tests/proxy_contracts/test_http2_gate.py](../tests/proxy_contracts/test_http2_gate.py#L129) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-http2-gate-py).
- [tests/proxy_contracts/test_http2_gate_timing.py](../tests/proxy_contracts/test_http2_gate_timing.py#L67) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-http2-gate-timing-py).
- [tests/proxy_contracts/test_http_contract.py](../tests/proxy_contracts/test_http_contract.py#L44) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-http-contract-py).
- [tests/proxy_contracts/test_http_test_context.py](../tests/proxy_contracts/test_http_test_context.py#L171) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-http-test-context-py).
- [tests/proxy_contracts/test_request_headers.py](../tests/proxy_contracts/test_request_headers.py#L52) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-request-headers-py).
- [tests/proxy_contracts/test_request_streaming_inspection.py](../tests/proxy_contracts/test_request_streaming_inspection.py#L289) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-request-streaming-inspection-py).
- [tests/proxy_contracts/test_selected_ip.py](../tests/proxy_contracts/test_selected_ip.py#L89) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-selected-ip-py).
- [tests/proxy_contracts/test_te_gzip_handoff.py](../tests/proxy_contracts/test_te_gzip_handoff.py#L232) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-te-gzip-handoff-py).
- [tests/proxy_contracts/test_tunnel_contract.py](../tests/proxy_contracts/test_tunnel_contract.py#L227) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-tunnel-contract-py).
- [tests/proxy_contracts/test_websocket_contract.py](../tests/proxy_contracts/test_websocket_contract.py#L263) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-websocket-contract-py).
- [tests/proxy_contracts/test_sse_shutdown.py](../tests/proxy_contracts/test_sse_shutdown.py#L98) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-sse-shutdown-py).
- [tests/proxy_contracts/test_tunnel_audit_wait.py](../tests/proxy_contracts/test_tunnel_audit_wait.py#L14) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-tunnel-audit-wait-py).
- [tests/blackbox/installed_workloads.py::main](../tests/blackbox/installed_workloads.py#L286) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `workloads`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `kvm` section `workloads`.
- [proxy/tests/credential_http/boundary.rs](../proxy/tests/credential_http/boundary.rs#L55) — Native HTTP; host process; controlled credentials and upstream origins. Evidence: Real proxy wire with controlled credential/provider adapters.
  Exact identities: [source inventory](#witness-proxy-tests-credential-http-boundary-rs).

### BB-13 — Configured parent routing

**What and why:** A required parent cannot be bypassed by direct fallback after connection/TLS failure.

**Audit coverage:** Proxy BB; nightly.

**Conformance / action:** Conformant: retain.

**Effort:** —. **Comments:** Selected and unselected agents/destinations covered.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/proxy_contracts/test_configured_parent_boundary.py).

**Assurance decisions:** `external_effects`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_configured_parent_boundary.py](../tests/proxy_contracts/test_configured_parent_boundary.py#L152) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-configured-parent-boundary-py).

### BB-14 — Budgets / circuit breakers

**What and why:** Limits stop real upstream effects, preserve unrelated scopes and permit authorized reset/recovery.

**Audit coverage:** Proxy BB; nightly.

**Conformance / action:** Conformant for current behavior: retain.

**Effort:** —. **Comments:** If temporary elevated windows are later introduced, add expiry/crash tests for that new contract.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/proxy_contracts/test_operator_budgets.py).

**Assurance decisions:** `authorization`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_operator_budgets.py](../tests/proxy_contracts/test_operator_budgets.py#L197) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-budgets-py).
- [tests/proxy_contracts/test_agent_api_budgets.py](../tests/proxy_contracts/test_agent_api_budgets.py#L57) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-budgets-py).
- [tests/proxy_contracts/test_connect_budgets.py](../tests/proxy_contracts/test_connect_budgets.py#L77) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-connect-budgets-py).
- [tests/proxy_contracts/test_circuit_bypass.py](../tests/proxy_contracts/test_circuit_bypass.py#L52) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-circuit-bypass-py).
- [tests/proxy_contracts/test_circuit_completion.py](../tests/proxy_contracts/test_circuit_completion.py#L115) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-circuit-completion-py).
- [tests/proxy_contracts/test_circuit_failure_recovery.py](../tests/proxy_contracts/test_circuit_failure_recovery.py#L85) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-circuit-failure-recovery-py).
- [tests/proxy_contracts/test_circuit_reload.py](../tests/proxy_contracts/test_circuit_reload.py#L89) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-circuit-reload-py).
- [tests/proxy_contracts/test_operator_circuits.py](../tests/proxy_contracts/test_operator_circuits.py#L211) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-circuits-py).
- [tests/blackbox/installed_state_transition.py::main](../tests/blackbox/installed_state_transition.py#L503) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `continuity`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `continuity`.

### BB-15 — Restart / abrupt-failure recovery

**What and why:** Outages cannot bypass enforcement, revive authority or replay effects.

**Audit coverage:** Orderly guest lifecycle nightly; SIGKILL witness on demand.

**Conformance / action:** Wire and extend abrupt failure: guest non-delivery during outage; consumed/revoked authority stays unusable after recovery.

**Effort:** M. **Comments:** Preserve graceful drain and admitted-stream semantics.

**Owner / remaining work:** [#1560](https://github.com/craigbalding/safeyolo/issues/1560). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_shared_approvals.py).

**Assurance decisions:** `policy_publication`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_blackbox_lifecycle.py](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L36) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-blackbox-lifecycle-py).
- [tests/proxy_contracts/test_lifecycle_batch.py](../tests/proxy_contracts/test_lifecycle_batch.py#L258) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-lifecycle-batch-py).
- [tests/proxy_contracts/test_readiness.py](../tests/proxy_contracts/test_readiness.py#L13) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-readiness-py).
- [tests/proxy_contracts/test_first_agent_launch.py](../tests/proxy_contracts/test_first_agent_launch.py#L49) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-first-agent-launch-py).
- [tests/blackbox/host/lifecycle/test_home_persistence.py](../tests/blackbox/host/lifecycle/test_home_persistence.py#L141) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-home-persistence-py).
- [tests/blackbox/host/lifecycle/test_token_lifecycle.py](../tests/blackbox/host/lifecycle/test_token_lifecycle.py#L84) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-token-lifecycle-py).
- [tests/blackbox/host/lifecycle/test_host_listener.py](../tests/blackbox/host/lifecycle/test_host_listener.py#L29) — Installed host with real guest; Linux/macOS; user/root parameter cases. Evidence: Real guest; owned live listener where selected.
  Exact identities: [source inventory](#witness-tests-blackbox-host-lifecycle-test-host-listener-py).
- [tests/blackbox/installed_ingress_pair.py::main](../tests/blackbox/installed_ingress_pair.py#L112) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: optional `systrap` section `ingress`.
- [tests/blackbox/installed_lifecycle.py::main](../tests/blackbox/installed_lifecycle.py#L395) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `lifecycle`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `lifecycle`.
- [tests/blackbox/installed_state_transition.py::main](../tests/blackbox/installed_state_transition.py#L503) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `continuity`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `continuity`.
- [tests/blackbox/installed_shared_approvals.py::main](../tests/blackbox/installed_shared_approvals.py#L1471) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: manual; no recurring selector resolved.

### BB-16 — Disposable-job isolation

**What and why:** Jobs receive only declared inputs/privilege, without inherited agent authority or persistent state.

**Audit coverage:** Maintained installed section; scheduled systrap selector. [Manual Ubuntu systrap observations qualified](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6886804289); [prepared public-shell run 18869 accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6925236509) at controller 0422caec, production 607d8488, original runsc 65645198 and sentry f29a1416. [Shipped systrap jobs accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6933305891) and [shipped KVM jobs accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6934606070) at controller b0fa383677936be1e32582bb440b26ccefa09451, Linux AMD64 production 1a8c698e6ca23f83655a2801c10e99f4d24a6829 and guest archive 1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe. [Physical Apple Virtualization.framework (VZ) jobs accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6938258553) at controller 899cd7313865287e766311b054ba0b18af810615, Darwin ARM64 production 1a8c698e6ca23f83655a2801c10e99f4d24a6829, standard guest source e138ebefba90919311e9e60cc272b140e78b5d61, index 712ef9468f4383945b5a4484c45d6c8d20a062fbcf1cb3351bc4e9b86012d2db and archive 010efdf86315df1426bedb49d33834e9317abc455dcb738650fe2f6289552e93. Public installation acquisition and installed catalogue qualification remain unverified; deployed cadence remains with #1563 and venue automation with #889.

**Conformance / action:** Retain named default/explicit privilege, input, discarded-state, signal/exit and timeout cases and direct network-off attempts at a functioning owned receiver. Shipped systrap/KVM typed outcomes and output details rely on matching procedure assertions; separate raw records are absent. Physical VZ typed results and streams are retained. The failed Kali execution and earlier failed attempts remain failed. Accepted platform executions do not establish deployed recurrence.

**Effort:** M. **Comments:** Missing proxy environment variables alone do not prove containment; foundation for new engines.

**Owner / remaining work:** [#1562](https://github.com/craigbalding/safeyolo/issues/1562). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/host/job_sandbox.py).

**Assurance decisions:** `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/host/job_sandbox.py::main](../tests/blackbox/host/job_sandbox.py#L357) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `job-sandbox`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `kvm` section `job-sandbox`; default `vz` section `job-sandbox`.

### BB-17 — Disposable-job network authority

**What and why:** Gate/service scopes constrain job effects; teardown ends delegated authority.

**Audit coverage:** Maintained installed section; scheduled systrap selector. [Manual Ubuntu systrap procedure accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6905097277); [prepared public-shell run 18861 accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6924137097) at controller 50c62547, production 607d8488, original runsc 65645198 and sentry f29a1416. [Shipped systrap jobs accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6933305891) and [shipped KVM jobs accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6934606070) at controller b0fa383677936be1e32582bb440b26ccefa09451, Linux AMD64 production 1a8c698e6ca23f83655a2801c10e99f4d24a6829 and guest archive 1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe. [Physical Apple Virtualization.framework (VZ) jobs accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6938258553) at controller 899cd7313865287e766311b054ba0b18af810615, Darwin ARM64 production 1a8c698e6ca23f83655a2801c10e99f4d24a6829, standard guest source e138ebefba90919311e9e60cc272b140e78b5d61, index 712ef9468f4383945b5a4484c45d6c8d20a062fbcf1cb3351bc4e9b86012d2db and archive 010efdf86315df1426bedb49d33834e9317abc455dcb738650fe2f6289552e93. Public installation acquisition and installed catalogue qualification remain unverified; deployed cadence remains with #1563 and venue automation with #889.

**Conformance / action:** Retain exact scoped origin counts, credential replacement, live revocation, timeout/cancellation, old/new delegated-connection refusal, native audit attribution and listener cleanup. Shipped systrap/KVM and physical VZ acceptance retains matching source assertions and completed checkpoints for lifecycle CLI exits, delegated refusal and audit; separate teardown/audit transcripts are absent. Earlier failed attempts remain failed; deployed recurrence remains unproved.

**Effort:** M. **Comments:** Origin counts and credential replacement already exist.

**Owner / remaining work:** [#1562](https://github.com/craigbalding/safeyolo/issues/1562). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/host/job_network.py).

**Assurance decisions:** `authorization`, `credentials`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/host/job_network.py::main](../tests/blackbox/host/job_network.py#L420) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `job-network`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `kvm` section `job-network`; default `vz` section `job-network`.

### BB-18 — Local peer support

**What and why:** Granted target/action/current-run scope, expiry and revocation constrain effects.

**Audit coverage:** The standalone real-guest systrap journey with independently read target canaries is accepted at its [recorded revision](https://github.com/craigbalding/safeyolo/issues/1561#issuecomment-6943564850). The current runner selects this journey; deployed cadence remains unverified.

**Conformance / action:** Retain guest-root, replay, narrowing, expiry/revocation and stale-run controls. Verify recurring execution separately from the accepted standalone run.

**Effort:** M. **Comments:** Retain guest-root, replay, narrowing and stale-generation coverage.

**Owner / remaining work:** [#1561](https://github.com/craigbalding/safeyolo/issues/1561). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_peer_support.py).

**Assurance decisions:** `management_evidence`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/installed_peer_support.py::main](../tests/blackbox/installed_peer_support.py#L347) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `peer-support`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections).

### BB-19 — Delegated approvals / route exceptions

**What and why:** Helpers decide only permitted typed actions for the exact principal, run and route.

**Audit coverage:** The standalone deterministic installed helper/worker journey is accepted at its [recorded revision](https://github.com/craigbalding/safeyolo/issues/1561#issuecomment-6943009258). Native process controller tests and the installed selector remain available; deployed cadence remains unverified.

**Conformance / action:** Retain exact network/gateway effects, wrong principal/route/run, expiry/revocation and no decision replay. Verify recurring execution separately; model/human modes remain optional.

**Effort:** M. **Comments:** Model/human modes remain optional; reuse native route-challenge coverage.

**Owner / remaining work:** [#1561](https://github.com/craigbalding/safeyolo/issues/1561). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_shared_approvals.py).

**Assurance decisions:** `management_evidence`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_gateway_scope.py](../tests/proxy_contracts/test_gateway_scope.py#L82) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-gateway-scope-py).
- [tests/proxy_contracts/test_gateway_risk_approval.py](../tests/proxy_contracts/test_gateway_risk_approval.py#L224) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-gateway-risk-approval-py).
- [tests/proxy_contracts/test_service_route_challenge.py](../tests/proxy_contracts/test_service_route_challenge.py#L125) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-service-route-challenge-py).
- [tests/proxy_contracts/test_shared_operator_approval.py](../tests/proxy_contracts/test_shared_operator_approval.py#L133) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-shared-operator-approval-py).
- [tests/proxy_contracts/test_operator_consumer_approval.py](../tests/proxy_contracts/test_operator_consumer_approval.py#L171) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operator-consumer-approval-py).
- [tests/proxy_contracts/test_installed_shared_approvals.py](../tests/proxy_contracts/test_installed_shared_approvals.py#L32) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-installed-shared-approvals-py).
- [tests/proxy_contracts/test_guard_approval_audit.py](../tests/proxy_contracts/test_guard_approval_audit.py#L39) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-guard-approval-audit-py).
- [tests/proxy_contracts/test_control_updates.py](../tests/proxy_contracts/test_control_updates.py#L111) — Native signals process; optional prepared Linux sandbox jobs. Evidence: Signed native candidates, owned NATS and controlled route requests; real isolated checks require the selected installed host.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-control-updates-py).
- [tests/blackbox/installed_access.py::main](../tests/blackbox/installed_access.py#L635) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `access`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `access`.
- [tests/blackbox/installed_shared_approvals.py::main](../tests/blackbox/installed_shared_approvals.py#L1471) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: manual; no recurring selector resolved.
- [tests/blackbox/installed_shared_approvals.py::deterministic_exchange](../tests/blackbox/installed_shared_approvals.py#L353) — Two actual Linux/systrap guests; deterministic typed decisions. Evidence: Worker and helper requests, exact network/gateway effects, wrong principal/route, expiry/revocation and run turnover; no model or human decision.
  Selection: default `systrap` section `shared-approvals`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections).
- [tests/proxy_contracts/test_shared_authority_assurance.py](../tests/proxy_contracts/test_shared_authority_assurance.py#L28) — Native proxy processes; controlled backend births and guest transport. Evidence: The actual deterministic controller, typed decisions and independently served origin effects; no real-guest claim.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-shared-authority-assurance-py).

### BB-20 — Agent-provided services

**What and why:** Only authorized callers/peers reach the service; a stopped provider cannot cause fallback.

**Audit coverage:** The standalone two-guest journey is accepted at its [recorded revision](https://github.com/craigbalding/safeyolo/issues/1561#issuecomment-6941122401). The systrap runner selects the driver; deployed cadence remains unverified.

**Conformance / action:** Retain exact delivery, caller/peer/method/path/port scope, revocation, closed/stopped provider and a live zero-hit fallback observer.

**Effort:** S–M. **Comments:** Trusted receiver identity, revocation and zero-hit fallback are already observed.

**Owner / remaining work:** [#1561](https://github.com/craigbalding/safeyolo/issues/1561). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_provider.py).

**Assurance decisions:** `provider_services`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_gateway_provider.py](../tests/proxy_contracts/test_gateway_provider.py#L60) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-gateway-provider-py).
- [tests/proxy_contracts/test_native_provider_recovery.py](../tests/proxy_contracts/test_native_provider_recovery.py#L109) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-provider-recovery-py).
- [tests/blackbox/installed_state_transition.py::main](../tests/blackbox/installed_state_transition.py#L503) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `continuity`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `continuity`.
- [tests/blackbox/installed_provider.py::main](../tests/blackbox/installed_provider.py#L423) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `provider`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections).

### BB-21 — Nested Docker / gateway

**What and why:** Extra guest privileges remain contained; Docker API scopes constrain actual effects.

**Audit coverage:** Maintained installed section; scheduled systrap selector. [Manual gateway effects accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6913325766); [fresh-token provider-stop observation accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6914345354); [bounded build/initial application accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6918014934); [retained application continuation accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6922996148); [bounded public pull accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6928512058); [gateway continuation accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6929891544); [prepared public-wrapper run 18935 accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6930793693) at controller 5893892b, production 607d8488 and complete qualified ae76 runtime. [Shipped systrap Docker result accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6933640925) at controller b0fa383677936be1e32582bb440b26ccefa09451, Linux AMD64 production 1a8c698e6ca23f83655a2801c10e99f4d24a6829 and guest archive 1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe. Applicable KVM/VZ proof remains unqualified. Public installation acquisition and installed catalogue qualification remain unverified; deployed cadence remains with #1563 and venue automation with #889.

**Conformance / action:** Prepared and shipped Ubuntu systrap proof cover the uninterrupted ten-checkpoint wrapper, provider-to-gateway transition, privileged inner containment, joined outbound/origin observations, Docker effects, adjacent refusal, revocation, daemon/provider failure and application persistence/deletion. Individual shipped Docker step output is checked by matching source assertions; raw stdout is not separately retained. Prepared-runtime acceptance and supplier comparison remain distinct from the shipped execution; neither establishes public installation acquisition or deployed recurrence. Failed run 18910 and earlier failed/setup attempts remain failed.

**Effort:** L. **Comments:** This is a distinct privilege configuration.

**Owner / remaining work:** [#1562](https://github.com/craigbalding/safeyolo/issues/1562). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_docker_preflight.py).

**Assurance decisions:** `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/installed_docker_preflight.py::main](../tests/blackbox/installed_docker_preflight.py#L1431) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `docker`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections).

### BB-22 — Live mounts / removal

**What and why:** Only approved paths/modes are exposed; removal truthfully reports remaining access.

**Audit coverage:** Maintained installed section; scheduled systrap selector. [Manual Ubuntu systrap journey accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6887897586). [Prepared public-shell mounts accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6932179534) at controller b0fa383677936be1e32582bb440b26ccefa09451, production 607d8488a7fdc5c0c6ada605077ca99b4cb21682, original runsc 65645198 and sentry f29a1416, guest archive 1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe. [Shipped systrap mounts accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6933640925) and [shipped KVM mounts accepted](https://github.com/craigbalding/safeyolo/issues/1562#issuecomment-6934606070) at controller b0fa383677936be1e32582bb440b26ccefa09451, Linux AMD64 production 1a8c698e6ca23f83655a2801c10e99f4d24a6829 and guest archive 1fb64d224df243e24bddbab42a4b1c12b876712270ae5eb59822cdb4c5f8febe. The physical VZ mount attempt stopped before invocation at third-listener admission; physical mount execution remains unproved. Public installation acquisition and installed catalogue qualification remain unverified; deployed cadence remains with #1563 and venue automation with #889.

**Conformance / action:** Preserve the accepted public-command journey with read-only/protected/reserved/stale refusals, busy file, working directory and memory map refusals, four actual detachments and eight process exits, saved/live intent after restart and unaffected peers/host files. Busy refusal is not removal. Failed preparation 18949 and 19223, the earlier shipped setup failures and their observer limits remain. Physical VZ execution, installed catalogue qualification and deployed recurrence remain unproved.

**Effort:** M. **Comments:** Retain busy-file refusal, real detach and unaffected-peer evidence.

**Owner / remaining work:** [#1562](https://github.com/craigbalding/safeyolo/issues/1562). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/nested-linux/live_mount_backend_proof.py).

**Assurance decisions:** `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/nested-linux/live_mount_backend_proof.py::run_proof](../tests/nested-linux/live_mount_backend_proof.py#L107) — Linux nested installed live mount; user/root backend-specific probes. Evidence: Real nested guests; manual venue.
  Selection: default `systrap` section `mounts`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `kvm` section `mounts`; default `vz` section `mounts`.

### BB-23 — Desktop / service sharing

**What and why:** Unlock/session authority binds to the target; expiry/revocation/stop ends access under the advertised lifecycle.

**Audit coverage:** The standalone installed viewer/session journey is accepted at its [recorded controller e940ae38 and production 607d8488](https://github.com/craigbalding/safeyolo/issues/1561#issuecomment-6947528574). Native controls remain separate; deployed cadence remains unverified.

**Conformance / action:** Retain live VNC bytes, invalid session/target, active-viewer revocation/expiry, stale-run refusal and independent-source preservation. Verify recurring execution separately.

**Effort:** M. **Comments:** No visual UI automation is required.

**Owner / remaining work:** [#1561](https://github.com/craigbalding/safeyolo/issues/1561). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_access.py).

**Assurance decisions:** `management_evidence`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_desktop_waiting_page.py](../tests/proxy_contracts/test_desktop_waiting_page.py#L128) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-desktop-waiting-page-py).
- [tests/blackbox/installed_access.py::main](../tests/blackbox/installed_access.py#L635) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `access`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `access`.

### BB-24 — Coord ownership / review / output authority

**What and why:** Ownership/review cannot be forged; evidence cannot authorize a different output or generation.

**Audit coverage:** The curated native cases are accepted at their [original f15e execution](https://github.com/craigbalding/safeyolo/issues/1561#issuecomment-6944537893), using real NATS without a guest. The scheduled Linux contract job selects these cases; deployed cadence remains unverified. Basic guest messaging is a separate narrower control.

**Conformance / action:** Retain exact selected/executed case receipts and independent acceptance; process tests do not prove a guest or deployed cadence.

**Effort:** M. **Comments:** Retain special-venue limitations; basic messaging is a narrower claim.

**Owner / remaining work:** [#1561](https://github.com/craigbalding/safeyolo/issues/1561). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/proxy/tests/native_coord/reviews.rs).

**Assurance decisions:** `management_evidence`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_coord_operator.py](../tests/proxy_contracts/test_native_coord_operator.py#L99) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-coord-operator-py).
- [tests/proxy_contracts/test_installed_coord_events.py](../tests/proxy_contracts/test_installed_coord_events.py#L24) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-installed-coord-events-py).
- [tests/proxy_contracts/test_native_factory_cli.py](../tests/proxy_contracts/test_native_factory_cli.py#L146) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-factory-cli-py).
- [tests/proxy_contracts/test_native_harness_attention.py](../tests/proxy_contracts/test_native_harness_attention.py#L87) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-harness-attention-py).
- [tests/blackbox/installed_access.py::main](../tests/blackbox/installed_access.py#L635) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: default `systrap` section `access`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections); default `vz` section `access`.
- [tests/blackbox/native_authority.py::main](../tests/blackbox/native_authority.py#L149) — Curated Coord cases on Linux or explicitly selected installed host-executor cases on Unix. Evidence: Per-control procedure receipts and exact executed cases with separate test/product/probe identities; process evidence without whole-workflow or Windows acceptance.
  Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).
- [proxy/tests/native_coord/reviews.rs](../proxy/tests/native_coord/reviews.rs#L100) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real instances/NATS; controlled run adapters.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-reviews-rs).
- [proxy/tests/native_coord/work.rs](../proxy/tests/native_coord/work.rs#L39) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real instances/NATS; controlled run adapters.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-work-rs).
- [proxy/tests/native_coord/outputs.rs](../proxy/tests/native_coord/outputs.rs#L23) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real instances/NATS; controlled run adapters.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-outputs-rs).
- [proxy/tests/native_coord/attestations.rs](../proxy/tests/native_coord/attestations.rs#L43) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real instances/NATS; controlled run adapters.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-attestations-rs).
- [tests/proxy_contracts/test_native_dispatch.py](../tests/proxy_contracts/test_native_dispatch.py#L47) — Native Coord/adapter; host identity. Evidence: Real NATS/HTTP with controlled external adapter and run fixtures; not a complete integrated before/after witness.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-dispatch-py).
- [tests/proxy_contracts/test_native_mattermost.py](../tests/proxy_contracts/test_native_mattermost.py#L389) — Native Coord/adapter; host identity. Evidence: Real NATS/HTTP with controlled external adapter and run fixtures; not a complete integrated before/after witness.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-mattermost-py).
- [tests/proxy_contracts/test_operational_events.py](../tests/proxy_contracts/test_operational_events.py#L122) — Native Coord/adapter; host identity. Evidence: Real NATS/HTTP with controlled external adapter and run fixtures; not a complete integrated before/after witness.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operational-events-py).
- [proxy/tests/native_coord/catch_up.rs](../proxy/tests/native_coord/catch_up.rs#L3) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-catch-up-rs).
- [proxy/tests/native_coord/continuation.rs](../proxy/tests/native_coord/continuation.rs#L14) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-continuation-rs).
- [proxy/tests/native_coord/diagnostics.rs](../proxy/tests/native_coord/diagnostics.rs#L123) — Native Agent API/MCP; host process; controlled HTTP failures. Evidence: Actual native client and scoped audit reader; canned body/deadline variants. These tests do not establish an installed guest or real-agent journey..
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-diagnostics-rs).
- [proxy/tests/native_coord/factory.rs](../proxy/tests/native_coord/factory.rs#L69) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-factory-rs).
- [proxy/tests/native_coord/github.rs](../proxy/tests/native_coord/github.rs#L90) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-github-rs).
- [proxy/tests/native_coord/inventory.rs](../proxy/tests/native_coord/inventory.rs#L67) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-inventory-rs).
- [proxy/tests/native_coord/room_status.rs](../proxy/tests/native_coord/room_status.rs#L37) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-room-status-rs).
- [proxy/tests/native_coord/signals.rs](../proxy/tests/native_coord/signals.rs#L229) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-signals-rs).
- [proxy/tests/native_coord/stage0.rs](../proxy/tests/native_coord/stage0.rs#L85) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-stage0-rs).
- [proxy/tests/native_coord/supervision.rs](../proxy/tests/native_coord/supervision.rs#L129) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-supervision-rs).
- [proxy/tests/native_coord/upgrade.rs](../proxy/tests/native_coord/upgrade.rs#L63) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-upgrade-rs).

### BB-25 — Federation authority / TLS

**What and why:** Destination owns the grant; identity, partition, rotation and revocation cannot widen authority.

**Audit coverage:** Curated TLS/NATS cases and a real-guest-to-separate-instance systrap selector; installed acceptance remains incomplete.

**Conformance / action:** Verify destination-owned guest effects and refusals, retained partition/restart/revocation and rotation cases; live tailnet remains separate.

**Effort:** L. **Comments:** Reuse support, delegation and rotation fixtures.

**Owner / remaining work:** [#1561](https://github.com/craigbalding/safeyolo/issues/1561). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/proxy/tests/native_coord/federation.rs).

**Assurance decisions:** `management_evidence`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/native_authority.py::main](../tests/blackbox/native_authority.py#L149) — Curated Coord cases on Linux or explicitly selected installed host-executor cases on Unix. Evidence: Per-control procedure receipts and exact executed cases with separate test/product/probe identities; process evidence without whole-workflow or Windows acceptance.
  Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).
- [tests/blackbox/installed_federation.py::main](../tests/blackbox/installed_federation.py#L188) — Two actual systrap guests and a separate destination instance on the same Linux host. Evidence: Real TLS/NATS, destination operator history, exact delivery, wrong principal/instance and trust revocation; no live Tailscale claim.
  Selection: default `systrap` section `federation`; [systrap](../.github/workflows/blackbox.yml) (scheduled/manual; default `systrap` sections); [retained](../.github/workflows/installed-arm64.yml) (conditional CI; default `systrap` sections).
- [proxy/tests/native_coord/federation.rs](../proxy/tests/native_coord/federation.rs#L267) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real instances/NATS; controlled run adapters.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-rs).
- [proxy/tests/native_coord/federation/guided.rs](../proxy/tests/native_coord/federation/guided.rs#L57) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-guided-rs).
- [proxy/tests/native_coord/federation/modes.rs](../proxy/tests/native_coord/federation/modes.rs#L44) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-modes-rs).
- [proxy/tests/native_coord/federation/operator.rs](../proxy/tests/native_coord/federation/operator.rs#L44) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-operator-rs).
- [proxy/tests/native_coord/federation/reliability.rs](../proxy/tests/native_coord/federation/reliability.rs#L316) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-reliability-rs).
- [proxy/tests/native_coord/federation/support.rs](../proxy/tests/native_coord/federation/support.rs#L197) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-support-rs).
- [proxy/tests/native_coord/federation/support_audit.rs](../proxy/tests/native_coord/federation/support_audit.rs#L43) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-support-audit-rs).
- [proxy/tests/native_coord/federation/support_authority.rs](../proxy/tests/native_coord/federation/support_authority.rs#L202) — Native Coord/NATS; host process; cfg and ignore annotations retain venue limits. Evidence: Real instances/NATS with controlled run-lifetime fixtures; not a real guest effect by itself.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-federation-support-authority-rs).

### BB-26 — Tailscale transport validation

**What and why:** Credentials are withheld without the correct node, interface and protected route.

**Audit coverage:** Maintained two-host refusal, live-source loss/recovery and destination-effect controllers with a fresh independent forwarding observer; protected execution pending.

**Conformance / action:** Execute wrong-node, isolated wrong-route/missing-interface, active source loss and restored-path phases; pair withheld bytes, canonical destination effects and owned cleanup.

**Effort:** L. **Comments:** Two-host bindings are supplied privately; isolated wrong-route/loss capability and deployed cadence remain unverified.

**Owner / remaining work:** [#1561](https://github.com/craigbalding/safeyolo/issues/1561). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/proxy/src/coord_rooms/federation/tailscale.rs).

**Assurance decisions:** `management_evidence`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/blackbox/installed_tailnet.py::main](../tests/blackbox/installed_tailnet.py#L523) — Manual two-host tailnet journey; real status, native CLI/Coord and unchanged source proxy/guest identities. Evidence: Fresh observer forwards to owned real NATS, brackets fixed phases on the source clock and forces an active reconnect. Destination verifies canonical effects, refused non-delivery and cleanup. Faults require authorized isolated contexts; no executed live-tailnet or scheduled coverage inferred.
  Selection: manual; no recurring selector resolved.
- [proxy/src/coord_rooms/federation/tailscale.rs](../proxy/src/coord_rooms/federation/tailscale.rs#L162) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Unit fixtures for node/interface/route validation; not a live tailnet witness.
  Exact identities: [source inventory](#witness-proxy-src-coord-rooms-federation-tailscale-rs-coord-rooms-federation-tailscale-tests).

### BB-27 — External TCP ingress

**What and why:** Owner is fixed at accept; client traffic cannot impersonate a guest run or cross partitions.

**Audit coverage:** Real-wire native tests; recurring.

**Conformance / action:** Conformant: retain.

**Effort:** —. **Comments:** Unauthenticated external-client exposure is an explicit operator choice.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/proxy/src/external_ingress/tests.rs).

**Assurance decisions:** `identity`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_ingress_observer.py](../tests/proxy_contracts/test_native_ingress_observer.py#L24) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-ingress-observer-py).
- [proxy/src/external_ingress/tests.rs](../proxy/src/external_ingress/tests.rs#L247) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real wire; independently owned local endpoints.
  Exact identities: [source inventory](#witness-proxy-src-external-ingress-tests-rs).

### BB-28 — Artifact integrity / archive confinement

**What and why:** Corrupt, incompatible or path-escaping inputs cannot activate or modify unrelated host paths.

**Audit coverage:** Real native-CLI BB in CI plus installed acquisition.

**Conformance / action:** Conformant: retain existing digest, size, path, link and metadata checks.

**Effort:** —. **Comments:** Valid BB evidence also lives outside tests/blackbox.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/test_guest_acquisition.py).

**Assurance decisions:** `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_managed_state.py](../tests/proxy_contracts/test_native_managed_state.py#L22) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-managed-state-py).
- [tests/test_guest_acquisition.py](../tests/test_guest_acquisition.py#L360) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-guest-acquisition-py).
- [tests/test_guest_upgrade.py](../tests/test_guest_upgrade.py#L67) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-guest-upgrade-py).
- [tests/test_component_upgrade.py](../tests/test_component_upgrade.py#L117) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-component-upgrade-py).
- [tests/test_linux_host.py](../tests/test_linux_host.py#L53) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-linux-host-py).
- [tests/blackbox/installed_storage.py::qualify](../tests/blackbox/installed_storage.py#L99) — Prepared native Linux installation; acquisition or prepared-guest reuse and two systrap boots with root/user persistence. Evidence: Rootless --boot uses the maintained pytest receipt and unavailable host sudo; standalone acquisition keeps its original scope. Both record actual package/guest/maps and owned cleanup; manual selection establishes no recurring cadence.
  Selection: manual; no recurring selector resolved.

### BB-29 — Named policy checks

**What and why:** Composition, evidence type, freshness and subject binding govern actual requests.

**Audit coverage:** Accepted #1543/#1544/#1546 fixtures; maintained named-checks and policy-recipe phases.

**Conformance / action:** Maintained native named-checks and pytest policy-recipe phases cover composition, binding, freshness, unknown/error, redirect and pending revocation. Preview observes zero assessed-target/dependency contact. The prepared real-job case remains required and incomplete without its selected host.

**Effort:** L. **Comments:** Retain accepted [typed/composition proof](https://github.com/craigbalding/safeyolo/issues/1543#issuecomment-6854609584), [job/service proof](https://github.com/craigbalding/safeyolo/issues/1544#issuecomment-6858612088), #1546 and [maintained BB-29 acceptance](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6901839101). The 30 nonignored native cases have [partial scheduled process evidence](https://github.com/craigbalding/safeyolo/actions/runs/43707854900/job/132807509327) at `d43ba93d`, before a later transport-test failure. The prepared real-job case was ignored. The focused receipt remains manual and incomplete without that case. These process/installed-layout selections boot no guest; no new installed-platform or live-provider pass is inferred.

**Owner / remaining work:** [#1563](https://github.com/craigbalding/safeyolo/issues/1563). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/1543).

**Assurance decisions:** `authorization`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_network_policy.py](../tests/proxy_contracts/test_native_network_policy.py#L191) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-network-policy-py).
- [tests/proxy_contracts/test_agent_api_policy.py](../tests/proxy_contracts/test_agent_api_policy.py#L121) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-policy-py).
- [tests/proxy_contracts/test_agent_api_policy_yaml.py](../tests/proxy_contracts/test_agent_api_policy_yaml.py#L51) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-policy-yaml-py).
- [tests/proxy_contracts/test_policy_authoring.py](../tests/proxy_contracts/test_policy_authoring.py#L93) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-policy-authoring-py).
- [tests/proxy_contracts/test_native_policy_cli.py](../tests/proxy_contracts/test_native_policy_cli.py#L54) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-policy-cli-py).
- [tests/proxy_contracts/test_service_effect_assessment.py](../tests/proxy_contracts/test_service_effect_assessment.py#L36) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-service-effect-assessment-py).
- [tests/proxy_contracts/test_control_updates.py](../tests/proxy_contracts/test_control_updates.py#L111) — Native signals process; optional prepared Linux sandbox jobs. Evidence: Signed native candidates, owned NATS and controlled route requests; real isolated checks require the selected installed host.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-control-updates-py).
- [proxy/src/http/policy_checks/execution_tests.rs](../proxy/src/http/policy_checks/execution_tests.rs#L127) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real native request/gateway; owned assessment service and origin.
  Exact identities: [source inventory](#witness-proxy-src-http-policy-checks-execution-tests-rs).
- [proxy/src/policy/checks.rs](../proxy/src/policy/checks.rs#L1551) — Native evaluator; process fixtures. Evidence: Composition, three-valued results, type/subject/version/freshness binding and offline preview; actual HTTP enforcement is separate.
  Exact identities: [source inventory](#witness-proxy-src-policy-checks-rs-policy-checks-tests).
- [proxy/src/policy/checks.rs](../proxy/src/policy/checks.rs#L2161) — Native recorded-evidence and candidate preview; process fixtures. Evidence: Recorded allow/deny/unknown/expiry, effective native controls and no preview budget charge.
  Exact identities: [source inventory](#witness-proxy-src-policy-checks-rs-policy-checks-fixture-tests).
- [proxy/src/policy/checks.rs](../proxy/src/policy/checks.rs#L2254) — Native numeric composition; process fixture. Evidence: Non-finite aggregation cannot create a positive finding.
  Exact identities: [source inventory](#witness-proxy-src-policy-checks-rs-policy-checks-composition-edge-tests).
- [proxy/src/policy/checks/execution/tests.rs](../proxy/src/policy/checks/execution/tests.rs#L1) — Native typed-result and captured-input boundary; process fixtures. Evidence: Exact captured GitHub evidence, adopted input mapping and caller-supplied provenance refusal; no live engine.
  Exact identities: [source inventory](#witness-proxy-src-policy-checks-execution-tests-rs).
- [proxy/src/coord_rooms/work/automatic_tests.rs](../proxy/src/coord_rooms/work/automatic_tests.rs#L410) — Native Work and HTTP service boundaries; process fixtures. Evidence: Real proxy/SQLite with independent helper-launch and service/effect counters; crash child and restart; uncertain dispatch is never automatically replayed.
  Exact identities: [source inventory](#witness-proxy-src-coord-rooms-work-automatic-tests-rs).

### BB-30 — Managed feeds

**What and why:** Invalid or stale refreshes cannot grant access contrary to configured policy.

**Audit coverage:** Accepted #1545 native CLI/proxy fixtures; maintained managed-feeds phase.

**Conformance / action:** Owned feed server covers acquisition, automatic membership change, malformed/partial/rejected updates, atomic last-valid activation, configured expiry, restart, rollback and recovery. Named-feed and local-list paths remain distinct witnesses.

**Effort:** M. **Comments:** Retain [feed proof](https://github.com/craigbalding/safeyolo/issues/1545#issuecomment-6858989106) and [maintained BB-30 acceptance](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6901839101). All eight native feed cases have [partial scheduled process evidence](https://github.com/craigbalding/safeyolo/actions/runs/43707854900/job/132807509327) at `d43ba93d`, before a later transport-test failure. The focused receipt remains manual. Both paths run native processes in an installed layout, without a guest or public-package acquisition; no recurring installed-guest coverage is established.

**Owner / remaining work:** [#1563](https://github.com/craigbalding/safeyolo/issues/1563). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/1545).

**Assurance decisions:** `policy_publication`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_network_policy.py](../tests/proxy_contracts/test_native_network_policy.py#L191) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-network-policy-py).
- [tests/proxy_contracts/test_agent_api_policy.py](../tests/proxy_contracts/test_agent_api_policy.py#L121) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-policy-py).
- [tests/proxy_contracts/test_agent_api_policy_yaml.py](../tests/proxy_contracts/test_agent_api_policy_yaml.py#L51) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-agent-api-policy-yaml-py).
- [tests/proxy_contracts/test_policy_authoring.py](../tests/proxy_contracts/test_policy_authoring.py#L93) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-policy-authoring-py).
- [tests/proxy_contracts/test_native_policy_cli.py](../tests/proxy_contracts/test_native_policy_cli.py#L54) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-policy-cli-py).
- [tests/proxy_contracts/test_service_effect_assessment.py](../tests/proxy_contracts/test_service_effect_assessment.py#L36) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-service-effect-assessment-py).
- [proxy/tests/native_policy_feeds.rs](../proxy/tests/native_policy_feeds.rs#L281) — Native CLI/proxy in an installed layout; owned feed server; no guest. Evidence: Real acquisition, refresh and request decisions with retained snapshot provenance and independent destination contact observations.
  Exact identities: [source inventory](#witness-proxy-tests-native-policy-feeds-rs).

### BB-31 — Hyperlight capabilities

**What and why:** Both engines receive only adopted scoped capabilities; revoked/expired invocations cannot retain authority.

**Audit coverage:** Accepted #1549/#1550/#1552 engine fixtures; manual two-engine driver and native mediated-services phase.

**Conformance / action:** The shared real-engine driver covers permitted GitHub reads, destination/method/path/repository and socket/DNS/direct-IP/ABI refusal, finite limits, cancellation/revocation/shutdown and late completion. Per-engine checkpoints and owned cleanup are required. Native mediated-services tests alone establish no VM boundary.

**Effort:** L. **Comments:** Retain [maintained two-engine acceptance](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6902006974), [engine evidence](https://github.com/craigbalding/safeyolo/issues/1552#issuecomment-6877115753) and [installed adoption proof](https://github.com/craigbalding/safeyolo/issues/1552#issuecomment-6877595456) at their recorded sources, profiles and Linux/Mac limits. The maintained execution used pinned accepted debug artifacts; it is not current-production qualification. Six native bridge cases have [partial scheduled process evidence](https://github.com/craigbalding/safeyolo/actions/runs/43707854900/job/132807509327) at `d43ba93d`, before a later transport-test failure; these cases prove no VM boundary. KVM/HVF, compatible artifacts and scoped GitHub credentials are explicit prerequisites for the manual two-engine driver. A missing engine or lifetimes-only run cannot complete its receipt. The selected AMD64 engine dispatch is deployed through the daily devstack rundeck caller. Its natural 19 November 2026 run 7fd9c86285a64d76af2ec5daaebad022 passed the engine phase; the five-dispatch adapter and cleanup returned zero. The independently reviewed recurrence receipt retains source, run and phase operands; no separate ARM64 recurrence is inferred. See the [independent AMD64 cadence disposition](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6967616840).

**Owner / remaining work:** [#1563](https://github.com/craigbalding/safeyolo/issues/1563). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/1550).

**Assurance decisions:** `foreign_and_embedded`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/test_hyperlight_adoption.py](../tests/test_hyperlight_adoption.py#L21) — Host job authoring and adoption; controlled adapters. Evidence: Controlled build/runner adapters; not a live Hyperlight boundary pass.
  Exact identities: [source inventory](#witness-tests-test-hyperlight-adoption-py).
- [tests/test_hyperlight_service_checker.py](../tests/test_hyperlight_service_checker.py#L45) — Host job authoring and adoption; controlled adapters. Evidence: Controlled build/runner adapters; not a live Hyperlight boundary pass.
  Exact identities: [source inventory](#witness-tests-test-hyperlight-service-checker-py).
- [tests/test_job_authoring.py](../tests/test_job_authoring.py#L61) — Host job authoring and adoption; controlled adapters. Evidence: Controlled build/runner adapters; not a live Hyperlight boundary pass.
  Exact identities: [source inventory](#witness-tests-test-job-authoring-py).
- [tests/blackbox/host/hyperlight_adoption.py::main](../tests/blackbox/host/hyperlight_adoption.py#L165) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: manual; no recurring selector resolved.
- [tests/blackbox/host/hyperlight_services.py::main](../tests/blackbox/host/hyperlight_services.py#L499) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: manual; no recurring selector resolved.
- [proxy/src/jobs/hyperlight/tests.rs](../proxy/src/jobs/hyperlight/tests.rs#L63) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Controlled executable-helper supervisor; no VM or Python checker execution.
  Exact identities: [source inventory](#witness-proxy-src-jobs-hyperlight-tests-rs).
- [proxy/src/jobs/mediated/tests.rs](../proxy/src/jobs/mediated/tests.rs#L31) — Native mediated job capabilities; host process. Evidence: Controlled runtime, artifact and credential fixtures; real native capability enforcement.
  Exact identities: [source inventory](#witness-proxy-src-jobs-mediated-tests-rs).
- [proxy/src/policy/checks/execution/tests.rs](../proxy/src/policy/checks/execution/tests.rs#L1) — Native typed-result and captured-input boundary; process fixtures. Evidence: Exact captured GitHub evidence, adopted input mapping and caller-supplied provenance refusal; no live engine.
  Exact identities: [source inventory](#witness-proxy-src-policy-checks-execution-tests-rs).

### BB-32 — Before/after enforcement

**What and why:** Required checks bind to the exact operation/output; follow-up effects are durable without unsafe external retry.

**Audit coverage:** Accepted #1551 native transition fixtures; maintained before-after phase.

**Conformance / action:** Real native Work/service boundaries cover omitted selectors, stale/substituted evidence, exact output replacement, pending revocation, committed-obligation recovery, crash after dispatch and explicit uncertainty without automatic replay. Follow-up failure cannot undo the committed transition.

**Effort:** L. **Comments:** Retain [maintained BB-32 acceptance](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6901839101). All eleven native transition cases have [partial scheduled process evidence](https://github.com/craigbalding/safeyolo/actions/runs/43707854900/job/132807509327) at `d43ba93d`, before a later transport-test failure. The focused receipt remains manual. Owned effect counters and controlled providers observe enforcement. These process results do not establish an external GitHub merge/release boundary or repeat #1552 installed factory proof.

**Owner / remaining work:** [#1563](https://github.com/craigbalding/safeyolo/issues/1563). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/1551).

**Assurance decisions:** `external_effects`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_coord_operator.py](../tests/proxy_contracts/test_native_coord_operator.py#L99) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-coord-operator-py).
- [tests/proxy_contracts/test_installed_coord_events.py](../tests/proxy_contracts/test_installed_coord_events.py#L24) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-installed-coord-events-py).
- [tests/proxy_contracts/test_native_factory_cli.py](../tests/proxy_contracts/test_native_factory_cli.py#L146) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-factory-cli-py).
- [tests/proxy_contracts/test_native_harness_attention.py](../tests/proxy_contracts/test_native_harness_attention.py#L87) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-harness-attention-py).
- [proxy/tests/native_coord/reviews.rs](../proxy/tests/native_coord/reviews.rs#L100) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real instances/NATS; controlled run adapters.
  Exact identities: [source inventory](#witness-proxy-tests-native-coord-reviews-rs).
- [proxy/src/http/policy_checks/execution_tests.rs](../proxy/src/http/policy_checks/execution_tests.rs#L127) — Native Rust; host OS/cfg and ignore attributes are retained per source. Evidence: Real native request/gateway; owned assessment service and origin.
  Exact identities: [source inventory](#witness-proxy-src-http-policy-checks-execution-tests-rs).
- [tests/proxy_contracts/test_native_dispatch.py](../tests/proxy_contracts/test_native_dispatch.py#L47) — Native Coord/adapter; host identity. Evidence: Real NATS/HTTP with controlled external adapter and run fixtures; not a complete integrated before/after witness.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-dispatch-py).
- [tests/proxy_contracts/test_native_mattermost.py](../tests/proxy_contracts/test_native_mattermost.py#L389) — Native Coord/adapter; host identity. Evidence: Real NATS/HTTP with controlled external adapter and run fixtures; not a complete integrated before/after witness.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-mattermost-py).
- [tests/proxy_contracts/test_operational_events.py](../tests/proxy_contracts/test_operational_events.py#L122) — Native Coord/adapter; host identity. Evidence: Real NATS/HTTP with controlled external adapter and run fixtures; not a complete integrated before/after witness.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-operational-events-py).
- [proxy/src/policy/checks/execution/tests.rs](../proxy/src/policy/checks/execution/tests.rs#L1) — Native typed-result and captured-input boundary; process fixtures. Evidence: Exact captured GitHub evidence, adopted input mapping and caller-supplied provenance refusal; no live engine.
  Exact identities: [source inventory](#witness-proxy-src-policy-checks-execution-tests-rs).
- [proxy/src/coord_rooms/work/automatic_tests.rs](../proxy/src/coord_rooms/work/automatic_tests.rs#L410) — Native Work and HTTP service boundaries; process fixtures. Evidence: Real proxy/SQLite with independent helper-launch and service/effect counters; crash child and restart; uncertain dispatch is never automatically replayed.
  Exact identities: [source inventory](#witness-proxy-src-coord-rooms-work-automatic-tests-rs).

### BB-33 — Rootless guest preparation

**What and why:** Install/update/cleanup needs no sudo after prerequisites and retains required metadata/usable guest behavior.

**Audit coverage:** Feasibility #1553 and all seven #1554 product criteria at 607d8488 are independently accepted. The maintained process/native-kernel and booted-guest phases at cb04eb10 have combined independent BB-33 acceptance under #1563.

**Conformance / action:** The manual rootless-preparation --execute selector runs native install/update/cache, active cancellation, failed-stage cleanup and existing-install preservation controls with recorded preparation and unavailable candidate sudo. It also runs the accepted default/distinct-map production metadata witness against the retained baseline. Every selected parameter case and setup/call/teardown must pass. The separate --boot selection reuses installed_storage.py and the prepared public guest for two systrap boots, root/user persistence, fresh-overlay checks and owned cleanup with host sudo unavailable. Without --execute or --boot, the selector remains a read-only digest-bound storage-receipt observer.

**Effort:** L. **Comments:** Retain [accepted feasibility](https://github.com/craigbalding/safeyolo/issues/1553#issuecomment-6892802583), [all-seven product acceptance](https://github.com/craigbalding/safeyolo/issues/1554#issuecomment-6899892091) and [combined maintained BB-33 acceptance](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6901362593). The executable fixture requires prepared Linux AMD64 UID/GID1000, delegated default/distinct ranges, the retained baseline and four verified specimens. It imports small synthetic trees, observes native ACL/xattr/capability/set-ID effects and specific unsupported refusals, then cleans owned trees without sudo. The process phase proves native-kernel metadata; the separate boot phase proves gVisor usability, not new gVisor ACL/capability enforcement or macOS qualification. The boot phase verifies the retained archive/index, records package and runtime hashes, observes actual UID/GID maps and reuses the lower tree without download, import or reinstall. The retained storage receipt separately covers installation, repeat/cache, same-index upgrade and two usable systrap boots; its original setup failures and narrower metadata/failure limits remain. Product Mac usability does not prove normal shutdown; installed same-index upgrades do not prove changed guest bytes. The selected AMD64 rootless-process and rootless-boot phases are deployed through the daily devstack rundeck caller. Their natural 19 November 2026 run 7fd9c86285a64d76af2ec5daaebad022 returned zero with no timeout or truncation; the independently reviewed receipt retains the actual pins and phase operands. This does not extend the product or platform qualifications above. See the [independent AMD64 cadence disposition](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6967616840). Missing prerequisites, omitted cases, observer or cleanup failure remain incomplete. Phase completion remains separate from independent control acceptance.

**Owner / remaining work:** [#1563](https://github.com/craigbalding/safeyolo/issues/1563). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/1553).

**Assurance decisions:** `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_managed_state.py](../tests/proxy_contracts/test_native_managed_state.py#L22) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-managed-state-py).
- [tests/test_guest_acquisition.py](../tests/test_guest_acquisition.py#L360) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-guest-acquisition-py).
- [tests/test_guest_upgrade.py](../tests/test_guest_upgrade.py#L67) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-guest-upgrade-py).
- [tests/test_component_upgrade.py](../tests/test_component_upgrade.py#L117) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-component-upgrade-py).
- [tests/test_linux_host.py](../tests/test_linux_host.py#L53) — Ordinary native CLI; Linux/macOS; host identity. Evidence: Owned OCI registry/archive fixtures and real native CLI; selected acquisition setup may use guest-only/rootfs helpers.
  Exact identities: [source inventory](#witness-tests-test-linux-host-py).
- [tests/blackbox/rootless_preparation.py::observe](../tests/blackbox/rootless_preparation.py#L50) — Retained native Linux storage observations; recorded ordinary host identity and systrap guest root/user. Evidence: Manual run-controls.sh rootless-preparation; canonical source/digest supplied separately; recorded operands checked without command replay or independent product acceptance.
  Selection: manual; no recurring selector resolved.
- [tests/blackbox/rootless_metadata.py::qualify](../tests/blackbox/rootless_metadata.py#L107) — Prepared Linux AMD64 ordinary UID/GID1000; native-kernel metadata and default/distinct UID/GID imports. Evidence: Manual rootless-preparation --execute; retained baseline/specimens, installed CLI and declared namespace preparation; no guest boot or deployed cadence inferred.
  Selection: manual; no recurring selector resolved.
- [tests/blackbox/installed_storage.py::qualify](../tests/blackbox/installed_storage.py#L99) — Prepared native Linux installation; acquisition or prepared-guest reuse and two systrap boots with root/user persistence. Evidence: Rootless --boot uses the maintained pytest receipt and unavailable host sudo; standalone acquisition keeps its original scope. Both record actual package/guest/maps and owned cleanup; manual selection establishes no recurring cadence.
  Selection: manual; no recurring selector resolved.

### BB-34 — Sudo disclosure

**What and why:** Exact privileged commands and reasons appear before existing consent and execution.

**Audit coverage:** Accepted #1555 fixtures; maintained sudo-disclosure pytest phase.

**Conformance / action:** Reuse exact preview/execution argument agreement, quoting, helper effects, consent/decline, fresh/cached/passwordless/refused authentication, early cleanup, failure/retry and prepared-host no-op cases.

**Effort:** M. **Comments:** Retain [disclosure proof](https://github.com/craigbalding/safeyolo/issues/1555#issuecomment-6874142655) and [maintained BB-34 acceptance](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6901839101). Authentication uses controlled executors for current host preparation and command installation. Public-installer cases cover early rootless guest preparation without sudo; BB-33 owns its full metadata, cleanup and usability proof. The selected AMD64 sudo-disclosure phase is deployed through the daily devstack rundeck caller. Its natural 19 November 2026 run 7fd9c86285a64d76af2ec5daaebad022 returned zero with no timeout or truncation. The independently reviewed recurrence receipt retains exact source and phase operands; the authentication and macOS limits below remain. See the [independent AMD64 cadence disposition](https://github.com/craigbalding/safeyolo/issues/1563#issuecomment-6967616840). This is not production-host authentication or macOS qualification. Existing consent is unchanged.

**Owner / remaining work:** [#1563](https://github.com/craigbalding/safeyolo/issues/1563). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/1555).

**Assurance decisions:** `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_managed_state.py](../tests/proxy_contracts/test_native_managed_state.py#L22) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-managed-state-py).
- [tests/test_host_sudo.py](../tests/test_host_sudo.py#L41) — Host command disclosure; controlled subprocess adapter. Evidence: Controlled command/consent executor; not installed sudo proof.
  Exact identities: [source inventory](#witness-tests-test-host-sudo-py).
- [tests/test_public_installer.py::test_guest_cache_is_prepared_during_host_extraction_without_early_activation](../tests/test_public_installer.py#L842) — Public bootstrap composition; Linux ordinary account with guest sudo. Evidence: Owned registry, controlled host package and held rootless guest validation; no guest-preparation sudo or early activation; no public release acquisition.
  Exact identities: [source inventory](#witness-tests-test-public-installer-py-test-guest-cache-is-prepared-during-host-extraction-without-early-activation).

### BB-35 — Native target identity

**What and why:** The selected package/binary is the native implementation and actual runtime backend is identified.

**Audit coverage:** Strong recurring identity checks exist.

**Conformance / action:** Conformant: retain.

**Effort:** —. **Comments:** Record product, controller and guest identities separately; this is not the old mitmproxy target.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/installed_host_smoke.py).

**Assurance decisions:** `identity`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/proxy_contracts/test_native_blackbox_lifecycle.py](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L36) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-native-blackbox-lifecycle-py).
- [tests/proxy_contracts/test_lifecycle_batch.py](../tests/proxy_contracts/test_lifecycle_batch.py#L258) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-lifecycle-batch-py).
- [tests/proxy_contracts/test_readiness.py](../tests/proxy_contracts/test_readiness.py#L13) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-readiness-py).
- [tests/proxy_contracts/test_first_agent_launch.py](../tests/proxy_contracts/test_first_agent_launch.py#L49) — Native process; Linux/macOS; host identity. Evidence: Owned HTTP origins; real native executable.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-first-agent-launch-py).
- [tests/blackbox/host/native/test_installed_native.py](../tests/blackbox/host/native/test_installed_native.py#L38) — Installed host proxy; Linux/macOS; host identity. Evidence: Real selected native executable and owned origin.
  Exact identities: [source inventory](#witness-tests-blackbox-host-native-test-installed-native-py).
- [tests/blackbox/installed_ingress.py::main](../tests/blackbox/installed_ingress.py#L195) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: optional `systrap` section `ingress`; default `kvm` section `ingress`.
- [tests/blackbox/installed_host_smoke.py::main](../tests/blackbox/installed_host_smoke.py#L995) — Installed driver; actual backend and identities recorded in its own report. Evidence: Real installed process/guest where the driver boots one; owned endpoints; no assertion that manual execution recurs.
  Selection: manual; no recurring selector resolved.
- [tests/proxy_contracts/test_public_arm_install_workflow.py](../tests/proxy_contracts/test_public_arm_install_workflow.py#L40) — Workflow/report fixtures; controlled installer adapters. Evidence: Controlled acquisition/report consumers; not a fresh installed native identity pass.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-public-arm-install-workflow-py).

### BB-36 — Required assertions executed

**What and why:** A missing prerequisite, skipped check or incomplete procedure cannot produce a complete receipt.

**Audit coverage:** Section/cleanup results exist; per-assertion accounting is partial.

**Conformance / action:** Extend per-phase machine-readable expected/executed checks by backend and guest identity, with explicit exclusions.

**Effort:** M. **Comments:** Named obligations; do not substitute total test counts or treat source inventory as execution.

**Owner / remaining work:** [#1558](https://github.com/craigbalding/safeyolo/issues/1558). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/blob/c9543b5c68fd86d218e61e32320864b337c52b9d/tests/blackbox/run-tests.sh).

**Current existence:** resolved witnesses listed below; no current run inferred.

- [tests/test_blackbox_execution_receipt.py](../tests/test_blackbox_execution_receipt.py#L21) — Receipt/catalogue fixtures; host identity. Evidence: Controlled reports and real fixture pytest; not product containment.
  Exact identities: [source inventory](#witness-tests-test-blackbox-execution-receipt-py).
- [tests/test_blackbox_catalogue.py](../tests/test_blackbox_catalogue.py#L21) — Receipt/catalogue fixtures; host identity. Evidence: Controlled reports and real fixture pytest; not product containment.
  Exact identities: [source inventory](#witness-tests-test-blackbox-catalogue-py).
- [tests/proxy_contracts/test_public_arm_install_workflow.py](../tests/proxy_contracts/test_public_arm_install_workflow.py#L40) — Workflow/report fixtures; controlled installer adapters. Evidence: Controlled acquisition/report consumers; not a fresh installed native identity pass.
  Exact identities: [source inventory](#witness-tests-proxy-contracts-test-public-arm-install-workflow-py).

### BB-37 — Backend coverage

**What and why:** Applicable control outcomes recur on each supported backend.

**Audit coverage:** Systrap scheduled; KVM/VZ automation unfinished under #889.

**Conformance / action:** Complete existing #889 venue work and fill justified per-backend selection omissions.

**Effort:** M + host setup. **Comments:** Compare control outcomes, not counts; retain independent hardware deployment architecture.

**Owner / remaining work:** [#889](https://github.com/craigbalding/safeyolo/issues/889). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/889).

**Current existence:** no maintained witness resolved. The owner above retains the missing control.


### BB-38 — Host-operation authority and native execution

**What and why:** Authenticated host operations retain exact scope and revision checks; native execution has observable bounds and cleanup.

**Audit coverage:** Native protocol and installed Unix fixtures, including adaptive application reads, fixed-service control, retained configuration effects, quiet/reviewed updates and dependency swaps. The Windows fixture selects packaged starters, machine/workload-user registry views, path aliases/reparse points, inherited handles, signed API isolation, catalogue updates/withdrawal, executable swaps, revocation/expiry, native bounds, controller crash recovery and storage limits. It retains canonical output and independent Windows service, file-identity and Job Object observations; platform results remain separate.

**Conformance / action:** Qualify all eight witness groups through installed interfaces. Independent acceptance at PR #1695/41b29878 covers useful progress and refused expansion, quiet updates and the selected fallback, measured cleanup/recovery, and real Windows starter categories, modes and advertised bounds. Complete native deployment/composition evidence and maintained coverage remain open.

**Effort:** L. **Comments:** The separately installed executor and independent host observers retain actual source, operating system, account, mode and output limits. Accepted evidence joins a real Linux sandbox to its co-located Linux target and a standalone macOS target over HTTPS, plus native Python-free Windows foreground and Windows Service runs. Windows proves every documented starter category, service status/start/stop/restart, Job Object memory/process/output/deadline bounds, protected paths, registry views, encoding and inherited handles; it does not claim disk/network containment, containment of delegated service effects, another architecture or a full Windows host stack. Linux adds whole-API scope refusals, cancellation/descendants, duplicate/lost-reply and crash reconciliation, expiry/revocation, adaptive investigation and stored-binding repair. Reuse the accepted #1675 finite Hyperlight/model and real-gVisor required-check evidence at their recorded limits; no general provider/platform cross-product is implied. An installed approved-stale journey now refuses both the original revisions and a fresh preparation carrying the earlier exact approval, with no new native job. Private assessment retains an unresolved full grant when four fixture operations lack annotations; the isolated characterised service pair reports same-resource match and different-resource non-match. The middle same-versus-other-service restart observation remains missing. A co-located physical macOS proxy/VZ guest/target reaches authenticated discovery, proposal and admission, but its required Seatbelt child exits71 with sandbox_apply denied; useful native execution there remains incomplete. Keep that actual facility failure visible without changing the host profile or claiming containment. Preserve the original uncertain results, persistent effects and explicit platform exceptions. See [the criterion disposition](https://github.com/craigbalding/safeyolo/issues/1677#issuecomment-7099825211). Missing required facilities leave the affected run incomplete.

**Owner / remaining work:** [#1677](https://github.com/craigbalding/safeyolo/issues/1677). [Audit source / evidence context](https://github.com/craigbalding/safeyolo/issues/1677).

**Assurance decisions:** `authorization`, `other_sinks_and_launch`.

**Current existence:** resolved witnesses listed below; no current run inferred.

- [host-executor/tests/unix_native.rs](../host-executor/tests/unix_native.rs#L191) — Real Unix installed executor; local authenticated HTTP; explicit native prerequisites. Evidence: Independent file and socket observations plus canonical job/output and owned cgroup/service checks; ignored unless explicitly selected; no Windows or whole-workflow acceptance.
  Exact identities: [source inventory](#witness-host-executor-tests-unix-native-rs).
- [proxy/tests/host_execution.rs](../proxy/tests/host_execution.rs#L174) — Controlled authenticated protocol, signatures, ledger and HTTP fixtures. Evidence: Protocol/component evidence; simulated dispatch does not establish native containment.
  Exact identities: [source inventory](#witness-proxy-tests-host-execution-rs).
- [proxy/src/policy_adoption_tests.rs](../proxy/src/policy_adoption_tests.rs#L20) — Controlled saved/runtime catalogue and gateway binding adoption. Evidence: Exact binding snapshots, rejected announcement stability and policy transaction rollback; no native execution claim.
  Exact identities: [source inventory](#witness-proxy-src-policy-adoption-tests-rs).
- [proxy/src/host_execution/gateway/tests.rs](../proxy/src/host_execution/gateway/tests.rs#L402) — Controlled gateway authentication, scope, dispatch and reply-loss fixtures. Evidence: Real gateway request parsing and controlled upstream; not a deployed target or native boundary.
  Exact identities: [source inventory](#witness-proxy-src-host-execution-gateway-tests-rs).
- [proxy/src/host_execution/gateway/task_action_tests.rs](../proxy/src/host_execution/gateway/task_action_tests.rs#L89) — Configured task/action admission and bounded checker fixtures. Evidence: Controlled check results and upstream dispatch counts; model measurements remain separate supplementary evidence.
  Exact identities: [source inventory](#witness-proxy-src-host-execution-gateway-task-action-tests-rs).
- [tests/blackbox/native_authority.py::main](../tests/blackbox/native_authority.py#L149) — Curated Coord cases on Linux or explicitly selected installed host-executor cases on Unix. Evidence: Per-control procedure receipts and exact executed cases with separate test/product/probe identities; process evidence without whole-workflow or Windows acceptance.
  Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

## Exact witness identities and maintained selection

Python identities name pytest functions/methods; a phase receipt expands parameter IDs and records each case. Cargo identities name the target and exact Rust test name. Ignore and cfg attributes remain source constraints. CI selectors describe maintained execution, not a passing receipt on every host. No hardware deployment or installed result is inferred from these files.

**Scheduled installed lanes resolved from automation:** `package`, `systrap`. Unlisted KVM/VZ venues remain with [#889](https://github.com/craigbalding/safeyolo/issues/889). A workflow selector describes intended cadence; it is not proof that a host deployment ran.

<a id="witness-host-executor-tests-unix-native-rs"></a>
### [`host-executor/tests/unix_native.rs`](../host-executor/tests/unix_native.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native host_receiver_positive_control_waits_for_readiness -- --exact`](../host-executor/tests/unix_native.rs#L191) — `#![cfg(unix)]`
Selection: manual `native-authority --suite host-execution` (prepared installed executor, probe and owned service); ignored by default.

- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_catalogue_adoption_persists_and_stale_preparation_cannot_launch -- --exact --ignored`](../host-executor/tests/unix_native.rs#L545) — `#![cfg(unix)]`; `#[ignore = "requires the existing native Unix fixture and prepared probe or C compiler"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_quiet_updates_execute_new_bytes_without_inheriting_expanded_authority -- --exact --ignored`](../host-executor/tests/unix_native.rs#L760) — `#![cfg(unix)]`; `#[ignore = "requires the prepared native Unix fixture"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_check_serve_and_reload_share_ledger_validation -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1033) — `#![cfg(unix)]`; `#[ignore = "requires the same installed native Unix fixture as the lifecycle test"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_unix_read_paths_resolve_without_sibling_contents -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1114) — `#![cfg(unix)]`; `#[ignore = "requires native Unix host; prepared probe or C compiler; Linux also needs bubblewrap and delegated cgroup v2"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_unix_bounds_lifecycle_reload_and_lost_reply -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1135) — `#![cfg(unix)]`; `#[ignore = "requires native Unix host; prepared probe or C compiler; Linux also needs bubblewrap and delegated cgroup v2"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_storage_exhaustion_preserves_output_replay_and_restart -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1354) — `#![cfg(unix)]`; `#[ignore = "requires the same installed native Unix fixture as the lifecycle test"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_user_service_profiles_and_channel_refusals -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1426) — `#![cfg(unix)]`; `#[ignore = "requires SAFEYOLO_HOST_EXECUTOR_SERVICE naming an operator-prepared owned user service"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_executable_swaps_preserve_size_and_mtime_but_cannot_launch -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1595) — `#![cfg(unix)]`; `#[ignore = "requires the prepared native Unix fixture"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_dependency_swaps_preserve_metadata_but_cannot_launch -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1659) — `#![cfg(unix)]`; `#[ignore = "requires the prepared native Unix fixture"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_api_authentication_and_cross_principal_reads_cannot_change_authority -- --exact --ignored`](../host-executor/tests/unix_native.rs#L1784) — `#![cfg(unix)]`; `#[ignore = "requires the prepared native Unix fixture"]`
- [`cargo test --manifest-path host-executor/Cargo.toml --test unix_native installed_adaptive_investigation_and_retained_configuration_effects -- --exact --ignored`](../host-executor/tests/unix_native.rs#L2251) — `#![cfg(unix)]`; `#[ignore = "requires the prepared native Unix fixture, installed assessor CLI and owned user service"]`

<a id="witness-proxy-tests-host-execution-rs"></a>
### [`proxy/tests/host_execution.rs`](../proxy/tests/host_execution.rs)

Selection: manual native phase `host-execution` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_admission_replay_restart_and_uncertain_process_reservation -- --exact`](../proxy/tests/host_execution.rs#L174)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_cancellation_output_limits_ownership_and_fresh_authority -- --exact`](../proxy/tests/host_execution.rs#L262)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_ledger_lock_target_and_capacity_refusals_leave_no_admission -- --exact`](../proxy/tests/host_execution.rs#L382)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_ledger_refuses_links_and_public_files -- --exact`](../proxy/tests/host_execution.rs#L412)
Selection: child helper: Executed by durable_process_failure_after_committed_admission with its private child environment; no separate phase obligation..

- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_crash_child -- --exact --ignored`](../proxy/tests/host_execution.rs#L430) — `#[ignore = "child process for durable_process_failure_after_committed_admission"]`
Selection: manual native phase `host-execution` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_process_failure_after_committed_admission -- --exact`](../proxy/tests/host_execution.rs#L455)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_storage_failure_rolls_back_call_and_replay_reservations -- --exact`](../proxy/tests/host_execution.rs#L477)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_mutation_capacity_preserves_one_cancellation_per_active_job -- --exact`](../proxy/tests/host_execution.rs#L511)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution durable_uncertain_concurrency_survives_a_new_grant_revision -- --exact`](../proxy/tests/host_execution.rs#L601)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution shared_negative_fixtures_cross_authenticated_validation -- --exact`](../proxy/tests/host_execution.rs#L656)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution signatures_rotation_expiry_and_fresh_authority_are_independent -- --exact`](../proxy/tests/host_execution.rs#L679)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution membership_scope_defaults_and_proposal_inputs_do_not_confer_authority -- --exact`](../proxy/tests/host_execution.rs#L792)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution one_package_binds_native_gateway_material_and_target_scope -- --exact`](../proxy/tests/host_execution.rs#L939)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution generated_gateway_contract_requires_bound_resource_and_exact_operation_payload -- --exact`](../proxy/tests/host_execution.rs#L987)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution invocation_cannot_replace_definitions_or_add_an_executable -- --exact`](../proxy/tests/host_execution.rs#L1038)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution same_authenticated_http_protocol_on_standalone_and_safeyolo_targets -- --exact`](../proxy/tests/host_execution.rs#L1315)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution issuer_namespaces_job_disclosure_and_terminal_states_are_explicit -- --exact`](../proxy/tests/host_execution.rs#L1508)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution command_words_preserve_fixed_implementation_and_never_evaluate_shell_text -- --exact`](../proxy/tests/host_execution.rs#L1632)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution local_action_ceiling_and_content_revisions_cannot_be_bypassed_by_labels -- --exact`](../proxy/tests/host_execution.rs#L1676)
- [`cargo test --manifest-path proxy/Cargo.toml --test host_execution stale_preparation_refreshes_through_real_discovery_proposal_and_ledger_without_invoking -- --exact`](../proxy/tests/host_execution.rs#L1728)

<a id="witness-proxy-src-policy-adoption-tests-rs"></a>
### [`proxy/src/policy_adoption_tests.rs`](../proxy/src/policy_adoption_tests.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib policy_adoption_tests::catalogue_discovery_uses_actual_bytes_and_activates_coherent_gateway_definitions -- --exact`](../proxy/src/policy_adoption_tests.rs#L20)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy_adoption_tests::adoption_save_failure_preserves_saved_and_active_policy -- --exact`](../proxy/src/policy_adoption_tests.rs#L284)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy_adoption_tests::adoption_receipt_failure_rolls_back_actual_saved_and_active_policy -- --exact`](../proxy/src/policy_adoption_tests.rs#L332)

<a id="witness-proxy-src-host-execution-gateway-tests-rs"></a>
### [`proxy/src/host_execution/gateway/tests.rs`](../proxy/src/host_execution/gateway/tests.rs)

Selection: manual native phase `host-execution` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::package_mismatch_discovery_reports_revisions_without_a_possible_job -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L402) — `#[cfg(target_os = "linux")]`
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::lost_cancel_reply_retains_the_original_job_for_inspection -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L428) — `#[cfg(target_os = "linux")]`
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::adaptive_operations_and_lost_reply_use_real_target_receipts_without_duplicate_dispatch -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L454) — `#[cfg(target_os = "linux")]`
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::native_scopes_defaults_current_policy_and_cross_agent_objects_are_enforced -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L532) — `#[cfg(target_os = "linux")]`
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::private_reconsideration_and_explicit_exact_escalation_reuse_the_approval_owner -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L702) — `#[cfg(target_os = "linux")]`
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::revocation_task_switch_and_target_revision_changes_preserve_retained_jobs -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L797) — `#[cfg(target_os = "linux")]`
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::an_allowed_host_route_still_requires_its_adopted_check_evidence -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L861)
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::agent_input_cannot_substitute_authority_or_enrol_issuers_and_definitions -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L914)
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::completed_task_action_checks_allow_new_operations_and_retain_refusals -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L972)
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::task_action_check_binds_canonical_task_and_bounds_unavailable_reconsideration -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L1050)
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::https_target_identity_precedes_signed_dispatch_and_keeps_native_receipts -- --exact`](../proxy/src/host_execution/gateway/tests.rs#L1134)

<a id="witness-proxy-src-host-execution-gateway-task-action-tests-rs"></a>
### [`proxy/src/host_execution/gateway/task_action_tests.rs`](../proxy/src/host_execution/gateway/task_action_tests.rs)

Selection: manual native phase `host-execution` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::configured_task_action::task_action_history_filters_before_selecting_the_bounded_tail -- --exact`](../proxy/src/host_execution/gateway/task_action_tests.rs#L89)
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::configured_task_action::large_task_action_history_respects_the_adopted_input_limit -- --exact`](../proxy/src/host_execution/gateway/task_action_tests.rs#L161)
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::configured_task_action::configured_task_action_dispatches_adaptive_operations_and_retains_refusals -- --exact`](../proxy/src/host_execution/gateway/task_action_tests.rs#L231)
- [`cargo test --manifest-path proxy/Cargo.toml --lib host_execution::gateway::tests::configured_task_action::configured_task_action_rejects_prior_findings_and_required_check_bypass -- --exact`](../proxy/src/host_execution/gateway/task_action_tests.rs#L310)

<a id="witness-tests-proxy-contracts-test-local-api-authorization-py"></a>
### [`tests/proxy_contracts/test_local_api_authorization.py`](../tests/proxy_contracts/test_local_api_authorization.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_local_api_authorization.py::test_reserved_routes_stay_local_when_agent_api_unavailable`](../tests/proxy_contracts/test_local_api_authorization.py#L18)
- [`tests/proxy_contracts/test_local_api_authorization.py::test_agent_cannot_reach_operator_listener_through_proxy`](../tests/proxy_contracts/test_local_api_authorization.py#L64)
- [`tests/proxy_contracts/test_local_api_authorization.py::test_shared_bearer_does_not_grant_other_agents_state`](../tests/proxy_contracts/test_local_api_authorization.py#L127)
- [`tests/proxy_contracts/test_local_api_authorization.py::test_flow_post_rejects_non_object_json_without_effect`](../tests/proxy_contracts/test_local_api_authorization.py#L241)
- [`tests/proxy_contracts/test_local_api_authorization.py::test_invalid_policy_startup_refuses_and_reload_keeps_denial`](../tests/proxy_contracts/test_local_api_authorization.py#L321)

<a id="witness-tests-proxy-contracts-test-agent-api-contract-py"></a>
### [`tests/proxy_contracts/test_agent_api_contract.py`](../tests/proxy_contracts/test_agent_api_contract.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_authentication`](../tests/proxy_contracts/test_agent_api_contract.py#L82)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_method_checks_precede_authentication`](../tests/proxy_contracts/test_agent_api_contract.py#L88)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_path_and_host_routing`](../tests/proxy_contracts/test_agent_api_contract.py#L102)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_trailing_dot_alias_remains_local`](../tests/proxy_contracts/test_agent_api_contract.py#L114)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_token_file_rotation_is_immediate`](../tests/proxy_contracts/test_agent_api_contract.py#L125)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_lookup_parameters`](../tests/proxy_contracts/test_agent_api_contract.py#L156)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_lookup_uses_trusted_identity_without_spending_budget`](../tests/proxy_contracts/test_agent_api_contract.py#L161)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_reserved_connect_cannot_open_a_tunnel`](../tests/proxy_contracts/test_agent_api_contract.py#L227)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_token_file_errors_remain_local`](../tests/proxy_contracts/test_agent_api_contract.py#L243)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_duplicate_authorization_uses_combined_value`](../tests/proxy_contracts/test_agent_api_contract.py#L261)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_lookup_uses_last_valid_policy_reload`](../tests/proxy_contracts/test_agent_api_contract.py#L266)
- [`tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_response_survives_canonical_worker_write_failure`](../tests/proxy_contracts/test_agent_api_contract.py#L281)

<a id="witness-tests-proxy-contracts-test-agent-egress-scope-py"></a>
### [`tests/proxy_contracts/test_agent_egress_scope.py`](../tests/proxy_contracts/test_agent_egress_scope.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_egress_scope.py::test_agent_and_destination_precedence_on_concurrent_reused_connections`](../tests/proxy_contracts/test_agent_egress_scope.py#L76)
- [`tests/proxy_contracts/test_agent_egress_scope.py::test_permitted_local_endpoint_overrides_host_prompt`](../tests/proxy_contracts/test_agent_egress_scope.py#L204)
- [`tests/proxy_contracts/test_agent_egress_scope.py::test_agent_default_deny_overrides_global_exact_allow`](../tests/proxy_contracts/test_agent_egress_scope.py#L268)
- [`tests/proxy_contracts/test_agent_egress_scope.py::test_forged_body_agent_cannot_cross_uds_listener`](../tests/proxy_contracts/test_agent_egress_scope.py#L293)

<a id="witness-tests-proxy-contracts-test-agent-api-test-context-py"></a>
### [`tests/proxy_contracts/test_agent_api_test_context.py`](../tests/proxy_contracts/test_agent_api_test_context.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_api_test_context.py::test_native_declaration_api_identity_lifecycle_and_early_body_checks`](../tests/proxy_contracts/test_agent_api_test_context.py#L175)
- [`tests/proxy_contracts/test_agent_api_test_context.py::test_native_declaration_api_byte_bodies_and_failed_mutation_retention`](../tests/proxy_contracts/test_agent_api_test_context.py#L220)
- [`tests/proxy_contracts/test_agent_api_test_context.py::test_native_declaration_api_reload_uses_current_ttl_and_retains_old_records`](../tests/proxy_contracts/test_agent_api_test_context.py#L251)

<a id="witness-tests-proxy-contracts-test-native-network-policy-py"></a>
### [`tests/proxy_contracts/test_native_network_policy.py`](../tests/proxy_contracts/test_native_network_policy.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_two_agent_http_and_forged_identity`](../tests/proxy_contracts/test_native_network_policy.py#L191)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_runtime_guard_modes`](../tests/proxy_contracts/test_native_network_policy.py#L231)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_scoped_bypass_and_required_addon`](../tests/proxy_contracts/test_native_network_policy.py#L248)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_homoglyph_checks_the_source_matching_host`](../tests/proxy_contracts/test_native_network_policy.py#L270)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_homoglyph_authority_forms`](../tests/proxy_contracts/test_native_network_policy.py#L295)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_malformed_ace_inspection_modes`](../tests/proxy_contracts/test_native_network_policy.py#L338)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_raw_decodable_mixed_script_ace`](../tests/proxy_contracts/test_native_network_policy.py#L385)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_raw_utf8_origin_host`](../tests/proxy_contracts/test_native_network_policy.py#L423)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_budget_is_shared_and_survives_reload`](../tests/proxy_contracts/test_native_network_policy.py#L475)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_failed_reload_retains_scoped_decisions`](../tests/proxy_contracts/test_native_network_policy.py#L509)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_invalid_configuration_reload_keeps_policy`](../tests/proxy_contracts/test_native_network_policy.py#L610)
- [`tests/proxy_contracts/test_native_network_policy.py::test_native_policy_connect_and_inner_https_have_separate_decisions`](../tests/proxy_contracts/test_native_network_policy.py#L687)

<a id="witness-tests-proxy-contracts-test-agent-api-policy-py"></a>
### [`tests/proxy_contracts/test_agent_api_policy.py`](../tests/proxy_contracts/test_agent_api_policy.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_api_policy.py::test_agent_api_policy_canonical_baseline_is_shared`](../tests/proxy_contracts/test_agent_api_policy.py#L121)
- [`tests/proxy_contracts/test_agent_api_policy.py::test_agent_api_policy_read_uses_last_valid_reload`](../tests/proxy_contracts/test_agent_api_policy.py#L137)
- [`tests/proxy_contracts/test_agent_api_policy.py::test_agent_api_policy_requires_the_shared_token`](../tests/proxy_contracts/test_agent_api_policy.py#L157)
- [`tests/proxy_contracts/test_agent_api_policy.py::test_agent_api_policy_gateway_tokens_follow_baseline_reload`](../tests/proxy_contracts/test_agent_api_policy.py#L251)
- [`tests/proxy_contracts/test_agent_api_policy.py::test_agent_api_policy_preserves_non_string_gateway_capability`](../tests/proxy_contracts/test_agent_api_policy.py#L304)

<a id="witness-tests-proxy-contracts-test-agent-api-policy-yaml-py"></a>
### [`tests/proxy_contracts/test_agent_api_policy_yaml.py`](../tests/proxy_contracts/test_agent_api_policy_yaml.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_api_policy_yaml.py::test_agent_api_yaml_temporal_values_preserve_source_types`](../tests/proxy_contracts/test_agent_api_policy_yaml.py#L51)
- [`tests/proxy_contracts/test_agent_api_policy_yaml.py::test_agent_api_yaml_serialization_failure_keeps_loaded_enforcement`](../tests/proxy_contracts/test_agent_api_policy_yaml.py#L98)

<a id="witness-tests-proxy-contracts-test-policy-authoring-py"></a>
### [`tests/proxy_contracts/test_policy_authoring.py`](../tests/proxy_contracts/test_policy_authoring.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_policy_authoring.py::test_author_preserves_inline_identity_controls_and_rejects_changed_owned_blocks`](../tests/proxy_contracts/test_policy_authoring.py#L93)
- [`tests/proxy_contracts/test_policy_authoring.py::test_generator_keeps_nondefault_policy_paths_and_sources_private`](../tests/proxy_contracts/test_policy_authoring.py#L122)
Selection: phase `proxy` (host); phase `policy-recipe` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_policy_authoring.py::test_installed_authoring_feed_rdap_preview_activation_and_adverse_cases`](../tests/proxy_contracts/test_policy_authoring.py#L225)
Selection: optional: select `SAFEYOLO_REAL_RESEARCH` = `1` (explicit bounded real provider/research run); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_policy_authoring.py::test_installed_real_provider_and_research_run`](../tests/proxy_contracts/test_policy_authoring.py#L326)

<a id="witness-tests-proxy-contracts-test-native-policy-cli-py"></a>
### [`tests/proxy_contracts/test_native_policy_cli.py`](../tests/proxy_contracts/test_native_policy_cli.py)

Selection: phase `proxy` (host); phase `policy-recipe` (host); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_policy_cli.py::test_candidate_evaluation_reports_actions_without_destination_contact`](../tests/proxy_contracts/test_native_policy_cli.py#L54)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_candidate_evaluation_preserves_captured_scores`](../tests/proxy_contracts/test_native_policy_cli.py#L129)
Selection: phase `proxy` (host); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_policy_cli.py::test_candidate_evaluation_uses_time_after_all_evidence_reads`](../tests/proxy_contracts/test_native_policy_cli.py#L223)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_stop_cleanup_accepts_inactive_native_process_record`](../tests/proxy_contracts/test_native_policy_cli.py#L533)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_check_show_apply_and_scoped_enforcement`](../tests/proxy_contracts/test_native_policy_cli.py#L586)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_lab_stages_skills_without_the_optional_python_checker`](../tests/proxy_contracts/test_native_policy_cli.py#L636)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_fixture_removes_executables_after_startup_failure`](../tests/proxy_contracts/test_native_policy_cli.py#L675)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_credential_approval_keeps_destination_scope`](../tests/proxy_contracts/test_native_policy_cli.py#L745)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_custom_credential_negative_controls`](../tests/proxy_contracts/test_native_policy_cli.py#L813)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_unknown_bearers_keep_policy_approval_reload_and_audit`](../tests/proxy_contracts/test_native_policy_cli.py#L846)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_unknown_bearer_websocket_requires_exact_approval`](../tests/proxy_contracts/test_native_policy_cli.py#L1008)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_rejected_apply_preserves_allowed_denied_saved_live_and_recovers`](../tests/proxy_contracts/test_native_policy_cli.py#L1079)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_failed_activation_retains_live_generation_when_saved_policy_differs`](../tests/proxy_contracts/test_native_policy_cli.py#L1133)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_apply_with_service_store_uses_existing_transaction_without_deadlock`](../tests/proxy_contracts/test_native_policy_cli.py#L1177)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_new_service_capability_is_loaded_before_its_policy_is_applied`](../tests/proxy_contracts/test_native_policy_cli.py#L1205)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_apply_keeps_checked_list_file_scope_when_saved_under_another_root`](../tests/proxy_contracts/test_native_policy_cli.py#L1261)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_show_distinguishes_saved_list_inputs_from_active_compiled_scope`](../tests/proxy_contracts/test_native_policy_cli.py#L1281)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_native_check_rejects_replaced_policy_fields`](../tests/proxy_contracts/test_native_policy_cli.py#L1326)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_config_help_and_named_diagnostics`](../tests/proxy_contracts/test_native_policy_cli.py#L1335)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_native_listener_update_preserves_other_toml_settings`](../tests/proxy_contracts/test_native_policy_cli.py#L1362)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_unlisted_destination_effects`](../tests/proxy_contracts/test_native_policy_cli.py#L1440)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_agent_override_precedence`](../tests/proxy_contracts/test_native_policy_cli.py#L1454)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_policy_overrides_coexist_with_degraded_host_identity_and_attachment`](../tests/proxy_contracts/test_native_policy_cli.py#L1478)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_exact_host_precedes_wildcard`](../tests/proxy_contracts/test_native_policy_cli.py#L1547)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_port_precedence_and_other_port_fallthrough`](../tests/proxy_contracts/test_native_policy_cli.py#L1557)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_named_list_and_advanced_method_path`](../tests/proxy_contracts/test_native_policy_cli.py#L1566)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_small_request_budget_scope`](../tests/proxy_contracts/test_native_policy_cli.py#L1591)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_connect_budget_leaves_inner_request_budget_unspent`](../tests/proxy_contracts/test_native_policy_cli.py#L1606)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_scanner_block_warn_and_host_exception`](../tests/proxy_contracts/test_native_policy_cli.py#L1642)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_expiring_host_entry_observes_reload_boundary`](../tests/proxy_contracts/test_native_policy_cli.py#L1669)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_configured_circuit_threshold_reset_recovery`](../tests/proxy_contracts/test_native_policy_cli.py#L1686)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_context_formatter_atomic_watched_file`](../tests/proxy_contracts/test_native_policy_cli.py#L1710)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_context_invalid_input_keeps_previous_file`](../tests/proxy_contracts/test_native_policy_cli.py#L1752)
- [`tests/proxy_contracts/test_native_policy_cli.py::test_installed_context_declare_injection_expiry_clear_and_evidence`](../tests/proxy_contracts/test_native_policy_cli.py#L1761)

<a id="witness-tests-proxy-contracts-test-service-effect-assessment-py"></a>
### [`tests/proxy_contracts/test_service_effect_assessment.py`](../tests/proxy_contracts/test_service_effect_assessment.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_service_effect_assessment.py::test_host_assessment_cli_reports_full_proposal_current_ceiling_and_unavailable_authority`](../tests/proxy_contracts/test_service_effect_assessment.py#L36)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_host_package_guidance_is_shared_by_challenge_private_and_operator_review`](../tests/proxy_contracts/test_service_effect_assessment.py#L95)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_normal_approval_interfaces_retain_canonical_effects_guidance_and_outcome`](../tests/proxy_contracts/test_service_effect_assessment.py#L171)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_combined_authority_is_prepared_before_operator_work_and_shared_by_approval`](../tests/proxy_contracts/test_service_effect_assessment.py#L208)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_policy_changes_expose_recomputed_assessment_and_supersede_old_consent`](../tests/proxy_contracts/test_service_effect_assessment.py#L245)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_alternative_recipe_needs_access_and_effect_denial_applies_to_other_endpoint`](../tests/proxy_contracts/test_service_effect_assessment.py#L265)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_prohibited_edit_does_not_deny_independent_inspection_or_recipe`](../tests/proxy_contracts/test_service_effect_assessment.py#L293)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_new_temporary_route_authority_invalidates_a_pending_assessment`](../tests/proxy_contracts/test_service_effect_assessment.py#L323)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_removed_temporary_execution_access_is_reassessed_without_asserting_upstream_state`](../tests/proxy_contracts/test_service_effect_assessment.py#L338)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_definition_changes_are_recomputed_before_approval`](../tests/proxy_contracts/test_service_effect_assessment.py#L359)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_unbounded_execution_scope_includes_the_job_except_where_policy_denies_it`](../tests/proxy_contracts/test_service_effect_assessment.py#L375)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_known_candidate_scope_establishes_overlap_through_native_selectors`](../tests/proxy_contracts/test_service_effect_assessment.py#L385)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_unresolved_alias_overlap_does_not_invent_an_effect_prohibition`](../tests/proxy_contracts/test_service_effect_assessment.py#L393)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_risk_only_grant_does_not_add_modeled_route_admission_authority`](../tests/proxy_contracts/test_service_effect_assessment.py#L405)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_actual_contract_binding_projects_enforced_cosmetic_constraints`](../tests/proxy_contracts/test_service_effect_assessment.py#L417)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_recipe_with_unspecified_binding_reports_the_prerequisite_and_full_effects`](../tests/proxy_contracts/test_service_effect_assessment.py#L447)
- [`tests/proxy_contracts/test_service_effect_assessment.py::test_existing_risk_approval_consumes_the_same_temporary_combined_authority`](../tests/proxy_contracts/test_service_effect_assessment.py#L463)

<a id="witness-tests-proxy-contracts-test-gateway-redirect-py"></a>
### [`tests/proxy_contracts/test_gateway_redirect.py`](../tests/proxy_contracts/test_gateway_redirect.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_gateway_redirect.py::test_client_followed_gateway_redirect_keeps_vault_credential_at_owned_origin`](../tests/proxy_contracts/test_gateway_redirect.py#L186)
- [`tests/proxy_contracts/test_gateway_redirect.py::test_client_that_reapplies_gateway_token_on_redirect_cannot_reach_new_authority`](../tests/proxy_contracts/test_gateway_redirect.py#L335)

<a id="witness-tests-proxy-contracts-test-coding-client-auth-py"></a>
### [`tests/proxy_contracts/test_coding_client_auth.py`](../tests/proxy_contracts/test_coding_client_auth.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_coding_client_auth.py::test_guided_owners_preserve_custody_denies_and_separate_readiness`](../tests/proxy_contracts/test_coding_client_auth.py#L88)

<a id="witness-tests-proxy-contracts-test-native-credentials-cli-py"></a>
### [`tests/proxy_contracts/test_native_credentials_cli.py`](../tests/proxy_contracts/test_native_credentials_cli.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_credentials_cli.py::test_surfaces_tolerates_atomic_snapshot_rename`](../tests/proxy_contracts/test_native_credentials_cli.py#L134)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_surfaces_detects_credentials_in_present_files`](../tests/proxy_contracts/test_native_credentials_cli.py#L157)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_surfaces_propagates_other_read_errors`](../tests/proxy_contracts/test_native_credentials_cli.py#L166)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_local_first_restart_scope_revocation_removal`](../tests/proxy_contracts/test_native_credentials_cli.py#L210)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_provider_order_failures_local_control_and_no_persistence`](../tests/proxy_contracts/test_native_credentials_cli.py#L248)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_catalogue_override_activation_and_malformed_preservation`](../tests/proxy_contracts/test_native_credentials_cli.py#L293)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_credential_free_service_requires_no_store_or_provider`](../tests/proxy_contracts/test_native_credentials_cli.py#L332)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_binding_does_not_replace_service_or_risk_approval`](../tests/proxy_contracts/test_native_credentials_cli.py#L352)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_credential_policy_approval_uses_existing_native_operation`](../tests/proxy_contracts/test_native_credentials_cli.py#L396)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_direct_credential_approval_activates_next_connection`](../tests/proxy_contracts/test_native_credentials_cli.py#L426)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_installed_direct_credential_activation_failure_is_visible`](../tests/proxy_contracts/test_native_credentials_cli.py#L431)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_init_and_read_only_commands_defer_storage_until_a_valid_secret_write`](../tests/proxy_contracts/test_native_credentials_cli.py#L525)
- [`tests/proxy_contracts/test_native_credentials_cli.py::test_first_storage_choice_and_hidden_passphrase_input`](../tests/proxy_contracts/test_native_credentials_cli.py#L572)

<a id="witness-tests-proxy-contracts-test-native-onepassword-cli-py"></a>
### [`tests/proxy_contracts/test_native_onepassword_cli.py`](../tests/proxy_contracts/test_native_onepassword_cli.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_onepassword_cli.py::test_real_onepassword_resolves_only_after_host_approval`](../tests/proxy_contracts/test_native_onepassword_cli.py#L39)

<a id="witness-tests-proxy-contracts-test-codex-approval-fallback-py"></a>
### [`tests/proxy_contracts/test_codex_approval_fallback.py`](../tests/proxy_contracts/test_codex_approval_fallback.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_codex_approval_fallback.py::test_codex_routing_continues_after_explicit_approval`](../tests/proxy_contracts/test_codex_approval_fallback.py#L132)
- [`tests/proxy_contracts/test_codex_approval_fallback.py::test_codex_routing_wait_keeps_refusal_and_cancellation`](../tests/proxy_contracts/test_codex_approval_fallback.py#L166)
- [`tests/proxy_contracts/test_codex_approval_fallback.py::test_codex_routing_wait_timeout_leaves_approval_pending_without_replay`](../tests/proxy_contracts/test_codex_approval_fallback.py#L203)
- [`tests/proxy_contracts/test_codex_approval_fallback.py::test_codex_routing_waits_for_active_approval_after_saved_receipt`](../tests/proxy_contracts/test_codex_approval_fallback.py#L223)
- [`tests/proxy_contracts/test_codex_approval_fallback.py::test_codex_fallback_approves_each_replacement_at_one_destination`](../tests/proxy_contracts/test_codex_approval_fallback.py#L271)

<a id="witness-tests-proxy-contracts-test-gateway-scope-py"></a>
### [`tests/proxy_contracts/test_gateway_scope.py`](../tests/proxy_contracts/test_gateway_scope.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_gateway_scope.py::test_default_catalogue_credentials_reach_only_their_provider`](../tests/proxy_contracts/test_gateway_scope.py#L82)
- [`tests/proxy_contracts/test_gateway_scope.py::test_installed_access_flow_probes_use_real_native_owner_scoping`](../tests/proxy_contracts/test_gateway_scope.py#L134)
- [`tests/proxy_contracts/test_gateway_scope.py::test_gateway_control_routes_reject_invalid_bodies_before_effects`](../tests/proxy_contracts/test_gateway_scope.py#L228)
- [`tests/proxy_contracts/test_gateway_scope.py::test_running_gateway_scope_blocks_unbound_requests_before_origin`](../tests/proxy_contracts/test_gateway_scope.py#L369)
- [`tests/proxy_contracts/test_gateway_scope.py::test_running_gateway_plain_http_injection_setting`](../tests/proxy_contracts/test_gateway_scope.py#L474)
- [`tests/proxy_contracts/test_gateway_scope.py::test_gateway_credential_guard_keeps_direct_secrets_at_owned_origin`](../tests/proxy_contracts/test_gateway_scope.py#L521)
- [`tests/proxy_contracts/test_gateway_scope.py::test_gateway_capture_keeps_owned_evidence_scoped_and_redacted`](../tests/proxy_contracts/test_gateway_scope.py#L614)

<a id="witness-tests-proxy-contracts-test-gateway-risk-approval-py"></a>
### [`tests/proxy_contracts/test_gateway_risk_approval.py`](../tests/proxy_contracts/test_gateway_risk_approval.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_gateway_risk_approval.py::test_running_gateway_prompt_requires_audit_append`](../tests/proxy_contracts/test_gateway_risk_approval.py#L224)
- [`tests/proxy_contracts/test_gateway_risk_approval.py::test_running_gateway_risk_approval_and_once_grant`](../tests/proxy_contracts/test_gateway_risk_approval.py#L311)
- [`tests/proxy_contracts/test_gateway_risk_approval.py::test_running_gateway_session_grant_revocation`](../tests/proxy_contracts/test_gateway_risk_approval.py#L435)

<a id="witness-tests-proxy-contracts-test-service-route-challenge-py"></a>
### [`tests/proxy_contracts/test_service_route_challenge.py`](../tests/proxy_contracts/test_service_route_challenge.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_service_route_challenge.py::test_adopted_questions_bind_pending_answers_and_operator_decisions`](../tests/proxy_contracts/test_service_route_challenge.py#L125)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_completed_check_survives_run_approval_and_receipt`](../tests/proxy_contracts/test_service_route_challenge.py#L162)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_challenge_abandon_alternative_and_explicit_retry`](../tests/proxy_contracts/test_service_route_challenge.py#L291)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_forged_scope_and_refusal_do_not_create_more_operator_work`](../tests/proxy_contracts/test_service_route_challenge.py#L339)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_route_exception_rechecks_current_authority`](../tests/proxy_contracts/test_service_route_challenge.py#L361)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_restart_preserves_pending_scope_and_grant_expiry`](../tests/proxy_contracts/test_service_route_challenge.py#L410)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_destination_and_literal_metacharacter_scope`](../tests/proxy_contracts/test_service_route_challenge.py#L438)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_risk_grant_alone_cannot_admit_missing_route`](../tests/proxy_contracts/test_service_route_challenge.py#L455)
- [`tests/proxy_contracts/test_service_route_challenge.py::test_exception_preserves_other_enforcement`](../tests/proxy_contracts/test_service_route_challenge.py#L465)

<a id="witness-tests-proxy-contracts-test-shared-operator-approval-py"></a>
### [`tests/proxy_contracts/test_shared_operator_approval.py`](../tests/proxy_contracts/test_shared_operator_approval.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_shared_operator_approval.py::test_continuity_wrong_port_skips_the_approved_vz_tls_authority`](../tests/proxy_contracts/test_shared_operator_approval.py#L133)
- [`tests/proxy_contracts/test_shared_operator_approval.py::test_shared_operator_approval_is_scoped_and_retried`](../tests/proxy_contracts/test_shared_operator_approval.py#L164)
- [`tests/proxy_contracts/test_shared_operator_approval.py::test_connect_approval_requires_a_new_admission`](../tests/proxy_contracts/test_shared_operator_approval.py#L329)
- [`tests/proxy_contracts/test_shared_operator_approval.py::test_live_connect_keeps_its_admission_after_policy_reload`](../tests/proxy_contracts/test_shared_operator_approval.py#L382)
- [`tests/proxy_contracts/test_shared_operator_approval.py::test_expiring_host_allowance_changes_only_at_reload`](../tests/proxy_contracts/test_shared_operator_approval.py#L461)

<a id="witness-tests-proxy-contracts-test-operator-consumer-approval-py"></a>
### [`tests/proxy_contracts/test_operator_consumer_approval.py`](../tests/proxy_contracts/test_operator_consumer_approval.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_operator_consumer_approval.py::test_retained_operator_client_approves_exact_native_network_scope`](../tests/proxy_contracts/test_operator_consumer_approval.py#L171)
- [`tests/proxy_contracts/test_operator_consumer_approval.py::test_retained_operator_client_approves_and_denies_native_credentials`](../tests/proxy_contracts/test_operator_consumer_approval.py#L263)
- [`tests/proxy_contracts/test_operator_consumer_approval.py::test_installed_access_refuses_binding_submitted_before_service_decision`](../tests/proxy_contracts/test_operator_consumer_approval.py#L523)
- [`tests/proxy_contracts/test_operator_consumer_approval.py::test_installed_access_approves_exact_canonical_service`](../tests/proxy_contracts/test_operator_consumer_approval.py#L549)
- [`tests/proxy_contracts/test_operator_consumer_approval.py::test_installed_access_combined_approvals`](../tests/proxy_contracts/test_operator_consumer_approval.py#L641)
- [`tests/proxy_contracts/test_operator_consumer_approval.py::test_installed_access_approves_canonical_binding_and_once_effect`](../tests/proxy_contracts/test_operator_consumer_approval.py#L652)
- [`tests/proxy_contracts/test_operator_consumer_approval.py::test_installed_access_rejects_exact_canonical_request`](../tests/proxy_contracts/test_operator_consumer_approval.py#L683)

<a id="witness-tests-proxy-contracts-test-installed-shared-approvals-py"></a>
### [`tests/proxy_contracts/test_installed_shared_approvals.py`](../tests/proxy_contracts/test_installed_shared_approvals.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_installed_shared_approvals.py::test_fresh_reviewer_attention_cutoff_records_all_prior_edges`](../tests/proxy_contracts/test_installed_shared_approvals.py#L32)
- [`tests/proxy_contracts/test_installed_shared_approvals.py::test_helper_consumer_refuses_unowned_runtime_before_guest_effects`](../tests/proxy_contracts/test_installed_shared_approvals.py#L95)
- [`tests/proxy_contracts/test_installed_shared_approvals.py::test_helper_consumer_failed_model_keeps_native_approval_and_owned_cleanup`](../tests/proxy_contracts/test_installed_shared_approvals.py#L139)

<a id="witness-tests-proxy-contracts-test-guard-approval-audit-py"></a>
### [`tests/proxy_contracts/test_guard_approval_audit.py`](../tests/proxy_contracts/test_guard_approval_audit.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_guard_approval_audit.py::test_guard_prompt_waits_for_audit_append`](../tests/proxy_contracts/test_guard_approval_audit.py#L39)

<a id="witness-tests-proxy-contracts-test-control-updates-py"></a>
### [`tests/proxy_contracts/test_control_updates.py`](../tests/proxy_contracts/test_control_updates.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_control_updates.py::test_signed_cli_push_receipt_is_separate_from_adoption`](../tests/proxy_contracts/test_control_updates.py#L111)
- [`tests/proxy_contracts/test_control_updates.py::test_installed_signed_v1_v2_updates_enforce_checks_and_recover`](../tests/proxy_contracts/test_control_updates.py#L149)

<a id="witness-tests-proxy-contracts-test-https-contract-py"></a>
### [`tests/proxy_contracts/test_https_contract.py`](../tests/proxy_contracts/test_https_contract.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_https_contract.py::test_preserved_upstream_chain_variants`](../tests/proxy_contracts/test_https_contract.py#L84)
- [`tests/proxy_contracts/test_https_contract.py::test_connect_has_no_http_path`](../tests/proxy_contracts/test_https_contract.py#L104)
Selection: phase `proxy` (host); phase `package-tls` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_https_contract.py::test_https_origin_verification`](../tests/proxy_contracts/test_https_contract.py#L152)
Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_https_contract.py::test_https_not_yet_valid_origin_certificate_is_rejected`](../tests/proxy_contracts/test_https_contract.py#L218)
- [`tests/proxy_contracts/test_https_contract.py::test_https_origin_requires_client_certificate_before_http`](../tests/proxy_contracts/test_https_contract.py#L482)
- [`tests/proxy_contracts/test_https_contract.py::test_https_tls12_origin_records_version_and_cipher`](../tests/proxy_contracts/test_https_contract.py#L622)

<a id="witness-tests-proxy-contracts-test-https-trust-continuity-py"></a>
### [`tests/proxy_contracts/test_https_trust_continuity.py`](../tests/proxy_contracts/test_https_trust_continuity.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_https_trust_continuity.py::test_upstream_tls_uses_logical_name_sni_and_additional_ca`](../tests/proxy_contracts/test_https_trust_continuity.py#L152)

<a id="witness-tests-proxy-contracts-test-raw-http-gateway-boundary-py"></a>
### [`tests/proxy_contracts/test_raw_http_gateway_boundary.py`](../tests/proxy_contracts/test_raw_http_gateway_boundary.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_raw_http_gateway_boundary.py::test_raw_headers_framing_and_gateway_route_agree_with_forwarded_bytes`](../tests/proxy_contracts/test_raw_http_gateway_boundary.py#L216)
- [`tests/proxy_contracts/test_raw_http_gateway_boundary.py::test_conflicting_request_framing_cannot_reinterpret_the_next_request`](../tests/proxy_contracts/test_raw_http_gateway_boundary.py#L414)
- [`tests/proxy_contracts/test_raw_http_gateway_boundary.py::test_reused_http1_connection_rechecks_destination_credential_and_agent`](../tests/proxy_contracts/test_raw_http_gateway_boundary.py#L484)

<a id="witness-tests-proxy-contracts-test-allowed-chunked-framing-py"></a>
### [`tests/proxy_contracts/test_allowed_chunked_framing.py`](../tests/proxy_contracts/test_allowed_chunked_framing.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_allowed_chunked_framing.py::test_allowed_chunked_request_finishes_at_origin`](../tests/proxy_contracts/test_allowed_chunked_framing.py#L187)

<a id="witness-tests-proxy-contracts-test-authority-consistency-py"></a>
### [`tests/proxy_contracts/test_authority_consistency.py`](../tests/proxy_contracts/test_authority_consistency.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_authority_consistency.py::test_absolute_authority_and_host_keep_credential_on_one_route`](../tests/proxy_contracts/test_authority_consistency.py#L356)
- [`tests/proxy_contracts/test_authority_consistency.py::test_absolute_root_dot_host_and_userinfo_do_not_change_route`](../tests/proxy_contracts/test_authority_consistency.py#L414)
- [`tests/proxy_contracts/test_authority_consistency.py::test_explicitly_allowed_root_dot_target_preserves_signed_request`](../tests/proxy_contracts/test_authority_consistency.py#L459)
- [`tests/proxy_contracts/test_authority_consistency.py::test_inner_port_and_root_dot_authorities_do_not_inherit_connect`](../tests/proxy_contracts/test_authority_consistency.py#L488)
- [`tests/proxy_contracts/test_authority_consistency.py::test_connect_inner_authority_sni_and_verification_stay_scoped`](../tests/proxy_contracts/test_authority_consistency.py#L560)
- [`tests/proxy_contracts/test_authority_consistency.py::test_idna_authority_keeps_credential_on_admitted_route`](../tests/proxy_contracts/test_authority_consistency.py#L754)
- [`tests/proxy_contracts/test_authority_consistency.py::test_absolute_ipv6_conflict_forwards_bracketed_admitted_host`](../tests/proxy_contracts/test_authority_consistency.py#L836)

<a id="witness-tests-proxy-contracts-test-authority-parent-fixture-py"></a>
### [`tests/proxy_contracts/test_authority_parent_fixture.py`](../tests/proxy_contracts/test_authority_parent_fixture.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_authority_parent_fixture.py::test_established_connect_client_close_is_clean`](../tests/proxy_contracts/test_authority_parent_fixture.py#L59)
- [`tests/proxy_contracts/test_authority_parent_fixture.py::test_established_connect_upstream_reset_is_still_an_error`](../tests/proxy_contracts/test_authority_parent_fixture.py#L73)
- [`tests/proxy_contracts/test_authority_parent_fixture.py::test_request_errors_remain_visible`](../tests/proxy_contracts/test_authority_parent_fixture.py#L91)
- [`tests/proxy_contracts/test_authority_parent_fixture.py::test_unexpected_relay_error_remains_visible`](../tests/proxy_contracts/test_authority_parent_fixture.py#L108)
- [`tests/proxy_contracts/test_authority_parent_fixture.py::test_client_reset_preserves_existing_errors`](../tests/proxy_contracts/test_authority_parent_fixture.py#L128)

<a id="witness-tests-proxy-contracts-test-http1-handoff-contract-py"></a>
### [`tests/proxy_contracts/test_http1_handoff_contract.py`](../tests/proxy_contracts/test_http1_handoff_contract.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http1_handoff_contract.py::test_http1_handoff_preserves_expect_and_bodyless_followups`](../tests/proxy_contracts/test_http1_handoff_contract.py#L294)
- [`tests/proxy_contracts/test_http1_handoff_contract.py::test_http1_response_cancel_keeps_next_request_and_agent_decision_clean`](../tests/proxy_contracts/test_http1_handoff_contract.py#L357)
- [`tests/proxy_contracts/test_http1_handoff_contract.py::test_http1_handoff_preserves_request_trailers`](../tests/proxy_contracts/test_http1_handoff_contract.py#L440)
- [`tests/proxy_contracts/test_http1_handoff_contract.py::test_http1_handoff_rejects_truncated_request_before_origin_completion`](../tests/proxy_contracts/test_http1_handoff_contract.py#L476)

<a id="witness-tests-proxy-contracts-test-http2-contract-py"></a>
### [`tests/proxy_contracts/test_http2_contract.py`](../tests/proxy_contracts/test_http2_contract.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http2_contract.py::test_h2_requests_rejection_closes_before_settings_ack`](../tests/proxy_contracts/test_http2_contract.py#L531)
- [`tests/proxy_contracts/test_http2_contract.py::test_upload_response_wait_requires_origin_progress`](../tests/proxy_contracts/test_http2_contract.py#L592)
- [`tests/proxy_contracts/test_http2_contract.py::test_http2_large_upload_preserves_streaming_and_required_body_checks`](../tests/proxy_contracts/test_http2_contract.py#L637)
- [`tests/proxy_contracts/test_http2_contract.py::test_http2_credential_headers_deny_held_body_and_keep_sibling`](../tests/proxy_contracts/test_http2_contract.py#L715)
- [`tests/proxy_contracts/test_http2_contract.py::test_concurrent_http2_streams_keep_agent_and_request_identity`](../tests/proxy_contracts/test_http2_contract.py#L842)
- [`tests/proxy_contracts/test_http2_contract.py::test_http2_mixed_stream_decisions_and_http1_control`](../tests/proxy_contracts/test_http2_contract.py#L872)
- [`tests/proxy_contracts/test_http2_contract.py::test_h2_cancellation_origin_flushes_sibling_without_another_client_frame`](../tests/proxy_contracts/test_http2_contract.py#L997)
- [`tests/proxy_contracts/test_http2_contract.py::test_http2_cancelled_stream_does_not_cancel_independent_stream`](../tests/proxy_contracts/test_http2_contract.py#L1043)
- [`tests/proxy_contracts/test_http2_contract.py::test_https_protocol_negotiation_delivers_allowed_request`](../tests/proxy_contracts/test_http2_contract.py#L1187)
- [`tests/proxy_contracts/test_http2_contract.py::test_http2_inner_authorities_cannot_change_destination`](../tests/proxy_contracts/test_http2_contract.py#L1222)

<a id="witness-tests-proxy-contracts-test-http2-gate-py"></a>
### [`tests/proxy_contracts/test_http2_gate.py`](../tests/proxy_contracts/test_http2_gate.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http2_gate.py::test_early_response_retains_validated_upload_evidence`](../tests/proxy_contracts/test_http2_gate.py#L129)
- [`tests/proxy_contracts/test_http2_gate.py::test_cold_and_warm_h2_streams_reach_origin_before_gate`](../tests/proxy_contracts/test_http2_gate.py#L196)
- [`tests/proxy_contracts/test_http2_gate.py::test_gated_stream_keeps_snapshot_while_new_streams_observe_reload`](../tests/proxy_contracts/test_http2_gate.py#L233)
- [`tests/proxy_contracts/test_http2_gate.py::test_stalled_old_tls_handshake_does_not_hold_new_runtime_session`](../tests/proxy_contracts/test_http2_gate.py#L262)
- [`tests/proxy_contracts/test_http2_gate.py::test_held_and_mixed_policy_streams_do_not_share_approval_or_budget`](../tests/proxy_contracts/test_http2_gate.py#L287)
- [`tests/proxy_contracts/test_http2_gate.py::test_shared_h2_charges_each_global_or_host_budget_once_and_keeps_reload_state`](../tests/proxy_contracts/test_http2_gate.py#L333)
- [`tests/proxy_contracts/test_http2_gate.py::test_upstream_settings_limit_and_request_reset_keep_staged_siblings`](../tests/proxy_contracts/test_http2_gate.py#L363)
- [`tests/proxy_contracts/test_http2_gate.py::test_stalled_h2_response_reader_does_not_hold_gated_siblings`](../tests/proxy_contracts/test_http2_gate.py#L394)
- [`tests/proxy_contracts/test_http2_gate.py::test_goaway_reconnects_without_replaying_requests`](../tests/proxy_contracts/test_http2_gate.py#L427)
- [`tests/proxy_contracts/test_http2_gate.py::test_h2_to_h1_fallback_keeps_small_request_completion_barrier`](../tests/proxy_contracts/test_http2_gate.py#L447)
- [`tests/proxy_contracts/test_http2_gate.py::test_reset_request_never_becomes_origin_eom_while_siblings_continue`](../tests/proxy_contracts/test_http2_gate.py#L473)
- [`tests/proxy_contracts/test_http2_gate.py::test_gated_h2_reuses_the_configured_parent_connect`](../tests/proxy_contracts/test_http2_gate.py#L503)
- [`tests/proxy_contracts/test_http2_gate.py::test_repeated_h2_batches_bound_fds_memory_and_close_origin_socket`](../tests/proxy_contracts/test_http2_gate.py#L545)
- [`tests/proxy_contracts/test_http2_gate.py::test_shutdown_closes_active_h2_session_without_completing_gated_requests`](../tests/proxy_contracts/test_http2_gate.py#L570)
- [`tests/proxy_contracts/test_http2_gate.py::test_applicable_h2_inspection_keeps_pre_egress_enforcement`](../tests/proxy_contracts/test_http2_gate.py#L591)
- [`tests/proxy_contracts/test_http2_gate.py::test_unavailable_h2_body_cannot_bypass_a_required_blocking_scan`](../tests/proxy_contracts/test_http2_gate.py#L625)
- [`tests/proxy_contracts/test_http2_gate.py::test_gateway_h2_buffers_only_when_applicable_contract_needs_body`](../tests/proxy_contracts/test_http2_gate.py#L673)

<a id="witness-tests-proxy-contracts-test-http2-gate-timing-py"></a>
### [`tests/proxy_contracts/test_http2_gate_timing.py`](../tests/proxy_contracts/test_http2_gate_timing.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http2_gate_timing.py::test_gated_race_overlaps_direct_and_intercepted_but_serial_control_does_not`](../tests/proxy_contracts/test_http2_gate_timing.py#L67)
Selection: optional: select `SAFEYOLO_H2_GATE_LIFECYCLE` = `1` (real idle timeout witness is opt-in); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http2_gate_timing.py::test_idle_session_closes_at_origin_and_next_stream_reconnects`](../tests/proxy_contracts/test_http2_gate_timing.py#L88)
Selection: optional: select `SAFEYOLO_H2_GATE_BENCHMARK` = `1` (controlled timing lane is opt-in); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http2_gate_timing.py::test_100_warm_batches_direct_and_intercepted`](../tests/proxy_contracts/test_http2_gate_timing.py#L122)

<a id="witness-tests-proxy-contracts-test-http-contract-py"></a>
### [`tests/proxy_contracts/test_http_contract.py`](../tests/proxy_contracts/test_http_contract.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http_contract.py::test_two_agent_http_policy_and_attribution`](../tests/proxy_contracts/test_http_contract.py#L44)
- [`tests/proxy_contracts/test_http_contract.py::test_generated_request_ids_follow_owned_effects`](../tests/proxy_contracts/test_http_contract.py#L48)
- [`tests/proxy_contracts/test_http_contract.py::test_enforced_context_and_scoped_request_evidence`](../tests/proxy_contracts/test_http_contract.py#L128)
- [`tests/proxy_contracts/test_http_contract.py::test_connect_and_inner_request_ids_keep_scoped_connection_evidence`](../tests/proxy_contracts/test_http_contract.py#L359)
- [`tests/proxy_contracts/test_http_contract.py::test_reserved_hosts_stay_local_and_do_not_contact_parent`](../tests/proxy_contracts/test_http_contract.py#L487)
- [`tests/proxy_contracts/test_http_contract.py::test_reserved_audit_wait_accepts_a_late_matching_row`](../tests/proxy_contracts/test_http_contract.py#L499)
- [`tests/proxy_contracts/test_http_contract.py::test_reserved_audit_wait_rejects_absent_or_wrong_rows`](../tests/proxy_contracts/test_http_contract.py#L547)
- [`tests/proxy_contracts/test_http_contract.py::test_via_self_loop_stays_local_and_distinct_instance_reaches_parent`](../tests/proxy_contracts/test_http_contract.py#L630)
- [`tests/proxy_contracts/test_http_contract.py::test_streamed_response_delivers_before_release_and_keeps_control_live`](../tests/proxy_contracts/test_http_contract.py#L737)
- [`tests/proxy_contracts/test_http_contract.py::test_slow_consumer_keeps_allowed_request_and_authenticated_admin_live`](../tests/proxy_contracts/test_http_contract.py#L751)
- [`tests/proxy_contracts/test_http_contract.py::test_repeated_concurrent_short_requests_keep_authenticated_admin_live`](../tests/proxy_contracts/test_http_contract.py#L779)
- [`tests/proxy_contracts/test_http_contract.py::test_short_https_requests_record_counts_latency_resources_and_control`](../tests/proxy_contracts/test_http_contract.py#L791)
- [`tests/proxy_contracts/test_http_contract.py::test_short_requests_report_warmup_quiet_and_repeated_resource_phases`](../tests/proxy_contracts/test_http_contract.py#L817)
- [`tests/proxy_contracts/test_http_contract.py::test_cancelled_sse_releases_upstream_and_keeps_other_request_live`](../tests/proxy_contracts/test_http_contract.py#L859)
- [`tests/proxy_contracts/test_http_contract.py::test_concurrent_policy_decisions_keep_agent_scope`](../tests/proxy_contracts/test_http_contract.py#L882)
- [`tests/proxy_contracts/test_http_contract.py::test_persistent_http1_requests_keep_routing_and_identity_isolated`](../tests/proxy_contracts/test_http_contract.py#L929)

<a id="witness-tests-proxy-contracts-test-http-test-context-py"></a>
### [`tests/proxy_contracts/test_http_test_context.py`](../tests/proxy_contracts/test_http_test_context.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_http_test_context.py::test_missing_context_blocks_before_parent_accept_without_waiting_for_body`](../tests/proxy_contracts/test_http_test_context.py#L171)
- [`tests/proxy_contracts/test_http_test_context.py::test_valid_explicit_context_preserves_bodies_and_trusted_source_phases`](../tests/proxy_contracts/test_http_test_context.py#L193)
- [`tests/proxy_contracts/test_http_test_context.py::test_declared_context_stays_in_its_trusted_slot_and_malformed_header_cannot_fall_back`](../tests/proxy_contracts/test_http_test_context.py#L210)
- [`tests/proxy_contracts/test_http_test_context.py::test_content_decode_failure_preserves_wire_bytes_and_reached_event_phase`](../tests/proxy_contracts/test_http_test_context.py#L232)
- [`tests/proxy_contracts/test_http_test_context.py::test_completed_large_request_preserves_bytes_and_has_both_provenance_phases`](../tests/proxy_contracts/test_http_test_context.py#L246)
- [`tests/proxy_contracts/test_http_test_context.py::test_ordinary_early_response_before_request_eom_has_no_provenance`](../tests/proxy_contracts/test_http_test_context.py#L264)

<a id="witness-tests-proxy-contracts-test-request-headers-py"></a>
### [`tests/proxy_contracts/test_request_headers.py`](../tests/proxy_contracts/test_request_headers.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_request_headers.py::test_source_header_hygiene_reaches_owned_origin`](../tests/proxy_contracts/test_request_headers.py#L52)

<a id="witness-tests-proxy-contracts-test-request-streaming-inspection-py"></a>
### [`tests/proxy_contracts/test_request_streaming_inspection.py`](../tests/proxy_contracts/test_request_streaming_inspection.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_request_streaming_inspection.py::test_request_inspection_before_and_after_streaming_boundary`](../tests/proxy_contracts/test_request_streaming_inspection.py#L289)
- [`tests/proxy_contracts/test_request_streaming_inspection.py::test_log_only_body_rules_preserve_streaming_bytes_and_evidence`](../tests/proxy_contracts/test_request_streaming_inspection.py#L357)
- [`tests/proxy_contracts/test_request_streaming_inspection.py::test_python_chunked_url_rule_blocks_at_head`](../tests/proxy_contracts/test_request_streaming_inspection.py#L434)
- [`tests/proxy_contracts/test_request_streaming_inspection.py::test_streamed_network_policy_decision_precedes_origin_bytes`](../tests/proxy_contracts/test_request_streaming_inspection.py#L447)
- [`tests/proxy_contracts/test_request_streaming_inspection.py::test_capture_limit_does_not_limit_buffered_inspection`](../tests/proxy_contracts/test_request_streaming_inspection.py#L490)

<a id="witness-tests-proxy-contracts-test-selected-ip-py"></a>
### [`tests/proxy_contracts/test_selected_ip.py`](../tests/proxy_contracts/test_selected_ip.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_selected_ip.py::test_numeric_connect_selects_hostname_parent_and_linked_explain`](../tests/proxy_contracts/test_selected_ip.py#L89)
- [`tests/proxy_contracts/test_selected_ip.py::test_ambiguous_connect_ends_without_any_outbound_attempt`](../tests/proxy_contracts/test_selected_ip.py#L143)
- [`tests/proxy_contracts/test_selected_ip.py::test_installed_curl_selected_ip_keeps_tls_http_credential_and_evidence`](../tests/proxy_contracts/test_selected_ip.py#L251)
- [`tests/proxy_contracts/test_selected_ip.py::test_connect_explain_uses_actual_descendants_and_keeps_agent_scope`](../tests/proxy_contracts/test_selected_ip.py#L327)
- [`tests/proxy_contracts/test_selected_ip.py::test_literal_ip_tls_without_dns_sni_can_select_its_numeric_route`](../tests/proxy_contracts/test_selected_ip.py#L374)
- [`tests/proxy_contracts/test_selected_ip.py::test_selected_parent_failure_never_contacts_origin_or_loses_explain_id`](../tests/proxy_contracts/test_selected_ip.py#L398)
- [`tests/proxy_contracts/test_selected_ip.py::test_selected_origin_certificate_failure_remains_explainable`](../tests/proxy_contracts/test_selected_ip.py#L431)
- [`tests/proxy_contracts/test_selected_ip.py::test_fragmented_client_hello_selects_only_after_complete_information`](../tests/proxy_contracts/test_selected_ip.py#L515)
- [`tests/proxy_contracts/test_selected_ip.py::test_operator_mapping_scope_conflict_reconnect_and_config_change`](../tests/proxy_contracts/test_selected_ip.py#L557)
- [`tests/proxy_contracts/test_selected_ip.py::test_selected_ip_keeps_both_network_and_credential_policy`](../tests/proxy_contracts/test_selected_ip.py#L596)
- [`tests/proxy_contracts/test_selected_ip.py::test_selected_ip_cannot_turn_reserved_or_provider_names_into_ordinary_egress`](../tests/proxy_contracts/test_selected_ip.py#L646)
- [`tests/proxy_contracts/test_selected_ip.py::test_selected_tunnel_keeps_inner_authority_pinned`](../tests/proxy_contracts/test_selected_ip.py#L679)
- [`tests/proxy_contracts/test_selected_ip.py::test_named_mapping_does_not_admit_an_unrelated_sni`](../tests/proxy_contracts/test_selected_ip.py#L709)
- [`tests/proxy_contracts/test_selected_ip.py::test_redirect_receives_its_own_mapping_and_policy_checks`](../tests/proxy_contracts/test_selected_ip.py#L727)
- [`tests/proxy_contracts/test_selected_ip.py::test_installed_selected_ip_uses_existing_credential_approval_and_policy_reload`](../tests/proxy_contracts/test_selected_ip.py#L750)
- [`tests/proxy_contracts/test_selected_ip.py::test_mapped_admin_endpoint_is_blocked_before_selected_parent_contact`](../tests/proxy_contracts/test_selected_ip.py#L781)

<a id="witness-tests-proxy-contracts-test-te-gzip-handoff-py"></a>
### [`tests/proxy_contracts/test_te_gzip_handoff.py`](../tests/proxy_contracts/test_te_gzip_handoff.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_te_gzip_handoff.py::test_transfer_coding_and_next_response`](../tests/proxy_contracts/test_te_gzip_handoff.py#L232)
- [`tests/proxy_contracts/test_te_gzip_handoff.py::test_native_http10_rejects_unrepresentable_transfer_coding`](../tests/proxy_contracts/test_te_gzip_handoff.py#L267)
- [`tests/proxy_contracts/test_te_gzip_handoff.py::test_http2_client_http1_origin_transfer_coding`](../tests/proxy_contracts/test_te_gzip_handoff.py#L325)
- [`tests/proxy_contracts/test_te_gzip_handoff.py::test_transfer_coding_oracle_rejects_false_success`](../tests/proxy_contracts/test_te_gzip_handoff.py#L413)

<a id="witness-tests-proxy-contracts-test-tunnel-contract-py"></a>
### [`tests/proxy_contracts/test_tunnel_contract.py`](../tests/proxy_contracts/test_tunnel_contract.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_tunnel_contract.py::test_parent_connect_failure_never_falls_back_to_direct_origin`](../tests/proxy_contracts/test_tunnel_contract.py#L227)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_parent_connect_failure_does_not_retry_same_request`](../tests/proxy_contracts/test_tunnel_contract.py#L350)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_parent_connect_failure_recovers_on_later_parent_request`](../tests/proxy_contracts/test_tunnel_contract.py#L452)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_fragmented_tls_keeps_the_inner_request_decision`](../tests/proxy_contracts/test_tunnel_contract.py#L712)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_configured_tls_passthrough_scope_and_interception_failure`](../tests/proxy_contracts/test_tunnel_contract.py#L728)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_http_method_spelling_remains_inspected`](../tests/proxy_contracts/test_tunnel_contract.py#L889)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_http_method_spelling_still_requires_400_after_closed_write`](../tests/proxy_contracts/test_tunnel_contract.py#L930)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_connect_half_close_retains_the_opposite_direction`](../tests/proxy_contracts/test_tunnel_contract.py#L938)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_connect_server_first_then_client_half_close_keeps_final_response`](../tests/proxy_contracts/test_tunnel_contract.py#L992)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_repeated_raw_connect_cancellation_reclaims_origin_and_process_resources`](../tests/proxy_contracts/test_tunnel_contract.py#L1108)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_configured_passthrough_server_first_half_close_keeps_canonical_lifecycle`](../tests/proxy_contracts/test_tunnel_contract.py#L1295)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_configured_passthrough_denied_agent_has_no_origin_contact`](../tests/proxy_contracts/test_tunnel_contract.py#L1398)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_configured_passthrough_client_half_close_keeps_final_response`](../tests/proxy_contracts/test_tunnel_contract.py#L1443)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_configured_passthrough_refusal_records_error_after_no_accept`](../tests/proxy_contracts/test_tunnel_contract.py#L1528)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_configured_passthrough_graceful_shutdown_releases_live_socket`](../tests/proxy_contracts/test_tunnel_contract.py#L1573)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_denied_connect_does_not_contact_raw_origin`](../tests/proxy_contracts/test_tunnel_contract.py#L1647)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_incomplete_connect_client_half_close_does_not_dial_origin`](../tests/proxy_contracts/test_tunnel_contract.py#L1687)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_repeated_incomplete_connect_cancellation_reclaims_origin_and_process_resources`](../tests/proxy_contracts/test_tunnel_contract.py#L1833)
- [`tests/proxy_contracts/test_tunnel_contract.py::test_concurrent_incomplete_connect_cancellation_records_resource_peak`](../tests/proxy_contracts/test_tunnel_contract.py#L2012)
Selection: optional: select `SAFEYOLO_RUN_SSH_CONTRACT` = `1` (Opt-in owned OpenSSH daemon; requires installed ssh, ssh-keygen and sshd); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_tunnel_contract.py::test_real_openssh_preserves_server_first_output_and_client_input`](../tests/proxy_contracts/test_tunnel_contract.py#L2240)

<a id="witness-tests-proxy-contracts-test-websocket-contract-py"></a>
### [`tests/proxy_contracts/test_websocket_contract.py`](../tests/proxy_contracts/test_websocket_contract.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_websocket_contract.py::test_d32_teardown_requires_proxy_control_delivery`](../tests/proxy_contracts/test_websocket_contract.py#L263)
- [`tests/proxy_contracts/test_websocket_contract.py::test_complete_fragmented_messages`](../tests/proxy_contracts/test_websocket_contract.py#L297)
- [`tests/proxy_contracts/test_websocket_contract.py::test_scan_pattern_split_across_fragments_with_interleaved_control`](../tests/proxy_contracts/test_websocket_contract.py#L428)
- [`tests/proxy_contracts/test_websocket_contract.py::test_scanner_across_websocket_storage_transition`](../tests/proxy_contracts/test_websocket_contract.py#L491)
- [`tests/proxy_contracts/test_websocket_contract.py::test_first_server_message_survives_coalesced_101_handoff`](../tests/proxy_contracts/test_websocket_contract.py#L585)
- [`tests/proxy_contracts/test_websocket_contract.py::test_idle_control_ping_pong_and_close_are_forwarded_exactly`](../tests/proxy_contracts/test_websocket_contract.py#L620)
- [`tests/proxy_contracts/test_websocket_contract.py::test_origin_close_after_client_close`](../tests/proxy_contracts/test_websocket_contract.py#L669)
- [`tests/proxy_contracts/test_websocket_contract.py::test_missing_origin_close_does_not_become_clean_reply`](../tests/proxy_contracts/test_websocket_contract.py#L727)
- [`tests/proxy_contracts/test_websocket_contract.py::test_denied_websocket_opens_no_origin_connection`](../tests/proxy_contracts/test_websocket_contract.py#L774)
- [`tests/proxy_contracts/test_websocket_contract.py::test_negotiated_websocket_messages_and_inspection`](../tests/proxy_contracts/test_websocket_contract.py#L800)
- [`tests/proxy_contracts/test_websocket_contract.py::test_unoffered_origin_subprotocol_is_not_accepted`](../tests/proxy_contracts/test_websocket_contract.py#L896)
- [`tests/proxy_contracts/test_websocket_contract.py::test_websocket_schemes_rejected_before_origin_contact`](../tests/proxy_contracts/test_websocket_contract.py#L936)
- [`tests/proxy_contracts/test_websocket_contract.py::test_scanning_modes_and_compression_dictionary`](../tests/proxy_contracts/test_websocket_contract.py#L962)
- [`tests/proxy_contracts/test_websocket_contract.py::test_rule_reload_applies_to_an_existing_websocket`](../tests/proxy_contracts/test_websocket_contract.py#L1011)
- [`tests/proxy_contracts/test_websocket_contract.py::test_message_preceding_close_is_delivered`](../tests/proxy_contracts/test_websocket_contract.py#L1078)
- [`tests/proxy_contracts/test_websocket_contract.py::test_protocol_error_close_codes`](../tests/proxy_contracts/test_websocket_contract.py#L1120)
- [`tests/proxy_contracts/test_websocket_contract.py::test_shutdown_closes_open_websocket_peers`](../tests/proxy_contracts/test_websocket_contract.py#L1139)
- [`tests/proxy_contracts/test_websocket_contract.py::test_native_pending_fragment_disconnect`](../tests/proxy_contracts/test_websocket_contract.py#L1251)
- [`tests/proxy_contracts/test_websocket_contract.py::test_repeated_compressed_fragment_cancellation_records_process_resources`](../tests/proxy_contracts/test_websocket_contract.py#L1316)
- [`tests/proxy_contracts/test_websocket_contract.py::test_native_running_vm_inspection_cancellation`](../tests/proxy_contracts/test_websocket_contract.py#L1480)

<a id="witness-tests-proxy-contracts-test-sse-shutdown-py"></a>
### [`tests/proxy_contracts/test_sse_shutdown.py`](../tests/proxy_contracts/test_sse_shutdown.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_sse_shutdown.py::test_early_sse_disconnect_exits_and_restarts`](../tests/proxy_contracts/test_sse_shutdown.py#L98)
- [`tests/proxy_contracts/test_sse_shutdown.py::test_live_sse_response_shutdown_behavior`](../tests/proxy_contracts/test_sse_shutdown.py#L156)

<a id="witness-tests-proxy-contracts-test-tunnel-audit-wait-py"></a>
### [`tests/proxy_contracts/test_tunnel_audit_wait.py`](../tests/proxy_contracts/test_tunnel_audit_wait.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_tunnel_audit_wait.py::test_http_audit_wait_reads_delayed_complete_record`](../tests/proxy_contracts/test_tunnel_audit_wait.py#L14)
- [`tests/proxy_contracts/test_tunnel_audit_wait.py::test_http_audit_wait_fails_for_missing_evidence`](../tests/proxy_contracts/test_tunnel_audit_wait.py#L36)

<a id="witness-tests-proxy-contracts-test-configured-parent-boundary-py"></a>
### [`tests/proxy_contracts/test_configured_parent_boundary.py`](../tests/proxy_contracts/test_configured_parent_boundary.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_configured_parent_boundary.py::test_configured_parent_http_connect_failure_and_direct_control`](../tests/proxy_contracts/test_configured_parent_boundary.py#L152)
- [`tests/proxy_contracts/test_configured_parent_boundary.py::test_selected_parent_mixed_agents_http_connect_and_spoofed_headers`](../tests/proxy_contracts/test_configured_parent_boundary.py#L268)
- [`tests/proxy_contracts/test_configured_parent_boundary.py::test_parent_agent_filter_default_keeps_global_parent`](../tests/proxy_contracts/test_configured_parent_boundary.py#L326)
- [`tests/proxy_contracts/test_configured_parent_boundary.py::test_selected_parent_connection_failure_has_no_direct_fallback`](../tests/proxy_contracts/test_configured_parent_boundary.py#L351)
- [`tests/proxy_contracts/test_configured_parent_boundary.py::test_destination_filter_mixed_http_and_verified_https`](../tests/proxy_contracts/test_configured_parent_boundary.py#L419)
- [`tests/proxy_contracts/test_configured_parent_boundary.py::test_exact_destination_boundaries_and_connect_authority`](../tests/proxy_contracts/test_configured_parent_boundary.py#L492)
- [`tests/proxy_contracts/test_configured_parent_boundary.py::test_selected_parent_tls_failure_and_unmatched_direct_control`](../tests/proxy_contracts/test_configured_parent_boundary.py#L540)

<a id="witness-tests-proxy-contracts-test-operator-budgets-py"></a>
### [`tests/proxy_contracts/test_operator_budgets.py`](../tests/proxy_contracts/test_operator_budgets.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_operator_budgets.py::test_network_request_limit_scope_and_recovery`](../tests/proxy_contracts/test_operator_budgets.py#L197)
- [`tests/proxy_contracts/test_operator_budgets.py::test_network_request_limit_recovers_after_refill`](../tests/proxy_contracts/test_operator_budgets.py#L277)
- [`tests/proxy_contracts/test_operator_budgets.py::test_operator_exact_budget_reset_shares_state_and_retains_order`](../tests/proxy_contracts/test_operator_budgets.py#L319)
- [`tests/proxy_contracts/test_operator_budgets.py::test_operator_all_reset_clears_global_limit_with_auth_and_shield_boundaries`](../tests/proxy_contracts/test_operator_budgets.py#L356)
- [`tests/proxy_contracts/test_operator_budgets.py::test_operator_malformed_budget_reset_is_terminal_without_mutation`](../tests/proxy_contracts/test_operator_budgets.py#L412)
- [`tests/proxy_contracts/test_operator_budgets.py::test_operator_python_rejected_numeric_body_does_not_reset_budget`](../tests/proxy_contracts/test_operator_budgets.py#L462)

<a id="witness-tests-proxy-contracts-test-agent-api-budgets-py"></a>
### [`tests/proxy_contracts/test_agent_api_budgets.py`](../tests/proxy_contracts/test_agent_api_budgets.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_api_budgets.py::test_agent_api_budgets_empty_schema_is_shared`](../tests/proxy_contracts/test_agent_api_budgets.py#L57)
- [`tests/proxy_contracts/test_agent_api_budgets.py::test_agent_api_budgets_reuses_local_auth_and_method_checks`](../tests/proxy_contracts/test_agent_api_budgets.py#L71)
- [`tests/proxy_contracts/test_agent_api_budgets.py::test_agent_api_budgets_preview_and_denial_do_not_charge`](../tests/proxy_contracts/test_agent_api_budgets.py#L76)
- [`tests/proxy_contracts/test_agent_api_budgets.py::test_agent_api_budgets_retained_counter_uses_last_valid_rule`](../tests/proxy_contracts/test_agent_api_budgets.py#L110)
- [`tests/proxy_contracts/test_agent_api_budgets.py::test_agent_api_budgets_host_and_global_keys_keep_charge_order`](../tests/proxy_contracts/test_agent_api_budgets.py#L134)
- [`tests/proxy_contracts/test_agent_api_budgets.py::test_agent_api_budgets_does_not_serialize_unrelated_temporal_baseline`](../tests/proxy_contracts/test_agent_api_budgets.py#L166)

<a id="witness-tests-proxy-contracts-test-connect-budgets-py"></a>
### [`tests/proxy_contracts/test_connect_budgets.py`](../tests/proxy_contracts/test_connect_budgets.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_connect_budgets.py::test_network_connect_limit_recovers_after_refill`](../tests/proxy_contracts/test_connect_budgets.py#L77)
- [`tests/proxy_contracts/test_connect_budgets.py::test_network_limits_count_reused_requests_and_fresh_tunnels`](../tests/proxy_contracts/test_connect_budgets.py#L197)
- [`tests/proxy_contracts/test_connect_budgets.py::test_network_connect_limit_scope_and_request_separation`](../tests/proxy_contracts/test_connect_budgets.py#L349)

<a id="witness-tests-proxy-contracts-test-circuit-bypass-py"></a>
### [`tests/proxy_contracts/test_circuit_bypass.py`](../tests/proxy_contracts/test_circuit_bypass.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_circuit_bypass.py::test_policy_bypass_skips_request_checks_but_records_completed_failure`](../tests/proxy_contracts/test_circuit_bypass.py#L52)
- [`tests/proxy_contracts/test_circuit_bypass.py::test_required_circuit_overrides_domain_and_client_bypass`](../tests/proxy_contracts/test_circuit_bypass.py#L85)
- [`tests/proxy_contracts/test_circuit_bypass.py::test_complete_429_counts_but_ordinary_4xx_does_not`](../tests/proxy_contracts/test_circuit_bypass.py#L119)

<a id="witness-tests-proxy-contracts-test-circuit-completion-py"></a>
### [`tests/proxy_contracts/test_circuit_completion.py`](../tests/proxy_contracts/test_circuit_completion.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_circuit_completion.py::test_only_complete_upstream_responses_change_live_failure_state`](../tests/proxy_contracts/test_circuit_completion.py#L115)
- [`tests/proxy_contracts/test_circuit_completion.py::test_outer_connect_has_no_circuit_response_hook`](../tests/proxy_contracts/test_circuit_completion.py#L170)

<a id="witness-tests-proxy-contracts-test-circuit-failure-recovery-py"></a>
### [`tests/proxy_contracts/test_circuit_failure_recovery.py`](../tests/proxy_contracts/test_circuit_failure_recovery.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_circuit_failure_recovery.py::test_parent_failure_opens_only_its_host_and_half_open_probe_recovers`](../tests/proxy_contracts/test_circuit_failure_recovery.py#L85)

<a id="witness-tests-proxy-contracts-test-circuit-reload-py"></a>
### [`tests/proxy_contracts/test_circuit_reload.py`](../tests/proxy_contracts/test_circuit_reload.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_circuit_reload.py::test_policy_reload_preserves_live_circuit_state_and_uses_new_settings`](../tests/proxy_contracts/test_circuit_reload.py#L89)
- [`tests/proxy_contracts/test_circuit_reload.py::test_old_admitted_response_uses_current_policy_after_reload`](../tests/proxy_contracts/test_circuit_reload.py#L151)
- [`tests/proxy_contracts/test_circuit_reload.py::test_graceful_restart_retains_saved_failure_state_and_resets_counters`](../tests/proxy_contracts/test_circuit_reload.py#L225)

<a id="witness-tests-proxy-contracts-test-operator-circuits-py"></a>
### [`tests/proxy_contracts/test_operator_circuits.py`](../tests/proxy_contracts/test_operator_circuits.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_operator_circuits.py::test_operator_reset_reopens_admission_for_shared_completed_failures`](../tests/proxy_contracts/test_operator_circuits.py#L211)
- [`tests/proxy_contracts/test_operator_circuits.py::test_circuit_controls_do_not_count_failures`](../tests/proxy_contracts/test_operator_circuits.py#L255)

<a id="witness-tests-proxy-contracts-test-native-blackbox-lifecycle-py"></a>
### [`tests/proxy_contracts/test_native_blackbox_lifecycle.py`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_lifecycle_observes_changed_policy_while_admitted_sse_stays_live`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L36)
- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_lifecycle_load_observation_distinguishes_old_rejected_and_unapplied_policy`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L83)
- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_process_secrecy_consumer_observes_tokens_and_owned_process`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L126)
- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_restart_consumer_uses_real_start_and_checks_sandbox_continuity`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L166)
- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_lifecycle_consumer_retains_inactive_receipt_and_uses_configured_readiness`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L236)
- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_start_waits_for_verified_readiness_and_bounds_owned_child`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L288)
- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_stop_observer_waits_for_process_exit_and_rejects_a_live_birth`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L499)
- [`tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_host_smoke_preserves_configured_ca_failure_and_owned_cleanup`](../tests/proxy_contracts/test_native_blackbox_lifecycle.py#L532)

<a id="witness-tests-proxy-contracts-test-lifecycle-batch-py"></a>
### [`tests/proxy_contracts/test_lifecycle_batch.py`](../tests/proxy_contracts/test_lifecycle_batch.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_lifecycle_batch.py::test_mixed_cancellation_batches_drain_and_restart_same_listener`](../tests/proxy_contracts/test_lifecycle_batch.py#L258)

<a id="witness-tests-proxy-contracts-test-readiness-py"></a>
### [`tests/proxy_contracts/test_readiness.py`](../tests/proxy_contracts/test_readiness.py)

Selection: phase `proxy` (host); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review')`); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_readiness.py::test_readiness_waits_for_this_child`](../tests/proxy_contracts/test_readiness.py#L13)
- [`tests/proxy_contracts/test_readiness.py::test_readiness_rejects_wrong_backend_marker`](../tests/proxy_contracts/test_readiness.py#L44)
- [`tests/proxy_contracts/test_readiness.py::test_readiness_rejects_stale_regular_file_for_socket`](../tests/proxy_contracts/test_readiness.py#L58)
- [`tests/proxy_contracts/test_readiness.py::test_readiness_rejects_nonaccepting_unix_socket`](../tests/proxy_contracts/test_readiness.py#L74)

<a id="witness-tests-proxy-contracts-test-first-agent-launch-py"></a>
### [`tests/proxy_contracts/test_first_agent_launch.py`](../tests/proxy_contracts/test_first_agent_launch.py)

Selection: phase `proxy` (host); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_first_agent_launch.py::test_first_run_numbered_decisions_show_and_enforce_their_real_scope`](../tests/proxy_contracts/test_first_agent_launch.py#L49)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_credential_picker_does_not_attribute_old_requests_to_a_recreated_name`](../tests/proxy_contracts/test_first_agent_launch.py#L89)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_launch_refusal_has_no_setup_service_or_agent_effect`](../tests/proxy_contracts/test_first_agent_launch.py#L111)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_return_launch_reuses_saved_codex_without_repeating_the_harness`](../tests/proxy_contracts/test_first_agent_launch.py#L224)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_return_launch_resolves_ambiguity_and_respects_explicit_harness`](../tests/proxy_contracts/test_first_agent_launch.py#L249)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_codex_launch_authorizes_selected_login_for_created_identity_before_startup`](../tests/proxy_contracts/test_first_agent_launch.py#L290)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_codex_launch_offers_passphrase_storage_on_its_first_import`](../tests/proxy_contracts/test_first_agent_launch.py#L353)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_locked_passphrase_start_keeps_services_and_unrelated_traffic_ready`](../tests/proxy_contracts/test_first_agent_launch.py#L378)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_codex_login_selection_uses_the_launch_config`](../tests/proxy_contracts/test_first_agent_launch.py#L492)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_codex_login_refusal_and_failed_selection_create_no_authority`](../tests/proxy_contracts/test_first_agent_launch.py#L516)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_codex_login_import_errors_preserve_owned_login_and_allow_cancellation`](../tests/proxy_contracts/test_first_agent_launch.py#L564)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_missing_guest_retry_keeps_agent_setup_services_and_unrelated_traffic`](../tests/proxy_contracts/test_first_agent_launch.py#L611)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_unsupported_launch_harness_is_rejected_before_instance_mutation`](../tests/proxy_contracts/test_first_agent_launch.py#L774)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_codex_launch_keeps_selected_authentication_on_setup_refusal`](../tests/proxy_contracts/test_first_agent_launch.py#L792)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_pending_credential_list_does_not_derive_authority_from_retained_audit`](../tests/proxy_contracts/test_first_agent_launch.py#L847)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_credential_retry_keeps_the_inspected_action`](../tests/proxy_contracts/test_first_agent_launch.py#L885)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_credential_selection_retains_its_authority_and_rechecks_policy`](../tests/proxy_contracts/test_first_agent_launch.py#L933)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_direct_credential_decision_keeps_the_selected_destination`](../tests/proxy_contracts/test_first_agent_launch.py#L1006)
- [`tests/proxy_contracts/test_first_agent_launch.py::test_credential_policy_write_cannot_bypass_canonical_approval`](../tests/proxy_contracts/test_first_agent_launch.py#L1039)

<a id="witness-tests-proxy-contracts-test-gateway-provider-py"></a>
### [`tests/proxy_contracts/test_gateway_provider.py`](../tests/proxy_contracts/test_gateway_provider.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_gateway_provider.py::test_native_service_tokens_reach_gateway_with_credential_guard_enabled`](../tests/proxy_contracts/test_gateway_provider.py#L60)
- [`tests/proxy_contracts/test_gateway_provider.py::test_native_unmapped_gateway_token_cannot_reach_parent`](../tests/proxy_contracts/test_gateway_provider.py#L165)
- [`tests/proxy_contracts/test_gateway_provider.py::test_provider_subordinate_bases_select_owned_ranges`](../tests/proxy_contracts/test_gateway_provider.py#L213)
- [`tests/proxy_contracts/test_gateway_provider.py::test_provider_subordinate_bases_require_a_complete_owned_range`](../tests/proxy_contracts/test_gateway_provider.py#L223)
- [`tests/proxy_contracts/test_gateway_provider.py::test_gateway_routes_only_authorized_calls_to_provider_stream`](../tests/proxy_contracts/test_gateway_provider.py#L295)

<a id="witness-tests-proxy-contracts-test-native-provider-recovery-py"></a>
### [`tests/proxy_contracts/test_native_provider_recovery.py`](../tests/proxy_contracts/test_native_provider_recovery.py)

Selection: optional: select `SAFEYOLO_971_RUNSC` explicitly (Explicit prepared provider-recovery Linux venue.); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_provider_recovery.py::test_authorized_provider_survives_only_its_holder_loss`](../tests/proxy_contracts/test_native_provider_recovery.py#L109)

<a id="witness-tests-proxy-contracts-test-desktop-waiting-page-py"></a>
### [`tests/proxy_contracts/test_desktop_waiting_page.py`](../tests/proxy_contracts/test_desktop_waiting_page.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_desktop_waiting_page.py::test_silent_listener_recovers_in_same_page_with_live_history`](../tests/proxy_contracts/test_desktop_waiting_page.py#L128)
- [`tests/proxy_contracts/test_desktop_waiting_page.py::test_hints_stalls_assets_access_and_log_bounds`](../tests/proxy_contracts/test_desktop_waiting_page.py#L161)
- [`tests/proxy_contracts/test_desktop_waiting_page.py::test_authoritative_access_failure_stops_requests`](../tests/proxy_contracts/test_desktop_waiting_page.py#L212)
- [`tests/proxy_contracts/test_desktop_waiting_page.py::test_credentials_and_server_verification_keep_the_page_and_redact_copy`](../tests/proxy_contracts/test_desktop_waiting_page.py#L227)
- [`tests/proxy_contracts/test_desktop_waiting_page.py::test_unknown_inspection_stale_results_and_deliberate_close`](../tests/proxy_contracts/test_desktop_waiting_page.py#L249)
- [`tests/proxy_contracts/test_desktop_waiting_page.py::test_viewer_failures_reach_a_bounded_stage_and_leave_diagnostics`](../tests/proxy_contracts/test_desktop_waiting_page.py#L285)
- [`tests/proxy_contracts/test_desktop_waiting_page.py::test_unusable_origin_observation_is_distinct_from_no_response`](../tests/proxy_contracts/test_desktop_waiting_page.py#L300)

<a id="witness-tests-proxy-contracts-test-native-coord-operator-py"></a>
### [`tests/proxy_contracts/test_native_coord_operator.py`](../tests/proxy_contracts/test_native_coord_operator.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_coord_operator.py::test_installed_continuity_setup_uses_native_room_grants_and_readers`](../tests/proxy_contracts/test_native_coord_operator.py#L99)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_scripted_inputs_payloads_authority_and_rejections`](../tests/proxy_contracts/test_native_coord_operator.py#L185)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_pty_draft_receive_unknown_count_and_later_send`](../tests/proxy_contracts/test_native_coord_operator.py#L215)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_pty_queued_arrivals_exit_without_another_message`](../tests/proxy_contracts/test_native_coord_operator.py#L247)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_clipboard_editor_confirmation_and_cancellation`](../tests/proxy_contracts/test_native_coord_operator.py#L271)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_watch_timeline_payload_modes_and_cursor_reconnect`](../tests/proxy_contracts/test_native_coord_operator.py#L315)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_history_byte_limit_returns_partial_pages_and_watch_tail`](../tests/proxy_contracts/test_native_coord_operator.py#L357)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_empty_retained_ranges_finish_and_watch_follows`](../tests/proxy_contracts/test_native_coord_operator.py#L389)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_history_provider_failure_remains_an_error`](../tests/proxy_contracts/test_native_coord_operator.py#L424)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_supervisor_events_reach_coord_and_live_watch`](../tests/proxy_contracts/test_native_coord_operator.py#L437)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_agent_watch_tool_summaries_omit_private_payloads`](../tests/proxy_contracts/test_native_coord_operator.py#L525)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_agent_watch_checkpoint_and_tool_targets_omit_url_credentials`](../tests/proxy_contracts/test_native_coord_operator.py#L587)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_agent_watch_public_references_and_secrets_in_terminal_and_pipe`](../tests/proxy_contracts/test_native_coord_operator.py#L631)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_agent_watch_failures_redaction_and_read_only`](../tests/proxy_contracts/test_native_coord_operator.py#L662)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_agent_watch_real_supervisor_restart_and_thread_replacement`](../tests/proxy_contracts/test_native_coord_operator.py#L731)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_supervisor_capacity_with_retained_task_and_native_ready`](../tests/proxy_contracts/test_native_coord_operator.py#L851)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_local_jsonl_and_maintained_factory_wrapper`](../tests/proxy_contracts/test_native_coord_operator.py#L946)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_retained_pi_event_formats`](../tests/proxy_contracts/test_native_coord_operator.py#L1036)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_compact_watcher_matches_retained_python_sequences`](../tests/proxy_contracts/test_native_coord_operator.py#L1045)
- [`tests/proxy_contracts/test_native_coord_operator.py::test_compact_rejects_conflicting_output_modes`](../tests/proxy_contracts/test_native_coord_operator.py#L1061)

<a id="witness-tests-proxy-contracts-test-installed-coord-events-py"></a>
### [`tests/proxy_contracts/test_installed_coord_events.py`](../tests/proxy_contracts/test_installed_coord_events.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_installed_coord_events.py::test_approval_event_allows_intervening_frames_and_still_matches_key`](../tests/proxy_contracts/test_installed_coord_events.py#L24)
- [`tests/proxy_contracts/test_installed_coord_events.py::test_unrelated_event_traffic_cannot_extend_approval_deadline`](../tests/proxy_contracts/test_installed_coord_events.py#L40)
- [`tests/proxy_contracts/test_installed_coord_events.py::test_installed_collaboration_matches_event_resolves_and_revokes`](../tests/proxy_contracts/test_installed_coord_events.py#L52)

<a id="witness-tests-proxy-contracts-test-native-factory-cli-py"></a>
### [`tests/proxy_contracts/test_native_factory_cli.py`](../tests/proxy_contracts/test_native_factory_cli.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_setup_preview_keeps_exact_contract_and_approval_separate`](../tests/proxy_contracts/test_native_factory_cli.py#L146)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_setup_resumes_prepared_roles_without_reapplying_or_initializing_checkpoints`](../tests/proxy_contracts/test_native_factory_cli.py#L168)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_setup_keeps_valid_checkpoint_and_diagnoses_corrupt_checkpoint`](../tests/proxy_contracts/test_native_factory_cli.py#L187)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_setup_approval_and_workspace_requirements_do_not_launch_roles`](../tests/proxy_contracts/test_native_factory_cli.py#L208)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_setup_keeps_explicit_codex_adoption_before_runtime_start`](../tests/proxy_contracts/test_native_factory_cli.py#L224)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_setup_repairs_stopped_staging_and_explicitly_changed_workspace`](../tests/proxy_contracts/test_native_factory_cli.py#L238)
Selection: phase `proxy` (host); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_installed_prepare_stages_codex_pi_and_retains_state_and_peer_grants`](../tests/proxy_contracts/test_native_factory_cli.py#L257)
Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_installed_repo_map_reads_working_tree_and_reports_guidance`](../tests/proxy_contracts/test_native_factory_cli.py#L336)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_installed_doctor_checks_actual_direct_and_wrapped_role_commands`](../tests/proxy_contracts/test_native_factory_cli.py#L373)
Selection: phase `proxy` (host); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_doctor_rejects_the_paused_exact_command_with_a_healthy_supervisor`](../tests/proxy_contracts/test_native_factory_cli.py#L447)
Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_native_release_preserves_other_work_and_requires_canonical_audit`](../tests/proxy_contracts/test_native_factory_cli.py#L545)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_doctor_names_missing_role_executable_and_room_permission`](../tests/proxy_contracts/test_native_factory_cli.py#L583)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_factory_stop_interprets_lifecycle_errors`](../tests/proxy_contracts/test_native_factory_cli.py#L626)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_factory_run_does_not_boot_workers_without_coord`](../tests/proxy_contracts/test_native_factory_cli.py#L649)
- [`tests/proxy_contracts/test_native_factory_cli.py::test_factory_run_does_not_boot_workers_when_room_provisioning_fails`](../tests/proxy_contracts/test_native_factory_cli.py#L662)
Selection: phase `proxy` (host); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_factory_run_requires_confirmation_before_any_role_starts`](../tests/proxy_contracts/test_native_factory_cli.py#L674)
Selection: optional: select `SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE` explicitly (Explicit disposable installed guided-setup acceptance root.); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_factory_setup_interruption_preserves_prepared_roles`](../tests/proxy_contracts/test_native_factory_cli.py#L701)
Selection: optional: select `SAFEYOLO_FACTORY_ACCEPTANCE_ROOT` explicitly (Explicit disposable installed Factory acceptance root.); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_factory_cli.py::test_factory_run_executes_staged_worker_commands`](../tests/proxy_contracts/test_native_factory_cli.py#L743)

<a id="witness-tests-proxy-contracts-test-native-harness-attention-py"></a>
### [`tests/proxy_contracts/test_native_harness_attention.py`](../tests/proxy_contracts/test_native_harness_attention.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_claude_streaming_refusal_keeps_native_connection`](../tests/proxy_contracts/test_native_harness_attention.py#L87)
Selection: optional: select `SAFEYOLO_CLAUDE_ATTENTION_MODEL` explicitly (select an authorized real native Claude model explicitly); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_claude_streaming_idle_busy_recovery_and_attribution`](../tests/proxy_contracts/test_native_harness_attention.py#L124)
Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_native_rpc_reader_retains_partial_and_complete_suffixes`](../tests/proxy_contracts/test_native_harness_attention.py#L438)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_native_requests_cannot_complete_frontend_or_attention_requests`](../tests/proxy_contracts/test_native_harness_attention.py#L462)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_claude_channel_canonical_submission_keeps_existing_tools`](../tests/proxy_contracts/test_native_harness_attention.py#L543)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_unsupported_attention_mode_fails_before_native_launch`](../tests/proxy_contracts/test_native_harness_attention.py#L599)
Selection: optional: select `SAFEYOLO_PI_ATTENTION_MODEL` explicitly (select an authorized real Pi model explicitly); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_pi_canonical_event_wakes_idle_native_session`](../tests/proxy_contracts/test_native_harness_attention.py#L609)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_pi_delivery_during_a_controlled_native_tool`](../tests/proxy_contracts/test_native_harness_attention.py#L649)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_pi_context_canonical_restart_and_operator_attribution`](../tests/proxy_contracts/test_native_harness_attention.py#L692)
Selection: optional: select `SAFEYOLO_CODEX_ATTENTION_MODEL` explicitly (select an authorized real Codex model explicitly); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_codex_canonical_event_wakes_idle_native_session`](../tests/proxy_contracts/test_native_harness_attention.py#L764)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_codex_delivery_during_a_controlled_native_tool`](../tests/proxy_contracts/test_native_harness_attention.py#L844)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_codex_context_canonical_restart_and_operator_attribution`](../tests/proxy_contracts/test_native_harness_attention.py#L923)
Selection: optional: select `SAFEYOLO_GEMINI_ATTENTION_MODEL` explicitly (select an authorized real Gemini model explicitly); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_gemini_canonical_event_wakes_idle_native_session`](../tests/proxy_contracts/test_native_harness_attention.py#L994)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_gemini_delivery_during_a_controlled_native_tool`](../tests/proxy_contracts/test_native_harness_attention.py#L1020)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_gemini_explicit_fallback_without_inference`](../tests/proxy_contracts/test_native_harness_attention.py#L1073)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_gemini_canonical_restart_duplicates_and_operator_attribution`](../tests/proxy_contracts/test_native_harness_attention.py#L1089)
Selection: optional: select `SAFEYOLO_HERMES_ATTENTION_MODEL` explicitly (select an authorized real Hermes model explicitly); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_hermes_canonical_event_wakes_idle_native_session`](../tests/proxy_contracts/test_native_harness_attention.py#L1168)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_hermes_delivery_during_a_controlled_native_tool`](../tests/proxy_contracts/test_native_harness_attention.py#L1195)
- [`tests/proxy_contracts/test_native_harness_attention.py::test_hermes_canonical_restart_and_operator_attribution`](../tests/proxy_contracts/test_native_harness_attention.py#L1254)
Selection: optional: select `SAFEYOLO_HERMES_ATTENTION_MODEL` explicitly (select a configured native Hermes profile explicitly); phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_harness_attention.py::test_hermes_explicit_fallback_and_scoped_catalog_without_inference`](../tests/proxy_contracts/test_native_harness_attention.py#L1311)

<a id="witness-tests-proxy-contracts-test-native-ingress-observer-py"></a>
### [`tests/proxy_contracts/test_native_ingress_observer.py`](../tests/proxy_contracts/test_native_ingress_observer.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_ingress_observer.py::test_ingress_native_defaults_trace_and_origin`](../tests/proxy_contracts/test_native_ingress_observer.py#L24)
- [`tests/proxy_contracts/test_native_ingress_observer.py::test_ingress_refuses_native_disabled_or_warn_control`](../tests/proxy_contracts/test_native_ingress_observer.py#L74)
- [`tests/proxy_contracts/test_native_ingress_observer.py::test_peer_boundary_rejects_access_and_requires_own_positive_controls`](../tests/proxy_contracts/test_native_ingress_observer.py#L81)

<a id="witness-tests-proxy-contracts-test-native-managed-state-py"></a>
### [`tests/proxy_contracts/test_native_managed_state.py`](../tests/proxy_contracts/test_native_managed_state.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_managed_state.py::test_installed_callers_keep_unavailable_managed_state_unverified`](../tests/proxy_contracts/test_native_managed_state.py#L22)

<a id="witness-tests-blackbox-isolation-test-vm-isolation-py"></a>
### [`tests/blackbox/isolation/test_vm_isolation.py`](../tests/blackbox/isolation/test_vm_isolation.py)

Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_direct_http_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L84)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_direct_https_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L98)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_dns_udp_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L113)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_raw_socket_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L140)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_direct_alt_port_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L158)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_libc_resolver_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L179)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_non_icmp_raw_protocols_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L197)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_ipv6_egress_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L219)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_metadata_ips_unreachable`](../tests/blackbox/isolation/test_vm_isolation.py#L251)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_af_packet_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L271)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_dns_tunnel_subdomain_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L287)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_host_header_mismatch_routes_by_url`](../tests/blackbox/isolation/test_vm_isolation.py#L314)
Selection: phase `guest-agent` (guest-agent); phase `listener-ordinary` (guest-agent); phase `listener-sandbox-root` (guest-agent).

- [`tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_proxy_reachable`](../tests/blackbox/isolation/test_vm_isolation.py#L349)
Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_vm_isolation.py::TestHostAdjacentReachability::test_admin_api_unreachable`](../tests/blackbox/isolation/test_vm_isolation.py#L421)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestHostAdjacentReachability::test_host_ssh_unreachable`](../tests/blackbox/isolation/test_vm_isolation.py#L438)
Selection: phase `guest-agent` (guest-agent); phase `listener-ordinary` (guest-agent).

- [`tests/blackbox/isolation/test_vm_isolation.py::TestHostAdjacentReachability::test_host_listener_unreachable`](../tests/blackbox/isolation/test_vm_isolation.py#L465)
Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_vm_isolation.py::TestHostAdjacentReachability::test_arbitrary_host_port_unreachable`](../tests/blackbox/isolation/test_vm_isolation.py#L479)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestHostAdjacentReachability::test_cross_agent_ip_unreachable`](../tests/blackbox/isolation/test_vm_isolation.py#L492)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestHostAdjacentReachability::test_sinkhole_direct_unreachable`](../tests/blackbox/isolation/test_vm_isolation.py#L536)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestGuestPrivilegeBoundary::test_expected_uid`](../tests/blackbox/isolation/test_vm_isolation.py#L566)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestGuestPrivilegeBoundary::test_privilege_transition_matches_platform_contract`](../tests/blackbox/isolation/test_vm_isolation.py#L577)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestGuestPrivilegeBoundary::test_sudo_reaches_guest_root`](../tests/blackbox/isolation/test_vm_isolation.py#L599)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestGuestPrivilegeBoundary::test_kernel_modules_disabled`](../tests/blackbox/isolation/test_vm_isolation.py#L618)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestGuestPrivilegeBoundary::test_no_dev_mem`](../tests/blackbox/isolation/test_vm_isolation.py#L643)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestGuestPrivilegeBoundary::test_no_dev_kmem`](../tests/blackbox/isolation/test_vm_isolation.py#L653)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestGuestPrivilegeBoundary::test_ebpf_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L663)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxRootContainment::test_config_share_stays_readonly_as_sandbox_root`](../tests/blackbox/isolation/test_vm_isolation.py#L695)
Selection: phase `guest-agent` (guest-agent); phase `listener-sandbox-root` (guest-agent).

- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxRootContainment::test_host_listener_stays_unreachable_as_sandbox_root`](../tests/blackbox/isolation/test_vm_isolation.py#L716)
Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxRootContainment::test_host_kernel_surfaces_stay_absent_as_sandbox_root`](../tests/blackbox/isolation/test_vm_isolation.py#L736)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestFilesystemIsolation::test_config_share_readonly`](../tests/blackbox/isolation/test_vm_isolation.py#L778)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestFilesystemIsolation::test_no_private_key_in_config_share`](../tests/blackbox/isolation/test_vm_isolation.py#L792)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxExposure::test_dev_whitelist`](../tests/blackbox/isolation/test_vm_isolation.py#L833)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxExposure::test_proc_kcore_unreadable`](../tests/blackbox/isolation/test_vm_isolation.py#L945)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxExposure::test_proc_kallsyms_redacted`](../tests/blackbox/isolation/test_vm_isolation.py#L960)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxExposure::test_sys_kernel_debug_inaccessible`](../tests/blackbox/isolation/test_vm_isolation.py#L985)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxExposure::test_pid_namespace_isolated`](../tests/blackbox/isolation/test_vm_isolation.py#L1004)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxExposure::test_firewall_rules_not_readable`](../tests/blackbox/isolation/test_vm_isolation.py#L1029)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSandboxExposure::test_host_ssh_not_reachable_via_sandbox_sshd`](../tests/blackbox/isolation/test_vm_isolation.py#L1055)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestFilesystemBoundary::test_workspace_symlink_traversal`](../tests/blackbox/isolation/test_vm_isolation.py#L1088)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestFilesystemBoundary::test_workspace_no_mknod`](../tests/blackbox/isolation/test_vm_isolation.py#L1130)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSyscallSeccompEquivalents::test_keyctl_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L1207)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSyscallSeccompEquivalents::test_add_key_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L1220)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSyscallSeccompEquivalents::test_pivot_root_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L1234)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSyscallSeccompEquivalents::test_unshare_user_ns_contained`](../tests/blackbox/isolation/test_vm_isolation.py#L1248)
- [`tests/blackbox/isolation/test_vm_isolation.py::TestSyscallSeccompEquivalents::test_ptrace_init_blocked`](../tests/blackbox/isolation/test_vm_isolation.py#L1306)

<a id="witness-tests-blackbox-isolation-test-root-containment-py"></a>
### [`tests/blackbox/isolation/test_root_containment.py`](../tests/blackbox/isolation/test_root_containment.py)

Selection: phase `guest-root` (guest-root).

- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootCapability::test_root_shell_has_uid_zero`](../tests/blackbox/isolation/test_root_containment.py#L50)
- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootCapability::test_root_shell_and_pid1_have_nofile_limit`](../tests/blackbox/isolation/test_root_containment.py#L62)
- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootCapability::test_root_can_install_local_apt_package`](../tests/blackbox/isolation/test_root_containment.py#L83)
- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootTrustIsolation::test_guest_ca_change_does_not_change_proxy_validation`](../tests/blackbox/isolation/test_root_containment.py#L164)
- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootContainment::test_root_direct_egress_blocked`](../tests/blackbox/isolation/test_root_containment.py#L264)
Selection: phase `guest-root` (guest-root); phase `listener-guest-root` (guest-root).

- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootContainment::test_root_proxy_path_works`](../tests/blackbox/isolation/test_root_containment.py#L290)
- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootContainment::test_root_cannot_reach_live_host_listener`](../tests/blackbox/isolation/test_root_containment.py#L322)
Selection: phase `guest-root` (guest-root).

- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootContainment::test_root_cannot_modify_host_config_share`](../tests/blackbox/isolation/test_root_containment.py#L332)
- [`tests/blackbox/isolation/test_root_containment.py::TestGuestRootContainment::test_gvisor_root_cannot_access_host_kvm_device`](../tests/blackbox/isolation/test_root_containment.py#L345)

<a id="witness-tests-blackbox-isolation-test-key-isolation-py"></a>
### [`tests/blackbox/isolation/test_key_isolation.py`](../tests/blackbox/isolation/test_key_isolation.py)

Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_key_isolation.py::TestPublicCertPresent::test_public_cert_exists`](../tests/blackbox/isolation/test_key_isolation.py#L72)
- [`tests/blackbox/isolation/test_key_isolation.py::TestPublicCertPresent::test_public_cert_readable`](../tests/blackbox/isolation/test_key_isolation.py#L83)
- [`tests/blackbox/isolation/test_key_isolation.py::TestPublicCertPresent::test_public_cert_has_no_private_key`](../tests/blackbox/isolation/test_key_isolation.py#L97)
Selection: phase `guest-agent` (guest-agent); phase `guest-root` (guest-root).

- [`tests/blackbox/isolation/test_key_isolation.py::TestPrivateKeyAbsent::test_no_key_files_in_cert_store`](../tests/blackbox/isolation/test_key_isolation.py#L124)
- [`tests/blackbox/isolation/test_key_isolation.py::TestPrivateKeyAbsent::test_no_key_files_in_config_share`](../tests/blackbox/isolation/test_key_isolation.py#L140)
- [`tests/blackbox/isolation/test_key_isolation.py::TestPrivateKeyAbsent::test_no_private_key_content_in_pem_files`](../tests/blackbox/isolation/test_key_isolation.py#L157)
- [`tests/blackbox/isolation/test_key_isolation.py::TestPrivateKeyAbsent::test_full_filesystem_scan_for_private_keys`](../tests/blackbox/isolation/test_key_isolation.py#L191)

<a id="witness-tests-blackbox-isolation-test-agent-api-scope-py"></a>
### [`tests/blackbox/isolation/test_agent_api_scope.py`](../tests/blackbox/isolation/test_agent_api_scope.py)

Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIAuth::test_health_with_valid_token`](../tests/blackbox/isolation/test_agent_api_scope.py#L84)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIAuth::test_health_without_token`](../tests/blackbox/isolation/test_agent_api_scope.py#L95)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIAuth::test_health_with_wrong_token`](../tests/blackbox/isolation/test_agent_api_scope.py#L105)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIAuth::test_health_with_empty_bearer`](../tests/blackbox/isolation/test_agent_api_scope.py#L116)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIAuth::test_every_get_route_requires_auth`](../tests/blackbox/isolation/test_agent_api_scope.py#L126)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIMethodRestriction::test_put_rejected`](../tests/blackbox/isolation/test_agent_api_scope.py#L156)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIMethodRestriction::test_patch_rejected`](../tests/blackbox/isolation/test_agent_api_scope.py#L168)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIMethodRestriction::test_delete_on_nonexistent_route`](../tests/blackbox/isolation/test_agent_api_scope.py#L178)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIMutationSurface::test_tag_post_requires_auth`](../tests/blackbox/isolation/test_agent_api_scope.py#L202)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIMutationSurface::test_tag_delete_requires_auth`](../tests/blackbox/isolation/test_agent_api_scope.py#L220)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIMutationSurface::test_gateway_request_access_requires_auth`](../tests/blackbox/isolation/test_agent_api_scope.py#L236)
- [`tests/blackbox/isolation/test_agent_api_scope.py::TestAgentAPIMutationSurface::test_post_on_get_only_route_rejected`](../tests/blackbox/isolation/test_agent_api_scope.py#L255)

<a id="witness-tests-blackbox-isolation-test-runtime-capabilities-py"></a>
### [`tests/blackbox/isolation/test_runtime_capabilities.py`](../tests/blackbox/isolation/test_runtime_capabilities.py)

Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_runtime_capabilities.py::TestOpenFileLimit::test_pid1_shell_and_child_inherit_nofile_limit`](../tests/blackbox/isolation/test_runtime_capabilities.py#L18)

<a id="witness-tests-blackbox-isolation-test-guest-ssh-py"></a>
### [`tests/blackbox/isolation/test_guest_ssh.py`](../tests/blackbox/isolation/test_guest_ssh.py)

Selection: phase `guest-agent` (guest-agent).

- [`tests/blackbox/isolation/test_guest_ssh.py::TestGuestSSH::test_guest_server_accepts_owned_key_and_refuses_unknown_key`](../tests/blackbox/isolation/test_guest_ssh.py#L17)

<a id="witness-tests-blackbox-host-native-test-installed-native-py"></a>
### [`tests/blackbox/host/native/test_installed_native.py`](../tests/blackbox/host/native/test_installed_native.py)

Selection: phase `native` (host).

- [`tests/blackbox/host/native/test_installed_native.py::TestInstalledNative::test_controlled_origin_and_protected_admin`](../tests/blackbox/host/native/test_installed_native.py#L38)

<a id="witness-tests-blackbox-host-security-test-firewall-structural-py"></a>
### [`tests/blackbox/host/security/test_firewall_structural.py`](../tests/blackbox/host/security/test_firewall_structural.py)

Selection: phase `security` (host).

- [`tests/blackbox/host/security/test_firewall_structural.py::TestProcessSecrecy::test_no_tokens_in_process_cmdline`](../tests/blackbox/host/security/test_firewall_structural.py#L28)

<a id="witness-tests-blackbox-host-identity-test-agent-identity-py"></a>
### [`tests/blackbox/host/identity/test_agent_identity.py`](../tests/blackbox/host/identity/test_agent_identity.py)

Selection: phase `identity` (host).

- [`tests/blackbox/host/identity/test_agent_identity.py::TestAgentListener::test_agent_listener_has_entry`](../tests/blackbox/host/identity/test_agent_identity.py#L36)
- [`tests/blackbox/host/identity/test_agent_identity.py::TestAgentListener::test_agent_listener_has_attribution_ip`](../tests/blackbox/host/identity/test_agent_identity.py#L44)
- [`tests/blackbox/host/identity/test_agent_identity.py::TestAgentListener::test_agent_listener_has_socket`](../tests/blackbox/host/identity/test_agent_identity.py#L52)
- [`tests/blackbox/host/identity/test_agent_identity.py::TestRootlessUidMapping::test_sandbox_root_maps_to_subordinate_host_uid`](../tests/blackbox/host/identity/test_agent_identity.py#L70)

<a id="witness-tests-blackbox-host-lifecycle-test-home-persistence-py"></a>
### [`tests/blackbox/host/lifecycle/test_home_persistence.py`](../tests/blackbox/host/lifecycle/test_home_persistence.py)

Selection: phase `host-lifecycle` (host).

- [`tests/blackbox/host/lifecycle/test_home_persistence.py::TestAgentHomePersistence::test_home_persists_across_restart`](../tests/blackbox/host/lifecycle/test_home_persistence.py#L141)

<a id="witness-tests-blackbox-host-lifecycle-test-token-lifecycle-py"></a>
### [`tests/blackbox/host/lifecycle/test_token_lifecycle.py`](../tests/blackbox/host/lifecycle/test_token_lifecycle.py)

Selection: phase `host-lifecycle` (host); phase `listener-restart` (host).

- [`tests/blackbox/host/lifecycle/test_token_lifecycle.py::TestLiveAgentLifecycle::test_agent_api_survives_proxy_restart`](../tests/blackbox/host/lifecycle/test_token_lifecycle.py#L84)

<a id="witness-tests-blackbox-host-lifecycle-test-host-listener-py"></a>
### [`tests/blackbox/host/lifecycle/test_host_listener.py`](../tests/blackbox/host/lifecycle/test_host_listener.py)

Selection: phase `host-lifecycle` (host); phase `listener-restart` (host).

- [`tests/blackbox/host/lifecycle/test_host_listener.py::TestLiveHostListener::test_live_host_listener_refused`](../tests/blackbox/host/lifecycle/test_host_listener.py#L29)

<a id="witness-tests-test-guest-acquisition-py"></a>
### [`tests/test_guest_acquisition.py`](../tests/test_guest_acquisition.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_native_acquisition_omits_only_publisher_identical_config`](../tests/test_guest_acquisition.py#L360)
- [`tests/test_guest_acquisition.py::test_native_acquisition_refuses_invalid_config_before_archive`](../tests/test_guest_acquisition.py#L402)
- [`tests/test_guest_acquisition.py::test_copied_instance_keeps_installed_guest_binding`](../tests/test_guest_acquisition.py#L443)
- [`tests/test_guest_acquisition.py::test_explicit_first_acquisition_selects_each_index_without_discovery`](../tests/test_guest_acquisition.py#L489)
- [`tests/test_guest_acquisition.py::test_custom_profile_requires_explicit_index_and_reuses_native_preparation`](../tests/test_guest_acquisition.py#L525)
Selection: phase `rootless-preparation` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_guest_validation_failure_keeps_verified_archive_for_retry`](../tests/test_guest_acquisition.py#L549)
Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_linux_extraction_preserves_metadata_across_tar_records`](../tests/test_guest_acquisition.py#L577)
Selection: phase `rootless-preparation` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_native_selection_pins_one_index_and_keeps_existing_installation`](../tests/test_guest_acquisition.py#L623)
Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_native_acquisition_refuses_before_activation`](../tests/test_guest_acquisition.py#L677)
- [`tests/test_guest_acquisition.py::test_guest_download_pins_index_and_reuses_verified_inputs`](../tests/test_guest_acquisition.py#L736)
- [`tests/test_guest_acquisition.py::test_pinned_handoff_revalidates_retained_content`](../tests/test_guest_acquisition.py#L772)
- [`tests/test_guest_acquisition.py::test_acquisition_reads_the_verified_file_and_refuses_nonregular_cache`](../tests/test_guest_acquisition.py#L830)
- [`tests/test_guest_acquisition.py::test_download_metadata_keeps_discovery_fresh_and_checks_package_compatibility`](../tests/test_guest_acquisition.py#L859)
Selection: phase `rootless-preparation` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_early_preparation_defers_unavailable_setup_and_reports_cleanup_failure`](../tests/test_guest_acquisition.py#L887)
- [`tests/test_guest_acquisition.py::test_guest_download_interruption_removes_partial_blob_and_allows_retry`](../tests/test_guest_acquisition.py#L934)
Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_guest_download_timing_is_opt_in`](../tests/test_guest_acquisition.py#L960)
Selection: phase `rootless-preparation` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_guest_download_decodes_during_transfer_but_extracts_only_verified_bytes`](../tests/test_guest_acquisition.py#L993)
Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_first_acquisition_rejects_wrong_index_digest`](../tests/test_guest_acquisition.py#L1115)
- [`tests/test_guest_acquisition.py::test_invalid_acquisition_index_options_make_no_changes`](../tests/test_guest_acquisition.py#L1132)
- [`tests/test_guest_acquisition.py::test_generated_malformed_acquisition_digests_make_no_changes`](../tests/test_guest_acquisition.py#L1144)
- [`tests/test_guest_acquisition.py::test_pinned_acquisition_preserves_nonfresh_roots`](../tests/test_guest_acquisition.py#L1156)
- [`tests/test_guest_acquisition.py::test_generated_archive_paths_cannot_escape_staging`](../tests/test_guest_acquisition.py#L1174)
Selection: phase `rootless-preparation` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_rootless_production_metadata_and_distinct_mappings`](../tests/test_guest_acquisition.py#L1201)
Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_native_client_reports_bad_proxy_and_ca_without_panicking`](../tests/test_guest_acquisition.py#L1213)
- [`tests/test_guest_acquisition.py::test_verified_bundle_installer_and_proxy_restart_retain_guest`](../tests/test_guest_acquisition.py#L1222)
- [`tests/test_guest_acquisition.py::test_host_archive_smoke_runs_normal_native_guest_acquisition`](../tests/test_guest_acquisition.py#L1291)
Selection: phase `rootless-guest` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_acquisition.py::test_prepared_rootless_guest_remains_usable_after_restart`](../tests/test_guest_acquisition.py#L1369)

<a id="witness-tests-test-guest-upgrade-py"></a>
### [`tests/test_guest_upgrade.py`](../tests/test_guest_upgrade.py)

Selection: phase `rootless-preparation` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_upgrade.py::test_explicit_upgrade_pins_reuses_and_rolls_back_without_changing_host_or_state`](../tests/test_guest_upgrade.py#L67)
Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_upgrade.py::test_metadata_only_upgrade_retains_previous_release_and_reuses_inputs`](../tests/test_guest_upgrade.py#L120)
Selection: phase `rootless-preparation` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_upgrade.py::test_upgrade_refusals_preserve_active_and_previous_selection`](../tests/test_guest_upgrade.py#L174)
- [`tests/test_guest_upgrade.py::test_failed_activation_is_retryable_and_bad_selected_inputs_can_be_rolled_back`](../tests/test_guest_upgrade.py#L224)
- [`tests/test_guest_upgrade.py::test_killed_archive_pull_preserves_selection_and_next_upgrade_recovers`](../tests/test_guest_upgrade.py#L261)
Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_guest_upgrade.py::test_generated_invalid_index_shapes_cannot_replace_the_active_guest`](../tests/test_guest_upgrade.py#L296)
- [`tests/test_guest_upgrade.py::test_invalid_guest_command_options_do_not_change_the_instance`](../tests/test_guest_upgrade.py#L315)
- [`tests/test_guest_upgrade.py::test_verified_bundle_guest_updates_preserve_running_proxy_host_and_restart_state`](../tests/test_guest_upgrade.py#L329)

<a id="witness-tests-test-component-upgrade-py"></a>
### [`tests/test_component_upgrade.py`](../tests/test_component_upgrade.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_component_upgrade.py::test_stock_installed_pair_status_upgrade_and_rollback`](../tests/test_component_upgrade.py#L117)
- [`tests/test_component_upgrade.py::test_runsc_pin_refusals_preserve_current_and_state`](../tests/test_component_upgrade.py#L152)
- [`tests/test_component_upgrade.py::test_bad_retained_stock_runtime_cannot_replace_current_on_rollback`](../tests/test_component_upgrade.py#L194)
- [`tests/test_component_upgrade.py::test_rollback_checks_retained_coord_before_selection`](../tests/test_component_upgrade.py#L219)
- [`tests/test_component_upgrade.py::test_shell_verifier_distinguishes_installed_and_target_runsc_pins`](../tests/test_component_upgrade.py#L296)
- [`tests/test_component_upgrade.py::test_shell_installed_stock_runtime_keeps_integrity_checks`](../tests/test_component_upgrade.py#L309)
- [`tests/test_component_upgrade.py::test_original_installer_layout_upgrades_and_rolls_back_without_rewriting_receipts`](../tests/test_component_upgrade.py#L392)
- [`tests/test_component_upgrade.py::test_installed_layout_still_refuses_missing_or_changed_payload`](../tests/test_component_upgrade.py#L414)
- [`tests/test_component_upgrade.py::test_legacy_guest_locations_allow_mapping_specific_upgrade_reuse_and_rollback`](../tests/test_component_upgrade.py#L462)
- [`tests/test_component_upgrade.py::test_host_only_reuses_guest_and_retains_complete_pair_and_upgrader`](../tests/test_component_upgrade.py#L542)
- [`tests/test_component_upgrade.py::test_complete_target_pair_and_guest_only_interface_share_retained_inputs`](../tests/test_component_upgrade.py#L584)
- [`tests/test_component_upgrade.py::test_bad_component_targets_leave_active_pair_and_state_unchanged`](../tests/test_component_upgrade.py#L616)
- [`tests/test_component_upgrade.py::test_explicit_incompatible_host_and_guest_change_together_and_roll_back`](../tests/test_component_upgrade.py#L663)
- [`tests/test_component_upgrade.py::test_killed_component_pull_keeps_the_old_pair_and_recovers_on_retry`](../tests/test_component_upgrade.py#L688)
- [`tests/test_component_upgrade.py::test_interrupted_legacy_import_resumes_without_reinitializing`](../tests/test_component_upgrade.py#L722)
- [`tests/test_component_upgrade.py::test_explicit_host_release_uses_the_existing_bootstrap_and_verified_cache`](../tests/test_component_upgrade.py#L747)
- [`tests/test_component_upgrade.py::test_guided_discovery_preview_and_failed_acquisition_reuse_verified_target`](../tests/test_component_upgrade.py#L802)
- [`tests/test_component_upgrade.py::test_guided_preview_pins_discovered_compatible_guest_and_reports_unknown_discovery`](../tests/test_component_upgrade.py#L850)
- [`tests/test_component_upgrade.py::test_guided_unavailable_host_discovery_retains_explicit_bundle_path`](../tests/test_component_upgrade.py#L895)
- [`tests/test_component_upgrade.py::test_guided_activation_failure_reports_selected_pair_and_retained_rollback`](../tests/test_component_upgrade.py#L920)
- [`tests/test_component_upgrade.py::test_terminal_upgrade_can_defer_activation_after_choosing_a_release`](../tests/test_component_upgrade.py#L969)
- [`tests/test_component_upgrade.py::test_guided_invalid_agent_choice_does_not_select_or_interrupt`](../tests/test_component_upgrade.py#L1001)
- [`tests/test_component_upgrade.py::test_guided_installed_upgrade_keeps_other_instance_live_and_recovers_failed_start`](../tests/test_component_upgrade.py#L1017)

<a id="witness-tests-test-linux-host-py"></a>
### [`tests/test_linux_host.py`](../tests/test_linux_host.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`); [focused-pr](../.github/workflows/proxy-rust.yml) (conditional CI; condition `github.event_name == 'push' || (github.event_name == 'pull_request' && github.event.action != 'ready_for_review'); step steps.changes.outputs.rust == 'true'`).

- [`tests/test_linux_host.py::test_retained_systrap_caller_remaps_only_its_private_copy`](../tests/test_linux_host.py#L53)
- [`tests/test_linux_host.py::test_runtime_input_fails_before_host_changes`](../tests/test_linux_host.py#L145)
- [`tests/test_linux_host.py::test_relative_package_directory_selects_its_bundled_payload`](../tests/test_linux_host.py#L167)
- [`tests/test_linux_host.py::test_namespace_failure_keeps_original_result_and_observes_only_its_audit`](../tests/test_linux_host.py#L186)
- [`tests/test_linux_host.py::test_runtime_access_preserves_other_acl_rights_and_honors_named_denial`](../tests/test_linux_host.py#L243)
- [`tests/test_linux_host.py::test_runtime_access_keeps_mapped_uid_read_access_before_after_and_repeat`](../tests/test_linux_host.py#L277)
- [`tests/test_linux_host.py::test_mapping_remap_keeps_modes_links_and_guest_user_ids`](../tests/test_linux_host.py#L313)
- [`tests/test_linux_host.py::test_remap_preserves_unchanged_inode_metadata`](../tests/test_linux_host.py#L359)
- [`tests/test_linux_host.py::test_remap_nested_attributes_and_links_preserve_external_target`](../tests/test_linux_host.py#L384)
- [`tests/test_linux_host.py::test_remap_refuses_live_tree_and_bad_owner_before_changing_files`](../tests/test_linux_host.py#L419)
- [`tests/test_linux_host.py::test_denied_runtime_permission_reports_changes_and_retry_is_idempotent`](../tests/test_linux_host.py#L439)
- [`tests/test_linux_host.py::test_doctor_keeps_selected_system_identity_when_runtime_disappears`](../tests/test_linux_host.py#L499)
- [`tests/test_linux_host.py::test_profile_load_failure_retains_only_its_complete_profile`](../tests/test_linux_host.py#L554)
- [`tests/test_linux_host.py::test_host_prepare_retries_retained_runtime_profile`](../tests/test_linux_host.py#L583)
- [`tests/test_linux_host.py::test_scoped_namespace_entry_with_both_apparmor_restrictions`](../tests/test_linux_host.py#L681)

<a id="witness-tests-test-host-sudo-py"></a>
### [`tests/test_host_sudo.py`](../tests/test_host_sudo.py)

Selection: phase `sudo-disclosure` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`).

- [`tests/test_host_sudo.py::test_command_install_discloses_literal_arguments_and_reuses_matching_link`](../tests/test_host_sudo.py#L41)
- [`tests/test_host_sudo.py::test_host_change_commands_and_helper_effects_precede_consent`](../tests/test_host_sudo.py#L97)
- [`tests/test_host_sudo.py::test_acl_sudo_preview_precedes_authentication_and_prepared_retry_is_a_noop`](../tests/test_host_sudo.py#L169)

<a id="witness-tests-test-public-installer-py-test-guest-cache-is-prepared-during-host-extraction-without-early-activation"></a>
### [`tests/test_public_installer.py::test_guest_cache_is_prepared_during_host_extraction_without_early_activation`](../tests/test_public_installer.py::test_guest_cache_is_prepared_during_host_extraction_without_early_activation)

Selection: phase `sudo-disclosure` (host); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'`); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`).

- [`tests/test_public_installer.py::test_guest_cache_is_prepared_during_host_extraction_without_early_activation`](../tests/test_public_installer.py#L842)

<a id="witness-tests-test-hyperlight-adoption-py"></a>
### [`tests/test_hyperlight_adoption.py`](../tests/test_hyperlight_adoption.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`).

- [`tests/test_hyperlight_adoption.py::test_checked_snapshot_is_consumed_only_for_its_exact_subject`](../tests/test_hyperlight_adoption.py#L21)
- [`tests/test_hyperlight_adoption.py::test_uncertain_unix_request_retains_original_operation_without_retry`](../tests/test_hyperlight_adoption.py#L45)

<a id="witness-tests-test-hyperlight-service-checker-py"></a>
### [`tests/test_hyperlight_service_checker.py`](../tests/test_hyperlight_service_checker.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`).

- [`tests/test_hyperlight_service_checker.py::test_complete_chunked_capture_and_identity_mismatch`](../tests/test_hyperlight_service_checker.py#L45)
- [`tests/test_hyperlight_service_checker.py::test_non_json_constants_in_capture_are_unavailable`](../tests/test_hyperlight_service_checker.py#L58)
- [`tests/test_hyperlight_service_checker.py::test_missing_evidence_is_unavailable`](../tests/test_hyperlight_service_checker.py#L65)
- [`tests/test_hyperlight_service_checker.py::test_mismatched_subject_and_wrong_types_are_unavailable`](../tests/test_hyperlight_service_checker.py#L74)
- [`tests/test_hyperlight_service_checker.py::test_incomplete_capture_is_unavailable`](../tests/test_hyperlight_service_checker.py#L82)
- [`tests/test_hyperlight_service_checker.py::test_provider_denial_and_limit_are_unavailable`](../tests/test_hyperlight_service_checker.py#L89)
- [`tests/test_hyperlight_service_checker.py::test_bundle_keeps_patched_dependency_licenses`](../tests/test_hyperlight_service_checker.py#L99)
- [`tests/test_hyperlight_service_checker.py::test_bundle_pins_both_service_checkers_without_changing_offline_examples`](../tests/test_hyperlight_service_checker.py#L129)
- [`tests/test_hyperlight_service_checker.py::test_shared_author_and_autonomy_cases`](../tests/test_hyperlight_service_checker.py#L181)
- [`tests/test_hyperlight_service_checker.py::test_shared_exact_artifact_cases`](../tests/test_hyperlight_service_checker.py#L195)
- [`tests/test_hyperlight_service_checker.py::test_non_json_constants_in_artifact_subject_are_unavailable`](../tests/test_hyperlight_service_checker.py#L209)
- [`tests/test_hyperlight_service_checker.py::test_driver_preserves_job33_failure_before_decoding_stdout`](../tests/test_hyperlight_service_checker.py#L231)
- [`tests/test_hyperlight_service_checker.py::test_driver_cannot_accept_json_from_a_failed_command`](../tests/test_hyperlight_service_checker.py#L265)
- [`tests/test_hyperlight_service_checker.py::test_driver_accepts_only_the_explicit_retained_grant_denial`](../tests/test_hyperlight_service_checker.py#L300)
- [`tests/test_hyperlight_service_checker.py::test_driver_matches_sibling_job_outcomes_and_cli_status`](../tests/test_hyperlight_service_checker.py#L320)
- [`tests/test_hyperlight_service_checker.py::test_expected_negative_still_rejects_command_and_observation_failures`](../tests/test_hyperlight_service_checker.py#L339)
- [`tests/test_hyperlight_service_checker.py::test_expected_negative_requires_a_retained_json_file`](../tests/test_hyperlight_service_checker.py#L347)
- [`tests/test_hyperlight_service_checker.py::test_host_capture_retains_the_current_policy_and_configuration_identities`](../tests/test_hyperlight_service_checker.py#L372)
- [`tests/test_hyperlight_service_checker.py::test_engine_observer_matches_selected_engine_and_artifact_pins`](../tests/test_hyperlight_service_checker.py#L383)
- [`tests/test_hyperlight_service_checker.py::test_host_capture_rejects_invalid_identity_or_time_binding`](../tests/test_hyperlight_service_checker.py#L404)
- [`tests/test_hyperlight_service_checker.py::test_named_evidence_binds_the_raw_adopted_definition_digest`](../tests/test_hyperlight_service_checker.py#L410)
- [`tests/test_hyperlight_service_checker.py::test_held_controls_keep_entry_triggers_late_release_and_fresh_runs`](../tests/test_hyperlight_service_checker.py#L431)
- [`tests/test_hyperlight_service_checker.py::test_held_controls_reject_an_unreached_or_finished_call`](../tests/test_hyperlight_service_checker.py#L495)
- [`tests/test_hyperlight_service_checker.py::test_remaining_window_skips_completed_phases_and_reports_its_actual_scope`](../tests/test_hyperlight_service_checker.py#L510)

<a id="witness-tests-test-job-authoring-py"></a>
### [`tests/test_job_authoring.py`](../tests/test_job_authoring.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`).

- [`tests/test_job_authoring.py::test_installed_helper_proposes_scoped_authority_without_applying`](../tests/test_job_authoring.py#L61)
- [`tests/test_job_authoring.py::test_installed_check_keeps_its_package_bytes_when_upgrade_selects_new_assets`](../tests/test_job_authoring.py#L106)
- [`tests/test_job_authoring.py::test_missing_installed_bundle_explains_acquisition_and_preserves_instance`](../tests/test_job_authoring.py#L148)
- [`tests/test_job_authoring.py::test_preparation_selects_developed_bundle_without_replacing_installed_bytes`](../tests/test_job_authoring.py#L162)
- [`tests/test_job_authoring.py::test_preparation_refuses_conflicts_instead_of_replacing_adopted_authority`](../tests/test_job_authoring.py#L199)
- [`tests/test_job_authoring.py::test_publication_fields_bind_the_actual_bytes`](../tests/test_job_authoring.py#L217)

<a id="witness-tests-test-blackbox-execution-receipt-py"></a>
### [`tests/test_blackbox_execution_receipt.py`](../tests/test_blackbox_execution_receipt.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'`); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`).

- [`tests/test_blackbox_execution_receipt.py::test_authority_receipts_keep_observations_and_refuse_incomplete_execution`](../tests/test_blackbox_execution_receipt.py#L21)
- [`tests/test_blackbox_execution_receipt.py::test_authority_selection_and_successful_process_exit_are_not_executed_coverage`](../tests/test_blackbox_execution_receipt.py#L59)
- [`tests/test_blackbox_execution_receipt.py::test_native_selector_observes_real_libtest_and_refuses_incomplete_results`](../tests/test_blackbox_execution_receipt.py#L74)
- [`tests/test_blackbox_execution_receipt.py::test_native_phases_resolve_current_catalogue_and_keep_the_prepared_job_required`](../tests/test_blackbox_execution_receipt.py#L136)
- [`tests/test_blackbox_execution_receipt.py::test_two_engine_receipt_requires_both_engines_and_owned_cleanup`](../tests/test_blackbox_execution_receipt.py#L145)
- [`tests/test_blackbox_execution_receipt.py::test_focused_shell_caller_cannot_pass_from_collection_only`](../tests/test_blackbox_execution_receipt.py#L156)
- [`tests/test_blackbox_execution_receipt.py::test_real_pytest_retains_parameter_cases_and_rejects_partial_execution`](../tests/test_blackbox_execution_receipt.py#L169)
- [`tests/test_blackbox_execution_receipt.py::test_named_platform_exclusion_does_not_excuse_other_skips`](../tests/test_blackbox_execution_receipt.py#L205)
- [`tests/test_blackbox_execution_receipt.py::test_procedure_requires_every_named_checkpoint_from_this_run`](../tests/test_blackbox_execution_receipt.py#L224)
- [`tests/test_blackbox_execution_receipt.py::test_guest_user_and_root_are_not_interchangeable`](../tests/test_blackbox_execution_receipt.py#L249)
- [`tests/test_blackbox_execution_receipt.py::test_explicit_optional_selection_makes_its_skipped_case_required`](../tests/test_blackbox_execution_receipt.py#L255)

<a id="witness-tests-test-blackbox-catalogue-py"></a>
### [`tests/test_blackbox_catalogue.py`](../tests/test_blackbox_catalogue.py)

Selection: [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'`); [test-addons](../.github/workflows/ci.yml) (conditional CI; condition `${{ !cancelled() && (needs.guest-inputs.result == 'success' || needs.guest-inputs.result == 'skipped') }}; step github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'`).

- [`tests/test_blackbox_catalogue.py::test_inline_rust_modules_keep_distinct_executable_identities`](../tests/test_blackbox_catalogue.py#L21)
- [`tests/test_blackbox_catalogue.py::test_catalogue_rejects_structural_drift`](../tests/test_blackbox_catalogue.py#L90)
- [`tests/test_blackbox_catalogue.py::test_current_catalogue_resolves_all_controls_and_external_families`](../tests/test_blackbox_catalogue.py#L126)
- [`tests/test_blackbox_catalogue.py::test_cargo_commands_use_the_witness_manifest_and_proxy_default`](../tests/test_blackbox_catalogue.py#L133)
- [`tests/test_blackbox_catalogue.py::test_host_protocol_selection_includes_nested_configured_checks_once`](../tests/test_blackbox_catalogue.py#L145)
- [`tests/test_blackbox_catalogue.py::test_procedure_workflow_selection_preserves_repository_and_module_paths`](../tests/test_blackbox_catalogue.py#L160)
- [`tests/test_blackbox_catalogue.py::test_workflow_selection_agrees_with_real_pytest_exclusions`](../tests/test_blackbox_catalogue.py#L176)
- [`tests/test_blackbox_catalogue.py::test_unresolved_shared_phase_operand_cannot_pass_generation`](../tests/test_blackbox_catalogue.py#L203)
- [`tests/test_blackbox_catalogue.py::test_cargo_identity_requires_its_real_module_and_keeps_ignore_selection`](../tests/test_blackbox_catalogue.py#L215)
- [`tests/test_blackbox_catalogue.py::test_cargo_library_root_uses_its_real_module`](../tests/test_blackbox_catalogue.py#L246)
- [`tests/test_blackbox_catalogue.py::test_native_host_selection_retains_partial_observations`](../tests/test_blackbox_catalogue.py#L269)
- [`tests/test_blackbox_catalogue.py::test_native_host_missing_input_is_incomplete_without_dispatch`](../tests/test_blackbox_catalogue.py#L331)
- [`tests/test_blackbox_catalogue.py::test_native_case_requires_one_executed_test_instead_of_target_pass_text`](../tests/test_blackbox_catalogue.py#L348)

<a id="witness-tests-proxy-contracts-test-shared-authority-assurance-py"></a>
### [`tests/proxy_contracts/test_shared_authority_assurance.py`](../tests/proxy_contracts/test_shared_authority_assurance.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_shared_authority_assurance.py::test_deterministic_controller_observes_native_decisions_and_origin_effects`](../tests/proxy_contracts/test_shared_authority_assurance.py#L28)

<a id="witness-proxy-tests-credential-http-codex-rs"></a>
### [`proxy/tests/credential_http/codex.rs`](../proxy/tests/credential_http/codex.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::imported_login_two_rotations_reload_restart_and_redaction -- --exact`](../proxy/tests/credential_http/codex.rs#L275)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::credentials_do_not_inherit_other_origins_routes_clients_or_beneficiaries -- --exact`](../proxy/tests/credential_http/codex.rs#L389)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::host_import_requires_a_subscription_pair_and_unique_beneficiary -- --exact`](../proxy/tests/credential_http/codex.rs#L550)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::refresh_observation_uses_the_final_route_json_and_only_imported_authentication -- --exact`](../proxy/tests/credential_http/codex.rs#L592)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::refresh_trailers_cannot_supply_unobserved_authentication -- --exact`](../proxy/tests/credential_http/codex.rs#L697)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::concurrent_issuance_retains_each_token_under_one_import -- --exact`](../proxy/tests/credential_http/codex.rs#L761)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::revocation_or_reimport_during_exchange_cannot_restore_old_authority -- --exact`](../proxy/tests/credential_http/codex.rs#L793)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::run_scoped_import_follows_the_verified_backend_lifetime -- --exact`](../proxy/tests/credential_http/codex.rs#L827) — `#[cfg(target_os = "linux")]`
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::guest_markers_expiry_identity_and_stopped_run_do_not_create_authority -- --exact`](../proxy/tests/credential_http/codex.rs#L905)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::imported_credentials_do_not_bypass_upstream_tls_verification -- --exact`](../proxy/tests/credential_http/codex.rs#L985)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http codex::malformed_duplicate_and_redirected_issuance_cannot_authorize_replacements -- --exact`](../proxy/tests/credential_http/codex.rs#L1007)

<a id="witness-proxy-tests-native-coord-reviews-rs"></a>
### [`proxy/tests/native_coord/reviews.rs`](../proxy/tests/native_coord/reviews.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord reviews::code_and_report_checks_challenges_corrections_and_independent_dispositions -- --exact --ignored`](../proxy/tests/native_coord/reviews.rs#L100) — `#[ignore = "requires pinned NATS; real assigned checks, challenges and attributed dispositions"]`

<a id="witness-proxy-tests-native-coord-work-rs"></a>
### [`proxy/tests/native_coord/work.rs`](../proxy/tests/native_coord/work.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord work::self_stop_api_refuses_scope_bypass_and_retains_original_request -- --exact --ignored`](../proxy/tests/native_coord/work.rs#L39) — `#[cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; controlled run authority, not an installed sandbox witness"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord work::commissioning_observation_and_followup_use_separate_selected_permissions -- --exact --ignored`](../proxy/tests/native_coord/work.rs#L196) — `#[ignore = "requires pinned NATS"]`
Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord work::native_work_claims_replay_identity_revocation_and_crash_recovery -- --exact --ignored`](../proxy/tests/native_coord/work.rs#L293) — `#[ignore = "requires pinned NATS; set SAFEYOLO_WORK_RETAIN_SECONDS=1800 for real duration proof"]`

<a id="witness-proxy-tests-native-coord-outputs-rs"></a>
### [`proxy/tests/native_coord/outputs.rs`](../proxy/tests/native_coord/outputs.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord outputs::retained_external_outputs_recover_once_or_reject_stale_publication -- --exact --ignored`](../proxy/tests/native_coord/outputs.rs#L23) — `#[ignore = "requires pinned NATS; isolated real publication, cancellation and restart boundaries"]`

<a id="witness-proxy-tests-native-coord-attestations-rs"></a>
### [`proxy/tests/native_coord/attestations.rs`](../proxy/tests/native_coord/attestations.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord attestations::native_attestations_exact_candidate_authorship_replay_and_recovery -- --exact --ignored`](../proxy/tests/native_coord/attestations.rs#L43) — `#[ignore = "requires pinned NATS; exact-target identity, authenticated evidence and interruption controls"]`

<a id="witness-proxy-tests-native-coord-federation-rs"></a>
### [`proxy/tests/native_coord/federation.rs`](../proxy/tests/native_coord/federation.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::two_safeyolos_share_only_home_authority_across_partition_restart_and_revocation -- --exact --ignored`](../proxy/tests/native_coord/federation.rs#L267) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; two real owned native SafeYolo instances"]`
Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::loopback_preserves_authority_retained_notifications_and_recovery -- --exact --ignored`](../proxy/tests/native_coord/federation.rs#L273) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; two owned instances over explicit loopback"]`

<a id="witness-proxy-src-coord-rooms-federation-tailscale-rs-coord-rooms-federation-tailscale-tests"></a>
### [`proxy/src/coord_rooms/federation/tailscale.rs`](../proxy/src/coord_rooms/federation/tailscale.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::federation::tailscale::tests::a_private_address_or_subnet_route_does_not_identify_a_node -- --exact`](../proxy/src/coord_rooms/federation/tailscale.rs#L162)

<a id="witness-proxy-src-external-ingress-tests-rs"></a>
### [`proxy/src/external_ingress/tests.rs`](../proxy/src/external_ingress/tests.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib external_ingress::tests::curl_http_connect_reuses_policy_credentials_budgets_and_scoped_store -- --exact`](../proxy/src/external_ingress/tests.rs#L247)
- [`cargo test --manifest-path proxy/Cargo.toml --lib external_ingress::tests::occupied_bind_missing_replaced_target_remove_and_restart_preserve_owners -- --exact`](../proxy/src/external_ingress/tests.rs#L438)
- [`cargo test --manifest-path proxy/Cargo.toml --lib external_ingress::tests::zero_body_retention_stays_metadata_only_for_external_flows -- --exact`](../proxy/src/external_ingress/tests.rs#L548)
- [`cargo test --manifest-path proxy/Cargo.toml --lib external_ingress::tests::ingress_endpoint_shield_stops_partition_hops_without_blocking_remote_ports -- --exact`](../proxy/src/external_ingress/tests.rs#L574)
- [`cargo test --manifest-path proxy/Cargo.toml --lib external_ingress::tests::bindings_reject_ambiguous_owners_and_duplicate_names_before_publication -- --exact`](../proxy/src/external_ingress/tests.rs#L642)
- [`cargo test --manifest-path proxy/Cargo.toml --lib external_ingress::tests::existing_uds_acceptor_is_required_and_replacement_cannot_claim_the_binding -- --exact`](../proxy/src/external_ingress/tests.rs#L669)

<a id="witness-proxy-src-http-policy-checks-execution-tests-rs"></a>
### [`proxy/src/http/policy_checks/execution_tests.rs`](../proxy/src/http/policy_checks/execution_tests.rs)

Selection: manual native phase `named-checks` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::named_invocation_enforces_adoption_input_and_pending_authority -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L127)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_live_service_preserves_typed_results_cache_freshness_and_offline_preview -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L253)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_live_service_distinguishes_negative_malformed_refused_and_oversized_results -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L334)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_live_service_missing_grants_and_cycles_fail_without_contact -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L411)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_live_service_limits_pending_cancels_transport_and_discards_late_evidence -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L462)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_policy_change_during_service_wait_cannot_restore_old_admission -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L545)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_job_fixture_preserves_selected_optional_linux_settings -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L774)
Selection: manual native phase `named-checks` (named execution receipt; ignored cases remain incomplete); ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_installed_job_check_binds_observed_execution_and_reuses_only_valid_evidence -- --exact --ignored`](../proxy/src/http/policy_checks/execution_tests.rs#L847) — `#[ignore = "requires SAFEYOLO_POLICY_CHECK_PREPARED pointing to a prepared native instance"]`
Selection: manual native phase `named-checks` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_shutdown_joins_cancelled_check_transport_and_removes_its_listener -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L1033)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_service_check_keeps_scoped_credentials_and_saved_authority -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L1081)
- [`cargo test --manifest-path proxy/Cargo.toml --lib http::policy_checks::execution_tests::native_check_input_and_network_dependency_denials_make_no_target_contact -- --exact`](../proxy/src/http/policy_checks/execution_tests.rs#L1161)

<a id="witness-proxy-src-jobs-hyperlight-tests-rs"></a>
### [`proxy/src/jobs/hyperlight/tests.rs`](../proxy/src/jobs/hyperlight/tests.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::pinned_helper_captures_complete_streams_and_removes_runtime -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L63)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::operator_selected_artifact_links_still_verify_the_copied_bytes -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L84)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::substituted_artifacts_and_manifest_architecture_fail_before_spawn -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L105)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::missing_artifacts_identify_role_path_and_os_error_before_discovery -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L134)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::missing_or_failed_vm_report_cannot_make_a_successful_helper_exit_pass -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L192)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::deadline_kills_and_reaps_a_spinning_helper_before_returning -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L205)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::cancellation_stops_a_blocked_helper_and_preserves_no_runtime -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L235)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::hyperlight::tests::unsupported_authority_is_refused_and_relative_artifacts_follow_adopted_spec -- --exact`](../proxy/src/jobs/hyperlight/tests.rs#L261)

<a id="witness-tests-proxy-contracts-test-agent-api-config-py"></a>
### [`tests/proxy_contracts/test_agent_api_config.py`](../tests/proxy_contracts/test_agent_api_config.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_api_config.py::test_agent_api_config_fields_and_hash_are_shared`](../tests/proxy_contracts/test_agent_api_config.py#L64)
- [`tests/proxy_contracts/test_agent_api_config.py::test_agent_api_config_reuses_local_auth_and_method_checks`](../tests/proxy_contracts/test_agent_api_config.py#L78)
- [`tests/proxy_contracts/test_agent_api_config.py::test_agent_api_config_reload_changes_fields_and_hash_then_retains_last_valid`](../tests/proxy_contracts/test_agent_api_config.py#L83)
- [`tests/proxy_contracts/test_agent_api_config.py::test_agent_api_config_hash_includes_unprojected_iam_permissions`](../tests/proxy_contracts/test_agent_api_config.py#L98)
- [`tests/proxy_contracts/test_agent_api_config.py::test_agent_api_config_only_serializes_projected_temporal_values`](../tests/proxy_contracts/test_agent_api_config.py#L123)

<a id="witness-tests-proxy-contracts-test-agent-api-status-py"></a>
### [`tests/proxy_contracts/test_agent_api_status.py`](../tests/proxy_contracts/test_agent_api_status.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_agent_api_status.py::test_agent_api_status_counts_real_requests_and_preserves_state_on_reload`](../tests/proxy_contracts/test_agent_api_status.py#L33)

<a id="witness-tests-proxy-contracts-test-operator-modes-and-listeners-py"></a>
### [`tests/proxy_contracts/test_operator_modes_and_listeners.py`](../tests/proxy_contracts/test_operator_modes_and_listeners.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_operator_modes_and_listeners.py::test_retained_admin_client_mode_change_reaches_live_enforcement`](../tests/proxy_contracts/test_operator_modes_and_listeners.py#L36)
- [`tests/proxy_contracts/test_operator_modes_and_listeners.py::test_retained_ignore_host_consumer_publishes_and_clears_native_entries`](../tests/proxy_contracts/test_operator_modes_and_listeners.py#L91)

<a id="witness-tests-proxy-contracts-test-operator-task-api-py"></a>
### [`tests/proxy_contracts/test_operator_task_api.py`](../tests/proxy_contracts/test_operator_task_api.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_operator_task_api.py::test_operator_client_registers_activates_and_clears_task_policy`](../tests/proxy_contracts/test_operator_task_api.py#L25)

<a id="witness-tests-proxy-contracts-test-github-git-py"></a>
### [`tests/proxy_contracts/test_github_git.py`](../tests/proxy_contracts/test_github_git.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_github_git.py::test_basic_git_password_is_substituted_by_the_native_gateway`](../tests/proxy_contracts/test_github_git.py#L49)
- [`tests/proxy_contracts/test_github_git.py::test_real_git_fetch_push_approval_retry_and_provider_failure`](../tests/proxy_contracts/test_github_git.py#L196)

<a id="witness-tests-proxy-contracts-test-native-dispatch-py"></a>
### [`tests/proxy_contracts/test_native_dispatch.py`](../tests/proxy_contracts/test_native_dispatch.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_dispatch.py::test_native_request_authority_duplicate_and_durable_restart`](../tests/proxy_contracts/test_native_dispatch.py#L47)
- [`tests/proxy_contracts/test_native_dispatch.py::test_withheld_ack_reconciles_same_envelope_without_second_publication`](../tests/proxy_contracts/test_native_dispatch.py#L87)
- [`tests/proxy_contracts/test_native_dispatch.py::test_absent_unknown_publication_is_never_automatically_replayed`](../tests/proxy_contracts/test_native_dispatch.py#L125)
- [`tests/proxy_contracts/test_native_dispatch.py::test_invalid_request_and_corrupt_ledger_do_not_publish`](../tests/proxy_contracts/test_native_dispatch.py#L139)
- [`tests/proxy_contracts/test_native_dispatch.py::test_installed_generation_and_site_consumers`](../tests/proxy_contracts/test_native_dispatch.py#L154)
- [`tests/proxy_contracts/test_native_dispatch.py::test_installed_inert_generation_and_site_consumers`](../tests/proxy_contracts/test_native_dispatch.py#L175)

<a id="witness-tests-proxy-contracts-test-native-mattermost-py"></a>
### [`tests/proxy_contracts/test_native_mattermost.py`](../tests/proxy_contracts/test_native_mattermost.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_native_mattermost.py::test_native_foreground_recovers_verification_and_poll_failures`](../tests/proxy_contracts/test_native_mattermost.py#L389)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_outage_diagnostics_are_strict_and_stale_authority_cannot_accept`](../tests/proxy_contracts/test_native_mattermost.py#L446)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_signal_interrupts_backoff_and_releases_listener_and_lease`](../tests/proxy_contracts/test_native_mattermost.py#L474)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_invalid_identity_or_transport_configuration_is_terminal`](../tests/proxy_contracts/test_native_mattermost.py#L496)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_authorization_outage_between_backlog_appends_retains_unsent_replies`](../tests/proxy_contracts/test_native_mattermost.py#L517)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_mapping_failure_or_reconciliation_keeps_safe_mapping_and_callback`](../tests/proxy_contracts/test_native_mattermost.py#L550)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_paging_deletion_retains_cursor_and_recovers_after_restart`](../tests/proxy_contracts/test_native_mattermost.py#L592)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_long_outage_pages_equal_timestamps_partial_failure_and_restart`](../tests/proxy_contracts/test_native_mattermost.py#L637)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_flat_conversation_without_projection_and_same_channel_reply`](../tests/proxy_contracts/test_native_mattermost.py#L675)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_flat_invalid_shapes_identity_and_timestamps_are_refused`](../tests/proxy_contracts/test_native_mattermost.py#L710)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_exchange_authority_restart_and_backend_isolation`](../tests/proxy_contracts/test_native_mattermost.py#L739)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_listener_bind_failure_keeps_projection_and_replies_available`](../tests/proxy_contracts/test_native_mattermost.py#L788)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_uncertain_callback_stays_pending_while_routine_exchange_continues`](../tests/proxy_contracts/test_native_mattermost.py#L804)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_callback_operator_verification_timeout_does_not_publish`](../tests/proxy_contracts/test_native_mattermost.py#L837)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_semantic_callback_authority_replay_and_restart`](../tests/proxy_contracts/test_native_mattermost.py#L863)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_uncertain_projection_reconciles_or_refuses_retry`](../tests/proxy_contracts/test_native_mattermost.py#L924)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_interrupted_projection_page_reconciles_without_reposting`](../tests/proxy_contracts/test_native_mattermost.py#L939)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_committed_wal_survives_killed_adapter_without_reposting`](../tests/proxy_contracts/test_native_mattermost.py#L962)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_uncertain_coord_reply_never_replays_after_restart`](../tests/proxy_contracts/test_native_mattermost.py#L986)
- [`tests/proxy_contracts/test_native_mattermost.py::test_native_callback_wire_limits_and_untrusted_schema`](../tests/proxy_contracts/test_native_mattermost.py#L1021)

<a id="witness-tests-proxy-contracts-test-operational-events-py"></a>
### [`tests/proxy_contracts/test_operational_events.py`](../tests/proxy_contracts/test_operational_events.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_operational_events.py::test_selected_attention_loss_restart_and_current_observation`](../tests/proxy_contracts/test_operational_events.py#L122)
- [`tests/proxy_contracts/test_operational_events.py::test_audit_directory_sync_failure_stays_pending_then_retries_same_event`](../tests/proxy_contracts/test_operational_events.py#L207)
- [`tests/proxy_contracts/test_operational_events.py::test_signal_disclosure_uses_canonical_state_without_room_history`](../tests/proxy_contracts/test_operational_events.py#L255)
- [`tests/proxy_contracts/test_operational_events.py::test_guest_metadata_cannot_spoof_host_or_a_different_generation`](../tests/proxy_contracts/test_operational_events.py#L301)
- [`tests/proxy_contracts/test_operational_events.py::test_guest_source_survives_abrupt_child_and_owner_exit`](../tests/proxy_contracts/test_operational_events.py#L349)

<a id="witness-tests-proxy-contracts-test-outbound-effects-py"></a>
### [`tests/proxy_contracts/test_outbound_effects.py`](../tests/proxy_contracts/test_outbound_effects.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_outbound_effects.py::test_completed_connect_trace_accepts_padded_pid`](../tests/proxy_contracts/test_outbound_effects.py#L83)
- [`tests/proxy_contracts/test_outbound_effects.py::test_reserved_and_denied_requests_make_no_ip_connect`](../tests/proxy_contracts/test_outbound_effects.py#L91)
- [`tests/proxy_contracts/test_outbound_effects.py::test_reserved_and_denied_requests_make_no_dns_query`](../tests/proxy_contracts/test_outbound_effects.py#L174)

<a id="witness-tests-proxy-contracts-test-single-event-log-py"></a>
### [`tests/proxy_contracts/test_single_event_log.py`](../tests/proxy_contracts/test_single_event_log.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_single_event_log.py::test_selected_route_reaches_operator_logs_and_scoped_explain`](../tests/proxy_contracts/test_single_event_log.py#L33)
- [`tests/proxy_contracts/test_single_event_log.py::test_failed_direct_attempt_is_not_delivery_and_missing_evidence_has_no_route`](../tests/proxy_contracts/test_single_event_log.py#L83)
- [`tests/proxy_contracts/test_single_event_log.py::test_retired_setting_does_not_touch_historical_files_during_reload`](../tests/proxy_contracts/test_single_event_log.py#L100)

<a id="witness-tests-proxy-contracts-test-public-arm-install-workflow-py"></a>
### [`tests/proxy_contracts/test_public_arm_install_workflow.py`](../tests/proxy_contracts/test_public_arm_install_workflow.py)

Selection: phase `proxy` (host); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_public_mode_selects_one_arm_job_and_keeps_old_mode`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L40)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_staged_onboarding_restores_checkout_imports`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L171)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_current_observer_requires_an_uncached_store_and_preserves_existing_inputs`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L210)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_current_download_and_installer_refusal_keep_source_binding_and_reached_exits`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L237)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_workflow_callers_remove_tokens_and_preserve_observer_exit_and_private_logs`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L267)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_report_step_preserves_missing_result_as_unobserved`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L316)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_complete_metadata_comparison_detects_material_changes`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L368)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_observer_refuses_installed_tree_that_does_not_reach_acquired_assets`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L391)
- [`tests/proxy_contracts/test_public_arm_install_workflow.py::test_observer_command_preserves_actual_binding_and_fails_on_wrong_metadata`](../tests/proxy_contracts/test_public_arm_install_workflow.py#L403)

<a id="witness-proxy-tests-native-coord-catch-up-rs"></a>
### [`proxy/tests/native_coord/catch_up.rs`](../proxy/tests/native_coord/catch_up.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord catch_up::native_catch_up_keeps_current_authority_and_inspectable_bounded_history -- --exact --ignored`](../proxy/tests/native_coord/catch_up.rs#L3) — `#[ignore = "requires pinned NATS; exercises derived catch-up CLI with real stores"]`

<a id="witness-proxy-tests-native-coord-continuation-rs"></a>
### [`proxy/tests/native_coord/continuation.rs`](../proxy/tests/native_coord/continuation.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord continuation::continuation_recovers_once_and_retains_delivery_across_restart -- --exact --ignored`](../proxy/tests/native_coord/continuation.rs#L14) — `#[ignore = "requires pinned NATS; real commit interruption, discarded response and restart delivery"]`

<a id="witness-proxy-tests-native-coord-diagnostics-rs"></a>
### [`proxy/tests/native_coord/diagnostics.rs`](../proxy/tests/native_coord/diagnostics.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::failed_attention_resolution_preserves_each_source_position_and_its_failure -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L123)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::tool_failure_preserves_original_and_bounded_reader_states -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L174)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::diagnostic_limits_and_failures_never_replace_or_repeat_the_original -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L218)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::error_body_states_and_correlation_remain_explicit -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L271)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::reduced_failure_details_preserve_body_retry_information -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L327)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::diagnostic_limits_describe_truncation_after_redaction_and_sanitization -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L353)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::sensitive_and_unbounded_failures_do_not_escape_to_mcp -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L408)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::real_agent_api_refusal_uses_its_existing_scoped_audit_reader -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L454)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord diagnostics::generic_transport_and_explicit_diagnostic_reads_do_not_collect -- --exact`](../proxy/tests/native_coord/diagnostics.rs#L508)

<a id="witness-proxy-tests-native-coord-factory-rs"></a>
### [`proxy/tests/native_coord/factory.rs`](../proxy/tests/native_coord/factory.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord factory::factory_selection_enforces_native_obligations_for_direct_callers -- --exact --ignored`](../proxy/tests/native_coord/factory.rs#L69) — `#[ignore = "requires pinned NATS; real approved Factory and authenticated public API"]`
Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord factory::interactive_coding_client_and_factory_supervisor_share_native_work -- --exact --ignored`](../proxy/tests/native_coord/factory.rs#L144) — `#[ignore = "requires pinned NATS and separate private SAFEYOLO_COORD_INTERACTIVE_HOME / SAFEYOLO_COORD_MODEL_HOME native Codex homes"]`

<a id="witness-proxy-tests-native-coord-federation-guided-rs"></a>
### [`proxy/tests/native_coord/federation/guided.rs`](../proxy/tests/native_coord/federation/guided.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::guided::guided_connection_material_and_addressed_handoffs_use_existing_checks -- --exact --ignored`](../proxy/tests/native_coord/federation/guided.rs#L57) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; real guided CLI across independently initialized roots"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::guided::guided_support_and_approval_selection_keep_distinct_authority -- --exact --ignored`](../proxy/tests/native_coord/federation/guided.rs#L204) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; real guided policy previews and application"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::guided::guided_stale_preview_is_refused_and_factory_binding_is_not_inherited -- --exact --ignored`](../proxy/tests/native_coord/federation/guided.rs#L282) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; concurrent real guided edit and exact factory binding"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::guided::guided_verification_recovers_original_receipts_without_repeating_operations -- --exact --ignored`](../proxy/tests/native_coord/federation/guided.rs#L415) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; real human verification and original-receipt recovery"]`

<a id="witness-proxy-tests-native-coord-federation-modes-rs"></a>
### [`proxy/tests/native_coord/federation/modes.rs`](../proxy/tests/native_coord/federation/modes.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::modes::renewal_and_explicit_rotation_preserve_retained_state_and_report_activation -- --exact --ignored`](../proxy/tests/native_coord/federation/modes.rs#L44) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; actual native certificate lifecycle"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::modes::same_path_peer_rotation_reports_restart_until_broker_loads_new_credentials -- --exact --ignored`](../proxy/tests/native_coord/federation/modes.rs#L296) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; actual same-path credential rotation and activation"]`

<a id="witness-proxy-tests-native-coord-federation-operator-rs"></a>
### [`proxy/tests/native_coord/federation/operator.rs`](../proxy/tests/native_coord/federation/operator.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::operator::remote_saved_deciding_authority_preserves_the_canonical_pending_record -- --exact --ignored`](../proxy/tests/native_coord/federation/operator.rs#L44) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; two independently initialized native owners"]`
Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::operator::qualified_operator_direction_and_approval_keep_b_ownership_and_independent_checks -- --exact --ignored`](../proxy/tests/native_coord/federation/operator.rs#L183) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; two independently initialized native owners"]`

<a id="witness-proxy-tests-native-coord-federation-reliability-rs"></a>
### [`proxy/tests/native_coord/federation/reliability.rs`](../proxy/tests/native_coord/federation/reliability.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::reliability::failed_peer_publication_does_not_hold_local_or_other_peer_hints -- --exact --ignored`](../proxy/tests/native_coord/federation/reliability.rs#L316) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; three independent instance roots and brokers"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::reliability::repeated_calls_reuse_connections_and_waits_release_consumers -- --exact --ignored`](../proxy/tests/native_coord/federation/reliability.rs#L412) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; three independent instance roots and brokers"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::reliability::accepted_publisher_exits_before_projection -- --exact --ignored`](../proxy/tests/native_coord/federation/reliability.rs#L586) — `#![cfg(target_os = "linux")]`; `#[ignore = "child helper for actual publisher exit immediately after JetStream acknowledgement"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::reliability::owner_repairs_after_publisher_exit_without_remote_polling -- --exact --ignored`](../proxy/tests/native_coord/federation/reliability.rs#L616) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; three independent instance roots and brokers"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::reliability::selected_sources_keep_independent_health_and_stop_disclosing_after_revoke -- --exact --ignored`](../proxy/tests/native_coord/federation/reliability.rs#L686) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; selected observer health and current disclosure grants"]`

<a id="witness-proxy-tests-native-coord-federation-support-rs"></a>
### [`proxy/tests/native_coord/federation/support.rs`](../proxy/tests/native_coord/federation/support.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::support::authenticated_mutation_misrouted_to_another_trusted_instance_has_no_effect -- --exact --ignored`](../proxy/tests/native_coord/federation/support.rs#L197) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; deliberately route a mutation to another trusted owner"]`
Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::support::core_support_survives_notification_outage_and_local_owner_can_restore_core -- --exact --ignored`](../proxy/tests/native_coord/federation/support.rs#L263) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; independently fail JetStream and Core"]`
Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only); step matrix.os == 'ubuntu-latest'`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::support::remote_support_uses_owner_grants_receipts_and_independent_attention_sources -- --exact --ignored`](../proxy/tests/native_coord/federation/support.rs#L433) — `#![cfg(target_os = "linux")]`; `#[ignore = "requires pinned NATS; independent roots and controlled ingress runs"]`

<a id="witness-proxy-tests-native-coord-federation-support-audit-rs"></a>
### [`proxy/tests/native_coord/federation/support_audit.rs`](../proxy/tests/native_coord/federation/support_audit.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::support::audit::direct_nats_refusals_record_destination_trust_principal_operation_and_phase -- --exact --ignored`](../proxy/tests/native_coord/federation/support_audit.rs#L43) — `#[ignore = "requires pinned NATS; direct authenticated destination refusal audit"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::support::audit::remote_final_audit_recovers_after_queue_failure_and_owner_termination -- --exact --ignored`](../proxy/tests/native_coord/federation/support_audit.rs#L228) — `#[ignore = "requires pinned NATS; queue exhaustion and real owner termination"]`

<a id="witness-proxy-tests-native-coord-federation-support-authority-rs"></a>
### [`proxy/tests/native_coord/federation/support_authority.rs`](../proxy/tests/native_coord/federation/support_authority.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord federation::support::authority::four_owner_report_discovers_typed_upstream_downstream_and_destination_owned_authority -- --exact --ignored`](../proxy/tests/native_coord/federation/support_authority.rs#L202) — `#[ignore = "requires pinned NATS; four independently initialized roots, identities, TLS roots and brokers"]`

<a id="witness-proxy-tests-native-coord-github-rs"></a>
### [`proxy/tests/native_coord/github.rs`](../proxy/tests/native_coord/github.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord github::native_github_read_uses_caller_service_and_preserves_local_work -- --exact --ignored`](../proxy/tests/native_coord/github.rs#L90) — `#[ignore = "requires pinned NATS; controlled external TLS fixture with real service controls"]`

<a id="witness-proxy-tests-native-coord-inventory-rs"></a>
### [`proxy/tests/native_coord/inventory.rs`](../proxy/tests/native_coord/inventory.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord inventory::native_inventory_uses_current_grants_and_fixture_provider_evidence_across_restart -- --exact --ignored`](../proxy/tests/native_coord/inventory.rs#L67) — `#[ignore = "requires pinned NATS; owns disposable native services"]`

<a id="witness-proxy-tests-native-coord-room-status-rs"></a>
### [`proxy/tests/native_coord/room_status.rs`](../proxy/tests/native_coord/room_status.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord room_status::native_room_status_current_authority_restart_and_cli -- --exact --ignored`](../proxy/tests/native_coord/room_status.rs#L37) — `#[ignore = "requires pinned NATS; exercises canonical combined room status"]`

<a id="witness-proxy-tests-native-coord-signals-rs"></a>
### [`proxy/tests/native_coord/signals.rs`](../proxy/tests/native_coord/signals.rs)

Selection: ignored by default; [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord signals::native_watch_clears_signal_attached_between_host_checks_during_audit_outage -- --exact --ignored`](../proxy/tests/native_coord/signals.rs#L229) — `#[ignore = "requires pinned NATS for setup; attachment runs with audit and broker unavailable"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord signals::native_watch_clears_approval_attached_between_host_checks_during_audit_outage -- --exact --ignored`](../proxy/tests/native_coord/signals.rs#L235) — `#[ignore = "requires pinned NATS for setup; attachment runs with audit and broker unavailable"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord signals::native_watch_recovers_final_signal_and_approval_changes_without_a_later_event -- --exact --ignored`](../proxy/tests/native_coord/signals.rs#L419) — `#[ignore = "requires pinned NATS for canonical room setup; operator recovery runs with it stopped"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord signals::native_watch_pty_recovers_complete_pending_state_while_a_choice_is_unfinished -- --exact --ignored`](../proxy/tests/native_coord/signals.rs#L805) — `#[ignore = "requires pinned NATS for setup; live PTY recovery runs with it stopped"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord signals::native_signals_author_page_watch_replay_and_restart -- --exact --ignored`](../proxy/tests/native_coord/signals.rs#L1005) — `#[ignore = "requires pinned NATS; exercises real authenticated signals and native watch"]`

<a id="witness-proxy-tests-native-coord-stage0-rs"></a>
### [`proxy/tests/native_coord/stage0.rs`](../proxy/tests/native_coord/stage0.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord stage0::native_stage0_replay_and_delivery_survive_current_master_and_process_crashes -- --exact --ignored`](../proxy/tests/native_coord/stage0.rs#L85) — `#[ignore = "requires the pinned NATS binary and retained current-master CLI"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord stage0::native_brief_replay_preserves_delivered_revision_metadata_and_authorized_reads -- --exact --ignored`](../proxy/tests/native_coord/stage0.rs#L538) — `#[ignore = "requires the pinned NATS binary; owns isolated native services"]`

<a id="witness-proxy-tests-native-coord-supervision-rs"></a>
### [`proxy/tests/native_coord/supervision.rs`](../proxy/tests/native_coord/supervision.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord supervision::native_action_receipt_recovers_after_lost_response_and_proxy_restart -- --exact --ignored`](../proxy/tests/native_coord/supervision.rs#L129) — `#[ignore = "requires pinned NATS; deliberately discards an authenticated delivery response"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord supervision::native_delivery_is_not_completed_by_narration_and_restart_uses_current_work -- --exact --ignored`](../proxy/tests/native_coord/supervision.rs#L184) — `#[ignore = "requires pinned NATS; native API and deterministic model event seam"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord supervision::real_model_wakes_for_report_check_challenge_disposition_and_acceptance -- --exact --ignored`](../proxy/tests/native_coord/supervision.rs#L332) — `#[ignore = "requires pinned NATS and SAFEYOLO_COORD_MODEL_HOME with private native Codex login and current Coord MCP registration"]`
- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord supervision::real_model_continues_code_report_and_changed_input_check -- --exact --ignored`](../proxy/tests/native_coord/supervision.rs#L433) — `#[ignore = "requires pinned NATS and a private SAFEYOLO_COORD_MODEL_HOME; actual continuation delivery and settlement"]`

<a id="witness-proxy-tests-native-coord-upgrade-rs"></a>
### [`proxy/tests/native_coord/upgrade.rs`](../proxy/tests/native_coord/upgrade.rs)

Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test native_coord upgrade::previous_generated_store_upgrades_with_and_without_federation -- --exact --ignored`](../proxy/tests/native_coord/upgrade.rs#L63) — `#[ignore = "requires pinned NATS and SAFEYOLO_COORD_BASE_BINARY from e138ebefba90919311e9e60cc272b140e78b5d61"]`

<a id="witness-proxy-tests-credential-http-boundary-rs"></a>
### [`proxy/tests/credential_http/boundary.rs`](../proxy/tests/credential_http/boundary.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http boundary::repeated_h1_fields_keep_credential_decisions_and_forwarding -- --exact`](../proxy/tests/credential_http/boundary.rs#L55)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http boundary::repeated_h2_fields_and_head_refusals_stay_at_proxy -- --exact`](../proxy/tests/credential_http/boundary.rs#L268)

<a id="witness-proxy-tests-credential-http-ghcr-rs"></a>
### [`proxy/tests/credential_http/ghcr.rs`](../proxy/tests/credential_http/ghcr.rs)

Selection: [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::repeated_public_pull_reuse_concurrency_replacement_and_restart -- --exact`](../proxy/tests/credential_http/ghcr.rs#L287)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::learned_tokens_keep_repeated_field_inspection_approvals_and_budgets -- --exact`](../proxy/tests/credential_http/ghcr.rs#L391)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::acquisition_origin_scope_authentication_and_redirects_do_not_register -- --exact`](../proxy/tests/credential_http/ghcr.rs#L593)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::learned_token_still_obeys_credential_and_network_denials_after_reload -- --exact`](../proxy/tests/credential_http/ghcr.rs#L729)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::final_gateway_injection_cannot_turn_authenticated_response_into_anonymous_issuance -- --exact`](../proxy/tests/credential_http/ghcr.rs#L796)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::unverified_upstream_tls_cannot_register_a_token -- --exact`](../proxy/tests/credential_http/ghcr.rs#L876)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::discovery_token_without_repository_scope_cannot_read_a_repository -- --exact`](../proxy/tests/credential_http/ghcr.rs#L899)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::h2_empty_data_is_anonymous_but_authentication_trailers_are_not -- --exact`](../proxy/tests/credential_http/ghcr.rs#L935)
- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::h2_delayed_empty_data_keeps_anonymous_issuance_and_trailer_isolation -- --exact`](../proxy/tests/credential_http/ghcr.rs#L997)
Selection: ignored by default.

- [`cargo test --manifest-path proxy/Cargo.toml --test credential_http ghcr::live_public_manifest_and_small_blob -- --exact --ignored`](../proxy/tests/credential_http/ghcr.rs#L1063) — `#[ignore = "live GHCR access; run explicitly at the clean candidate revision"]`

<a id="witness-proxy-src-jobs-mediated-tests-rs"></a>
### [`proxy/src/jobs/mediated/tests.rs`](../proxy/src/jobs/mediated/tests.rs)

Selection: manual native phase `mediated-services` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::mediated::tests::complete_large_evidence_is_chunked_and_off_scope_calls_are_denied -- --exact`](../proxy/src/jobs/mediated/tests.rs#L31)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::mediated::tests::adopted_authentication_reaches_the_gateway_without_guest_override_or_token_evidence -- --exact`](../proxy/src/jobs/mediated/tests.rs#L149)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::mediated::tests::policy_revocation_closes_a_held_response_and_discards_late_evidence -- --exact`](../proxy/src/jobs/mediated/tests.rs#L277)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::mediated::tests::shutdown_closes_a_held_response_and_discards_late_evidence -- --exact`](../proxy/src/jobs/mediated/tests.rs#L282)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::mediated::tests::adopted_limits_are_finite_and_message_sizes_fit_both_abis -- --exact`](../proxy/src/jobs/mediated/tests.rs#L393)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::mediated::tests::oversized_provider_evidence_is_unavailable_and_never_truncated -- --exact`](../proxy/src/jobs/mediated/tests.rs#L405)
- [`cargo test --manifest-path proxy/Cargo.toml --lib jobs::mediated::tests::interrupted_effect_retains_uncertainty_separately_from_findings -- --exact`](../proxy/src/jobs/mediated/tests.rs#L486)

<a id="witness-proxy-src-policy-checks-rs-policy-checks-tests"></a>
### [`proxy/src/policy/checks.rs`](../proxy/src/policy/checks.rs)

Selection: manual native phase `named-checks` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::scoped_ipv6_keeps_required_checks_and_normalization_failure_uses_fallback -- --exact`](../proxy/src/policy/checks.rs#L1551)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::validation_rejects_unknown_types_scales_stages_and_influence -- --exact`](../proxy/src/policy/checks.rs#L1625)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::hard_exclusion_dominates_host_agent_and_positive_advisory_allows -- --exact`](../proxy/src/policy/checks.rs#L1678)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::scoped_exception_only_overrides_its_named_advisory_rule -- --exact`](../proxy/src/policy/checks.rs#L1730)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::thresholds_aggregation_boolean_precedence_and_advisory_priority -- --exact`](../proxy/src/policy/checks.rs#L1778)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::no_match_missing_stale_and_failure_never_become_positive_under_negation -- --exact`](../proxy/src/policy/checks.rs#L1853)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::subject_input_version_type_source_time_and_validity_are_bound -- --exact`](../proxy/src/policy/checks.rs#L1907)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::registration_age_uses_decision_time_and_expires_at_the_transition -- --exact`](../proxy/src/policy/checks.rs#L1978)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::direct_ip_opaque_and_unsupported_stage_use_the_selected_fallback -- --exact`](../proxy/src/policy/checks.rs#L2026)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::unavailable_boolean_inputs_follow_three_valued_logic -- --exact`](../proxy/src/policy/checks.rs#L2089)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::tests::recorded_replacement_and_missing_versions_are_observed_without_result_cache -- --exact`](../proxy/src/policy/checks.rs#L2111)

<a id="witness-proxy-src-policy-checks-rs-policy-checks-fixture-tests"></a>
### [`proxy/src/policy/checks.rs`](../proxy/src/policy/checks.rs)

Selection: manual native phase `named-checks` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::fixture_tests::reusable_fixture_preserves_allow_deny_unknown_and_expiry -- --exact`](../proxy/src/policy/checks.rs#L2161)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::fixture_tests::preview_uses_native_warn_and_bypass_and_never_charges_network_budget -- --exact`](../proxy/src/policy/checks.rs#L2190)

<a id="witness-proxy-src-policy-checks-rs-policy-checks-composition-edge-tests"></a>
### [`proxy/src/policy/checks.rs`](../proxy/src/policy/checks.rs)

Selection: manual native phase `named-checks` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::composition_edge_tests::non_finite_aggregate_cannot_assert_a_positive_condition -- --exact`](../proxy/src/policy/checks.rs#L2254)

<a id="witness-proxy-src-policy-checks-execution-tests-rs"></a>
### [`proxy/src/policy/checks/execution/tests.rs`](../proxy/src/policy/checks/execution/tests.rs)

Selection: manual native phase `named-checks` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::execution::tests::returned_job_metadata_does_not_disclose_host_retained_dependency_bodies -- --exact`](../proxy/src/policy/checks/execution/tests.rs#L1)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::execution::tests::admission_consumes_one_complete_host_capture_not_caller_normalized_facts -- --exact`](../proxy/src/policy/checks/execution/tests.rs#L32)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::execution::tests::captured_authoritative_github_issue_reports_identity_match_mismatch_and_missing_evidence -- --exact`](../proxy/src/policy/checks/execution/tests.rs#L91)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::execution::tests::adopted_path_mapping_preserves_gateway_canonical_paths_and_escapes_caller_values -- --exact`](../proxy/src/policy/checks/execution/tests.rs#L139)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::execution::tests::typed_results_cannot_supply_host_binding_fields_or_promote_pass_text -- --exact`](../proxy/src/policy/checks/execution/tests.rs#L167)
- [`cargo test --manifest-path proxy/Cargo.toml --lib policy::checks::execution::tests::rdap_registration_uses_only_exact_domain_creation_and_preserves_unknowns -- --exact`](../proxy/src/policy/checks/execution/tests.rs#L180)

<a id="witness-proxy-tests-native-policy-feeds-rs"></a>
### [`proxy/tests/native_policy_feeds.rs`](../proxy/tests/native_policy_feeds.rs)

Selection: manual native phase `managed-feeds` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds assessment_keeps_adopted_feed_scope_and_expiry_without_reloading_its_path -- --exact`](../proxy/tests/native_policy_feeds.rs#L281)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds installed_refresh_preserves_literal_initial_and_redirect_endpoints -- --exact`](../proxy/tests/native_policy_feeds.rs#L327)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds installed_refresh_after_rollback_recovers_unchanged_provider_membership -- --exact`](../proxy/tests/native_policy_feeds.rs#L376)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds installed_setup_refresh_retention_expiry_restart_rollback_and_recovery -- --exact`](../proxy/tests/native_policy_feeds.rs#L504)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds installed_download_validation_and_adopted_redirect_boundaries -- --exact`](../proxy/tests/native_policy_feeds.rs#L638)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds installed_first_start_failure_recovers_automatically_without_approvals -- --exact`](../proxy/tests/native_policy_feeds.rs#L770)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds installed_named_feed_only_fallback_refresh_preview_restart_and_rollback -- --exact`](../proxy/tests/native_policy_feeds.rs#L799)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds pending_acquisition_rechecks_source_adoption_and_retains_interrupted_schedule -- --exact`](../proxy/tests/native_policy_feeds.rs#L1023)
- [`cargo test --manifest-path proxy/Cargo.toml --test native_policy_feeds feed_setup_and_candidate_check_keep_the_selected_policy_directory -- --exact`](../proxy/tests/native_policy_feeds.rs#L1123)

<a id="witness-proxy-src-coord-rooms-work-automatic-tests-rs"></a>
### [`proxy/src/coord_rooms/work/automatic_tests.rs`](../proxy/src/coord_rooms/work/automatic_tests.rs)

Selection: manual native phase `before-after` (named execution receipt; ignored cases remain incomplete); [contracts](../.github/workflows/proxy-rust.yml) (scheduled/manual; condition `github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.packages_only)`).

- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_is_durable_before_creation_and_dispatches_once_under_concurrency -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L410)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_success_survives_failed_protected_commit_and_exact_restart_replay -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L544)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_changed_selector_cannot_escape_retained_operation_identity -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L574)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_lost_reply_requires_distinct_recovery_and_bounded_idempotent_retry -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L662)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_never_retries_without_adoption_and_revoked_recovery_cannot_progress -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L771)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_pending_revocation_retains_uncertainty_and_prevents_commit -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L813)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_completed_effect_does_not_restore_revoked_requester_membership -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L887)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::prerequisite_crash_after_dispatch_recovers_without_blind_repetition -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L924)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_preflight_refuses_invalid_requests_before_jobs_or_provider_contacts -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L983)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_preflight_preserves_positive_negative_and_failed_findings -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1117)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_preflight_does_not_replace_transactional_state_or_requirement_validation -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1146)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_concurrent_exact_requests_share_the_committed_receipt_and_replay -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1220)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_configuration_rejects_unknown_jobs_types_effects_and_dependencies -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1270)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_admission_covers_api_cli_import_omitted_factory_and_existing_delegation -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1301)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_output_verification_cannot_replace_independent_reviews_or_reuse_other_bytes -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1426)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_pending_admission_revalidates_revocation_without_holding_coord_or_policy_locks -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1570)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_missing_malformed_stale_and_substituted_output_evidence_holds_acceptance -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1618)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_follow_up_recovers_a_committed_pending_obligation_once -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1768)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_action_failure_is_uncertain_and_cannot_undo_the_completed_transition -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1841)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_crash_after_action_dispatch_keeps_the_same_uncertain_obligation -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L1962)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_service_request_rule_prevents_the_authorized_effect -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L2051)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_cli_reads_new_verifiers_and_identifies_recorded_offline_status -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L2137)
- [`cargo test --manifest-path proxy/Cargo.toml --lib coord_rooms::work::tests::automatic_tests::automatic_current_authority_read_invalidates_a_previously_accepted_finding -- --exact`](../proxy/src/coord_rooms/work/automatic_tests.rs#L2293)

## Explicitly outside this control catalogue

Harness, presentation, reporting or diagnostic behavior; no additional BB control assertion is claimed. Existing tests remain selected by the native-contract runner.

- [`tests/proxy_contracts/test_event_log_reader.py`](../tests/proxy_contracts/test_event_log_reader.py)
- [`tests/proxy_contracts/test_heap_release.py`](../tests/proxy_contracts/test_heap_release.py)
- [`tests/proxy_contracts/test_native_skill_trace.py`](../tests/proxy_contracts/test_native_skill_trace.py)
- [`tests/proxy_contracts/test_observability_contract.py`](../tests/proxy_contracts/test_observability_contract.py)

Guest artifact publication, preparation, scheduling and supporting contracts; no additional running sandbox-control witness is claimed. These source and workflow tests remain selected by their maintained CI lanes.

- [`tests/test_guest_helper_build.py`](../tests/test_guest_helper_build.py)
- [`tests/test_guest_inputs.py`](../tests/test_guest_inputs.py)
- [`tests/test_guest_oci_publisher.py`](../tests/test_guest_oci_publisher.py)
- [`tests/test_guest_promotion.py`](../tests/test_guest_promotion.py)
- [`tests/test_guest_release_auth.py`](../tests/test_guest_release_auth.py)
- [`tests/test_guest_scheduling.py`](../tests/test_guest_scheduling.py)
- [`tests/test_guest_signatures.py`](../tests/test_guest_signatures.py)
- [`tests/test_guest_smoke_upload.py`](../tests/test_guest_smoke_upload.py)
- [`tests/test_guest_test_packages.py`](../tests/test_guest_test_packages.py)


## Maintained guest and host pytest descriptions

Each entry states the security property the test asserts and the threat it defends against. The probe (What) describes the specific observation used to confirm the property.

**84 distinct pytest methods across 25 threat categories.**

This is a source inventory, not a passing execution receipt. The ordinary guest selection excludes root containment; the root selection runs root containment and private-key isolation. Private-key scans run under both identities; public-cert checks run as the ordinary user. Parameterization and platform/fixture skips affect executed nodes. The retired host/proxy selection is excluded.

## Installed procedural selections

`run-installed.sh` prepares once and runs these independent sections:

| Actual lane | Selected sections |
|---|---|
| `systrap` | isolation, workloads, access, peer-support, shared-approvals, provider, federation, lifecycle, continuity, job-sandbox, job-network, mounts, docker |
| `kvm` | isolation, ingress, workloads, job-sandbox, job-network, mounts |
| `vz` | isolation, access, lifecycle, continuity, job-sandbox, job-network, mounts |

### `tests/blackbox/installed_access.py`

Exercise installed access through two live systrap or VZ guests.

Retain service and contract binding/risk approvals, exact credential injection
and live peer denial, populated owner-positive/peer-negative guest flow search
and detail, test-context/trace evidence, real NATS Coord and attention, operator
collaboration approval/exchange/revocation, WebSocket peer effects and traffic-inspector
filter/transcript/export. These observations stay in one installed composition.
The fixture prepares guest desktop packages and an owned host opener. Headless
Linux runs also own a host Xvfb display for the typed action's display check.
Viewer checks observe VNC bytes, session binding and cessation on revocation,
expiry and run turnover; they do not require visual UI automation.

### `tests/blackbox/installed_state_transition.py`

Check installed native state through restart, replacement and recovery.

Use the current installed CLI and its exact --install-commit.
No agent is booted: this is installed host composition, not guest isolation.
Each return process must read durable state, reset process-local task policy,
and enforce revocations before deliberately restoring access.

The procedure uses four native process lifetimes. Historical cross-backend
receipts remain recorded in the issue; they are not a current execution mode.

### `tests/blackbox/installed_docker_preflight.py`

Probe nested Docker in one disposable installed Linux/systrap sandbox.

On an owned Linux host, supply a prepared installation, this source checkout,
and Python 3.11+ with tomlkit. Use a new output directory and a new root unless
--reuse-root is selected. A new instance also needs a free Admin port. Use
disk-backed paths with traversable parents. --nested-docker selects the
candidate's guest configuration; without it the driver records the default.
The guest installs Debian Docker packages through its normal proxy, attempts
one local daemon/pull/container and stops. --journey additionally runs the
Compose lifecycle, sandbox recovery and application-bound provider controls.
--gateway reuses the stopped qualified fixture for Docker management through
its provider route. It restores ephemeral guest tools, but does not repeat image
pulls or the application lifecycle. The single-container journey also checks
adjacent-operation refusal and live revocation against independent daemon reads.
--gateway-lifecycle adds the missing Compose lifecycle through that same route.
It seeds an owned loopback registry from the retained nested-notes image, then
pulls that image through the gateway before building and running the application.
The registry uses Python in that same image and stores blobs on provider disk.
Its container stops before the build. Failed mutations are retained without
replay. This does not repair or retry an earlier registry credential.
--gateway-lifecycle-resume RECEIPT continues only recovery and teardown from an
operator receipt for a stopped run that reached gateway-notes-recovered. It inspects the
same recreated containers and volume before starting any stopped container.
It records the recovery command's output and exit in the caller workspace,
separately from the native shell result. No pull, build or recreation is repeated.
With --gateway-recovery-receipt RECEIPT, it consumes the retained successful
client recovery instead of starting workloads or reading the application again.
The receipt must identify the same source receipt, workloads and saved data.
--gateway-failures-only retains the earlier management proof and runs only the
daemon, closed-port and stopped-provider failure controls with --gateway.
--application-resume RESULT continues a stopped --journey interrupted at
privileged-network. Supply its result.json and sibling notes-written.log with
--reuse-root, --journey and the retained --docker-data path. It inspects the
same image, containers and volume before starting the application, then runs
the remaining containment, lifecycle, provider and owned-origin checks.
It does not pull, build, rewrite the saved note or repeat management-gateway
proof. Old request IDs remain in the referenced result; new probes bind the
new sandbox run. A passed continuation does not establish recurring coverage.
--reuse-root continues this probe's stopped disposable instance and persistent
home. It temporarily selects --prepared-config's executable and guest inputs,
then restores the donor's input paths after stopping. It preserves unrelated
policy entries and registry approvals. The driver does not
approve or retry a failed operation in a reused instance. In a fresh journey,
the pinned public pull may consume one new canonical registry credential
approval for the owned notes run. The driver checks the offered run scope and
active grant before retrying that pull once. Other failures stop the journey.
Both pulls use one anonymous DockerHub bearer through Docker's RegistryToken
config field. The driver resolves the pinned Debian input's read challenge
through the guest proxy and CA. Token responses and config files stay private;
the driver removes them after the pull sequence, including on failure. Reports
retain only the input, issuer, service, read scope and Docker versions.
This operator fixture decision permits the current fingerprints at
registry-1.docker.io across ports, methods and paths for the current notes run.
Network and service controls still apply. Shared baseline credential policy
stays unchanged. The report retains the first refusal and canonical decision
separately.
Independent acceptance remains separate.

--recurring runs a fresh application journey followed by the scoped Docker API
controls, live revocation and daemon/provider failures. It uses owned allowed
and denied origins and retains named checkpoints. With a parent route for the
test origin, SAFEYOLO_DOCKER_ORIGIN_BIND selects an owned routable IPv4 address.
For a fresh instance, --docker-image-data copies a host-prepared image-only VFS
store into its new guest home. Supply a dedicated qualified input, not a donor's
Docker data root. Only image and vfs directories are copied; container, volume,
network and daemon credential state are excluded. The pinned base image must
still resolve through image inspect. This selection does not prove a public pull.
The explicit image input uses noninteractive host sudo and rsync to preserve
subordinate numeric ownership, hard links, modes, ACLs, xattrs and symlinks.

### `tests/blackbox/installed_federation.py`

Send from real systrap guests to a separate TLS/NATS instance owner.

On a prepared disposable Linux host, supply the same installation and runtime
prerequisites as installed_authority, plus OpenSSL for a private test certificate.
The new root owns two credential-free guests. A second root owns the destination
room, broker, TLS key and peer credential. No peer credential enters a guest.
Both roots must be new; output must be empty and disk-backed. The driver checks
destination-owned message effects, wrong principal/instance and revocation,
then stops both instances. This is a same-host TLS journey, not a live tailnet.
Wrong-instance selection is refused by the source before forwarding. Native
federation tests cover the destination's payload-mismatch handler separately.

### `tests/blackbox/installed_ingress.py`

Check installed native ingress through one real gVisor/KVM guest.

Require the selected native installation and packaged executable, authenticated runtime and
actual KVM runsc argv/UID mapping. Bind guest localhost requests to its mounted
agent UDS. Observe an exact allowed HTTP marker at the owned origin, a denied
request with no origin delivery, and protected local API boundaries.

### `tests/blackbox/host/job_network.py`

Exercise scoped jobs, revocation and teardown through an owned proxy.

Requires host Python 3.10+, tomlkit, OpenSSL, candidate CLI/proxy binaries and
an installed shared Trixie guest. Supply a fresh --root with traversable parents
and a disk-backed --scratch directory. --admin-port and --upstream-port must be
free ports authorized for this run. On macOS use the approved physical VZ wrapper
and a short, owned TMPDIR. This creates a separate instance and retains its saved
grant, sanitized upstream observations and job results for inspection.
Two ordinary runs check stable saved authority. Three further runs check live
revocation, expiry and caller cancellation, including retained connections.

### `tests/blackbox/host/job_sandbox.py`

Exercise disposable jobs on a prepared Linux or physical macOS instance.

On the selected host, supply the candidate CLI and a disposable installed root:
python3 tests/blackbox/host/job_sandbox.py --cli /path/to/safeyolo --root /path/to/instance --scratch /disk/backed/directory
The root must already select the shared Trixie guest and native launcher.
For macOS, also supply --observer-probe /path/to/arm64-linux-static-probe.
Build that small test executable on Linux as documented in tests/fixtures/job-observer-probe.c.
This runs fixed local checks without starting a coding agent or contacting services.
Successful output names each observed boundary. Failure retains the scratch path.

### `tests/blackbox/installed_lifecycle.py`

Exercise installed lifecycle through systrap or physical VZ guests.

Retain live listener add/remove, policy changes during admitted SSE, all five
default guest-trust TLS cases (valid, wrong SAN, self-signed, future, expired)
with origin/no-passthrough checks, scoped ignore_hosts removal across held and
new connections, stable CA/upstream trust/policy and recovery. Keep mixed
HTTP/SSE/WS/CONNECT drain, three subject cycles and a separate live owner whose
process, policy and controls survive those cycles. Observe owned stop/cleanup.

### `tests/nested-linux/live_mount_backend_proof.py`

Check public live-directory actions on an owned Linux or physical Mac instance.

Run as the prepared host account. ROOT must be a fresh candidate installation
with its proxy and Coord running. BASE must not exist and must be outside ROOT.
On Mac, use the signed candidate helper, the approved VZ runner and a positive
SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS deadline. The guest helper must be this candidate.
The driver creates two synthetic agents, starts no model, and stops its agents
and proxy on every exit. It deliberately restarts the primary at the end to
check saved versus live-only intent. The earlier same-session proof is retained.

    python3 tests/nested-linux/live_mount_backend_proof.py         --root /owned/fresh-instance --base /owned/new-result-directory         --candidate FULL_COMMIT

Use --saved-retirement for the focused saved add/update/remove, live change,
explicit restart and retirement proof. It retains a home marker and checks the
second agent and unrelated configuration throughout.

The optional --native-test-binary retains the earlier Linux-only backend
witness. Omit it for product acceptance through the public commands.

The live-mount journey builds tests/fixtures/live-mount-holder.c with the Linux
host's cc and static C library. To supply a prepared executable, use --holder-probe.
On Mac, that option is required and must name a static Linux ARM64 executable.
The holder exercises real file descriptors, cwd and mmap without guest Python.
The --saved-retirement journey does not use the holder.

### `tests/blackbox/installed_peer_support.py`

Exercise delegated support on an owned disposable installed instance.

On the selected Linux/gVisor or physical macOS/VZ host, prepare an isolated
instance with the candidate native CLI/proxy, Linux guest helper and MCP binary.
Start its proxy and configure two disposable workers with an owned workspace,
the supervisor launcher and a long-running command such as ``exec sleep 300``.
Both workers must be stopped. Supply their names as --support and --target.

Run with host Python 3.11+ and --cli, --root and an empty disk-backed --scratch.
This starts and stops those two workers, changes only the named test grant,
and retains proposals in scratch and canonical receipts in the instance.
It does not launch a model or establish the separate unexplained-fault journey.
Guest requests use Bash/curl and never copy the Agent API token to the host.
On macOS retain the operator-approved VZ wrapper and authorized port settings.
For recurring execution, --output and --platform retain the named procedure
checkpoints and observed backend birth beside the selected report path.

--probe-recovery selects only the failed-harness/probe/config-repair journey on
the retained worker.sh fixture. Its saved command must run /workspace/worker.sh,
which reads /home/agent/.config/worker.conf and writes /tmp/worker-ready. The
driver changes only that owned config, preserves the script, observes the
managed process through the guest helper, and prints receipts and status polls
before assertions. It does not repeat the model diagnosis.

### `tests/blackbox/installed_provider.py`

Compose a native HTTP service through two real Linux/systrap sandboxes.

On an owned Linux host, supply Python 3.11+, tomlkit, a prepared installation
with the selected CLI/proxy/guest binaries, pinned runsc and native host
preparation, and a free Admin port. --root and --output must be new disk-backed
directories with traversable parents. The driver reuses immutable inputs and
creates two credential-free agents. It grants only the caller's reader
capability, exercises refusal and revocation, then stops its guests, proxy and
broker. It preserves the prepared installation.
No model, external service credential or Coord message is used.

### `tests/blackbox/installed_shared_approvals.py`

Run the shared #821 action on two owned, running Ubuntu/systrap guests.

The selected native proxy and the two guests must already be running in a
marked disposable instance. This probe temporarily replaces its policy,
serves two owned HTTP origins, then stops both guests and the owned proxy.
Real Helper mode waits for a human decision and retains its private raw events.
Model-unavailable mode observes a live Codex request receiving an owned 503,
then checks that the pending action still requires a direct operator decision.
Delegated mode instead lets the eligible Codex reviewer decide three typed
requests through native MCP tools. It requires the separate fixture service
and checks owned origin effects without a human decision.
Delegated-service mode proves one scoped service authorization with a synthetic
host credential, the same attention tools and an explicit guest retry.
Delegated-binding mode uses that path for a fixed contract binding, verifies
forbidden values and operations, then revokes its derived binding.
Delegated-room mode uses an existing local room, real guest requests and
reviewer decisions, message/history access, paging and actual worker turnover.
Fresh delegated model journeys start at the current attention cutoff. Older
edges are recorded without reading or resolving their payloads. An explicit
--attention-cutoff must match the current cutoff on the owned instance.
Deterministic mode uses the shipped curl for guest requests. Other modes use
Python for the black-box driver and guest request transport.

### `tests/blackbox/installed_workloads.py`

Exercise installed Linux workloads through one systrap or KVM guest.

Retain package fetch/hash/query/install/payload/purge, read-only Git clone and
exact commit/marker, held SSE first-event/control/release ordering, WSS echo
and peer-close state, denied-upgrade canary with no origin delivery, and pinned
SSH host-key/command through CONNECT. Each selected run owns its fixtures,
disposable key, SSH server and guest writable state.
Installed access owns the plain-WS exchange and inspector observations through
the same guest handshake, payload and close helper.

### Installed host package

`run-installed-package.sh` can install a checksum-verified host archive through
the archive's own installer. The archive path does not build or install product
files from the test checkout. The default installation acquires the compatible
guest through the native OCI client. `--platform-assets` selects prepared offline
inputs; `--no-guest-download` selects a proxy-only witness.

On a disposable supported Linux host, start from this test checkout with its
Python test environment prepared. Python and uv are test-driver dependencies,
not packaged-product dependencies. The host must have the runtime prerequisites
in [installation prerequisites](installation.md#guest-prerequisites). Obtain the host archive and its SHA-256
digest from the selected release. Replace both values below with those actual
inputs. The command creates owned installation and section state under `HOME`,
downloads the default guest, and starts and stops the test runtime.

```sh
./tests/blackbox/run-installed-package.sh --package /path/to/host.tar.gz --sha256 FULL_RELEASE_SHA256 --lane systrap
```

The output names the host archive digest, package source/profile and selected
guest identities separately. The existing reports record the running installed
executables and owned cleanup. Install-to-agent-ready timing includes artifact
verification, installation and test fixture preparation. A staged input is not
a published-artifact result.

`--lane systrap` and `--lane vz` run the maintained isolation and lifecycle
sections against that installation. `--lane kvm` runs isolation and ingress;
guest restart/persistence proof for KVM remains separate. Physical Apple Silicon
VZ needs the approved host route and assigned fixture ports. The fixed-port
lifecycle and continuity probes cover TLS on that route. The same installation
can be reused with `run-installed.sh LANE --prepared-config INSTALLATION_ROOT`; an
explicit `--install-commit` must match the package's source identity.

Without `--lane`, `installed_host_smoke.py` observes the native installed
launcher, authenticated runtime identity, owned HTTP allow/deny authorities and
verified stop. That host-only result boots no guest and proves no guest isolation.
Without `--package`, the wrapper retains the existing source-based proxy witness.

The host witness also selects `tests/proxy_contracts/test_https_contract.py::test_https_origin_verification` against its packaged executable. Those ephemeral-port controls run on Linux and the hosted Mac; physical VZ uses the fixed-port probes described above.

The complete native process/protocol family is separately maintained in `tests/proxy_contracts/`, run once per supported host platform overnight. installed_state_transition.py checks installed durable state through four native process lifetimes on Linux and the hosted Mac. Historical cross-backend receipts remain in the accepted issues. Runner selection describes intended execution, not a passing receipt.

## Installed native ingress

### `tests/blackbox/host/native/test_installed_native.py`

#### TestInstalledNative — The installed native listener serves real host requests during the guest run.

**Threat:** An isolation pass cannot name a Rust proxy if its host requests ran
through a different process or never reached an origin.

- **`test_controlled_origin_and_protected_admin`** — The selected agent reaches an owned origin and cannot proxy to admin.
  - *Probe:* Send one ordinary request to the controlled sinkhole, then one
to the protected management listener through the same agent socket.
  - *Consequence if unasserted:* A response alone cannot show origin delivery or admin containment.

## Host process security

### `tests/blackbox/host/security/test_firewall_structural.py`

#### TestProcessSecrecy — Proxy process doesn't leak SafeYolo tokens via its cmdline.

**Threat:** Process command lines are readable by any local user via
`ps aux` or `/proc/PID/cmdline`. If SafeYolo tokens appear in
the Rust proxy invocation, a non-root user on the host (or a
process that escaped the sandbox) can read them and gain full
admin control. Tokens must be passed via file or env var instead.

- **`test_no_tokens_in_process_cmdline`** — Admin and agent tokens do not appear in the selected proxy cmdline.
  - *Probe:* Bind the native receipt to its live process and configuration,
then inspect its command line; assert neither token is a substring.
  - *Consequence if unasserted:* A token in the cmdline is readable by any local user —
full admin access leaks to anyone with shell on the host.

## Installed agent identity

### `tests/blackbox/host/identity/test_agent_identity.py`

#### TestAgentListener — Host-owned Unix domain sockets supply each agent's request identity.

**Threat:** A missing or shared listener can break guest egress or attribute
requests to the wrong agent. Policy and evidence need the correct identity.

- **`test_agent_listener_has_entry`** — The running agent has a configured listener.
  - *Probe:* Read the host's native listener configuration and find the agent.
  - *Consequence if unasserted:* Listener ownership determines policy and evidence attribution.
- **`test_agent_listener_has_attribution_ip`** — The managed listener retains its attribution IP.
  - *Probe:* Check the listener source address is in 10.200.0.0/16.
  - *Consequence if unasserted:* Host lifecycle operations reserve this range for managed agents.
- **`test_agent_listener_has_socket`** — The configured proxy socket is present.
  - *Probe:* Check that the configured listener path is a Unix domain socket.
  - *Consequence if unasserted:* Each guest needs its host-owned socket for proxy egress.

#### TestRootlessUidMapping — Linux sandbox identities map to non-root host identities.

**Threat:** SafeYolo intentionally permits namespace-root for package
installation. Its host safety depends on the enclosing user
namespace mapping sandbox uid 0 to a subordinate uid while mapping
sandbox uid 1000 to the operator for workspace access.

- **`test_sandbox_root_maps_to_subordinate_host_uid`** — Sandbox root maps to the selected subordinate UID and GID.
  - *Probe:* Read the live namespace holder's UID and GID maps. Check
that root uses the prepared bases and guest ID 1000 uses the
host account. Retain the original mapping for older packages.
  - *Consequence if unasserted:* If sandbox uid 0 mapped to host uid 0, setpriv or a package
maintainer script would gain real host root. If uid 1000 did
not map to the operator, normal workspace ownership would fail.

## Installed agent persistence and restart

### `tests/blackbox/host/lifecycle/test_home_persistence.py`

#### TestAgentHomePersistence — Writes to /home/agent persist across `agent stop` and `agent run`.

**Threat:** The persistent home is where mise installs, shell history,
host-script-staged auth (e.g. ~/.claude.json), and any user state
live. If it doesn't survive a sandbox restart, every `agent run`
is effectively a fresh install — no auth, no cached tools, no
shell history. On Linux the memory-backed overlay silently
discarded those writes before the OCI bind-mount landed; this
test guards against a regression to that behavior.

- **`test_home_persists_across_restart`** — Home, workspace and a deferred mise tool survive stop/start.
  - *Probe:* Install Node through mise, write markers to the home and
workspace, and check both markers and the same tool after restart.
Read the workspace marker on the host too.
  - *Consequence if unasserted:* A missing file or mismatched content means writes to
/home/agent landed somewhere ephemeral (the memory overlay
on Linux, or an un-mounted location on either platform) —
the OCI bind-mount is broken or was never wired. Host-script
auth staging, mise installs, and shell history all rely on
this invariant.

### `tests/blackbox/host/lifecycle/test_host_listener.py`

#### TestLiveHostListener — A contemporaneously live host listener remains isolated from guests.

**Threat:** A guest refusal without host liveness can pass when no service exists.

- **`test_live_host_listener_refused`** — A live host listener stays unreachable to ordinary and root guests.
  - *Probe:* Connect from the host before and after the maintained guest refusal
and proxy positive controls. Record the actual endpoint and guest identity.
  - *Consequence if unasserted:* A stale port or an absent listener cannot establish host isolation.

### `tests/blackbox/host/lifecycle/test_token_lifecycle.py`

#### TestLiveAgentLifecycle — Agent egress survives proxy restart without restarting its sandbox.

**Threat:** A running guest must retain authenticated Agent API and proxy access
after proxy replacement. Boot-time health cannot prove that the same
guest reconnects to the recreated socket with its current token.

- **`test_agent_api_survives_proxy_restart`** — Agent API stays reachable from the sandbox across proxy restart.
  - *Probe:* Verify agent API /health returns 200 from inside the
sandbox and deliver a marked proxy request. Stop and start the proxy.
Require the same guest/backend birth, health, traffic and home state.
  - *Consequence if unasserted:* A recreated token or Unix socket must remain reachable from
the same sandbox. File-binding the old socket inode made every
reconnect fail even though the host pathname had been recreated.

## In-sandbox (isolation)

### `tests/blackbox/isolation/test_agent_api_scope.py`

#### TestAgentAPIAuth — Agent API rejects every unauthenticated request.

**Threat:** The agent API exposes proxy diagnostics and a small mutation
surface. Any bypass of the bearer-token gate means any local
process on the VM (or a LAN attacker if the endpoint ever leaks)
can read policy, flow contents, and credentials metadata, or
mutate agent gateway state.

- **`test_health_with_valid_token`** — Valid token returns 200.
  - *Probe:* GET /health with the agent token from /app/agent_token;
assert 200.
  - *Consequence if unasserted:* Baseline positive case — if this fails, every other
auth test is meaningless because auth is entirely broken.
- **`test_health_without_token`** — No Authorization header returns 401/403.
  - *Probe:* GET /health with no Authorization header.
  - *Consequence if unasserted:* Default-deny — any bypass here means the whole API is
open to unauthenticated callers.
- **`test_health_with_wrong_token`** — Bogus bearer value returns 401/403.
  - *Probe:* GET /health with Authorization: Bearer wrong-token-value.
  - *Consequence if unasserted:* Confirms the auth check actually compares the full token,
not just its presence. A check that accepts 'any non-empty
value' is effectively unauthenticated.
- **`test_health_with_empty_bearer`** — Empty Bearer token returns 401/403.
  - *Probe:* GET /health with Authorization: Bearer  (empty value).
  - *Consequence if unasserted:* An empty string passes a naive truthiness check in some
implementations. Closes that specific evasion.
- **`test_every_get_route_requires_auth`** — Every documented GET route rejects unauthenticated callers.
  - *Probe:* GET each of /health, /status, /policy, /budgets,
/config, /memory, /agents, /circuits with no token;
assert 401/403 each time.
  - *Consequence if unasserted:* Individual auth decorators could be forgotten when new
routes are added. Coverage across the route set catches
per-route auth bypasses.

#### TestAgentAPIMethodRestriction — Each route accepts only its documented HTTP methods.

**Threat:** A route that silently accepts any method can become a
mutation endpoint by accident. PUT/PATCH/DELETE on a GET-only
route must not succeed — if they do, someone has forgotten a
method allowlist and mutations can happen unintentionally.

- **`test_put_rejected`** — PUT on /health returns 405.
  - *Probe:* PUT /health with a valid token; assert 405.
  - *Consequence if unasserted:* PUT is a mutation method. /health is read-only. A 200
or 2xx here would indicate the route accepts arbitrary
methods — potential mutation surface.
- **`test_patch_rejected`** — PATCH on /health returns 405.
  - *Probe:* PATCH /health; assert 405.
  - *Consequence if unasserted:* Same property as PUT — mutation method on a read route.
- **`test_delete_on_nonexistent_route`** — DELETE on /nonexistent returns 404 or 405.
  - *Probe:* DELETE /nonexistent; assert status is 404 or 405.
  - *Consequence if unasserted:* A 200 on an unrecognised path indicates a catch-all
handler that silently accepts any method — a route-matching
bug that could eat valid requests or accept unintended ones.

#### TestAgentAPIMutationSurface — Mutation endpoints are auth-gated; non-mutation routes reject writes.

**Threat:** The agent API's mutation surface is deliberately narrow:
flow tagging plus gateway request/binding. Bypasses here let
an unauthenticated caller mark flows or trigger capability
grants — higher-blast-radius than read-only diagnostic access.

- **`test_tag_post_requires_auth`** — POST /api/flows/.../tag without token returns 401/403.
  - *Probe:* POST to the tag endpoint with a JSON body but no
Authorization header; assert 401/403.
  - *Consequence if unasserted:* Tag mutation is part of the audit trail. Unauthenticated
tagging corrupts flow metadata — someone could add misleading
tags that throw off post-incident analysis.
- **`test_tag_delete_requires_auth`** — DELETE /api/flows/.../tag/... without token returns 401/403.
  - *Probe:* DELETE the tag endpoint with no Authorization header;
assert 401/403.
  - *Consequence if unasserted:* Tag deletion is also mutation. An attacker who can
delete tags can wipe evidence tying flows to a test run or
investigation context.
- **`test_gateway_request_access_requires_auth`** — POST /gateway/request-access without token returns 401/403.
  - *Probe:* POST to /gateway/request-access with a JSON body but
no Authorization header; assert 401/403.
  - *Consequence if unasserted:* request-access triggers the human-in-the-loop approval
flow for capability grants. An unauthenticated caller
spamming this endpoint could social-engineer approvals or
exhaust operator attention.
- **`test_post_on_get_only_route_rejected`** — POST on /policy returns 405, not 200.
  - *Probe:* POST /policy with a valid token; assert 405.
  - *Consequence if unasserted:* /policy is a read-only diagnostic endpoint. A 200 would
indicate method-router confusion — another mutation surface
silently opened.

### `tests/blackbox/isolation/test_guest_ssh.py`

#### TestGuestSSH — The default guest retains working key-only SSH access.

**Threat:** Linux agent shell uses runsc, so a shell or SSH banner alone does
not prove that the shipped SSH server can authenticate an agent.

- **`test_guest_server_accepts_owned_key_and_refuses_unknown_key`** — Guest SSH executes a command only with an authorized key.
  - *Probe:* Add a disposable public key to the owned agent's authorized
keys, pin the guest's existing public host key, and connect on loopback.
Check the reached UID and an unknown-key refusal, then restore the keys.
  - *Consequence if unasserted:* Both SSH packages and the existing authentication controls must
work on gVisor and VZ after the image package reduction.

### `tests/blackbox/isolation/test_key_isolation.py`

#### TestPublicCertPresent — Public CA cert is installed in the agent's trust store.

**Threat:** The agent validates HTTPS traffic against this CA. Without
it, every HTTPS request through the proxy fails with certificate
errors and the agent can't do useful work — or it's tempted to
use --insecure flags that undermine interception security.

- **`test_public_cert_exists`** — Public CA cert file is present in /usr/local/share/ca-certificates.
  - *Probe:* Check `PUBLIC_CERT.exists()` for safeyolo.crt.
  - *Consequence if unasserted:* Missing file means update-ca-certificates never added
it — the agent can't verify proxy-signed certs.
- **`test_public_cert_readable`** — Public CA cert file is readable and contains a PEM certificate.
  - *Probe:* Read safeyolo.crt; assert contents include 'BEGIN
CERTIFICATE'.
  - *Consequence if unasserted:* A zero-byte or non-PEM file would pass the existence
check but still break TLS. Confirms the file is actually a
usable cert, not a stub.
- **`test_public_cert_has_no_private_key`** — Public CA cert file contains no PRIVATE KEY block.
  - *Probe:* Read safeyolo.crt; assert 'PRIVATE KEY' is not in
the content.
  - *Consequence if unasserted:* If the install script accidentally concatenates the
public cert with the private key, shipping both to every
sandbox, the agent has root of trust on arbitrary domains —
complete interception bypass.

#### TestPrivateKeyAbsent — CA private key never enters the sandbox, anywhere.

**Threat:** The CA private key is the root of trust for mitmproxy's
TLS interception. An agent that obtains it can sign certificates
for any domain and impersonate any service — defeating every
network/credential guard that depends on TLS inspection. This
class probes multiple filesystem locations from the adversary's
perspective to prove the key is structurally absent.

- **`test_no_key_files_in_cert_store`** — No .key files in /usr/local/share/ca-certificates.
  - *Probe:* List the trust store dir; assert no file has suffix .key.
  - *Consequence if unasserted:* The trust store is the obvious place to accidentally
drop a private key alongside its cert. A .key file here is
the simplest possible leak pattern.
- **`test_no_key_files_in_config_share`** — No .key files in /safeyolo (the config share).
  - *Probe:* List files in /safeyolo; assert no .key suffix.
  - *Consequence if unasserted:* The config share is mounted from the host and could
accidentally include key material if prepare_config_share
is too greedy about what it copies.
- **`test_no_private_key_content_in_pem_files`** — No .pem/.crt file in cert directories contains PRIVATE KEY.
  - *Probe:* Walk the trust store, config share, and /etc/ssl/certs;
read every .pem/.crt; assert none contain 'PRIVATE KEY'.
  - *Consequence if unasserted:* Catches the naming-convention dodge — even if the file
is called .crt (public), it could carry private key content.
Tests the content, not the name.
- **`test_full_filesystem_scan_for_private_keys`** — Whole-filesystem scan finds no unexpected private-key material.
  - *Probe:* os.walk from / (skipping /proc, /sys, /dev, /run and
third-party site-packages); inspect private-key markers and allow only
the listed exact guest sshd host-key paths.
  - *Consequence if unasserted:* The targeted tests above check known-critical paths.
This is the catch-all: if any private key leaked to a surprising
location (/tmp, /var/log, an agent workspace subdir), the
targeted tests would miss it but this scan would catch it. Guest-local
SSH host keys are expected only at their standard paths.

### `tests/blackbox/isolation/test_root_containment.py`

#### TestGuestRootCapability — Guest root is available and useful inside the isolated environment.

**Threat:** Agents need to install distro packages and repair their own guest
environment. A test suite which only proves non-root operation can miss a
broken sudo/root path even though that path is a supported feature.

- **`test_root_shell_has_uid_zero`** — The operator-selected root shell really runs as guest UID 0.
  - *Probe:* Read the effective and real process UIDs and require both to be
zero when the suite uses the selected guest-root test transport.
  - *Consequence if unasserted:* Merely accepting a root selection is not useful acceptance evidence;
package installation and guest repair require actual guest-root
privileges.
- **`test_root_shell_and_pid1_have_nofile_limit`** — The selected root process and its PID 1 view have the required limit.
  - *Probe:* Inspect this process through the selected guest-root test transport
lane and read the open-file limit for PID 1 from proc.
  - *Consequence if unasserted:* SSH can produce identity-specific limits, so macOS uses the direct
root login rather than an agent-session sudo transition. Linux enters
guest root through sudo after native shell validates its current run.
- **`test_root_can_install_local_apt_package`** — Guest root can install and remove a local package with apt/dpkg.
  - *Probe:* Build a minimal local Debian package, install it through apt,
verify its payload under /usr/local, then purge it without network
downloads.
  - *Consequence if unasserted:* This exercises the filesystem overlay and package database that
real ``apt`` installs depend on, while keeping acceptance deterministic
and independent of an external mirror.

#### TestGuestRootTrustIsolation — Guest trust changes cannot widen the host proxy's upstream trust.

**Threat:** Guest root can install packages and local trust anchors. That
supported capability must remain inside the sandbox. The host proxy must
continue to authenticate upstream TLS with its own trust store.

- **`test_guest_ca_change_does_not_change_proxy_validation`** — A guest-only trust anchor remains untrusted by the host proxy.
  - *Probe:* Install the sinkhole's self-signed leaf into the writable guest
trust store, prove the guest bundle accepts it, then request that
upstream through SafeYolo and require the host proxy to return 502.
  - *Consequence if unasserted:* A successful upstream request would show that guest-controlled
trust changed the proxy's host-side certificate validation boundary.

#### TestGuestRootContainment — Guest root cannot cross the SafeYolo isolation boundary.

**Threat:** UID 0 is intentionally powerful inside the guest. It must still be
unable to bypass proxy-only egress, reach host listeners, modify the
host-backed SafeYolo share, or access a host virtualization device.

- **`test_root_direct_egress_blocked`** — Guest root cannot bypass the proxy with a direct connection.
  - *Probe:* Use curl with all proxy handling disabled against a public IP
and require the connection to fail.
  - *Consequence if unasserted:* Package-management privilege must not also grant an unobserved
network path around SafeYolo's policy and credential controls.
- **`test_root_proxy_path_works`** — Guest root retains the authorised proxy egress path.
  - *Probe:* Send an HTTP request through HTTP_PROXY to the allowlisted test
host and require a 200 response.
  - *Consequence if unasserted:* A direct-egress failure is only meaningful when the intended
proxy path is a working positive control for the same root process.
- **`test_root_cannot_reach_live_host_listener`** — Guest root cannot connect to a known-live host TCP service.
  - *Probe:* Read the harness listener endpoint from the read-only config share
and attempt a direct TCP connection to the host address.
  - *Consequence if unasserted:* Testing a live listener distinguishes real host isolation from a
connection failure caused only by choosing an unused port.
- **`test_root_cannot_modify_host_config_share`** — Guest root cannot write the host-backed SafeYolo config share.
  - *Probe:* Attempt to create a probe beneath /safeyolo and require an
operating-system error with no file left behind.
  - *Consequence if unasserted:* A writable share would let a root package maintainer script
mutate host-side proxy or agent configuration across the boundary.
- **`test_gvisor_root_cannot_access_host_kvm_device`** — The host KVM device is not exposed inside a gVisor sandbox.
  - *Probe:* In a gVisor lane, assert /dev/kvm is absent even in a
guest-root shell; hardware microVMs use their own device boundary.
  - *Consequence if unasserted:* The Linux KVM lane gives gVisor's sentry host-side access to KVM;
passing that device through to the agent would expose a powerful host
virtualization interface outside the intended boundary.

### `tests/blackbox/isolation/test_runtime_capabilities.py`

#### TestOpenFileLimit — Every supported sandbox exposes the same open-file headroom.

**Threat:** A lower hard limit on the VZ normal-session path makes agent
workloads depend on the operator's host platform. The session must repair
that limit before it runs the requested workload.

- **`test_pid1_shell_and_child_inherit_nofile_limit`** — PID 1 and all later descendants have a 65536 soft/hard limit.
  - *Probe:* Read PID 1's proc limit, inspect the running test process that
was launched through the normal agent-shell path, and spawn one more
child.
  - *Consequence if unasserted:* Checking only the final agent process can hide a child-only
workaround. The normal SSH entry path must establish the session and
its visible PID 1 limit before it launches the requested workload.

### `tests/blackbox/isolation/test_vm_isolation.py`

#### TestNetworkEscape — Sandbox cannot reach external networks except through the proxy.

**Threat:** The proxy is the sole authorised egress path. Every other
network-layer route — direct IP, raw sockets, alternate ports,
IPv6, DNS, cloud metadata IPs — must be unreachable. A gap here
means data exfiltrates outside the credential/network guards
entirely, and the agent operates with no policy enforcement.

- **`test_direct_http_blocked`** — Direct HTTP to an external IP (bypassing proxy) fails.
  - *Probe:* curl --noproxy to http://1.1.1.1; assert non-zero exit.
  - *Consequence if unasserted:* The most basic egress escape — if the agent can just
curl any IP directly, the proxy is decorative.
- **`test_direct_https_blocked`** — Direct HTTPS to an external IP (bypassing proxy) fails.
  - *Probe:* curl -k --noproxy to https://8.8.8.8; assert non-zero exit.
  - *Consequence if unasserted:* A firewall that only blocks port 80 would let port 443
traffic through. TLS at the IP layer bypasses URL-based
inspection entirely.
- **`test_dns_udp_blocked`** — Raw UDP to 8.8.8.8:53 fails.
  - *Probe:* Craft a DNS query, sendto() a UDP socket pointed at
8.8.8.8:53; assert the receive times out.
  - *Consequence if unasserted:* DNS is a classic covert-channel egress. If UDP/53 is
open, an agent can stream data via DNS tunnelling, which
never touches the HTTP proxy.
- **`test_raw_socket_blocked`** — AF_INET raw socket creation fails (no CAP_NET_RAW in sandbox).
  - *Probe:* socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) then sendto a
crafted ICMP echo to 1.1.1.1; assert PermissionError/OSError.
  - *Consequence if unasserted:* ICMP tunnelling and ping-based exfiltration rely on raw
sockets. Without CAP_NET_RAW the syscall fails at creation.
- **`test_direct_alt_port_blocked`** — Direct TCP to 1.1.1.1 on 8443, 22, 6667, 25 all fail.
  - *Probe:* curl --noproxy to 1.1.1.1 on each non-standard port;
assert non-zero exit for every port.
  - *Consequence if unasserted:* A firewall that only blocked :80 and :443 would leave
every other port open. Alt-HTTPS (:8443), SSH (:22), IRC
(:6667, historical C2), SMTP (:25) are all realistic C2/
exfil channels the agent might attempt.
- **`test_libc_resolver_blocked`** — getaddrinfo() on an external name raises gaierror.
  - *Probe:* socket.getaddrinfo("blackbox-probe-should-not-resolve.
example", 80, ...); assert gaierror.
  - *Consequence if unasserted:* Raw UDP/53 blocking alone doesn't cover the libc
resolver path. If /etc/resolv.conf points at a reachable
nameserver, getaddrinfo quietly succeeds — agents using
the system resolver bypass the proxy for lookups and can
DNS-tunnel data.
- **`test_non_icmp_raw_protocols_blocked`** — Raw sockets for SCTP/GRE/IPIP also fail.
  - *Probe:* socket(AF_INET, SOCK_RAW, proto) for proto in
[132=SCTP, 47=GRE, 4=IPIP]; assert PermissionError/OSError
for each.
  - *Consequence if unasserted:* If the sandbox filter scopes raw sockets only by
IPPROTO_ICMP, tunnelling protocols (GRE, IPIP, SCTP) leak
through and provide alternate exfil paths invisible to
TCP/UDP observers.
- **`test_ipv6_egress_blocked`** — IPv6 egress via curl -6 and AF_INET6 socket both fail.
  - *Probe:* curl -6 to a literal v6 address; AF_INET6 socket
connect to the same; both must fail/timeout.
  - *Consequence if unasserted:* mitmproxy binds to IPv4 only. If the sandbox has v6
connectivity, the agent can reach any v6-capable destination
outside the proxy's view entirely — a complete bypass.
- **`test_metadata_ips_unreachable`** — Cloud metadata IPs (169.254.169.254, 169.254.170.2) are unreachable.
  - *Probe:* curl --noproxy to each metadata IP; assert non-zero exit.
  - *Consequence if unasserted:* On a cloud VM host, link-local metadata endpoints expose
instance IAM credentials and user-data. A sandbox that can
reach them SSRFs the host's IAM role — often full access to
the cloud account.
- **`test_af_packet_blocked`** — AF_PACKET socket creation fails.
  - *Probe:* socket(17 /* AF_PACKET */, SOCK_RAW, 0); assert
PermissionError/OSError.
  - *Consequence if unasserted:* AF_PACKET lets the process craft Ethernet frames
directly. With it, an agent can ARP-spoof, forge source
IPs (bypassing L3 firewall rules by appearing to be the
host), or probe the L2 neighbourhood.
- **`test_dns_tunnel_subdomain_blocked`** — Arbitrary subdomain under a real TLD does not resolve.
  - *Probe:* getaddrinfo("exfil-data-here.tunnel-probe.httpbin.org",
...); assert gaierror. If it resolves, fail.
  - *Consequence if unasserted:* DNS tunnelling encodes data in subdomain labels
(<base64>.exfil.attacker.com) — every query leaks ~60 bytes
to a nameserver the attacker controls. The proxy never sees
it because it's DNS, not HTTP. The only safe posture is no
external name resolution at all.
- **`test_host_header_mismatch_routes_by_url`** — Host-header mismatch with URL routes by URL (200, not 4xx).
  - *Probe:* Send a proxy'd GET with URL=httpbin.org and
Host=evil.com; assert 200 (URL is authoritative; Host is
advisory per RFC 7230 §5.4).
  - *Consequence if unasserted:* An agent must not be able to smuggle a blocked
destination by putting it in the Host header while keeping
an allowed URL. The URL is what gets evaluated and where the
traffic goes; confirming that guarantees no Host-based
domain-fronting evasion.
- **`test_proxy_reachable`** — HTTP via the proxy to an allowlisted host succeeds (200).
  - *Probe:* curl through HTTP_PROXY to an allowlisted host with
an X-SafeYolo-Test-Context header; assert 200.
  - *Consequence if unasserted:* Positive control for the entire isolation suite. If
this fails, the agent has no connectivity at all — all
other "reachability blocked" assertions become meaningless
("everything is blocked including what should work").

#### TestHostAdjacentReachability — Sandbox cannot reach host-side services other than the proxy.

**Threat:** The agent is meant to reach only the proxy, and everything
else on the host (admin API, SSH, arbitrary local services,
other agents' subnets) must be off-limits. A pass-by-default
configuration (whatever isn't explicitly blocked is reachable)
would let an agent pivot to local-only services assumed safe
because they're bound to loopback or LAN.

- **`test_admin_api_unreachable`** — The host admin API listeners are unreachable from the sandbox.
  - *Probe:* TCP connect to the admin ports named by the harness. The
default Linux lane checks both production 9090 and test 9190;
the physical VZ lane checks its assigned live test port.
  - *Consequence if unasserted:* The admin API can change policy modes (block → warn),
add allowlist entries, or approve credentials. Agent access
to it would defeat every other control SafeYolo enforces —
a single-request sandbox escape.
- **`test_host_ssh_unreachable`** — Port 22 reachable from sandbox is its own sshd, not the host's.
  - *Probe:* Connect to port 22 on the resolved proxy host; if a
banner comes back, the connection terminated to the
sandbox-internal sshd (or nothing at all). Pass if
timeout/refused.
  - *Consequence if unasserted:* If the agent can reach the host's SSH, it can try
password brute force or probe for authorized_keys leaks.
The sandbox-internal sshd is a separate service that
doesn't run against host keys.
- **`test_host_listener_unreachable`** — A live TCP listener on the host is unreachable.
  - *Probe:* Read the listener address and port markers under /safeyolo
(harness starts a real TCP listener on 127.0.0.1:<port>
before booting the VM); assert the sandbox cannot connect.
  - *Consequence if unasserted:* Distinguishes "blocked by isolation" from "nothing
listening." The listener test guards against future
implementation changes — a regression that gave the sandbox
routable paths to the host would silently break isolation
but pass the arbitrary-port test.
- **`test_arbitrary_host_port_unreachable`** — An unused port (44444) on the host is unreachable.
  - *Probe:* TCP connect to host:44444; assert fail.
  - *Consequence if unasserted:* Together with test_host_listener_unreachable, confirms
block-by-default — an arbitrary port nothing listens on
should still be unreachable (not just refused by the
kernel because no service is bound). Complements the
live-listener test for full coverage.
- **`test_cross_agent_ip_unreachable`** — Adjacent agents' attribution IPs are unreachable.
  - *Probe:* Derive this agent's attribution IP (10.200.x.y) from
loopback; probe TCP on the neighbouring ±1 offsets; assert
both unreachable.
  - *Consequence if unasserted:* Each agent runs in an isolated netns with its own
loopback. If one agent could reach another's attribution
IP, cross-agent lateral movement would be possible — an
agent compromised by the user's content could pivot to a
neighbouring agent's workspace.
- **`test_sinkhole_direct_unreachable`** — The live sinkhole HTTP, HTTPS, and control paths are unreachable.
  - *Probe:* TCP connect to each harness origin and control path. On VZ,
HTTP and control share one listener; both probes use that port.
  - *Consequence if unasserted:* Sinkhole ports bind 0.0.0.0 during test runs, so they
ARE listening — unlike the 44444 test. A direct sandbox →
sinkhole connect succeeding here would mean the isolation
boundary has a real hole, not just absence of services.

#### TestGuestPrivilegeBoundary — Guest privilege remains inside the sandbox boundary.

**Threat:** Agents start as uid 1000 but may need guest root to install
packages. On Linux that root is deliberately namespace-root,
mapped to an unprivileged subordinate host uid. Kernel modules,
host memory, and eBPF remain unavailable regardless of guest uid.

- **`test_expected_uid`** — Agent process runs as uid 1000.
  - *Probe:* os.getuid() == 1000.
  - *Consequence if unasserted:* The attribution chain (listener ownership, bind-mount
ownership, userns mapping) all assume uid 1000 inside the
sandbox. A different uid means ownership mismatches and
identity confusion.
- **`test_privilege_transition_matches_platform_contract`** — Guest-root transition follows the platform's isolation model.
  - *Probe:* On a hardware microVM, direct setuid(0) must fail. On
Linux gVisor, setpriv must reach uid 0 inside the sandbox;
the host-side uid-map test separately proves this maps to a
subordinate uid rather than host root.
  - *Consequence if unasserted:* Package installation needs an intentional guest-root
path, while treating namespace-root as host root would both
break that feature and test the wrong security boundary.
- **`test_sudo_reaches_guest_root`** — The standard sudo command reaches root only inside the guest.
  - *Probe:* Run `sudo -n id -u` as the agent and require uid 0. On
gVisor the SafeYolo shim uses namespace capabilities; on a
hardware microVM the distro's normal sudo transition applies.
  - *Consequence if unasserted:* Agents need a familiar, non-operator-mediated way to
install native packages without confusing host root with
sandbox or VM root.
- **`test_kernel_modules_disabled`** — init_module(2) syscall returns non-success.
  - *Probe:* Direct syscall to init_module with null args; assert
return value is -1 and errno non-zero.
  - *Consequence if unasserted:* Loading a kernel module is immediate, total compromise
— the module runs in ring 0. Blocked either by
CONFIG_MODULES=n in the guest kernel, or by gVisor's
user-space kernel rejecting the syscall.
- **`test_no_dev_mem`** — /dev/mem does not exist in the sandbox.
  - *Probe:* os.path.exists("/dev/mem") is False.
  - *Consequence if unasserted:* /dev/mem is a direct view of physical RAM. If present
and readable, the agent can dump kernel data structures and
potentially extract secrets from other processes.
- **`test_no_dev_kmem`** — /dev/kmem does not exist in the sandbox.
  - *Probe:* os.path.exists("/dev/kmem") is False.
  - *Consequence if unasserted:* /dev/kmem exposes kernel virtual memory directly —
easier to parse than /dev/mem and equally dangerous for
secret extraction.
- **`test_ebpf_blocked`** — bpf(2) syscall fails.
  - *Probe:* Invoke syscall numbers 321 (x86_64) and 280 (aarch64)
for SYS_bpf with zero args; if any returns 0, fail.
  - *Consequence if unasserted:* eBPF programs run in kernel context with wide access —
network introspection, kprobe instrumentation, cgroup
hooks. Even with verifier constraints, eBPF has been a
recurring privilege-escalation vector.

#### TestSandboxRootContainment — Linux namespace-root cannot cross SafeYolo's host boundary.

**Threat:** Allowing agents to install distro packages intentionally
grants root inside gVisor. The security property is therefore
containment: namespace-root must still be unable to modify the
host config share, reach host listeners, inspect host processes,
or access host devices.

- **`test_config_share_stays_readonly_as_sandbox_root`** — Sandbox root cannot write the host-backed config share.
  - *Probe:* Elevate with setpriv and attempt to create a file under
/safeyolo; require the write to fail and the path to remain
absent.
  - *Consequence if unasserted:* If namespace-root can modify this host bind mount it can
tamper with proxy configuration or guest bootstrap state,
turning guest package installation into host-state mutation.
- **`test_host_listener_stays_unreachable_as_sandbox_root`** — Sandbox root cannot connect to a live host TCP listener.
  - *Probe:* Elevate with setpriv, read the harness listener endpoint,
and attempt a direct TCP connection to
the harness's known-live host listener; require failure.
  - *Consequence if unasserted:* Guest root must not turn the loopback-only network
namespace into a path to host services or the admin API.
- **`test_host_kernel_surfaces_stay_absent_as_sandbox_root`** — Sandbox root sees neither host devices nor the host PID 1.
  - *Probe:* Elevate with setpriv, assert /dev/kvm, /dev/mem and
/dev/kmem are absent, then assert PID 1's command line is not
a host init such as systemd or launchd.
  - *Consequence if unasserted:* Exposing a host device or process namespace to guest root
would convert an intentionally useful guest capability into a
direct host-compromise primitive.

#### TestFilesystemIsolation — Config share mount is read-only and holds no private keys.

**Threat:** /safeyolo contains configuration and agent metadata from
the host. It is mounted read-only so a compromised agent can't
write back to the host's config, and must never contain private
key material that a TLS-intercept attack would benefit from.

- **`test_config_share_readonly`** — Writes to /safeyolo raise OSError.
  - *Probe:* open("/safeyolo/test-write-attempt", "w") under
pytest.raises(OSError).
  - *Consequence if unasserted:* A writable config share would let the agent modify
its own configuration (proxy settings, policy files) and
potentially affect the host's view of agent state. Must
be read-only.
- **`test_no_private_key_in_config_share`** — No file in /safeyolo contains PRIVATE KEY markers or has .key suffix.
  - *Probe:* List /safeyolo files; reject any whose name contains
'private' or ends in '.key', or whose first 500 bytes
contain 'PRIVATE KEY'.
  - *Consequence if unasserted:* The CA private key is the root of trust for TLS
interception. A stray copy on the config share is
game-over for cert verification.

#### TestSandboxExposure — Sandbox surfaces (/dev, /proc, PID namespace) expose nothing useful.

**Threat:** A hardened sandbox minimises what the adversary can inspect
or manipulate. Each leaked surface — an unexpected device node,
a readable /proc/kcore, a full host process list — is a rung on
the escalation ladder. These probes test the reduction, not the
mechanism (which varies between gVisor and VZ).

- **`test_dev_whitelist`** — Every /dev entry is on the expected whitelist.
  - *Probe:* Enumerate /dev; compare against the expected set
(plus prefixed exceptions for microVMs). If /dev/log exists,
verify it is a guest-root-owned socket. Assert no unexpected
entries.
  - *Consequence if unasserted:* Novel device entries are attack surface. This test is
deliberately allowlist-based rather than blocklist-based —
if the runtime adds a new device, the test fails until a
human evaluates whether it should be there.
- **`test_proc_kcore_unreadable`** — /proc/kcore is absent or unreadable.
  - *Probe:* Skip if /proc/kcore doesn't exist; otherwise, open
it under pytest.raises(PermissionError/OSError).
  - *Consequence if unasserted:* /proc/kcore is a live view of kernel memory as an ELF
core dump. Reading it leaks kernel data structures and
credentials from other processes.
- **`test_proc_kallsyms_redacted`** — /proc/kallsyms (if readable) shows addresses redacted to zero.
  - *Probe:* Read first 50 lines of /proc/kallsyms; assert every
line starts with '0000000000000000'.
  - *Consequence if unasserted:* Unredacted kernel symbol addresses give attackers
exact offsets for ROP/JOP gadgets — a major leg-up for
kernel-exploit chains. Modern kernels redact to zero for
unprivileged readers; this test catches regressions.
- **`test_sys_kernel_debug_inaccessible`** — /sys/kernel/debug is absent or unreadable.
  - *Probe:* Skip if /sys/kernel/debug doesn't exist; else, call
os.listdir() under pytest.raises(PermissionError/OSError).
  - *Consequence if unasserted:* debugfs/tracefs expose kernel internals (probes, event
tracers, module lists). A listable /sys/kernel/debug is a
broad surface for kernel introspection and — via tracefs —
a privilege-escalation vector.
- **`test_pid_namespace_isolated`** — PID 1's cmdline is the sandbox init, not the host's.
  - *Probe:* Read /proc/1/cmdline; assert it does NOT contain
'systemd', '/sbin/init', or 'launchd'.
  - *Consequence if unasserted:* If PID 1 is the host's init, the PID namespace is
leaking through and the agent can read the full host
process table — every running service's cmdline, including
argv secrets and parent hierarchies.
- **`test_firewall_rules_not_readable`** — iptables/pfctl don't emit rules from inside the sandbox.
  - *Probe:* Run `iptables -L`, `iptables-save`, `pfctl` if present;
fail if any exits 0 with non-empty output.
  - *Consequence if unasserted:* An agent that can enumerate host firewall rules learns
exactly which ports/IPs are reachable via which path — a
map of the egress surface to probe. Also implies CAP_NET_ADMIN,
which the sandbox must not have.
- **`test_host_ssh_not_reachable_via_sandbox_sshd`** — No SSH private keys are present in the sandbox filesystem.
  - *Probe:* Check /root/.ssh/ and /home/agent/.ssh/ for id_ed25519
or id_rsa; fail if any exists.
  - *Consequence if unasserted:* Defence-in-depth. The sandbox runs sshd for inbound
operator access, but must not possess client private keys
that could be used to ssh OUT to the host or another agent.
A leaked private key turns the sandbox into a lateral-
movement pivot.

#### TestFilesystemBoundary — Workspace mount cannot expose host files or host devices.

**Threat:** /workspace is a shared surface between agent and host. If
the agent can create usable device nodes or symlinks that leak
outside the mount, it can trick the host mount implementation into
exposing resources beyond /workspace. Guest-root access itself is
tested as an intended capability in test_root_containment.py.

- **`test_workspace_symlink_traversal`** — Symlink to /etc/shadow inside /workspace doesn't reach host files.
  - *Probe:* Create /workspace/.../shadow-link → /etc/shadow; try
to read it. If readable, assert it resolves to the same guest
inode and bytes as opening /etc/shadow directly.
  - *Consequence if unasserted:* virtiofs/lisafs gofer mounts are supposed to contain
traversal within the sandbox rootfs. A bug that followed
symlinks on the host side would let the agent read any host
file the mount process can see — /etc/shadow, SSH keys,
cloud credentials.
- **`test_workspace_no_mknod`** — mknod on /workspace fails with PermissionError/OSError.
  - *Probe:* os.mknod('/workspace/.../testdev', S_IFCHR, makedev(1,3));
assert the call fails.
  - *Consequence if unasserted:* /workspace should be mounted `nodev` and the sandbox
should lack CAP_MKNOD. Device nodes on a shared mount let
the agent access arbitrary devices (raw block devices like
/dev/sda, tty, etc.) once the host views the file.

#### TestSyscallSeccompEquivalents — Dangerous syscalls (keyring, pivot_root, unshare, ptrace) are blocked or contained.

**Threat:** A conservative container seccomp baseline drops ~44
syscalls that are rarely legitimate and historically exploited
— kernel keyring injection (CVE-2017-6074), pivot_root
filesystem escape, user-namespace creation as escalation
vehicle, ptrace process introspection. Blackbox checks confirm
the same
exposures are closed on the current runtime (gVisor or VZ).

- **`test_keyctl_blocked`** — A valid keyctl request is unavailable or permission denied.
  - *Probe:* Request this thread's keyring with creation enabled. Require
ENOSYS, EPERM or EACCES after a successful getpid syscall control.
  - *Consequence if unasserted:* This valid request needs no existing key or special privilege
on an unrestricted kernel. Invalid arguments and a missing key do
not establish refusal of access to the kernel keyring.
- **`test_add_key_blocked`** — A valid add_key request is unavailable or permission denied.
  - *Probe:* Add a user key with a valid payload to this thread's keyring.
Require ENOSYS, EPERM or EACCES after a successful getpid control.
  - *Consequence if unasserted:* Keep add_key distinct from keyctl and reject bad pointers as
proof that the sandbox refuses key creation.
- **`test_pivot_root_blocked`** — pivot_root(2) returns -1 with non-zero errno.
  - *Probe:* Call SYS_pivot_root with zero args; assert ret == -1
and errno != 0.
  - *Consequence if unasserted:* pivot_root moves the root filesystem — combined with
a mount from an attacker-controlled directory, it's a
classic container escape. Must not be callable from the
sandbox.
- **`test_unshare_user_ns_contained`** — unshare(CLONE_NEWUSER) grants no new access even if it succeeds.
  - *Probe:* Call unshare with CLONE_NEWUSER. If it fails, pass
(strongest outcome). If it succeeds, verify /etc/shadow is
still unreadable, PID 1's cmdline still doesn't reveal host
init, and /safeyolo is still read-only.
  - *Consequence if unasserted:* gVisor's sentry emulates namespaces, and VZ microVMs
run real kernels — both allow the syscall. The property
that matters is that the new namespace doesn't grant
privileges the agent didn't already have. Tests the
escape, not the syscall.
- **`test_ptrace_init_blocked`** — ptrace(PTRACE_ATTACH, 1, ...) returns -1.
  - *Probe:* Call SYS_ptrace with PTRACE_ATTACH on pid 1; assert
ret == -1 and errno != 0.
  - *Consequence if unasserted:* Attaching to init lets the agent read memory (keys,
tokens) from the most privileged process in the sandbox
and potentially inject code. Conservative container seccomp
baselines drop ptrace entirely.
