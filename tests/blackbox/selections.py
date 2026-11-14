"""Shared installed section, driver and pytest selections.

The runners execute these selections; the catalogue and receipt reader inspect
the same names. Platform exclusions are explicit and do not hide missing setup.
"""

SECTIONS = {
    "systrap": ("isolation", "workloads", "access", "peer-support", "shared-approvals", "provider", "federation", "lifecycle", "continuity"),
    "kvm": ("isolation", "ingress", "workloads"),
    "vz": ("isolation", "access", "lifecycle", "continuity"),
}
OPTIONAL_SECTIONS = {"systrap": ("claude", "ingress"), "kvm": (), "vz": ()}

PYTEST_PHASES = {
    "native": ("host", ("tests/blackbox/host/native",)),
    "security": ("host", ("tests/blackbox/host/security",)),
    "identity": ("host", ("tests/blackbox/host/identity",)),
    "guest-agent": ("guest-agent", ("tests/blackbox/isolation", "--ignore=tests/blackbox/isolation/test_root_containment.py")),
    "guest-root": ("guest-root", (
        "tests/blackbox/isolation/test_root_containment.py",
        "tests/blackbox/isolation/test_key_isolation.py::TestPrivateKeyAbsent",
    )),
    "host-lifecycle": ("host", ("tests/blackbox/host/lifecycle",)),
    "listener-restart": ("host", (
        "tests/blackbox/host/lifecycle/test_host_listener.py",
        "tests/blackbox/host/lifecycle/test_token_lifecycle.py",
    )),
    "proxy": ("host", ("tests/proxy_contracts",)),
    "package-tls": ("host", ("tests/proxy_contracts/test_https_contract.py::test_https_origin_verification",)),
    "listener-ordinary": ("guest-agent", (
        "tests/blackbox/isolation/test_vm_isolation.py::TestHostAdjacentReachability::test_host_listener_unreachable",
        "tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_proxy_reachable",
    )),
    "listener-guest-root": ("guest-root", (
        "tests/blackbox/isolation/test_root_containment.py::TestGuestRootContainment::test_root_cannot_reach_live_host_listener",
        "tests/blackbox/isolation/test_root_containment.py::TestGuestRootContainment::test_root_proxy_path_works",
    )),
    "listener-sandbox-root": ("guest-agent", (
        "tests/blackbox/isolation/test_vm_isolation.py::TestSandboxRootContainment::test_host_listener_stays_unreachable_as_sandbox_root",
        "tests/blackbox/isolation/test_vm_isolation.py::TestNetworkEscape::test_proxy_reachable",
    )),
}

# A completed procedure records these names after the corresponding assertions.
# A terminal status or zero exit without every named checkpoint is insufficient.
PROCEDURES = {
    "ingress": ("installed_ingress.py", ("identity", "policy", "guest", "origin", "finished")),
    "ingress-pair": ("installed_ingress_pair.py", ("identity", "user-and-root", "restart", "finished")),
    "workloads": ("installed_workloads.py", ("identity", "package-repo", "sse", "wss-ssh", "origin", "finished")),
    "access": ("installed_access.py", ("identity", "service", "contract", "flow-ownership", "coord", "origin", "desktop-sharing", "finished")),
    "lifecycle": ("installed_lifecycle.py", ("identity", "listener", "tls", "restart", "drain", "recovery", "finished")),
    "continuity": ("installed_state_transition.py", ("initial", "restart", "replacement", "return", "cleanup", "finished")),
    "peer-support": ("installed_peer_support.py", ("identity", "scope", "permitted-effect", "replay", "stale-run", "narrow-expire-revoke", "finished")),
    "shared-approvals": ("installed_shared_approvals.py", ("identity", "scope", "permitted-effect", "expire-revoke", "stale-run", "gateway-route", "finished")),
    "provider": ("installed_provider.py", ("identity", "scope", "delivery", "revoke-recover", "closed-stopped", "observer", "finished")),
    "native-authority": ("native_authority.py", ("selected-cases", "finished")),
    "federation": ("installed_federation.py", ("identity", "scope", "destination-effect", "revocation", "finished")),
}

SECTION_DRIVERS = {
    "isolation": tuple(PYTEST_PHASES)[:6],
    **{name: (name,) for name in PROCEDURES if name not in {"ingress-pair", "native-authority"}},
    "claude": ("claude_smoke.py",),
}

# Each case owns isolated native instances and a real pinned NATS broker.
# Model, human-interaction, long-duration and child-helper tests remain opt-in.
NATIVE_AUTHORITY = {
    "BB-24": (
        "work::native_work_claims_replay_identity_revocation_and_crash_recovery",
        "attestations::native_attestations_exact_candidate_authorship_replay_and_recovery",
        "outputs::retained_external_outputs_recover_once_or_reject_stale_publication",
        "reviews::code_and_report_checks_challenges_corrections_and_independent_dispositions",
        "factory::factory_selection_enforces_native_obligations_for_direct_callers",
        "continuation::continuation_recovers_once_and_retains_delivery_across_restart",
    ),
    "BB-25": (
        "federation::two_safeyolos_share_only_home_authority_across_partition_restart_and_revocation",
        "federation::support::authenticated_mutation_misrouted_to_another_trusted_instance_has_no_effect",
        "federation::support::remote_support_uses_owner_grants_receipts_and_independent_attention_sources",
        "federation::operator::remote_saved_deciding_authority_preserves_the_canonical_pending_record",
        "federation::modes::renewal_and_explicit_rotation_preserve_retained_state_and_report_activation",
        "federation::modes::same_path_peer_rotation_reports_restart_until_broker_loads_new_credentials",
    ),
}

# These checks assert gVisor-specific behavior. VZ has a real guest kernel.
# Match only named cases, never every skip on a platform.
PLATFORM_EXCLUSIONS = (
    ("vz", "identity", "*::test_sandbox_root_maps_to_subordinate_host_uid", "VZ uses a separate guest kernel, not a host user namespace."),
    ("vz", "guest-agent", "*::TestSandboxRootContainment::*", "The setpriv/user-namespace controls apply to gVisor."),
    ("vz", "guest-root", "*::test_gvisor_root_cannot_access_host_kvm_device", "The host KVM device control applies to gVisor."),
    ("vz", "host-lifecycle", "*::test_live_host_listener_refused[[]sandbox-root]", "The namespace-root listener control applies to gVisor."),
    ("vz", "listener-restart", "*::test_live_host_listener_refused[[]sandbox-root]", "The namespace-root listener control applies to gVisor."),
)

# Existing opt-in checks retain their explicit selection; other skips remain failures.
OPTIONAL_CASES = (
    ('tests/proxy_contracts/test_native_harness_attention.py::test_claude_streaming_idle_busy_recovery_and_attribution', 'SAFEYOLO_CLAUDE_ATTENTION_MODEL', '', 'select an authorized real native Claude model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_pi_canonical_event_wakes_idle_native_session', 'SAFEYOLO_PI_ATTENTION_MODEL', '', 'select an authorized real Pi model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_pi_delivery_during_a_controlled_native_tool', 'SAFEYOLO_PI_ATTENTION_MODEL', '', 'select an authorized real Pi model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_pi_context_canonical_restart_and_operator_attribution', 'SAFEYOLO_PI_ATTENTION_MODEL', '', 'select an authorized real Pi model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_codex_canonical_event_wakes_idle_native_session', 'SAFEYOLO_CODEX_ATTENTION_MODEL', '', 'select an authorized real Codex model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_codex_delivery_during_a_controlled_native_tool', 'SAFEYOLO_CODEX_ATTENTION_MODEL', '', 'select an authorized real Codex model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_codex_context_canonical_restart_and_operator_attribution', 'SAFEYOLO_CODEX_ATTENTION_MODEL', '', 'select an authorized real Codex model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_gemini_canonical_event_wakes_idle_native_session', 'SAFEYOLO_GEMINI_ATTENTION_MODEL', '', 'select an authorized real Gemini model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_gemini_delivery_during_a_controlled_native_tool', 'SAFEYOLO_GEMINI_ATTENTION_MODEL', '', 'select an authorized real Gemini model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_gemini_explicit_fallback_without_inference', 'SAFEYOLO_GEMINI_ATTENTION_MODEL', '', 'select an authorized real Gemini model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_gemini_canonical_restart_duplicates_and_operator_attribution', 'SAFEYOLO_GEMINI_ATTENTION_MODEL', '', 'select an authorized real Gemini model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_hermes_canonical_event_wakes_idle_native_session', 'SAFEYOLO_HERMES_ATTENTION_MODEL', '', 'select an authorized real Hermes model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_hermes_delivery_during_a_controlled_native_tool', 'SAFEYOLO_HERMES_ATTENTION_MODEL', '', 'select an authorized real Hermes model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_hermes_canonical_restart_and_operator_attribution', 'SAFEYOLO_HERMES_ATTENTION_MODEL', '', 'select an authorized real Hermes model explicitly'),
    ('tests/proxy_contracts/test_native_harness_attention.py::test_hermes_explicit_fallback_and_scoped_catalog_without_inference', 'SAFEYOLO_HERMES_ATTENTION_MODEL', '', 'select a configured native Hermes profile explicitly'),
    ('tests/proxy_contracts/test_http2_gate_timing.py::test_idle_session_closes_at_origin_and_next_stream_reconnects', 'SAFEYOLO_H2_GATE_LIFECYCLE', '1', 'real idle timeout witness is opt-in'),
    ('tests/proxy_contracts/test_http2_gate_timing.py::test_100_warm_batches_direct_and_intercepted', 'SAFEYOLO_H2_GATE_BENCHMARK', '1', 'controlled timing lane is opt-in'),
    ('tests/proxy_contracts/test_policy_authoring.py::test_installed_real_provider_and_research_run', 'SAFEYOLO_REAL_RESEARCH', '1', 'explicit bounded real provider/research run'),
    ('tests/proxy_contracts/test_tunnel_contract.py::test_real_openssh_preserves_server_first_output_and_client_input', 'SAFEYOLO_RUN_SSH_CONTRACT', '1', 'Opt-in owned OpenSSH daemon; requires installed ssh, ssh-keygen and sshd'),
    ('tests/proxy_contracts/test_native_skill_trace.py::test_untraced_request_timing_against_prepared_baseline', 'SAFEYOLO_TRACE_OVERHEAD_BASELINE', '', 'manual ordinary-request comparison needs a prepared baseline executable'),
    ('tests/proxy_contracts/test_native_factory_cli.py::test_factory_run_executes_staged_worker_commands', 'SAFEYOLO_FACTORY_ACCEPTANCE_ROOT', '', 'Explicit disposable installed Factory acceptance root.'),
    ('tests/proxy_contracts/test_native_factory_cli.py::test_factory_setup_interruption_preserves_prepared_roles', 'SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE', '', 'Explicit disposable installed guided-setup acceptance root.'),
    ('tests/proxy_contracts/test_native_provider_recovery.py::test_authorized_provider_survives_only_its_holder_loss', 'SAFEYOLO_971_RUNSC', '', 'Explicit prepared provider-recovery Linux venue.'),
)

# Current native-process fixtures which explicitly require Linux.
HOST_EXCLUSIONS = (
    ('darwin', 'tests/proxy_contracts/test_codex_approval_fallback.py::*', 'Linux-specific installed/process fixture; no macOS claim.'),
    ('darwin', 'tests/proxy_contracts/test_native_managed_state.py::*', 'Linux-specific installed/process fixture; no macOS claim.'),
    ('darwin', 'tests/proxy_contracts/test_native_policy_cli.py::*', 'Linux-specific installed/process fixture; no macOS claim.'),
    ('darwin', 'tests/proxy_contracts/test_selected_ip.py::*', 'Linux-specific installed/process fixture; no macOS claim.'),
    ('darwin', 'tests/proxy_contracts/test_outbound_effects.py::*', 'Linux-specific installed/process fixture; no macOS claim.'),
    ('darwin', 'tests/proxy_contracts/test_installed_shared_approvals.py::*', 'Linux-specific installed/process fixture; no macOS claim.'),
    ('darwin', 'tests/proxy_contracts/test_service_route_challenge.py::*', 'Linux-specific installed/process fixture; no macOS claim.'),
    ('darwin', 'tests/proxy_contracts/test_agent_api_contract.py::test_agent_api_response_survives_canonical_worker_write_failure', 'Requires /dev/full to inject a real write failure'),
    ('darwin', 'tests/proxy_contracts/test_gateway_provider.py::test_gateway_routes_only_authorized_calls_to_provider_stream', 'Fake runsc provider fixture requires Linux'),
    ('darwin', 'tests/proxy_contracts/test_heap_release.py::test_periodic_release_preserves_capture_and_live_requests', 'the correction uses GNU/Linux malloc_trim'),
    ('darwin', 'tests/proxy_contracts/test_native_blackbox_lifecycle.py::test_native_start_waits_for_verified_readiness_and_bounds_owned_child', 'the owned-child probe uses Linux procfs'),
    ('darwin', 'tests/proxy_contracts/test_native_coord_operator.py::test_supervisor_events_reach_coord_and_live_watch', 'Model-turn execution belongs to the Linux guest, including VZ guests'),
    ('darwin', 'tests/proxy_contracts/test_native_coord_operator.py::test_agent_watch_real_supervisor_restart_and_thread_replacement', 'the supervised executable runs in the Linux guest'),
    ('darwin', 'tests/proxy_contracts/test_native_provider_recovery.py::test_authorized_provider_survives_only_its_holder_loss', 'requires the selected native bundle and an owned Linux runsc/rootfs host'),
    ('darwin', 'tests/proxy_contracts/test_operational_events.py::test_guest_metadata_cannot_spoof_host_or_a_different_generation', 'The guest/process control requires Linux; VZ uses the installed driver.'),
    ('darwin', 'tests/proxy_contracts/test_operational_events.py::test_guest_source_survives_abrupt_child_and_owner_exit', 'The guest/process control requires Linux; VZ uses the installed driver.'),
)
