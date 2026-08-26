"""Independent clean mutation families; known defects live in focused replays."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import tomlkit
from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st

from experiments.policy_assurance.harness import (
    PolicyWorld,
    engine_from_path,
    make_world,
    observe_transaction,
    permission_surface,
    surface_for_path,
    write_policy,
)

INITIAL_AGENTS = ("atlas", "boris", "cody")
INITIAL_HOSTS = (
    "api.alpha.example",
    "blocked.example",
    "review.example",
    "private.alpha.example",
)
INITIAL_CREDENTIALS = ("alpha", "beta", "gamma")
SEQUENCE_SETTINGS = settings(
    max_examples=8,
    deadline=None,
    phases=(Phase.generate,),
    suppress_health_check=(HealthCheck.too_slow,),
)
HOST_OPERATIONS = st.lists(
    st.sampled_from(("rated_allow", "deny", "rate", "bypass", "remove", "reload")),
    min_size=1,
    max_size=8,
)


def _setup(tmp_path: Path):
    world = make_world(INITIAL_AGENTS, INITIAL_HOSTS, INITIAL_CREDENTIALS)
    path = tmp_path / "policy.toml"
    write_policy(path, world.policy)
    return world, path, engine_from_path(path)


def _assert_active_equals_disk(engine, path: Path, world: PolicyWorld) -> None:
    active = permission_surface(world, engine=engine, broad=False)
    durable = surface_for_path(path, world, broad=False)
    assert active.changed(durable) == {}


@SEQUENCE_SETTINGS
@given(operations=HOST_OPERATIONS)
def test_host_policy_sequences_are_independent(operations: list[str]) -> None:
    """Rated allows, denies, rates, bypasses, removals and reloads stay coherent."""
    with tempfile.TemporaryDirectory(prefix="policy-host-sequence-") as directory:
        temporary_path = Path(directory)
        world, path, engine = _setup(temporary_path)
        candidate = "generated.clean.example"
        os.environ["SAFEYOLO_CONFIG_DIR"] = str(temporary_path)
        try:
            for operation in operations:
                if operation == "rated_allow":
                    engine.add_host_allowance(candidate, rate=100_000)
                elif operation == "deny":
                    engine.add_host_denial(candidate)
                elif operation == "rate":
                    engine.update_host_rate(candidate, 200_000)
                elif operation == "bypass":
                    engine.add_host_bypass(candidate, "pattern-scanner")
                elif operation == "remove":
                    from safeyolo.commands.policy_host import host_remove

                    document = tomlkit.parse(path.read_text())
                    if candidate in document.get("hosts", {}):
                        host_remove(candidate, agent=None)
                        assert engine._loader.reload()
                else:
                    assert engine._loader.reload()
                _assert_active_equals_disk(engine, path, world)
        finally:
            engine.done()


@SEQUENCE_SETTINGS
@given(
    approvals=st.lists(
        st.tuples(
            st.sampled_from(("credentials.one.example", "credentials.two.example")),
            st.sampled_from(("alpha:*", "beta:*", "gamma:*")),
        ),
        min_size=1,
        max_size=6,
    )
)
def test_credential_approval_and_reload_sequences(
    approvals: list[tuple[str, str]],
) -> None:
    with tempfile.TemporaryDirectory(prefix="policy-credential-sequence-") as directory:
        world, path, engine = _setup(Path(directory))
        try:
            for host, credential in approvals:
                engine.add_credential_approval(host, credential)
                assert engine._loader.reload()
                _assert_active_equals_disk(engine, path, world)
        finally:
            engine.done()


def test_agent_metadata_save_remove_and_admin_service_changes(tmp_path: Path, monkeypatch) -> None:
    """Agent-store and Admin mutations preserve unrelated agents and policy."""
    world, path, engine = _setup(tmp_path)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))

    from pdp import PolicyClientConfig, configure_policy_client, reset_policy_client
    from safeyolo import agents_store
    from safeyolo.mitm_addons.admin_api import AdminRequestHandler
    from safeyolo.policy import toml_roundtrip

    agents_store.save_agent(
        "delta",
        {"egress": "deny", "folder": "/workspace/delta", "services": {}},
    )
    assert toml_roundtrip.load_agents(toml_roundtrip.load_roundtrip(path))["boris"]

    # Exercise the real Admin mutation wrapper and real configured PDP path.
    reset_policy_client()
    configure_policy_client(PolicyClientConfig(baseline_path=path))

    def add_service(agents):
        agents["delta"].setdefault("services", {})["mail"] = {
            "capability": "read",
            "token": "vault:mail",
        }

    try:
        AdminRequestHandler._policy_toml_mutate(add_service)
    finally:
        reset_policy_client()
    assert agents_store.load_agent("delta")["services"]["mail"]["capability"] == "read"
    assert agents_store.remove_agent("delta") is True
    assert "delta" not in agents_store.load_all_agents()
    assert engine._loader.reload()
    _assert_active_equals_disk(engine, path, world)


def test_gateway_grant_binding_addition_and_revocation(tmp_path: Path, monkeypatch) -> None:
    """Gateway persistence changes only the selected agent metadata."""
    world, path, engine = _setup(tmp_path)
    from safeyolo.mitm_addons.service_gateway import ServiceGateway

    gateway = ServiceGateway()
    monkeypatch.setattr(gateway, "_get_policy_path", lambda: path)
    grant = gateway.add_grant("atlas", "mail", "POST", "/messages", "session")
    binding = gateway.add_contract_binding(
        "atlas", "mail", "read", "tenant={tenant}", {"tenant": "one"}, ["GET /messages"]
    )
    assert gateway.revoke_grant(grant.grant_id)
    assert gateway.revoke_contract_binding(binding.binding_id)
    assert tomlkit.parse(path.read_text())
    assert engine._loader.reload()
    _assert_active_equals_disk(engine, path, world)


def test_shared_observation_captures_a_rated_agent_transaction(tmp_path: Path) -> None:
    """The shared observation records every evidence plane for one transaction."""
    world, path, engine = _setup(tmp_path)
    host = "observed.transaction.example"
    observation = observe_transaction(
        path,
        PolicyWorld(world.policy, world.agents, (*world.hosts, host), world.credentials),
        lambda: engine.add_host_allowance(host, rate=100_000, agent=world.owner),
        engine=engine,
        related=lambda probe: probe.kind == "network"
        and probe.agent == world.owner
        and probe.host in {host, host.upper(), f"child.{host}"},
    )
    assert observation.reported_success
    assert observation.original_hash != observation.final_hash
    assert observation.toml_valid
    assert observation.active_decisions is not None
    assert observation.fresh_process_decisions is not None
    assert observation.active_decisions.changed(observation.fresh_process_decisions) == {}
    assert observation.unrelated_preserved
    assert observation.audit_events
    assert observation.temporary_files == ()
