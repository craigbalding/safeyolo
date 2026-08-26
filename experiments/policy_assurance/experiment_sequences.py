"""Experiment: generated mutation sequences against live and persisted policy."""

from __future__ import annotations

import tempfile
from collections import deque
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, Phase, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from experiments.policy_assurance.harness import (
    PolicyWorld,
    engine_from_path,
    make_world,
    permission_surface,
    surface_for_path,
    write_policy,
)
from experiments.policy_assurance.strategies import (
    agent_names,
    credential_names,
    host_names,
)

INITIAL_AGENTS = ("atlas", "boris", "cody")
INITIAL_HOSTS = (
    "api.alpha.example",
    "blocked.example",
    "review.example",
    "private.alpha.example",
)
INITIAL_CREDENTIALS = ("alpha", "beta", "gamma")


class PolicyMutationMachine(RuleBasedStateMachine):
    """Exercise broad operation sequences while enforcing narrow boundaries."""

    def __init__(self) -> None:
        super().__init__()
        self._temporary = tempfile.TemporaryDirectory(prefix="safeyolo-policy-experiment-")
        self.path = Path(self._temporary.name) / "policy.toml"
        # One recent generated value per dimension keeps each transaction probe
        # modest. Breadth comes from generated examples and operation sequences,
        # rather than an ever-growing Cartesian product inside every step.
        self.recent_agents = deque(maxlen=1)
        self.recent_hosts = deque(maxlen=1)
        self.recent_credentials = deque(maxlen=1)
        initial = make_world(INITIAL_AGENTS, INITIAL_HOSTS, INITIAL_CREDENTIALS)
        write_policy(self.path, initial.policy)
        self.engine = engine_from_path(self.path)

    def _world(self) -> PolicyWorld:
        agents = tuple(dict.fromkeys((*INITIAL_AGENTS, *self.recent_agents)))
        hosts = tuple(dict.fromkeys((*INITIAL_HOSTS, *self.recent_hosts)))
        credentials = tuple(dict.fromkeys((*INITIAL_CREDENTIALS, *self.recent_credentials)))
        # Permission probing only needs names; the file is the source of the policy.
        return PolicyWorld({}, agents, hosts, credentials)

    def _surface(self):
        return permission_surface(self._world(), engine=self.engine, broad=False)

    def _track(self, agent: str, host: str, credential: str | None = None) -> None:
        self.recent_agents.append(agent)
        self.recent_hosts.append(host)
        if credential:
            self.recent_credentials.append(credential)

    def _assert_only_agent_changed(self, before, target_agent: str) -> None:
        changed = before.changed(self._surface())
        assert all(probe.kind != "network" or probe.agent == target_agent for probe in changed), changed

    @rule(agent=agent_names, host=host_names, with_rate=st.booleans())
    def add_agent_allowance(self, agent: str, host: str, with_rate: bool) -> None:
        self._track(agent, host)
        before = self._surface()
        self.engine.add_host_allowance(
            host,
            rate=100_000 if with_rate else None,
            agent=agent,
        )
        self._assert_only_agent_changed(before, agent)

    @rule(agent=agent_names, host=host_names)
    def add_agent_denial(self, agent: str, host: str) -> None:
        self._track(agent, host)
        before = self._surface()
        self.engine.add_host_denial(host, agent=agent)
        self._assert_only_agent_changed(before, agent)

    @rule(host=host_names, with_rate=st.booleans())
    def add_baseline_allowance(self, host: str, with_rate: bool) -> None:
        self.recent_hosts.append(host)
        self.engine.add_host_allowance(host, rate=100_000 if with_rate else None)

    @rule(host=host_names)
    def add_baseline_denial(self, host: str) -> None:
        self.recent_hosts.append(host)
        self.engine.add_host_denial(host)

    @rule(host=host_names, credential=credential_names)
    def add_credential_approval(self, host: str, credential: str) -> None:
        self.recent_hosts.append(host)
        self.recent_credentials.append(credential)
        self.engine.add_credential_approval(host, f"{credential}:*")

    @rule()
    def reload_active_policy(self) -> None:
        assert self.engine._loader.reload()

    @invariant()
    def active_policy_matches_durable_policy(self) -> None:
        active = self._surface()
        durable = surface_for_path(self.path, self._world(), broad=False)
        assert active.changed(durable) == {}

    def teardown(self) -> None:
        self.engine.done()
        self._temporary.cleanup()


PolicyMutationMachine.TestCase.settings = settings(
    max_examples=12,
    stateful_step_count=10,
    deadline=None,
    # Full state-machine shrinking repeatedly reparses an expanding TOML file
    # and took longer than the experiment itself. Seeded generation preserves
    # replayability; a focused regression should minimize any accepted finding.
    phases=(Phase.generate,),
    suppress_health_check=(HealthCheck.too_slow,),
)
TestPolicyMutationMachine = PolicyMutationMachine.TestCase


def test_known_finding_no_rate_allowance_is_durable(tmp_path: Path) -> None:
    """Focused replay: an allowance reported live must survive a reload."""
    world = make_world(INITIAL_AGENTS, INITIAL_HOSTS, INITIAL_CREDENTIALS)
    path = tmp_path / "policy.toml"
    write_policy(path, world.policy)
    engine = engine_from_path(path)
    host = "known-no-rate.example"
    observed_world = PolicyWorld(
        world.policy,
        world.agents,
        (*world.hosts, host),
        world.credentials,
    )

    engine.add_host_allowance(host, agent=world.owner)
    active = permission_surface(observed_world, engine=engine, broad=False)
    durable = surface_for_path(path, observed_world, broad=False)
    assert active.changed(durable) == {}


def test_failed_persistence_cannot_report_success(tmp_path: Path) -> None:
    """A mutation must not become live or report success if durable save fails."""
    world = make_world(INITIAL_AGENTS, INITIAL_HOSTS, INITIAL_CREDENTIALS)
    path = tmp_path / "policy.toml"
    write_policy(path, world.policy)
    engine = engine_from_path(path)
    original_bytes = path.read_bytes()
    before = permission_surface(world, engine=engine)

    with patch(
        "safeyolo.policy.toml_roundtrip.save_roundtrip",
        autospec=True,
        side_effect=OSError("injected persistence failure"),
    ):
        with pytest.raises(OSError, match="injected persistence failure"):
            engine.add_host_allowance("newly-approved.example", agent=world.owner)

    assert path.read_bytes() == original_bytes
    assert before.changed(permission_surface(world, engine=engine)) == {}
