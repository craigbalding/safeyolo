"""Experiment: how much security ground truth a broad decision surface detects."""

from __future__ import annotations

from copy import deepcopy

import pytest
import tomlkit
from hypothesis import HealthCheck, given, settings

from experiments.policy_assurance.defects import DEFECTS, Defect
from experiments.policy_assurance.harness import (
    EFFECT_RANK,
    PolicyWorld,
    permission_surface,
    toml_text,
)
from experiments.policy_assurance.strategies import policy_worlds
from safeyolo.policy.toml_normalize import normalize

EXPERIMENT_SETTINGS = settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=(HealthCheck.too_slow,),
)


@pytest.mark.parametrize("defect", DEFECTS, ids=lambda defect: defect.name)
@EXPERIMENT_SETTINGS
@given(world=policy_worlds())
def test_decision_surface_detects_catalogue_defects(
    defect: Defect,
    world: PolicyWorld,
) -> None:
    """Every catalogue corruption must alter at least one effective decision."""
    before = permission_surface(world)
    corrupt_world = PolicyWorld(
        defect.mutate(world),
        world.agents,
        world.hosts,
        world.credentials,
    )
    after = permission_surface(corrupt_world)

    changed = before.changed(after)
    assert changed, (
        f"decision surface missed {defect.name} ({defect.threat}); "
        "expand probes or replace a defect that has no authorization consequence"
    )


@EXPERIMENT_SETTINGS
@given(world=policy_worlds())
def test_toml_round_trip_preserves_effective_decisions(world: PolicyWorld) -> None:
    """Formatting-preserving serialization must not alter authorization."""
    source = toml_text(world.policy)
    decorated = "# operator context must not affect enforcement\n" + source
    reparsed = normalize(tomlkit.parse(decorated).unwrap())
    round_tripped = PolicyWorld(
        reparsed,
        world.agents,
        world.hosts,
        world.credentials,
    )

    assert permission_surface(world).changed(permission_surface(round_tripped)) == {}


@EXPERIMENT_SETTINGS
@given(world=policy_worlds())
def test_agent_approval_changes_only_selected_scope(world: PolicyWorld) -> None:
    """A generated agent approval may broaden only one agent/host tuple."""
    before = permission_surface(world)
    policy = deepcopy(world.policy)
    target = world.prompt_host
    policy["agents"][world.owner]["hosts"][target] = {"rate_limit": 100_000}
    after = permission_surface(PolicyWorld(policy, world.agents, world.hosts, world.credentials))

    changed = before.changed(after)
    broadened = before.broadened(after)
    assert broadened, "the intended approval did not become effective"
    assert all(probe.kind == "network" and probe.agent == world.owner and probe.host == target for probe in changed), (
        changed
    )


@EXPERIMENT_SETTINGS
@given(world=policy_worlds())
def test_denial_never_increases_permission(world: PolicyWorld) -> None:
    """Adding a denial may change decisions, but never toward prompt or allow."""
    before = permission_surface(world)
    policy = deepcopy(world.policy)
    policy["hosts"][world.allow_host]["egress"] = "deny"
    after = permission_surface(PolicyWorld(policy, world.agents, world.hosts, world.credentials))

    for old, new in before.changed(after).values():
        assert EFFECT_RANK.get(new, -1) <= EFFECT_RANK.get(old, -1)
