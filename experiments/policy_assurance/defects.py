"""Threat-aligned corruptions used as ground truth for experiment comparison."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from experiments.policy_assurance.harness import PolicyWorld, clone_policy


@dataclass(frozen=True)
class Defect:
    name: str
    threat: str
    mutate: Callable[[PolicyWorld], dict[str, Any]]


def _agent_allow_leaks_to_baseline(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    config = policy["agents"][world.owner]["hosts"].pop(world.owned_host)
    policy["hosts"][world.owned_host] = config
    return policy


def _drop_agent_catchall_deny(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    del policy["agents"][world.owner]["egress"]
    return policy


def _write_to_wrong_agent(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    config = policy["agents"][world.owner]["hosts"].pop(world.owned_host)
    policy["agents"][world.peer]["hosts"][world.owned_host] = config
    return policy


def _broaden_credential(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    policy["hosts"][world.allow_host]["credentials"].append(f"{world.credentials[2]}:*")
    return policy


def _deny_becomes_prompt(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    policy["hosts"][world.deny_host]["egress"] = "prompt"
    return policy


def _delete_other_agent(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    del policy["agents"][world.peer]
    return policy


def _wildcard_becomes_prompt(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    policy["hosts"]["*"]["egress"] = "prompt"
    return policy


def _exact_allow_becomes_wildcard_budget(world: PolicyWorld) -> dict[str, Any]:
    policy = clone_policy(world.policy)
    policy["hosts"]["*"]["egress"] = "allow"
    policy["hosts"]["*"]["rate_limit"] = policy["hosts"][world.allow_host]["rate_limit"]
    return policy


DEFECTS = (
    Defect("agent_allow_leaks_to_baseline", "approval broadening", _agent_allow_leaks_to_baseline),
    Defect(
        "drop_agent_catchall_deny",
        "cross-agent precedence",
        _drop_agent_catchall_deny,
    ),
    Defect("write_to_wrong_agent", "cross-agent isolation", _write_to_wrong_agent),
    Defect("broaden_credential", "credential scope", _broaden_credential),
    Defect("deny_becomes_prompt", "fail-open effect", _deny_becomes_prompt),
    Defect("delete_other_agent", "unrelated data loss", _delete_other_agent),
    Defect("wildcard_becomes_prompt", "default posture", _wildcard_becomes_prompt),
    Defect("exact_allow_becomes_wildcard_budget", "wildcard broadening", _exact_allow_becomes_wildcard_budget),
)
