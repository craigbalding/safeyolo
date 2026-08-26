"""Staged transaction failures against shared and live-first writer paths."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from experiments.policy_assurance.harness import (
    PolicyWorld,
    append_observation,
    engine_from_path,
    make_world,
    observe_transaction,
    permission_surface,
    write_policy,
)


def _setup(tmp_path: Path):
    world = make_world(
        ("atlas", "boris", "cody"),
        ("api.alpha.example", "blocked.example", "review.example", "private.example"),
        ("alpha", "beta", "gamma"),
    )
    path = tmp_path / "policy.toml"
    write_policy(path, world.policy)
    engine = engine_from_path(path)
    host = "failure-stage.example"
    observed_world = PolicyWorld(world.policy, world.agents, (*world.hosts, host), world.credentials)
    return observed_world, path, engine, host


def _shared_mutation(path: Path, host: str, *, normalize: bool = False):
    from safeyolo.policy.toml_roundtrip import locked_policy_mutate, update_host_field
    from safeyolo.policy.toml_roundtrip import normalize as normalize_doc

    def mutate(document):
        if normalize:
            normalize_doc(document.unwrap())
        update_host_field(document, host, "rate", 100_000)

    return locked_policy_mutate(path, mutate)


def _fsync_failure(target_call: int):
    import os

    real_fsync = os.fsync
    calls = 0

    def injected(fd):
        nonlocal calls
        calls += 1
        if calls == target_call:
            raise OSError(f"injected fsync failure {target_call}")
        return real_fsync(fd)

    return injected


BEFORE_RENAME_STAGES = (
    "existing-file-parse",
    "normalization",
    "serialization",
    "temporary-write",
    "file-fsync",
    "rename",
)


@pytest.mark.parametrize("stage", BEFORE_RENAME_STAGES)
def test_precommit_failure_preserves_old_policy(tmp_path: Path, stage: str) -> None:
    world, path, engine, host = _setup(tmp_path)

    def operation():
        return _shared_mutation(path, host, normalize=stage == "normalization")

    if stage == "existing-file-parse":
        patcher = patch(
            "safeyolo.policy.toml_roundtrip.load_roundtrip",
            autospec=True,
            side_effect=ValueError("injected parse failure"),
        )
    elif stage == "normalization":
        patcher = patch(
            "safeyolo.policy.toml_roundtrip.normalize",
            autospec=True,
            side_effect=ValueError("injected normalization failure"),
        )
    elif stage == "serialization":
        patcher = patch(
            "safeyolo.policy.toml_roundtrip.tomlkit.dumps",
            autospec=True,
            side_effect=ValueError("injected serialization failure"),
        )
    elif stage == "temporary-write":
        patcher = patch(
            "safeyolo.policy.toml_roundtrip.tempfile.NamedTemporaryFile",
            autospec=True,
            side_effect=OSError("injected temporary write failure"),
        )
    elif stage == "file-fsync":
        patcher = patch("safeyolo.policy.toml_roundtrip.os.fsync", side_effect=_fsync_failure(1))
    else:
        patcher = patch(
            "safeyolo.policy.toml_roundtrip.shutil.move",
            autospec=True,
            side_effect=OSError("injected rename failure"),
        )

    with patcher:
        observation = observe_transaction(path, world, operation, engine=engine)

    assert not observation.reported_success
    assert observation.original_hash == observation.final_hash
    assert observation.toml_valid
    assert observation.active_decisions.changed(observation.fresh_process_decisions) == {}
    assert observation.unrelated_preserved
    assert not any(event.get("decision") == "allow" for event in observation.audit_events)


def test_directory_fsync_failure_leaves_complete_old_or_new_policy(tmp_path: Path) -> None:
    world, path, engine, host = _setup(tmp_path)
    before = permission_surface(world, engine=engine, broad=False)
    with patch(
        "safeyolo.policy.toml_roundtrip.os.fsync",
        side_effect=_fsync_failure(2),
    ):
        observation = observe_transaction(
            path,
            world,
            lambda: _shared_mutation(path, host),
            engine=engine,
            related=lambda probe: probe.kind == "network" and probe.host == host,
        )

    assert not observation.reported_success
    assert observation.toml_valid
    assert observation.final_hash != observation.original_hash
    # The live engine was never updated by this failed external operation.
    assert before is not None
    assert before.broadened(observation.active_decisions) == {}
    assert observation.unrelated_preserved


def test_reload_failure_cannot_report_success(tmp_path: Path) -> None:
    world, path, engine, host = _setup(tmp_path)
    with patch.object(engine._loader, "reload", autospec=True, return_value=False):
        observation = observe_transaction(
            path,
            world,
            lambda: engine.add_host_bypass(host, "pattern-scanner"),
            engine=engine,
        )
    assert not observation.reported_success
    assert observation.toml_valid


def test_audit_failure_is_recorded_separately_when_policy_is_coherent(tmp_path: Path) -> None:
    world, path, engine, host = _setup(tmp_path)
    with patch(
        "safeyolo.policy.engine.write_event",
        autospec=True,
        side_effect=OSError("injected audit emission failure"),
    ):
        observation = observe_transaction(
            path,
            world,
            lambda: engine.add_host_allowance(host, rate=100_000),
            engine=engine,
            related=lambda probe: probe.kind == "network" and probe.host == host,
            audit_targets=(),
        )

    assert observation.exception_type == "OSError"
    assert observation.toml_valid
    assert observation.active_decisions.changed(observation.fresh_process_decisions) == {}
    append_observation(
        {
            "status": "OBSERVATION",
            "family": "audit-write-failure",
            "policy_coherent": True,
            "reported_exception": observation.exception_type,
        }
    )
