"""Process-death recovery around rename (not power-loss durability testing)."""

from __future__ import annotations

import multiprocessing
from pathlib import Path
from unittest.mock import patch

import pytest
import tomlkit

from experiments.policy_assurance.harness import (
    append_observation,
    file_hash,
    make_world,
    parseable_toml,
    temporary_policy_files,
    write_policy,
)

TIMEOUT = 12


def _crashing_writer(path_text: str, host: str, stage: str, paused, release) -> None:
    import os
    import shutil

    from safeyolo.policy.toml_roundtrip import locked_policy_mutate, update_host_field

    path = Path(path_text)
    if stage == "before-rename":
        real_move = shutil.move

        def pause_before_move(source, destination):
            paused.set()
            if not release.wait(timeout=TIMEOUT):  # pragma: no cover - parent kills first
                raise TimeoutError("parent did not terminate writer")
            return real_move(source, destination)

        target = patch("safeyolo.policy.toml_roundtrip.shutil.move", side_effect=pause_before_move)
    else:
        real_fsync = os.fsync
        calls = 0

        def pause_before_directory_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                paused.set()
                if not release.wait(timeout=TIMEOUT):  # pragma: no cover - parent kills first
                    raise TimeoutError("parent did not terminate writer")
            return real_fsync(fd)

        target = patch("safeyolo.policy.toml_roundtrip.os.fsync", side_effect=pause_before_directory_fsync)

    with target:
        locked_policy_mutate(path, lambda doc: update_host_field(doc, host, "rate", 100_000))


@pytest.mark.parametrize("stage", ("before-rename", "after-rename-before-directory-fsync"))
def test_process_death_never_exposes_partial_policy(tmp_path: Path, stage: str) -> None:
    world = make_world(
        ("atlas", "boris", "cody"),
        ("api.alpha.example", "blocked.example", "review.example", "private.example"),
        ("alpha", "beta", "gamma"),
    )
    path = tmp_path / "policy.toml"
    write_policy(path, world.policy)
    old_hash = file_hash(path)
    host = "crash-recovery.example"
    context = multiprocessing.get_context("spawn")
    paused = context.Event()
    release = context.Event()
    process = context.Process(
        target=_crashing_writer,
        args=(str(path), host, stage, paused, release),
    )
    process.start()
    if not paused.wait(timeout=TIMEOUT):
        process.kill()
        process.join(timeout=2)
        pytest.fail(f"INFRASTRUCTURE_ERROR: writer did not reach {stage}")
    process.terminate()
    process.join(timeout=5)
    if process.is_alive():
        process.kill()
        process.join(timeout=2)
        pytest.fail("INFRASTRUCTURE_ERROR: terminated writer did not exit")

    assert parseable_toml(path)
    document = tomlkit.parse(path.read_text()).unwrap()
    assert document["hosts"]["blocked.example"]["egress"] == "deny"
    assert document["hosts"]["*"]["egress"] == "deny"
    assert "boris" in document["agents"]
    visible_state = "new" if host in document["hosts"] else "old"
    assert visible_state in {"old", "new"}
    if visible_state == "old":
        assert file_hash(path) == old_hash
    residue = temporary_policy_files(path)
    append_observation(
        {
            "status": "OBSERVATION",
            "family": "process-death",
            "stage": stage,
            "visible_state": visible_state,
            "temporary_files": list(residue),
            "description": "process termination, not simulated power loss",
        }
    )
