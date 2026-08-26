"""Experiment: real policy writers under controlled process interleavings."""

from __future__ import annotations

import multiprocessing
import os
from pathlib import Path

import pytest

from experiments.policy_assurance.harness import engine_from_path, make_world, write_policy

HOST_PAIRS = (
    ("alpha.concurrent.example", "beta.concurrent.example"),
    ("API.CASE.EXAMPLE", "api.case.example"),
    ("xn--bcher-kva.example", "bücher.example"),
    ("deep.one.concurrent.test", "deep.two.concurrent.test"),
)


def _policy_host_writer(
    config_dir: str,
    host: str,
    loaded,
    release,
) -> None:
    """Use the public policy-host mutation path in a real process."""
    os.environ["SAFEYOLO_CONFIG_DIR"] = config_dir
    from safeyolo.commands.policy_host import host_add

    loaded.set()
    if not release.wait(timeout=10):
        raise TimeoutError("parent did not release writer")
    host_add(host, rate=100_000, agent=None, expires=None)


def _locked_writer(policy_path: str, host: str) -> None:
    from safeyolo.policy.toml_roundtrip import locked_policy_mutate, update_host_field

    path = Path(policy_path)
    locked_policy_mutate(path, lambda doc: update_host_field(doc, host, "rate", 100_000))


def _join(process) -> None:
    process.join(timeout=15)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)
        raise AssertionError(f"writer {process.pid} did not exit")
    assert process.exitcode == 0


def _initial_policy(path: Path) -> None:
    world = make_world(
        ("atlas", "boris", "cody"),
        ("api.alpha.example", "blocked.example", "review.example", "private.example"),
        ("alpha", "beta", "gamma"),
    )
    write_policy(path, world.policy)


def _assert_hosts_are_effectively_allowed(path: Path, hosts: tuple[str, str]) -> None:
    engine = engine_from_path(path)
    for host in hosts:
        assert engine.evaluate_request(host).effect == "allow", host


@pytest.mark.parametrize("hosts", HOST_PAIRS)
def test_locked_writers_preserve_both_changes(tmp_path: Path, hosts: tuple[str, str]) -> None:
    """The common locked mutation helper should serialize independent changes."""
    path = tmp_path / "policy.toml"
    _initial_policy(path)
    context = multiprocessing.get_context("spawn")
    writers = [context.Process(target=_locked_writer, args=(str(path), host)) for host in hosts]

    for writer in writers:
        writer.start()
    for writer in writers:
        _join(writer)

    _assert_hosts_are_effectively_allowed(path, hosts)


@pytest.mark.parametrize("hosts", HOST_PAIRS)
def test_policy_host_writers_do_not_lose_completed_changes(
    tmp_path: Path,
    hosts: tuple[str, str],
) -> None:
    """Force two public CLI writers to save snapshots loaded at the same time."""
    path = tmp_path / "policy.toml"
    _initial_policy(path)
    context = multiprocessing.get_context("spawn")
    loaded = (context.Event(), context.Event())
    release = (context.Event(), context.Event())
    writers = [
        context.Process(
            target=_policy_host_writer,
            args=(str(tmp_path), host, loaded[index], release[index]),
        )
        for index, host in enumerate(hosts)
    ]

    for writer in writers:
        writer.start()
    assert loaded[0].wait(timeout=10)
    assert loaded[1].wait(timeout=10)

    # Both writers now hold stale snapshots. Complete both operations in a
    # deterministic order; a sound transaction keeps both completed changes.
    release[0].set()
    _join(writers[0])
    release[1].set()
    _join(writers[1])

    _assert_hosts_are_effectively_allowed(path, hosts)
