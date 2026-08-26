"""Representative policy writers under controlled process interleavings."""

from __future__ import annotations

import fcntl
import multiprocessing
import os
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from experiments.policy_assurance.harness import make_world, write_policy

TIMEOUT = 12


def _writer(kind: str, path_text: str, key: str, ready, release, result) -> None:
    """Prepare one real writer, pause, then report its public outcome."""
    path = Path(path_text)
    os.environ["SAFEYOLO_CONFIG_DIR"] = str(path.parent)
    try:
        prepared: Any = None
        if kind == "cli":
            from safeyolo.commands.policy_host import host_add

            prepared = host_add
        elif kind == "engine":
            from experiments.policy_assurance.harness import engine_from_path

            prepared = engine_from_path(path)
        ready.set()
        if not release.wait(timeout=TIMEOUT):
            raise TimeoutError("release barrier timed out")

        if kind == "cli":
            prepared(key, rate=100_000, agent=None, expires=None)
        elif kind == "engine":
            prepared.add_host_allowance(key, rate=100_000)
        elif kind == "locked":
            from safeyolo.policy.toml_roundtrip import locked_policy_mutate, update_host_field

            locked_policy_mutate(path, lambda doc: update_host_field(doc, key, "rate", 100_000))
        elif kind == "agents":
            from safeyolo.agents_store import save_agent

            save_agent(key, {"egress": "deny", "folder": f"/workspace/{key}"})
        elif kind == "admin":
            from pdp import PolicyClientConfig, configure_policy_client, reset_policy_client
            from safeyolo.mitm_addons.admin_api import AdminRequestHandler

            configure_policy_client(PolicyClientConfig(baseline_path=path))

            def mutate(agents):
                agents["atlas"].setdefault("services", {})[key] = {
                    "capability": "read",
                    "token": f"vault:{key}",
                }

            AdminRequestHandler._policy_toml_mutate(mutate)
            reset_policy_client()
        elif kind == "gateway":
            from safeyolo.mitm_addons.service_gateway import ServiceGateway

            gateway = ServiceGateway()
            gateway._get_policy_path = lambda: path
            gateway.add_contract_binding("atlas", key, "read", "tenant={tenant}", {"tenant": key}, ["GET /"])
        elif kind == "credential":
            from experiments.policy_assurance.harness import engine_from_path

            engine = engine_from_path(path)
            engine.add_credential_approval(key, "alpha:*")
        elif kind == "revoke":
            from safeyolo.mitm_addons.service_gateway import ServiceGateway

            gateway = ServiceGateway()
            gateway._get_policy_path = lambda: path
            gateway._load_grants_from_policy()
            if not gateway.revoke_grant(key):
                raise AssertionError(f"grant not found: {key}")
        else:  # pragma: no cover - matrix definition error
            raise ValueError(kind)
        result.put((True, kind, key, None))
    except Exception as exc:
        result.put((False, kind, key, f"{type(exc).__name__}: {exc}"))


def _lock_order_probe(path_text: str, marker_text: str, started) -> None:
    from unittest.mock import patch

    from safeyolo.policy.toml_roundtrip import load_roundtrip, locked_policy_mutate

    marker = Path(marker_text)

    def observed_load(path):
        marker.write_text("load-started")
        return load_roundtrip(path)

    with patch("safeyolo.policy.toml_roundtrip.load_roundtrip", side_effect=observed_load):
        started.set()
        locked_policy_mutate(Path(path_text), lambda _document: None)


def _initial_policy(path: Path) -> None:
    world = make_world(
        ("atlas", "boris", "cody"),
        ("api.alpha.example", "blocked.example", "review.example", "private.example"),
        ("alpha", "beta", "gamma"),
    )
    write_policy(path, world.policy)


def _run_pair(path: Path, left: tuple[str, str], right: tuple[str, str], order: str) -> list[tuple]:
    context = multiprocessing.get_context("spawn")
    ready = (context.Event(), context.Event())
    release = (context.Event(), context.Event())
    result = context.Queue()
    processes = [
        context.Process(
            target=_writer,
            args=(kind, str(path), key, ready[index], release[index], result),
        )
        for index, (kind, key) in enumerate((left, right))
    ]
    for process in processes:
        process.start()
    if not all(event.wait(timeout=TIMEOUT) for event in ready):
        for process in processes:
            process.kill()
        pytest.fail("INFRASTRUCTURE_ERROR: writer preparation barrier timed out")

    indexes = (0, 1) if order == "left-first" else (1, 0)
    for index in indexes:
        release[index].set()
        processes[index].join(timeout=TIMEOUT)
        if processes[index].is_alive():
            processes[index].kill()
            pytest.fail("INFRASTRUCTURE_ERROR: writer completion barrier timed out")

    outcomes = [result.get(timeout=TIMEOUT), result.get(timeout=TIMEOUT)]
    assert all(outcome[0] for outcome in outcomes), outcomes
    return outcomes


def _document(path: Path) -> dict:
    return tomlkit.parse(path.read_text()).unwrap()


def _assert_restrictions_survive(document: dict) -> None:
    assert document["hosts"]["blocked.example"]["egress"] == "deny"
    assert document["hosts"]["*"]["egress"] == "deny"
    assert "boris" in document["agents"]


@pytest.mark.parametrize("order", ("left-first", "right-first"))
def test_locked_control_for_each_release_pattern(tmp_path: Path, order: str) -> None:
    path = tmp_path / "policy.toml"
    _initial_policy(path)
    keys = ("locked-one.example", "locked-two.example")
    _run_pair(path, ("locked", keys[0]), ("locked", keys[1]), order)
    document = _document(path)
    assert all(key in document["hosts"] for key in keys)
    _assert_restrictions_survive(document)


def test_locked_mutation_loads_only_after_acquiring_lock(tmp_path: Path) -> None:
    """A blocked contender must not take a stale snapshot before the lock."""
    path = tmp_path / "policy.toml"
    marker = tmp_path / "load-started"
    _initial_policy(path)
    lock_path = tmp_path / ".policy.toml.lock"
    lock_path.touch()
    context = multiprocessing.get_context("spawn")
    started = context.Event()
    with lock_path.open() as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        process = context.Process(
            target=_lock_order_probe,
            args=(str(path), str(marker), started),
        )
        process.start()
        if not started.wait(timeout=TIMEOUT):
            process.kill()
            pytest.fail("INFRASTRUCTURE_ERROR: lock-order probe did not start")
        process.join(timeout=0.5)
        assert not marker.exists(), "contending writer loaded policy before acquiring the lock"
        fcntl.flock(lock_file, fcntl.LOCK_UN)
    process.join(timeout=TIMEOUT)
    if process.is_alive():
        process.kill()
        pytest.fail("INFRASTRUCTURE_ERROR: lock-order probe did not exit")
    assert process.exitcode == 0
    assert marker.exists()


MATRIX = (
    ("cli-same", ("cli", "cli-one.example"), ("cli", "cli-two.example"), "left-first"),
    ("engine-same", ("engine", "engine-one.example"), ("engine", "engine-two.example"), "left-first"),
    ("agents-same", ("agents", "delta-one"), ("agents", "delta-two"), "right-first"),
    ("admin-same", ("admin", "mail-one"), ("admin", "mail-two"), "left-first"),
    ("gateway-same", ("gateway", "gateway-one"), ("gateway", "gateway-two"), "left-first"),
    ("cli-locked", ("locked", "locked-mixed.example"), ("cli", "cli-mixed.example"), "left-first"),
    ("engine-agents", ("engine", "engine-mixed.example"), ("agents", "delta-mixed"), "left-first"),
    ("admin-gateway", ("admin", "mail-mixed"), ("gateway", "gateway-mixed"), "left-first"),
)


@pytest.mark.parametrize("_name,left,right,order", MATRIX, ids=[row[0] for row in MATRIX])
def test_successful_disjoint_writer_pairs_preserve_both_changes(
    tmp_path: Path,
    _name: str,
    left: tuple[str, str],
    right: tuple[str, str],
    order: str,
) -> None:
    path = tmp_path / "policy.toml"
    _initial_policy(path)
    _run_pair(path, left, right, order)
    document = _document(path)
    for kind, key in (left, right):
        if kind in {"cli", "engine", "locked", "credential"}:
            assert key in document["hosts"]
        elif kind == "agents":
            assert key in document["agents"]
        elif kind == "admin":
            assert key in document["agents"]["atlas"]["services"]
        elif kind == "gateway":
            bindings = document["agents"]["atlas"].get("contract_bindings", [])
            assert any(binding["service"] == key for binding in bindings)
    _assert_restrictions_survive(document)


def test_revocation_racing_unrelated_approval_is_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    _initial_policy(path)
    from safeyolo.mitm_addons.service_gateway import ServiceGateway

    gateway = ServiceGateway()
    gateway._get_policy_path = lambda: path
    grant = gateway.add_grant("atlas", "mail", "POST", "/send", "remembered")
    credential_host = "credential.concurrent.example"
    _run_pair(path, ("credential", credential_host), ("revoke", grant.grant_id), "left-first")
    document = _document(path)
    assert credential_host in document["hosts"]
    grants = document["agents"]["atlas"].get("grants", [])
    assert all(item["grant_id"] != grant.grant_id for item in grants)
    _assert_restrictions_survive(document)
