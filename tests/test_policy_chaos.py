"""Safety and recovery contracts for the policy chaos engineering command."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import tomlkit

POLICY = """\
budget = 12000

[hosts]
"allowed.example" = { rate = 1000 }
"blocked.example" = { egress = "deny" }
"*" = { egress = "deny" }
"""

STOCK_POLICY_PATH = Path(__file__).parents[1] / "cli" / "src" / "safeyolo" / "templates" / "policy.toml"


def _listed_policy(list_name: str, list_path: str) -> str:
    document = tomlkit.document()
    document["budget"] = 12000
    document["lists"] = {list_name: list_path}
    document["hosts"] = {
        f"${list_name}": {"egress": "deny"},
        "*": {"egress": "deny"},
    }
    return tomlkit.dumps(document)


def _fault_command(config: Path, state: Path, run_id: str, checkpoint: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "tools.policy_chaos",
        "fault",
        "prepare-power-cut",
        "--checkpoint",
        checkpoint,
        "--config-dir",
        str(config),
        "--state-dir",
        str(state),
        "--run-id",
        run_id,
        "--confirm-disposable-vm",
    ]


def test_fault_mode_requires_disposable_vm_contract(tmp_path, monkeypatch):
    from tools.policy_chaos import _safe_fault_paths

    config = tmp_path / "config"
    config.mkdir()
    (config / "policy.toml").write_text(POLICY)
    monkeypatch.delenv("SAFEYOLO_CHAOS_DISPOSABLE_VM", raising=False)

    with pytest.raises(RuntimeError, match="requires --confirm-disposable-vm"):
        _safe_fault_paths(config, tmp_path / "state", confirmed=True)


def test_oracle_runs_against_stock_init_policy_with_all_lists(tmp_path):
    from tools.policy_chaos import _expected_mutation

    config = tmp_path / "config"
    lists = config / "lists"
    lists.mkdir(parents=True)
    policy_path = config / "policy.toml"
    policy_path.write_bytes(STOCK_POLICY_PATH.read_bytes())
    chaos_host = "chaos-stock.invalid"
    (lists / "package-registries.txt").write_text("pypi.org\nnpmjs.org\n")
    (lists / "stevenblack-hosts.txt").write_text(f"0.0.0.0 {chaos_host}\n")

    operation, expected, surface = _expected_mutation(policy_path.read_bytes(), chaos_host, policy_path)

    assert operation == "allow"
    assert surface[chaos_host] == "deny"
    mutated = tomlkit.parse(expected.decode())
    assert mutated["lists"]["package_registries"] == ("lists/package-registries.txt")
    assert mutated["lists"]["known_bad"] == "lists/stevenblack-hosts.txt"


def test_oracle_snapshots_multiple_nested_and_absolute_lists(tmp_path):
    from tools.policy_chaos import _expected_mutation

    config = tmp_path / "config"
    nested = config / "lists" / "nested"
    shared = tmp_path / "shared"
    nested.mkdir(parents=True)
    shared.mkdir()
    absolute = tmp_path / "absolute.txt"
    (nested / "one.txt").write_text("one.example\n")
    (shared / "two.txt").write_text("two.example\n")
    absolute.write_text("three.example\n")
    policy_path = config / "policy.toml"
    document = tomlkit.document()
    document["budget"] = 12000
    document["lists"] = {
        "one": "lists/nested/one.txt",
        "two": "../shared/two.txt",
        "three": str(absolute),
    }
    document["hosts"] = {
        "$one": {"rate": 100},
        "$two": {"rate": 100},
        "$three": {"rate": 100},
        "*": {"egress": "deny"},
    }
    policy_path.write_text(tomlkit.dumps(document))

    operation, expected, _surface = _expected_mutation(policy_path.read_bytes(), "chaos-multiple.invalid", policy_path)

    assert operation == "allow"
    assert tomlkit.parse(expected.decode())["lists"].unwrap() == (document["lists"].unwrap())


def test_oracle_never_reopens_live_list_after_snapshot(tmp_path, monkeypatch):
    from tools import policy_chaos

    dependency = tmp_path / "dependency.txt"
    dependency.write_text("blocked.example\n")
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(_listed_policy("blocked", dependency.name))
    original = policy_path.read_bytes()
    real_decision = policy_chaos._decision
    calls = 0

    def delete_source_then_decide(path, host):
        nonlocal calls
        if calls == 0:
            dependency.unlink()
        calls += 1
        return real_decision(path, host)

    monkeypatch.setattr(policy_chaos, "_decision", delete_source_then_decide)

    operation, _expected, surface = policy_chaos._expected_mutation(original, "chaos-snapshot.invalid", policy_path)

    assert operation == "allow"
    assert surface["chaos-snapshot.invalid"] == "deny"
    assert calls >= 3
    assert not dependency.exists()


def test_snapshot_paths_are_generated_and_canonical_aliases_are_deduplicated(
    tmp_path,
):
    from tools.policy_chaos import ORACLE_LIST_DIR, _snapshot_oracle_lists

    config = tmp_path / "config"
    config.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside.example\n")
    (config / "alias.txt").symlink_to(outside)
    policy_path = config / "policy.toml"
    document = tomlkit.document()
    document["lists"] = {
        "../../escape": "../outside.txt",
        "absolute": str(outside),
        "symlink": "alias.txt",
    }
    document["hosts"] = {
        "$../../escape": {"rate": 1},
        "$absolute": {"rate": 1},
        "$symlink": {"rate": 1},
    }
    policy_path.write_text(tomlkit.dumps(document))
    oracle_dir = tmp_path / "oracle"
    oracle_dir.mkdir()

    snapshots = _snapshot_oracle_lists(policy_path, document, oracle_dir)

    rewritten = set(document["lists"].unwrap().values())
    assert len(rewritten) == 1
    relative = next(iter(rewritten))
    assert relative.startswith(f"{ORACLE_LIST_DIR}/0000-")
    assert (oracle_dir / relative).read_text() == "outside.example\n"
    assert len(list((oracle_dir / ORACLE_LIST_DIR).iterdir())) == 1
    assert set(snapshots.values()) == {relative}
    assert outside.read_text() == "outside.example\n"
    assert not (tmp_path.parent / "escape").exists()


@pytest.mark.parametrize(
    ("contents", "message"),
    (
        (None, r"\$dependency.*not found:.*missing\.txt"),
        (b"\xff", r"\$dependency.*invalid UTF-8 at:?.*dependency\.txt"),
    ),
)
def test_oracle_reports_missing_and_invalid_list_dependencies(tmp_path, contents, message):
    from tools.policy_chaos import _expected_mutation

    policy_path = tmp_path / "policy.toml"
    target_name = "missing.txt" if contents is None else "dependency.txt"
    policy_path.write_text(_listed_policy("dependency", target_name))
    if contents is not None:
        (tmp_path / target_name).write_bytes(contents)

    with pytest.raises(RuntimeError, match=message):
        _expected_mutation(policy_path.read_bytes(), "chaos-invalid.invalid", policy_path)


def test_oracle_reports_unreadable_list_dependency(tmp_path, monkeypatch):
    from tools.policy_chaos import _expected_mutation

    policy_path = tmp_path / "policy.toml"
    dependency = tmp_path / "dependency.txt"
    dependency.write_text("listed.example\n")
    policy_path.write_text(_listed_policy("blocked", dependency.name))
    original = policy_path.read_bytes()
    real_read_bytes = Path.read_bytes

    def guarded_read_bytes(path):
        if path == dependency.resolve():
            raise PermissionError("test denies this list")
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    with pytest.raises(
        RuntimeError,
        match=r"\$blocked.*unreadable at.*dependency\.txt.*PermissionError",
    ):
        _expected_mutation(original, "chaos-unreadable.invalid", policy_path)


def test_mutated_oracle_rejects_dependency_not_in_source_snapshot(tmp_path):
    from tools.policy_chaos import (
        _rewrite_oracle_lists,
        _snapshot_oracle_lists,
    )

    source = tmp_path / "source.txt"
    source.write_text("source.example\n")
    policy_path = tmp_path / "policy.toml"
    original = tomlkit.parse(_listed_policy("source", source.name))
    policy_path.write_text(tomlkit.dumps(original))
    oracle_dir = tmp_path / "oracle"
    oracle_dir.mkdir()
    snapshots = _snapshot_oracle_lists(policy_path, original, oracle_dir)
    conflicting = tomlkit.parse(_listed_policy("new", "new.txt"))

    with pytest.raises(
        RuntimeError,
        match=r"mutated list dependency \$new.*new\.txt.*conflicts",
    ):
        _rewrite_oracle_lists(conflicting, policy_path, snapshots, "mutated")


def test_missing_list_keeps_fault_command_json_error_contract(tmp_path):
    config = tmp_path / "config"
    state = tmp_path / "state"
    config.mkdir()
    (config / "policy.toml").write_text(_listed_policy("missing_list", "lists/missing.txt"))
    (config / ".safeyolo-chaos-disposable").write_text("pytest\n")
    environment = os.environ.copy()
    environment["SAFEYOLO_CHAOS_DISPOSABLE_VM"] = "1"

    completed = subprocess.run(
        _fault_command(config, state, "missing-list", "before-rename"),
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    error = json.loads(completed.stderr)
    assert error["status"] == "INFRASTRUCTURE_ERROR"
    assert "$missing_list" in error["error"]
    assert "lists/missing.txt" in error["error"]


@pytest.mark.parametrize(
    "checkpoint,expected_version",
    (
        ("before-rename", "old"),
        ("after-rename-before-directory-fsync", "new"),
    ),
)
def test_power_cut_protocol_recovers_complete_policy(
    tmp_path, checkpoint, expected_version
):
    config = tmp_path / "config"
    state = tmp_path / "state"
    config.mkdir()
    (config / "policy.toml").write_text(POLICY)
    (config / ".safeyolo-chaos-disposable").write_text("pytest\n")
    run_id = checkpoint.replace("-", "")
    environment = os.environ.copy()
    environment["SAFEYOLO_CHAOS_DISPOSABLE_VM"] = "1"
    process = subprocess.Popen(
        _fault_command(config, state, run_id, checkpoint),
        cwd=Path(__file__).parents[1],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    state_path = state / run_id / "state.json"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if state_path.exists():
            payload = json.loads(state_path.read_text())
            if payload.get("phase") == "ready-for-power-cut":
                break
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"prepare exited early: {stdout}\n{stderr}")
        time.sleep(0.05)
    else:
        process.kill()
        pytest.fail("prepare did not reach its power-cut checkpoint")

    process.kill()
    process.wait(timeout=5)
    report = tmp_path / f"{run_id}.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.policy_chaos",
            "fault",
            "recover",
            "--run-id",
            run_id,
            "--config-dir",
            str(config),
            "--state-dir",
            str(state),
            "--output",
            str(report),
            "--confirm-disposable-vm",
        ],
        cwd=Path(__file__).parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    evidence = json.loads(report.read_text())
    assert evidence["results"][0]["status"] == "PASS"
    assert evidence["results"][0]["visible_version"] == expected_version
    assert (config / "policy.toml").read_text() == POLICY

    # Regression: the advertised replay_command must actually parse
    # AND actually run to completion when paired with replay_env. The
    # pre-fix emit only had `--run-id` and no env hint, so executing
    # the advertised command in a clean environment exited 2 twice
    # over: argparse missing-args, then `_safe_fault_paths` refusing
    # without SAFEYOLO_CHAOS_DISPOSABLE_VM. Round-trip both by
    # running the replay end-to-end. (Merge dogfood finding.)
    from tools.policy_chaos import _parser

    replay = evidence["replay_command"]
    assert replay[:3] == [sys.executable, "-m", "tools.policy_chaos"]
    parsed = _parser().parse_args(replay[3:])
    assert parsed.command == "fault"
    assert parsed.fault_command == "recover"
    assert parsed.run_id == run_id
    assert parsed.confirm_disposable_vm is True

    replay_env = evidence["replay_env"]
    assert replay_env == {"SAFEYOLO_CHAOS_DISPOSABLE_VM": "1"}, (
        "replay_env must set the disposable-VM env guard the caller "
        "would otherwise forget"
    )
    # Execute the replay in a clean environment plus the emitted
    # replay_env. If _safe_fault_paths' env check ever gains a new
    # required key, this catches it — the emit has to keep up.
    replay_env_full = {**os.environ.copy(), **replay_env}
    replayed = subprocess.run(
        replay,
        cwd=Path(__file__).parents[1],
        env=replay_env_full,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert replayed.returncode == 0, (
        f"replay exited {replayed.returncode}: stderr={replayed.stderr}"
    )
