"""Safety and recovery contracts for the policy chaos engineering command."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

POLICY = """\
budget = 12000

[hosts]
"allowed.example" = { rate = 1000 }
"blocked.example" = { egress = "deny" }
"*" = { egress = "deny" }
"""


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
