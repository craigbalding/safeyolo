"""Runner accounting and owned-process controls for native policy chaos."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tools import policy_chaos


def _args(tmp_path: Path, groups: list[str]) -> argparse.Namespace:
    return argparse.Namespace(binary=tmp_path / "binary", output=tmp_path / "report.json",
                              group=groups, seed=None)


def test_runner_rejects_empty_selection_and_missing_pytest_accounting(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_chaos, "_binary", lambda _: (tmp_path / "binary", "proxy test", "a" * 64))
    monkeypatch.setattr(policy_chaos, "GROUPS", {})
    with pytest.raises(ValueError, match="No policy-chaos group"):
        policy_chaos._run(_args(tmp_path, []))

    monkeypatch.setattr(policy_chaos, "GROUPS", {"empty": ("missing::test", "test writer", "one case runs")})
    monkeypatch.setattr(policy_chaos, "_pytest", lambda *_: (0, "", ""))
    assert policy_chaos._run(_args(tmp_path, ["empty"])) == 2
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["status"] == "INCOMPLETE"
    assert report["selected_runs"] == report["attempted_runs"] == 1
    assert report["executed_runs"] == 0
    assert report["executed_cases"] == 0


def test_runner_continues_after_finding_and_rejects_skipped_case(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_chaos, "_binary", lambda _: (tmp_path / "binary", "proxy test", "b" * 64))
    monkeypatch.setattr(policy_chaos, "GROUPS", {
        "finding": ("test_finding.py", "test writer", "case passes"),
        "passing": ("test_passing.py", "test writer", "case passes"),
        "skipped": ("test_skipped.py", "test writer", "case passes"),
    })
    called = []

    def fake_pytest(command, _environment):
        selector = command[command.index("-s") + 2]
        called.append(selector)
        xml = Path(next(item.removeprefix("--junitxml=") for item in command
                        if item.startswith("--junitxml=")))
        child = ("<failure message='wrong decision'/>" if selector == "test_finding.py"
                 else "<skipped message='not executed'/>" if selector == "test_skipped.py" else "")
        xml.write_text(f"<testsuites><testsuite><testcase name='{selector}'>{child}</testcase>"
                       "</testsuite></testsuites>")
        return (1 if selector == "test_finding.py" else 0), "", ""

    monkeypatch.setattr(policy_chaos, "_pytest", fake_pytest)
    assert policy_chaos._run(_args(tmp_path, list(policy_chaos.GROUPS))) == 1
    report = json.loads((tmp_path / "report.json").read_text())
    assert called == [group[0] for group in policy_chaos.GROUPS.values()]
    assert [item["status"] for item in report["results"]] == [
        "FINDING", "PASS", "INCOMPLETE",
    ]
    assert report["selected_runs"] == report["attempted_runs"] == 3
    assert report["executed_runs"] == 2


@pytest.mark.parametrize("binary,error", [
    ("missing", "does not exist"),
    ("wrong", "unexpected identity"),
])
def test_runner_rejects_missing_or_wrong_binary_before_selection(tmp_path, binary, error):
    selected = tmp_path / binary
    if binary == "wrong":
        selected.write_text("#!/bin/sh\necho another-program 1.0\n")
        selected.chmod(0o755)
    result = subprocess.run(
        [sys.executable, "-m", "tools.policy_chaos", "run", "--binary", str(selected),
         "--group", "existing-state", "--output", str(tmp_path / "report.json")],
        cwd=policy_chaos.ROOT, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 2 and error in result.stderr
    assert not (tmp_path / "report.json").exists()


def test_runner_rejects_missing_group(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "tools.policy_chaos", "run", "--group", "absent",
         "--output", str(tmp_path / "report.json")],
        cwd=policy_chaos.ROOT, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 2 and "invalid choice" in result.stderr
    assert not (tmp_path / "report.json").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="owned process-group inspection uses /proc")
def test_selected_group_timeout_kills_owned_child(tmp_path):
    child_pid = tmp_path / "child-pid"
    program = ("import subprocess,sys,time\n"
               "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
               f"open({str(child_pid)!r},'w').write(str(child.pid))\n"
               "time.sleep(30)\n")
    code, _, stderr = policy_chaos._pytest(
        [sys.executable, "-c", program], os.environ.copy(), timeout=0.5,
    )
    assert code is None and "timed out" in stderr
    pid = int(child_pid.read_text())
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        state = Path(f"/proc/{pid}/stat")
        if not state.exists() or state.read_text().split()[2] == "Z":
            break
        time.sleep(0.02)
    else:
        pytest.fail("owned child process survived the group timeout")
