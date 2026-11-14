"""Prove named execution accounting with real fixture pytest processes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.blackbox import execution_receipt as receipts
from tests.blackbox.selections import OPTIONAL_CASES, PROCEDURES

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("defect", [None, "deselect", "ignore", "skip", "setup", "call", "teardown", "collect-only"])
def test_real_pytest_retains_parameter_cases_and_rejects_partial_execution(tmp_path, defect):
    suite = tmp_path / "tests/blackbox/host/identity"
    suite.mkdir(parents=True)
    source = """import pytest
@pytest.fixture
def prepared():
    SETUP
    yield
    TEARDOWN
@pytest.mark.parametrize('case', ['one', 'two'])
def test_required(case, prepared):
    CALL
""".replace("SETUP", "assert False" if defect == "setup" else "pass")
    source = source.replace("TEARDOWN", "assert False" if defect == "teardown" else "pass")
    source = source.replace("CALL", "pytest.skip('missing prerequisite')" if defect == "skip" else
                            "assert False" if defect == "call" else "assert case in ('one', 'two')")
    (suite / "test_cases.py").write_text(source)
    output = tmp_path / "phase.json"
    extra = {"deselect": ["-k", "one"], "ignore": ["--ignore=tests/blackbox/host/identity/test_cases.py"],
             "collect-only": ["--collect-only"]}.get(defect, [])
    result = subprocess.run([sys.executable, str(ROOT / "tests/blackbox/execution_receipt.py"),
                             "--phase", "identity", "--lane", "kvm", "--run-id", "selected-run",
                             "--root", str(tmp_path), "--output", str(output), "--", "-q", *extra],
                            capture_output=True, text=True, timeout=25, check=False,
                            env=dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"))
    report = json.loads(output.read_text())
    problems = receipts.pytest_problems(report, "identity", "kvm", root=tmp_path)
    assert (result.returncode == 0) == (not problems) == (defect is None), result.stdout + result.stderr
    if defect not in {"ignore"}:
        assert {node.rsplit("[", 1)[-1] for node in report["collected"]} == {"one]", "two]"}
    if defect == "deselect":
        assert len(report["selected"]) == 1 and len(report["deselected"]) == 1
    if defect in {"setup", "call", "teardown"}:
        assert any(steps.get(defect) == "failed" for steps in report["tests"].values())


def test_named_platform_exclusion_does_not_excuse_other_skips(tmp_path):
    suite = tmp_path / "tests/blackbox/host/identity"
    suite.mkdir(parents=True)
    path = suite / "test_mapping.py"
    path.write_text("def test_sandbox_root_maps_to_subordinate_host_uid(): pass\ndef test_other(): pass\n")
    mapping, other = receipts.phase_functions("identity", tmp_path)
    # Sort by the concrete function name instead of relying on declaration order.
    mapping = next(node for node in (mapping, other) if "subordinate" in node)
    other = next(node for node in receipts.phase_functions("identity", tmp_path) if node != mapping)
    report = {"phase": "identity", "lane": "vz", "identity": "host", "uid": 1000,
              "finished": True, "exit": 0, "collected": [mapping, other], "selected": [mapping, other],
              "tests": {mapping: {"setup": "skipped", "teardown": "passed"},
                        other: dict.fromkeys(("setup", "call", "teardown"), "passed")}}
    assert receipts.pytest_problems(report, "identity", "vz", root=tmp_path) == []
    report["tests"][other]["call"] = "skipped"
    assert any("did not pass" in problem for problem in receipts.pytest_problems(report, "identity", "vz", root=tmp_path))


@pytest.mark.parametrize("defect", [None, "missing", "partial", "wrong-run", "wrong-section", "unfinished"])
def test_procedure_requires_every_named_checkpoint_from_this_run(tmp_path, monkeypatch, defect):
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_RUN_ID", "current")
    context = {"platform": "kvm", "agent": "bbtest", "pid": 123, "start_token": "birth"}
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_GUEST_IDENTITY", json.dumps(context))
    receipts.save(tmp_path / "platform.json", context)
    receipt = receipts.ProcedureReceipt("workloads", tmp_path / "installed-workloads.json")
    if defect == "missing":
        receipt.path.unlink()
    else:
        for name in PROCEDURES["workloads"][1]:
            if defect == "partial" and name == "sse":
                continue
            receipt.checkpoint(name)
        if defect == "wrong-run":
            receipt.document["run_id"] = "other"
        if defect == "wrong-section":
            receipt.document["section"] = "access"
        if defect == "unfinished":
            receipt.document["finished"] = False
        receipts.save(receipt.path, receipt.document)
    result = receipts.section_execution(tmp_path, "workloads", "kvm", "current")
    assert result["complete"] == (defect is None)


@pytest.mark.parametrize("identity,uid", [("guest-root", 1000), ("guest-agent", 0)])
def test_guest_user_and_root_are_not_interchangeable(identity, uid):
    report = {"phase": identity, "lane": "kvm", "identity": identity, "uid": uid,
              "finished": True, "exit": 0, "collected": [], "selected": [], "tests": {}}
    assert "wrong guest uid" in receipts.pytest_problems(report, identity, "kvm")


@pytest.mark.parametrize("defect", [None, "missing", "failed", "wrong-run", "wrong-phase", "wrong-guest"])
def test_guest_phase_needs_its_independent_host_observer(tmp_path, monkeypatch, defect):
    context = {"platform": "systrap", "agent": "bbtest", "pid": 123, "start_token": "birth"}
    receipts.save(tmp_path / "platform.json", context)
    monkeypatch.setitem(receipts.SECTION_DRIVERS, "isolation", ("guest-agent",))
    monkeypatch.setattr(receipts, "pytest_problems", lambda *args, **kwargs: [])
    report = {"phase": "guest-agent", "run_id": "current", "guest": context, "tests": {}, "collected": [], "selected": []}
    receipts.save(tmp_path / "pytest-guest-agent.json", report)
    observer = {"phase": "guest-agent", "run_id": "current", "guest": context, "status": "passed"}
    if defect == "failed":
        observer["status"] = "incomplete"
    elif defect == "wrong-run":
        observer["run_id"] = "previous"
    elif defect == "wrong-phase":
        observer["phase"] = "guest-root"
    elif defect == "wrong-guest":
        observer["guest"] = {**context, "start_token": "previous-birth"}
    if defect != "missing":
        receipts.save(tmp_path / "containment-guest-agent.json", observer)
    result = receipts.section_execution(tmp_path, "isolation", "systrap", "current")
    assert result["complete"] == (defect is None)


def test_guest_destination_observations_are_retained_in_the_phase_receipt(tmp_path):
    plugin = receipts.PytestReceipt(tmp_path / "receipt.json", "guest-agent", "systrap", "run", tmp_path)
    plugin.nodes["probe"] = "test_network.py::test_owned_receiver"
    observed = [{"address": "192.0.2.8", "guest_network": {"route_exit": 2, "route": []}, "uid": 1000}]
    plugin.pytest_runtest_logreport(SimpleNamespace(
        nodeid="probe", when="call", outcome="passed",
        capstdout="CONTAINMENT_ATTEMPTS=" + json.dumps(observed) + "\n"))
    saved = json.loads(plugin.path.read_text())
    assert saved["containment_observations"][plugin.nodes["probe"]] == [
        {"kind": "CONTAINMENT_ATTEMPTS", "value": observed}]


def test_explicit_optional_selection_makes_its_skipped_case_required(tmp_path, monkeypatch):
    node, variable, selected_value, _reason = OPTIONAL_CASES[0]
    relative, function = node.split("::")
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text(f"def {function}(): pass\ndef test_required(): pass\n")
    required = relative + "::test_required"
    report = {"phase": "proxy", "lane": "proxy", "identity": "host", "uid": 1000,
              "finished": True, "exit": 0, "collected": [node, required], "selected": [node, required],
              "tests": {node: {"setup": "skipped", "teardown": "passed"},
                        required: dict.fromkeys(("setup", "call", "teardown"), "passed")}}
    assert receipts.pytest_problems(report, "proxy", "proxy", root=tmp_path) == []
    report["enabled_optional"] = [node]
    assert receipts.pytest_problems(report, "proxy", "proxy", root=tmp_path)
    monkeypatch.setenv(variable, selected_value or "private-model-selection")
    plugin = receipts.PytestReceipt(tmp_path / "record.json", "proxy", "proxy", "run", tmp_path)
    assert node in plugin.document["enabled_optional"]
    assert "private-model-selection" not in json.dumps(plugin.document)
