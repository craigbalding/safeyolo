"""Prove named execution accounting with real fixture pytest processes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.blackbox import execution_receipt as receipts
from tests.blackbox.selections import NATIVE_PHASES, OPTIONAL_CASES, PROCEDURES

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("defect", [None, "ignored", "include-ignored", "failed", "missing", "empty", "build", "observer", "source"])
def test_native_selector_observes_real_libtest_and_refuses_incomplete_results(tmp_path, defect):
    source = tmp_path / "proxy/src/jobs/mediated/tests.rs"
    source.parent.mkdir(parents=True)
    source.write_text("#[test]\nfn one() {}\n#[test]\nfn two() {}\n")
    source.parent.with_suffix(".rs").write_text("mod tests;\n")
    metadata = tmp_path / "tests/blackbox/controls.toml"
    metadata.parent.mkdir(parents=True)
    metadata.write_text('''[[witnesses]]
kind = "cargo"
target = "lib"
module = "jobs::mediated::tests"
owner = "proxy/src/jobs/mediated.rs"
paths = ["proxy/src/jobs/mediated/tests.rs"]
''')
    body = source.read_text()
    if defect in {"ignored", "include-ignored"}:
        body = body.replace("fn two", "#[ignore]\nfn two")
    elif defect == "failed":
        body = body.replace("fn two() {}", 'fn two() { panic!("controlled failure"); }')
    elif defect == "missing":
        body = body.replace("fn two", "fn another")
    elif defect == "empty":
        body = ""
    crate = tmp_path / "lib.rs"
    crate.write_text("mod jobs { mod mediated { mod tests {" + body + "} } }")
    binary = tmp_path / "native-test"
    subprocess.run(["rustc", "--test", str(crate), "-o", str(binary)], check=True, capture_output=True)
    wrapper = tmp_path / "scripts/cargo_with_space.sh"
    wrapper.parent.mkdir()
    artifact = {"reason": "compiler-artifact", "profile": {"test": True},
                "target": {"kind": ["lib"], "name": "fixture"}, "executable": str(binary)}
    wrapper.write_text(f"#!{sys.executable}\nimport json\n"
                       + ("raise SystemExit(75)\n" if defect == "build" else
                          "print('broken observer input')\n" if defect == "observer" else
                          f"print({json.dumps(json.dumps(artifact))})\n"))
    wrapper.chmod(0o755)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "native receipt fixture"], cwd=tmp_path, check=True)
    expected = receipts.native_cases("mediated-services", tmp_path)
    if defect == "source":
        source.parent.with_suffix(".rs").unlink()
    output = tmp_path / "result.json"
    result = subprocess.run([sys.executable, str(ROOT / "tests/blackbox/execution_receipt.py"),
                             "--native-phase", "mediated-services", "--root", str(tmp_path),
                             "--lane", "process", "--run-id", "owned", "--output", str(output),
                             *(["--include-ignored"] if defect == "include-ignored" else [])],
                            capture_output=True, text=True, timeout=30)
    report = json.loads(output.read_text())
    problems = receipts.native_problems(report, expected)
    success = defect in {None, "include-ignored"}
    assert (result.returncode == 0) == (not problems) == report["complete"] == success, result.stdout + result.stderr
    assert report["boundary"] == "native-process" and report["run_id"] == "owned"
    if defect in {"observer", "source"}:
        assert report["observer_error"]
    if defect not in {"build", "observer", "source"}:
        assert report["groups"][0]["executable_sha256"]
    if success:
        assert report["groups"][0]["tests"] == {"jobs::mediated::tests::one": "ok", "jobs::mediated::tests::two": "ok"}


def test_native_phases_resolve_current_catalogue_and_keep_the_prepared_job_required():
    for phase in NATIVE_PHASES:
        assert receipts.native_cases(phase, ROOT)
    selected = receipts.native_cases("named-checks", ROOT)
    assert any(name.endswith("::native_installed_job_check_binds_observed_execution_and_reuses_only_valid_evidence")
               for _target, _module, names in selected for name in names)


@pytest.mark.parametrize("missing", [None, "hyperlight", "hyperlight-unikraft", "cleanup"])
def test_two_engine_receipt_requires_both_engines_and_owned_cleanup(tmp_path, missing):
    receipt = receipts.ProcedureReceipt("hyperlight-services", tmp_path / "result.json")
    assert receipt.document["complete"] is False
    for name in PROCEDURES["hyperlight-services"][1]:
        if name != missing:
            receipt.checkpoint(name)
    report = json.loads(receipt.path.read_text())
    assert report["complete"] == (missing is None)
    assert report["finished"] is True


def test_focused_shell_caller_cannot_pass_from_collection_only(tmp_path):
    output = tmp_path / "reports"
    result = subprocess.run([str(ROOT / "tests/blackbox/run-controls.sh"), "sudo-disclosure", "--collect-only", "-q"],
                            cwd=ROOT, env={**os.environ, "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(output),
                                           "SAFEYOLO_BLACKBOX_RUN_ID": "wrapper-collection"},
                            capture_output=True, text=True, timeout=30)
    report = json.loads((output / "sudo-disclosure.json").read_text())
    assert result.returncode == 2 and report["complete"] is False, result.stdout + result.stderr
    assert report["run_id"] == "wrapper-collection"
    assert report["selected"] and report["tests"] == {}


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
