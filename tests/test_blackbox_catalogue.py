"""Detect catalogue drift without executing product or hardware tests."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.blackbox import catalogue, execution_receipt
from tests.blackbox.selections import PROCEDURES

ROOT = Path(__file__).resolve().parents[1]


def test_inline_rust_modules_keep_distinct_executable_identities(tmp_path):
    path = tmp_path / "checks.rs"
    path.write_text('''#[cfg(test)]
mod tests {
    #[test]
    fn regular() {}
}
#[cfg(test)]
mod fixture_tests {
    #[tokio::test]
    async fn preview() {}
}
''')
    for module, function in [("tests", "regular"), ("fixture_tests", "preview")]:
        witness = {"kind": "cargo", "target": "lib", "module": "checks::" + module, "owner": "checks.rs"}
        nodes = catalogue.resolve(witness, "checks.rs", tmp_path)
        assert [node["node"] for node in nodes] == ["checks::" + module + "::" + function]


@pytest.fixture
def catalogue_root(tmp_path, monkeypatch):
    for path in ("tests/blackbox/host/identity", "docs", ".github/workflows"):
        (tmp_path / path).mkdir(parents=True)
    shutil.copyfile(ROOT / "docs/assurance-map.toml", tmp_path / "docs/assurance-map.toml")
    metadata = ""
    for number in range(1, 39):
        metadata += "[[controls]]\n"
        for field in ("id", "control", "source", "what", "existing", "conformance", "effort", "comments", "owner"):
            value = f"BB-{number:02}" if field == "id" else "#1558" if field == "owner" else "fixture"
            metadata += field + " = " + json.dumps(value) + "\n"
        metadata += "decisions = []\n"
    metadata += '''[[witnesses]]
paths = ["tests/blackbox/host/identity/test_named.py::test_required"]
controls = ["BB-01"]
kind = "pytest"
scope = "fixture host"
adapter = "controlled assertion"
'''
    (tmp_path / catalogue.METADATA).write_text(metadata)
    (tmp_path / "tests/blackbox/host/identity/test_named.py").write_text("def test_required(): pass\n")
    phases = "native security identity guest-agent guest-root host-lifecycle listener-restart proxy".split()
    shared = dict.fromkeys(phases, ("host", ("tests/blackbox/host/identity/test_named.py",)))
    monkeypatch.setattr(catalogue, "PYTEST_PHASES", shared)
    monkeypatch.setattr(execution_receipt, "PYTEST_PHASES", shared)
    shell = "\n".join("run_pytest_phase " + phase for phase in phases)
    for _section, (filename, checkpoints) in PROCEDURES.items():
        (tmp_path / "tests/blackbox" / filename).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "tests/blackbox" / filename).write_text(
            "def main():\n" + "\n".join(f"    receipt.checkpoint({name!r})" for name in checkpoints) + "\n")
        shell += "\npython3 " + filename
    (tmp_path / "tests/blackbox/run-tests.sh").write_text(shell)
    (tmp_path / "tests/blackbox/installed_sections.py").write_text("")
    (tmp_path / ".github/workflows/test.yml").write_text('''on: [pull_request]
jobs:
  fixture:
    steps:
      - run: pytest tests/blackbox/host/identity/test_named.py::test_required
''')
    return tmp_path


@pytest.mark.parametrize("defect,expected", [
    (None, None), ("duplicate", "exactly once"), ("missing-id", "exactly once"),
    ("incomplete", "incomplete control"), ("renamed", "unresolved witness identity"),
    ("deleted", "unresolved witness file"), ("unmapped", "need control mapping"),
    ("unwired", "unwired pytest"), ("yaml", "unresolved pytest identity"),
    ("shell", "unresolved pytest identity"),
    ("procedure", "procedure checkpoints"),
])
def test_catalogue_rejects_structural_drift(catalogue_root, defect, expected):
    root = catalogue_root
    path = root / catalogue.METADATA
    text = path.read_text()
    if defect == "duplicate":
        path.write_text(text.replace('id = "BB-37"', 'id = "BB-01"'))
    elif defect == "missing-id":
        path.write_text(text.replace('id = "BB-38"', 'id = "BB-39"'))
    elif defect == "incomplete":
        path.write_text(text.replace('what = "fixture"', 'what = ""', 1))
    elif defect in {"renamed", "deleted"}:
        target = root / "tests/blackbox/host/identity/test_named.py"
        target.unlink() if defect == "deleted" else target.write_text("def test_renamed(): pass\n")
    elif defect == "unmapped":
        (root / "tests/blackbox/host/identity/test_unmapped.py").write_text("def test_new(): pass\n")
    elif defect == "unwired":
        shell = root / "tests/blackbox/run-tests.sh"
        shell.write_text(shell.read_text().replace("run_pytest_phase guest-root", "echo guest-root"))
    elif defect == "yaml":
        workflow = root / ".github/workflows/test.yml"
        workflow.write_text(workflow.read_text().replace("::test_required", "::test_renamed"))
    elif defect == "shell":
        (root / "tests/blackbox/run-external.sh").write_text(
            "pytest tests/blackbox/host/identity/test_named.py::test_renamed\n")
    elif defect == "procedure":
        procedure = root / "tests/blackbox/installed_workloads.py"
        procedure.write_text(procedure.read_text().replace("receipt.checkpoint('sse')", "pass"))
    if expected:
        with pytest.raises(ValueError, match=expected):
            catalogue.load(root)
    else:
        controls, witnesses, _outside = catalogue.load(root)
        assert len(controls) == 38 and witnesses[0]["resolved"][0][1][0]["node"].endswith("::test_required")
        assert not any("BB-37" in witness["controls"] for witness in witnesses)


def test_current_catalogue_resolves_all_controls_and_external_families():
    controls, witnesses, _outside = catalogue.load(ROOT)
    assert len(controls) == 38
    assert {witness["kind"] for witness in witnesses} == {"pytest", "cargo", "procedure"}
    assert any("tests/test_guest_acquisition.py" in witness["paths"] for witness in witnesses)


def test_cargo_commands_use_the_witness_manifest_and_proxy_default():
    rendered = catalogue.render(ROOT)
    assert (
        "cargo test --manifest-path host-executor/Cargo.toml --test unix_native "
        "installed_api_authentication_and_cross_principal_reads_cannot_change_authority -- --exact --ignored"
    ) in rendered
    assert (
        "cargo test --manifest-path proxy/Cargo.toml --test host_execution "
        "same_authenticated_http_protocol_on_standalone_and_safeyolo_targets -- --exact"
    ) in rendered


def test_host_protocol_selection_includes_nested_configured_checks_once():
    groups = execution_receipt.native_cases("host-execution", ROOT)
    assert len(groups) == 2
    assert "durable_crash_child" not in groups[0][2]
    assert "durable_process_failure_after_committed_admission" in groups[0][2]
    cases = groups[1][2]
    assert len(cases) == len(set(cases))
    assert any(name.startswith("host_execution::gateway::tests::configured_task_action::") for name in cases)


@pytest.mark.parametrize("tokens,selected", [
    (["python", "-m", "tests.blackbox.installed_federation"], True),
    (["python", "tests/blackbox/installed_federation.py"], True),
    (["python", "-m", "tests.blackbox.installed_provider"], False),
])
def test_procedure_workflow_selection_preserves_repository_and_module_paths(tokens, selected):
    command = {"tokens": tokens, "job": "fixture", "path": ".github/workflows/test.yml",
               "cadence": "manual", "condition": ""}
    result = catalogue.selection({"kind": "procedure"}, "tests/blackbox/installed_federation.py::run",
                                 {}, [command], {})
    assert any("[fixture]" in item for item in result) is selected


@pytest.mark.parametrize("arguments", [
    ("tests/", "--ignore=tests/blackbox/"),
    ("tests/", "--ignore", "tests/blackbox/host/identity/test_named.py"),
    ("tests/", "--ignore-glob=tests/blackbox/*"),
    ("tests/", "--deselect", "tests/blackbox/host/identity/test_named.py::test_required"),
    ("tests/", "--ignore=tests/blackbox/", "tests/blackbox/host/identity/test_named.py"),
    ("tests/test_positive.py", "tests/blackbox/host/identity/test_named.py", "--ignore=tests/blackbox/"),
])
def test_workflow_selection_agrees_with_real_pytest_exclusions(catalogue_root, arguments):
    root = catalogue_root
    (root / "tests/test_positive.py").write_text("def test_positive(): pass\n")
    (root / ".github/workflows/test.yml").write_text(
        "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  fixture:\n    steps:\n      - run: pytest "
        + shlex.join(arguments) + "\n")
    config = root / "pytest.ini"
    config.write_text("[pytest]\n")
    collected = subprocess.run([sys.executable, "-m", "pytest", "-c", str(config), "--collect-only", "-q", *arguments],
                               cwd=root, env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
                               capture_output=True, text=True, check=True)
    actual = {line for line in collected.stdout.splitlines() if line.startswith("tests/")}
    assert "tests/test_positive.py::test_positive" in actual
    commands = catalogue.workflows(root)
    for path in root.rglob("test_*.py"):
        for node in execution_receipt.python_tests(path, root):
            selection = catalogue.selection({"kind": "pytest"}, path.relative_to(root).as_posix(),
                                            {"node": node}, commands, {})
            assert any("[fixture]" in item for item in selection) == (node in actual), (node, selection, actual)


@pytest.mark.parametrize("selector", [
    "tests/blackbox/host/identity/test_renamed.py",
    "tests/blackbox/host/identity/test_named.py::TestRenamed",
    "tests/blackbox/host/identity/test_named.py::test_renamed",
    "--ignore=tests/blackbox/host/identity/test_renamed.py",
])
def test_unresolved_shared_phase_operand_cannot_pass_generation(catalogue_root, monkeypatch, selector):
    monkeypatch.setitem(catalogue.PYTEST_PHASES, "guest-root", (
        "guest-root", ("tests/blackbox/host/identity/test_named.py::test_required", selector)))
    assert any("shared phase guest-root" in problem for problem in catalogue.selector_problems(catalogue_root))
    with pytest.raises(ValueError, match="shared phase guest-root"):
        catalogue.render(catalogue_root)


@pytest.mark.parametrize("unwired,module,expected", [
    (False, "reviews", None), (True, "reviews", "unwired Cargo source"),
    (False, "wrong::reviews", "module identity"),
])
def test_cargo_identity_requires_its_real_module_and_keeps_ignore_selection(catalogue_root, unwired, module, expected):
    root = catalogue_root
    source = root / "proxy/tests/native_coord/reviews.rs"
    source.parent.mkdir(parents=True)
    source.write_text('#[tokio::test]\n#[ignore = "requires owned NATS"]\nasync fn required_review() {}\n')
    owner = source.parent.with_suffix(".rs")
    owner.write_text('#[path="native_coord/' + ('renamed' if unwired else 'reviews') + '.rs"]\nmod reviews;\n')
    witness = {"paths": ["proxy/tests/native_coord/reviews.rs"], "controls": ["BB-24"], "kind": "cargo",
               "scope": "fixture native target", "adapter": "controlled NATS", "target": "native_coord",
               "module": module, "owner": "proxy/tests/native_coord.rs"}
    metadata = root / catalogue.METADATA
    with metadata.open("a") as output:
        output.write("\n[[witnesses]]\n" + "\n".join(key + " = " + json.dumps(value) for key, value in witness.items()))
    if expected:
        with pytest.raises(ValueError, match=expected):
            catalogue.load(root)
    else:
        _controls, witnesses, _outside = catalogue.load(root)
        node = witnesses[-1]["resolved"][0][1][0]
        assert node["node"] == "reviews::required_review" and node["ignored"]
        command = {"tokens": ["scripts/cargo_with_space.sh", "test", "--test", "native_coord"]}
        assert not catalogue.cargo_selected(witness, node, command)
        command["tokens"] += ["--", "--include-ignored"]
        assert catalogue.cargo_selected(witness, node, command)


@pytest.mark.parametrize("failure", ["missing", "ignored", "failure", "timeout", None])
def test_native_host_selection_retains_partial_observations(tmp_path, monkeypatch, failure):
    """Missing/ignored/failed cases cannot become a complete installed receipt."""
    from tests.blackbox import native_authority

    executable = tmp_path / "fixture"
    executable.write_bytes(b"fixture identity")
    executor = tmp_path / "installed-executor"
    executor.write_bytes(b"independently installed identity")
    probe = tmp_path / "probe"
    probe.write_bytes(b"probe identity")
    monkeypatch.setenv("SAFEYOLO_HOST_EXECUTOR_PROBE", str(probe))
    monkeypatch.setenv("SAFEYOLO_HOST_EXECUTOR_SERVICE", "owned-test.service")
    monkeypatch.setenv("SAFEYOLO_HOST_ASSESSOR_BIN", str(executor))
    monkeypatch.setenv("SAFEYOLO_HOST_EXECUTOR_CGROUP", str(tmp_path / "delegation"))
    monkeypatch.setenv("SAFEYOLO_HOST_EXECUTOR_BWRAP", str(executable))
    monkeypatch.setattr(native_authority, "HOST_EXECUTION_AUTHORITY", {"BB-38": ("first", "second")})
    monkeypatch.setattr(native_authority, "controller_identity", lambda: {"controller_revision": "fixture", "controller_dirty": False})
    monkeypatch.setattr(native_authority.platform, "platform", lambda: "fixture OS")
    monkeypatch.setattr(native_authority.platform, "machine", lambda: "fixture architecture")
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        if "--version" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout="installed version", stderr="")
        case = argv[1]
        if "--list" in argv:
            text = "" if failure == "missing" and case == "second" else case + ": test\n"
            return subprocess.CompletedProcess(argv, 0, stdout=text, stderr="")
        if failure == "timeout" and case == "second":
            raise subprocess.TimeoutExpired(argv, 300)
        result = "ignored" if failure == "ignored" and case == "second" else "ok"
        kwargs["stdout"].write(f"test {case} ... independent observation\n{result}\n")
        kwargs["stdout"].write("test result: ok. " +
                               ("0 passed; 0 failed; 1 ignored;\n" if result == "ignored"
                                else "1 passed; 0 failed; 0 ignored;\n"))
        return subprocess.CompletedProcess(argv, 1 if failure == "failure" and case == "second" else 0)

    monkeypatch.setattr(native_authority.subprocess, "run", command)
    output = tmp_path / "results"
    if failure:
        with pytest.raises((AssertionError, RuntimeError)):
            native_authority.run(executable, output, suite="host-execution", executor=executor)
    else:
        native_authority.run(executable, output, suite="host-execution", executor=executor)
    report = json.loads((output / "result.json").read_text())
    rows = report["controls"]["BB-38"]["executed"]
    assert rows[0]["passed"] is True
    assert rows[1]["passed"] is (failure is None)
    assert report["complete"] is (failure is None)
    assert report["inputs"]["executor"]["path"] == str(executor)
    assert report["inputs"]["test_executable"]["sha256"] != report["inputs"]["executor"]["sha256"]
    if failure == "missing":
        assert not any(call[1] == "second" and "--list" not in call for call in calls)
    if failure == "timeout":
        assert "unverified" in rows[1]["cleanup"]


@pytest.mark.parametrize("missing,error,message", [
    ("SAFEYOLO_HOST_EXECUTOR_SERVICE", ValueError, "prepared owned service"),
    ("SAFEYOLO_HOST_ASSESSOR_BIN", KeyError, "SAFEYOLO_HOST_ASSESSOR_BIN"),
])
def test_native_host_missing_input_is_incomplete_without_dispatch(tmp_path, monkeypatch, missing, error, message):
    from tests.blackbox import native_authority

    executable = tmp_path / "fixture"
    executable.touch()
    monkeypatch.setenv("SAFEYOLO_HOST_EXECUTOR_PROBE", str(executable))
    monkeypatch.setenv("SAFEYOLO_HOST_EXECUTOR_SERVICE", "owned-test.service")
    monkeypatch.setenv("SAFEYOLO_HOST_ASSESSOR_BIN", str(executable))
    monkeypatch.delenv(missing, raising=False)
    output = tmp_path / "results"
    with pytest.raises(error, match=message):
        native_authority.run(executable, output, suite="host-execution", executor=executable)
    report = json.loads((output / "result.json").read_text())
    assert report["complete"] is False
    assert all(not control["executed"] for control in report["controls"].values())


def test_native_case_requires_one_executed_test_instead_of_target_pass_text():
    from tests.blackbox.native_authority import rust_case_passed

    assert not rust_case_passed(0, "target says PASS\n")
    assert not rust_case_passed(0, "test result: ok. 0 passed; 0 failed; 0 ignored;\n")
    assert not rust_case_passed(0, "test result: ok. 0 passed; 0 failed; 1 ignored;\n")
