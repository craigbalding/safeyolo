"""Detect catalogue drift without executing product or hardware tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.blackbox import catalogue
from tests.blackbox.selections import PROCEDURES

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def catalogue_root(tmp_path):
    for path in ("tests/blackbox/host/identity", "docs", ".github/workflows"):
        (tmp_path / path).mkdir(parents=True)
    shutil.copyfile(ROOT / "docs/assurance-map.toml", tmp_path / "docs/assurance-map.toml")
    metadata = ""
    for number in range(1, 38):
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
    shell = "\n".join("run_pytest_phase " + phase for phase in phases)
    for _section, (filename, checkpoints) in PROCEDURES.items():
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
        path.write_text(text.replace('id = "BB-37"', 'id = "BB-38"'))
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
        assert len(controls) == 37 and witnesses[0]["resolved"][0][1][0]["node"].endswith("::test_required")
        assert not any("BB-37" in witness["controls"] for witness in witnesses)


def test_current_catalogue_resolves_all_controls_and_external_families():
    controls, witnesses, _outside = catalogue.load(ROOT)
    assert len(controls) == 37
    assert {witness["kind"] for witness in witnesses} == {"pytest", "cargo", "procedure"}
    assert any("tests/test_guest_acquisition.py" in witness["paths"] for witness in witnesses)


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
