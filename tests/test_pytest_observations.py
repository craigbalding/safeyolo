"""Exercise retained outcomes through real pytest collection and execution."""

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.blackbox.installed_sections import PYTEST_SUITES, pytest_observations

ROOT = Path(__file__).resolve().parents[1]


def observation(suite):
    now = datetime.now(UTC).isoformat()
    return {"schema_version": 1, "started_at": now, "finished_at": now, "exit": 0, "deselected": 0,
            "suite": suite, "run_id": "a" * 32, "source_revision": "b" * 40, "collected": 1,
            "collection_errors": 0, "omitted_cases": 0, "counts": {"passed": 1},
            "cases": [{"test": "test_fixture.py::test_case", "case_sha256": "f" * 64,
                       "outcome": "passed", "phase": "call"}]}


@pytest.mark.parametrize("stop_after_failure", [False, True])
def test_real_pytest_retains_skips_and_unexecuted_cases_without_private_data(tmp_path, stop_after_failure):
    suite = tmp_path / "test_outcomes.py"
    suite.write_text("""
import pytest
@pytest.mark.parametrize('value', ['secret-parameter-one', 'secret-parameter-two'])
def test_pass(value): pass
@pytest.mark.skip(reason='secret skip diagnostic')
def test_skipped(): pass
def test_failure(): assert False, 'secret failure diagnostic'
def test_after_failure(): pass
""")
    artifacts = tmp_path / "artifacts"
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTEST_ADDOPTS": "",
           "SAFEYOLO_BLACKBOX_OBSERVATIONS_DIR": str(artifacts), "SAFEYOLO_BLACKBOX_PYTEST_SUITE": "isolation",
           "SAFEYOLO_BLACKBOX_RUN_ID": "a" * 32, "SAFEYOLO_BLACKBOX_INSTALL_REVISION": "b" * 40}
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "tests.blackbox.pytest_observations",
                             *(["-x"] if stop_after_failure else []), str(suite)],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, result.stdout + result.stderr
    content = (artifacts / "pytest-isolation.json").read_text()
    document = json.loads(content)
    assert "secret" not in content
    assert document["collected"] == 5
    assert document["counts"] == ({"passed": 2, "skipped": 1, "failed": 1, "unexecuted": 1}
                                   if stop_after_failure else {"passed": 3, "skipped": 1, "failed": 1})
    skipped = [row for row in document["cases"] if row["outcome"] == "skipped"]
    assert skipped == [{"test": "test_outcomes.py::test_skipped", "case_sha256": skipped[0]["case_sha256"],
                        "outcome": "skipped", "phase": "setup"}]
    parameterized = [row for row in document["cases"] if row["test"].endswith("test_pass")]
    assert len({row["case_sha256"] for row in parameterized}) == 2
    assert document["source_revision"] == "b" * 40
    assert document["run_id"] == "a" * 32


@pytest.mark.parametrize("explicit_plugin", [False, True])
def test_observer_supports_late_nested_conftest_collection(tmp_path, explicit_plugin):
    project = tmp_path / "project"
    blackbox = project / "tests/blackbox"
    blackbox.mkdir(parents=True)
    (project / "pytest.ini").write_text("[pytest]\n")
    for name in ("conftest.py", "pytest_observations.py"):
        shutil.copy2(ROOT / "tests/blackbox" / name, blackbox / name)
    (blackbox / "test_probe.py").write_text("def test_probe(): pass\n")
    artifacts = tmp_path / "artifacts"
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTEST_ADDOPTS": "",
           "SAFEYOLO_BLACKBOX_OBSERVATIONS_DIR": str(artifacts), "SAFEYOLO_BLACKBOX_PYTEST_SUITE": "isolation",
           "SAFEYOLO_BLACKBOX_RUN_ID": "a" * 32, "SAFEYOLO_BLACKBOX_INSTALL_REVISION": "b" * 40}
    result = subprocess.run([sys.executable, "-m", "pytest", "-q",
                             *(["-p", "tests.blackbox.pytest_observations"] if explicit_plugin else []), "tests"],
                            cwd=project, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    document = json.loads((artifacts / "pytest-isolation.json").read_text())
    assert document["collected"] == 1 and document["counts"] == {"passed": 1}


@pytest.mark.parametrize("failure", ["missing", "stale", "mixed-source", "wrong-suite", "unexecuted"])
def test_missing_or_misattributed_pytest_observations_do_not_pass(tmp_path, failure):
    for suite in PYTEST_SUITES:
        document = observation(suite)
        if suite == "isolation":
            if failure == "missing":
                continue
            if failure == "stale":
                document["run_id"] = "c" * 32
            if failure == "mixed-source":
                document["source_revision"] = "d" * 40
            if failure == "wrong-suite":
                document["suite"] = "identity"
            if failure == "unexecuted":
                document["counts"] = {"unexecuted": 1}
                document["cases"][0].update(outcome="unexecuted", phase=None)
        (tmp_path / f"pytest-{suite}.json").write_text(json.dumps(document))
    observations, failures = pytest_observations(tmp_path, "a" * 32, "b" * 40)
    assert len(observations) == (6 if failure == "unexecuted" else 5)
    assert len(failures) == 1 and failures[0].startswith("isolation:")


def test_generated_observation_field_shapes_are_reported_as_incomplete(tmp_path):
    for suite in PYTEST_SUITES:
        (tmp_path / f"pytest-{suite}.json").write_text(json.dumps(observation(suite)))
    original = observation("isolation")
    values = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=60),
                          lambda child: st.lists(child, max_size=5) | st.dictionaries(st.text(max_size=30), child, max_size=5),
                          max_leaves=10)

    @given(field=st.sampled_from(["schema_version", "started_at", "finished_at", "exit", "collected", "deselected",
                                 "collection_errors", "counts", "omitted_cases", "cases"]), value=values)
    def report_failure(field, value):
        (tmp_path / "pytest-isolation.json").write_text(json.dumps({**original, field: value}))
        observations, failures = pytest_observations(tmp_path, "a" * 32, "b" * 40)
        assert len(failures) <= 1
        assert all(message.startswith("isolation:") for message in failures)
        assert len(observations) in (5, 6)

    report_failure()
