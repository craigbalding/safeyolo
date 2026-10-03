"""Real runner/report and subprocess publication controls; no hardware runs."""

import copy
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests import test_blackbox_harness
from tests.blackbox import installed_sections
from tests.blackbox.hardware import attempt_results, publish_results, service_calls

runner_commands = test_blackbox_harness.installed_section_commands


@pytest.fixture
def github_fixture(tmp_path, monkeypatch):
    """Exercise the actual gh subprocess request/read-back path locally."""
    executable = tmp_path / "gh"
    store = tmp_path / "github.json"
    store.write_text(json.dumps({"comments": {}, "next_id": 1, "calls": [], "selected": "a" * 40}))
    executable.write_text(f"#!{sys.executable}\n" + """
import json, os, sys
from pathlib import Path
path = Path(os.environ['FIXTURE_GITHUB_STORE'])
data = json.loads(path.read_text())
route = sys.argv[2]
method = sys.argv[sys.argv.index('--method') + 1]
data['calls'].append([route, method])
if data.get('deny'): sys.exit(7)
base = 'repos/craigbalding/safeyolo'
if route == base: result = {'default_branch': 'master'}
elif route.startswith(base + '/commits/'): result = {'sha': data['selected']}
elif method == 'POST':
    assert route == base + '/issues/889/comments'
    identifier = data['next_id']; data['next_id'] += 1
    result = {'id': identifier, 'html_url': 'https://github.com/craigbalding/safeyolo/issues/889#issuecomment-' + str(identifier),
              'body': json.load(sys.stdin)['body']}
    data['comments'][str(identifier)] = result
else:
    identifier = route.rsplit('/', 1)[1]
    result = data['comments'][identifier]
    if method == 'PATCH': result['body'] = json.load(sys.stdin)['body']
    if method == 'GET' and data.get('tamper'): result = dict(result, body='unrelated or partial result')
path.write_text(json.dumps(data))
print(json.dumps(result))
""")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("FIXTURE_GITHUB_STORE", str(store))
    return publish_results.GitHubResults(), store


@pytest.fixture
def runner_summary(tmp_path, runner_commands):
    attempt = attempt_results.HardwareAttempt(tmp_path / "attempts", "b" * 40, "on-demand")
    attempt.select("a" * 40)
    receipt = attempt.start_lane("kvm")
    artifacts = tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "kvm", installed_sections.SECTIONS["kvm"], runner_commands, "a" * 40,
        tmp_path / "installed", artifacts, run_id=receipt["run_id"],
    ) == 0
    private = json.loads((artifacts / "installed-sections.json").read_text())
    assert private["run_id"] == receipt["run_id"]
    assert all(data["run_id"] == receipt["run_id"] for data in private["sections"][0]["pytest"])
    assert not list((tmp_path / "installed").glob("*/agents/*/container.pid"))
    return attempt, artifacts / "installed-summary.json"


def test_attempt_is_saved_before_selection_and_published_before_fetch(tmp_path, github_fixture):
    github, store = github_fixture
    with publish_results.managed_attempt(tmp_path / "attempts", "b" * 40, "overnight", github) as attempt:
        recorded = attempt_results.read_json(attempt.directory / "attempt.json")
        assert recorded["source_revision"] is None
        assert stat.S_IMODE(attempt.directory.stat().st_mode) == 0o700
        comments = json.loads(store.read_text())["comments"]
        assert len(comments) == 1 and "not selected" in comments["1"]["body"]
        assert service_calls.select_source(attempt, github) == "a" * 40
        with attempt.phase("preflight"):
            attempt.fail("preflight")
    assert attempt.data["publication"]["verified"] is True
    assert attempt.execution_succeeded() is False
    assert attempt_results.read_json(attempt.directory / "attempt.json")["finished_at"]
    bodies = json.dumps(json.loads(store.read_text())["comments"])
    assert "preflight" in bodies and f"commit/{'a' * 40}" in bodies


def test_untrusted_ref_cannot_reach_origin_or_change_selection(tmp_path, github_fixture):
    github, store = github_fixture
    attempt = attempt_results.HardwareAttempt(tmp_path / "attempts", "b" * 40, "on-demand")
    for selection in (None, "master", "refs/pull/905/head", "a" * 39, "A" * 40):
        with pytest.raises(ValueError):
            service_calls.select_source(attempt, github, selection)
    assert json.loads(store.read_text())["calls"] == []
    assert service_calls.select_source(attempt, github, "a" * 40) == "a" * 40
    with pytest.raises(ValueError):
        attempt.select("c" * 40)


def test_verified_kvm_summary_is_insufficient_for_paired_success(runner_summary):
    attempt, summary = runner_summary
    attempt.retain_lane("kvm", summary)
    assert attempt.data["lanes"]["kvm"]["result"]["complete_success"] is True
    assert attempt.execution_succeeded() is False
    attempt.data["lanes"]["kvm"]["cleanup"] = "verified"
    assert attempt.execution_succeeded() is False
    attempt.start_lane("vz")
    attempt.retain_lane("vz", summary)
    attempt.finish()
    assert {"stage": "report", "lane": "vz"} in attempt.data["failures"]
    assert attempt.execution_succeeded() is False


def test_generated_stale_partial_and_failed_reports_cannot_pass(runner_summary):
    attempt, path = runner_summary
    original = json.loads(path.read_text())
    expected = attempt.data["lanes"]["kvm"]

    @settings(max_examples=40, deadline=None)
    @given(st.sets(st.sampled_from(("sha", "run", "stale", "exit", "section", "partial", "runtime", "pytest", "cleanup")), max_size=5),
           st.text(min_size=1, max_size=100))
    def verify(mutations, private):
        data = copy.deepcopy(original)
        data["private_instance"] = private
        data["preparation"]["private_key"] = private
        isolation = data["sections"][0]
        isolation["installed_runtime"]["process"]["private_state"] = private
        for case in isolation["pytest"][0]["cases"]:
            case["capture"] = private
        if "sha" in mutations:
            data["source_revision"] = "c" * 40
        if "run" in mutations:
            data["run_id"] = "c" * 32
        if "stale" in mutations:
            data["started_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        if "exit" in mutations:
            data["exit"] = 2
        if "section" in mutations:
            isolation.update(exit=1, result="assertion_failure")
        if "partial" in mutations:
            data["requested_sections"] = ["isolation", "ingress"]
            data["sections"] = data["sections"][:2]
            data["full_section_selection"] = False
        if "runtime" in mutations:
            isolation["installed_runtime"] = None
        if "pytest" in mutations:
            observation = isolation["pytest"][0]
            observation["counts"] = {"failed": 1}
            observation["cases"][0]["outcome"] = "failed"
        if "cleanup" in mutations:
            isolation.update(cleanup="failed", cleanup_failure_count=1)
        path.write_text(json.dumps(data))
        try:
            result = attempt_results.lane_result(path, expected)
        except ValueError:
            assert mutations & {"sha", "run", "stale"}
            return
        assert result["complete_success"] == (not mutations)
        assert "private_instance" not in result and "private_key" not in result["preparation"]
        assert "private_state" not in result["sections"][0].get("installed_runtime", {}).get("process", {})
        assert "capture" not in result["sections"][0]["pytest"][0]["cases"][0]

    verify()


def test_skips_remain_unproved_in_published_results(runner_summary, github_fixture, monkeypatch):
    attempt, path = runner_summary
    github, store = github_fixture
    data = json.loads(path.read_text())
    observation = data["sections"][0]["pytest"][0]
    observation["counts"] = {"skipped": 1}
    observation["cases"][0].update(outcome="skipped", phase="setup", traceback="private skipped traceback")
    path.write_text(json.dumps(data))
    attempt.retain_lane("kvm", path)
    assert attempt.data["lanes"]["kvm"]["result"]["skipped_assertions"] == 1
    attempt.data["lanes"]["kvm"]["allocation"] = {"disk_path": "/private/operator/disk", "token": "private adapter token"}
    attempt.data["lanes"]["kvm"]["result"]["private_diagnostic"] = "private retained annotation"
    attempt.finish()
    monkeypatch.setattr(publish_results, "COMMENT_CHARACTERS", 1500)
    publish_results.publish_attempt(attempt, github)
    assert attempt.data["publication"]["verified"] is True
    comments = json.loads(store.read_text())["comments"]
    assert len(comments) > 3
    bodies = json.dumps(comments)
    assert "Skipped assertions: 1; skipped assertions remain unproved" in bodies
    assert "private skipped traceback" not in bodies and str(path.parent) not in bodies
    assert "private adapter token" not in bodies and "private retained annotation" not in bodies
    assert "/private/operator/disk" not in bodies
    assert "failed or incomplete execution" in comments["1"]["body"]
    assert all(comment["html_url"] in comments["1"]["body"] for key, comment in comments.items() if key != "1")


def test_partial_publication_and_readback_failure_remain_failed(tmp_path, github_fixture):
    github, store = github_fixture
    attempt = attempt_results.HardwareAttempt(tmp_path / "attempts", "b" * 40, "overnight")
    publish_results.announce_attempt(attempt, github)
    attempt.fail("selection")
    attempt.finish()
    data = json.loads(store.read_text())
    data["tamper"] = True
    store.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        publish_results.publish_attempt(attempt, github)
    assert attempt.data["publication"]["verified"] is False
    assert {"stage": "publication", "lane": None} in attempt.data["failures"]
    assert attempt.execution_succeeded() is False
    data = json.loads(store.read_text())
    data.pop("tamper")
    store.write_text(json.dumps(data))
    publish_results.publish_attempt(attempt, github)
    assert attempt.data["publication"]["verified"] is True
    assert attempt.execution_succeeded() is False, "publication retry must preserve the failed original"


def test_cancellation_is_published_without_becoming_success(tmp_path, github_fixture):
    github, store = github_fixture
    with pytest.raises(KeyboardInterrupt):
        with publish_results.managed_attempt(tmp_path / "attempts", "b" * 40, "overnight", github) as attempt:
            with attempt.phase("execution", lane="vz"):
                raise KeyboardInterrupt
    assert attempt.data["publication"]["verified"] is True
    assert {"stage": "cancelled", "lane": "vz"} in attempt.data["failures"]
    assert "cancelled (vz)" in json.loads(store.read_text())["comments"]["1"]["body"]


def test_publication_outage_does_not_replace_cancellation(tmp_path, github_fixture):
    github, store = github_fixture
    with pytest.raises(KeyboardInterrupt):
        with publish_results.managed_attempt(tmp_path / "attempts", "b" * 40, "overnight", github) as attempt:
            data = json.loads(store.read_text())
            data["deny"] = True
            store.write_text(json.dumps(data))
            with attempt.phase("execution", lane="vz"):
                raise KeyboardInterrupt
    assert attempt.data["publication"]["verified"] is False
    assert {"stage": "publication", "lane": None} in attempt.data["failures"]
    assert {"stage": "cancelled", "lane": "vz"} in attempt.data["failures"]
    assert "pending or failed; this attempt cannot pass" in json.loads(store.read_text())["comments"]["1"]["body"]


def test_report_reader_rejects_special_and_oversized_files_before_read(tmp_path, monkeypatch):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    symlink = tmp_path / "link"
    symlink.symlink_to(fifo)
    oversized = tmp_path / "large.json"
    oversized.write_bytes(b" " * 1025)
    monkeypatch.setattr(attempt_results, "MAX_REPORT_BYTES", 1024)
    for path in (fifo, symlink, tmp_path, oversized):
        with pytest.raises((OSError, ValueError)):
            attempt_results.read_json(path)


def test_pair_requires_both_reports_cleanup_and_verified_publication(runner_summary, github_fixture):
    """Synthetic Mac observations check pairing; they prove no Mac execution."""
    attempt, kvm_path = runner_summary
    github, _store = github_fixture
    attempt.retain_lane("kvm", kvm_path)
    vz = attempt.start_lane("vz")
    document = copy.deepcopy(json.loads(kvm_path.read_text()))
    stamp = datetime.now(UTC).isoformat()
    document.update(lane="vz", run_id=vz["run_id"], started_at=stamp, finished_at=stamp,
                    requested_sections=list(installed_sections.SECTIONS["vz"]))
    document["preparation"].update(source_revision="a" * 40, wheel_sha256="d" * 64, input_index_sha256="e" * 64,
                                   tmux_sha256="7" * 64, tmux_version="tmux 3.7c",
                                   vm_helper={"git_sha": "a" * 40, "git_dirty": False, "architecture": "arm64", "build_profile": "production"},
                                   boot_inputs={name: {"source_revision": "b" * 40, "sha256": "f" * 64}
                                                for name in attempt_results.BOOT_FILES})
    document["sections"].append(copy.deepcopy(document["sections"][-1]))
    for section, name in zip(document["sections"], installed_sections.SECTIONS["vz"]):
        section.update(section=name, started_at=stamp, finished_at=stamp)
        if name == "continuity":
            section.pop("installed_runtime")
        else:
            runtime = section["installed_runtime"]
            runtime.update(run_id=vz["run_id"], isolation_platform="vz", captured_at=stamp,
                           host={"system": "Darwin", "machine": "arm64"})
            runtime["process"]["start_token"] = f"darwin:{runtime['process']['pid']}:123:456"
        for pytest_result in section.get("pytest", []):
            pytest_result.update(run_id=vz["run_id"], started_at=stamp, finished_at=stamp)
    path = kvm_path.with_name("vz-summary.json")
    path.write_text(json.dumps(document))
    attempt.retain_lane("vz", path)
    attempt.finish()
    assert not attempt.execution_succeeded()
    attempt.data["lanes"]["kvm"]["cleanup"] = "verified"
    assert not attempt.execution_succeeded()
    attempt.data["lanes"]["vz"]["cleanup"] = "verified"
    assert attempt.execution_succeeded() and not attempt.passed()
    publish_results.publish_attempt(attempt, github)
    assert attempt.passed()
    restored = attempt_results.HardwareAttempt.restore(attempt.directory)
    assert restored.passed() and restored.data["source_revision"] == "a" * 40


def test_replay_command_publishes_failure_without_rerunning_or_replacing_attempt(tmp_path, github_fixture):
    github, store = github_fixture
    attempt = attempt_results.HardwareAttempt(tmp_path / "attempts", "b" * 40, "overnight")
    publish_results.announce_attempt(attempt, github)
    attempt.fail("allocation", lane="kvm")
    attempt.finish()
    finished = attempt.data["finished_at"]
    command = [sys.executable, "-m", "tests.blackbox.hardware.publish_results", "--attempt", str(attempt.directory)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    published = json.loads(result.stdout)
    assert published["run_id"] == attempt.data["run_id"]
    assert published["publication_verified"] is True and published["attempt_passed"] is False
    original_comments = json.loads(store.read_text())["comments"]
    again = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert again.returncode == 0, again.stderr
    assert json.loads(store.read_text())["comments"] == original_comments
    restored = attempt_results.HardwareAttempt.restore(attempt.directory)
    assert restored.data["finished_at"] == finished
    assert restored.data["failures"] == [{"stage": "allocation", "lane": "kvm"}]
    assert len(list((tmp_path / "attempts").iterdir())) == 1


def test_replay_cannot_replace_another_attempts_index(tmp_path, github_fixture):
    github, store = github_fixture
    first = attempt_results.HardwareAttempt(tmp_path / "attempts", "b" * 40, "overnight")
    second = attempt_results.HardwareAttempt(tmp_path / "attempts", "b" * 40, "on-demand")
    publish_results.announce_attempt(first, github)
    publish_results.announce_attempt(second, github)
    before = copy.deepcopy(json.loads(store.read_text())["comments"])
    first.data["publication"]["index"] = second.data["publication"]["index"]
    with pytest.raises(ValueError):
        publish_results.publish_attempt(first, github)
    assert json.loads(store.read_text())["comments"] == before
    assert first.data["publication"]["verified"] is False


def test_invalid_caller_run_id_is_rejected_before_product_preparation(tmp_path):
    artifacts = tmp_path / "artifacts"
    result = subprocess.run([sys.executable, str(installed_sections.REPOSITORY / "tests/blackbox/installed_sections.py"),
                             "kvm", "--run-id", "refs/pull/905/head", "--artifacts", str(artifacts)],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 2 and "--run-id must be" in result.stderr
    assert not artifacts.exists()
