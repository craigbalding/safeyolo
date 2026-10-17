"""Exercise quarantine, trusted staging and exact installed gate selection."""
import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts import guest_release as release

NOW = datetime(2026, 10, 17, 2, 47, tzinfo=UTC)
INDEX = {"digest": "sha256:" + "a" * 64, "size": 123, "mediaType": "application/vnd.oci.image.index.v1+json"}


def candidate(age=172800, digit="a"):
    return {"index": {**INDEX, "digest": "sha256:" + digit * 64}, "staged_at": (NOW - timedelta(seconds=age)).isoformat(),
            "source_revision": "b" * 40, "compatibility": "v1", "producer": {"run_id": 123, "run_attempt": 2, "job_id": 456}}


@pytest.fixture
def producer(monkeypatch):
    calls = []
    def verify(identity, source, workflow, branch):
        calls.append(identity)
        assert branch == "master" and source == "b" * 40
        assert identity["run_attempt"] == 2
        return {"started_at": "2026-10-10T23:50:00Z", "completed_at": "2026-10-17T03:00:00Z"}
    monkeypatch.setattr(release.selection, "verify_producer", verify)
    return calls


@pytest.mark.parametrize("seconds,eligible", [(172799, False), (172800, True), (172801, True), (4 * 86400, True)])
def test_exact_elapsed_quarantine(seconds, eligible, producer):
    value = candidate(seconds)
    assert (release.newest_eligible([(value, {})], "master", NOW) == value) == eligible


def test_a_b_c_nights_and_failed_c_build_do_not_reset_a(producer):
    a, b, c = candidate(172800, "a"), candidate(86400, "b"), candidate(0, "c")
    assert release.newest_eligible([(c, {}), (a, {}), (b, {})], "master", NOW) == a
    assert release.newest_eligible([(a, {}), (b, {})], "master", NOW) == a
    assert len(producer) == 2


def test_long_build_midnight_and_missed_cron_use_complete_staging(producer):
    value = candidate(172800)
    # Neither upstream/commit/run start nor version date enters the calculation.
    value.update(version="guest-1999-01-01.1", run_started_at="2025-01-01T00:00:00Z")
    assert release.newest_eligible([(value, {})], "master", NOW) == value
    assert release.newest_eligible([(value, {})], "master", NOW - timedelta(seconds=1)) is None
    assert release.newest_eligible([(value, {})], "master", NOW + timedelta(days=3)) == value


@pytest.mark.parametrize("time", [None, "", "not-a-date", "2026-10-17T02:47:01Z", "2026-10-15T02:47:00"])
def test_missing_malformed_future_and_non_utc_staging_cannot_age(time, producer):
    value = candidate()
    value["staged_at"] = time
    with pytest.raises((ValueError, TypeError)):
        release.newest_eligible([(value, {})], "master", NOW)


def test_failed_or_mismatched_staging_job_is_not_trusted(monkeypatch):
    value = candidate()
    monkeypatch.setattr(release.selection, "verify_producer", lambda *args: {"started_at": "2026-10-15T03:00:00Z", "completed_at": "2026-10-15T04:00:00Z"})
    with pytest.raises(ValueError, match="outside"):
        release.validate_stage(value, "master", NOW)
    def failed(*args):
        raise ValueError("selected producer job did not complete successfully")
    monkeypatch.setattr(release.selection, "verify_producer", failed)
    with pytest.raises(ValueError, match="successfully"):
        release.newest_eligible([(value, {})], "master", NOW)


def evidence(value):
    return [{"schema": "safeyolo.guest-smoke/v1", "index_digest": value["index"]["digest"], "platform": platform,
             "result": "passed", "operator": "trusted-operator", "finished_at": (NOW - timedelta(hours=1)).isoformat(),
             "host_id": "controlled-host", "gate_url": "https://example.invalid/retained-result",
             "host": {"profile": "production", "platform": platform, "compatibility": "v1", "source_revision": "b" * 40,
                      "archive": {"sha256": "c" * 64}},
             "lane": "vz" if platform == "darwin-arm64" else "systrap", "guest": {"index": value["index"], "compatibility": "v1"}}
            for platform in release.selection.PLATFORMS]


def test_exact_three_platform_proof_reused_without_running_it_twice(monkeypatch, producer):
    monkeypatch.setattr(release, "verify_operator", lambda actor: None)
    value = candidate()
    proof = evidence(value)
    assert release.gates(value, proof, "master") == proof
    assert release.gates(value, proof, "master") == proof
    for defect in ("missing-arm", "failed", "hosted-mac", "wrong-bytes", "before-staging", "newer-failure"):
        changed = copy.deepcopy(proof)
        if defect == "missing-arm":
            changed.pop(1)
        if defect == "failed":
            changed[0]["result"] = "failed"
        if defect == "hosted-mac":
            changed[2]["lane"] = "package"
        if defect == "wrong-bytes":
            changed[0]["guest"]["index"]["digest"] = "sha256:" + "f" * 64
        if defect == "before-staging":
            changed[0]["finished_at"] = "2020-01-01T00:00:00Z"
        if defect == "newer-failure":
            changed.append({**changed[0], "result": "failed", "finished_at": NOW.isoformat()})
        with pytest.raises(ValueError):
            release.gates(value, changed, "master")


def test_same_digest_retry_preserves_original_trusted_receipt(tmp_path, monkeypatch, producer):
    value = candidate()
    monkeypatch.setenv("GITHUB_SHA", value["source_revision"])
    monkeypatch.setattr(release, "branch", lambda: "master")
    monkeypatch.setattr(release.selection, "manifest", lambda ref: (value["index"], {"annotations": {"org.opencontainers.image.revision": value["source_revision"]}}))
    monkeypatch.setattr(release.selection, "staging_receipt", lambda *args: {"staged_at": value["staged_at"], "producer": value["producer"]})
    monkeypatch.setattr(release, "attach", lambda *args: pytest.fail("retry rewrote original receipt"))
    result = release.stage(SimpleNamespace(index=value["index"]["digest"], staged_at=NOW.isoformat(), provenance=tmp_path))
    assert result["staged_at"] == value["staged_at"]
    assert result["producer"]["run_attempt"] == 2
    # A new digest does not have this receipt and cannot borrow its age.
    rebuilt = candidate(0, "f")
    assert release.newest_eligible([(rebuilt, {})], "master", NOW) is None


def promotion_fixture(tmp_path, monkeypatch):
    value = candidate()
    monkeypatch.setattr(release, "branch", lambda: "master")
    monkeypatch.setattr(release, "promotion_context", lambda: {"source_revision": "b" * 40, "publisher_version": "controlled"})
    monkeypatch.setattr(release, "paused", lambda: False)
    monkeypatch.setattr(release.selection, "staged_guest_candidates", lambda *args: ([(value, {})], ["legacy-index"]))
    monkeypatch.setattr(release, "datetime", SimpleNamespace(now=lambda *args: NOW))
    monkeypatch.setattr(release.selection, "verify_producer", lambda *args: {
        "started_at": (NOW - timedelta(days=5)).isoformat(), "completed_at": NOW.isoformat()})
    monkeypatch.setattr(release, "records", lambda *args: evidence(value))
    monkeypatch.setattr(release, "verify_operator", lambda *args: None)
    monkeypatch.setattr(release, "differences", lambda *args: {"packages": "fixture"})
    state = {"index": "sha256:" + "e" * 64, "writes": [], "verified": False, "receipts": []}
    monkeypatch.setattr(release, "channel", lambda *args: state["index"])
    def verify(selected, verifier, path):
        state["verified"] = True
        assert selected["index"] == value["index"]
    monkeypatch.setattr(release, "verify_content", verify)
    monkeypatch.setattr(release, "attach", lambda *args: state["receipts"].append(copy.deepcopy(args[2])))
    def tag(*args):
        assert state["verified"]
        state["writes"].append(args)
        assert args == ("oras", "tag", f"{release.selection.GUEST_REPOSITORY}@{value['index']['digest']}", "compat-v1")
        state["index"] = value["index"]["digest"]
        return ""
    monkeypatch.setattr(release, "command", tag)
    args = SimpleNamespace(compatibility="v1", work_directory=tmp_path, verifier=tmp_path / "verifier")
    return value, state, args


def test_promotion_only_moves_tag_after_gates_and_content(tmp_path, monkeypatch):
    _, state, args = promotion_fixture(tmp_path, monkeypatch)
    assert release.promote(args)["decision"] == "promoted"
    assert len(state["writes"]) == 1
    assert [row["decision"] for row in state["receipts"]] == ["qualified", "promoted"]
    assert release.promote(args)["decision"] == "unchanged"
    assert len(state["writes"]) == 1


@pytest.mark.parametrize("failure", ["missing-smoke", "bad-content", "concurrent", "paused", "late-older"])
def test_holds_preserve_existing_channel(tmp_path, monkeypatch, failure):
    value, state, args = promotion_fixture(tmp_path, monkeypatch)
    if failure == "missing-smoke":
        monkeypatch.setattr(release, "records", lambda *args: [])
    if failure == "bad-content":
        def bad(*args):
            raise ValueError("corrupt staged archive")
        monkeypatch.setattr(release, "verify_content", bad)
    if failure == "paused":
        monkeypatch.setattr(release, "paused", lambda: True)
    if failure == "concurrent":
        responses = iter([state["index"], "sha256:" + "f" * 64])
        monkeypatch.setattr(release, "channel", lambda *args: next(responses))
    if failure == "late-older":
        current = candidate(0, "e")
        monkeypatch.setattr(release.selection, "staged_guest_candidates", lambda *args: ([(value, {}), (current, {})], []))
        monkeypatch.setattr(release, "validate_stage", lambda *args: NOW)
    if failure == "paused":
        assert release.promote(args)["decision"] == "held"
    else:
        with pytest.raises(ValueError):
            release.promote(args)
    assert not state["writes"]
    assert state["index"] == "sha256:" + "e" * 64


def test_workflow_has_independent_utc_activities_and_no_normal_bypass():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/guest-oci.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert {row["cron"] for row in events["schedule"]} == {"17 1 * * *", "47 2 * * *"}
    assert "needs" not in workflow["jobs"]["promote"]
    assert workflow["jobs"]["receipt"]["needs"] == "stage"
    assert workflow["concurrency"] == {"group": "default-guest-publication", "cancel-in-progress": False}
    assert not any(name.startswith("publish_") for name in events["workflow_dispatch"]["inputs"])
    source = (root / "scripts/publish_guest_oci.sh").read_text()
    assert '"compat-$compatibility"' not in source
    assert "T00:00:00Z" not in source
    assert "sleep" not in (root / ".github/workflows/guest-oci.yml").read_text()


def test_complete_promotion_rejects_172799_without_a_tag_write(tmp_path, monkeypatch):
    value, state, args = promotion_fixture(tmp_path, monkeypatch)
    value["staged_at"] = (NOW - timedelta(seconds=172799)).isoformat()
    assert release.promote(args)["decision"] == "held"
    assert not state["writes"] and not state["verified"]


def report_files(directory, platform="darwin-arm64"):
    directory.mkdir()
    (directory / "guest").mkdir()
    descriptor = {"digest": "sha256:" + "c" * 64, "size": 10, "mediaType": "fixture"}
    frozen = {"status": "selected", "platform": platform, "host": {"source_revision": "b" * 40, "compatibility": "v1",
               "executables_sha256": {"safeyolo": "d" * 64}}, "guest": {"index": INDEX, "child": descriptor,
               "archive": descriptor, "compatibility": "v1"}}
    installed = {"guest": {name: {key: source[key] for key in ("digest", "size")} for name, source in
                          (("index", INDEX), ("manifest", descriptor), ("archive", descriptor))}, "platform": platform,
                 "installed_files_sha256": frozen["host"]["executables_sha256"], "host_source_revision": "b" * 40,
                 "profile": "production"}
    run = {"exit": 0, "lane": "vz", "controller_dirty": False, "controller_revision": "e" * 40,
           "host_id": "physical-test-mac", "host_system": "Darwin", "host_architecture": "arm64",
           "finished_at": NOW.isoformat()}
    sections = {"source_revision": "b" * 40, "lane": "vz", "sections": [{"section": "isolation", "exit": 0, "result": "passed"}]}
    for name, value in (("selection.json", frozen), ("installed-inputs.json", installed), ("retained-run.json", run),
                        ("guest/installed-sections.json", sections)):
        (directory / name).write_text(json.dumps(value))
    return frozen, installed, run, sections


@pytest.mark.parametrize("fault", [None, "package-only", "wrong-archive", "wrong-host", "failed-cleanup", "dirty-controller"])
def test_smoke_receipt_uses_existing_installed_reports(tmp_path, fault):
    reports = tmp_path / "physical"
    frozen, installed, run, sections = report_files(reports)
    if fault == "package-only":
        run["lane"] = "package"
    if fault == "wrong-archive":
        installed["guest"]["archive"]["size"] += 1
    if fault == "wrong-host":
        installed["host_source_revision"] = "f" * 40
    if fault == "failed-cleanup":
        sections["sections"][0]["result"] = "cleanup_failure"
    if fault == "dirty-controller":
        run["controller_dirty"] = True
    for name, value in (("installed-inputs.json", installed), ("retained-run.json", run), ("guest/installed-sections.json", sections)):
        (reports / name).write_text(json.dumps(value))
    gate_url = "https://github.com/craigbalding/safeyolo/issues/1104#issuecomment-123"
    if fault:
        with pytest.raises(ValueError):
            release.smoke_result(reports, gate_url)
    else:
        result = release.smoke_result(reports, gate_url)
        assert result["index_digest"] == frozen["guest"]["index"]["digest"]
        assert result["host_id"] == "physical-test-mac" and result["lane"] == "vz"


def test_receipt_retry_looks_up_the_original_stage_attempt(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    def jobs(endpoint, field):
        assert endpoint == "actions/runs/123/attempts/1/jobs?per_page=100" and field == "jobs"
        return [{"name": "stage", "id": 456}]
    monkeypatch.setattr(release.selection, "pages", jobs)
    identity = release.producer("stage", 1)
    assert identity["run_attempt"] == 1 and identity["job_id"] == 456
