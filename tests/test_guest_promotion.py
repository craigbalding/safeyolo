"""Exercise quarantine, trusted staging and exact installed gate selection."""
import copy
import json
import subprocess
import sys
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


@pytest.mark.parametrize("failure", ["newest-smoke", "held-retention", "qualified-retention", "tag", "readback", "uncertain-retention", "promoted-retention"])
def test_promotion_failure_keeps_decision_in_stdout_and_actions_summary(tmp_path, monkeypatch, capsys, failure):
    value, state, args = promotion_fixture(tmp_path, monkeypatch)
    origin = {"source_revision": "b" * 40, "publisher_version": "controlled",
              "producer": {"run_id": 1234, "run_attempt": 2, "job_id": 5678},
              "job_url": "https://example.invalid/promotion-job"}
    monkeypatch.setattr(release, "promotion_context", lambda: origin)
    old = state["index"]
    refused = {"schema": "safeyolo.guest-smoke/v1", "index_digest": value["index"]["digest"],
               "platform": "linux-amd64", "result": "failed", "finished_at": NOW.isoformat(),
               "reason": "original installed run failed", "gate_url": "https://example.invalid/failed-run",
               "controller_revision": "d" * 40, "producer": {"run_id": 789, "run_attempt": 1, "job_id": 987}}
    if failure in {"newest-smoke", "held-retention"}:
        # Receipt discovery order does not determine which result is newest.
        proof = [refused, *evidence(value), {**refused, "finished_at": (NOW - timedelta(minutes=1)).isoformat()}]
        monkeypatch.setattr(release, "records", lambda *args: proof)
    if failure.endswith("retention"):
        def retain(index, kind, result):
            refused_decision = "publication-uncertain" if failure == "uncertain-retention" else failure.removesuffix("-retention")
            if result["decision"] == refused_decision:
                raise ValueError("decision attachment readback failed")
            state["receipts"].append(copy.deepcopy(result))
        monkeypatch.setattr(release, "attach", retain)
    if failure in {"tag", "uncertain-retention"}:
        def tag(*arguments):
            state["writes"].append(arguments)
            raise subprocess.CalledProcessError(1, arguments)
        monkeypatch.setattr(release, "command", tag)
    if failure == "readback":
        responses = iter([old, old, "sha256:" + "f" * 64])
        monkeypatch.setattr(release, "channel", lambda *args: next(responses))
    summary = tmp_path / "summary.md"
    summary.write_text("Earlier step\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(sys, "argv", ["guest_release.py", "promote", "--verifier", str(args.verifier),
                                     "--work-directory", str(tmp_path)])
    with pytest.raises(SystemExit) as stopped:
        release.main()
    assert stopped.value.code == 2
    output = capsys.readouterr().out
    result = json.loads(output)
    assert summary.read_text() == "Earlier step\n```json\n" + output + "```\n"
    assert result["index_digest"] == result["new_index"] == value["index"]["digest"]
    assert result["old_index"] == old and result["compatibility"] == "v1"
    assert result["source_revision"] == "b" * 40 and result["at"] == NOW.isoformat()
    assert all(result[key] == expected for key, expected in origin.items())
    if failure in {"newest-smoke", "held-retention"}:
        assert result["decision"] == "held"
        assert result["failed_smoke"] == refused
        assert result["reason"] == "latest installed smoke failed: linux-amd64"
        assert not state["verified"]
    elif failure in {"tag", "readback", "uncertain-retention"}:
        assert result["decision"] == "publication-uncertain"
        assert result["gates"] == evidence(value)
    elif failure == "promoted-retention":
        assert result["decision"] == "promoted" and result["promoted_at"]
        assert state["index"] == value["index"]["digest"]
    else:
        assert result["decision"] == "held"
    if failure == "qualified-retention":
        assert result["reason"] == "decision attachment readback failed"
        assert state["receipts"][-1] == result
    elif failure.endswith("retention"):
        assert result["retention_error"] == "decision attachment readback failed"
    else:
        assert state["receipts"][-1] == result
    if result["decision"] == "held":
        assert not state["writes"] and state["index"] == old
    else:
        assert len(state["writes"]) == 1


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


@pytest.mark.parametrize("mismatch", [None, "run_id", "run_attempt", "job_id", "repository", "workflow"])
def test_inspection_locates_historical_subject_by_exact_job_attempt(tmp_path, monkeypatch, capsys, mismatch):
    historical, current = candidate(digit="b"), candidate(digit="c")
    origin = {"repository": release.selection.REPOSITORY, "workflow": release.selection.GUEST_WORKFLOW,
              "run_id": 123, "run_attempt": 2, "job_id": 456}
    recorded = {**origin, **({mismatch: "different"} if mismatch else {})}
    decision = {"decision": "held", "index_digest": historical["index"]["digest"], "producer": recorded}
    monkeypatch.setattr(release.selection, "gh", lambda endpoint: {
        "name": "promote", "id": 456, "run_id": 123, "run_attempt": 2, "html_url": "https://example.invalid/promotion"})
    monkeypatch.setattr(release, "command", lambda *args: json.dumps({"tags": ["compat-v1", "guest-2026-10-26.1", "guest-2026-10-15.1"]}))
    def manifest(reference):
        assert not reference.endswith(":compat-v1")
        selected = historical if reference.endswith(":guest-2026-10-15.1") else current
        return selected["index"], {"annotations": {"source": selected["source_revision"]}}
    monkeypatch.setattr(release.selection, "manifest", manifest)
    def records(index, kind, *, include_attachment):
        assert include_attachment
        if kind == release.DECISION and index == historical["index"]:
            return [{"receipt": decision}]
        return []
    monkeypatch.setattr(release, "records", records)
    monkeypatch.setattr(release, "channel", lambda *args: pytest.fail("historical inspection read the current channel"))
    monkeypatch.setattr(release, "attach", lambda *args: pytest.fail("inspection wrote an attachment"))
    monkeypatch.setattr(release, "verify_content", lambda *args: pytest.fail("inspection invoked the native verifier"))
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(sys, "argv", ["guest_release.py", "inspect", "--promotion-job", "456"])
    if mismatch:
        with pytest.raises(SystemExit) as stopped:
            release.main()
        assert stopped.value.code == 2
    else:
        release.main()
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["requested_promotion"] == origin
    assert summary.read_text() == "```json\n" + output + "```\n"
    if mismatch:
        assert result["matches"] == [] and "unknown" in result["reason"]
    else:
        assert len(result["matches"]) == 1
        assert result["matches"][0]["index"] == historical["index"]
        assert result["matches"][0]["promotion"] == [decision]
