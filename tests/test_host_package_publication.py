"""Exact-master gating, complete downloads and stale-publication prevention."""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import publish_host_packages as publisher

REPOSITORY = "operator/safeyolo"
COMMIT = "a" * 40


def successful_run(workflow: str = "ci.yml") -> dict:
    return {
        "id": 20, "run_attempt": 1, "html_url": "https://github.com/operator/safeyolo/actions/runs/20",
        "head_sha": COMMIT, "head_branch": "master", "head_repository": {"full_name": REPOSITORY},
        "event": "push", "status": "completed", "conclusion": "success",
        "path": f".github/workflows/{workflow}",
    }


def successful_job(name: str) -> dict:
    return {
        "id": 30, "run_id": 20, "run_attempt": 1, "head_sha": COMMIT,
        "html_url": "https://github.com/operator/safeyolo/actions/runs/20/job/30",
        "name": name, "status": "completed", "conclusion": "success", "steps": [],
    }


@pytest.fixture
def source_checks(monkeypatch):
    runs = {name: [successful_run(name)] for name in publisher.WORKFLOWS}
    jobs = {name: [successful_job(job) for job in required] for name, required in publisher.WORKFLOWS.items()}

    def api(repository, path):
        assert repository == REPOSITORY
        if path.startswith("compare/"):
            return {"status": "identical"}
        if path.startswith("actions/workflows/"):
            assert f"head_sha={COMMIT}" in path
            name = path.split("/")[2]
            api.current_workflow = name
            return {"workflow_runs": runs[name]}
        assert path == f"actions/runs/{runs[api.current_workflow][-1]['id']}/jobs?filter=latest&per_page=100"
        return {"jobs": jobs[api.current_workflow]}

    monkeypatch.setattr(publisher, "api", api)
    return runs, jobs


def test_source_checks_require_existing_jobs_for_each_current_master_push(source_checks):
    checks = publisher.successful_checks(REPOSITORY, COMMIT)
    assert set(checks) == set(publisher.WORKFLOWS)
    assert all(set(check["jobs"]) == set(publisher.WORKFLOWS[name]) for name, check in checks.items())


def test_successful_native_producer_survives_failed_optional_macos_job(source_checks):
    runs, jobs = source_checks
    runs["proxy-rust.yml"][0]["conclusion"] = "failure"
    jobs["proxy-rust.yml"].append({**successful_job("Relevant macOS platform checks"), "conclusion": "failure"})
    checks = publisher.successful_checks(REPOSITORY, COMMIT)
    assert checks["proxy-rust.yml"]["conclusion"] == "failure"
    assert set(checks["proxy-rust.yml"]["jobs"]) == {"Quick native checks (Ubuntu)"}


def test_optional_failed_job_rerun_retains_latest_successful_required_jobs(source_checks):
    runs, _ = source_checks
    runs["proxy-rust.yml"][0].update(run_attempt=2, conclusion="failure")
    checks = publisher.successful_checks(REPOSITORY, COMMIT)
    assert checks["proxy-rust.yml"]["attempt"] == 2
    assert checks["proxy-rust.yml"]["jobs"]["Quick native checks (Ubuntu)"]["attempt"] == 1


@pytest.mark.parametrize("field,value", [
    ("head_sha", "b" * 40), ("head_branch", "feature"), ("event", "pull_request"),
    ("head_repository", {"full_name": "other/fork"}), ("status", "in_progress"),
    ("path", ".github/workflows/unrelated.yml"),
])
def test_different_head_or_incomplete_run_does_not_select_packages(source_checks, field, value):
    runs, _ = source_checks
    runs["ci.yml"][0][field] = value
    assert publisher.successful_checks(REPOSITORY, COMMIT) is None


@pytest.mark.parametrize("workflow", publisher.WORKFLOWS)
@pytest.mark.parametrize("field,value", [
    ("head_sha", "b" * 40), ("run_id", 21), ("run_attempt", 2),
    ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "cancelled"), ("conclusion", "skipped"),
])
def test_required_check_failure_or_wrong_job_provenance_blocks(source_checks, workflow, field, value):
    _, jobs = source_checks
    jobs[workflow][0][field] = value
    assert publisher.successful_checks(REPOSITORY, COMMIT) is None


@pytest.mark.parametrize("missing", ["run", "job"])
def test_missing_required_check_does_not_publish(source_checks, missing):
    runs, jobs = source_checks
    (runs if missing == "run" else jobs)["ci.yml"].clear()
    assert publisher.successful_checks(REPOSITORY, COMMIT) is None


def test_a_later_failed_check_cannot_use_an_older_success(source_checks):
    runs, jobs = source_checks
    runs["ci.yml"].append({**successful_run(), "id": 21, "conclusion": "failure"})
    for job in jobs["ci.yml"]:
        job["run_id"] = 21
    jobs["ci.yml"][0]["conclusion"] = "failure"
    assert publisher.successful_checks(REPOSITORY, COMMIT) is None


def test_a_check_outside_master_history_cannot_publish(monkeypatch):
    monkeypatch.setattr(publisher, "api", lambda *args: {"status": "diverged"})
    with pytest.raises(ValueError, match="master history"):
        publisher.successful_checks(REPOSITORY, COMMIT)


@pytest.mark.parametrize("status", ["404", "403", "503"])
def test_release_lookup_only_treats_not_found_as_absent(monkeypatch, status):
    response = subprocess.CompletedProcess(["gh"], 1, json.dumps({"status": status}), "API failure")
    monkeypatch.setattr(publisher.subprocess, "run", lambda *args, **kwargs: response)
    if status == "404":
        assert publisher.release(REPOSITORY, f"host-{COMMIT}") is None
    else:
        with pytest.raises(subprocess.CalledProcessError):
            publisher.release(REPOSITORY, f"host-{COMMIT}")


def make_archives(directory: Path, commit: str = COMMIT) -> None:
    for name in publisher.ASSETS:
        root = name.removesuffix(".tar.gz")
        profile = "debug" if root.endswith("-debug") else "production"
        platform = root.removeprefix("safeyolo-").removesuffix(f"-{profile}")
        document = json.dumps({"native": {"commit": commit, "platform": platform, "profile": profile}}).encode()
        with tarfile.open(directory / name, "w:gz") as archive:
            member = tarfile.TarInfo(f"{root}/manifest.json")
            member.size = len(document)
            archive.addfile(member, io.BytesIO(document))


def test_a_complete_stage_publishes_downloads_without_promoting_latest(source_checks, tmp_path, monkeypatch):
    make_archives(tmp_path)
    runs, _ = source_checks
    runs["proxy-rust.yml"][0]["conclusion"] = "failure"
    staged = {"id": 40, "draft": True, "assets": [{"name": name} for name in publisher.ASSETS | {"SHA256SUMS"}]}
    lookups = iter([None, staged])
    monkeypatch.setattr(publisher, "release", lambda *args: next(lookups))
    calls = []
    notes = []

    def gh(*args):
        calls.append(args)
        if "--notes-file" in args:
            notes.append(Path(args[args.index("--notes-file") + 1]).read_text())

    monkeypatch.setattr(publisher, "gh", gh)
    publisher.stage(REPOSITORY, COMMIT, tmp_path)
    assert "--draft" in calls[0] and "--latest=false" in calls[0]
    assert len((tmp_path / "SHA256SUMS").read_text().splitlines()) == 6
    assert "draft=false" in calls[-1] and "make_latest=false" in calls[-1]
    assert "prerelease=true" in calls[-1]
    assert not any("make_latest=true" in call for call in calls)
    assert "workflow conclusion failure" in notes[0]
    job_url = successful_job("Quick native checks (Ubuntu)")["html_url"]
    assert f"[Quick native checks (Ubuntu)]({job_url}) (attempt 1)" in notes[0]


@pytest.mark.parametrize("failure", ["missing", "extra", "wrong-commit", "failed-check", "published"])
def test_incomplete_or_wrong_source_releases_are_not_changed(tmp_path, monkeypatch, failure):
    make_archives(tmp_path, "b" * 40 if failure == "wrong-commit" else COMMIT)
    if failure == "missing":
        next(tmp_path.glob("*.tar.gz")).unlink()
    elif failure == "extra":
        (tmp_path / "unexpected.tar.gz").write_bytes(b"unexpected")
    monkeypatch.setattr(publisher, "successful_checks", lambda *args: None if failure == "failed-check" else {})
    monkeypatch.setattr(publisher, "release", lambda *args: {"draft": False} if failure == "published" else None)
    monkeypatch.setattr(publisher, "gh", lambda *args: pytest.fail("invalid package set changed GitHub"))
    with pytest.raises(ValueError):
        publisher.stage(REPOSITORY, COMMIT, tmp_path)


@pytest.mark.parametrize("ancestry,promoted", [("ahead", True), ("identical", True), ("behind", False), ("diverged", False)])
def test_latest_promotion_uses_commit_ancestry_not_finish_time(monkeypatch, ancestry, promoted):
    monkeypatch.setattr(publisher, "successful_checks", lambda *args: {})
    candidate = {"id": 40, "draft": False, "tag_name": f"host-{COMMIT}", "html_url": "release-url",
                 "assets": [{"name": name} for name in publisher.ASSETS | {"SHA256SUMS"}]}
    latest = {"tag_name": "host-" + "b" * 40}
    monkeypatch.setattr(publisher, "release", lambda repository, tag: candidate if tag else latest)
    monkeypatch.setattr(publisher, "api", lambda repository, path: {"sha": "b" * 40} if path.startswith("commits/") else {"status": ancestry})
    calls = []
    monkeypatch.setattr(publisher, "gh", lambda *args: calls.append(args))
    publisher.promote(REPOSITORY, COMMIT)
    assert bool(calls) is promoted
    if promoted:
        assert "make_latest=true" in calls[-1]
        assert "prerelease=false" in calls[-1]


def test_failed_source_recheck_cannot_promote_a_completed_build(monkeypatch):
    monkeypatch.setattr(publisher, "successful_checks", lambda *args: None)
    monkeypatch.setattr(publisher, "gh", lambda *args: pytest.fail("failed checks promoted latest"))
    with pytest.raises(ValueError, match="source checks changed"):
        publisher.promote(REPOSITORY, COMMIT)


def test_first_complete_release_can_become_latest(monkeypatch):
    monkeypatch.setattr(publisher, "successful_checks", lambda *args: {})
    candidate = {"id": 40, "draft": False, "html_url": "release-url",
                 "assets": [{"name": name} for name in publisher.ASSETS | {"SHA256SUMS"}]}
    monkeypatch.setattr(publisher, "release", lambda repository, tag: candidate if tag else None)
    calls = []
    monkeypatch.setattr(publisher, "gh", lambda *args: calls.append(args))
    publisher.promote(REPOSITORY, COMMIT)
    assert "make_latest=true" in calls[-1]


@pytest.fixture
def debug_download(monkeypatch):
    run = successful_run("proxy-rust.yml")
    job = successful_job("Quick native checks (Ubuntu)")
    job["steps"] = [
        {"name": "Save actual master CI debug runtimes", "status": "completed", "conclusion": "success"},
        {"name": "Run actions/upload-artifact@pinned", "status": "completed", "conclusion": "success",
         "started_at": "2026-10-04T11:18:22Z", "completed_at": "2026-10-04T11:18:30Z"},
    ]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("safeyolo-proxy", b"saved debug runtime")
        archive.writestr("build.json", json.dumps({"commit": COMMIT, "platform": "linux-amd64", "run_id": "20"}))
    payload = buffer.getvalue()
    artifact = {
        "id": 40, "name": "host-debug-linux-amd64", "expired": False,
        "workflow_run": {"id": 20, "head_sha": COMMIT, "head_branch": "master"},
        "created_at": "2026-10-04T11:18:30Z", "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
    }

    def api(repository, path):
        assert repository == REPOSITORY
        if path == "actions/runs/20":
            return run
        if path == "actions/runs/20/jobs?filter=latest&per_page=100":
            return {"jobs": [job]}
        assert path == "actions/runs/20/artifacts?per_page=100"
        return {"artifacts": [artifact]}

    calls = []

    def download(args, **kwargs):
        assert args == ["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/40/zip"]
        calls.append(args)
        kwargs["stdout"].write(payload)

    monkeypatch.setattr(publisher, "api", api)
    monkeypatch.setattr(publisher.subprocess, "run", download)
    return run, job, artifact, calls


def test_debug_download_uses_successful_producer_in_failed_mixed_workflow(debug_download, tmp_path):
    run, _, _, calls = debug_download
    run["conclusion"] = "failure"
    publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=1)
    assert len(calls) == 1
    assert (tmp_path / "safeyolo-proxy").read_bytes() == b"saved debug runtime"


def test_debug_download_keeps_unrerun_successful_producers_after_optional_rerun(debug_download, tmp_path):
    run, _, _, calls = debug_download
    run.update(run_attempt=2, conclusion="failure")
    publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=2)
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["cache", "expired", "other-platform"])
def test_missing_debug_artifact_does_not_download_caches_or_test_files(debug_download, tmp_path, change):
    _, _, artifact, calls = debug_download
    if change == "expired":
        artifact["expired"] = True
    else:
        artifact["name"] = "compiler-cache" if change == "cache" else "host-debug-darwin-arm64"
    publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=1)
    assert not calls


@pytest.mark.parametrize("field,value", [
    ("id", 21), ("head_sha", "b" * 40), ("event", "pull_request"), ("head_branch", "feature"),
    ("head_repository", {"full_name": "other/fork"}), ("run_attempt", 2), ("status", "in_progress"),
    ("path", ".github/workflows/other.yml"),
])
def test_debug_download_rejects_wrong_run_provenance(debug_download, tmp_path, field, value):
    run, _, _, calls = debug_download
    run[field] = value
    with pytest.raises(ValueError, match="selected master push and attempt"):
        publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=1)
    assert not calls


@pytest.mark.parametrize("field,value", [
    ("name", "Unrelated producer"), ("head_sha", "b" * 40), ("run_id", 21), ("run_attempt", 2),
    ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "cancelled"), ("conclusion", "skipped"),
])
def test_debug_download_rejects_wrong_or_unsuccessful_producer(debug_download, tmp_path, field, value):
    _, job, _, calls = debug_download
    job[field] = value
    publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=1)
    assert not calls


@pytest.mark.parametrize("step", [0, 1])
def test_debug_download_requires_successful_runtime_save_and_upload(debug_download, tmp_path, step):
    _, job, _, calls = debug_download
    job["steps"][step]["conclusion"] = "skipped"
    publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=1)
    assert not calls


@pytest.mark.parametrize("field,value", [("id", 21), ("head_sha", "b" * 40), ("head_branch", "feature")])
def test_debug_download_rejects_artifact_from_another_source(debug_download, tmp_path, field, value):
    _, _, artifact, calls = debug_download
    artifact["workflow_run"][field] = value
    with pytest.raises(ValueError, match="artifact source differs"):
        publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=1)
    assert not calls


def test_debug_artifact_from_an_older_producer_attempt_takes_missing_output_fallback(debug_download, tmp_path):
    run, job, _, calls = debug_download
    run["run_attempt"] = job["run_attempt"] = 2
    job["steps"][1].update(started_at="2026-10-04T12:00:00Z", completed_at="2026-10-04T12:00:08Z")
    publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=2)
    assert not calls


def test_debug_zip_checksum_failure_cannot_supply_runtime_bytes(debug_download, tmp_path):
    _, _, artifact, calls = debug_download
    artifact["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="ZIP checksum"):
        publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path, attempt=1)
    assert len(calls) == 1
    assert not (tmp_path / "safeyolo-proxy").exists()


@pytest.mark.parametrize("order", list(itertools.permutations(publisher.WORKFLOWS)))
def test_last_completion_selects_packages_even_when_optional_native_job_failed(source_checks, tmp_path, monkeypatch, order):
    runs, jobs = source_checks
    for values in runs.values():
        values[0]["status"] = "in_progress"
    runs["proxy-rust.yml"][0]["conclusion"] = "failure"
    jobs["proxy-rust.yml"].append({**successful_job("Relevant macOS platform checks"), "conclusion": "failure"})
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(publisher, "release", lambda *args: None)
    for workflow in order:
        runs[workflow][0]["status"] = "completed"
        publisher.select(REPOSITORY, COMMIT)
    assert output.read_text().splitlines() == ["ready=false", "ready=false", "ready=true", "native_run=20", "native_attempt=1"]


def test_existing_published_commit_skips_duplicate_build(monkeypatch, tmp_path):
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(publisher, "successful_checks", lambda *args: {"proxy-rust.yml": {"id": 20}})
    monkeypatch.setattr(publisher, "release", lambda *args: {"draft": False, "html_url": "release-url"})
    publisher.select(REPOSITORY, COMMIT)
    assert output.read_text() == "ready=false\n"


def test_postmerge_workflow_has_exact_source_download_consumers_and_serial_latest():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/host-packages.yml").read_text())
    assert set(workflow[True]) == {"workflow_run"}
    assert workflow[True]["workflow_run"]["branches"] == ["master"]
    assert workflow[True]["workflow_run"]["workflows"] == ["CI", "Native proxy contracts", "CodeQL"]
    assert "github.event.workflow_run.event == 'push'" in workflow["jobs"]["select"]["if"]
    assert "head_repository.full_name == github.repository" in workflow["jobs"]["select"]["if"]
    assert " ".join(workflow["jobs"]["select"]["if"].split()) == (
        "github.event.workflow_run.event == 'push' && "
        "github.event.workflow_run.head_repository.full_name == github.repository"
    )
    assert workflow["jobs"]["select"]["outputs"]["native_attempt"] == "${{ steps.select.outputs.native_attempt }}"
    build = workflow["jobs"]["build"]
    assert {row["platform"] for row in build["strategy"]["matrix"]["include"]} == set(publisher.PLATFORMS)
    assert all("self-hosted" not in row["os"] for row in build["strategy"]["matrix"]["include"])
    download = next(step for step in build["steps"] if step.get("name") == "Download usable same-commit CI debug runtimes")
    assert download["env"]["NATIVE_ATTEMPT"] == "${{ needs.select.outputs.native_attempt }}"
    assert '--native-attempt "$NATIVE_ATTEMPT"' in download["run"]
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["ref"] == "${{ env.PACKAGE_COMMIT }}"
    consume = workflow["jobs"]["consume"]
    assert not any(str(step.get("uses", "")).startswith("actions/checkout@") for step in consume["steps"])
    assert workflow["jobs"]["promote"]["needs"] == "consume"
    assert workflow["jobs"]["promote"]["concurrency"] == {"group": "host-package-latest-promotion", "cancel-in-progress": False}
