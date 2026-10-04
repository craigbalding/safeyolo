"""Exact-master gating, complete downloads and stale-publication prevention."""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

from scripts import publish_host_packages as publisher

REPOSITORY = "operator/safeyolo"
COMMIT = "a" * 40


def successful_run() -> dict:
    return {
        "id": 20, "run_attempt": 1, "html_url": "https://github.com/operator/safeyolo/actions/runs/20",
        "head_sha": COMMIT, "head_branch": "master", "head_repository": {"full_name": REPOSITORY},
        "event": "push", "status": "completed", "conclusion": "success",
    }


def test_source_checks_require_every_current_master_push_workflow(monkeypatch):
    paths = []

    def api(repository, path):
        paths.append(path)
        if path.startswith("compare/"):
            return {"status": "identical"}
        return {"workflow_runs": [successful_run()]}

    monkeypatch.setattr(publisher, "api", api)
    checks = publisher.successful_checks(REPOSITORY, COMMIT)
    assert set(checks) == set(publisher.WORKFLOWS)
    assert len(paths) == 4
    assert all(f"head_sha={COMMIT}" in path for path in paths[1:])


@pytest.mark.parametrize("field,value", [
    ("head_sha", "b" * 40), ("head_branch", "feature"), ("event", "pull_request"),
    ("head_repository", {"full_name": "other/fork"}), ("status", "in_progress"),
    ("conclusion", "failure"), ("conclusion", "cancelled"), ("conclusion", "skipped"),
])
def test_different_head_or_unsuccessful_checks_do_not_select_packages(monkeypatch, field, value):
    run = {**successful_run(), field: value}
    monkeypatch.setattr(publisher, "api", lambda repository, path: (
        {"status": "identical"} if path.startswith("compare/") else {"workflow_runs": [run]}
    ))
    assert publisher.successful_checks(REPOSITORY, COMMIT) is None


def test_a_later_failed_check_cannot_use_an_older_success(monkeypatch):
    latest = {**successful_run(), "id": 21, "conclusion": "failure"}
    monkeypatch.setattr(publisher, "api", lambda repository, path: (
        {"status": "ahead"} if path.startswith("compare/") else {"workflow_runs": [successful_run(), latest]}
    ))
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


def test_a_complete_stage_publishes_downloads_without_promoting_latest(tmp_path, monkeypatch):
    make_archives(tmp_path)
    monkeypatch.setattr(publisher, "successful_checks", lambda *args: {})
    staged = {"id": 40, "draft": True, "assets": [{"name": name} for name in publisher.ASSETS | {"SHA256SUMS"}]}
    lookups = iter([None, staged])
    monkeypatch.setattr(publisher, "release", lambda *args: next(lookups))
    calls = []
    monkeypatch.setattr(publisher, "gh", lambda *args: calls.append(args))
    publisher.stage(REPOSITORY, COMMIT, tmp_path)
    assert "--draft" in calls[0] and "--latest=false" in calls[0]
    assert len((tmp_path / "SHA256SUMS").read_text().splitlines()) == 6
    assert "draft=false" in calls[-1] and "make_latest=false" in calls[-1]
    assert "prerelease=true" in calls[-1]
    assert not any("make_latest=true" in call for call in calls)


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


def test_missing_debug_artifact_does_not_download_caches_or_test_files(monkeypatch, tmp_path):
    monkeypatch.setattr(publisher, "api", lambda repository, path: (
        {"artifacts": [{"name": "compiler-cache", "expired": False}]} if path.endswith("per_page=100") else successful_run()
    ))
    monkeypatch.setattr(publisher.subprocess, "run", lambda *args, **kwargs: pytest.fail("downloaded unusable outputs"))
    publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path)


@pytest.mark.parametrize("field,value", [("head_sha", "b" * 40), ("event", "pull_request"), ("conclusion", "failure")])
def test_debug_download_rejects_wrong_run_provenance(monkeypatch, tmp_path, field, value):
    monkeypatch.setattr(publisher, "api", lambda *args: {**successful_run(), field: value})
    with pytest.raises(ValueError, match="successful push"):
        publisher.download_debug(REPOSITORY, COMMIT, 20, "linux-amd64", tmp_path)


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
    build = workflow["jobs"]["build"]
    assert {row["platform"] for row in build["strategy"]["matrix"]["include"]} == set(publisher.PLATFORMS)
    assert all("self-hosted" not in row["os"] for row in build["strategy"]["matrix"]["include"])
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["ref"] == "${{ env.PACKAGE_COMMIT }}"
    consume = workflow["jobs"]["consume"]
    assert not any(str(step.get("uses", "")).startswith("actions/checkout@") for step in consume["steps"])
    assert workflow["jobs"]["promote"]["needs"] == "consume"
    assert workflow["jobs"]["promote"]["concurrency"] == {"group": "host-package-latest-promotion", "cancel-in-progress": False}
