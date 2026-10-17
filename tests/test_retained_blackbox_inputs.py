"""Challenge retained selection and installation without compiling the product."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from scripts import build_host_packages as package_builder
from scripts import select_blackbox_artifacts as selector
from tests.blackbox import retained_inputs
from tests.test_guest_acquisition import descriptor, release
from tests.test_host_packages import package_inputs as _package_inputs

package_inputs = _package_inputs

SOURCE = "a" * 40
GUEST_SOURCE = "b" * 40
PLATFORM = "linux-arm64"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def retained(tmp_path, monkeypatch):
    now = datetime.now(UTC)
    start = (now - timedelta(hours=2)).isoformat()
    built = (now - timedelta(hours=1)).isoformat()
    finished = (now - timedelta(minutes=30)).isoformat()
    host = {
        "schema": "safeyolo.host-build/v1", "source_revision": SOURCE, "profile": "production",
        "platform": PLATFORM, "built_at": built,
        "producer": {"repository": selector.REPOSITORY, "workflow": selector.HOST_WORKFLOW,
                     "run_id": 10, "run_attempt": 2, "job_key": "build", "runner_name": "host-builder"},
    }
    data = {"host": host, "head": "c" * 40, "calls": [], "source": SOURCE, "runs": {}, "jobs": {}}
    for run_id, source, workflow, attempt, job_id in (
        (10, SOURCE, selector.HOST_WORKFLOW, 2, 101),
        (20, GUEST_SOURCE, selector.GUEST_WORKFLOW, 1, 201),
    ):
        data["runs"][run_id] = {"head_sha": source, "head_branch": "master", "path": workflow,
                                "event": "schedule", "run_attempt": attempt,
                                "status": "completed", "conclusion": "success"}
        data["jobs"][run_id] = [{"id": job_id, "status": "completed", "conclusion": "success",
                                 "name": "guest-inputs (arm64) / build", "runner_name": "host-builder",
                                 "started_at": start, "completed_at": finished}]
    name = f"safeyolo-{PLATFORM}-production.tar.gz"

    def pack():
        archive = io.BytesIO()
        info = (f"source_commit={data['source']}\nprofile=production\nplatform={PLATFORM}\n"
                f"guest_repository={selector.GUEST_REPOSITORY}\nguest_compatibility=v1\n").encode()
        with tarfile.open(fileobj=archive, mode="w:gz") as output:
            member = tarfile.TarInfo(name.removesuffix(".tar.gz") + "/package-info")
            member.size = len(info)
            output.addfile(member, io.BytesIO(info))
            checksums = "".join(f"{hashlib.sha256(name.encode()).hexdigest()}  ./{name}\n"
                                for name in selector.installed_binaries(PLATFORM)).encode()
            member = tarfile.TarInfo(name.removesuffix(".tar.gz") + "/SHA256SUMS")
            member.size = len(checksums)
            output.addfile(member, io.BytesIO(checksums))
        checksum = hashlib.sha256(archive.getvalue()).hexdigest()
        host["archive"] = {"name": name, "sha256": checksum, "size": len(archive.getvalue())}
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as output:
            output.writestr(name, archive.getvalue())
            output.writestr("SHA256SUMS", f"{checksum}  {name}\n")
            output.writestr("build.json", json.dumps(host))
        data["zip"] = content.getvalue()
        data["artifact"] = {"id": 100, "name": f"nightly-host-{PLATFORM}-production", "expired": False,
                            "digest": "sha256:" + hashlib.sha256(data["zip"]).hexdigest(),
                            "size_in_bytes": len(data["zip"]), "created_at": built,
                            "workflow_run": {"id": 10, "head_branch": "master", "head_sha": SOURCE}}

    pack()
    data["pack"] = pack
    contents = release(b"retained guest bytes", version="guest-2026-10-17.1")
    # Give the guest its independent source identity before calculating descriptors.
    values = release(b"retained guest bytes", version="guest-2026-10-17.1")
    original = json.loads(values["manifests/compat-v1"])
    children = []
    for child in original["manifests"]:
        value = json.loads(values["manifests/" + child["digest"]])
        value["annotations"]["org.opencontainers.image.revision"] = GUEST_SOURCE
        raw = json.dumps(value).encode()
        entry = {**descriptor(raw, child["mediaType"]), "platform": child["platform"]}
        contents["manifests/" + entry["digest"]] = raw
        children.append(entry)
    original["manifests"] = children
    original["annotations"]["org.opencontainers.image.revision"] = GUEST_SOURCE
    raw = json.dumps(original).encode()
    index = descriptor(raw, original["mediaType"])
    contents["manifests/" + index["digest"]] = raw
    data["index"] = index
    data["receipt"] = {"schema": "safeyolo.guest-staging/v1", "index_digest": index["digest"],
                       "source_revision": GUEST_SOURCE, "staged_at": built,
                       "producer": {"repository": selector.REPOSITORY, "workflow": selector.GUEST_WORKFLOW,
                                    "run_id": 20, "run_attempt": 1, "job_id": 201}}
    data["tags"] = {"guest-2026-10-17.1": index}
    data["has_receipt"] = True
    data["receipts"] = {index["digest"]: data["receipt"]}
    data["contents"] = contents

    def add_candidate(version, staged_at, *, staged=True):
        candidate = copy.deepcopy(original)
        candidate["annotations"]["org.opencontainers.image.version"] = version
        for child in candidate["manifests"]:
            value = json.loads(contents["manifests/" + child["digest"]])
            value["annotations"]["org.opencontainers.image.version"] = version
            payload = b"retained guest bytes " + version.encode()
            value["layers"][0] = descriptor(payload, value["layers"][0]["mediaType"])
            contents["blobs/" + value["layers"][0]["digest"]] = payload
            raw = json.dumps(value).encode()
            child.update(descriptor(raw, child["mediaType"]))
            contents["manifests/" + child["digest"]] = raw
        raw = json.dumps(candidate).encode()
        entry = descriptor(raw, candidate["mediaType"])
        contents["manifests/" + entry["digest"]] = raw
        data["tags"][version] = entry
        if staged:
            data["receipts"][entry["digest"]] = {**data["receipt"], "index_digest": entry["digest"], "staged_at": staged_at}
        return entry

    data["add_candidate"] = add_candidate

    def attach(index_digest):
        raw = json.dumps(data["receipts"][index_digest]).encode()
        layer = descriptor(raw, selector.STAGING_TYPE)
        contents["blobs/" + layer["digest"]] = raw
        selected_index = next(entry for entry in data["tags"].values() if entry["digest"] == index_digest)
        attachment = {"artifactType": selector.STAGING_TYPE, "subject": selected_index, "layers": [layer]}
        raw = json.dumps(attachment).encode()
        entry = descriptor(raw, "application/vnd.oci.image.manifest.v1+json")
        contents["manifests/" + entry["digest"]] = raw
        return entry

    def api(endpoint):
        if endpoint == f"repos/{selector.REPOSITORY}":
            return {"default_branch": "master"}
        if endpoint.endswith("/commits/master"):
            return {"sha": data["head"]}
        if "/artifacts?" in endpoint:
            return [{"artifacts": data.get("artifacts", [data["artifact"]])}]
        if "/actions/runs/" in endpoint:
            run_id = int(endpoint.split("/actions/runs/", 1)[1].split("/", 1)[0])
            if run_id in data.get("unavailable_runs", set()):
                raise subprocess.CalledProcessError(1, ["gh", "api"], stderr=b"HTTP 404")
            return [{"jobs": data["jobs"][run_id]}] if "/jobs?" in endpoint else data["runs"][run_id]
        raise AssertionError(endpoint)

    def capture(*args):
        data["calls"].append(args)
        if args[0] == "git":
            if "status" in args:
                return b""
            return ("d" * 40).encode()
        if args[0] == "gh":
            return json.dumps(api(args[-1])).encode()
        if args[:3] == ("oras", "repo", "tags"):
            assert args[3:5] == ("--format", "json")  # actual ORAS 1.3 tag-list interface
            return json.dumps({"tags": list(data["tags"])}).encode()
        if args[:2] == ("oras", "discover"):
            index_digest = args[-1].split("@", 1)[1]
            return json.dumps({"referrers": [attach(index_digest)] if data["has_receipt"] and index_digest in data["receipts"] else []}).encode()
        if args[:3] == ("oras", "manifest", "fetch"):
            reference = args[-1]
            if "@" in reference:
                key = reference.split("@", 1)[1]
                raw = contents["manifests/" + key]
                if "--descriptor" in args:
                    return json.dumps(descriptor(raw, json.loads(raw).get("mediaType", "application/vnd.oci.image.manifest.v1+json"))).encode()
                return raw
            return json.dumps(data["tags"][reference.rsplit(":", 1)[1]]).encode()
        if args[:3] == ("oras", "blob", "fetch"):
            if args[-1].split("@", 1)[1] in data.get("unavailable_blobs", set()):
                raise FileNotFoundError("controlled unavailable blob")
            if "--descriptor" in args:
                return json.dumps(descriptor(contents["blobs/" + args[-1].split("@", 1)[1]], "application/octet-stream")).encode()
            return contents["blobs/" + args[-1].split("@", 1)[1]]
        raise AssertionError(args)

    def download(args, **kwargs):
        assert args[-1].endswith("/artifacts/100/zip")
        kwargs["stdout"].write(data["zip"])
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(selector, "capture", capture)
    monkeypatch.setattr(selector.subprocess, "run", download)
    return data


def test_freeze_has_independent_sources_producers_and_quarantined_guest(retained, tmp_path):
    result = selector.select(tmp_path / "selection", PLATFORM)
    assert result["status"] == "selected"
    assert result["host"]["source_revision"] == SOURCE
    assert result["guest"]["source_revision"] == GUEST_SOURCE
    assert result["controller_revision"] == "d" * 40
    assert result["default_branch_head"] == "c" * 40
    assert result["host"]["producer"]["run_attempt"] == 2
    assert result["host"]["producer"]["job_id"] == 101
    assert result["selected_host_artifact"]["producer"] == result["host"]["producer"]
    assert 0 < result["host_build_age_seconds"] < 172800
    assert result["guest"]["index"] == retained["index"]
    frozen = (tmp_path / "selection/selection.json").read_bytes()
    retained["head"] = "e" * 40
    retained["tags"].clear()
    assert (tmp_path / "selection/selection.json").read_bytes() == frozen
    assert all(call[:2] != ("oras", "tag") for call in retained["calls"])


def test_producer_completing_during_selection_is_not_mistaken_for_future_input(retained, tmp_path, monkeypatch):
    class SelectionClock(datetime):
        calls = 0

        @classmethod
        def now(cls, tz=None):
            cls.calls += 1
            return datetime.now(tz) - (timedelta(hours=3) if cls.calls == 1 else timedelta())

    monkeypatch.setattr(selector, "datetime", SelectionClock)
    result = selector.select(tmp_path / "selection", PLATFORM)
    assert result["host_build_age_seconds"] > 0
    assert selector.utc(result["guest"]["staged_at"]) <= selector.utc(result["selected_at"])


@pytest.mark.parametrize("defect,reason", [
    ("expired", "expired"), ("checksum", "ZIP checksum"), ("profile", "source/profile/platform"),
    ("source", "package-info differs"), ("failed-job", "no retained"),
    ("untrusted", "no retained"), ("wrong-attempt", "production attempt"),
    ("missing-staging", "completed-staging receipt"), ("wrong-staging-source", "source/index differs"),
    ("future-staging", "outside its successful producer job"),
])
def test_selected_failure_is_visible_and_never_substitutes_older_inputs(retained, tmp_path, defect, reason):
    if defect == "expired":
        retained["artifact"]["expired"] = True
    elif defect == "checksum":
        retained["zip"] += b"changed"
    elif defect == "profile":
        retained["host"]["profile"] = "debug"
        retained["pack"]()
    elif defect == "source":
        retained["source"] = "f" * 40
        retained["pack"]()
    elif defect == "failed-job":
        retained["jobs"][10][0]["conclusion"] = "failure"
    elif defect == "untrusted":
        retained["runs"][10]["event"] = "pull_request"
    elif defect == "wrong-attempt":
        retained["host"]["producer"]["run_attempt"] = 1
        retained["pack"]()
    elif defect == "missing-staging":
        retained["has_receipt"] = False
    elif defect == "wrong-staging-source":
        retained["receipt"]["source_revision"] = "e" * 40
    elif defect == "future-staging":
        retained["receipt"]["staged_at"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    with pytest.raises(ValueError, match=reason):
        selector.select(tmp_path / "failed", PLATFORM)
    result = json.loads((tmp_path / "failed/selection.json").read_bytes())
    assert result["status"] == "failed" and reason in result["failure"]
    assert not any("build" in call[0] for call in retained["calls"])
    # Retry cannot replace the original failure record.
    previous = (tmp_path / "failed/selection.json").read_bytes()
    with pytest.raises(FileExistsError):
        selector.select(tmp_path / "failed", PLATFORM)
    assert (tmp_path / "failed/selection.json").read_bytes() == previous


def test_newest_build_is_selected_without_using_test_success(retained, tmp_path):
    older = copy.deepcopy(retained["artifact"])
    older["id"] = 99
    older["created_at"] = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    retained["artifacts"] = [older, retained["artifact"]]
    retained["runs"][10]["conclusion"] = "failure"
    retained["jobs"][10].append({"id": 102, "name": "blackbox", "runner_name": "test-runner",
                                 "status": "completed", "conclusion": "failure"})
    selected = selector.select(tmp_path / "attempt", PLATFORM)
    assert selected["selected_host_artifact"]["id"] == 100


@pytest.mark.parametrize("platform", selector.PLATFORMS)
@pytest.mark.parametrize("status,conclusion", [("in_progress", None), ("completed", "failure")])
def test_host_qualification_waits_for_its_production_job(retained, platform, status, conclusion):
    name = f"nightly-host-{platform}-production"
    retained["artifact"]["name"] = name
    job_name = f"guest-inputs ({platform.rsplit('-', 1)[1]}) / " + ("macos-host" if platform == "darwin-arm64" else "build")
    retained["jobs"][10][0]["name"] = job_name
    newer = copy.deepcopy(retained["artifact"])
    newer.update(id=101, created_at=datetime.now(UTC).isoformat())
    newer["workflow_run"]["id"] = 11
    retained["artifacts"] = [retained["artifact"], newer]
    retained["runs"][11] = {**retained["runs"][10], "status": status, "conclusion": conclusion}
    retained["jobs"][11] = [{**retained["jobs"][10][0], "id": 111, "status": status, "conclusion": conclusion},
                             {"id": 112, "name": "blackbox", "runner_name": "test-runner",
                              "status": "completed", "conclusion": "success"}]
    selected = selector.select_host(platform, "master", None)
    assert selected["id"] == 100
    # An explicit unfinished/failed run cannot silently choose another producer.
    retained["artifacts"] = [newer]
    with pytest.raises(ValueError, match="did not complete successfully"):
        selector.select_host(platform, "master", 11)


@pytest.mark.parametrize("missing_run", [9, 10])
def test_host_selection_ignores_only_unselected_historical_producers(retained, tmp_path, missing_run):
    older = copy.deepcopy(retained["artifact"])
    older.update(id=99, created_at=(datetime.now(UTC) - timedelta(days=3)).isoformat())
    older["workflow_run"]["id"] = 9
    retained["artifacts"] = [older, retained["artifact"]]
    retained["unavailable_runs"] = {missing_run}
    if missing_run == 10:
        with pytest.raises(subprocess.CalledProcessError):
            selector.select(tmp_path / "selection", PLATFORM)
        failed = json.loads((tmp_path / "selection/selection.json").read_bytes())
        assert failed["status"] == "failed" and failed["stage"] == "host-selection"
    else:
        selected = selector.select(tmp_path / "selection", PLATFORM)
        assert selected["host"]["artifact"]["id"] == 100
    assert not any("/runs/9" in call[-1] for call in retained["calls"])


@pytest.mark.parametrize("change", ["failed-job", "attempt", "job"])
def test_frozen_host_producer_is_verified_again_without_reselection(retained, tmp_path, change):
    selected = selector.select_host(PLATFORM, "master", None)
    if change == "failed-job":
        retained["jobs"][10][0]["conclusion"] = "failure"
    elif change == "attempt":
        retained["host"]["producer"]["run_attempt"] = 3
        retained["runs"][10]["run_attempt"] = 3
    else:
        retained["jobs"][10][0]["id"] = 102
    retained["pack"]()
    # Keep the selected ZIP hash matching so this challenges producer binding.
    selected["digest"] = retained["artifact"]["digest"]
    with pytest.raises(ValueError, match="producer"):
        selector.download_host(selected, tmp_path, PLATFORM, "master")


@pytest.mark.parametrize("missing_run", [20, 21])
def test_guest_selection_ignores_only_unselected_historical_producers(retained, tmp_path, missing_run):
    staged = (datetime.now(UTC) - timedelta(minutes=45)).isoformat()
    newest = retained["add_candidate"]("guest-2026-10-17.2", staged)
    retained["receipts"][newest["digest"]]["producer"] = {**retained["receipt"]["producer"], "run_id": 21, "job_id": 211}
    retained["runs"][21] = copy.deepcopy(retained["runs"][20])
    retained["jobs"][21] = [{**retained["jobs"][20][0], "id": 211}]
    retained["unavailable_runs"] = {missing_run}
    if missing_run == 21:
        with pytest.raises(ValueError, match=newest["digest"]):
            selector.select(tmp_path / "selection", PLATFORM)
        failed = json.loads((tmp_path / "selection/selection.json").read_bytes())
        assert failed["status"] == "failed" and newest["digest"] in failed["failure"]
    else:
        selected = selector.select(tmp_path / "selection", PLATFORM)
        assert selected["guest"]["index"] == newest
    assert not any("/runs/20" in call[-1] for call in retained["calls"])


@pytest.mark.parametrize("status,conclusion", [("in_progress", None), ("completed", "failure")])
def test_guest_qualification_waits_for_successful_staging_job(retained, tmp_path, status, conclusion):
    staged = (datetime.now(UTC) - timedelta(minutes=45)).isoformat()
    newest = retained["add_candidate"]("guest-2026-10-17.2", staged)
    retained["receipts"][newest["digest"]]["producer"] = {**retained["receipt"]["producer"], "run_id": 21, "job_id": 211}
    retained["runs"][21] = {**retained["runs"][20], "status": status, "conclusion": conclusion}
    retained["jobs"][21] = [{**retained["jobs"][20][0], "id": 211, "status": status, "conclusion": conclusion}]
    selected = selector.select(tmp_path / "selection", PLATFORM)
    assert selected["guest"]["index"] == retained["index"]
    assert selected["guest"]["uncompleted_indexes"] == [newest["digest"]]
    with pytest.raises(ValueError, match="did not complete successfully"):
        selector.select(tmp_path / "explicit", PLATFORM, guest_index=newest["digest"])


def test_newest_completed_candidate_is_tested_during_quarantine_without_older_green_substitution(retained, tmp_path):
    staged = (datetime.now(UTC) - timedelta(minutes=45)).isoformat()
    newest = retained["add_candidate"]("guest-2026-10-17.2", staged)
    retained["receipts"][newest["digest"]]["last_blackbox_result"] = "failure"
    partial = retained["add_candidate"]("guest-2026-10-17.3", staged, staged=False)
    selected = selector.select(tmp_path / "newest", PLATFORM)
    assert selected["guest"]["index"] == newest
    assert selected["guest"]["uncompleted_indexes"] == [partial["digest"]]
    assert selected["guest"]["staged_at"] == staged
    # Explicit qualification retains its exact original index, independently of tags.
    explicit = selector.select(tmp_path / "explicit", PLATFORM, guest_index=retained["index"]["digest"])
    assert explicit["guest"]["index"] == retained["index"]


def test_only_selected_staged_candidate_content_controls_availability(retained, tmp_path):
    staged = (datetime.now(UTC) - timedelta(minutes=45)).isoformat()
    newest = retained["add_candidate"]("guest-2026-10-17.2", staged)
    old_archive = descriptor(b"retained guest bytes", "archive")["digest"]
    retained["unavailable_blobs"] = {old_archive}
    selected = selector.select(tmp_path / "newest", PLATFORM)
    assert selected["guest"]["index"] == newest
    retained["unavailable_blobs"] = {selected["guest"]["archive"]["digest"]}
    with pytest.raises(ValueError, match=newest["digest"]):
        selector.select(tmp_path / "missing-newest", PLATFORM)
    failed = json.loads((tmp_path / "missing-newest/selection.json").read_bytes())
    assert failed["status"] == "failed" and newest["digest"] in failed["failure"]


def test_private_annotations_and_extra_receipt_fields_do_not_enter_reports(retained, tmp_path):
    retained["host"]["private"] = "private-marker"
    retained["host"]["producer"]["token"] = "private-marker"
    retained["receipt"]["private"] = "private-marker"
    retained["receipt"]["producer"]["token"] = "private-marker"
    retained["pack"]()
    selector.select(tmp_path / "selection", PLATFORM)
    assert "private-marker" not in (tmp_path / "selection/selection.json").read_text()


def test_cadence_and_consumers_have_no_product_build_steps():
    workflow = yaml.safe_load((ROOT / ".github/workflows/blackbox.yml").read_text())
    assert set(workflow["jobs"]) == {"systrap", "macos-package"}
    for job in workflow["jobs"].values():
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        assert "select_blackbox_artifacts.py" in commands and "retained_inputs.py run" in commands
        for builder in ("cargo", "rustup", "build_host_packages", "build-rootfs", "make -C vm", "guest-test-inputs"):
            assert builder not in commands
        upload = job["steps"][-1]
        assert upload["if"] == "always()"
        assert "github.run_attempt" in upload["with"]["name"]
        assert "selection/selection.json" in upload["with"]["path"]


@pytest.mark.parametrize("has_report", [True, False])
def test_arm64_installed_result_step_reaches_recorder_or_reports_missing_input(tmp_path, has_report):
    workflow = yaml.safe_load((ROOT / ".github/workflows/installed-arm64.yml").read_text())
    step = next(step for step in workflow["jobs"]["retained"]["steps"]
                if step.get("name") == "Retain digest-bound installed guest result")
    reports = tmp_path / "retained-reports"
    if has_report:
        reports.mkdir()
        (reports / "selection.json").write_text("{}")
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "oras").write_text("#!/bin/sh\ncat >/dev/null\n")
    (tools / "oras").chmod(0o755)
    recorder = tmp_path / ".venv/bin/python"
    recorder.parent.mkdir(parents=True)
    recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$RECORDER_CALL"\n')
    recorder.chmod(0o755)
    call = tmp_path / "recorder-call"
    env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "RUNNER_TEMP": str(tmp_path),
           "GH_TOKEN": "controlled-fixture", "GITHUB_ACTOR": "operator",
           "GITHUB_REPOSITORY": selector.REPOSITORY, "GITHUB_RUN_ID": "20", "GITHUB_RUN_ATTEMPT": "1",
           "RECORDER_CALL": str(call)}
    # GitHub evaluates expressions in env, but does not expand embedded shell variables.
    env["REPORTS"] = step["env"]["REPORTS"].replace("${{ runner.temp }}", str(tmp_path))
    result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    if has_report:
        assert result.returncode == 0, result.stderr
        args = call.read_text().splitlines()
        assert args[:3] == ["scripts/guest_release.py", "record-smoke", "--reports"]
        assert args[3] == str(reports)
    else:
        assert result.returncode != 0
        assert "report" in result.stderr.lower()
        assert not call.exists()


def test_guest_archive_without_host_package_cannot_reach_source_preparation(tmp_path):
    state_parent = tmp_path / "must-not-be-created"
    result = subprocess.run([str(ROOT / "tests/blackbox/run-installed-package.sh"), "--guest-archive", "missing.tar.zst"],
                            env=dict(os.environ, HOME=str(state_parent)), text=True, capture_output=True, check=False)
    assert result.returncode == 2 and "Archive options require --package" in result.stderr
    assert not state_parent.exists()


def test_retained_runner_uses_only_frozen_bytes_and_keeps_failed_execution(retained, tmp_path, monkeypatch):
    selection_dir = tmp_path / "selection"
    result = selector.select(selection_dir, PLATFORM)
    retained["head"] = "f" * 40
    retained["tags"].clear()

    def execute(args, **kwargs):
        assert args[0].endswith("run-installed-package.sh")
        assert args[args.index("--guest-index") + 1] == result["guest"]["index"]["digest"]
        assert args[args.index("--sha256") + 1] == result["host"]["archive"]["sha256"]
        assert "--lane" in args and args[args.index("--lane") + 1] == "systrap"
        assert kwargs["env"]["SAFEYOLO_BLACKBOX_FULL_SECTIONS"] == "1"
        return subprocess.CompletedProcess(args, 19)

    monkeypatch.setattr(retained_inputs.subprocess, "run", execute)
    monkeypatch.setattr(retained_inputs, "controller_identity", lambda: {"controller_revision": "d" * 40, "controller_dirty": False})
    before = len(retained["calls"])
    assert retained_inputs.run(selection_dir / "selection.json", "systrap", tmp_path / "reports", [], True) == 19
    assert len(retained["calls"]) == before  # no moving name/API read during execution
    report = json.loads((tmp_path / "reports/retained-run.json").read_bytes())
    assert report["exit"] == 19 and report["finished_at"]
    assert json.loads((tmp_path / "reports/selection.json").read_bytes()) == result


def test_retained_runner_rejects_changed_archive_before_installation(retained, tmp_path, monkeypatch):
    directory = tmp_path / "selection"
    result = selector.select(directory, PLATFORM)
    (directory / result["host"]["archive"]["name"]).write_bytes(b"changed archive")
    monkeypatch.setattr(retained_inputs.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("installer must not run"))
    monkeypatch.setattr(retained_inputs, "controller_identity", lambda: {"controller_revision": "d" * 40, "controller_dirty": False})
    assert retained_inputs.run(directory / "selection.json", "systrap", tmp_path / "reports", [], True) == 2
    assert "checksum differs" in (tmp_path / "reports/retained-run.json").read_text()


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
def test_archive_install_and_section_handoff_work_with_product_builders_unavailable(package_inputs, tmp_path, monkeypatch):
    """Run the real package installer; section instrumentation is controlled, not hardware proof."""
    import zstandard

    inputs = tmp_path / "inputs"
    inputs.mkdir()
    built = subprocess.run([*package_inputs[4], "--output", str(inputs)], capture_output=True, text=True, check=False)
    assert built.returncode == 0, built.stderr
    platform = package_builder.host_platform()
    archive = inputs / f"safeyolo-{platform}-production.tar.gz"
    monkeypatch.setattr(package_builder, "ROOT", package_inputs[0])
    # The real shell producer just verified the clean fixture checkout. The
    # imported Python module belongs to the separate controller checkout.
    monkeypatch.setattr(package_builder, "commit", lambda: package_inputs[5])
    for key, value in {"GITHUB_REPOSITORY": selector.REPOSITORY, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "2",
                       "GITHUB_WORKFLOW_REF": selector.REPOSITORY + "/" + selector.HOST_WORKFLOW + "@refs/heads/master",
                       "GITHUB_JOB": "build", "RUNNER_NAME": "controlled-builder"}.items():
        monkeypatch.setenv(key, value)
    package_builder.save_production(inputs)
    build = json.loads((inputs / "build.json").read_bytes())
    assert build["archive"]["sha256"] == retained_inputs.sha256(archive)
    with tarfile.open(archive) as package:
        sums = package.extractfile(archive.name.removesuffix(".tar.gz") + "/SHA256SUMS").read().decode()
    hashes = dict(reversed(line.split("  ", 1)) for line in sums.splitlines())
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w") as output:
        directory = tarfile.TarInfo("rootfs-tree")
        directory.type, directory.uid, directory.gid, directory.mode = tarfile.DIRTYPE, 100000, 100000, 0o755
        output.addfile(directory)
        cache = tarfile.TarInfo("cache-paths.txt")
        payload = b"/var/cache/apt\n"
        cache.size = len(payload)
        output.addfile(cache, io.BytesIO(payload))
    guest_archive = inputs / "guest.tar.zst"
    guest_archive.write_bytes(zstandard.ZstdCompressor().compress(content.getvalue()))
    selection = {"schema": "safeyolo.blackbox-inputs/v1", "status": "selected", "platform": platform,
                 "host": {**build, "executables_sha256": {name: hashes["./" + name] for name in selector.installed_binaries(platform)}},
                 "guest": {"version": "guest-2026-10-17.1", "compatibility": "v1", "index": descriptor(b"index", "index"),
                           "child": descriptor(b"manifest", "manifest"), "archive": descriptor(guest_archive.read_bytes(), "archive")}}
    (inputs / "selection.json").write_text(json.dumps(selection))
    controller = tmp_path / "controller"
    scripts = controller / "tests/blackbox"
    scripts.mkdir(parents=True)
    (controller / "scripts").mkdir()
    for name in ("run-installed-package.sh", "retained_inputs.py", "installed_host_smoke.py"):
        shutil.copy2(ROOT / "tests/blackbox" / name, scripts / name)
    for name in ("native_package.sh", "select_blackbox_artifacts.py"):
        shutil.copy2(ROOT / "scripts" / name, controller / "scripts" / name)
    (controller / ".venv").symlink_to(sys.prefix, target_is_directory=True)
    handoff = scripts / "run-installed.sh"
    handoff.write_text(f"#!{sys.executable}\n" + '''import json, pathlib, subprocess, sys
args = sys.argv[1:]
assert args[0] == 'systrap' and '--prepared-config' in args and '--section' not in args
root = pathlib.Path(args[args.index('--prepared-config')+1])
assert (root/'package-info').is_file() and (root/'share/guest-selection.json').is_file()
subprocess.run([str(root/'bin/safeyolo'), '--version'], check=True)
reports = pathlib.Path(args[args.index('--artifacts')+1]); reports.mkdir(parents=True)
(reports/'controlled-section-handoff.json').write_text(json.dumps(args))
''')
    handoff.chmod(0o755)
    tools = tmp_path / "unavailable-builders"
    tools.mkdir()
    for name in ("cargo", "rustup", "make", "swift"):
        executable = tools / name
        executable.write_text('#!/bin/sh\necho "product builder was invoked" >&2\nexit 99\n')
        executable.chmod(0o755)
    for name in ("build_host_packages.sh", "build_guest_command.sh"):
        executable = controller / "scripts" / name
        executable.write_text('#!/bin/sh\nexit 99\n')
        executable.chmod(0o755)
    (controller / "install.sh").write_text('#!/bin/sh\nexit 99\n')
    (controller / "install.sh").chmod(0o755)
    # The tiny identity fixtures were compiled before builders became unavailable.
    monkeypatch.setenv("PATH", f"{tools}:{sys.prefix}/bin:{os.environ['PATH']}")
    states = tmp_path / "states"
    states.mkdir()
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_STATE_PARENT", str(states))
    monkeypatch.setattr(retained_inputs, "ROOT", controller)
    assert retained_inputs.run(inputs / "selection.json", "systrap", tmp_path / "reports", [], True,
                               guest_archive=guest_archive) == 0
    installed = json.loads((tmp_path / "reports/installed-inputs.json").read_bytes())
    assert installed["installed_files_sha256"] == selection["host"]["executables_sha256"]
    assert installed["guest"]["archive"]["digest"] == selection["guest"]["archive"]["digest"]
    assert (tmp_path / "reports/guest/controlled-section-handoff.json").is_file()


def test_actual_oras_staging_attachment_round_trip(tmp_path, monkeypatch):
    """Exercise real ORAS metadata locally; this is not GHCR or staging-job proof."""
    oras = os.environ.get("SAFEYOLO_TEST_ORAS")
    if not oras:
        pytest.skip("set SAFEYOLO_TEST_ORAS to the separately prepared publisher tool")
    layout = tmp_path / "layout"
    blobs = layout / "blobs/sha256"
    blobs.mkdir(parents=True)
    contents = release(b"opaque archive wire fixture", version="guest-2026-10-17.1")
    for key, data in contents.items():
        if "/sha256:" in key:
            (blobs / key.split("sha256:", 1)[1]).write_bytes(data)
    raw = contents["manifests/compat-v1"]
    index = descriptor(raw, "application/vnd.oci.image.index.v1+json")
    (blobs / index["digest"].removeprefix("sha256:")).write_bytes(raw)
    (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [{
        **index, "annotations": {"org.opencontainers.image.ref.name": "guest-2026-10-17.1"}}]}))
    now = datetime.now(UTC)
    staging = {"schema": "safeyolo.guest-staging/v1", "index_digest": index["digest"],
               "source_revision": "a" * 40, "staged_at": now.isoformat(),
               "producer": {"repository": selector.REPOSITORY, "workflow": selector.GUEST_WORKFLOW,
                            "run_id": 20, "run_attempt": 1, "job_id": 201}}
    (tmp_path / "staging.json").write_text(json.dumps(staging))
    attached = subprocess.run([oras, "attach", "--oci-layout", "--artifact-type", selector.STAGING_TYPE,
                               f"{layout}@{index['digest']}", f"staging.json:{selector.STAGING_TYPE}"],
                              cwd=tmp_path, capture_output=True, text=True, check=False)
    assert attached.returncode == 0, attached.stdout + attached.stderr

    def local_oras(*args):
        assert args[0] == "oras"
        command = [oras, *args[1:-1], "--oci-layout", args[-1].replace(selector.GUEST_REPOSITORY, str(layout))]
        return subprocess.check_output(command, timeout=20)

    monkeypatch.setattr(selector, "capture", local_oras)
    monkeypatch.setattr(selector, "verify_producer", lambda *_args, **_kwargs: {
        "status": "completed", "conclusion": "success",
        "started_at": (now - timedelta(seconds=1)).isoformat(), "completed_at": (now + timedelta(seconds=1)).isoformat()})
    actual = selector.select_guest("v1", PLATFORM, "master", None)
    assert actual["index"] == index and actual["staged_at"] == staging["staged_at"]
    assert actual["receipt_blob"]["mediaType"] == selector.STAGING_TYPE
    assert str(tmp_path) not in json.dumps(actual)
