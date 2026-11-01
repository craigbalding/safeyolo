"""Exercise scheduled input download, receipts and the actual Actions Bash callers."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import build_host_packages as packages
from scripts import select_blackbox_artifacts as selection
from tests.test_host_packages import executable

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/guest-test-inputs.yml").read_text())


def run(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)


@pytest.fixture(params=["guest", "host"])
def inputs(tmp_path, request):
    if sys.platform != "linux":
        pytest.skip("controlled executable consumer runs on Linux")
    source = tmp_path / "source"
    (source / "scripts").mkdir(parents=True)
    for name in ("select_blackbox_artifacts.py", "build_host_packages.py", "native_package.sh"):
        shutil.copy2(ROOT / "scripts" / name, source / "scripts" / name)
    for tree in ("proxy", "guest/command"):
        (source / tree).mkdir(parents=True)
        shutil.copy2(ROOT / tree / "Cargo.lock", source / tree / "Cargo.lock")
    (source / ".gitignore").write_text("__pycache__/\nproxy/target/\nguest/command/target/\n")
    for command in (("git", "init", "-q"), ("git", "add", "."),
                    ("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                     "commit", "-qm", "Controlled CI source")):
        result = run(*command, cwd=source)
        assert result.returncode == 0, result.stderr
    revision = run("git", "rev-parse", "HEAD", cwd=source).stdout.strip()
    tools = tmp_path / "tools"
    tools.mkdir()
    rustc = tools / "rustc"
    rustc.write_text("#!/bin/sh\nprintf 'rustc 1.94.0\\nhost: fixture-native\\n'\n")
    rustc.chmod(0o755)
    (tools / "python3").symlink_to(sys.executable)
    gh = tools / "gh"
    gh.write_text(
        f"#!{sys.executable}\nimport json, os, pathlib, sys\n"
        "endpoint = sys.argv[-1]\n"
        "with open(os.environ['API_CALLS'], 'a') as calls: calls.write(endpoint + '\\n')\n"
        "if os.environ.get('API_FAILURE') == 'true': raise SystemExit(37)\n"
        "if endpoint.endswith('/zip'):\n"
        "    sys.stdout.buffer.write(pathlib.Path(os.environ['ARTIFACT_ZIP']).read_bytes())\n"
        "else:\n"
        "    print(json.dumps(json.loads(pathlib.Path(os.environ['API_ROUTES']).read_text())[endpoint]))\n",
    )
    gh.chmod(0o755)
    environment = dict(os.environ, BASH_ENV=os.devnull, PATH=f"{tools}:{os.environ['PATH']}",
                       GITHUB_REPOSITORY=selection.REPOSITORY, GITHUB_RUN_ID="10", GITHUB_RUN_ATTEMPT="1",
                       GITHUB_WORKFLOW_REF=f"{selection.REPOSITORY}/.github/workflows/ci.yml@refs/heads/master",
                       GITHUB_JOB="build", RUNNER_NAME="producer", GITHUB_OUTPUT=str(tmp_path / "outputs"),
                       API_ROUTES=str(tmp_path / "api.json"), ARTIFACT_ZIP=str(tmp_path / "artifact.zip"),
                       API_CALLS=str(tmp_path / "api-calls"), SAFEYOLO_BUILD_REVISION=revision,
                       SAFEYOLO_BUILD_PROFILE="production", DEFAULT_BRANCH="master",
                       REQUIRE_SUCCESSFUL_RUN="false",
                       INPUT_PLATFORM=packages.host_platform())
    host, guest = source / "proxy/target/release", source / "guest/command/target/release"
    for directory, names in ((host, selection.native_input_files("host")),
                             (guest, ["safeyolo-guest", "safeyolo-coord"])):
        directory.mkdir(parents=True)
        for name in names:
            identity = f"{name} 0.1.0 commit={revision} profile=production"
            executable(directory / name, identity)
            if directory == guest:
                (directory / f"{name}.version").write_text(identity + "\n")
                (directory / f"{name}.sha256").write_text(packages.sha256(directory / name) + "\n")
    kind = request.param
    directory = guest if kind == "guest" else host
    result = run(sys.executable, "scripts/select_blackbox_artifacts.py", "--native-input", kind,
                 "--save-native-input", "--platform", environment["INPUT_PLATFORM"], "--revision", revision,
                 "--output", str(directory), cwd=source, env=environment)
    assert result.returncode == 0, result.stderr
    receipt = json.loads((directory / selection.INPUT_RECEIPT).read_bytes())
    # Cargo leaves this file beside the guest executable. Select archive
    # members from the producer's actual patterns, independently of the reader.
    (guest / "safeyolo-guest.d").write_text("safeyolo-guest: fixture source\n")
    steps = WORKFLOW["jobs"]["build"]["steps"]
    upload = next(step for step in steps if step.get("with", {}).get("name") ==
                  "linux-" + kind + "-${{ inputs.architecture }}-${{ inputs.profile }}")
    patterns = upload["with"]["path"].replace("${{ inputs.profile == 'production' && 'release' || 'debug' }}", "release")
    payload = {path.name: path.read_bytes() for pattern in patterns.splitlines()
               for path in source.glob(pattern) if path.is_file()}
    shutil.rmtree(directory)
    arch = environment["INPUT_PLATFORM"].split("-")[1]
    name = f"linux-{kind}-{arch}-production"
    run_record = {"id": 10, "head_sha": revision, "head_branch": "master", "path": ".github/workflows/ci.yml",
                  "event": "schedule", "run_attempt": 1, "status": "completed", "conclusion": "success"}
    job = {"id": 100, "name": f"guest-inputs ({arch}) / build", "runner_name": "producer",
           "status": "completed", "conclusion": "success",
           "started_at": "2026-01-01T00:00:00Z", "completed_at": "2027-01-01T00:00:00Z"}
    artifact = {"id": 1, "name": name, "expired": False, "created_at": receipt["built_at"],
                "workflow_run": {"id": 10, "head_sha": revision, "head_branch": "master"}}
    routes = {
        f"repos/{selection.REPOSITORY}/actions/artifacts?name={name}&per_page=100": [{"artifacts": [artifact]}],
        f"repos/{selection.REPOSITORY}/actions/runs/10": run_record,
        f"repos/{selection.REPOSITORY}/actions/runs/10/attempts/1": run_record,
        f"repos/{selection.REPOSITORY}/actions/runs/10/attempts/1/jobs?per_page=100": [{"jobs": [job]}],
    }

    def prepare():
        payload[selection.INPUT_RECEIPT] = json.dumps(receipt, indent=2).encode() + b"\n"
        with zipfile.ZipFile(environment["ARTIFACT_ZIP"], "w") as archive:
            for filename, content in payload.items():
                archive.writestr(filename, content)
        artifact["digest"] = "sha256:" + packages.sha256(Path(environment["ARTIFACT_ZIP"]))
        Path(environment["API_ROUTES"]).write_text(json.dumps(routes))

    prepare()
    step = next(step for step in steps if step.get("id") == f"reuse_{kind}")
    return {"source": source, "environment": environment, "kind": kind, "directory": directory, "receipt": receipt,
            "payload": payload, "artifact": artifact, "routes": routes,
            "producer": run_record, "job": job, "prepare": prepare, "step": step}


@pytest.mark.parametrize("case", ["match", "missing", "expired", "failed-run", "unfinished-run", "source",
                                  "branch", "pr", "toolchain", "flags", "legacy", "digest", "file",
                                  "receipt-source", "receipt-profile", "receipt-platform", "receipt-kind",
                                  "attempt", "failed-job", "upload-time", "build-time", "missing-file", "api",
                                  "features", "output-kind", "reuploaded", "failed-origin", "newest-failed",
                                  "match-package", "failed-run-package", "unfinished-run-package", "failed-origin-package",
                                  "newest-failed-package"])
def test_native_input_selection_and_actions_caller(inputs, case):
    data = inputs
    receipt, artifact, producer = data["receipt"], data["artifact"], data["producer"]
    missing = {"missing", "expired", "source", "branch", "pr", "toolchain", "flags", "legacy", "failed-job",
               "features", "output-kind", "failed-run-package", "unfinished-run-package", "failed-origin-package", "newest-failed-package"}
    if case.endswith("-package"):
        data["environment"]["REQUIRE_SUCCESSFUL_RUN"] = "true"
    base_case = case.removesuffix("-package")
    if case == "missing":
        next(value for value in data["routes"].values() if isinstance(value, list) and "artifacts" in value[0])[0]["artifacts"] = []
    elif case == "expired":
        artifact["expired"] = True
    elif base_case == "failed-run":
        producer["conclusion"] = "failure"
    elif base_case == "unfinished-run":
        producer.update(status="in_progress", conclusion=None)
    elif case in {"source", "branch"}:
        artifact["workflow_run"]["head_sha" if case == "source" else "head_branch"] = "b" * 40
    elif case == "pr":
        producer["event"] = "pull_request"
    elif case == "toolchain":
        receipt["settings"]["rustc"] = "different compiler"
    elif case == "flags":
        receipt["settings"]["environment"]["RUSTFLAGS"] = "-C opt-level=2"
    elif case == "features":
        receipt["settings"]["features"] = "different"
    elif case == "output-kind":
        artifact["name"] = "nightly-host-linux-arm64-production"
    elif base_case in {"reuploaded", "failed-origin"}:
        origin = {**producer, "id": 9, "conclusion": "failure" if base_case == "failed-origin" else "success"}
        receipt["producer"]["run_id"] = 9
        for suffix, value in (("", origin), ("/jobs?per_page=100", [{"jobs": [data["job"]]}])):
            data["routes"][f"repos/{selection.REPOSITORY}/actions/runs/9/attempts/1{suffix}"] = value
    elif base_case == "newest-failed":
        old = {**artifact, "id": 0, "created_at": "2026-01-01T00:00:01Z", "workflow_run": {**artifact["workflow_run"], "id": 9}}
        next(value for value in data["routes"].values() if isinstance(value, list) and "artifacts" in value[0])[0]["artifacts"].append(old)
        producer["conclusion"] = "failure"
    elif case.startswith("receipt-"):
        field = {"source": "source_revision", "profile": "profile", "platform": "platform", "kind": "kind"}[case[8:]]
        receipt[field] = "different"
    elif case == "attempt":
        producer["run_attempt"] = 2
    elif case == "failed-job":
        data["job"]["conclusion"] = "failure"
    elif case == "upload-time":
        artifact["created_at"] = "2025-01-01T00:00:00Z"
    elif case == "build-time":
        receipt["built_at"] = "2025-01-01T00:00:00Z"
    elif case == "file":
        data["payload"]["safeyolo-coord"] += b"changed bytes"
    elif case == "missing-file":
        del data["payload"]["safeyolo-coord"]
    elif case == "api":
        data["environment"]["API_FAILURE"] = "true"
    data["prepare"]()
    if case == "legacy":
        with zipfile.ZipFile(data["environment"]["ARTIFACT_ZIP"], "w") as archive:
            for name, content in data["payload"].items():
                if name != selection.INPUT_RECEIPT:
                    archive.writestr(name, content)
        artifact["digest"] = "sha256:" + packages.sha256(Path(data["environment"]["ARTIFACT_ZIP"]))
        Path(data["environment"]["API_ROUTES"]).write_text(json.dumps(data["routes"]))
    elif case == "digest":
        with Path(data["environment"]["ARTIFACT_ZIP"]).open("ab") as output:
            output.write(b"untrusted transport change")
    result = run("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", data["step"]["run"],
                 cwd=data["source"], env=data["environment"])
    outputs = Path(data["environment"]["GITHUB_OUTPUT"])
    matching = case in {"match", "reuploaded", "failed-run", "unfinished-run", "failed-origin", "match-package", "newest-failed"}
    expected = "true" if matching else "false"
    if matching or case in missing:
        assert result.returncode == 0, result.stderr
        assert outputs.read_text() == f"reused={expected}\n"
    else:
        assert result.returncode != 0, result.stdout
        assert not outputs.exists()
    # Actions adds success() to these if expressions. Run their comparisons
    # under the explicit Actions Bash flags with that same failure condition.
    build_name = "Build Linux guest executables and receipts" if data["kind"] == "guest" else "Build Linux host test inputs"
    build = next(step for step in WORKFLOW["jobs"]["build"]["steps"] if step.get("name") == build_name)
    condition = build["if"].replace(f"steps.reuse_{data['kind']}.outputs.reused", shlex.quote(expected))
    condition = condition.replace("inputs.host_inputs", "true").replace("inputs.architecture", "'amd64'").replace("inputs.retain_packages", "true")
    admitted = run("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                   f"[[ {result.returncode} == 0 && ( {condition} ) ]]")
    assert (admitted.returncode == 0) == (case in missing)
    if matching:
        assert "Reused linux-" in result.stdout
        assert (data["directory"] / selection.INPUT_RECEIPT).read_bytes() == data["payload"][selection.INPUT_RECEIPT]
        for name, content in data["payload"].items():
            assert (data["directory"] / name).read_bytes() == content
        check_name = "Check Linux guest input identity" if data["kind"] == "guest" else "Verify reused Linux host test inputs"
        check = next(step for step in WORKFLOW["jobs"]["build"]["steps"] if step.get("name") == check_name)
        checked = run("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", check["run"],
                      cwd=data["source"], env=data["environment"])
        assert checked.returncode == 0, checked.stderr
    else:
        assert not data["directory"].exists()
    if base_case == "newest-failed":
        assert "/actions/runs/9" not in Path(data["environment"]["API_CALLS"]).read_text()


@pytest.mark.parametrize("platform,target", [
    ("linux-amd64", "x86_64-unknown-linux-musl"),
    ("linux-arm64", "aarch64-unknown-linux-musl"),
])
def test_guest_input_receipt_records_target_and_c_compiler(monkeypatch, platform, target):
    revision = "a" * 40
    monkeypatch.setattr(packages, "commit", lambda: revision)
    monkeypatch.setattr(packages, "proxy_settings", lambda profile: {"environment": {}})
    monkeypatch.setattr(packages, "output", lambda *args, **kwargs: "pinned rustc")
    monkeypatch.delenv("SAFEYOLO_GUEST_TARGET", raising=False)
    compiler = "CC_" + target.replace("-", "_")
    monkeypatch.setenv(compiler, "configured-musl-cc")
    identity = selection.native_input_identity("guest", platform, "production", revision)
    assert identity["settings"]["guest_target"] == target
    assert identity["settings"]["environment"][compiler] == "configured-musl-cc"
    monkeypatch.setenv("SAFEYOLO_GUEST_TARGET", target.replace("musl", "gnu"))
    assert selection.native_input_identity("guest", platform, "production", revision) != identity


def test_reuse_keeps_independent_schedules_tests_and_package_assembly():
    for workflow_name in ("ci.yml", "proxy-rust.yml"):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text())
        assert workflow["jobs"]["guest-inputs"]["permissions"] == {"contents": "read", "actions": "read"}
        assert "schedule" in workflow[True]
    for job in WORKFLOW["jobs"].values():
        assert job["env"]["CARGO_BUILD_JOBS"] == "1"
        assert job["env"]["SAFEYOLO_CARGO_RESERVE_GIB"] == "10"
        package = next(step for step in job["steps"] if "Retain complete" in step.get("name", ""))
        assert package["if"] == "inputs.retain_packages && inputs.profile == 'production'"
        assert "build_host_packages.sh" in package["run"]
        assert "reuse" not in package["if"]
        selectors = [step for step in job["steps"] if step.get("id", "").startswith("reuse_")]
        for step in selectors:
            assert step["env"]["REQUIRE_SUCCESSFUL_RUN"] == "${{ inputs.retain_packages && inputs.profile == 'production' }}"
    steps = WORKFLOW["jobs"]["build"]["steps"]
    guest_build = next(step for step in steps if step.get("name") == "Build Linux guest executables and receipts")
    host_select = next(step for step in steps if step.get("id") == "reuse_host")
    # Keep guest compilation before host selection, including explicit targets
    # that can write proxy/target's host Coord binary.
    assert steps.index(guest_build) < steps.index(host_select)


@pytest.mark.parametrize("inputs", ["host"], indirect=True)
@pytest.mark.parametrize("failure", [False, True])
def test_mac_selection_uses_its_platform_job_and_propagates_failure(inputs, failure):
    data = inputs
    old_endpoint = next(endpoint for endpoint in data["routes"] if "/artifacts?" in endpoint)
    data["artifact"]["name"] = "darwin-host-arm64-production"
    new_endpoint = f"repos/{selection.REPOSITORY}/actions/artifacts?name=darwin-host-arm64-production&per_page=100"
    data["routes"][new_endpoint] = data["routes"].pop(old_endpoint)
    data["receipt"]["platform"] = "darwin-arm64"
    data["receipt"]["producer"]["job_key"] = "macos-host"
    data["job"]["name"] = "guest-inputs (arm64) / macos-host"
    if failure:
        data["environment"]["API_FAILURE"] = "true"
    data["prepare"]()
    step = next(step for step in WORKFLOW["jobs"]["macos-host"]["steps"] if step.get("id") == "reuse_host")
    result = run("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"],
                 cwd=data["source"], env=data["environment"])
    assert (result.returncode == 0) != failure, result.stderr
    if not failure:
        assert "Reused darwin-host-arm64-production" in result.stdout
        assert (data["directory"] / selection.INPUT_RECEIPT).read_bytes() == data["payload"][selection.INPUT_RECEIPT]


@pytest.mark.parametrize("inputs", ["guest"], indirect=True)
@pytest.mark.parametrize("archive_kind", ["current", "legacy", "current-extra", "legacy-extra", "legacy-damaged"])
def test_guest_producer_zip_members_allow_reuse_or_legacy_build(inputs, tmp_path, archive_kind):
    data = inputs
    archive_path = Path(data["environment"]["ARTIFACT_ZIP"])
    if archive_kind.startswith("legacy"):
        output = tmp_path / "old-producer"
        output.mkdir()
        for name, content in data["payload"].items():
            (output / name).write_bytes(content)
        (output / "safeyolo-guest.d").write_text("safeyolo-guest: fixture source\n")
        if archive_kind == "legacy-extra":
            (output / "safeyolo-guest.unexpected").write_text("unrecognized upload member\n")
        # These are the old workflow patterns observed in artifact12250797504.
        with zipfile.ZipFile(archive_path, "w") as archive:
            for pattern in ("safeyolo-guest*", "safeyolo-coord*"):
                for path in output.glob(pattern):
                    archive.write(path, path.name)
        with zipfile.ZipFile(archive_path) as archive:
            assert "safeyolo-guest.d" in archive.namelist()
            assert selection.INPUT_RECEIPT not in archive.namelist()
    else:
        # The fixture staged a depfile before applying the current YAML paths.
        # A fresh upload must leave it out while retaining the full receipt.
        assert "safeyolo-guest.d" not in data["payload"]
        assert selection.INPUT_RECEIPT in data["payload"]
        if archive_kind == "current-extra":
            with zipfile.ZipFile(archive_path, "a") as archive:
                archive.writestr("unexpected/payload", b"unrecognized upload path")
    data["artifact"]["digest"] = "sha256:" + packages.sha256(archive_path)
    Path(data["environment"]["API_ROUTES"]).write_text(json.dumps(data["routes"]))
    if archive_kind == "legacy-damaged":
        with archive_path.open("ab") as output:
            output.write(b"changed after the producer digest")
    result = run("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", data["step"]["run"],
                 cwd=data["source"], env=data["environment"])
    outputs = Path(data["environment"]["GITHUB_OUTPUT"])
    if archive_kind in {"current", "legacy"}:
        assert result.returncode == 0, result.stderr
        reused = "true" if archive_kind == "current" else "false"
        assert outputs.read_text() == f"reused={reused}\n"
        if archive_kind == "current":
            assert (data["directory"] / selection.INPUT_RECEIPT).read_bytes() == data["payload"][selection.INPUT_RECEIPT]
        else:
            assert not data["directory"].exists()
    else:
        assert result.returncode != 0, result.stdout
        assert not outputs.exists()
        assert not data["directory"].exists()
