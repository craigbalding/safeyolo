"""Exercise the manual retained-archive consumer before any hosted runtime claim."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest
import yaml

from tests.test_guest_acquisition import digest, release

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/installed-arm64.yml").read_text())
JOB = WORKFLOW["jobs"]["installed-arm64"]
HOST_JOB = WORKFLOW["jobs"]["acquire-host"]
HOST = WORKFLOW["env"]


def step(name, job=JOB):
    return next(item for item in job["steps"] if item.get("name") == name)


def execute(name, cwd, env, job=JOB):
    selected = step(name, job)
    workflow_shell = WORKFLOW.get("defaults", {}).get("run", {}).get("shell")
    job_shell = job.get("defaults", {}).get("run", {}).get("shell", workflow_shell)
    shell = selected.get("shell", job_shell)
    # Match GitHub's Ubuntu shell templates. An unspecified shell lacks
    # pipefail; explicit Bash uses --noprofile --norc -eo pipefail.
    command = ["bash", "-e"] if shell is None else ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
    if shell not in {None, "bash"}:
        raise ValueError(f"unsupported workflow shell: {shell}")
    script = cwd / "workflow-step.sh"
    script.write_text(selected["run"])
    return subprocess.run([*command, str(script)],
                          cwd=cwd, env={**os.environ, **HOST, **job.get("env", {}), **env},
                          text=True, capture_output=True, check=False, timeout=20)


@pytest.mark.parametrize("shell", [None, "bash"])
def test_step_executor_preserves_github_default_and_explicit_bash_semantics(tmp_path, monkeypatch, shell):
    selected = {"name": "shell control", "run": "false | tee verifier.txt\nprintf after > after.txt\n"}
    if shell is not None:
        selected["shell"] = shell
    monkeypatch.setitem(JOB, "steps", [selected])
    result = execute("shell control", tmp_path, {})
    assert (result.returncode == 0) == (shell is None), result.stdout + result.stderr
    assert (tmp_path / "after.txt").exists() == (shell is None)


def test_manual_route_separates_acquisition_and_pins_read_only_qualification():
    assert set(WORKFLOW.get("on", WORKFLOW.get(True))) == {"workflow_dispatch"}
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert set(WORKFLOW["jobs"]) == {"retained", "acquire-host", "installed-arm64", "public-install"}
    assert WORKFLOW.get("on", WORKFLOW.get(True))["workflow_dispatch"]["inputs"]["mode"]["default"] == "retained"
    retained = WORKFLOW["jobs"]["retained"]
    assert retained["if"] == "github.event_name == 'workflow_dispatch' && inputs.mode == 'retained'"
    assert retained["runs-on"] == "ubuntu-24.04-arm"
    retained_commands = "\n".join(item.get("run", "") for item in retained["steps"])
    assert "select_blackbox_artifacts.py" in retained_commands and "retained_inputs.py run" in retained_commands
    assert "cargo" not in retained_commands and "guest/build" not in retained_commands
    draft_route = "github.event_name == 'workflow_dispatch' && inputs.mode == 'draft-offline'"
    assert HOST_JOB["if"] == draft_route
    assert HOST_JOB["permissions"] == {"contents": "read"}
    assert len(HOST_JOB["steps"]) == 2
    acquisition = step("Read and bind the retained host inputs", HOST_JOB)
    assert acquisition["shell"] == "bash"
    assert acquisition["env"] == {"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}
    assert "tar " not in acquisition["run"]
    assert "cargo" not in acquisition["run"] and "tests/" not in acquisition["run"]
    transfer = step("Transfer only bound host inputs", HOST_JOB)
    assert transfer["uses"].startswith("actions/upload-artifact@")
    assert transfer["with"]["path"].splitlines() == [
        "${{ runner.temp }}/retained-host/" + name
        for name in ("safeyolo-linux-arm64-production.tar.gz", "SHA256SUMS", "release.json")
    ]
    assert transfer["with"]["if-no-files-found"] == "error" and "if" not in transfer
    assert HOST_JOB["outputs"] == {"artifact-id": "${{ steps.host-inputs.outputs.artifact-id }}"}
    assert transfer["id"] == "host-inputs"
    assert JOB["if"] == draft_route
    public = WORKFLOW["jobs"]["public-install"]
    assert public["if"] == "github.event_name == 'workflow_dispatch' && inputs.mode == 'public-install'"
    assert public["permissions"] == {"contents": "read"} and "needs" not in public
    assert JOB["runs-on"] == "ubuntu-24.04-arm" and JOB["needs"] == "acquire-host"
    assert JOB["permissions"] == {"contents": "read", "actions": "read"}
    assert "continue-on-error" not in HOST_JOB and "continue-on-error" not in JOB
    assert all("continue-on-error" not in item for job in WORKFLOW["jobs"].values() for item in job["steps"])
    checkout = next(item for item in JOB["steps"] if item.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"] == {"persist-credentials": False}
    assert HOST["HOST_REVISION"] == "c9ecb66b462c2ba0c499f2322f6cfc5c142012da"
    assert HOST["HOST_RELEASE_ID"] == "414106024"
    assert HOST["HOST_ARCHIVE_ASSET_ID"] == "644683987"
    assert HOST["HOST_CHECKSUM_ASSET_ID"] == "644683989"
    assert HOST["HOST_SHA256"] == "eab9b709b3e4c6b536614eeb6b422d12c2b55826149085f78c326b31637922af"
    assert HOST["HOST_BYTES"] == "176869006" and HOST["GUEST_COMPATIBILITY"] == "v1"
    assert JOB["env"]["GUEST_REVISION"] == "8234a047d810d543d8c4d1cb1fa9859987be035b"
    assert JOB["env"]["GUEST_INDEX"] == "sha256:df0068692909088a90db2c8f9777807404e3b7d8061ee72bc94a5feabd7dc46e"
    assert JOB["env"]["GUEST_ARCHIVE_SHA256"] == "2899415b6f4ec2eb3ab2ad3a6ef05c7cc5b9b2de14f9c623ff22b2478c8cb6f5"
    downloads = [item for item in JOB["steps"] if item.get("uses", "").startswith("actions/download-artifact@")]
    assert len(downloads) == 2
    assert downloads[0]["with"] == {
        "artifact-ids": "${{ needs.acquire-host.outputs.artifact-id }}", "merge-multiple": True,
        "path": "${{ runner.temp }}/retained-host",
    }
    assert "if" not in downloads[0]
    assert "if" not in step("Recheck the transferred host inputs before installation")
    assert JOB["steps"].index(downloads[0]) < JOB["steps"].index(step("Recheck the transferred host inputs before installation"))
    assert downloads[1]["with"] == {
        "artifact-ids": "${{ env.GUEST_ARTIFACT_ID }}", "run-id": "${{ env.GUEST_RUN_ID }}",
        "repository": "craigbalding/safeyolo", "github-token": "${{ secrets.GITHUB_TOKEN }}",
        "merge-multiple": True, "path": "${{ runner.temp }}/retained-guest-oci",
    }
    commands = "\n".join(item.get("run", "") for item in JOB["steps"])
    assert "gh api" not in commands
    assert "--example verify_guest_oci" in commands and "--bin " not in commands
    assert "guest/build" not in commands and "publish_guest" not in commands
    assert "--lane systrap" in commands and "--platform-assets" in commands
    upload = JOB["steps"][-1]
    assert upload["if"] == "always()" and upload["with"]["path"] == "${{ env.SAFEYOLO_BLACKBOX_ARTIFACTS_DIR }}"
    nightly = yaml.safe_load((ROOT / ".github/workflows/blackbox.yml").read_text())
    assert set(nightly.get("on", nightly.get(True))["workflow_dispatch"]["inputs"]) == {"host_run", "guest_index"}
    assert set(nightly["jobs"]) == {"systrap", "macos-package"}
    assert all("if" not in job for job in nightly["jobs"].values())
    preparation = step("Prepare the supported systrap host")["run"]
    assert preparation == "tests/blackbox/prepare-systrap-host.sh"
    source_preparation = next(item for item in nightly["jobs"]["systrap"]["steps"]
                              if item.get("name") == "Prepare the supported systrap host")
    assert source_preparation["run"] == "tests/blackbox/prepare-systrap-host.sh"


@pytest.mark.parametrize("selection", ["original-g1", "reduced-33224", "unknown"])
def test_guest_selection_binds_retained_artifact_and_archive(tmp_path, selection):
    env_file = tmp_path / "github-env"
    result = execute("Select the retained guest inputs", tmp_path, {
        "GITHUB_ENV": str(env_file), "GUEST_SELECTION": selection,
    })
    if selection == "unknown":
        assert result.returncode == 2 and not env_file.exists()
        return
    assert result.returncode == 0, result.stderr
    selected = dict(JOB["env"])
    if env_file.exists():
        selected.update(line.split("=", 1) for line in env_file.read_text().splitlines())
    if selection == "original-g1":
        assert selected == JOB["env"]
        assert selected["GUEST_ARTIFACT_ID"] == "11747551391"
        assert selected["GUEST_RUN_ID"] == "38248401312"
    else:
        assert {key: value for key, value in selected.items() if key.startswith("GUEST_")} == {
            "GUEST_REVISION": "33224c9fc14beeb00be30eb71bdc09f91c5aa58b",
            "GUEST_VERSION": "guest-2026-10-16.1082",
            "GUEST_INDEX": "sha256:14359301826746d088f124205de232c77c40567871550d38b035e6bfb53e5a2e",
            "GUEST_ARCHIVE_SHA256": "234c1b1fb58e58822315bf896fcfaba2618ff0bcb98e73372edcf9dccbd24aad",
            "GUEST_ARCHIVE_BYTES": "119728693",
            "GUEST_ARTIFACT_ID": "12079186556",
            "GUEST_RUN_ID": "38975155518",
        }


@pytest.fixture
def host_inputs(tmp_path, linux_workflow_stat):
    bundle = tmp_path / "safeyolo-linux-arm64-production"
    bundle.mkdir()
    (bundle / "package-info").write_text(
        f"source_commit={HOST['HOST_REVISION']}\nprofile=production\nplatform=linux-arm64\nguest_compatibility=v1\n"
    )
    archive = tmp_path / "fixture-host.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        output.add(bundle, arcname=bundle.name)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(f"{sha}  safeyolo-linux-arm64-production.tar.gz\n")
    metadata = {
        "id": 42, "draft": False, "tag_name": "host-" + HOST["HOST_REVISION"],
        "target_commitish": HOST["HOST_REVISION"],
        "assets": [{"id": 43, "name": "safeyolo-linux-arm64-production.tar.gz", "state": "uploaded"},
                   {"id": 44, "name": "SHA256SUMS", "state": "uploaded"}],
    }
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "stat").symlink_to(linux_workflow_stat)
    gh = tools / "gh"
    gh.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
from pathlib import Path
endpoint = sys.argv[-1]
with Path(os.environ['API_CALLS']).open('a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
if os.environ.get('DENIED_ENDPOINT') == endpoint:
    print('fixture access denied', file=sys.stderr)
    sys.exit(1)
files = {'repos/craigbalding/safeyolo/releases/42': 'RELEASE_JSON',
         'repos/craigbalding/safeyolo/releases/assets/43': 'HOST_FILE',
         'repos/craigbalding/safeyolo/releases/assets/44': 'SUMS_FILE'}
sys.stdout.buffer.write(Path(os.environ[files[endpoint]]).read_bytes())
''')
    gh.chmod(0o755)
    env = {"RUNNER_TEMP": str(tmp_path), "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(tmp_path / "reports"),
           "HOST_RELEASE_ID": "42", "HOST_ARCHIVE_ASSET_ID": "43", "HOST_CHECKSUM_ASSET_ID": "44",
           "HOST_SHA256": sha, "HOST_BYTES": str(archive.stat().st_size),
           "PATH": f"{tools}:{os.environ['PATH']}", "GH_TOKEN": "fixture-token",
           "RELEASE_JSON": str(tmp_path / "release.json"), "HOST_FILE": str(archive),
           "SUMS_FILE": str(sums), "API_CALLS": str(tmp_path / "api-calls")}
    return metadata, env


@pytest.fixture
def transferred_host_inputs(tmp_path, host_inputs):
    metadata, env = host_inputs
    Path(env["RELEASE_JSON"]).write_text(json.dumps(metadata))
    result = execute("Read and bind the retained host inputs", tmp_path, env, HOST_JOB)
    assert result.returncode == 0, result.stdout + result.stderr
    runner_temp = tmp_path / "consumer runner $(unused)"
    received = runner_temp / "retained-host"
    received.mkdir(parents=True)
    # Upload preserves paths relative to their common root. The pinned download
    # action requires merge-multiple even for one ID to avoid a name subdirectory.
    download = step("Download the bound host inputs from this run")["with"]
    assert download["merge-multiple"] is True
    assert received == Path(download["path"].replace("${{ runner.temp }}", str(runner_temp)))
    for path in step("Transfer only bound host inputs", HOST_JOB)["with"]["path"].splitlines():
        source = Path(path.replace("${{ runner.temp }}", env["RUNNER_TEMP"]))
        shutil.copy2(source, received / source.name)
    return received, {**env, "RUNNER_TEMP": str(runner_temp), "GH_TOKEN": "",
                      "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(runner_temp / "reports")}


def test_report_binding_uses_admitted_context_and_reaches_writer_and_upload(tmp_path, host_inputs):
    # runner is unavailable in job.env. Runtime paths belong to a run step,
    # whose GITHUB_ENV assignment is supplied to subsequent steps by Actions.
    assert "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR" not in JOB["env"]
    assert "${{ runner." not in json.dumps(JOB["env"])
    assert "${{ runner." not in json.dumps(HOST)
    metadata, env = host_inputs
    runner_temp = tmp_path / "runner temp $(unused)"
    runner_temp.mkdir()
    env_file = tmp_path / "github-env"
    result = execute("Select the owned report directory", tmp_path, {
        "RUNNER_TEMP": str(runner_temp), "GITHUB_ENV": str(env_file),
    })
    assert result.returncode == 0, result.stdout + result.stderr
    key, value = env_file.read_text().strip().split("=", 1)
    assert key == "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"
    assert value == str(runner_temp / "installed-arm64-reports")
    Path(env["RELEASE_JSON"]).write_text(json.dumps(metadata))
    result = execute("Read and bind the retained host inputs", tmp_path, env, HOST_JOB)
    assert result.returncode == 0, result.stdout + result.stderr
    shutil.copytree(tmp_path / "retained-host", runner_temp / "retained-host")
    result = execute("Recheck the transferred host inputs before installation", tmp_path, {
        **env, "RUNNER_TEMP": str(runner_temp), key: value,
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert (Path(value) / "host-input.txt").is_file()
    assert JOB["steps"][-1]["with"]["path"] == "${{ env." + key + " }}"


@pytest.mark.parametrize("defect", [None, "release-denied", "asset-denied", "checksums-denied", "draft", "tag", "source",
                                  "missing", "duplicate", "uploading", "digest", "size", "checksum-file",
                                  "release-id", "asset-id", "release-shape", "asset-shape", "asset-name"])
def test_actual_published_acquisition_rejects_wrong_inputs_before_transfer(tmp_path, host_inputs, defect):
    metadata, env = host_inputs
    if defect in {"release-denied", "asset-denied", "checksums-denied"}:
        env["DENIED_ENDPOINT"] = "repos/craigbalding/safeyolo/releases/" + (
            {"release-denied": "42", "asset-denied": "assets/43", "checksums-denied": "assets/44"}[defect])
    elif defect == "draft":
        metadata["draft"] = True
    elif defect == "tag":
        metadata["tag_name"] = "other-host"
    elif defect == "source":
        metadata["target_commitish"] = "b" * 40
    elif defect == "release-id":
        metadata["id"] = "42"
    elif defect == "asset-id":
        metadata["assets"][0]["id"] = 99
    elif defect == "release-shape":
        metadata = []
    elif defect == "asset-shape":
        metadata["assets"] = None
    elif defect == "asset-name":
        metadata["assets"][0]["name"] = "safeyolo-linux-arm64-debug.tar.gz"
    elif defect == "missing":
        metadata["assets"] = []
    elif defect == "duplicate":
        metadata["assets"].append(metadata["assets"][0])
    elif defect == "uploading":
        metadata["assets"][0]["state"] = "new"
    elif defect == "digest":
        with Path(env["HOST_FILE"]).open("ab") as output:
            output.write(b"changed")
        env["HOST_BYTES"] = str(Path(env["HOST_FILE"]).stat().st_size)
    elif defect == "size":
        env["HOST_BYTES"] = "1"
    elif defect == "checksum-file":
        Path(env["SUMS_FILE"]).write_text("wrong checksum\n")
    Path(env["RELEASE_JSON"]).write_text(json.dumps(metadata))
    result = execute("Read and bind the retained host inputs", tmp_path, env, HOST_JOB)
    assert (result.returncode == 0) == (defect is None), result.stdout + result.stderr
    assert not (tmp_path / "retained-host/package-info").exists()
    calls = [json.loads(line) for line in Path(env["API_CALLS"]).read_text().splitlines()]
    assert all(call[0] == "api" and "--method" not in call for call in calls)
    assert "fixture-token" not in result.stdout + result.stderr
    if defect in {"release-denied", "asset-denied", "checksums-denied"}:
        assert "acquisition job token cannot" in result.stderr


@pytest.mark.parametrize("defect", [None, "missing-archive", "missing-checksums", "missing-metadata",
                                  "digest", "size", "checksum-file", "release-id", "asset-id", "source", "tag",
                                  "draft", "profile", "package-source", "platform", "compatibility"])
def test_read_only_consumer_refuses_missing_or_tampered_transfers(tmp_path, transferred_host_inputs, defect):
    received, env = transferred_host_inputs
    archive = received / "safeyolo-linux-arm64-production.tar.gz"
    metadata_file = received / "release.json"
    metadata = json.loads(metadata_file.read_text())
    if defect in {"missing-archive", "missing-checksums", "missing-metadata"}:
        (received / {"missing-archive": archive.name, "missing-checksums": "SHA256SUMS",
                     "missing-metadata": "release.json"}[defect]).unlink()
    elif defect == "digest":
        # Keep the size correct so the actual archive hash must reject it.
        content = archive.read_bytes()
        archive.write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
    elif defect == "size":
        archive.write_bytes(archive.read_bytes()[:-1])
    elif defect == "checksum-file":
        (received / "SHA256SUMS").write_text("wrong checksum\n")
    elif defect in {"release-id", "asset-id", "source", "tag", "draft"}:
        if defect == "asset-id":
            metadata["assets"][0]["id"] = 99
        else:
            key, value = {"release-id": ("id", 99), "source": ("target_commitish", "b" * 40),
                          "tag": ("tag_name", "other-host"), "draft": ("draft", True)}[defect]
            metadata[key] = value
        metadata_file.write_text(json.dumps(metadata))
    elif defect in {"profile", "package-source", "platform", "compatibility"}:
        info = tmp_path / "safeyolo-linux-arm64-production/package-info"
        before, after = {"profile": ("profile=production", "profile=debug"),
                         "package-source": (HOST["HOST_REVISION"], "b" * 40),
                         "platform": ("platform=linux-arm64", "platform=linux-amd64"),
                         "compatibility": ("guest_compatibility=v1", "guest_compatibility=v2")}[defect]
        info.write_text(info.read_text().replace(before, after))
        with tarfile.open(archive, "w:gz") as output:
            output.add(info.parent, arcname=info.parent.name)
        # Challenge package fields after supplying a self-consistent hash/size.
        env["HOST_SHA256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        env["HOST_BYTES"] = str(archive.stat().st_size)
        (received / "SHA256SUMS").write_text(f"{env['HOST_SHA256']}  {archive.name}\n")
    calls_before = Path(env["API_CALLS"]).read_text()
    result = execute("Recheck the transferred host inputs before installation", tmp_path, env)
    assert (result.returncode == 0) == (defect is None), result.stdout + result.stderr
    assert (Path(env["SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"]) / "host-input.txt").exists() == (defect is None)
    assert Path(env["API_CALLS"]).read_text() == calls_before
    assert "fixture-token" not in result.stdout + result.stderr
    if defect is None:
        assert {path.name for path in received.iterdir()} == {archive.name, "SHA256SUMS", "release.json", "package-info"}
        assert "Published release=42" in result.stdout and f"host_source={HOST['HOST_REVISION']}" in result.stdout
        assert all(b"fixture-token" not in path.read_bytes() for path in received.iterdir())


@pytest.fixture
def guest_inputs(tmp_path, linux_workflow_stat):
    verifier = Path(os.environ.get("SAFEYOLO_GUEST_OCI_VERIFIER", ROOT / "proxy/target/release/examples/verify_guest_oci")).resolve()
    if not verifier.is_file():
        pytest.skip("the existing native OCI verification tool is required")
    real_sudo = shutil.which("sudo")
    if not real_sudo or not shutil.which("zstd"):
        pytest.skip("guest sudo and zstd are required for the metadata control")
    # Small ownership/sparse controls need a filesystem that preserves numeric
    # IDs. Larger layout and test outputs remain on the disk-backed basetemp.
    with tempfile.TemporaryDirectory(prefix="arm64-archive-control-") as small:
        source = Path(small) / "source"
        tree = source / "rootfs-tree"
        (tree / "bin").mkdir(parents=True)
        (tree / "usr/local/bin").mkdir(parents=True)
        bash = tree / "bin/bash"
        bash.write_bytes(b"fixture executable\n")
        bash.chmod(0o751)
        (tree / "usr/local/bin/safeyolo-guest-init").symlink_to("../../../bin/bash")
        os.link(bash, tree / "hard")
        with (tree / "sparse").open("wb") as output:
            output.seek(1024 * 1024)
            output.write(b"x")
        sparse_observable = (tree / "sparse").stat().st_blocks * 512 < (tree / "sparse").stat().st_size // 4
        (source / "cache-paths.txt").write_text("/var/cache/apt\n")
        subprocess.run(["sudo", "-n", "chown", "-Rh", "100000:100000", str(tree)], check=True)
        try:
            raw = subprocess.check_output(["sudo", "-n", shutil.which("tar"), "--format=pax", "--sparse", "-C", str(source),
                                           "-cf", "-", "rootfs-tree", "cache-paths.txt"])
        finally:
            subprocess.run(["sudo", "-n", "chown", "-Rh", f"{os.getuid()}:{os.getgid()}", str(tree)], check=True)
        archive = subprocess.run(["zstd", "-q", "-c"], input=raw, capture_output=True, check=True).stdout
        contents = release(archive)
        index = json.loads(contents["manifests/compat-v1"])
        mac = next(item for item in index["manifests"] if item["platform"]["os"] == "darwin")
        child = json.loads(contents["manifests/" + mac["digest"]])
        # The native contract requires separate opaque Mac and Linux archives.
        mac_archive = b"distinct opaque Mac fixture"
        child["layers"][0].update(digest=digest(mac_archive), size=len(mac_archive))
        child_bytes = json.dumps(child).encode()
        mac.update(digest=digest(child_bytes), size=len(child_bytes))
        contents["blobs/" + digest(mac_archive)] = mac_archive
        contents["manifests/" + digest(child_bytes)] = child_bytes
        contents["manifests/compat-v1"] = json.dumps(index).encode()
        layout = tmp_path / "retained-guest-oci"
        blobs = layout / "blobs/sha256"
        blobs.mkdir(parents=True)
        for name, content in contents.items():
            if name.rsplit("/", 1)[1].startswith("sha256:"):
                (blobs / digest(content)[7:]).write_bytes(content)
        logical = contents["manifests/compat-v1"]
        index_digest = digest(logical)
        (blobs / index_digest[7:]).write_bytes(logical)
        # This deliberately is not the logical release index.
        (layout / "index.json").write_text('{"catalogue":"use the pinned logical digest"}')
        examples = tmp_path / "proxy/target/release/examples"
        examples.mkdir(parents=True)
        (examples / "verify_guest_oci").symlink_to(verifier)
        reports = tmp_path / "reports"
        reports.mkdir()
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "stat").symlink_to(linux_workflow_stat)
        sudo = tools / "sudo"
        sudo.write_text(f'#!/bin/bash\nif [[ "$2" != apt-get ]]; then exec "{real_sudo}" "$@"; fi\n')
        sudo.chmod(0o755)
        # Point the workflow's owned extraction directory at the small native
        # filesystem, while exercising its real GNU tar and stat commands.
        (tmp_path / "verified-extracted-assets").symlink_to(Path(small) / "extracted")
        env = {"RUNNER_TEMP": str(tmp_path), "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(reports),
               "GUEST_INDEX": index_digest, "GUEST_REVISION": "a" * 40,
               "GUEST_ARCHIVE_SHA256": digest(archive)[7:], "GUEST_ARCHIVE_BYTES": str(len(archive)),
               "SPARSE_OBSERVABLE": str(sparse_observable),
               "PATH": f"{tools}:{os.environ['PATH']}"}
        # mkdir on a dangling symlink would fail. The real workflow creates
        # this directory; a controlled mkdir supplies that same owned target.
        mkdir = tools / "mkdir"
        mkdir.write_text('#!/bin/bash\nif [[ "$1" == */verified-extracted-assets ]]; then mkdir_path=$(readlink "$1"); exec /bin/mkdir "$mkdir_path"; fi\nexec /bin/mkdir "$@"\n')
        mkdir.chmod(0o755)
        try:
            yield layout, env
        finally:
            extracted = Path(small) / "extracted"
            if extracted.exists():
                subprocess.run([real_sudo, "-n", "chown", "-Rh", f"{os.getuid()}:{os.getgid()}", str(extracted)], check=True)


@pytest.mark.parametrize("defect", [None, "index", "child", "config", "blob", "missing-blob", "missing-mac-archive",
                                  "source", "version", "compatibility", "selected-digest", "size"])
def test_logical_index_native_verification_and_actual_extraction(tmp_path, guest_inputs, defect):
    layout, env = guest_inputs
    blobs = layout / "blobs/sha256"
    index = json.loads((blobs / env["GUEST_INDEX"][7:]).read_bytes())
    child = next(item for item in index["manifests"] if item["platform"] == {"os": "linux", "architecture": "arm64"})
    manifest = json.loads((blobs / child["digest"][7:]).read_bytes())
    targets = {"index": env["GUEST_INDEX"], "child": child["digest"],
               "config": manifest["config"]["digest"], "blob": manifest["layers"][0]["digest"]}
    if defect in targets:
        with (blobs / targets[defect][7:]).open("ab") as output:
            output.write(b"changed")
    elif defect == "missing-blob":
        (blobs / manifest["layers"][0]["digest"][7:]).unlink()
    elif defect == "missing-mac-archive":
        mac = next(item for item in index["manifests"] if item["platform"]["os"] == "darwin")
        mac_manifest = json.loads((blobs / mac["digest"][7:]).read_bytes())
        (blobs / mac_manifest["layers"][0]["digest"][7:]).unlink()
    elif defect in {"source", "version", "compatibility", "selected-digest", "size"}:
        env[{"source": "GUEST_REVISION", "version": "GUEST_VERSION", "compatibility": "GUEST_COMPATIBILITY",
             "selected-digest": "GUEST_ARCHIVE_SHA256", "size": "GUEST_ARCHIVE_BYTES"}[defect]] = "wrong"
    result = execute("Verify the selected index and extract Linux ARM64 assets", tmp_path, env)
    assert (result.returncode == 0) == (defect is None), result.stdout + result.stderr
    extracted = tmp_path / "verified-extracted-assets"
    if defect is not None:
        assert not extracted.exists()
        if defect in {"config", "missing-mac-archive"}:
            verification = (tmp_path / "reports/guest-verification.txt").read_text()
            assert ("guest descriptor size mismatch" if defect == "config" else "No such file or directory") in verification
        return
    assert "verified linux/arm64" in result.stdout and "verified index=" in result.stdout
    tree = extracted / "rootfs-tree"
    assert tree.stat().st_uid == tree.stat().st_gid == 100000
    assert (tree / "bin/bash").stat().st_mode & 0o777 == 0o751
    assert (tree / "usr/local/bin/safeyolo-guest-init").is_symlink()
    assert (tree / "hard").stat().st_ino == (tree / "bin/bash").stat().st_ino
    sparse = tree / "sparse"
    assert sparse.read_bytes() == b"\0" * (1024 * 1024) + b"x"
    # gVisor reports fully allocated blocks even for seek-created holes. Check
    # physical allocation only where this test filesystem exposes it.
    if env["SPARSE_OBSERVABLE"] == "True":
        assert sparse.stat().st_blocks * 512 < sparse.stat().st_size // 4
    assert (extracted / "cache-paths.txt").read_text() == "/var/cache/apt\n"


@pytest.mark.parametrize("restricted,existing,failure,fixed", [
    (False, True, None, True), (False, False, None, True),
    (True, True, None, True), (True, False, None, True),
    (False, False, "usermod", True), (False, True, "runsc", True),
    (False, True, "unshare", True), (True, True, "aa-exec", True),
    (False, False, None, False), (True, False, None, False),
    (False, False, "collision-uid", True), (False, False, "collision-gid", True),
])
def test_shared_host_preparation_keeps_mapping_trust_and_namespace_failures(tmp_path, restricted, existing, failure, fixed):
    scripts = tmp_path / "tests/blackbox"
    scripts.mkdir(parents=True)
    template = tmp_path / "cli/src/safeyolo/templates"
    template.mkdir(parents=True)
    shutil.copy2(ROOT / "cli/src/safeyolo/templates/apparmor-safeyolo-runsc", template)
    helper = scripts / "prepare-systrap-host.sh"
    text = (ROOT / "tests/blackbox/prepare-systrap-host.sh").read_text()
    # Supply the helper's real OS-file reads without changing this test host.
    allocations = "fixture:100000:65536\n" if existing else "other:500000:65536\n"
    if not fixed:
        allocations = "packer:100000:65536\nfixture:165536:65536\n"
    contents = {
        "/etc/subuid": allocations,
        "/etc/subgid": allocations,
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1\n" if restricted else "0\n",
    }
    if failure in {"collision-uid", "collision-gid"}:
        contents["/etc/sub" + failure.removeprefix("collision-")] += "packer:100000:65536\n"
    for name, content in contents.items():
        path = tmp_path / Path(name).name
        path.write_text(content)
        text = text.replace(name, str(path))
    helper.write_text(text)
    tools = tmp_path / "tools"
    tools.mkdir()
    command = tools / "controlled-command"
    command.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
with Path(os.environ['COMMANDS']).open('a') as output:
    output.write(json.dumps([name, *args]) + '\\n')
if name == 'sudo':
    assert args.pop(0) == '-n'
    operation = args.pop(0)
    if operation == os.environ.get('FAILURE') or (os.environ.get('FAILURE') == 'runsc' and 'runsc' in args):
        sys.exit(9)
    if operation == 'usermod':
        path = Path(os.environ['RUNNER_TEMP']) / ('subuid' if args[0] == '--add-subuids' else 'subgid')
        with path.open('a') as output:
            output.write('fixture:100000:65536\\n')
    elif operation in {'gpg', 'tee'}:
        sys.stdin.read()
elif name == os.environ.get('FAILURE'):
    sys.exit(9)
elif name == 'curl':
    print('fixture public signing key')
elif name == 'dpkg':
    print('arm64')
elif name == 'getsubids':
    path = Path(os.environ['RUNNER_TEMP']) / ('subgid' if '-g' in args else 'subuid')
    for index, row in enumerate(path.read_text().splitlines()):
        owner, start, count = row.split(':')
        if owner == 'fixture':
            print(f'{index}: {owner} {start} {count}')
''')
    command.chmod(0o755)
    for name in ("sudo", "curl", "dpkg", "runsc", "tmux", "newuidmap", "newgidmap", "getsubids", "setfacl", "unshare", "aa-exec"):
        (tools / name).symlink_to(command)
    env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "RUNNER_TEMP": str(tmp_path),
           "USER": "fixture", "COMMANDS": str(tmp_path / "commands"), "FAILURE": failure or ""}
    result = subprocess.run(["bash", str(helper), *(["--fixed-rootfs-ids"] if fixed else [])],
                            env=env, text=True, capture_output=True, timeout=10)
    assert (result.returncode == 0) == (failure is None), result.stdout + result.stderr
    if failure in {"collision-uid", "collision-gid"}:
        assert "Retained host requires exclusive IDs 100000-165535" in result.stderr
        assert "allocation for packer overlaps" in result.stderr
        assert not (tmp_path / "commands").exists()
        for name in ("subuid", "subgid"):
            assert (tmp_path / name).read_text() == contents["/etc/" + name]
        return
    calls = [json.loads(line) for line in (tmp_path / "commands").read_text().splitlines()]
    assert bool([row for row in calls if "usermod" in row]) == (fixed and not existing)
    if not fixed:
        assert (tmp_path / "subuid").read_text() == (tmp_path / "subgid").read_text() == allocations
    if failure is None:
        assert ["curl", "-fsSL", "https://gvisor.dev/archive.key"] in calls
        assert ["sudo", "-n", "gpg", "--dearmor", "--yes", "-o", "/usr/share/keyrings/gvisor-archive-keyring.gpg"] in calls
        assert ["sudo", "-n", "apt-get", "install", "-y", "-qq", "--no-install-recommends", "runsc"] in calls
        assert (["aa-exec", "-p", "safeyolo-runsc", "--", "unshare", "-Urn", "true"] if restricted
                else ["unshare", "-Urn", "true"]) in calls
        if restricted:
            assert str(tools / "runsc") in (tmp_path / "safeyolo-runsc").read_text()


@pytest.mark.parametrize("lifecycle_only", [False, True])
@pytest.mark.parametrize("reduced", [False, True])
@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_installed_caller_retains_actual_output_and_failure(tmp_path, exit_code, reduced, lifecycle_only):
    scripts = tmp_path / "tests/blackbox"
    scripts.mkdir(parents=True)
    runner = scripts / "run-installed-package.sh"
    runner.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
from pathlib import Path
Path('arguments.json').write_text(json.dumps(sys.argv[1:]))
print('test_direct_egress PASSED')
print('test_home_persistence SKIPPED (fixture control)')
sys.exit(int(os.environ['SMOKE_EXIT']))
''')
    runner.chmod(0o755)
    reports = tmp_path / "reports"
    reports.mkdir()
    # This Ubuntu workflow uses Linux diagnostics before the controlled caller.
    # Model those commands on Darwin without changing the real lane/host guard.
    tools = tmp_path / "tools"
    tools.mkdir()
    for name, argument, output in (("uname", "-a", "Linux fixture arm64"),
                                   ("getconf", "GNU_LIBC_VERSION", "glibc fixture")):
        tool = tools / name
        tool.write_text(f'#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = "{argument}" ] || exit 9\nprintf "%s\\n" "{output}"\n')
        tool.chmod(0o755)
    result = execute("Run the installed production archive smoke", tmp_path, {
        "RUNNER_TEMP": str(tmp_path), "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(reports),
        "GITHUB_SHA": "c" * 40, "SMOKE_EXIT": str(exit_code),
        "GUEST_REVISION": "33224c9fc14beeb00be30eb71bdc09f91c5aa58b" if reduced else JOB["env"]["GUEST_REVISION"],
        "SECTION_SELECTION": "lifecycle" if lifecycle_only else "default",
        "PATH": f"{tools}:{os.environ['PATH']}",
    })
    assert result.returncode == exit_code, result.stdout + result.stderr
    sections = (["--section", "lifecycle"] if lifecycle_only else
                ["--section", "isolation", "--section", "workloads", "--section", "lifecycle"] if reduced else [])
    assert json.loads((tmp_path / "arguments.json").read_text()) == [
        "--package", str(tmp_path / "retained-host/safeyolo-linux-arm64-production.tar.gz"),
        "--sha256", HOST["HOST_SHA256"], "--platform-assets", str(tmp_path / "verified-extracted-assets"),
        "--lane", "systrap", "--yes",
    ] + sections
    output = (reports / "installed-smoke.txt").read_text()
    assert "test_direct_egress PASSED" in output and "test_home_persistence SKIPPED" in output


@pytest.mark.parametrize("failure", [None, "prepare", "remap-rootfs"])
def test_fresh_guest_mapping_uses_released_helpers_and_stops_on_failure(linux_workflow_stat, failure):
    real_sudo = shutil.which("sudo")
    if not real_sudo:
        pytest.skip("guest sudo is required for the archive ownership control")
    # Tiny inputs use a native filesystem so root ownership is enforced.
    with tempfile.TemporaryDirectory(prefix="arm64-mapping-control-") as small:
        tmp_path = Path(small)
        host = tmp_path / "retained-host"
        host.mkdir()
        bundle = tmp_path / "safeyolo-linux-arm64-production"
        (bundle / "bin").mkdir(parents=True)
        helper = bundle / "bin/safeyolo"
        helper.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
operation = args[3]
with Path(os.environ['CALLS']).open('a') as output:
    output.write(json.dumps(args) + '\\n')
if operation == os.environ.get('MAPPING_FAILURE'):
    sys.exit(1)
if operation == 'prepare':
    assert '--yes' in args and '--platform-assets' not in args
    Path(args[args.index('--write-settings') + 1]).write_text(
        '[linux]\\nuid_base=165536\\ngid_base=231072\\nhost_uid=1001\\nhost_gid=1001\\n')
    print('{"state":"prepared"}')
elif operation == 'remap-rootfs':
    tree = Path(args[4])
    assert tree.is_dir() and tree.parent.name.startswith('extract-')
    assert tree.parent.stat().st_mode & 0o777 == 0o700
    assert args[5:] == ['165536', '231072', '1001', '1001']
else:
    sys.exit(2)
    ''')
        helper.chmod(0o755)
        with tarfile.open(host / "safeyolo-linux-arm64-production.tar.gz", "w:gz") as output:
            output.add(bundle, arcname=bundle.name)
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "stat").symlink_to(linux_workflow_stat)
        sudo = tools / "sudo"
        sudo.write_text(
            '#!/bin/bash\n'
            + f'if [[ $2 == mv ]]; then exec {shlex.quote(real_sudo)} "$@"; fi\n'
            + '[[ $1 == -n ]] || exit 9\nshift\nexec "$@"\n'
        )
        sudo.chmod(0o755)
        assets = tmp_path / "verified-extracted-assets"
        (assets / "rootfs-tree").mkdir(parents=True)
        (assets / "rootfs-tree/marker").write_text('owned fresh tree')
        (assets / "cache-paths.txt").write_text('/var/cache/apt\n')
        reports = tmp_path / "reports"
        reports.mkdir()
        calls = tmp_path / "calls"
        subprocess.run([real_sudo, "-n", "chown", "100000:100000", str(assets / "rootfs-tree")], check=True)
        try:
            result = execute("Prepare the fresh guest for this host account", tmp_path, {
                "RUNNER_TEMP": str(tmp_path), "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(reports),
                "PATH": f"{tools}:{os.environ['PATH']}", "CALLS": str(calls),
                "MAPPING_FAILURE": failure or "",
            })
        finally:
            trees = [assets / "rootfs-tree", *tmp_path.glob("extract-*/rootfs-tree")]
            for tree in trees:
                if tree.exists():
                    subprocess.run([real_sudo, "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(tree)], check=True)
        assert (result.returncode == 0) == (failure is None), result.stdout + result.stderr
        operations = [json.loads(line)[3] for line in calls.read_text().splitlines()]
        assert operations == (["prepare"] if failure == "prepare" else ["prepare", "remap-rootfs"])
        assert (reports / "mapped-guest-metadata.txt").exists() == (failure is None)
        assert (assets / "cache-paths.txt").read_text() == '/var/cache/apt\n'
        if failure != "remap-rootfs":
            assert (assets / "rootfs-tree/marker").read_text() == 'owned fresh tree'
        else:
            assert not (assets / "rootfs-tree").exists()
            assert len(list(tmp_path.glob('extract-*/rootfs-tree/marker'))) == 1


@pytest.mark.parametrize("failure,exit_code", [(None, 0), *[
    (suite, code) for suite in ("identity", "guest", "guest-root", "lifecycle") for code in (1, 2)
]])
def test_maintained_isolation_caller_requests_individual_guest_root_and_home_outcomes(tmp_path, failure, exit_code):
    runner = (ROOT / "tests/blackbox/run-tests.sh").read_text()
    phase = runner[runner.index("# --- Phase 2: Run tests ---"):]
    (tmp_path / "host").mkdir()
    capture = tmp_path / "pytest-calls.jsonl"
    record = (
        "import json,os,sys; from pathlib import Path; args=sys.argv[2:]; "
        "Path(sys.argv[1]).open('a').write(json.dumps(args)+'\\n'); "
        "suite=('guest-root' if '--user' in args else 'guest') if args[0].endswith('guest_exec.py') "
        "else 'identity' if 'identity/' in args else 'lifecycle'; "
        "sys.exit(int(os.environ['SUITE_EXIT']) if suite==os.environ['FAIL_SUITE'] else 0)"
    )
    command = " ".join(map(shlex.quote, [sys.executable, "-c", record, str(capture)]))
    probe = tmp_path / "isolation-caller.sh"
    probe.write_text(
        "set -euo pipefail\nRUN_PROXY=false\nRUN_ISOLATION=true\nLISTENER_RESTART=false\nVERBOSE=\n"
        "PYTEST_FORWARD_ARGS=()\nPYTEST_FORWARD_SHELL=\nINSTALLED_CLI=installed-cli\nAGENT_NAME=bbtest\n"
        + f"SCRIPT_DIR={shlex.quote(str(tmp_path))}\n"
        + f'python3() {{ {command} "$@"; }}\n'
        + f'pytest() {{ {command} pytest "$@"; }}\n'
        + phase
    )
    result = subprocess.run(["bash", str(probe)], capture_output=True, text=True, timeout=10,
                            env={**os.environ, "FAIL_SUITE": failure or "", "SUITE_EXIT": str(exit_code)})
    assert result.returncode == exit_code, result.stdout + result.stderr
    calls = [json.loads(line) for line in capture.read_text().splitlines()]
    guest = [call for call in calls if call[0].endswith("guest_exec.py")]
    assert len(guest) == 2 and "--user" in guest[1]
    for call in guest:
        args = shlex.split(call[-1])
        assert "-v" in args and "-rs" in args
    home = next(call for call in calls if "lifecycle/" in call)
    assert "-v" in home and "-rs" in home
