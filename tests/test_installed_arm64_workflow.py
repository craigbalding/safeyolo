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


def step(name):
    return next(item for item in JOB["steps"] if item.get("name") == name)


def execute(name, cwd, env):
    selected = step(name)
    workflow_shell = WORKFLOW.get("defaults", {}).get("run", {}).get("shell")
    job_shell = JOB.get("defaults", {}).get("run", {}).get("shell", workflow_shell)
    shell = selected.get("shell", job_shell)
    # Match GitHub's Ubuntu shell templates. An unspecified shell lacks
    # pipefail; explicit Bash uses --noprofile --norc -eo pipefail.
    command = ["bash", "-e"] if shell is None else ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
    if shell not in {None, "bash"}:
        raise ValueError(f"unsupported workflow shell: {shell}")
    script = cwd / "workflow-step.sh"
    script.write_text(selected["run"])
    return subprocess.run([*command, str(script)],
                          cwd=cwd, env={**os.environ, **JOB["env"], **env},
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


def test_manual_route_preserves_source_jobs_and_pins_read_only_inputs():
    assert set(WORKFLOW.get("on", WORKFLOW.get(True))) == {"workflow_dispatch"}
    assert JOB["if"] == "github.event_name == 'workflow_dispatch'"
    assert JOB["runs-on"] == "ubuntu-24.04-arm" and "needs" not in JOB
    assert JOB["permissions"] == {"contents": "read", "actions": "read"}
    checkout = next(item for item in JOB["steps"] if item.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"] == {"persist-credentials": False}
    assert JOB["env"]["HOST_REVISION"] == "7a38dff14e7e4eacb4095da732ffe06d7c7c5796"
    assert JOB["env"]["HOST_RELEASE_ID"] == "410991309"
    assert JOB["env"]["HOST_ARCHIVE_ASSET_ID"] == "634976985"
    assert JOB["env"]["HOST_CHECKSUM_ASSET_ID"] == "634976991"
    assert JOB["env"]["HOST_SHA256"] == "8f8bcb426762aecab725547d4e3df73b7d577afbdcca2e7302f7344ec067c88f"
    assert JOB["env"]["GUEST_REVISION"] == "8234a047d810d543d8c4d1cb1fa9859987be035b"
    assert JOB["env"]["GUEST_INDEX"] == "sha256:df0068692909088a90db2c8f9777807404e3b7d8061ee72bc94a5feabd7dc46e"
    assert JOB["env"]["GUEST_ARCHIVE_SHA256"] == "2899415b6f4ec2eb3ab2ad3a6ef05c7cc5b9b2de14f9c623ff22b2478c8cb6f5"
    downloads = [item for item in JOB["steps"] if item.get("uses", "").startswith("actions/download-artifact@")]
    assert len(downloads) == 1
    assert downloads[0]["with"] == {
        "artifact-ids": "11747551391", "run-id": 38248401312,
        "repository": "craigbalding/safeyolo", "github-token": "${{ secrets.GITHUB_TOKEN }}",
        "merge-multiple": True, "path": "${{ runner.temp }}/retained-guest-oci",
    }
    commands = "\n".join(item.get("run", "") for item in JOB["steps"])
    assert "--example verify_guest_oci" in commands and "--bin " not in commands
    assert "guest/build" not in commands and "publish_guest" not in commands
    assert "--lane systrap" in commands and "--platform-assets" in commands
    upload = JOB["steps"][-1]
    assert upload["if"] == "always()" and upload["with"]["path"] == "${{ env.SAFEYOLO_BLACKBOX_ARTIFACTS_DIR }}"
    nightly = yaml.safe_load((ROOT / ".github/workflows/blackbox.yml").read_text())
    assert nightly.get("on", nightly.get(True))["workflow_dispatch"] is None
    assert set(nightly["jobs"]) == {"guest-inputs", "systrap", "macos-package"}
    assert all("if" not in job for job in nightly["jobs"].values())
    preparation = step("Prepare the supported systrap host")["run"]
    assert preparation in [item.get("run") for item in nightly["jobs"]["systrap"]["steps"]]


@pytest.fixture
def host_inputs(tmp_path):
    bundle = tmp_path / "safeyolo-linux-arm64-production"
    bundle.mkdir()
    (bundle / "package-info").write_text(
        f"source_commit={JOB['env']['HOST_REVISION']}\nprofile=production\nplatform=linux-arm64\nguest_compatibility=v1\n"
    )
    archive = tmp_path / "fixture-host.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        output.add(bundle, arcname=bundle.name)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(f"{sha}  safeyolo-linux-arm64-production.tar.gz\n")
    metadata = {
        "id": 42, "draft": True, "tag_name": "host-" + JOB["env"]["HOST_REVISION"],
        "target_commitish": JOB["env"]["HOST_REVISION"],
        "assets": [{"id": 43, "name": "safeyolo-linux-arm64-production.tar.gz", "state": "uploaded"},
                   {"id": 44, "name": "SHA256SUMS", "state": "uploaded"}],
    }
    tools = tmp_path / "tools"
    tools.mkdir()
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


def test_report_binding_uses_admitted_context_and_reaches_writer_and_upload(tmp_path, host_inputs):
    # runner is unavailable in job.env. Runtime paths belong to a run step,
    # whose GITHUB_ENV assignment is supplied to subsequent steps by Actions.
    assert "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR" not in JOB["env"]
    assert "${{ runner." not in json.dumps(JOB["env"])
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
    result = execute("Read and verify the retained host archive", tmp_path, {
        **env, "RUNNER_TEMP": str(runner_temp), key: value,
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert (Path(value) / "host-input.txt").is_file()
    assert JOB["steps"][-1]["with"]["path"] == "${{ env." + key + " }}"


@pytest.mark.parametrize("defect", [None, "release-denied", "asset-denied", "public", "tag", "source",
                                  "missing", "duplicate", "uploading", "digest", "size", "checksum-file", "profile",
                                  "release-id", "asset-id", "release-shape", "asset-shape", "asset-name"])
def test_actual_draft_consumer_rejects_wrong_inputs_before_install(tmp_path, host_inputs, defect):
    metadata, env = host_inputs
    if defect in {"release-denied", "asset-denied"}:
        env["DENIED_ENDPOINT"] = "repos/craigbalding/safeyolo/releases/" + (
            "42" if defect == "release-denied" else "assets/43")
    elif defect == "public":
        metadata["draft"] = False
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
    elif defect == "profile":
        bundle = tmp_path / "safeyolo-linux-arm64-production"
        info = bundle / "package-info"
        info.write_text(info.read_text().replace("profile=production", "profile=debug"))
        with tarfile.open(env["HOST_FILE"], "w:gz") as output:
            output.add(bundle, arcname=bundle.name)
        env["HOST_SHA256"] = hashlib.sha256(Path(env["HOST_FILE"]).read_bytes()).hexdigest()
        env["HOST_BYTES"] = str(Path(env["HOST_FILE"]).stat().st_size)
        Path(env["SUMS_FILE"]).write_text(f"{env['HOST_SHA256']}  safeyolo-linux-arm64-production.tar.gz\n")
    Path(env["RELEASE_JSON"]).write_text(json.dumps(metadata))
    result = execute("Read and verify the retained host archive", tmp_path, env)
    assert (result.returncode == 0) == (defect is None), result.stdout + result.stderr
    assert (tmp_path / "reports/host-input.txt").exists() == (defect is None)
    calls = [json.loads(line) for line in Path(env["API_CALLS"]).read_text().splitlines()]
    assert all(call[0] == "api" and "--method" not in call for call in calls)
    assert "fixture-token" not in result.stdout + result.stderr
    if defect in {"release-denied", "asset-denied"}:
        assert "job read token cannot" in result.stderr


@pytest.fixture
def guest_inputs(tmp_path):
    verifier = Path(os.environ.get("SAFEYOLO_GUEST_OCI_VERIFIER", ROOT / "proxy/target/debug/examples/verify_guest_oci")).resolve()
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
            raw = subprocess.check_output(["sudo", "-n", "tar", "--format=pax", "--sparse", "-C", str(source),
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
        examples = tmp_path / "proxy/target/debug/examples"
        examples.mkdir(parents=True)
        (examples / "verify_guest_oci").symlink_to(verifier)
        reports = tmp_path / "reports"
        reports.mkdir()
        tools = tmp_path / "tools"
        tools.mkdir()
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
    result = execute("Verify the logical G1 index and extract Linux ARM64 assets", tmp_path, env)
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


@pytest.mark.parametrize("restricted,existing,failure", [
    (False, True, None), (False, False, None), (True, True, None), (True, False, None),
    (False, False, "usermod"), (False, True, "runsc"),
    (False, True, "unshare"), (True, True, "aa-exec"),
])
def test_shared_host_preparation_keeps_mapping_trust_and_namespace_failures(tmp_path, restricted, existing, failure):
    scripts = tmp_path / "tests/blackbox"
    scripts.mkdir(parents=True)
    template = tmp_path / "cli/src/safeyolo/templates"
    template.mkdir(parents=True)
    shutil.copy2(ROOT / "cli/src/safeyolo/templates/apparmor-safeyolo-runsc", template)
    helper = scripts / "prepare-systrap-host.sh"
    text = (ROOT / "tests/blackbox/prepare-systrap-host.sh").read_text()
    # Supply the helper's real OS-file reads without changing this test host.
    for name, content in {
        "/etc/subuid": "fixture:100000:65536\n" if existing else "other:200000:65536\n",
        "/etc/subgid": "fixture:100000:65536\n" if existing else "other:200000:65536\n",
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1\n" if restricted else "0\n",
    }.items():
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
''')
    command.chmod(0o755)
    for name in ("sudo", "curl", "dpkg", "runsc", "tmux", "newuidmap", "newgidmap", "setfacl", "unshare", "aa-exec"):
        (tools / name).symlink_to(command)
    env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "RUNNER_TEMP": str(tmp_path),
           "USER": "fixture", "COMMANDS": str(tmp_path / "commands"), "FAILURE": failure or ""}
    result = subprocess.run(["bash", str(helper)], env=env, text=True, capture_output=True, timeout=10)
    assert (result.returncode == 0) == (failure is None), result.stdout + result.stderr
    calls = [json.loads(line) for line in (tmp_path / "commands").read_text().splitlines()]
    assert bool([row for row in calls if "usermod" in row]) == (not existing)
    if failure is None:
        assert ["curl", "-fsSL", "https://gvisor.dev/archive.key"] in calls
        assert ["sudo", "-n", "gpg", "--dearmor", "--yes", "-o", "/usr/share/keyrings/gvisor-archive-keyring.gpg"] in calls
        assert ["sudo", "-n", "apt-get", "install", "-y", "-qq", "--no-install-recommends", "runsc"] in calls
        assert (["aa-exec", "-p", "safeyolo-runsc", "--", "unshare", "-Urn", "true"] if restricted
                else ["unshare", "-Urn", "true"]) in calls
        if restricted:
            assert str(tools / "runsc") in (tmp_path / "safeyolo-runsc").read_text()


@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_installed_caller_retains_actual_output_and_failure(tmp_path, exit_code):
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
    result = execute("Run the installed production archive smoke", tmp_path, {
        "RUNNER_TEMP": str(tmp_path), "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(reports),
        "GITHUB_SHA": "c" * 40, "SMOKE_EXIT": str(exit_code),
    })
    assert result.returncode == exit_code, result.stdout + result.stderr
    assert json.loads((tmp_path / "arguments.json").read_text()) == [
        "--package", str(tmp_path / "retained-host/safeyolo-linux-arm64-production.tar.gz"),
        "--sha256", JOB["env"]["HOST_SHA256"], "--platform-assets", str(tmp_path / "verified-extracted-assets"),
        "--lane", "systrap",
    ]
    output = (reports / "installed-smoke.txt").read_text()
    assert "test_direct_egress PASSED" in output and "test_home_persistence SKIPPED" in output


def test_maintained_isolation_caller_requests_individual_guest_root_and_home_outcomes(tmp_path):
    runner = (ROOT / "tests/blackbox/run-tests.sh").read_text()
    phase = runner[runner.index("# --- Phase 2: Run tests ---"):runner.index("# --- Phase 3: Summary ---")]
    (tmp_path / "host").mkdir()
    capture = tmp_path / "pytest-calls.jsonl"
    record = "import json,sys; from pathlib import Path; p=Path(sys.argv[1]); p.open('a').write(json.dumps(sys.argv[2:])+'\\n')"
    command = " ".join(map(shlex.quote, [sys.executable, "-c", record, str(capture)]))
    probe = tmp_path / "isolation-caller.sh"
    probe.write_text(
        "set -euo pipefail\nRUN_PROXY=false\nRUN_ISOLATION=true\nVERBOSE=\n"
        "PYTEST_FORWARD_ARGS=()\nPYTEST_FORWARD_SHELL=\nINSTALLED_CLI=installed-cli\nAGENT_NAME=bbtest\n"
        + f"SCRIPT_DIR={shlex.quote(str(tmp_path))}\n"
        + f'python3() {{ {command} "$@"; }}\n'
        + f'pytest() {{ {command} pytest "$@"; }}\n'
        + phase
    )
    subprocess.run(["bash", str(probe)], check=True, capture_output=True, timeout=10)
    calls = [json.loads(line) for line in capture.read_text().splitlines()]
    guest = [call for call in calls if call[0].endswith("guest_exec.py")]
    assert len(guest) == 2 and "--user" in guest[1]
    for call in guest:
        args = shlex.split(call[-1])
        assert "-v" in args and "-rs" in args
    home = next(call for call in calls if "lifecycle/" in call)
    assert "-v" in home and "-rs" in home
