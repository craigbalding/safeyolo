"""Exercise the maintained archive producer and actual ORAS publication boundary."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REVISION = "a" * 40
BASE = "docker.io/library/debian@sha256:" + "b" * 64


def run(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


@pytest.fixture
def archive_tools():
    if not all(shutil.which(tool) for tool in ("tar", "zstd", "sudo")):
        pytest.skip("GNU tar, zstd and guest sudo are required")
    if run("sudo", "-n", "true").returncode:
        pytest.skip("guest sudo is unavailable")
    assert "GNU tar" in run("tar", "--version").stdout, "put GNU tar on PATH for archive fixtures"


@pytest.fixture
def publisher_tools():
    oras = os.environ.get("ORAS", shutil.which("oras"))
    verifier = os.environ.get("GUEST_OCI_VERIFIER")
    if not oras or not verifier:
        pytest.skip("set ORAS to pinned 1.3.4 and GUEST_OCI_VERIFIER to the native example")
    assert "Version:        1.3.4" in run(oras, "version").stdout
    assert Path(verifier).is_file()
    return oras, verifier


def archive(platform, source, destination):
    result = run(str(ROOT / "guest/archive-default.sh"), platform, str(source), str(destination))
    assert result.returncode == 0, result.stderr
    return destination / "guest.tar.zst"


@pytest.fixture
def built(tmp_path, archive_tools):
    source = tmp_path / "built"
    source.mkdir()
    (source / "build-base.txt").write_text(BASE + "\n")
    tree = source / "rootfs-tree"
    tree.mkdir(mode=0o751)
    (tree / "command").write_text("guest command\n")
    (tree / "command").chmod(0o751)
    (tree / "private").write_text("private\n")
    (tree / "private").chmod(0o600)
    (tree / "symbolic").symlink_to("command")
    os.link(tree / "command", tree / "hard")
    (source / "cache-paths.txt").write_text("/var/cache/apt\n/var/lib/apt/lists\n")
    (source / "Image").write_bytes(b"kernel fixture")
    (source / "initramfs.cpio.gz").write_bytes(b"initramfs fixture")
    with (source / "rootfs-base.ext4").open("wb") as image:
        image.seek(1024 * 1024 - 1)
        image.write(b"x")
    return source


def test_archive_preserves_numeric_owners_modes_links_and_cache_paths(tmp_path, built):
    # Only a few KiB of metadata fixtures use /tmp. SafeYolo's persistent 9p
    # mounts report the caller's UID even after chown; the guest filesystem
    # preserves numeric ownership. Archives and all publisher data stay on disk.
    with tempfile.TemporaryDirectory(prefix="guest-oci-owners-") as temporary:
        source = Path(temporary) / "built"
        source.mkdir()
        tree = source / "rootfs-tree"
        shutil.copytree(built / "rootfs-tree", tree, symlinks=True)
        (tree / "hard").unlink()
        os.link(tree / "command", tree / "hard")
        for file in ("cache-paths.txt", "build-base.txt"):
            shutil.copyfile(built / file, source / file)
        extracted = Path(temporary) / "extracted"
        extracted.mkdir()
        assert run("sudo", "-n", "chown", "-Rh", "100000:100000", str(tree)).returncode == 0
        assert tree.stat().st_uid == 100000
        try:
            output = archive("linux/arm64", source, tmp_path / "archive")
            result = run("sudo", "-n", shutil.which("tar"), "--zstd", "--numeric-owner", "--same-owner", "--same-permissions",
                         "-xf", str(output), "-C", str(extracted))
            assert result.returncode == 0, result.stderr
            for file in ("rootfs-tree", "rootfs-tree/command", "rootfs-tree/private", "rootfs-tree/symbolic"):
                assert (extracted / file).lstat().st_uid == 100000
                assert (extracted / file).lstat().st_gid == 100000
            assert (extracted / "rootfs-tree/command").stat().st_mode & 0o777 == 0o751
            assert (extracted / "rootfs-tree/private").stat().st_mode & 0o777 == 0o600
            assert (extracted / "rootfs-tree/symbolic").readlink() == Path("command")
            assert (extracted / "rootfs-tree/command").stat().st_ino == (extracted / "rootfs-tree/hard").stat().st_ino
            assert (extracted / "cache-paths.txt").read_bytes() == (built / "cache-paths.txt").read_bytes()
            assert sorted(path.name for path in extracted.iterdir()) == ["cache-paths.txt", "rootfs-tree"]
            first = output.read_bytes()
            assert archive("linux/arm64", source, tmp_path / "retry").read_bytes() == first
        finally:
            for directory in (tree, extracted):
                assert run("sudo", "-n", "chown", "-Rh", f"{os.getuid()}:{os.getgid()}", str(directory)).returncode == 0


def test_archive_contains_finished_mac_files(tmp_path, built):
    output = archive("darwin/arm64", built, tmp_path / "archive")
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    assert run("tar", "--zstd", "-xf", str(output), "-C", str(extracted)).returncode == 0
    image = extracted / "rootfs-base.ext4"
    assert image.read_bytes() == (built / "rootfs-base.ext4").read_bytes()
    assert sorted(path.name for path in extracted.iterdir()) == ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]
    assert output.stat().st_size < 8192


def test_sparse_map_on_a_filesystem_reporting_holes(tmp_path, built):
    image = built / "rootfs-base.ext4"
    if image.stat().st_blocks * 512 >= image.stat().st_size // 4:
        pytest.skip("filesystem reports sparse fixture as fully allocated; sparse-map witness requires native filesystem")
    output = archive("darwin/arm64", built, tmp_path / "archive")
    raw = subprocess.check_output(["zstd", "-d", "-q", "-c", str(output)])
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        member = tar.getmember("rootfs-base.ext4")
        assert member.sparse and any(offset > 0 for offset, _ in member.sparse)
        assert len(raw) < member.size // 4


@pytest.mark.parametrize("missing", ["cache-paths.txt", "build-base.txt"])
def test_archive_refuses_missing_required_output(tmp_path, built, missing):
    (built / missing).unlink()
    result = run(str(ROOT / "guest/archive-default.sh"), "linux/amd64", str(built), str(tmp_path / "out"))
    assert result.returncode != 0
    assert not (tmp_path / "out/guest.tar.zst").exists()


@pytest.fixture
def artifacts(tmp_path, built):
    directory = tmp_path / "artifacts"
    for platform in ("darwin/arm64", "linux/amd64", "linux/arm64"):
        # Distinct architecture content represents independent builder outputs.
        (built / "rootfs-tree/command").write_text(platform)
        archive(platform, built, directory / platform.replace("/", "-"))
    return directory


@pytest.fixture
def registry():
    """Disposable Distribution API store: ORAS supplies all OCI objects and transfer."""
    blobs, manifests, tags, uploads, events = {}, {}, {}, {}, []
    faults = {"blob": False, "index": False}

    class Registry(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            return

        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                # ORAS closes a transfer when a deliberate corrupt readback
                # fails its digest check; that client disconnect is expected.
                return

        def reply(self, status, data=b"", **headers):
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            for key, value in headers.items():
                self.send_header(key.replace("_", "-"), value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def dispatch(self):
            request = urlsplit(self.path)
            path = request.path
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            events.append((self.command, path))
            if path in ("/v2/", "/v2"):
                return self.reply(200, b"{}")
            if path.endswith("/tags/list"):
                return self.reply(200, json.dumps({"name": "guest", "tags": list(tags)}).encode(),
                                  Content_Type="application/json")
            if "/blobs/uploads" in path:
                if self.command == "POST":
                    token = str(len(uploads))
                    uploads[token] = body
                    return self.reply(202, Location=f"/v2/guest/blobs/uploads/{token}", Docker_Upload_UUID=token)
                token = path.rsplit("/", 1)[1]
                uploads[token] += body
                if self.command == "PATCH":
                    return self.reply(202, Location=path, Docker_Upload_UUID=token)
                digest = parse_qs(request.query)["digest"][0]
                assert digest == "sha256:" + hashlib.sha256(uploads[token]).hexdigest()
                blobs[digest] = uploads[token]
                return self.reply(201, Location=f"/v2/guest/blobs/{digest}", Docker_Content_Digest=digest)
            if "/blobs/" in path:
                digest = path.rsplit("/", 1)[1]
                if digest not in blobs:
                    return self.reply(404)
                data = blobs[digest]
                if faults["blob"] and self.command == "GET":
                    data = b"!" + data[1:]
                return self.reply(200, data, Content_Type="application/octet-stream", Docker_Content_Digest=digest)
            if "/manifests/" in path:
                reference = path.rsplit("/", 1)[1]
                if self.command == "PUT":
                    digest = "sha256:" + hashlib.sha256(body).hexdigest()
                    manifests[digest] = body
                    if not reference.startswith("sha256:"):
                        tags[reference] = digest
                    return self.reply(201, Location=path, Docker_Content_Digest=digest)
                digest = tags.get(reference, reference)
                if digest not in manifests:
                    return self.reply(404)
                data = manifests[digest]
                if faults["index"] and self.command == "GET" and "manifests" in json.loads(data):
                    data = b" " + data
                return self.reply(200, data, Content_Type=json.loads(data)["mediaType"], Docker_Content_Digest=digest)
            return self.reply(404)

        do_GET = do_HEAD = do_POST = do_PATCH = do_PUT = dispatch

    server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_port}/guest", blobs, manifests, tags, events, faults
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def publish(tmp_path, artifacts, publisher_tools, repository=None, version="guest-2026-10-12.1", compatibility="v1", revision=REVISION):
    oras, verifier = publisher_tools
    args = [str(ROOT / "scripts/publish_guest_oci.sh"), "--artifacts", str(artifacts),
            "--layout", str(tmp_path / f"layout-{version}"), "--version", version,
            "--compatibility", compatibility, "--revision", revision, "--verifier", verifier]
    if repository:
        args += ["--publish", repository, "--plain-http"]
    return run(*args, env={**os.environ, "ORAS": oras}, timeout=30)


def test_actual_oras_local_release_and_no_registry_writes(tmp_path, artifacts, publisher_tools, registry):
    result = publish(tmp_path, artifacts, publisher_tools)
    assert result.returncode == 0, result.stderr
    assert all(f"verified {platform}" in result.stdout for platform in ("darwin/arm64", "linux/amd64", "linux/arm64"))
    assert not registry[4]


def test_actual_oras_publication_retry_versions_and_generations(tmp_path, artifacts, publisher_tools, registry):
    repository, _, manifests, tags, events, _ = registry
    first = publish(tmp_path, artifacts, publisher_tools, repository)
    assert first.returncode == 0, first.stderr
    g1 = tags["guest-2026-10-12.1"]
    assert tags["compat-v1"] == g1
    first_events = list(events)
    compatibility_put = first_events.index(("PUT", "/v2/guest/manifests/compat-v1"))
    version_put = first_events.index(("PUT", "/v2/guest/manifests/guest-2026-10-12.1"))
    index_put = first_events.index(("PUT", f"/v2/guest/manifests/{g1}"))
    assert index_put < version_put < compatibility_put
    index = json.loads(manifests[g1])
    for child_descriptor in index["manifests"]:
        child_digest = child_descriptor["digest"]
        assert first_events.index(("GET", f"/v2/guest/manifests/{child_digest}")) < index_put
        child = json.loads(manifests[child_digest])
        for descriptor in [child["config"], *child["layers"]]:
            assert first_events.index(("GET", f"/v2/guest/blobs/{descriptor['digest']}")) < index_put
    retry = publish(tmp_path, artifacts, publisher_tools, repository)
    assert retry.returncode == 0, retry.stderr
    assert tags["guest-2026-10-12.1"] == g1
    prior_tags = dict(tags)
    conflict = publish(tmp_path, artifacts, publisher_tools, repository, revision="c" * 40)
    assert conflict.returncode != 0 and "Immutable guest version conflict" in conflict.stderr
    assert tags == prior_tags
    g2_result = publish(tmp_path, artifacts, publisher_tools, repository, version="guest-2026-10-12.2")
    assert g2_result.returncode == 0, g2_result.stderr
    g2 = tags["guest-2026-10-12.2"]
    assert g2 != g1 and tags["compat-v1"] == g2
    incompatible = publish(tmp_path, artifacts, publisher_tools, repository,
                           version="guest-2026-10-12.3", compatibility="v2")
    assert incompatible.returncode == 0, incompatible.stderr
    assert tags["compat-v1"] == g2
    assert tags["compat-v2"] == tags["guest-2026-10-12.3"]
    assert tags["guest-2026-10-12.1"] == g1 and g1 in manifests


@pytest.mark.parametrize("fault", ["blob", "index"])
def test_corrupt_readback_does_not_promote(tmp_path, artifacts, publisher_tools, registry, fault):
    repository, _, _, tags, _, faults = registry
    first = publish(tmp_path, artifacts, publisher_tools, repository)
    assert first.returncode == 0, first.stderr
    prior_tags = dict(tags)
    faults[fault] = True
    result = publish(tmp_path, artifacts, publisher_tools, repository, version="guest-2026-10-12.2")
    assert result.returncode != 0
    assert tags == prior_tags


@pytest.mark.parametrize("defect", ["incomplete", "same-arm", "unpinned", "bad-compatibility"])
def test_invalid_release_refused_before_upload(tmp_path, artifacts, publisher_tools, registry, defect):
    if defect == "incomplete":
        shutil.rmtree(artifacts / "linux-amd64")
    elif defect == "same-arm":
        shutil.copyfile(artifacts / "linux-arm64/guest.tar.zst", artifacts / "darwin-arm64/guest.tar.zst")
    elif defect == "unpinned":
        (artifacts / "linux-arm64/build-base.txt").write_text("docker.io/library/debian:trixie")
    result = publish(tmp_path, artifacts, publisher_tools, registry[0],
                     compatibility="invalid/compat" if defect == "bad-compatibility" else "v1")
    assert result.returncode != 0
    assert not registry[4]


@pytest.fixture(params=["g1", "g2"])
def retained_publisher(request, tmp_path):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    job = workflow["jobs"]["publish"]
    inputs = {
        "PUBLISH_INITIAL_G1": str(request.param == "g1").lower(),
        "PUBLISH_RETAINED_G2": str(request.param == "g2").lower(),
        "REQUESTED_VERSION": "guest-2026-10-12.1" if request.param == "g1" else "guest-2026-10-16.1",
        "REQUESTED_COMPATIBILITY": "v1",
    }
    env_file = tmp_path / "selected-release"
    result = run("bash", "-euo", "pipefail", "-c", job["steps"][0]["run"], cwd=tmp_path,
                 env={**os.environ, **inputs, "GITHUB_SHA": REVISION, "GITHUB_ENV": str(env_file)})
    assert result.returncode == 0, result.stderr
    env = dict(line.split("=", 1) for line in env_file.read_text().splitlines())
    return SimpleNamespace(job=job, env=env, inputs=inputs, generation=request.param)


@pytest.mark.parametrize("event", ["workflow_dispatch", "push", "release", "schedule", "pull_request"])
@pytest.mark.parametrize("initial", [None, False, True])
@pytest.mark.parametrize("retained", [None, False, True])
def test_workflow_retained_publication_routing(event, initial, retained):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    inputs = workflow.get("on", workflow.get(True))["workflow_dispatch"]["inputs"]
    assert inputs["publish_initial_g1"] == {
        "description": "Publish only the retained original guest-2026-10-12.1 after host publication",
        "required": False, "default": False, "type": "boolean",
    }
    assert inputs["publish_retained_g2"] == {
        "description": "Publish the accepted retained guest-2026-10-16.1 without rebuilding guests",
        "required": False, "default": False, "type": "boolean",
    }
    context = {"__builtins__": {}, "github": SimpleNamespace(event_name=event),
               "inputs": SimpleNamespace(publish_initial_g1=initial, publish_retained_g2=retained)}
    jobs = workflow["jobs"]
    # These conditions use only boolean operations and string equality. Evaluate
    # both branches, then check dependencies so skipped preparation cannot hold publication.
    publish_condition = jobs["publish"]["if"].removeprefix("${{").removesuffix("}}").strip()
    build_condition = jobs["build"]["if"].removeprefix("${{").removesuffix("}}").strip()
    assert bool(eval(publish_condition.replace("&&", " and ").replace("||", " or "), context)) == (
        event == "workflow_dispatch" and (initial is True or retained is True)
    )
    assert bool(eval(build_condition.replace("!", "not ").replace("&&", " and "), context)) == (
        initial is not True and retained is not True
    )
    # GitHub skips prepare when its build dependency is skipped. Publication
    # must have no such dependency, including when preparation fails.
    assert jobs["prepare"]["needs"] == "build" and "if" not in jobs["prepare"]
    assert "needs" not in jobs["publish"]


def test_workflow_retained_source_artifacts_and_token_narrow(retained_publisher):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    # PyYAML's YAML1.1 loader maps the Actions 'on' key to boolean True.
    assert set(workflow.get("on", workflow.get(True))) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    for name, job in workflow["jobs"].items():
        assert job.get("permissions", workflow["permissions"]) == (
            {"actions": "read", "contents": "read", "packages": "write"}
            if name == "publish" else {"contents": "read"}
        )
    assert workflow["concurrency"] == {"group": "default-guest-publication", "cancel-in-progress": False}
    expected = {
        "g1": {
            "GUEST_VERSION": "guest-2026-10-12.1", "GUEST_COMPATIBILITY": "v1",
            "GUEST_REVISION": "8234a047d810d543d8c4d1cb1fa9859987be035b",
            "GUEST_INDEX": "sha256:df0068692909088a90db2c8f9777807404e3b7d8061ee72bc94a5feabd7dc46e",
            "GUEST_RUN_ID": "38248401312", "GUEST_ARCHIVE_IDS": "11748025327,11746464998",
            "GUEST_LAYOUT_ID": "11747551391", "PUBLISHER_REVISION": "8234a047d810d543d8c4d1cb1fa9859987be035b",
        },
        "g2": {
            "GUEST_VERSION": "guest-2026-10-16.1", "GUEST_COMPATIBILITY": "v1",
            "GUEST_REVISION": "ee291fba78ab34e4dca630d529ac8083ec29802f",
            "GUEST_INDEX": "sha256:b5f3b69562fd4b84730813bd3eb0554b351c975bb363a1be9404f0646147c06b",
            "GUEST_RUN_ID": "38897452318", "GUEST_ARCHIVE_IDS": "12044318477,12044582213",
            "GUEST_LAYOUT_ID": "12045630940", "PUBLISHER_REVISION": REVISION,
        },
    }
    assert retained_publisher.env == expected[retained_publisher.generation]
    steps = retained_publisher.job["steps"]
    assert steps[0]["name"] == "Select retained release and refuse conflicting inputs"
    assert steps[0]["env"] == {
        "REQUESTED_VERSION": "${{ inputs.version }}", "REQUESTED_COMPATIBILITY": "${{ inputs.compatibility }}",
        "PUBLISH_INITIAL_G1": "${{ inputs.publish_initial_g1 }}",
        "PUBLISH_RETAINED_G2": "${{ inputs.publish_retained_g2 }}",
    }
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ env.PUBLISHER_REVISION }}"
    downloads = [step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")]
    assert len(downloads) == 2
    for download, ids, path in zip(downloads, ["GUEST_ARCHIVE_IDS", "GUEST_LAYOUT_ID"],
                                   ["archives", "retained-guest-oci"]):
        assert download["uses"] == "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
        assert download["with"] == {
            "artifact-ids": "${{ env." + ids + " }}", "run-id": "${{ env.GUEST_RUN_ID }}",
            "repository": "craigbalding/safeyolo",
            "github-token": "${{ secrets.GITHUB_TOKEN }}", "merge-multiple": True,
            "path": "${{ runner.temp }}/" + path,
        }
    build = next(step for step in steps if step.get("name") == "Build the shared native OCI verifier")
    assert build["env"]["SAFEYOLO_BUILD_REVISION"] == "${{ env.PUBLISHER_REVISION }}"
    assert build["env"]["CARGO_BUILD_JOBS"] == "1"
    assert build["run"] == "scripts/cargo_with_space.sh build --release --manifest-path proxy/Cargo.toml --locked --example verify_guest_oci"
    assert not any("guest/build" in step.get("run", "") for step in steps)
    authenticate = next(step for step in steps if step.get("name") == "Authenticate with the linked repository token")
    assert authenticate["env"] == {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}
    assert authenticate["run"] == 'printf \'%s\' "$GITHUB_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin'
    names = [step.get("name") for step in steps]
    assert names.index("Verify retained inputs before registry authentication") < names.index(
        "Authenticate with the linked repository token"
    ) < names.index("Upload, verify and promote the complete guest release")
    text = json.dumps(workflow)
    assert "secrets.GITHUB_TOKEN" in text
    assert "--password-stdin" in text
    assert "sbom" not in text.lower()


@pytest.mark.parametrize("version,compatibility", [
    ("guest-2026-10-12.2", "v1"), (None, "v2"),
    ("", "v1"), (None, ""),
    ("$(touch forbidden-write)", "v1"),
])
def test_retained_workflow_refuses_conflicting_inputs(tmp_path, retained_publisher, version, compatibility):
    step = retained_publisher.job["steps"][0]
    env_file = tmp_path / "refused-release"
    result = run("bash", "-euo", "pipefail", "-c", step["run"], cwd=tmp_path, env={
        **os.environ, **retained_publisher.inputs,
        "REQUESTED_VERSION": retained_publisher.env["GUEST_VERSION"] if version is None else version,
        "REQUESTED_COMPATIBILITY": compatibility, "GITHUB_SHA": REVISION, "GITHUB_ENV": str(env_file),
    })
    assert result.returncode != 0 and "Retained publication requires" in result.stderr
    assert not env_file.exists() and not (tmp_path / "forbidden-write").exists()


@pytest.mark.parametrize("initial,retained", [(True, True), (False, False), (True, False), (False, True)])
def test_retained_workflow_refuses_conflicting_modes_or_release(tmp_path, initial, retained):
    # For one enabled mode, require the other release's version to fail too.
    version = "guest-2026-10-16.1" if initial else "guest-2026-10-12.1"
    env_file = tmp_path / "refused-release"
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    step = workflow["jobs"]["publish"]["steps"][0]
    result = run("bash", "-euo", "pipefail", "-c", step["run"], cwd=tmp_path, env={
        **os.environ, "PUBLISH_INITIAL_G1": str(initial).lower(), "PUBLISH_RETAINED_G2": str(retained).lower(),
        "REQUESTED_VERSION": version, "REQUESTED_COMPATIBILITY": "v1",
        "GITHUB_SHA": REVISION, "GITHUB_ENV": str(env_file),
    })
    assert result.returncode != 0
    assert not env_file.exists()


@pytest.mark.parametrize("defect", [None, "missing-layout", "wrong-index", "missing-blob",
                                  "corrupt-index", "corrupt-child", "corrupt-config", "corrupt-archive",
                                  "missing-archive", "changed-archive", "changed-provenance",
                                  "wrong-revision", "wrong-version", "wrong-compatibility"])
def test_retained_workflow_verifies_inputs_before_authentication(
    tmp_path, artifacts, publisher_tools, retained_publisher, defect,
):
    oras, verifier = publisher_tools
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/publish_guest_oci.sh", scripts / "publish_guest_oci.sh")
    (scripts / "publish_guest_oci.sh").chmod(0o755)
    examples = source / "proxy/target/release/examples"
    examples.mkdir(parents=True)
    (examples / "verify_guest_oci").symlink_to(Path(verifier).resolve())
    tools = tmp_path / "bin"
    tools.mkdir()
    (tools / "oras").symlink_to(Path(oras).resolve())
    runner = tmp_path / "runner"
    runner.mkdir()
    shutil.move(artifacts, runner / "archives")
    retained = runner / "retained-guest-oci"
    env = {**os.environ, **retained_publisher.env, "RUNNER_TEMP": str(runner), "ORAS": oras,
           "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
    prepared = run(str(scripts / "publish_guest_oci.sh"), "--artifacts", str(runner / "archives"),
                   "--layout", str(retained), "--version", env["GUEST_VERSION"],
                   "--compatibility", env["GUEST_COMPATIBILITY"], "--revision", env["GUEST_REVISION"],
                   "--verifier", verifier, env=env)
    assert prepared.returncode == 0, prepared.stderr
    digest = run(oras, "resolve", "--oci-layout", f"{retained}:{env['GUEST_VERSION']}")
    assert digest.returncode == 0, digest.stderr
    # The small native-verified fixture substitutes only the expected content
    # digest. The preceding control binds the production digest and all inputs.
    env["GUEST_INDEX"] = digest.stdout.strip()
    if defect == "missing-layout":
        shutil.rmtree(retained)
    elif defect == "wrong-index":
        env["GUEST_INDEX"] = retained_publisher.env["GUEST_INDEX"]
    elif defect in {"missing-blob", "corrupt-index", "corrupt-child", "corrupt-config", "corrupt-archive"}:
        blobs = retained / "blobs/sha256"
        index_path = blobs / env["GUEST_INDEX"].removeprefix("sha256:")
        index = json.loads(index_path.read_text())
        child_path = blobs / index["manifests"][0]["digest"].removeprefix("sha256:")
        child = json.loads(child_path.read_text())
        paths = {
            "corrupt-index": index_path, "corrupt-child": child_path,
            "corrupt-config": blobs / child["config"]["digest"].removeprefix("sha256:"),
            "corrupt-archive": blobs / child["layers"][0]["digest"].removeprefix("sha256:"),
            "missing-blob": blobs / child["layers"][0]["digest"].removeprefix("sha256:"),
        }
        blob = paths[defect]
        if defect == "missing-blob":
            blob.unlink()
        else:
            blob.chmod(0o644)
            blob.write_bytes(b"corrupt")
    elif defect == "missing-archive":
        (runner / "archives/linux-amd64/guest.tar.zst").unlink()
    elif defect == "changed-archive":
        with (runner / "archives/linux-amd64/guest.tar.zst").open("ab") as archive_file:
            archive_file.write(b"different archive bytes")
    elif defect == "changed-provenance":
        (runner / "archives/linux-amd64/build-base.txt").write_text(
            "docker.io/library/debian@sha256:" + "c" * 64 + "\n"
        )
    elif defect == "wrong-revision":
        env["GUEST_REVISION"] = "c" * 40
    elif defect == "wrong-version":
        env["GUEST_VERSION"] = "guest-2026-10-12.2"
    elif defect == "wrong-compatibility":
        env["GUEST_COMPATIBILITY"] = "v2"
    step = next(step for step in retained_publisher.job["steps"] if step.get("name") ==
                "Verify retained inputs before registry authentication")
    reached_auth = runner / "authentication-reached"
    result = run("bash", "-euo", "pipefail", "-c",
                 step["run"] + '\ntouch "$RUNNER_TEMP/authentication-reached"', cwd=source, env=env)
    if defect:
        assert result.returncode != 0, result.stdout
        assert not reached_auth.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert "verified darwin/arm64" in result.stdout
        assert "verified linux/amd64" in result.stdout
        assert "verified linux/arm64" in result.stdout
        args_file = tmp_path / "publisher-args.json"
        (scripts / "publish_guest_oci.sh").write_text(
            "#!/usr/bin/env python3\nimport json, os, sys\n"
            "with open(os.environ['PUBLISHER_ARGS'], 'w') as output:\n    json.dump(sys.argv[1:], output)\n"
        )
        upload = next(step for step in retained_publisher.job["steps"] if step.get("name") ==
                      "Upload, verify and promote the complete guest release")
        invoked = run("bash", "-euo", "pipefail", "-c", upload["run"], cwd=source,
                      env={**env, "PUBLISHER_ARGS": str(args_file)})
        assert invoked.returncode == 0, invoked.stderr
        assert json.loads(args_file.read_text()) == [
            "--artifacts", str(runner / "archives"), "--layout", str(runner / "guest-oci"),
            "--version", env["GUEST_VERSION"], "--compatibility", "v1", "--revision", env["GUEST_REVISION"],
            "--verifier", "proxy/target/release/examples/verify_guest_oci",
            "--publish", "ghcr.io/craigbalding/safeyolo-guest",
        ]


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_rootfs_uses_pinned_input_and_records_copied_manifest(tmp_path, architecture):
    # Drive the real builder's input/output wiring without building another
    # Debian filesystem. Real skopeo parses each source before a deliberately
    # invalid destination stops the command without a package/network call.
    real_skopeo = shutil.which("skopeo")
    if not real_skopeo:
        pytest.skip("skopeo is required to exercise the actual OCI reference parser")
    tools = tmp_path / "tools"
    tools.mkdir()
    builder = tmp_path / "guest"
    builder.mkdir()
    shutil.copyfile(ROOT / "guest/build-rootfs.sh", builder / "build-rootfs.sh")
    (builder / "rootfs-customize-hook.sh").write_text("#!/bin/bash\nset -eu\nmkdir -p \"$1/etc\"\n")
    script = """#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['BUILD_CALLS'], 'a') as calls:
    calls.write(json.dumps([name,*args])+'\\n')
if name=='sudo':
    while args[0].startswith('-'): args.pop(0)
    os.execvp(args[0],args)
elif name=='skopeo':
    reference=args[-2] if 'copy' in args else args[-1]
    parsed=subprocess.run([os.environ['SKOPEO_PARSER'], 'copy', reference, 'safeyolo-parser-test:destination'],
                          capture_output=True, text=True, timeout=10)
    if 'Invalid destination name' not in parsed.stderr:
        sys.stderr.write(parsed.stderr)
        sys.exit(parsed.returncode or 1)
    if 'copy' in args:
        _,directory,ref=args[-1].split(':')
        path=pathlib.Path(directory)
        path.mkdir(parents=True,exist_ok=True)
        (path/'index.json').write_text(json.dumps({'manifests':[{'digest':'sha256:'+'d'*64,'annotations':{'org.opencontainers.image.ref.name':ref}}]}))
    elif '--config' in args:
        print(json.dumps({'os':'linux','architecture':os.environ['ARCH']}))
    else: print('docker.io/library/debian')
elif name=='umoci':
    (pathlib.Path(args[-1])/'rootfs/etc').mkdir(parents=True)
elif name=='curl':
    pathlib.Path(args[args.index('-o')+1]).write_bytes(b'fixture')
elif name=='rsync':
    shutil.copytree(args[-2],args[-1],dirs_exist_ok=True)
# chroot/mkfs/chown are controlled no-ops for this producer-wiring test.
"""
    for name in ("sudo", "skopeo", "umoci", "curl", "rsync", "chroot", "mkfs.ext4", "chown"):
        path = tools / name
        path.write_text(script)
        path.chmod(0o755)
    output = tmp_path / "output"
    work = tmp_path / "work"
    work.mkdir()
    calls_path = tmp_path / "calls"
    digest = hashlib.sha256(b"fixture").hexdigest()
    env = {**os.environ, "PATH": f"{tools}:{Path(os.sys.executable).parent}:{os.environ['PATH']}",
           "ARCH": architecture, "OUTPUT_DIR": str(output), "TMPDIR": str(work), "BUILD_CALLS": str(calls_path),
           "SKOPEO_PARSER": real_skopeo,
           "MISE_SHA256_AMD64": digest, "MISE_SHA256_ARM64": digest,
           "GH_SHA256_AMD64": digest, "GH_SHA256_ARM64": digest, "ROOTFS_SIZE_MB": "1"}
    env.pop("DEBIAN_IMAGE", None)
    result = run("bash", str(builder / "build-rootfs.sh"), env=env, timeout=30)
    assert result.returncode == 0, result.stderr
    calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
    copies = [call for call in calls if call[0] == "skopeo" and "copy" in call]
    assert len(copies) == 1
    assert "--preserve-digests" in copies[0]
    assert f"--override-arch={architecture}" in copies[0]
    assert any(arg.startswith("docker://docker.io/library/debian@sha256:") for arg in copies[0])
    assert (output / "build-base.txt").read_text() == "docker.io/library/debian@sha256:" + "d" * 64 + "\n"
    assert (output / "rootfs-tree").is_dir()
    assert (output / "rootfs-base.ext4").is_file()
    assert (output / "cache-paths.txt").read_text() == "/var/cache/apt\n/var/lib/apt/lists\n"
    before = calls_path.read_bytes()
    env["DEBIAN_IMAGE"] = "docker://example.test/changed@sha256:" + "e" * 64
    cached = run("bash", str(builder / "build-rootfs.sh"), env=env, timeout=30)
    assert cached.returncode == 0 and "Rootfs already present" in cached.stdout
    assert calls_path.read_bytes() == before
    assert (output / "build-base.txt").read_text().endswith("d" * 64 + "\n")

    # Restore the rejected default in the disposable builder. The same real
    # input parser must fail before copy rather than let the controlled tools
    # hide the regression again. Neither run builds or downloads Debian.
    script_path = builder / "build-rootfs.sh"
    script_path.write_text(script_path.read_text().replace("/debian@sha256:", "/debian:trixie@sha256:"))
    env.pop("DEBIAN_IMAGE")
    env["OUTPUT_DIR"] = str(tmp_path / "rejected-output")
    rejected = run("bash", str(script_path), env=env, timeout=30)
    assert rejected.returncode != 0
    assert "Docker references with both a tag and digest" in rejected.stderr
