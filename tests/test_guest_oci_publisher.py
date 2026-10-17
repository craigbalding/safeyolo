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

from scripts import prepare_guest_transport_fixture

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
    metrics = dict(field.split("=", 1) for field in result.stdout.split()[1:])
    assert int(metrics["archive_bytes"]) == (destination / "guest.tar.zst").stat().st_size
    files = ["rootfs-tree", "cache-paths.txt"] if platform.startswith("linux/") else [
        "Image", "initramfs.cpio.gz", "rootfs-base.ext4",
    ]
    paths = [str(source / name) for name in files]
    for field, options in (("apparent_bytes", ["--apparent-size"]), ("allocated_bytes", [])):
        measured = run("sudo", "-n", "du", "-sc", "-B1", *options, "--", *paths)
        assert measured.returncode == 0, measured.stderr
        assert int(metrics[field]) == int(measured.stdout.splitlines()[-1].split()[0])
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
    faults = {"blob": False, "index": False, "upload": False, "promotion": False}

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
                    if faults["upload"] or (faults["promotion"] and reference == "compat-v1"):
                        return self.reply(400)
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


def select_retained_publisher(tmp_path, generation):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    job = workflow["jobs"]["publish"]
    inputs = {
        "PUBLISH_INITIAL_G1": str(generation == "g1").lower(),
        "PUBLISH_RETAINED_G2": str(generation == "g2").lower(),
        "PUBLISH_TRANSPORT_FIXTURE": "false",
        "PUBLISH_REDUCED_GUEST": str(generation == "reduced").lower(),
        "PUBLISH_REDUCED_DEFAULT": str(generation == "reduced-default").lower(),
        "REQUESTED_VERSION": {"g1": "guest-2026-10-12.1", "g2": "guest-2026-10-16.1",
                              "reduced": "guest-2026-10-16.1082", "reduced-default": "guest-2026-10-16.1082"}[generation],
        "REQUESTED_COMPATIBILITY": "v1",
    }
    env_file = tmp_path / "selected-release"
    result = run("bash", "-euo", "pipefail", "-c", job["steps"][0]["run"], cwd=tmp_path,
                 env={**os.environ, **inputs, "GITHUB_SHA": REVISION, "GITHUB_ENV": str(env_file)})
    assert result.returncode == 0, result.stderr
    env = dict(line.split("=", 1) for line in env_file.read_text().splitlines())
    return SimpleNamespace(job=job, env=env, inputs=inputs, generation=generation)


@pytest.fixture(params=["g1", "g2"])
def retained_publisher(request, tmp_path):
    return select_retained_publisher(tmp_path, request.param)


@pytest.fixture
def reduced_publisher(tmp_path):
    return select_retained_publisher(tmp_path, "reduced")


@pytest.mark.parametrize("event", ["workflow_dispatch", "push", "release", "schedule", "pull_request"])
@pytest.mark.parametrize("initial", [None, False, True])
@pytest.mark.parametrize("retained", [None, False, True])
@pytest.mark.parametrize("fixture", [None, False, True])
@pytest.mark.parametrize("reduced", [None, False, True])
@pytest.mark.parametrize("default", [None, False, True])
def test_workflow_retained_publication_routing(event, initial, retained, fixture, reduced, default):
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
    assert inputs["publish_transport_fixture"] == {
        "description": "Generate and publish the nonbootable >2 GiB transport fixture by digest only",
        "required": False, "default": False, "type": "boolean",
    }
    assert inputs["publish_reduced_guest"] == {
        "description": "Publish retained guest-2026-10-16.1082 by digest without changing production tags",
        "required": False, "default": False, "type": "boolean",
    }
    assert inputs["publish_reduced_default"] == {
        "description": "Publish retained guest-2026-10-16.1082 with its version tag and advance compat-v1",
        "required": False, "default": False, "type": "boolean",
    }
    context = {"__builtins__": {}, "github": SimpleNamespace(event_name=event),
               "inputs": SimpleNamespace(publish_initial_g1=initial, publish_retained_g2=retained,
                                         publish_transport_fixture=fixture, publish_reduced_guest=reduced,
                                         publish_reduced_default=default)}
    jobs = workflow["jobs"]
    # These conditions use only boolean operations and string equality. Evaluate
    # both branches, then check dependencies so skipped preparation cannot hold publication.
    publish_condition = jobs["publish"]["if"].removeprefix("${{").removesuffix("}}").strip()
    build_condition = jobs["build"]["if"].removeprefix("${{").removesuffix("}}").strip()
    assert bool(eval(publish_condition.replace("&&", " and ").replace("||", " or "), context)) == (
        event == "workflow_dispatch" and (initial is True or retained is True or fixture is True or reduced is True or default is True)
    )
    assert bool(eval(build_condition.replace("!", "not ").replace("&&", " and "), context)) == (
        initial is not True and retained is not True and fixture is not True and reduced is not True and default is not True
    )
    # GitHub skips prepare when its build dependency is skipped. Publication
    # must have no such dependency, including when preparation fails.
    assert jobs["prepare"]["needs"] == "build" and "if" not in jobs["prepare"]
    assert "needs" not in jobs["publish"]


@pytest.mark.parametrize("generation", ["g1", "g2", "reduced", "reduced-default"])
def test_workflow_retained_source_artifacts_and_token_narrow(tmp_path, generation):
    retained_publisher = select_retained_publisher(tmp_path, generation)
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
        "reduced": {
            "GUEST_VERSION": "guest-2026-10-16.1082", "GUEST_COMPATIBILITY": "v1",
            "GUEST_REVISION": "33224c9fc14beeb00be30eb71bdc09f91c5aa58b",
            "GUEST_INDEX": "sha256:14359301826746d088f124205de232c77c40567871550d38b035e6bfb53e5a2e",
            "GUEST_RUN_ID": "38975155518", "GUEST_ARCHIVE_IDS": "",
            "GUEST_LAYOUT_ID": "12079186556", "PUBLISHER_REVISION": REVISION,
        },
    }
    expected["reduced-default"] = expected["reduced"]
    assert retained_publisher.env == expected[retained_publisher.generation]
    steps = retained_publisher.job["steps"]
    assert steps[0]["name"] == "Select retained release and refuse conflicting inputs"
    assert steps[0]["env"] == {
        "REQUESTED_VERSION": "${{ inputs.version }}", "REQUESTED_COMPATIBILITY": "${{ inputs.compatibility }}",
        "PUBLISH_INITIAL_G1": "${{ inputs.publish_initial_g1 }}",
        "PUBLISH_RETAINED_G2": "${{ inputs.publish_retained_g2 }}",
        "PUBLISH_TRANSPORT_FIXTURE": "${{ inputs.publish_transport_fixture }}",
        "PUBLISH_REDUCED_GUEST": "${{ inputs.publish_reduced_guest }}",
        "PUBLISH_REDUCED_DEFAULT": "${{ inputs.publish_reduced_default }}",
    }
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ env.PUBLISHER_REVISION }}"
    downloads = [step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")]
    assert len(downloads) == 2
    for download, ids, path in zip(downloads, ["GUEST_ARCHIVE_IDS", "GUEST_LAYOUT_ID"],
                                   ["archives", "retained-guest-oci"]):
        assert download["uses"] == "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131"
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
    assert result.returncode != 0 and "Selected publication requires" in result.stderr
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
        "PUBLISH_TRANSPORT_FIXTURE": "false", "PUBLISH_REDUCED_GUEST": "false", "PUBLISH_REDUCED_DEFAULT": "false",
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


@pytest.mark.parametrize("initial,retained,fixture,version,compatibility", [
    (False, False, False, "guest-2026-10-16.1082", "v1"),
    (True, False, False, "guest-2026-10-16.1082", "v1"),
    (False, True, False, "guest-2026-10-16.1082", "v1"),
    (False, False, True, "guest-2026-10-16.1082", "v1"),
    (False, False, False, "guest-2026-10-16.1", "v1"),
    (False, False, False, "$(touch forbidden-write)", "v1"),
    (False, False, False, "guest-2026-10-16.1082", "v2"),
])
@pytest.mark.parametrize("mode", ["digest", "default", "both"])
def test_reduced_workflow_admission(tmp_path, initial, retained, fixture, version, compatibility, mode):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    step = workflow["jobs"]["publish"]["steps"][0]
    env_file = tmp_path / "selected-release"
    result = run("bash", "-euo", "pipefail", "-c", step["run"], cwd=tmp_path, env={
        **os.environ, "PUBLISH_INITIAL_G1": str(initial).lower(), "PUBLISH_RETAINED_G2": str(retained).lower(),
        "PUBLISH_TRANSPORT_FIXTURE": str(fixture).lower(),
        "PUBLISH_REDUCED_GUEST": str(mode != "default").lower(),
        "PUBLISH_REDUCED_DEFAULT": str(mode != "digest").lower(),
        "REQUESTED_VERSION": version, "REQUESTED_COMPATIBILITY": compatibility,
        "GITHUB_SHA": REVISION, "GITHUB_ENV": str(env_file),
    })
    admitted = mode != "both" and not any((initial, retained, fixture)) and version == "guest-2026-10-16.1082" and compatibility == "v1"
    assert (result.returncode == 0) == admitted, result.stderr
    assert env_file.exists() == admitted
    assert not (tmp_path / "forbidden-write").exists()


@pytest.fixture
def reduced_layout(tmp_path, artifacts, publisher_tools, reduced_publisher):
    oras, verifier = publisher_tools
    env = reduced_publisher.env
    prepared = publish(tmp_path, artifacts, publisher_tools, version=env["GUEST_VERSION"], revision=env["GUEST_REVISION"])
    assert prepared.returncode == 0, prepared.stderr
    source = tmp_path / "workflow-source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/publish_guest_by_digest.sh", scripts)
    shutil.copy2(ROOT / "scripts/publish_guest_oci.sh", scripts)
    examples = source / "proxy/target/release/examples"
    examples.mkdir(parents=True)
    (examples / "verify_guest_oci").symlink_to(Path(verifier).resolve())
    tools = source / "bin"
    tools.mkdir()
    (tools / "oras").symlink_to(Path(oras).resolve())
    runner = tmp_path / "runner"
    runner.mkdir()
    layout = runner / "retained-guest-oci"
    shutil.move(tmp_path / f"layout-{env['GUEST_VERSION']}", layout)
    # Substitute only the fixture's index. The selection control binds the real
    # retained digest, source and artifact. No separate archives are staged.
    index = run(oras, "resolve", "--oci-layout", f"{layout}:{env['GUEST_VERSION']}")
    assert index.returncode == 0, index.stderr
    env = {**os.environ, **env, "GUEST_INDEX": index.stdout.strip(), "ORAS": oras,
           "RUNNER_TEMP": str(runner), "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
    return SimpleNamespace(source=source, runner=runner, layout=layout, env=env, job=reduced_publisher.job)


@pytest.mark.parametrize("defect", [None, "missing-layout", "wrong-index", "wrong-version", "wrong-compatibility",
                                  "corrupt-index", "corrupt-child", "corrupt-config", "corrupt-archive", "missing-blob"])
def test_reduced_workflow_verifies_full_layout_before_authentication(reduced_layout, defect):
    layout, env = reduced_layout.layout, reduced_layout.env
    if defect == "missing-layout":
        shutil.rmtree(layout)
    elif defect == "wrong-index":
        env["GUEST_INDEX"] = "sha256:" + "0" * 64
    elif defect == "wrong-version":
        env["GUEST_VERSION"] = "guest-2026-10-16.1"
    elif defect == "wrong-compatibility":
        env["GUEST_COMPATIBILITY"] = "v2"
    elif defect:
        blobs = layout / "blobs/sha256"
        index_path = blobs / env["GUEST_INDEX"].removeprefix("sha256:")
        index = json.loads(index_path.read_text())
        child_path = blobs / index["manifests"][0]["digest"].removeprefix("sha256:")
        child = json.loads(child_path.read_text())
        blob = {
            "corrupt-index": index_path, "corrupt-child": child_path,
            "corrupt-config": blobs / child["config"]["digest"].removeprefix("sha256:"),
            "corrupt-archive": blobs / child["layers"][0]["digest"].removeprefix("sha256:"),
            "missing-blob": blobs / child["layers"][0]["digest"].removeprefix("sha256:"),
        }[defect]
        if defect == "missing-blob":
            blob.unlink()
        else:
            blob.chmod(0o644)
            blob.write_bytes(b"corrupt")
    step = next(step for step in reduced_layout.job["steps"] if step.get("id") == "verify_reduced_guest")
    result = run("bash", "-euo", "pipefail", "-c", step["run"] + '\ntouch "$RUNNER_TEMP/authentication-reached"',
                 cwd=reduced_layout.source, env=env)
    assert (result.returncode == 0) == (defect is None), result.stderr
    assert (reduced_layout.runner / "authentication-reached").exists() == (defect is None)
    assert not (reduced_layout.runner / "archives").exists()
    assert not (reduced_layout.runner / "guest-oci").exists()


@pytest.mark.parametrize("fault", [None, "index", "blob", "upload", "missing-tag"])
def test_actual_oras_reduced_workflow_copies_by_digest_without_changing_tags(
    tmp_path, reduced_layout, artifacts, publisher_tools, registry, fault,
):
    repository, blobs, manifests, tags, events, faults = registry
    for version in ("guest-2026-10-12.1", "guest-2026-10-16.1"):
        seeded = publish(tmp_path, artifacts, publisher_tools, repository, version=version)
        assert seeded.returncode == 0, seeded.stderr
    before_tags, before_manifests, before_blobs = dict(tags), dict(manifests), dict(blobs)
    if fault == "missing-tag":
        del tags["guest-2026-10-12.1"]
        before_tags = dict(tags)
    elif fault:
        faults[fault] = True
    events.clear()
    step = next(step for step in reduced_layout.job["steps"] if step.get("name") ==
                "Upload the retained reduced guest without production tags")
    # Use the real workflow command and publisher against the owned registry.
    command = step["run"].replace("ghcr.io/craigbalding/safeyolo-guest", repository).rstrip() + " --plain-http"
    result = run("bash", "-euo", "pipefail", "-c", command, cwd=reduced_layout.source,
                 env=reduced_layout.env, timeout=30)
    assert (result.returncode == 0) == (fault is None), result.stderr
    assert tags == before_tags
    assert all(manifests[key] == value for key, value in before_manifests.items())
    assert all(blobs[key] == value for key, value in before_blobs.items())
    assert all(path.rsplit("/", 1)[1].startswith("sha256:") for method, path in events
               if method == "PUT" and "/manifests/" in path)
    archives = set()
    for descriptor in json.loads((reduced_layout.layout / "blobs/sha256" /
                                 reduced_layout.env["GUEST_INDEX"].removeprefix("sha256:")).read_text())["manifests"]:
        child = json.loads((reduced_layout.layout / "blobs/sha256" / descriptor["digest"].removeprefix("sha256:")).read_text())
        for item in [child["config"], *child["layers"]]:
            if fault is None:
                assert len(blobs[item["digest"]]) == item["size"]
        archives.update(item["digest"] for item in child["layers"])
    assert not any(method == "GET" and path.rsplit("/", 1)[1] in archives for method, path in events)
    if fault is None:
        assert "Published guest layout" in result.stdout
        assert "fixture" not in result.stdout.lower()
        index = reduced_layout.env["GUEST_INDEX"]
        publication = reduced_layout.runner / "reduced-guest-publication"
        assert manifests[index] == (publication / "public-index.json").read_bytes()
        for tag, digest in before_tags.items():
            assert (publication / f"after-{tag}").read_text().strip() == digest
    elif fault == "missing-tag":
        assert not any(method == "PUT" for method, _ in events)


@pytest.mark.parametrize("fault", [None, "index", "blob", "upload", "promotion", "version-conflict"])
def test_actual_oras_reduced_default_publication_and_recovery(
    tmp_path, reduced_layout, artifacts, publisher_tools, registry, fault,
):
    repository, blobs, manifests, tags, events, faults = registry
    for version, compatibility in (("guest-2026-10-12.1", "v1"), ("guest-2026-10-16.1", "v1"),
                                   ("guest-2026-10-16.2", "v2")):
        seeded = publish(tmp_path, artifacts, publisher_tools, repository, version=version, compatibility=compatibility)
        assert seeded.returncode == 0, seeded.stderr
    version, index = reduced_layout.env["GUEST_VERSION"], reduced_layout.env["GUEST_INDEX"]
    if fault == "version-conflict":
        tags[version] = tags["guest-2026-10-16.1"]
    elif fault:
        faults[fault] = True
    before_tags, before_manifests, before_blobs = dict(tags), dict(manifests), dict(blobs)
    layout_index = (reduced_layout.layout / "index.json").read_bytes()
    step = next(step for step in reduced_layout.job["steps"] if step.get("name") ==
                "Publish the retained reduced guest as the default")
    # Execute the workflow's command, changing only its remote test destination.
    command = step["run"].replace("ghcr.io/craigbalding/safeyolo-guest", repository).rstrip() + " --plain-http"

    def invoke():
        return run("bash", "-euo", "pipefail", "-c", command, cwd=reduced_layout.source,
                   env=reduced_layout.env, timeout=30)

    events.clear()
    result = invoke()
    assert (result.returncode == 0) == (fault is None), result.stderr
    if fault:
        assert tags["compat-v1"] == before_tags["compat-v1"]
        if fault == "promotion":
            assert tags == {**before_tags, version: index}
        else:
            assert tags == before_tags
        if fault == "version-conflict":
            assert "Immutable guest version conflict" in result.stderr
            assert not any(method == "PUT" and path.endswith((f"/{version}", "/compat-v1"))
                           for method, path in events)
            return
        # A failed verification/upload, or a stop between version and channel
        # writes, can be retried with identical retained input after diagnosis.
        faults[fault] = False
        events.clear()
        result = invoke()
        assert result.returncode == 0, result.stderr
    assert tags == {**before_tags, version: index, "compat-v1": index}
    assert all(manifests[key] == value for key, value in before_manifests.items())
    assert all(blobs[key] == value for key, value in before_blobs.items())
    assert not any(method == "DELETE" for method, _ in events)
    version_put = events.index(("PUT", f"/v2/guest/manifests/{version}"))
    compatibility_put = events.index(("PUT", "/v2/guest/manifests/compat-v1"))
    assert version_put < compatibility_put
    index_get = events.index(("GET", f"/v2/guest/manifests/{index}"))
    assert index_get < version_put
    # ORAS can reuse an index uploaded by the failed attempt. The complete
    # graph must still be fetched and verified before either tag is written.
    if ("PUT", f"/v2/guest/manifests/{index}") in events:
        assert events.index(("PUT", f"/v2/guest/manifests/{index}")) < index_get
    for descriptor in json.loads(manifests[index])["manifests"]:
        child = json.loads(manifests[descriptor["digest"]])
        assert events.index(("GET", f"/v2/guest/manifests/{descriptor['digest']}")) < index_get
        for item in [child["config"], *child["layers"]]:
            assert events.index(("GET", f"/v2/guest/blobs/{item['digest']}")) < index_get
    assert manifests[index] == (reduced_layout.layout / "blobs/sha256" / index.removeprefix("sha256:")).read_bytes()
    assert "Published" in result.stdout
    assert not (reduced_layout.runner / "archives").exists()
    assert not (reduced_layout.runner / "guest-oci").exists()
    assert (reduced_layout.layout / "index.json").read_bytes() == layout_index
    retry = invoke()
    assert retry.returncode == 0, retry.stderr
    assert tags == {**before_tags, version: index, "compat-v1": index}


@pytest.mark.parametrize("defect", ["both-inputs", "no-input-mode", "missing-layout", "wrong-revision", "alias-version"])
def test_retained_layout_publisher_refuses_wrong_input_before_registry(reduced_layout, registry, defect):
    env = reduced_layout.env
    args = [str(ROOT / "scripts/publish_guest_oci.sh"), "--from-layout", "--layout", str(reduced_layout.layout),
            "--version", env["GUEST_VERSION"], "--compatibility", env["GUEST_COMPATIBILITY"],
            "--revision", env["GUEST_REVISION"], "--verifier", "proxy/target/release/examples/verify_guest_oci",
            "--publish", registry[0], "--plain-http"]
    if defect == "both-inputs":
        args += ["--artifacts", str(reduced_layout.runner / "unused-archives")]
    elif defect == "no-input-mode":
        args.remove("--from-layout")
    elif defect == "missing-layout":
        shutil.rmtree(reduced_layout.layout)
    elif defect == "wrong-revision":
        args[args.index("--revision") + 1] = "c" * 40
    elif defect == "alias-version":
        alias = "guest-2026-10-16.9999"
        tagged = run(env["ORAS"], "tag", "--oci-layout", f"{reduced_layout.layout}@{env['GUEST_INDEX']}", alias)
        assert tagged.returncode == 0, tagged.stderr
        args[args.index("--version") + 1] = alias
    result = run(*args, cwd=reduced_layout.source, env=env, timeout=30)
    assert result.returncode != 0
    assert not registry[4]


@pytest.mark.parametrize("initial,retained,version,compatibility", [
    (False, False, "guest-2026-10-16.239", "v1"),
    (True, False, "guest-2026-10-16.239", "v1"),
    (False, True, "guest-2026-10-16.239", "v1"),
    (True, True, "guest-2026-10-16.239", "v1"),
    (False, False, "guest-2026-10-16.1", "v1"),
    (False, False, "$(touch forbidden-write)", "v1"),
    (False, False, "guest-2026-10-16.239", "v2"),
])
def test_transport_workflow_admission(tmp_path, initial, retained, version, compatibility):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    step = workflow["jobs"]["publish"]["steps"][0]
    env_file = tmp_path / "selected-release"
    result = run("bash", "-euo", "pipefail", "-c", step["run"], cwd=tmp_path, env={
        **os.environ, "PUBLISH_INITIAL_G1": str(initial).lower(), "PUBLISH_RETAINED_G2": str(retained).lower(),
        "PUBLISH_TRANSPORT_FIXTURE": "true", "PUBLISH_REDUCED_GUEST": "false", "PUBLISH_REDUCED_DEFAULT": "false",
        "REQUESTED_VERSION": version,
        "REQUESTED_COMPATIBILITY": compatibility, "GITHUB_SHA": REVISION, "GITHUB_ENV": str(env_file),
    })
    admitted = not initial and not retained and version == prepare_guest_transport_fixture.VERSION and compatibility == "v1"
    assert (result.returncode == 0) == admitted, result.stderr
    assert env_file.exists() == admitted
    assert not (tmp_path / "forbidden-write").exists()
    if admitted:
        selected = dict(line.split("=", 1) for line in env_file.read_text().splitlines())
        assert selected["GUEST_INDEX"] == "sha256:b5f3b69562fd4b84730813bd3eb0554b351c975bb363a1be9404f0646147c06b"
        assert selected["GUEST_RUN_ID"] == "38897452318" and selected["GUEST_LAYOUT_ID"] == "12045630940"
        assert selected["PUBLISHER_REVISION"] == REVISION


@pytest.mark.parametrize("fixture,reduced,default", [(False, False, False), (True, False, False),
                                                    (False, True, False), (False, False, True)])
def test_retained_publication_workflow_effective_steps(fixture, reduced, default):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    context = {"__builtins__": {}, "inputs": SimpleNamespace(publish_transport_fixture=fixture, publish_reduced_guest=reduced,
                                         publish_reduced_default=default),
               "steps": SimpleNamespace(prepare_transport_fixture=SimpleNamespace(outcome="success"),
                                        verify_reduced_guest=SimpleNamespace(outcome="success")),
               "cancelled": lambda: False}
    enabled = []
    for step in workflow["jobs"]["publish"]["steps"]:
        expression = step.get("if", "${{ True }}").removeprefix("${{").removesuffix("}}").strip()
        if eval(expression.replace("!", "not ").replace("&&", " and ").replace("||", " or "), context):
            enabled.append(step)
    names = [step.get("name") for step in enabled]
    assert ("Prepare and verify the nonbootable transport fixture" in names) == fixture
    assert ("Upload the transport fixture without production tags" in names) == fixture
    assert ("Verify retained inputs before registry authentication" in names) == (not fixture and not reduced and not default)
    assert ("Upload, verify and promote the complete guest release" in names) == (not fixture and not reduced and not default)
    assert ("Verify retained reduced guest before registry authentication" in names) == (reduced or default)
    assert ("Upload the retained reduced guest without production tags" in names) == reduced
    assert ("Publish the retained reduced guest as the default" in names) == default
    downloads = [step for step in enabled if "actions/download-artifact@" in step.get("uses", "")]
    assert len(downloads) == (1 if fixture or reduced or default else 2)
    if reduced:
        assert downloads[0]["with"]["artifact-ids"] == "${{ env.GUEST_LAYOUT_ID }}"
        assert names.index("Verify retained reduced guest before registry authentication") < names.index(
            "Authenticate with the linked repository token"
        ) < names.index("Upload the retained reduced guest without production tags")
        upload = next(step for step in enabled if "actions/upload-artifact@" in step.get("uses", ""))
        assert upload["with"]["name"] == "reduced-guest-publication-result"
        assert upload["with"]["path"] == "${{ runner.temp }}/reduced-guest-publication"
    if default:
        assert names.index("Verify retained reduced guest before registry authentication") < names.index(
            "Authenticate with the linked repository token"
        ) < names.index("Publish the retained reduced guest as the default")
        assert not any("actions/upload-artifact@" in step.get("uses", "") for step in enabled)
    if fixture:
        assert downloads[0]["with"]["artifact-ids"] == "${{ env.GUEST_LAYOUT_ID }}"
        assert names.index("Prepare and verify the nonbootable transport fixture") < names.index(
            "Authenticate with the linked repository token"
        ) < names.index("Upload the transport fixture without production tags")
        upload = next(step for step in enabled if "actions/upload-artifact@" in step.get("uses", ""))
        assert upload["with"]["name"] == "guest-transport-fixture-result"
        assert upload["with"]["path"].splitlines() == [
            "${{ runner.temp }}/transport-fixture/fixture.json", "${{ runner.temp }}/transport-fixture/publication",
        ]


def test_transport_workflow_upload_uses_generated_index(tmp_path):
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    upload = next(step for step in workflow["jobs"]["publish"]["steps"] if step.get("name") ==
                  "Upload the transport fixture without production tags")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    command = scripts / "publish_guest_by_digest.sh"
    command.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                       "with open(os.environ['CAPTURE_ARGS'], 'w') as target: json.dump(sys.argv[1:], target)\n")
    command.chmod(0o755)
    fixture = tmp_path / "transport-fixture"
    fixture.mkdir()
    index = "sha256:" + "c" * 64
    (fixture / "fixture.json").write_text(json.dumps({"index": {"digest": index}}))
    captured = tmp_path / "args.json"
    result = run("bash", "-euo", "pipefail", "-c", upload["run"], cwd=tmp_path,
                 env={**os.environ, "RUNNER_TEMP": str(tmp_path), "CAPTURE_ARGS": str(captured)})
    assert result.returncode == 0, result.stderr
    assert "Never boot this fixture." in result.stdout
    assert json.loads(captured.read_text()) == [
        str(fixture / "layout"), index, "proxy/target/release/examples/verify_guest_oci",
        "ghcr.io/craigbalding/safeyolo-guest", str(fixture / "publication"),
    ]


@pytest.fixture
def transport_seed(tmp_path, built, publisher_tools):
    (built / "rootfs-tree/etc").mkdir()
    (built / "rootfs-tree/etc/os-release").write_text("ID=debian\n")
    artifacts = tmp_path / "seed-archives"
    for platform in ("darwin/arm64", "linux/amd64", "linux/arm64"):
        (built / "rootfs-tree/command").write_text(platform)
        archive(platform, built, artifacts / platform.replace("/", "-"))
    result = publish(tmp_path, artifacts, publisher_tools, version="guest-2026-10-16.1")
    assert result.returncode == 0, result.stderr
    layout = tmp_path / "layout-guest-2026-10-16.1"
    index = run(publisher_tools[0], "resolve", "--oci-layout", str(layout) + ":guest-2026-10-16.1").stdout.strip()
    return SimpleNamespace(artifacts=artifacts, layout=layout, index=index)


@pytest.fixture
def transport_step(tmp_path, transport_seed, publisher_tools):
    source = tmp_path / "workflow-source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    # Exercise the effective workflow command and the real producer with a small
    # random image. The dispatch has no size override; it always uses 2049 MiB.
    (scripts / "prepare_guest_transport_fixture.py").write_text(
        f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n"
        "from scripts import prepare_guest_transport_fixture as fixture\n"
        "fixture.RANDOM_IMAGE_BYTES = 65536\nfixture.MINIMUM_ARCHIVE_BYTES = 32768\nfixture.main()\n"
    )
    examples = source / "proxy/target/release/examples"
    examples.mkdir(parents=True)
    (examples / "verify_guest_oci").symlink_to(Path(publisher_tools[1]).resolve())
    runner = tmp_path / "runner"
    runner.mkdir()
    (runner / "retained-guest-oci").symlink_to(transport_seed.layout, target_is_directory=True)
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    step = next(step for step in workflow["jobs"]["publish"]["steps"] if step.get("id") == "prepare_transport_fixture")
    env = {**os.environ, "ORAS": publisher_tools[0], "RUNNER_TEMP": str(runner),
           "GUEST_INDEX": transport_seed.index, "GITHUB_SHA": REVISION}
    return SimpleNamespace(source=source, runner=runner, step=step, env=env)


@pytest.mark.parametrize("defect", [None, "corrupt-seed", "small-archive", "existing-output", "low-disk"])
def test_transport_preparation_and_failure_before_authentication(transport_step, transport_seed, defect):
    output = transport_step.runner / "transport-fixture"
    driver = transport_step.source / "scripts/prepare_guest_transport_fixture.py"
    if defect == "corrupt-seed":
        child = json.loads(prepare_guest_transport_fixture.blob(transport_seed.layout, transport_seed.index).read_bytes())["manifests"][0]
        path = prepare_guest_transport_fixture.blob(transport_seed.layout, child["digest"])
        path.chmod(0o644)
        path.write_bytes(b"corrupt")
    elif defect == "small-archive":
        driver.write_text(driver.read_text().replace("32768", "2147483648"))
    elif defect == "existing-output":
        output.mkdir()
        (output / "retained").write_text("do not overwrite")
    elif defect == "low-disk":
        driver.write_text(driver.read_text().replace("fixture.main()", "from types import SimpleNamespace\n"
                         "fixture.shutil.disk_usage = lambda path: SimpleNamespace(free=0)\nfixture.main()"))
    result = run("bash", "-euo", "pipefail", "-c",
                 transport_step.step["run"] + '\ntouch "$RUNNER_TEMP/authentication-reached"',
                 cwd=transport_step.source, env=transport_step.env, timeout=30)
    assert (result.returncode == 0) == (defect is None), result.stderr
    assert (transport_step.runner / "authentication-reached").exists() == (defect is None)
    assert (output / "fixture.json").exists() == (defect is None)
    if defect == "existing-output":
        assert (output / "retained").read_text() == "do not overwrite"
    if defect is not None:
        return
    record = json.loads((output / "fixture.json").read_text())
    assert record["revision"] == REVISION and record["seed_index"] == transport_seed.index
    assert record["version"] == "guest-2026-10-16.239" and record["compatibility"] == "v1"
    assert "Never boot" in record["scope"]
    assert set(record["platforms"]) == {"darwin/arm64", "linux/amd64", "linux/arm64"}
    for descriptors in [record, *record["platforms"].values()]:
        for descriptor in descriptors.values():
            if isinstance(descriptor, dict) and "digest" in descriptor:
                raw = prepare_guest_transport_fixture.blob(output / "layout", descriptor["digest"]).read_bytes()
                assert len(raw) == descriptor["size"]
                assert "sha256:" + hashlib.sha256(raw).hexdigest() == descriptor["digest"]
    assert not (output / "built/darwin-arm64/rootfs-base.ext4").exists()


@pytest.mark.parametrize("fault", [None, "index", "blob", "upload", "missing-tag"])
def test_actual_oras_transport_publication_preserves_production_and_has_small_readbacks(
    tmp_path, transport_step, transport_seed, publisher_tools, registry, fault,
):
    repository, blobs, manifests, tags, events, faults = registry
    oras, verifier = publisher_tools
    for version in ("guest-2026-10-12.1", "guest-2026-10-16.1"):
        result = publish(tmp_path, transport_seed.artifacts, publisher_tools, repository, version=version)
        assert result.returncode == 0, result.stderr
    prepared = run("bash", "-euo", "pipefail", "-c", transport_step.step["run"],
                   cwd=transport_step.source, env=transport_step.env, timeout=30)
    assert prepared.returncode == 0, prepared.stderr
    fixture = transport_step.runner / "transport-fixture"
    record = json.loads((fixture / "fixture.json").read_text())
    before_tags, before_manifests, before_blobs = dict(tags), dict(manifests), dict(blobs)
    events.clear()
    if fault == "missing-tag":
        del tags["guest-2026-10-12.1"]
        before_tags = dict(tags)
    elif fault:
        faults[fault] = True
    result = run(str(ROOT / "scripts/publish_guest_by_digest.sh"), str(fixture / "layout"),
                 record["index"]["digest"], verifier, repository, str(fixture / "publication"), "--plain-http",
                 env={**os.environ, "ORAS": oras}, timeout=30)
    assert (result.returncode == 0) == (fault is None), result.stderr
    assert tags == before_tags
    assert all(manifests[key] == value for key, value in before_manifests.items())
    assert all(blobs[key] == value for key, value in before_blobs.items())
    assert all(path.rsplit("/", 1)[1].startswith("sha256:") for method, path in events
               if method == "PUT" and "/manifests/" in path)
    archives = {item["archive"]["digest"] for item in record["platforms"].values()}
    assert not any(method == "GET" and path.rsplit("/", 1)[1] in archives for method, path in events)
    if fault is None:
        assert record["index"]["digest"] in manifests
        for platform in record["platforms"].values():
            assert len(manifests[platform["child"]["digest"]]) == platform["child"]["size"]
            for kind in ("config", "archive"):
                assert len(blobs[platform[kind]["digest"]]) == platform[kind]["size"]
        for tag in before_tags:
            assert (fixture / "publication" / f"after-{tag}").read_text().strip() == before_tags[tag]
    elif fault == "missing-tag":
        assert not any(method == "PUT" for method, _ in events)


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
