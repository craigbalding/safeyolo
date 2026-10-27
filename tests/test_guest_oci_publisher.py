"""Exercise the maintained archive producer and actual ORAS publication boundary."""

import hashlib
import io
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import certifi
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
    assert "GNU coreutils" in run("du", "--version").stdout, "put GNU du on PATH for archive fixtures"


@pytest.fixture
def publisher_tools():
    oras = os.environ.get("ORAS", shutil.which("oras"))
    verifier = os.environ.get("GUEST_OCI_VERIFIER")
    if not oras or not verifier:
        pytest.skip("set ORAS and GUEST_OCI_VERIFIER to the retained publisher tools")
    assert run(oras, "manifest", "index", "create", "--help").returncode == 0
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
        measured = run("sudo", "-n", shutil.which("du"), "-sc", "-B1", *options, "--", *paths)
        assert measured.returncode == 0, measured.stderr
        assert int(metrics[field]) == int(measured.stdout.splitlines()[-1].split()[0])
    return destination / "guest.tar.zst"


@pytest.fixture
def built(tmp_path, archive_tools):
    source = tmp_path / "built"
    source.mkdir()
    (source / "rootfs-tree/etc").mkdir(parents=True)
    (source / "rootfs-tree/etc/os-release").write_text("ID=debian\n")
    (source / "build-base.txt").write_text(BASE + "\n")
    tree = source / "rootfs-tree"
    tree.mkdir(mode=0o751, exist_ok=True)
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
        linux_metadata = []
        if sys.platform == "linux":
            # The release builds on Linux. Mac publisher fixtures use synthetic
            # inputs; Homebrew GNU tar cannot retain Linux ACLs and xattrs.
            private = tree / "private"
            os.setxattr(private, "user.safeyolo.fixture", b"guest metadata")
            # Linux POSIX ACL version 2: owner, named user, group, mask, other.
            acl = struct.pack("<I", 2) + b"".join(
                struct.pack("<HHI", tag, permissions, uid) for tag, permissions, uid in (
                    (1, 6, 0xFFFFFFFF), (2, 4, 100001), (4, 0, 0xFFFFFFFF),
                    (16, 0, 0xFFFFFFFF), (32, 0, 0xFFFFFFFF),
                )
            )
            os.setxattr(private, "system.posix_acl_access", acl)
            linux_metadata = ["--acls", "--xattrs", "--xattrs-include=*"]
        extracted = Path(temporary) / "extracted"
        extracted.mkdir()
        assert run("sudo", "-n", "chown", "-Rh", "100000:100000", str(tree)).returncode == 0
        assert tree.stat().st_uid == 100000
        try:
            output = archive("linux/arm64", source, tmp_path / "archive")
            result = run("sudo", "-n", shutil.which("tar"), "--zstd", *linux_metadata,
                         "--numeric-owner", "--same-owner", "--same-permissions",
                         "-xf", str(output), "-C", str(extracted))
            assert result.returncode == 0, result.stderr
            for file in ("rootfs-tree", "rootfs-tree/command", "rootfs-tree/private", "rootfs-tree/symbolic"):
                assert (extracted / file).lstat().st_uid == 100000
                assert (extracted / file).lstat().st_gid == 100000
            assert (extracted / "rootfs-tree/command").stat().st_mode & 0o777 == 0o751
            assert (extracted / "rootfs-tree/private").stat().st_mode & 0o777 == 0o600
            if sys.platform == "linux":
                private = extracted / "rootfs-tree/private"
                attributes = run("sudo", "-n", sys.executable, "-c",
                                 "import json, os, sys; print(json.dumps([os.getxattr(sys.argv[1], name).hex() "
                                 "for name in ('user.safeyolo.fixture', 'system.posix_acl_access')]))", str(private))
                assert attributes.returncode == 0, attributes.stderr
                assert json.loads(attributes.stdout) == [b"guest metadata".hex(), acl.hex()]
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


def publish(tmp_path, artifacts, publisher_tools, repository=None, version="guest-2026-10-12.1", compatibility="v1", revision=REVISION, from_layout=False):
    oras, verifier = publisher_tools
    args = [str(ROOT / "scripts/publish_guest_oci.sh"),
            "--layout", str(tmp_path / f"layout-{version}"), "--version", version,
            "--compatibility", compatibility, "--revision", revision, "--verifier", verifier]
    args += ["--from-layout"] if from_layout else ["--artifacts", str(artifacts)]
    if repository:
        args += ["--publish", repository, "--plain-http"]
    return run(*args, env={**os.environ, "ORAS": oras}, timeout=30)


def test_actual_oras_local_release_and_no_registry_writes(tmp_path, artifacts, publisher_tools, registry):
    result = publish(tmp_path, artifacts, publisher_tools)
    assert result.returncode == 0, result.stderr
    assert all(f"verified {platform}" in result.stdout for platform in ("darwin/arm64", "linux/amd64", "linux/arm64"))
    fetched = run(publisher_tools[0], "manifest", "fetch", "--oci-layout",
                  f"{tmp_path / 'layout-guest-2026-10-12.1'}:guest-2026-10-12.1")
    assert fetched.returncode == 0, fetched.stderr
    index = json.loads(fetched.stdout)
    assert {(child["platform"]["os"], child["platform"]["architecture"]) for child in index["manifests"]} == {
        ("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64"),
    }
    blobs = tmp_path / "layout-guest-2026-10-12.1/blobs/sha256"
    for descriptor in index["manifests"]:
        child = json.loads((blobs / descriptor["digest"].removeprefix("sha256:")).read_bytes())
        config = (blobs / child["config"]["digest"].removeprefix("sha256:")).read_bytes()
        platform = descriptor["platform"]
        assert config == json.dumps({"os": platform["os"], "architecture": platform["architecture"]},
                                    separators=(",", ":")).encode()
        assert child["config"]["size"] == len(config)
        assert child["config"]["digest"] == "sha256:" + hashlib.sha256(config).hexdigest()
    assert not registry[4]


@pytest.mark.parametrize(("defect", "error"), [
    ("missing-platform", "missing guest platform"),
    ("missing-consumer", "missing linux/arm64 guest"),
    ("unsupported-platform", "unsupported guest consumer platform"),
    ("duplicate-platform", "duplicate guest consumer platform"),
    ("wrong-platform", "guest config must contain only the selected consumer os and architecture"),
])
def test_invalid_index_platforms_refused_before_upload(tmp_path, artifacts, publisher_tools, registry, defect, error):
    prepared = publish(tmp_path, artifacts, publisher_tools)
    assert prepared.returncode == 0, prepared.stderr
    oras, _ = publisher_tools
    reference = f"{tmp_path / 'layout-guest-2026-10-12.1'}:guest-2026-10-12.1"
    fetched = run(oras, "manifest", "fetch", "--oci-layout", reference)
    assert fetched.returncode == 0, fetched.stderr
    index = json.loads(fetched.stdout)
    children = index["manifests"]
    if defect == "missing-platform":
        del children[0]["platform"]
    elif defect == "missing-consumer":
        children.pop()
    elif defect == "unsupported-platform":
        children[0]["platform"]["architecture"] = "ppc64le"
    elif defect == "duplicate-platform":
        children[1]["platform"] = children[0]["platform"]
    elif defect == "wrong-platform":
        children[0]["platform"], children[1]["platform"] = children[1]["platform"], children[0]["platform"]
    invalid = tmp_path / "invalid-index.json"
    invalid.write_text(json.dumps(index))
    # ORAS records the changed index's true digest. Refusal must come from the
    # platform checks, rather than an unrelated stale digest or length.
    pushed = run(oras, "manifest", "push", "--oci-layout", reference, str(invalid))
    assert pushed.returncode == 0, pushed.stderr
    refused = publish(tmp_path, artifacts, publisher_tools, registry[0], from_layout=True)
    assert refused.returncode != 0 and error in refused.stderr
    assert not registry[4]


def test_actual_oras_publication_retry_versions_and_generations(tmp_path, artifacts, publisher_tools, registry):
    repository, _, manifests, tags, events, _ = registry
    prepared = publish(tmp_path, artifacts, publisher_tools)
    assert prepared.returncode == 0, prepared.stderr
    resolved = run(publisher_tools[0], "resolve", "--oci-layout",
                   f"{tmp_path / 'layout-guest-2026-10-12.1'}:guest-2026-10-12.1")
    assert resolved.returncode == 0, resolved.stderr
    first = publish(tmp_path, artifacts, publisher_tools, repository, from_layout=True)
    assert first.returncode == 0, first.stderr
    g1 = tags["guest-2026-10-12.1"]
    assert g1 == resolved.stdout.strip()
    assert "compat-v1" not in tags
    tags["compat-v1"] = g1
    first_events = list(events)
    assert not any(path.endswith("/compat-v1") for method, path in first_events if method == "PUT")
    version_put = first_events.index(("PUT", "/v2/guest/manifests/guest-2026-10-12.1"))
    index_put = first_events.index(("PUT", f"/v2/guest/manifests/{g1}"))
    assert index_put < version_put
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
    assert g2 != g1 and tags["compat-v1"] == g1
    incompatible = publish(tmp_path, artifacts, publisher_tools, repository,
                           version="guest-2026-10-12.3", compatibility="v2")
    assert incompatible.returncode == 0, incompatible.stderr
    assert tags["compat-v1"] == g1
    assert "compat-v2" not in tags
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



@pytest.mark.parametrize("enough_space", [True, False])
def test_digest_only_transport_has_no_channel_write(tmp_path, artifacts, publisher_tools, registry, monkeypatch, enough_space):
    repository, _, _, tags, events, _ = registry
    staged = publish(tmp_path, artifacts, publisher_tools, repository)
    assert staged.returncode == 0, staged.stderr
    seed = tags["guest-2026-10-12.1"]
    tags["compat-v1"] = seed
    layout = tmp_path / "layout-guest-2026-10-12.1"
    output = tmp_path / "transport"
    oras, verifier = publisher_tools
    monkeypatch.setattr(prepare_guest_transport_fixture, "RANDOM_IMAGE_BYTES", 8192)
    monkeypatch.setattr(prepare_guest_transport_fixture, "MINIMUM_ARCHIVE_BYTES", 1024)
    monkeypatch.setenv("ORAS", oras)
    from types import SimpleNamespace
    # The transport payload is only 8 KiB in this control. Exercise the real
    # production capacity guard explicitly instead of reserving its 8 GiB.
    monkeypatch.setattr(prepare_guest_transport_fixture.shutil, "disk_usage",
                        lambda path: SimpleNamespace(free=8 * 1024**3 if enough_space else 0))
    if not enough_space:
        before = dict(tags)
        with pytest.raises(RuntimeError, match="8 GiB"):
            prepare_guest_transport_fixture.prepare(layout, seed, output, REVISION, Path(verifier))
        assert tags == before
        return
    recipe = prepare_guest_transport_fixture.prepare(layout, seed, output, REVISION, Path(verifier))
    before = dict(tags)
    events.clear()
    result = run(str(ROOT / "scripts/publish_guest_by_digest.sh"), str(output / "layout"),
                 recipe["index"]["digest"], verifier, repository, str(tmp_path / "publication"), "--plain-http",
                 env={**os.environ, "ORAS": oras}, timeout=30)
    assert result.returncode == 0, result.stderr
    assert tags == before
    assert all(path.rsplit("/", 1)[1].startswith("sha256:") for method, path in events
               if method == "PUT" and "/manifests/" in path)

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
    shutil.copyfile(ROOT / "guest/input-functions.sh", builder / "input-functions.sh")
    shutil.copyfile(ROOT / "guest/resolve_inputs.py", builder / "resolve_inputs.py")
    (builder / "rootfs-customize-hook.sh").write_text("#!/bin/bash\nset -eu\nmkdir -p \"$1/etc\"\nrm -rf \"$1/var/lib/apt/lists/\"*\n")
    script = """#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['BUILD_CALLS'], 'a') as calls:
    calls.write(json.dumps([name,*args])+'\\n')
if args in (['--version'], ['-V']):
    print(name+' fixture-version'); sys.exit(0)
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
    tree=pathlib.Path(args[-1])/'rootfs'
    (tree/'etc').mkdir(parents=True)
    (tree/'var/lib/apt/lists').mkdir(parents=True)
    (tree/'var/lib/apt/lists/fixture_InRelease').write_bytes(b'fixture')
    (tree/'var/lib/apt/lists/fixture_Packages').write_bytes(b'fixture')
    (tree/'usr/share/keyrings').mkdir(parents=True)
    (tree/'usr/share/keyrings/debian-archive-keyring.gpg').write_bytes(b'fixture')
elif name=='chroot':
    if '/usr/bin/apt-get' in args:
        assert 'Acquire::https::CaInfo=/tmp/safeyolo-build-ca.pem' in args
        assert (pathlib.Path(args[0])/'tmp/safeyolo-build-ca.pem').read_bytes() == pathlib.Path(os.environ['SSL_CERT_FILE']).read_bytes()
    if '/usr/local/bin/mise' in args: print('1.2.3 fixture')
    if '/usr/local/bin/gh' in args: print('gh version 1.2.3 fixture')
    if 'update' in args and os.environ.get('APT_FAULT')=='update': sys.exit(100)
    if '--upgradable' in args and os.environ.get('APT_FAULT')=='held-back': print('Listing...\\nheld-package 2.0 [upgradable from: 1.0]')
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
    output.mkdir()
    cache=output / '.download-cache'
    cache.mkdir()
    for tool in ('mise','gh'):
        (cache / f'{tool}-1.2.3-{architecture}.tar.gz').write_bytes(b'fixture')
    inputs=tmp_path / 'inputs.json'
    inputs.write_text(json.dumps({'schema':'safeyolo.guest-inputs/v1', 'tools':{
        tool:{'version':'1.2.3','assets':{architecture:{'url':'https://fixture.invalid/tool','sha256':digest}}}
        for tool in ('mise','gh')}, 'debian':{'manifests':{architecture:{'reference':
            'docker://docker.io/library/debian@sha256:'+'c'*64}}}}))
    env = {**os.environ, "PATH": f"{tools}:{Path(os.sys.executable).parent}:{os.environ['PATH']}",
           "SAFEYOLO_BUILD_PYTHON": sys.executable, "SSL_CERT_FILE": certifi.where(),
           "ARCH": architecture, "OUTPUT_DIR": str(output), "TMPDIR": str(work), "BUILD_CALLS": str(calls_path),
           "SKOPEO_PARSER": real_skopeo, "GUEST_INPUTS": str(inputs),
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
    assert not (output / "rootfs-tree/tmp/safeyolo-build-ca.pem").exists()
    assert (output / "rootfs-base.ext4").is_file()
    assert (output / "cache-paths.txt").read_text() == "/var/cache/apt\n/var/lib/apt/lists\n"
    before = calls_path.read_bytes()
    env["DEBIAN_IMAGE"] = "docker://example.test/changed@sha256:" + "e" * 64
    cached = run("bash", str(builder / "build-rootfs.sh"), env=env, timeout=30)
    assert cached.returncode == 0, cached.stderr
    assert calls_path.read_bytes() != before
    assert (output / "build-base.txt").read_text().endswith("d" * 64 + "\n")

    for fault in ("update", "held-back"):
        env.pop("DEBIAN_IMAGE", None)
        env["APT_FAULT"] = fault
        refused = run("bash", str(builder / "build-rootfs.sh"), env=env, timeout=30)
        assert refused.returncode != 0
        assert not (output / "build-base.txt").exists()
        if fault == "held-back":
            assert "remain upgradable" in refused.stderr
    env.pop("APT_FAULT")

    # Reject the malformed explicit input in the real reference parser. The same real
    # input parser must fail before copy rather than let the controlled tools
    # hide the regression again. Neither run builds or downloads Debian.
    env["DEBIAN_IMAGE"] = "docker://docker.io/library/debian:trixie@sha256:" + "e" * 64
    rejected = run("bash", str(builder / "build-rootfs.sh"), env=env, timeout=30)
    assert rejected.returncode != 0
    assert "Docker references with both a tag and digest" in rejected.stderr


def test_real_oras_receipt_attachment_discovery_and_inventory_retrieval(tmp_path, artifacts, publisher_tools, registry, monkeypatch, capsys):
    from scripts import guest_release
    repository, _, _, tags, _, _ = registry
    prior = publish(tmp_path, artifacts, publisher_tools, repository, version="guest-2026-10-11.1")
    assert prior.returncode == 0, prior.stderr
    tags["compat-v1"] = tags["guest-2026-10-11.1"]
    old_index = tags["compat-v1"]
    result = publish(tmp_path, artifacts, publisher_tools, repository)
    assert result.returncode == 0, result.stderr
    index, metadata = None, None
    oras, _ = publisher_tools
    monkeypatch.setenv("PATH", str(Path(oras).parent) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(guest_release.selection, "GUEST_REPOSITORY", repository)
    original = subprocess.run
    def local_run(args, **kwargs):
        if args[0] in {"oras", oras}:
            args = [oras, *args[1:]]
            if args[1] == "cp":
                args += ["--from-plain-http"]
            elif args[1] != "version":
                args += ["--plain-http"]
        return original(args, **kwargs)
    monkeypatch.setattr(subprocess, "run", local_run)
    index, metadata = guest_release.selection.manifest(repository + ":guest-2026-10-12.1")
    from datetime import UTC, datetime, timedelta
    now = datetime.now(UTC)
    provenance = tmp_path / "origins"
    provenance.mkdir()
    frozen = {"schema": "safeyolo.guest-inputs/v1", "resolved_at": (now - timedelta(minutes=6)).isoformat(),
              "resolution_started_at": (now - timedelta(minutes=7)).isoformat(), "producer": {"repository": "craigbalding/safeyolo", "workflow": ".github/workflows/guest-oci.yml",
                          "run_id": 1, "run_attempt": 2, "job_id": 7},
              "debian": {"manifests": {arch: {"reference": "docker://" + BASE} for arch in ("amd64", "arm64")}},
              "tools": {"mise": {"version": "1.2.3"}}}
    (provenance / "inputs.json").write_text(json.dumps(frozen))
    (provenance / "oras-inputs.json").write_text(json.dumps(frozen))
    (provenance / "publisher-oras.txt").write_text("controlled publisher version")
    (provenance / "publisher-builder.txt").write_text("controlled Rust publisher identity")
    for arch in ("amd64", "arm64"):
        directory = provenance / arch
        directory.mkdir()
        for name in (f"dpkg-{arch}.tsv", f"apt-sources-{arch}.txt", f"apt-{arch}.tar", f"apt-indexes-{arch}.sha256", f"builder-{arch}.txt",
                     f"mise-version-{arch}.txt", f"gh-version-{arch}.txt"):
            (directory / name).write_text("controlled inventory\n")
        (directory / "build-base.txt").write_text(BASE)
        (directory / "run-attempt.txt").write_text("2")
        (directory / "inputs.json").write_text(json.dumps(frozen))
        (directory / "build-started-at.txt").write_text((now - timedelta(minutes=5)).isoformat())
        (directory / "build-completed-at.txt").write_text((now - timedelta(minutes=1)).isoformat())
    for name in ("kernel.config", "kernel-builder.txt", "kernel-verification.json"):
        (provenance / "arm64" / name).write_text("controlled kernel identity\n")
    (provenance / "arm64/kernel-inputs.json").write_text(json.dumps(frozen))
    identity = {"repository": "craigbalding/safeyolo", "workflow": ".github/workflows/guest-oci.yml",
                "run_id": 1, "run_attempt": 2, "job_id": 3}
    monkeypatch.setenv("GITHUB_SHA", REVISION)
    monkeypatch.setattr(guest_release, "producer", lambda job, attempt: identity)
    monkeypatch.setattr(guest_release, "branch", lambda: "master")
    monkeypatch.setattr(guest_release.selection, "verify_producer", lambda *args: {
        "id": 7, "started_at": (now - timedelta(hours=1)).isoformat(), "completed_at": now.isoformat()})
    from types import SimpleNamespace
    args = SimpleNamespace(index=index["digest"], staged_at=now.isoformat(), stage_attempt=2, provenance=provenance)
    before = {key: value for key, value in tags.items() if key.startswith(("guest-", "compat-"))}
    receipt = guest_release.stage(args)
    shutil.rmtree(provenance)
    # Retry without the original local files. The trustworthy original remains.
    assert guest_release.stage(args)["staged_at"] == receipt["staged_at"]
    assert guest_release.records(index, guest_release.STAGING) == [receipt]
    recovered = guest_release.selection.staging_receipt(index, REVISION)
    assert recovered["producer"]["run_attempt"] == 2
    assert recovered["staged_at"] == receipt["staged_at"]
    assert {key: value for key, value in tags.items() if key.startswith(("guest-", "compat-"))} == before
    assert json.loads(guest_release.selection.capture("oras", "manifest", "fetch", "--output", "-", repository + "@" + index["digest"])) == metadata
    # Retrieve package bytes after the local build/report tree has gone away.
    _, attachment = guest_release.selection.manifest(repository + "@" + recovered["receipt_manifest"]["digest"])
    package_layer = next(layer for layer in attachment["layers"] if
                         layer.get("annotations", {}).get("org.opencontainers.image.title", "").endswith("dpkg-arm64.tsv"))
    assert guest_release.selection.capture("oras", "blob", "fetch", "--output", "-", repository + "@" + package_layer["digest"]) == b"controlled inventory\n"

    # Drive the real guard, registry content pull, native verifier and tag write.
    # Only the clock and trusted Actions/operator records are controlled here.
    promotion = SimpleNamespace(compatibility="v1", verifier=Path(publisher_tools[1]), work_directory=tmp_path)
    origin = {"repository": guest_release.selection.REPOSITORY, "workflow": guest_release.selection.GUEST_WORKFLOW,
              "run_id": 321, "run_attempt": 3, "job_id": 654}
    monkeypatch.setattr(guest_release, "promotion_context", lambda: {
        "source_revision": REVISION, "publisher_version": "controlled", "producer": origin})
    monkeypatch.setattr(guest_release, "paused", lambda: False)
    monkeypatch.setattr(guest_release, "datetime", SimpleNamespace(now=lambda *args: now + timedelta(seconds=172799)))
    assert guest_release.promote(promotion)["decision"] == "held"
    assert tags["compat-v1"] == old_index
    # Exercise the failed gate through the real CLI renderer and OCI reader.
    # The failure precedes content verification; inspection needs no verifier.
    monkeypatch.setattr(guest_release, "datetime", SimpleNamespace(now=lambda *args: now + timedelta(seconds=172800)))
    failed_smoke = {"schema": "safeyolo.guest-smoke/v1", "index_digest": index["digest"],
                    "platform": "linux-amd64", "result": "failed", "finished_at": now.isoformat(),
                    "reason": "original failed attempt", "gate_url": "https://example.invalid/failed-run",
                    "operator": "controlled-operator"}
    guest_release.attach(index, guest_release.SMOKE, failed_smoke)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setattr(sys, "argv", ["guest_release.py", "promote", "--verifier", "/absent-verifier",
                                     "--work-directory", str(tmp_path)])
    with pytest.raises(SystemExit) as stopped:
        guest_release.main()
    assert stopped.value.code == 2
    output = capsys.readouterr().out
    held = json.loads(output)
    assert held["decision"] == "held" and held["failed_smoke"] == failed_smoke
    assert held["old_index"] == old_index and held["index_digest"] == held["new_index"] == index["digest"]
    assert summary.read_text() == "```json\n" + output + "```\n"
    assert tags["compat-v1"] == old_index
    monkeypatch.delenv("GITHUB_STEP_SUMMARY")
    monkeypatch.setattr(sys, "argv", ["guest_release.py", "inspect", "--reference", repository + "@" + index["digest"]])
    guest_release.main()
    recovered = json.loads(capsys.readouterr().out)
    assert recovered["promotion"] == [held] and recovered["smoke"] == [failed_smoke]
    assert recovered["index"] == index
    # Execute the maintained workflow consumer, shell wrapper and real reader.
    # Only Actions metadata/login and the disposable registry address are local.
    tools = tmp_path / "inspection-tools"
    tools.mkdir()
    oras_wrapper = tools / "oras"
    oras_wrapper.write_text("#!/bin/sh\nif [ \"$1\" = login ]; then cat >/dev/null; exit 0; fi\n"
                            f"exec {shlex.quote(shutil.which(oras) or oras)} \"$@\" --plain-http\n")
    oras_wrapper.chmod(0o755)
    job = {"name": "promote", "id": origin["job_id"], "run_id": origin["run_id"],
           "run_attempt": origin["run_attempt"], "html_url": "https://example.invalid/promotion-job"}
    launcher = tools / "inspection-python"
    launcher.write_text(f"#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(ROOT)!r})\n"
                        "from scripts import guest_release as release\n"
                        f"release.selection.GUEST_REPOSITORY = {repository!r}\n"
                        f"def gh(endpoint):\n    assert endpoint == 'actions/jobs/{origin['job_id']}'\n    return {job!r}\n"
                        "release.selection.gh = gh\nsys.argv = sys.argv[1:]\nrelease.main()\n")
    launcher.chmod(0o755)
    inspection = tmp_path / "inspection-run"
    inspection.mkdir()
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    step = next(step for step in workflow["jobs"]["inspect"]["steps"] if step.get("name") == "Read the retained promotion decision")
    registry[4].clear()
    inspected = run("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"], cwd=ROOT,
                    env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                         "SAFEYOLO_BUILD_PYTHON": str(launcher), "RUNNER_TEMP": str(inspection),
                         "GITHUB_STEP_SUMMARY": str(inspection / "summary.md"), "GH_TOKEN": "test-only",
                         "GITHUB_ACTOR": "controlled-operator", "PROMOTION_JOB": str(origin["job_id"])}, timeout=30)
    assert inspected.returncode == 0, inspected.stderr
    report_text = (inspection / "guest-inspection.json").read_text()
    report = json.loads(report_text)
    assert report["requested_promotion"] == origin and report["matches"] == [recovered]
    assert (inspection / "summary.md").read_text() == "```json\n" + report_text + "```\n"
    assert tags["compat-v1"] == old_index and all(method in {"GET", "HEAD"} for method, _ in registry[4])
    for attachments in report["matches"][0]["attachments"].values():
        for row in attachments:
            assert row["manifest"] == json.loads(registry[2][row["attachment"]["digest"]])
            assert row["manifest"]["subject"] == index
            layer = next(layer for layer in row["manifest"]["layers"] if layer["mediaType"] == row["manifest"]["artifactType"])
            assert row["receipt_text"].encode() == registry[1][layer["digest"]]
            assert json.loads(row["receipt_text"]) == row["receipt"]
    for platform in guest_release.selection.PLATFORMS:
        smoke = {"schema": "safeyolo.guest-smoke/v1", "index_digest": index["digest"], "platform": platform,
                 "operator": "controlled-operator", "result": "passed", "finished_at": (now + timedelta(hours=1)).isoformat(),
                 "host_id": "controlled-host-" + platform, "gate_url": "https://example.invalid/retained-result",
                 "host": {"profile": "production", "platform": platform, "compatibility": "v1", "source_revision": REVISION,
                          "archive": {"sha256": "c" * 64}},
                 "lane": "vz" if platform == "darwin-arm64" else "systrap", "guest": {"index": index, "compatibility": "v1"}}
        guest_release.attach(index, guest_release.SMOKE, smoke)
    monkeypatch.setattr(guest_release, "verify_operator", lambda *args: None)
    monkeypatch.setattr(guest_release, "datetime", SimpleNamespace(now=lambda *args: now + timedelta(seconds=172800)))
    saved_blobs = dict(registry[1])
    saved_manifests = dict(registry[2])
    assert guest_release.promote(promotion)["decision"] == "promoted"
    assert tags["compat-v1"] == index["digest"]
    assert all(registry[1][key] == value for key, value in saved_blobs.items())
    assert all(registry[2][key] == value for key, value in saved_manifests.items())
    assert tags["guest-2026-10-11.1"] == old_index
    assert {row["decision"] for row in guest_release.records(index, guest_release.DECISION)} == {"held", "qualified", "promoted"}



def test_manual_promote_entrypoint_cannot_accept_bypass_flags(tmp_path):
    command = [str(ROOT / "scripts/publish_guest_oci.sh"), "--promote", "--verifier", "/unused", "--work-directory", str(tmp_path), "--force", "--now", "2099-01-01"]
    result = run(*command, env={**os.environ, "SAFEYOLO_BUILD_PYTHON": sys.executable})
    assert result.returncode != 0 and "unrecognized arguments" in result.stderr
