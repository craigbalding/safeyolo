"""Drive native OCI acquisition through TLS, extraction and installed selection.

The registry is an owned local fixture reached through the maintained CONNECT
parent. These are source controls, not public GHCR or booted platform acceptance.
"""

import copy
import hashlib
import io
import json
import os
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.blackbox.harness.sinkhole_parent import Parent, Request

REPO = Path(__file__).resolve().parents[1]
REPOSITORY = "ghcr.io/craigbalding/safeyolo-guest"
PREFIX = "/v2/craigbalding/safeyolo-guest/"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
ARCHIVE = "application/vnd.safeyolo.guest.v1.tar+zstd"
CONFIG = "application/vnd.safeyolo.guest.platform.v1+json"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def descriptor(data, media_type):
    return {"digest": digest(data), "size": len(data), "mediaType": media_type}


def release(archive, version="guest-2026-10-12.1", compatibility="v1", edit_child=None):
    annotations = {"org.opencontainers.image.version": version,
                   "org.opencontainers.image.source": "https://github.com/craigbalding/safeyolo",
                   "org.opencontainers.image.revision": "a" * 40,
                   "dev.safeyolo.guest.compatibility": compatibility}
    contents = {"blobs/" + digest(archive): archive}
    manifests = []
    for os_name, architecture in (("darwin", "arm64"), ("linux", "amd64"), ("linux", "arm64")):
        platform = {"os": os_name, "architecture": architecture}
        config = json.dumps(platform).encode()
        contents["blobs/" + digest(config)] = config
        child = {"schemaVersion": 2, "mediaType": MANIFEST, "artifactType": "application/vnd.safeyolo.guest.v1",
                 "annotations": {**annotations, "dev.safeyolo.guest.build-base":
                                 "docker.io/library/debian@sha256:" + "b" * 64},
                 "config": descriptor(config, CONFIG), "layers": [descriptor(archive, ARCHIVE)]}
        if edit_child:
            edit_child(child)
        child_bytes = json.dumps(child).encode()
        contents["manifests/" + digest(child_bytes)] = child_bytes
        manifests.append({**descriptor(child_bytes, MANIFEST), "platform": platform})
    index = {"schemaVersion": 2, "mediaType": INDEX, "artifactType": "application/vnd.safeyolo.guest.v1",
             "annotations": annotations, "manifests": manifests}
    contents["manifests/compat-v1"] = json.dumps(index).encode()
    return contents


def compressed_archive(extra=(), content=b"guest bytes", owner=100000, missing_cache=False, child_owner=None):
    """Use tar's real wire formats, including malicious link and path entries."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        entries = [("rootfs-tree", tarfile.DIRTYPE, b"", ""),
                   ("rootfs-tree/command", tarfile.REGTYPE, content, ""),
                   ("rootfs-tree/hard", tarfile.LNKTYPE, b"", "rootfs-tree/command"),
                   ("rootfs-tree/symbolic", tarfile.SYMTYPE, b"", "command")]
        if not missing_cache:
            entries.append(("cache-paths.txt", tarfile.REGTYPE, b"/var/cache/apt\n", ""))
        for name, kind, data, target in (*entries, *extra):
            entry = tarfile.TarInfo(name)
            entry.type, entry.linkname = kind, target
            entry.uid = entry.gid = owner
            if name == "rootfs-tree/command" and child_owner is not None:
                entry.uid = entry.gid = child_owner
            entry.mode = 0o644 if name == "cache-paths.txt" else (0o751 if kind in (tarfile.DIRTYPE, tarfile.REGTYPE) else 0o777)
            entry.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(entry, io.BytesIO(data) if entry.size else None)
    return subprocess.run(["zstd", "-q", "-c"], input=output.getvalue(), capture_output=True, check=True).stdout


@pytest.fixture
def native_cli():
    binary = Path(os.environ.get("SAFEYOLO_NATIVE_CLI", REPO / "proxy/target/debug/safeyolo"))
    if not binary.is_file():
        pytest.skip("build the candidate native CLI or set SAFEYOLO_NATIVE_CLI")
    if os.uname().sysname != "Linux":
        pytest.skip("Linux extraction controls; Mac installed proof belongs to #239")
    assert subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0, "owned Linux extraction fixture requires guest sudo"
    return binary.resolve()


@pytest.fixture
def guest_store():
    # Tiny synthetic blobs/trees need numeric ownership. The nested disk-backed
    # bind mount cannot supply that metadata; the guest filesystem can.
    with tempfile.TemporaryDirectory(prefix="guest-acquisition-") as directory:
        store = Path(directory) / ".local/share/safeyolo/guests"
        try:
            yield store
        finally:
            subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(Path(directory) / ".local")], check=True)


@pytest.fixture
def registry(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ghcr.io")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("ghcr.io")]), False)
            .sign(key, hashes.SHA256()))
    pem = tmp_path / "registry.pem"
    pem.touch(mode=0o600)
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM))
    ca = tmp_path / "registry-ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pem)
    contents, requests = {}, []
    faults = {"partial": None, "advance": None, "pause": None,
              "entered": threading.Event(), "resume": threading.Event()}

    class RegistryRequest(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            requests.append(path)
            assert not self.headers.get("Authorization", "").startswith("Basic ")
            if path == "/v2/":
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="https://ghcr.io/token",service="fixture"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/token":
                data = b'{"token":"synthetic-fixture-token","expires_in":3600}'
                key = None
            else:
                key = path.removeprefix(PREFIX)
                data = contents.get(key)
            if data is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Docker-Content-Digest", digest(data))
            self.send_header("Connection", "close")
            self.end_headers()
            if key == "manifests/compat-v1" and faults["advance"] is not None:
                contents.update(faults["advance"])
                faults["advance"] = None
            if key is not None and key == faults["pause"]:
                faults["entered"].set()
                faults["resume"].wait(timeout=10)
            try:
                self.wfile.write(data[:len(data) // 2] if key == faults["partial"] else data)
            except (BrokenPipeError, ConnectionResetError):
                # The native client closes deliberate digest/size refusals early.
                pass
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), RegistryRequest)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    class RegistryParent(Request):
        def _peer(self, host, port, *, tls_origin):
            assert tls_origin and host == "ghcr.io" and port == 443
            return socket.create_connection(server.server_address, timeout=5), False

    parent = Parent(None, None, request_handler=RegistryParent)
    threads = [threading.Thread(target=fixture.serve_forever, daemon=True) for fixture in (server, parent)]
    for thread in threads:
        thread.start()
    environment = dict(os.environ, HTTPS_PROXY=f"http://127.0.0.1:{parent.server_port}",
                       HTTP_PROXY=f"http://127.0.0.1:{parent.server_port}",
                       SSL_CERT_FILE=str(ca), REQUESTS_CA_BUNDLE=str(ca))
    try:
        yield contents, requests, faults, environment
    finally:
        faults["resume"].set()
        for fixture in (parent, server):
            fixture.shutdown()
            fixture.server_close()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()


def install(binary, root, store, environment, package_info):
    result = subprocess.run([str(binary), "--root", str(root), "guest", "acquire",
                           "--package-info", str(package_info), "--store", str(store),
                           "--write-selection", str(root / "prepared-selection.json")],
                          env=environment, capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        # Exercise the same backend function used by the actual installer.
        record = root / "prepared-selection.json"
        if not (root / "share/guest-selection.json").exists():
            subprocess.run(["bash", "-c", 'source "$1"; install_platform_assets "$2" "$3"; cp "$4" "$3/guest-selection.json"',
                            "guest-test", str(REPO / "scripts/native_package.sh"), result.stdout.strip(),
                            str(root / "share"), str(record)], env=environment, check=True, capture_output=True)
        record.unlink()
    return result


@pytest.fixture
def package_info(tmp_path):
    architecture = "amd64" if os.uname().machine == "x86_64" else "arm64"
    path = tmp_path / "package-info"
    path.write_text(f"source_commit={'a' * 40}\nprofile=debug\nplatform=linux-{architecture}\nminimum_runtime=2.34\n"
                    f"guest_compatibility=v1\nguest_repository={REPOSITORY}\nguest_discovery_tag=compat-v1\n")
    return path


def test_native_selection_pins_one_index_and_keeps_existing_installation(native_cli, registry, package_info, tmp_path, guest_store):
    contents, requests, faults, environment = registry
    first = release(compressed_archive())
    second = release(compressed_archive(content=b"new guest bytes"), version="guest-2026-10-12.2")
    contents.update(first)
    faults["advance"] = second
    host_metadata = package_info.read_bytes()
    store, root = guest_store, tmp_path / "first"
    result = install(native_cli, root, store, environment, package_info)
    assert result.returncode == 0, result.stderr
    selection = json.loads((root / "share/guest-selection.json").read_bytes())
    assert selection["index"]["digest"] == digest(first["manifests/compat-v1"])
    assert selection["version"] == "guest-2026-10-12.1"
    assert requests.count(PREFIX + "manifests/compat-v1") == 1
    assert (root / "share/rootfs-tree").is_symlink()
    tree = root / "share/rootfs-tree"
    assert tree.stat().st_uid == tree.stat().st_gid == 100000
    assert (tree / "command").stat().st_mode & 0o777 == 0o751
    assert (tree / "hard").stat().st_ino == (tree / "command").stat().st_ino
    assert (tree / "symbolic").readlink() == Path("command")
    assert (root / "share/cache-paths.txt").read_text() == "/var/cache/apt\n"
    initialized = subprocess.run([str(native_cli), "--root", str(root), "init"], env=environment,
                                 capture_output=True, text=True, timeout=10)
    assert initialized.returncode == 0, initialized.stderr
    preserved = {path: (root / path).read_bytes() for path in ("policy.toml", "data/admin_token", "data/agent_token", "data/instance_id")}
    before = len(requests)
    result = install(native_cli, root, store, environment, package_info)
    assert result.returncode == 0, result.stderr
    assert len(requests) == before
    assert json.loads((root / "share/guest-selection.json").read_bytes()) == selection
    assert all((root / path).read_bytes() == value for path, value in preserved.items())
    fresh = tmp_path / "second"
    result = install(native_cli, fresh, store, environment, package_info)
    assert result.returncode == 0, result.stderr
    newer = json.loads((fresh / "share/guest-selection.json").read_bytes())
    assert newer["version"] == "guest-2026-10-12.2"
    assert newer["archive"]["digest"] != selection["archive"]["digest"]
    assert package_info.read_bytes() == host_metadata
    read = subprocess.run(["sudo", "-n", "cat", str(tree / "command")], capture_output=True, check=True)
    assert read.stdout == b"guest bytes"
    before = len(requests)
    inode = (fresh / "share/rootfs-tree").resolve().stat().st_ino
    result = install(native_cli, tmp_path / "third", store, environment, package_info)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "third/share/rootfs-tree").resolve().stat().st_ino == inode
    assert all("/blobs/" not in path for path in requests[before:])


@pytest.mark.parametrize("fault", ["partial", "hash", "size", "compatibility", "missing-platform", "ambiguous-platform", "zstd", "tar", "ownership", "child-owner", "missing-cache"])
def test_native_acquisition_refuses_before_activation(native_cli, registry, package_info, tmp_path, fault, guest_store):
    contents, _requests, faults, environment = registry
    archive = compressed_archive(owner=0 if fault == "ownership" else 100000, missing_cache=fault == "missing-cache", child_owner=0 if fault == "child-owner" else None)
    if fault == "zstd":
        archive = b"not a zstd archive"
    if fault == "tar":
        archive = subprocess.run(["zstd", "-q", "-c"], input=b"not a tar archive", capture_output=True, check=True).stdout
    edit_child = (lambda child: child["layers"][0].update(size=len(archive) + 1)) if fault == "size" else None
    data = release(archive, compatibility="v2" if fault == "compatibility" else "v1", edit_child=edit_child)
    if fault in ("missing-platform", "ambiguous-platform"):
        index = json.loads(data["manifests/compat-v1"])
        if fault == "missing-platform":
            index["manifests"] = index["manifests"][:1]
        else:
            index["manifests"].append(copy.deepcopy(index["manifests"][1]))
        data["manifests/compat-v1"] = json.dumps(index).encode()
    key = "blobs/" + digest(archive)
    if fault == "partial":
        faults["partial"] = key
    if fault == "hash":
        data[key] = b"!" + archive[1:]
    contents.update(data)
    root, store = tmp_path / "refused", guest_store
    result = install(native_cli, root, store, environment, package_info)
    assert result.returncode != 0
    assert "panic" not in result.stderr.lower()
    assert not (root / "share").exists()
    assert not (root / "config.toml").exists()
    assert not (root / "data").exists()
    trees = store / "trees/sha256"
    assert not trees.exists() or not list(trees.iterdir())
    blobs = store / "blobs/sha256"
    assert not blobs.exists() or all(len(path.name) == 64 for path in blobs.iterdir())


@settings(max_examples=24, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(kind=st.sampled_from(["parent", "symlink", "hardlink"]),
       name=st.text(alphabet="abcXYZ09 _-\né", min_size=1, max_size=12))
def test_generated_archive_paths_cannot_escape_staging(native_cli, registry, package_info, tmp_path, guest_store, kind, name):
    contents, _requests, _faults, environment = registry
    canary = tmp_path / "canary"
    canary.write_bytes(b"preserved host bytes")
    if kind == "parent":
        extra = [("rootfs-tree/../../../../" + name, tarfile.REGTYPE, b"changed", "")]
    elif kind == "symlink":
        extra = [("rootfs-tree/escape", tarfile.SYMTYPE, b"", str(tmp_path)),
                 ("rootfs-tree/escape/canary", tarfile.REGTYPE, b"changed", "")]
    else:
        extra = [("rootfs-tree/" + name, tarfile.LNKTYPE, b"", str(canary))]
    contents.clear()
    contents.update(release(compressed_archive(extra)))
    root, store = tmp_path / "generated", guest_store
    result = install(native_cli, root, store, environment, package_info)
    assert result.returncode != 0, result.stdout
    assert canary.read_bytes() == b"preserved host bytes"
    assert not (root / "share").exists()
    assert not list((store / "trees/sha256").iterdir())


def test_native_client_reports_bad_proxy_and_ca_without_panicking(native_cli, package_info, tmp_path):
    for key, value in (("HTTPS_PROXY", "http://[invalid"), ("SSL_CERT_FILE", str(tmp_path / "missing-ca"))):
        environment = dict(os.environ, **{key: value})
        result = install(native_cli, tmp_path / "refused", tmp_path / "store", environment, package_info)
        assert result.returncode != 0
        assert "panic" not in result.stderr.lower()
        assert not (tmp_path / "refused/share").exists()


def test_verified_bundle_installer_and_proxy_restart_retain_guest(native_cli, registry, tmp_path, guest_store):
    bundle = os.environ.get("SAFEYOLO_NATIVE_BUNDLE")
    nats = os.environ.get("SAFEYOLO_COORD_NATS_BINARY")
    if not bundle or not nats:
        pytest.skip("set SAFEYOLO_NATIVE_BUNDLE and SAFEYOLO_COORD_NATS_BINARY for the real native bundle caller")
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "h"
    environment = {**environment, "HOME": str(guest_store.parents[3]),
                   "SAFEYOLO_NATS_TEST_INSTANCE": "guest-acquisition-installed", "TERM": "xterm-256color"}
    installer = Path(bundle) / "install.sh"
    result = subprocess.run([str(installer), "--root", str(root), "--command-dir", str(root / "commands")],
                            env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    selection = (root / "share/guest-selection.json").read_bytes()
    preserved = {name: (root / name).read_bytes() for name in ("policy.toml", "data/instance_id", "data/admin_token", "data/agent_token")}
    config = root / "config.toml"
    config.write_text(config.read_text().replace("admin_port = 9090", "admin_port = 0"))
    cli = root / "bin/safeyolo"

    def command(*arguments):
        return subprocess.run([str(cli), "--root", str(root), *arguments], env=environment,
                              capture_output=True, text=True, timeout=20)

    before = len(requests)
    try:
        coord = command("coord", "start", "--binary", nats)
        assert coord.returncode == 0, coord.stderr
        for _ in range(2):
            started = command("start")
            assert started.returncode == 0, started.stderr
            assert json.loads(command("status").stdout)["proxy_state"] == "running"
            stopped = command("stop")
            assert stopped.returncode == 0, stopped.stderr
        assert len(requests) == before
        assert (root / "share/guest-selection.json").read_bytes() == selection
        assert all((root / name).read_bytes() == data for name, data in preserved.items())
        refused = subprocess.run([str(installer), "--root", str(root), "--command-dir", str(root / "commands")],
                                 env=environment, capture_output=True, text=True, timeout=10)
        assert refused.returncode != 0 and "fresh root" in refused.stderr
        assert len(requests) == before
        assert all((root / name).read_bytes() == data for name, data in preserved.items())
    finally:
        assert command("stop").returncode == 0
        assert command("coord", "stop").returncode == 0
        assert json.loads(command("status").stdout)["proxy_state"] == "unavailable"
        assert json.loads(command("coord", "status").stdout)["state"] == "stopped"


def test_host_archive_smoke_runs_normal_native_guest_acquisition(registry, tmp_path, guest_store):
    """Exercise the actual archive wrapper against controlled anonymous TLS."""
    if os.uname().sysname != "Linux":
        pytest.skip("uses the existing tiny Linux guest payload; physical Mac proof belongs to #239")
    archive = os.environ.get("SAFEYOLO_TEST_HOST_ARCHIVE")
    nats = os.environ.get("SAFEYOLO_COORD_NATS_BINARY")
    if not archive or not nats:
        pytest.skip("requires a native host archive and pinned NATS binary")
    contents, requests, _faults, environment = registry
    guest = release(compressed_archive())
    contents.update(guest)
    # Keep host archives/installations on disk; only the tiny numeric-ownership
    # guest fixture uses the guest filesystem, as in the existing controls.
    # The maintained Unix listeners need a short parent, independently of the
    # long pytest node name; retain disk-backed host state in this owned root.
    test_home = tmp_path.parent / "archive"
    guest_link = test_home / ".local/share/safeyolo/guests"
    guest_link.parent.mkdir(parents=True)
    guest_store.mkdir(parents=True)
    guest_link.symlink_to(guest_store, target_is_directory=True)
    reports = tmp_path / "reports"
    with Path(archive).open("rb") as stream:
        archive_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    environment.update(HOME=str(test_home), SAFEYOLO_BLACKBOX_ARTIFACTS_DIR=str(reports))
    result = subprocess.run([
        str(REPO / "tests/blackbox/run-installed-package.sh"), "--package", archive,
        "--sha256", archive_digest,
    ], env=environment, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout[-6000:] + result.stderr[-6000:]
    smoke = json.loads((reports / "host-package.json").read_text())
    assert smoke["status"] == "host_package_passed" and smoke["cleanup"]["status"] == "stopped"
    assert smoke["cli"]["source"]["root"] is None
    root = Path(smoke["cli"]["package_root"])
    selected = json.loads((root / "share/guest-selection.json").read_text())
    architecture = {"aarch64": "arm64", "x86_64": "amd64"}[os.uname().machine]
    assert selected["platform"] == f"linux/{architecture}"
    assert selected["index"]["digest"] == digest(guest["manifests/compat-v1"])
    assert selected["archive"]["digest"] == digest(compressed_archive())
    assert (root / "share/rootfs-tree").stat().st_uid == 100000
    assert requests.count(PREFIX + "manifests/compat-v1") == 1
    continuity = json.loads((reports / "installed-continuity.json").read_text())
    assert continuity["result"] == "installed_native_continuity_passed"
    assert continuity["agents_started"] == 0 and continuity["cleanup"] == "stopped"
    assert f"sha256:{archive_digest}" in result.stdout
