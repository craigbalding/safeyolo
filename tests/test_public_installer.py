"""Drive public host acquisition over owned HTTPS with real curl and tar.

Controlled ELF packages test the installer boundary. Clean host and first-agent
proof remain separate. The TLS parent serves only this fixture's local server.
"""

import gzip
import hashlib
import io
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.proxy_contracts.test_native_coord_operator import terminal
from tests.test_guest_acquisition import compressed_archive, digest, release
from tests.test_guest_acquisition import guest_store as _guest_store
from tests.test_guest_acquisition import native_cli as _native_cli
from tests.test_guest_acquisition import registry as _registry
from tests.test_host_packages import executable, run
from tests.test_host_packages import musl_runtime as _musl_runtime
from tests.test_host_packages import package_inputs as _package_inputs

# Reuse fixtures in standalone and combined collection without plugin registration.
guest_store = _guest_store
registry = _registry
package_inputs = _package_inputs
musl_runtime = _musl_runtime
native_cli = _native_cli

REPO = Path(__file__).resolve().parents[1]
RELEASES = "/craigbalding/safeyolo/releases"


@pytest.mark.parametrize("encoding", ["single", "concatenated", "truncated", "checksum", "invalid"])
def test_native_host_package_gunzip_checks_complete_stream(native_cli, tmp_path, encoding):
    payload = bytes(range(256)) * 2049
    compressed = gzip.compress(payload)
    if encoding == "concatenated":
        compressed = gzip.compress(payload[:100001]) + gzip.compress(payload[100001:])
    elif encoding == "truncated":
        compressed = compressed[:-4]
    elif encoding == "checksum":
        compressed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
    elif encoding == "invalid":
        compressed = b"not a gzip archive"
    archive = tmp_path / "host package.tar.gz"
    archive.write_bytes(compressed)
    result = subprocess.run([str(native_cli), "host-package", "gunzip", str(archive)], capture_output=True)
    if encoding in ("single", "concatenated"):
        assert result.returncode == 0, result.stderr
        assert result.stdout == payload
    else:
        assert result.returncode != 0


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("decoder", ["native", "legacy"])
def test_bootstrap_uses_available_verified_native_gzip_decoder(public_release, native_cli, tmp_path, decoder):
    _contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    marker = tmp_path / "decoder-calls"
    environment = {**environment, "PACKAGE_HOST_GUNZIP_CALLS": str(marker)}
    if decoder == "native":
        environment["PACKAGE_HOST_GUNZIP_CLI"] = str(native_cli)
    result = run("bash", str(bootstrap), env=environment)
    assert result.returncode == 0, result.stderr
    assert (root / "config.toml").is_file()
    with tarfile.open(archive) as package:
        assert (root / "bin/safeyolo").read_bytes() == package.extractfile(
            archive.name.removesuffix(".tar.gz") + "/bin/safeyolo").read()
        for relative in ("bin", "bin/safeyolo"):
            member = package.getmember(archive.name.removesuffix(".tar.gz") + "/" + relative)
            assert (root / relative).stat().st_mode & 0o777 == member.mode & 0o777
    if decoder == "native":
        calls = marker.read_text().splitlines()
        assert calls[:4] == ["host-package", "--help", "host-package", "gunzip"]
    else:
        assert not marker.exists()
    assert requests.count(f"{base}/{archive.name}") == 1
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("damage", ["gzip-trailer", "tar"])
def test_native_gzip_or_tar_failure_stops_bootstrap_and_allows_retry(public_release, native_cli, tmp_path, damage):
    contents, _requests, _faults, environment, bootstrap, root, base, archive = public_release
    original = contents[f"{base}/{archive.name}"]
    bad = original[:-4] if damage == "gzip-trailer" else gzip.compress(b"not a tar archive")
    contents[f"{base}/{archive.name}"] = bad
    checksums = contents[f"{base}/SHA256SUMS"]
    contents[f"{base}/SHA256SUMS"] = checksums.replace(
        hashlib.sha256(original).hexdigest().encode(), hashlib.sha256(bad).hexdigest().encode())
    marker = tmp_path / "decoder-calls"
    environment = {**environment, "PACKAGE_HOST_GUNZIP_CLI": str(native_cli),
                   "PACKAGE_HOST_GUNZIP_CALLS": str(marker)}
    result = run("bash", str(bootstrap), env=environment)
    assert result.returncode != 0
    assert "gunzip" in marker.read_text().splitlines()
    assert not root.exists()
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
    contents[f"{base}/{archive.name}"] = original
    contents[f"{base}/SHA256SUMS"] = checksums
    retried = run("bash", str(bootstrap), env=environment)
    assert retried.returncode == 0, retried.stderr
    assert (root / "config.toml").is_file()


def codex_release(tmp_path, contents, *, young_latest=False, version="9.9.9"):
    """Complete controlled ELF package for the real native acquisition boundary."""
    payload = tmp_path / "codex-release"
    for name in ("bin/codex", "bin/codex-code-mode-host", "codex-path/rg"):
        path = payload / name
        path.parent.mkdir(parents=True, exist_ok=True)
        executable(path, f"codex-cli {version}" if name == "bin/codex" else "companion fixture")
    (payload / "codex-resources").mkdir()
    (payload / "codex-resources/resource").write_bytes(b"adjacent resource; preserve these bytes")
    (payload / "LICENSE").write_bytes(b"upstream notice; preserve this file too")
    tar = subprocess.check_output(["tar", "-cf", "-", "-C", str(payload), "."])
    package = subprocess.check_output(["zstd", "-q", "-c"], input=tar)
    architecture = "x86_64" if os.uname().machine == "x86_64" else "aarch64"
    asset = f"codex-package-{architecture}-unknown-linux-musl.tar.zst"
    path = f"/openai/codex/releases/download/rust-v{version}/{asset}"
    metadata = {"id": 1, "name": version, "tag_name": f"rust-v{version}", "created_at": "2020-01-01T00:00:00Z",
                "published_at": "2020-01-01T00:00:00Z", "draft": False, "prerelease": False,
                "assets": [{"id": 2, "name": asset, "digest": digest(package), "size": len(package),
                            "url": "https://github.com" + path, "browser_download_url": "https://github.com" + path}]}
    contents["/repos/openai/codex/releases/latest"] = json.dumps(metadata).encode()
    contents["/repos/openai/codex/releases"] = json.dumps([metadata]).encode()
    if young_latest:
        published = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        latest = {**metadata, "id": 3, "name": "9.10.0", "tag_name": "rust-v9.10.0",
                  "created_at": published, "published_at": published,
                  "assets": [{**metadata["assets"][0], "id": 4,
                              "url": "https://github.com" + path.replace(version, "9.10.0"),
                              "browser_download_url": "https://github.com" + path.replace(version, "9.10.0")}]}
        contents["/repos/openai/codex/releases/latest"] = json.dumps(latest).encode()
        contents["/repos/openai/codex/releases"] = json.dumps([latest, metadata]).encode()
    contents[path] = package
    return payload, path, metadata


@pytest.mark.parametrize("encoding", ["gzip", "invalid-gzip"])
def test_codex_prefetch_decodes_compressed_metadata_before_selection(registry, native_cli, tmp_path, encoding):
    contents, requests, faults, environment = registry
    _payload, asset, metadata = codex_release(tmp_path, contents, young_latest=True)
    releases = "/repos/openai/codex/releases"
    contents[releases] = gzip.compress(contents[releases]) if encoding == "gzip" else b"invalid gzip"
    faults["gzip"] = releases
    environment["CURL_CA_BUNDLE"] = environment["SSL_CERT_FILE"]
    output = tmp_path / "prefetched"
    result = run(str(native_cli), "codex", "prefetch", str(output), env=environment)
    if encoding == "invalid-gzip":
        assert result.returncode != 0 and not output.exists()
        assert requests == [releases]
    else:
        assert result.returncode == 0, result.stderr
        assert (output / "version").read_text().strip() == "9.9.9"
        assert (output / "upstream.json").read_text() == json.dumps(metadata)
        assert requests == [releases, asset]


@pytest.mark.parametrize("fault", ["young", "future", "draft", "prerelease", "tag", "date",
                                   "missing-asset", "missing-digest", "url", "duplicate-asset",
                                   "missing-date"])
def test_codex_prefetch_selects_newest_eligible_complete_release(registry, native_cli, tmp_path, fault):
    contents, requests, _faults, environment = registry
    _payload, asset, metadata = codex_release(tmp_path, contents, version="9.10.0")
    metadata["published_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 24 * 3600 - 60))
    lower = {**metadata, "tag_name": "rust-v9.9.9", "assets": [
        {**metadata["assets"][0], "browser_download_url": "https://github.com" + asset.replace("9.10.0", "9.9.9")}]}
    excluded = {**metadata, "tag_name": "rust-v10.0.0", "assets": [
        {**metadata["assets"][0], "browser_download_url": "https://github.com" + asset.replace("9.10.0", "10.0.0")}]}
    if fault in ("young", "future"):
        offset = -24 * 3600 + 60 if fault == "young" else 3600
        excluded["published_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))
    elif fault in ("draft", "prerelease"):
        excluded[fault] = True
    elif fault == "tag":
        excluded["tag_name"] += "-alpha.1"
    elif fault == "date":
        excluded["published_at"] = "unknown"
    elif fault == "missing-asset":
        excluded["assets"] = []
    elif fault == "missing-digest":
        del excluded["assets"][0]["digest"]
    elif fault == "url":
        excluded["assets"][0]["browser_download_url"] = "https://github.com" + asset
    elif fault == "duplicate-asset":
        excluded["assets"] *= 2
    elif fault == "missing-date":
        del excluded["published_at"]
    # Neither response order nor lexicographic version order selects 9.10.0.
    contents["/repos/openai/codex/releases"] = json.dumps([metadata, excluded, lower]).encode()
    environment["CURL_CA_BUNDLE"] = environment["SSL_CERT_FILE"]
    output = tmp_path / "prefetched"
    result = run(str(native_cli), "codex", "prefetch", str(output), env=environment)
    if fault == "missing-date":
        assert result.returncode != 0 and not output.exists()
        assert requests == ["/repos/openai/codex/releases"]
    else:
        assert result.returncode == 0, result.stderr
        assert (output / "version").read_text().strip() == "9.10.0"
        assert (output / "upstream.json").read_text() == json.dumps(metadata)
        assert requests == ["/repos/openai/codex/releases", asset]


@pytest.mark.parametrize("refusal", [None, "source", "target", "existing"])
def test_verified_prefetch_reaches_guest_without_second_selection_or_transfer(registry, native_cli, tmp_path, refusal):
    mise = shutil.which("mise")
    if not mise:
        pytest.skip("real mise is required to check existing installed selections")
    contents, requests, _faults, environment = registry
    payload, asset, metadata = codex_release(tmp_path, contents, young_latest=True)
    contents["/repos/openai/codex/releases/tags/rust-v9.9.9"] = json.dumps(metadata).encode()
    environment = {key: value for key, value in environment.items()
                   if not key.startswith(("MISE_", "__MISE_", "SAFEYOLO_CODEX_")) and key != "BASH_ENV"}
    environment["CURL_CA_BUNDLE"] = environment["SSL_CERT_FILE"]
    output = tmp_path / "prefetched"
    result = run(str(native_cli), "codex", "prefetch", str(output), env=environment)
    assert result.returncode == 0, result.stderr
    assert (output / "version").read_text().strip() == "9.9.9"
    assert json.loads((output / "upstream.json").read_text())["tag_name"] == metadata["tag_name"]
    assert requests == ["/repos/openai/codex/releases", asset]
    home = tmp_path / "agent"
    managed = home / ".safeyolo"
    managed.mkdir(parents=True)
    if refusal in ("source", "target"):
        (output / refusal).write_text("mismatched binding\n")
    elif refusal == "existing":
        (managed / "codex-package").mkdir()
        (managed / "codex-package/keep").write_bytes(b"retained agent state")
    imported = run(str(native_cli), "codex", "import", str(output), str(home), env=environment)
    if refusal:
        assert imported.returncode != 0
        assert (output / "payload/bin/codex").exists()
        if refusal == "existing":
            assert (managed / "codex-package/keep").read_bytes() == b"retained agent state"
        else:
            assert not (managed / "codex-package").exists()
        return
    assert imported.returncode == 0, imported.stderr
    assert not (output / "payload").exists()
    for path in payload.rglob("*"):
        if path.is_file():
            assert (managed / "codex-package/payload" / path.relative_to(payload)).read_bytes() == path.read_bytes()
    environment.update(HOME=str(home), PATH=f"{Path(mise).parent}:/usr/bin:/bin")
    first = run(str(REPO / "contrib/codex-command.sh"), "--probe", env=environment)
    assert first.returncode == 0, first.stderr
    assert first.stdout.strip() == "codex-cli 9.9.9"
    assert requests == ["/repos/openai/codex/releases", asset]
    # A newly eligible version must be reported on reentry, without replacing
    # the complete payload selected for this agent's first launch.
    available = json.loads(contents["/repos/openai/codex/releases/latest"])
    for field in ("published_at", "created_at"):
        available[field] = metadata[field]
    contents["/repos/openai/codex/releases/latest"] = json.dumps(available).encode()
    contents["/repos/openai/codex/releases"] = json.dumps([available, metadata]).encode()
    contents["/repos/openai/codex/releases/tags/rust-v9.10.0"] = json.dumps(available).encode()
    repeat = run(str(REPO / "contrib/codex-command.sh"), "--probe", env=environment)
    assert repeat.returncode == 0, repeat.stderr
    assert repeat.stdout.strip() == "codex-cli 9.9.9"
    assert "9.10.0 is available; not upgrading automatically" in repeat.stderr
    assert f"run: mise use -g github:openai/codex[asset_pattern={Path(asset).name},version_prefix=rust-v,bin_path=bin]@9.10.0" in repeat.stderr
    assert requests.count(asset) == 1
    assert available["assets"][0]["browser_download_url"].removeprefix("https://github.com") not in requests
    selected, = (home / ".mise/installs/github-openai-codex").glob("9.9.9*")
    assert (selected / "bin/codex").samefile(managed / "codex-package/payload/bin/codex")
    assert (managed / "codex-package/payload/LICENSE").read_bytes() == (payload / "LICENSE").read_bytes()


@pytest.mark.parametrize("interruption", [signal.SIGINT, signal.SIGTERM])
def test_interrupted_codex_prefetch_removes_partial_package_and_can_retry(registry, native_cli, tmp_path, interruption):
    contents, _requests, faults, environment = registry
    _payload, asset, _metadata = codex_release(tmp_path, contents)
    environment["CURL_CA_BUNDLE"] = environment["SSL_CERT_FILE"]
    output = tmp_path / "prefetched"
    faults["pause"] = asset
    process = subprocess.Popen([str(native_cli), "codex", "prefetch", str(output)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert faults["entered"].wait(timeout=10)
        process.send_signal(interruption)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode != 0 and "interrupted" in stderr, (stdout, stderr)
        assert not output.exists()
        assert not list(tmp_path.glob("codex-*/package.tar.zst"))
    finally:
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    faults["pause"] = None
    retried = run(str(native_cli), "codex", "prefetch", str(output), env=environment)
    assert retried.returncode == 0, retried.stderr
    assert (output / "version").read_text().strip() == "9.9.9"


@pytest.mark.parametrize("fault", [None, "digest", "partial", "young", "custom-age", "pin"])
def test_native_codex_prefetch_verifies_complete_package_and_preserves_selection(registry, native_cli, tmp_path, fault):
    contents, requests, faults, environment = registry
    payload, asset, metadata = codex_release(tmp_path, contents)
    if fault == "digest":
        metadata["assets"][0]["digest"] = "sha256:" + "0" * 64
    elif fault == "partial":
        faults["partial"] = asset
    elif fault == "young":
        metadata["published_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    elif fault == "custom-age":
        environment["SAFEYOLO_MIN_RELEASE_AGE"] = "72h"
    elif fault == "pin":
        environment["SAFEYOLO_CODEX_NATIVE_SPEC"] = "aqua:openai/codex@9.9.9"
    contents["/repos/openai/codex/releases/latest"] = json.dumps(metadata).encode()
    contents["/repos/openai/codex/releases"] = json.dumps([metadata]).encode()
    environment["CURL_CA_BUNDLE"] = environment["SSL_CERT_FILE"]
    output = tmp_path / "prefetched"
    result = run(str(native_cli), "codex", "prefetch", str(output), env=environment)
    if fault in ("digest", "partial"):
        assert result.returncode != 0, result.stdout
        assert not output.exists()
        faults["partial"] = None
        metadata["assets"][0]["digest"] = digest(contents[asset])
        contents["/repos/openai/codex/releases/latest"] = json.dumps(metadata).encode()
        contents["/repos/openai/codex/releases"] = json.dumps([metadata]).encode()
        result = run(str(native_cli), "codex", "prefetch", str(output), env=environment)
    if fault in ("young", "custom-age", "pin"):
        assert result.returncode == 0, result.stderr
        assert not output.exists() and asset not in requests
    else:
        assert result.returncode == 0, result.stderr
        for path in payload.rglob("*"):
            if path.is_file():
                assert (output / "payload" / path.relative_to(payload)).read_bytes() == path.read_bytes()
        assert (output / "version").read_text().strip() == "9.9.9"
        assert requests.count(asset) == (2 if fault else 1)
    assert not [path for path in tmp_path.glob("codex-*") if path != payload]


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
def test_complete_codex_package_arrives_during_host_transfer_and_is_handed_to_launch(public_release, native_cli, tmp_path):
    contents, requests, faults, environment, bootstrap, root, base, archive = public_release
    _payload, asset, _metadata = codex_release(tmp_path, contents, young_latest=True)
    marker = tmp_path / "launch-inputs"
    handoff = tmp_path / "codex-handoff"
    environment.update(PACKAGE_CODEX_PREFETCH_CLI=str(native_cli), PACKAGE_LAUNCH_CALLS=str(marker),
                       PACKAGE_CODEX_HANDOFF=str(handoff))
    faults["pause"] = f"{base}/{archive.name}"
    process = subprocess.Popen(["bash", str(bootstrap), "--launch", "--harness", "codex"], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert faults["entered"].wait(timeout=10)
        cache = Path(environment["HOME"]) / ".cache/safeyolo/host-packages"
        deadline = time.monotonic() + 5
        while not list(cache.glob("*/acquire.*/codex/version")):
            assert time.monotonic() < deadline, "Codex acquisition waited for host extraction or sandbox startup"
            time.sleep(0.01)
        assert not root.exists() and process.poll() is None
        assert requests.count(asset) == 1
        faults["resume"].set()
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, stderr
        assert stdout.count("Verified SafeYolo package:") == 1
        arguments = marker.read_text().splitlines()
        assert arguments[-2:] == ["--harness", "codex"]
        assert handoff.read_text().endswith("/codex")
        assert requests.count(asset) == 1
        assert (root / "config.toml").is_file()
        assert not list(cache.glob("*/acquire.*"))
    finally:
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.fixture
def public_release(package_inputs, registry, tmp_path, request):
    contents, requests, faults, environment = registry
    output = tmp_path / "release"
    runtime_tools = request.getfixturevalue("musl_runtime") if getattr(request, "param", None) == "musl" else None
    if getattr(request, "param", None) == "native":
        bundle = os.environ.get("SAFEYOLO_NATIVE_BUNDLE")
        if not bundle:
            pytest.skip("set SAFEYOLO_NATIVE_BUNDLE to test candidate installers with retained product bytes")
        # Retain the product executables' actual source/profile. Only the
        # candidate shell installer changes in this local HTTPS fixture.
        metadata = dict(line.split("=", 1) for line in (Path(bundle) / "package-info").read_text().splitlines())
        name = f'safeyolo-{metadata["platform"]}-{metadata["profile"]}'
        assert metadata["profile"] == "production"
        output.mkdir()
        package = output / name
        shutil.copytree(bundle, package)
        shutil.copy2(REPO / "scripts/install_native.sh", package / "install_native.sh")
        sums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(package)}\n"
                       for path in sorted(package.rglob("*")) if path.is_file() and path.name != "SHA256SUMS")
        (package / "SHA256SUMS").write_text(sums)
        with tarfile.open(output / f"{name}.tar.gz", "w:gz") as stream:
            stream.add(package, arcname=name)
        tag = f'host-{metadata["source_commit"]}'
        (output / "install-safeyolo.sh").write_text((REPO / "install.sh").read_text().replace("\nrelease=\n", f"\nrelease={tag}\n"))
    else:
        built = run(*package_inputs[4], "--output", str(output))
        assert built.returncode == 0, built.stderr
        tag = f"host-{package_inputs[5]}"
    archive, = (path for path in output.glob("*.tar.gz") if not path.name.endswith("-guest-download.tar.gz"))
    base = f"{RELEASES}/download/{tag}"
    contents[f"{base}/{archive.name}"] = archive.read_bytes()
    archives = sorted(output.glob("*.tar.gz"))
    for path in archives:
        contents[f"{base}/{path.name}"] = path.read_bytes()
    contents[f"{base}/SHA256SUMS"] = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in archives
    ).encode()
    contents[f"{base}/install-safeyolo.sh"] = (output / "install-safeyolo.sh").read_bytes()
    contents[f"{RELEASES}/tag/{tag}"] = b"fixture release page"
    faults["host_release"] = tag
    home = tmp_path / "operator"
    commands = home / ".local/bin"
    commands.mkdir(parents=True)
    runtime_path = f"{runtime_tools}:" if runtime_tools else ""
    environment = {**environment, "HOME": str(home), "PATH": f"{commands}:{runtime_path}/usr/local/bin:/usr/bin:/bin",
                   "CURL_CA_BUNDLE": environment["SSL_CERT_FILE"]}
    for key in ("SAFEYOLO_CONFIG_DIR", "SAFEYOLO_HOME", "SAFEYOLO_NATIVE_CONFIG_PATH", "BASH_ENV"):
        environment.pop(key, None)
    downloaded = tmp_path / "downloaded/install-safeyolo.sh"
    downloaded.parent.mkdir()
    fetched = run("curl", "--fail", "--location", "--silent", "--show-error", "--proto", "=https",
                  "--proto-redir", "=https", "--output", str(downloaded),
                  f"https://github.com{base}/install-safeyolo.sh", env=environment)
    assert fetched.returncode == 0, fetched.stderr
    assert downloaded.read_bytes() == (output / "install-safeyolo.sh").read_bytes()
    return contents, requests, faults, environment, downloaded, home / ".safeyolo", base, archive


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["glibc", "musl"], indirect=True)
def test_downloaded_bootstrap_installs_without_checkout_and_exposes_same_terminal_command(public_release):
    _contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    environment = {**environment, "BOOTSTRAP": str(bootstrap)}
    # Additional commands observe the same shell after installation. They are
    # validation, not prerequisites hidden in the proposed user workflow.
    result = run("/bin/bash", "--noprofile", "--norc", "-c",
                 'set -e\nbash "$BOOTSTRAP" --yes\ncommand -v safeyolo\nsafeyolo --version', env=environment)
    assert result.returncode == 0, result.stderr
    assert (root / "bin/safeyolo").read_bytes().startswith(b"\x7fELF")
    assert str(Path(environment["HOME"]) / ".local/bin/safeyolo") in result.stdout
    assert (root / "share/guest-selection.json").exists()
    assert (root / "install_native.sh").is_file()
    assert f"{base}/{archive.name}" in requests
    if "-musl-" in archive.name:
        assert "libc=musl\n" in (root / "package-info").read_text()
    assert f"{RELEASES}/latest" not in requests
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("status", [0, 37])
def test_bootstrap_forwards_literal_launch_arguments_and_exit_status(public_release, tmp_path, status):
    _contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    marker = tmp_path / "launch-called"
    environment = {**environment, "PACKAGE_LAUNCH_CALLS": str(marker), "PACKAGE_LAUNCH_EXIT": str(status)}
    arguments = [str(tmp_path / "workspace with spaces; literal"), "--name", "chosen", "--harness", "claude"]
    result = run("bash", str(bootstrap), "--launch", *arguments, env=environment)
    assert result.returncode == status, result.stderr
    assert marker.read_text().splitlines() == ["--root", str(root), "agent", "launch", *arguments]
    assert (root / "bin/safeyolo").is_file()
    assert requests.count(f"{base}/{archive.name}") == 1
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("fault", ["checksum", "duplicate-checksum", "partial", "inner-checksum"])
@pytest.mark.parametrize("decoder", ["legacy", "native"])
def test_bad_host_download_never_activates_and_retry_preserves_another_installation(
        public_release, native_cli, tmp_path, fault, decoder):
    contents, requests, faults, environment, bootstrap, root, base, archive = public_release
    marker = tmp_path / "decoder-calls"
    if decoder == "native":
        environment = {**environment, "PACKAGE_HOST_GUNZIP_CLI": str(native_cli),
                       "PACKAGE_HOST_GUNZIP_CALLS": str(marker)}
    unrelated = tmp_path / "another-instance/policy.toml"
    unrelated.parent.mkdir()
    unrelated.write_bytes(b"operator policy; keep unchanged")
    original = dict(contents)
    if fault == "checksum":
        contents[f"{base}/{archive.name}"] += b"corrupt transfer"
    elif fault == "duplicate-checksum":
        contents[f"{base}/SHA256SUMS"] *= 2
    elif fault == "partial":
        faults["partial"] = f"{base}/{archive.name}"
    else:
        expanded = tmp_path / "expanded"
        with tarfile.open(archive) as stream:
            stream.extractall(expanded, filter="data")
        package, = expanded.iterdir()
        (package / "assets/guest/guest-init").write_bytes(b"changed packaged input")
        changed = tmp_path / "changed.tar.gz"
        with tarfile.open(changed, "w:gz") as stream:
            stream.add(package, arcname=package.name)
        contents[f"{base}/{archive.name}"] = changed.read_bytes()
        contents[f"{base}/SHA256SUMS"] = contents[f"{base}/SHA256SUMS"].replace(
            hashlib.sha256(archive.read_bytes()).hexdigest().encode(),
            hashlib.sha256(changed.read_bytes()).hexdigest().encode())
    refused = run("bash", str(bootstrap), env=environment)
    assert refused.returncode != 0
    assert not root.exists()
    assert unrelated.read_bytes() == b"operator policy; keep unchanged"
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
    if decoder == "native" and fault != "duplicate-checksum":
        # Decoding may precede the outer checksum. Installation still waits
        # for both that checksum and complete gzip/tar validation.
        assert "gunzip" in marker.read_text().splitlines()
    contents.update(original)
    faults["partial"] = None
    retried = run("bash", str(bootstrap), env=environment)
    assert retried.returncode == 0, retried.stderr
    assert (root / "config.toml").exists()
    assert unrelated.read_bytes() == b"operator policy; keep unchanged"
    assert requests.count(f"{base}/{archive.name}") == (1 if fault == "duplicate-checksum" else 2)


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("decoder", ["legacy", "native"])
@pytest.mark.parametrize("outcome", ["installed", "checksum", "interrupted"])
def test_host_unpack_overlaps_transfer_without_activating_unverified_files(
        public_release, native_cli, tmp_path, decoder, outcome):
    contents, requests, faults, environment, bootstrap, root, base, archive = public_release
    path = f"{base}/{archive.name}"
    if outcome == "checksum":
        contents[path] += b"incorrect release bytes"
    faults["pause_after"] = path
    host_calls = tmp_path / "host-calls"
    environment = {**environment, "PACKAGE_HOST_CALLS": str(host_calls)}
    if decoder == "native":
        environment["PACKAGE_HOST_GUNZIP_CLI"] = str(native_cli)
    process = subprocess.Popen(["bash", str(bootstrap)], env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert faults["entered"].wait(timeout=10), "host transfer did not reach its held suffix"
        cache = Path(environment["HOME"]) / ".cache/safeyolo/host-packages"
        deadline = time.monotonic() + 10
        while not list(cache.glob("*/acquire.*/host/*/bin/safeyolo")):
            assert time.monotonic() < deadline and process.poll() is None, "unpacking waited for the complete host transfer"
            time.sleep(0.01)
        assert not root.exists() and not host_calls.exists()
        assert process.poll() is None
        if outcome == "interrupted":
            # Signal only the bootstrap. It must reap all of its FIFO children.
            process.terminate()
        else:
            faults["resume"].set()
        stdout, stderr = process.communicate(timeout=10)
        if outcome == "installed":
            assert process.returncode == 0, stderr
            assert (root / "config.toml").is_file() and host_calls.exists()
        else:
            assert process.returncode == (143 if outcome == "interrupted" else 1), (stdout, stderr)
            assert not root.exists() and not host_calls.exists()
        assert not list(cache.rglob("acquire.*"))
        assert requests.count(path) == 1
    finally:
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("decoder", ["legacy", "native"])
def test_rejected_host_archive_cleans_directories_without_owner_permissions(
        public_release, native_cli, decoder):
    contents, _requests, _faults, environment, bootstrap, root, base, archive = public_release
    name = archive.name.removesuffix(".tar.gz")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as package:
        directory = tarfile.TarInfo(f"{name}/locked")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0
        package.addfile(directory)
        entry = tarfile.TarInfo(f"{name}/locked/file")
        entry.mode = 0o600
        entry.size = 1
        package.addfile(entry, io.BytesIO(b"x"))
    # Keep the published checksum so rejection must clean the extracted modes.
    contents[f"{base}/{archive.name}"] = stream.getvalue()
    if decoder == "native":
        environment = {**environment, "PACKAGE_HOST_GUNZIP_CLI": str(native_cli)}
    result = run("bash", str(bootstrap), env=environment)
    assert result.returncode != 0
    assert "Host archive checksum failed" in result.stderr
    assert not root.exists()
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("decoder", ["legacy", "native"])
@pytest.mark.parametrize("extractor", ["tar", "bsdtar"])
@pytest.mark.parametrize("escape", ["parent", "absolute", "symlink", "hardlink"])
def test_unverified_host_extraction_preserves_files_outside_its_stage(
        public_release, native_cli, tmp_path, decoder, extractor, escape):
    contents, _requests, _faults, environment, bootstrap, root, base, archive = public_release
    if extractor == "bsdtar":
        binary = shutil.which(extractor)
        if not binary:
            pytest.skip("install libarchive-tools to exercise the BSD tar extractor")
        tools = tmp_path / "extractor"
        tools.mkdir()
        (tools / "tar").symlink_to(binary)
        environment = {**environment, "PATH": f"{tools}:{environment['PATH']}"}
    outside = tmp_path / "operator-data/keep"
    outside.parent.mkdir()
    outside.write_bytes(b"operator data")
    name = archive.name.removesuffix(".tar.gz")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as package:
        if escape in ("symlink", "hardlink"):
            link = tarfile.TarInfo(f"{name}/pivot")
            link.type = tarfile.SYMTYPE if escape == "symlink" else tarfile.LNKTYPE
            link.linkname = str(outside.parent if escape == "symlink" else outside)
            package.addfile(link)
            target = f"{name}/pivot/keep" if escape == "symlink" else f"{name}/pivot"
        else:
            target = str(outside) if escape == "absolute" else "../" * 20 + str(outside).lstrip("/")
        entry = tarfile.TarInfo(target)
        entry.size = len(b"changed")
        package.addfile(entry, io.BytesIO(b"changed"))
    # The expected release checksum remains unchanged. Extraction can already
    # see these bytes, but cannot follow archive paths into operator data.
    contents[f"{base}/{archive.name}"] = stream.getvalue()
    if decoder == "native":
        environment = {**environment, "PACKAGE_HOST_GUNZIP_CLI": str(native_cli)}
    result = run("bash", str(bootstrap), env=environment)
    assert result.returncode != 0
    assert outside.read_bytes() == b"operator data"
    assert not root.exists()
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
def test_interrupted_host_download_cleans_staging_and_can_resume(public_release):
    _contents, _requests, faults, environment, bootstrap, root, base, archive = public_release
    faults["pause"] = f"{base}/{archive.name}"
    process = subprocess.Popen(["bash", str(bootstrap)], env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert faults["entered"].wait(timeout=10), "bootstrap did not reach the real archive download"
        os.killpg(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode != 0, (stdout, stderr)
        assert not root.exists()
        assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
    finally:
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    faults["pause"] = None
    result = run("bash", str(bootstrap), env=environment)
    assert result.returncode == 0, result.stderr
    assert (root / "config.toml").exists()


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("interrupt", [False, True])
def test_guest_archive_arrives_before_host_transfer_finishes(public_release, native_cli, tmp_path, interrupt):
    contents, requests, faults, environment, bootstrap, root, base, archive = public_release
    guest = compressed_archive()
    data = release(guest)
    index = digest(data["manifests/compat-v1"])
    contents.update(data)
    # The producer fixture's ELF delegates only guest download to the real CLI.
    # Existing direct native controls prove extraction and installed selection.
    marker = tmp_path / "installer-guest-arguments"
    environment = {**environment, "PACKAGE_GUEST_DOWNLOAD_CLI": str(native_cli), "PACKAGE_GUEST_CALLS": str(marker)}
    faults["pause"] = f"{base}/{archive.name}"
    arrived = threading.Event()
    faults["written"]["blobs/" + digest(guest)] = arrived
    process = subprocess.Popen(["bash", str(bootstrap)], env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    started = time.monotonic()
    try:
        assert faults["entered"].wait(timeout=10)
        assert arrived.wait(timeout=10), "guest transfer waited for the blocked host body"
        # A server write is earlier than the native verifier's fsync/commit.
        # Observe the completed native result before testing retained reuse.
        deadline = time.monotonic() + 5
        cache = Path(environment["HOME"]) / ".cache/safeyolo/host-packages"
        while not any(path.read_text().strip() == index for path in cache.rglob("guest-index")):
            assert time.monotonic() < deadline, "native guest download did not commit its verified index"
            time.sleep(0.01)
        assert process.poll() is None and not root.exists()
        assert requests.count("/v2/craigbalding/safeyolo-guest/manifests/compat-v1") == 1
        if interrupt:
            # Signal the bootstrap alone: it owns and reaps both children.
            process.terminate()
        else:
            faults["resume"].set()
        stdout, stderr = process.communicate(timeout=15)
        if interrupt:
            assert process.returncode == 143, (stdout, stderr)
            assert not root.exists()
        else:
            assert process.returncode == 0, stderr
            arguments = marker.read_text().splitlines()
            assert arguments[arguments.index("--index") + 1] == index
            assert (root / "config.toml").exists()
        assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
        store = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
        # Early preparation may create the tree cache or retain a verified
        # tree. It must not leave an incomplete extraction there.
        assert not list((store / "trees").rglob("extract-*"))
        assert all(len(path.name) == 64 for path in (store / "blobs/sha256").iterdir())
        print(f"real TLS guest archive completed while host body was held; controlled run {time.monotonic() - started:.3f}s")
    finally:
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    if interrupt:
        faults["pause"] = None
        retried = run("bash", str(bootstrap), env=environment)
        assert retried.returncode == 0, retried.stderr
        assert requests.count("/v2/craigbalding/safeyolo-guest/blobs/" + digest(guest)) == 1


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("help_result", ["supported", "absent", "failed"])
def test_bootstrap_consumes_complete_guest_help_and_preserves_failure(public_release, tmp_path, help_result):
    _contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    helper = tmp_path / "guest-help"
    completed = tmp_path / "help-completed"
    arguments = tmp_path / "early-guest-arguments"
    helper.write_text(
        f"#!{sys.executable}\n"
        "import sys\nfrom pathlib import Path\n"
        "if sys.argv[1:] == ['guest', 'download', '--help']:\n"
        f"    print({'--prepare' if help_result != 'absent' else 'guest download help'!r}, flush=True)\n"
        # Exceed the pipe buffer after the match so an early reader exit
        # makes the producer fail before it can complete successfully.
        "    sys.stdout.write('Further help output.\\n' * 65536)\n"
        "    sys.stdout.flush()\n"
        f"    Path({str(completed)!r}).touch()\n"
        f"    sys.exit({37 if help_result == 'failed' else 0})\n"
        f"Path({str(arguments)!r}).write_text('\\n'.join(sys.argv[1:]))\n"
        f"print('sha256:{'b' * 64}')\n"
    )
    helper.chmod(0o755)
    result = run("bash", str(bootstrap), env={**environment, "PACKAGE_GUEST_DOWNLOAD_CLI": str(helper)})
    assert result.returncode == 0, result.stderr
    assert completed.exists(), result.stderr
    assert "BrokenPipeError" not in result.stderr
    assert ("--prepare" in arguments.read_text().splitlines()) == (help_result == "supported")
    assert (root / "config.toml").is_file()
    assert requests.count(f"{base}/{archive.name}") == 1
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("outcome", ["installed", "host-integrity", "binding", "declined"])
@pytest.mark.parametrize("held_phase", ["host-extraction", "guest-preparation"])
def test_guest_cache_is_prepared_during_host_extraction_without_early_activation(
        public_release, native_cli, guest_store, tmp_path, outcome, held_phase):
    contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    guest = compressed_archive()
    guest_release = release(guest)
    selected_index = digest(guest_release["manifests/compat-v1"])
    contents.update(guest_release)
    store_link = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
    store_link.parent.mkdir(parents=True)
    guest_store.mkdir(parents=True)
    store_link.symlink_to(guest_store, target_is_directory=True)
    if outcome in ("host-integrity", "binding"):
        expanded = tmp_path / "expanded"
        with tarfile.open(archive) as stream:
            stream.extractall(expanded, filter="data")
        package, = expanded.iterdir()
        if outcome == "binding":
            metadata = package / "package-info"
            previous = metadata.read_bytes()
            metadata.write_bytes(previous.replace(b"guest_compatibility=v1", b"guest_compatibility=v2")
                                 .replace(b"guest_discovery_tag=compat-v1", b"guest_discovery_tag=compat-v2"))
            sums = package / "SHA256SUMS"
            sums.write_bytes(sums.read_bytes().replace(hashlib.sha256(previous).hexdigest().encode(),
                                                      hashlib.sha256(metadata.read_bytes()).hexdigest().encode()))
        else:
            (package / "LICENSE").write_text("changed bytes with the original inner checksum")
        original = archive.read_bytes()
        with tarfile.open(archive, "w:gz") as stream:
            stream.add(package, arcname=package.name)
        contents[f"{base}/{archive.name}"] = archive.read_bytes()
        contents[f"{base}/SHA256SUMS"] = contents[f"{base}/SHA256SUMS"].replace(
            hashlib.sha256(original).hexdigest().encode(), hashlib.sha256(archive.read_bytes()).hexdigest().encode())
    tools = tmp_path / "tools"
    tools.mkdir()
    entered, resume = tmp_path / "held-child", tmp_path / "resume-child"
    wrapper = tools / "tar"
    host_gate = resume if held_phase == "host-extraction" else entered
    wrapper.write_text(
        '#!/bin/sh\ncase "$*" in\n'
        f'*"{archive.name}"*|*/host) '
        + (f'echo $$ > "{entered}"; ' if held_phase == "host-extraction" else '')
        + f'while [ ! -f "{host_gate}" ]; do sleep 0.01; done;;\n'
        f'esac\nexec "{shutil.which("tar")}" "$@"\n')
    wrapper.chmod(0o755)
    if held_phase == "guest-preparation":
        wrapper = tools / "sudo"
        wrapper.write_text(
            '#!/bin/sh\nset -e\n'
            'if [ "$1" = -n ] && [ "${4:-}" = host ] && [ "${5:-}" = remap-rootfs ]; then\n'
            f'echo $$ > "{entered}"; while [ ! -f "{resume}" ]; do sleep 0.01; done\nfi\n'
            f'exec "{shutil.which("sudo")}" "$@"\n')
        wrapper.chmod(0o755)
    host_calls, guest_calls = tmp_path / "host-calls", tmp_path / "guest-calls"
    environment = {**environment, "PATH": f"{tools}:{environment['PATH']}",
                   "PACKAGE_GUEST_DOWNLOAD_CLI": str(native_cli), "PACKAGE_HOST_CALLS": str(host_calls),
                   "PACKAGE_GUEST_CALLS": str(guest_calls)}
    if outcome == "declined":
        environment["PACKAGE_HOST_EXIT"] = "41"
    trees = guest_store / "trees/sha256"
    prepared = digest(guest).removeprefix("sha256:") + "*/rootfs-tree"
    stdout_log, stderr_log = tmp_path / "bootstrap.stdout", tmp_path / "bootstrap.stderr"
    with stdout_log.open("w") as stdout, stderr_log.open("w") as stderr:
        process = subprocess.Popen(["bash", str(bootstrap)], env=environment, stdout=stdout,
                                   stderr=stderr, text=True, start_new_session=True)
    try:
        deadline = time.monotonic() + 10
        while True:
            if held_phase == "host-extraction":
                ready = entered.exists() and bool(list(trees.glob(prepared)))
            else:
                message = ("stopping early guest preparation" if outcome in ("host-integrity", "binding")
                           else "Verified SafeYolo package:")
                log = stderr_log if outcome in ("host-integrity", "binding") else stdout_log
                ready = entered.exists() and message in log.read_text()
            if ready:
                break
            assert time.monotonic() < deadline and process.poll() is None, (stdout_log.read_text(), stderr_log.read_text())
            time.sleep(0.01)
        held_pid = int(entered.read_text())
        if held_phase == "host-extraction":
            tree, = trees.glob(prepared)
            inode = tree.stat().st_ino
        else:
            assert not list(trees.glob(prepared))
            assert not host_calls.exists() and not guest_calls.exists()
            # Discovery may advance while preparation is held. Installation
            # must still consume the index selected by the joined child.
            contents.update(release(compressed_archive(content=b"later guest")))
        assert not root.exists() and process.poll() is None
        resume.touch()
        process.wait(timeout=15)
        stdout, stderr = stdout_log.read_text(), stderr_log.read_text()
        if outcome == "installed":
            assert process.returncode == 0, stderr
            assert (root / "config.toml").exists()
            arguments = guest_calls.read_text().splitlines()
            assert arguments[arguments.index("--index") + 1] == selected_index
        else:
            assert process.returncode != 0, (stdout, stderr)
            assert not root.exists() and not (Path(environment["HOME"]) / ".local/bin/safeyolo").exists()
            if outcome == "binding":
                assert "Guest download inputs differ" in stderr
        if held_phase == "host-extraction":
            assert tree.stat().st_ino == inode
        if outcome in ("installed", "declined"):
            assert stdout.count("Verified SafeYolo package:") == 1
        assert not Path(f"/proc/{held_pid}").exists()
        assert not list((guest_store / "trees").rglob("extract-*"))
        assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
        assert requests.count("/v2/craigbalding/safeyolo-guest/blobs/" + digest(guest)) == 1
    finally:
        resume.touch()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("interruption", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize(("phase", "scope"), [("download", "bootstrap"), ("preparation", "bootstrap"), ("preparation", "group")])
def test_bootstrap_interrupt_reaps_active_guest_work(public_release, native_cli, guest_store, tmp_path, interruption, phase, scope):
    contents, _requests, faults, environment, bootstrap, root, base, archive = public_release
    guest = compressed_archive()
    contents.update(release(guest))
    faults["pause"] = "blobs/" + digest(guest)
    environment = {**environment, "PACKAGE_GUEST_DOWNLOAD_CLI": str(native_cli)}
    entered, resume = tmp_path / "guest-extracted", tmp_path / "resume-guest"
    if phase == "preparation":
        faults["pause"] = f"{base}/{archive.name}"
        store_link = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
        store_link.parent.mkdir(parents=True)
        guest_store.mkdir(parents=True)
        store_link.symlink_to(guest_store, target_is_directory=True)
        tools = tmp_path / "tools"
        tools.mkdir()
        wrapper = tools / "sudo"
        wrapper.write_text(
            '#!/bin/sh\nset -e\n'
            'if [ "$1" = -n ] && [ "${4:-}" = host ] && [ "${5:-}" = remap-rootfs ]; then\n'
            f'touch "{entered}"; while [ ! -f "{resume}" ]; do sleep 0.01; done\nfi\n'
            f'exec "{shutil.which("sudo")}" "$@"\n')
        wrapper.chmod(0o755)
        environment["PATH"] = f"{tools}:{environment['PATH']}"
    process = subprocess.Popen(["bash", str(bootstrap)], env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    stdout_prefix = b""
    try:
        assert faults["entered"].wait(timeout=10), "bootstrap did not start the native guest transfer"
        if phase == "preparation":
            deadline = time.monotonic() + 10
            while not entered.exists():
                assert time.monotonic() < deadline and process.poll() is None, "early extraction did not reach its held child"
                time.sleep(0.01)
            faults["resume"].set()
            deadline = time.monotonic() + 10
            while b"Verified SafeYolo package:" not in stdout_prefix:
                assert select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))[0], "host verification waited for guest preparation"
                chunk = os.read(process.stdout.fileno(), 65536)
                assert chunk, "bootstrap exited before host verification completed"
                stdout_prefix += chunk
            assert not root.exists() and process.poll() is None
        if scope == "group":
            os.killpg(process.pid, interruption)
        else:
            process.send_signal(interruption)
        stderr_prefix = b""
        if phase == "preparation":
            if scope == "bootstrap":
                deadline = time.monotonic() + 5
                while b"stopping early guest preparation" not in stderr_prefix:
                    assert select.select([process.stderr], [], [], max(0, deadline - time.monotonic()))[0], "guest preparation did not observe cancellation"
                    chunk = os.read(process.stderr.fileno(), 65536)
                    assert chunk, "guest preparation exited before joining extraction"
                    stderr_prefix += chunk
                assert process.poll() is None, "bootstrap exited while extraction still owned its stage"
            resume.touch()
        stdout, stderr = process.communicate(timeout=10)
        stdout = stdout_prefix.decode() + stdout
        stderr = stderr_prefix.decode() + stderr
        assert process.returncode == 128 + interruption, (stdout, stderr)
        if scope == "bootstrap":
            assert "interrupted" in stderr
        assert not root.exists()
        assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
        store = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
        assert not list((store / "trees").rglob("extract-*"))
        assert not list((store / "trees/sha256").glob("*"))
        assert all(len(path.name) == 64 for path in (store / "blobs/sha256").iterdir())
    finally:
        resume.touch()
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    faults["pause"] = None
    retried = run("bash", str(bootstrap), env=environment)
    assert retried.returncode == 0, retried.stderr


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("fault", ["checksum", "partial", "source", "binding", "legacy", "legacy-installer", "offline"])
def test_early_guest_download_package_preserves_trust_and_legacy_paths(public_release, tmp_path, fault):
    contents, requests, faults, environment, bootstrap, root, base, archive = public_release
    early_name = archive.name.removesuffix(".tar.gz") + "-guest-download.tar.gz"
    early_path = f"{base}/{early_name}"
    if fault == "checksum":
        contents[early_path] += b"damaged early package"
    elif fault == "partial":
        faults["partial"] = early_path
    elif fault in ("source", "binding"):
        expanded = tmp_path / "expanded"
        with tarfile.open(archive.parent / early_name) as stream:
            stream.extractall(expanded, filter="data")
        package, = expanded.iterdir()
        metadata = package / "package-info"
        text = metadata.read_text()
        text = text.replace("source_commit=", "source_commit=0") if fault == "source" else text.replace("guest_compatibility=v1", "guest_compatibility=v2")
        metadata.write_text(text)
        changed = tmp_path / "early.tar.gz"
        with tarfile.open(changed, "w:gz") as stream:
            for relative in ("bin/safeyolo", "package-info"):
                stream.add(package / relative, arcname=package.name + "/" + relative)
        contents[early_path] = changed.read_bytes()
        contents[f"{base}/SHA256SUMS"] = contents[f"{base}/SHA256SUMS"].replace(
            hashlib.sha256((archive.parent / early_name).read_bytes()).hexdigest().encode(),
            hashlib.sha256(changed.read_bytes()).hexdigest().encode())
    elif fault == "legacy":
        del contents[early_path]
        contents[f"{base}/SHA256SUMS"] = f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n".encode()
    elif fault == "legacy-installer":
        expanded = tmp_path / "expanded"
        with tarfile.open(archive) as stream:
            stream.extractall(expanded, filter="data")
        package, = expanded.iterdir()
        installer = package / "install_native.sh"
        # This package exposes only its standalone entry point to the
        # bootstrap. Its ordinary verification must still run exactly once.
        installer.write_text(installer.read_text().replace("install_native() {", "standalone_install() {")
                             .replace("  install_native ''", "  standalone_install ''"))
        sums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(package)}\n"
                       for path in sorted(package.rglob("*")) if path.is_file() and path.name != "SHA256SUMS")
        (package / "SHA256SUMS").write_text(sums)
        with tarfile.open(archive, "w:gz") as stream:
            stream.add(package, arcname=package.name)
        previous = contents[f"{base}/{archive.name}"]
        contents[f"{base}/{archive.name}"] = archive.read_bytes()
        contents[f"{base}/SHA256SUMS"] = contents[f"{base}/SHA256SUMS"].replace(
            hashlib.sha256(previous).hexdigest().encode(), hashlib.sha256(archive.read_bytes()).hexdigest().encode())
    arguments = ["--no-guest-download"] if fault == "offline" else []
    result = run("bash", str(bootstrap), *arguments, env=environment)
    if fault in ("legacy", "legacy-installer", "offline"):
        assert result.returncode == 0, result.stderr
        assert result.stdout.count("Verified SafeYolo package:") == 1
        assert (early_path in requests) == (fault == "legacy-installer")
    else:
        assert result.returncode != 0, result.stdout
        assert not root.exists()
        assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("fault", ["partial", "hash", "compatibility"])
def test_composed_guest_download_failure_never_activates_and_can_retry(public_release, native_cli, fault):
    contents, requests, faults, environment, bootstrap, root, base, archive = public_release
    guest = compressed_archive()
    data = release(guest, compatibility="v2" if fault == "compatibility" else "v1")
    blob = "blobs/" + digest(guest)
    if fault == "partial":
        faults["partial"] = blob
    elif fault == "hash":
        data[blob] = b"!" + guest[1:]
    contents.update(data)
    environment = {**environment, "PACKAGE_GUEST_DOWNLOAD_CLI": str(native_cli)}
    refused = run("bash", str(bootstrap), env=environment)
    assert refused.returncode != 0 and "Guest acquisition failed" in refused.stderr
    assert not root.exists()
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
    store = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
    assert not (store / "trees").exists()
    assert all(len(path.name) == 64 for path in (store / "blobs/sha256").glob("*"))
    contents.update(release(guest))
    faults["partial"] = None
    retried = run("bash", str(bootstrap), env=environment)
    assert retried.returncode == 0, retried.stderr
    assert requests.count(f"{base}/{archive.name}") == 1


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
def test_unpinned_source_bootstrap_resolves_latest_once(public_release):
    _contents, requests, _faults, environment, bootstrap, root, _base, _archive = public_release
    shutil.copy2(REPO / "install.sh", bootstrap)
    result = run("bash", str(bootstrap), env=environment)
    assert result.returncode == 0, result.stderr
    assert (root / "config.toml").exists()
    assert requests.count(f"{RELEASES}/latest") == 1


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["native"], indirect=True)
@pytest.mark.parametrize("decision", ["decline", "interrupt"])
def test_download_then_install_and_launch_keeps_host_consent_and_repeat_state(public_release, tmp_path, decision):
    _contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    # The first entered command is the real HTTPS download in public_release.
    # The second installs and enters the actual first-launch operation.
    workspace = tmp_path / "workspace with spaces; literal"
    workspace.mkdir()
    environment = {**environment, "TERM": "xterm-256color"}
    instance = SimpleNamespace(root=root, environment=environment)
    selected_workspace = [str(workspace)] if decision == "decline" else []
    # This mounted fixture lacks POSIX ACL support. Host preparation and
    # guest acquisition retain their separate installed controls and proof.
    command = ["bash", str(bootstrap), "--no-guest-download", "--yes", "--launch", *selected_workspace,
               "--name", "first", "--harness", "claude", "--launcher", "tmux-window"]
    with terminal(instance, command=command, cwd=workspace) as (process, master, until):
        output = until(b"Run this setup and share this workspace?")
        assert b"SafeYolo host" in output and b"agent first" in output
        assert str(workspace).encode() in output
        assert b"guest can read and write" in output
        # Download files and the installation lock must not live for the
        # duration of the interactive session.
        assert not list(Path(environment["HOME"]).rglob("acquire.*"))
        assert not root.with_name(root.name + ".install-lock").exists()
        state = {name: (root / name).read_bytes() for name in (
            "config.toml", "policy.toml", "data/instance_id", "data/admin_token", "data/agent_token",
            "certs/mitmproxy-ca.pem", "certs/mitmproxy-ca-cert.pem",
        )}
        if decision == "decline":
            os.write(master, b"n\n")
            until(b"Setup declined")
            assert process.wait(timeout=5) == 0
        else:
            os.killpg(process.pid, signal.SIGINT)
            assert process.wait(timeout=5) in (-signal.SIGINT, 130)
    assert requests.count(f"{base}/{archive.name}") == 1
    before = list(requests)
    with terminal(instance, command=command, cwd=workspace) as (process, master, until):
        until(b"Run this setup and share this workspace?")
        os.write(master, b"n\n")
        until(b"Setup declined")
        assert process.wait(timeout=5) == 0
    assert requests == before
    assert all((root / name).read_bytes() == value for name, value in state.items())
    assert not (root / "agents").exists()
    assert not (root / "data/proxy-process.json").exists()
    assert not (root / "data/coord/nats/process.json").exists()
    located = run("bash", "--noprofile", "--norc", "-c", "command -v safeyolo", env=environment)
    assert located.stdout.strip() == str(Path(environment["HOME"]) / ".local/bin/safeyolo")


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["native"], indirect=True)
def test_downloaded_composition_launches_from_relative_root_starting_with_dash(public_release, tmp_path):
    _contents, requests, _faults, environment, bootstrap, default_root, base, archive = public_release
    root = tmp_path / "-instance"
    arguments = ["bash", str(bootstrap), "--root", root.name, "--no-guest-download", "--launch", "--help"]
    result = run(*arguments, cwd=tmp_path, env=environment)
    assert result.returncode == 0, result.stderr
    assert "agent launch [WORKSPACE]" in result.stdout
    assert (root / "config.toml").is_file() and not default_root.exists()
    assert requests.count(f"{base}/{archive.name}") == 1
    instance_id = (root / "data/instance_id").read_bytes()
    before = list(requests)
    repeated = run(*arguments, cwd=tmp_path, env=environment)
    assert repeated.returncode == 0, repeated.stderr
    assert "agent launch [WORKSPACE]" in repeated.stdout
    assert requests == before
    assert (root / "data/instance_id").read_bytes() == instance_id


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["native"], indirect=True)
def test_composed_install_failure_and_launch_failure_recover_without_reinstallation(public_release, tmp_path):
    contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original = contents[f"{base}/{archive.name}"]
    contents[f"{base}/{archive.name}"] += b"bad host transfer"
    arguments = ["bash", str(bootstrap), "--no-guest-download", "--yes", "--launch"]
    refused = run(*arguments, str(workspace), env=environment)
    assert refused.returncode != 0 and "checksum failed" in refused.stderr
    assert "launching the first agent" not in refused.stderr and not root.exists()
    contents[f"{base}/{archive.name}"] = original
    # Actual first launch needs a trusted terminal. Its error must propagate
    # while retaining the successful installation for the next invocation.
    failed_launch = run(*arguments, str(workspace), env=environment)
    assert failed_launch.returncode != 0 and "interactive host terminal" in failed_launch.stderr
    state = {name: (root / name).read_bytes() for name in (
        "config.toml", "policy.toml", "data/admin_token", "data/instance_id",
    )}
    before = list(requests)
    repeated = run(*arguments, "--help", env=environment)
    assert repeated.returncode == 0 and "agent launch [WORKSPACE]" in repeated.stdout
    assert requests == before
    assert all((root / name).read_bytes() == value for name, value in state.items())
    assert not (root / "agents").exists()


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["native"], indirect=True)
@pytest.mark.parametrize("entry", ["source", "bundle"])
def test_contributor_composition_uses_the_selected_installed_root(public_release, entry):
    _contents, requests, _faults, environment, bootstrap, root, _base, archive = public_release
    before = list(requests)
    selected = root.parent / "separate instance"
    entrypoint = REPO / "install.sh" if entry == "source" else bootstrap
    result = run("bash", str(entrypoint), "--root", str(selected),
                 "--bundle", str(archive.parent / archive.name.removesuffix(".tar.gz")),
                 "--no-guest-download", "--launch", "--help", env=environment)
    assert result.returncode == 0, result.stderr
    assert "agent launch [WORKSPACE]" in result.stdout
    assert (selected / "config.toml").is_file() and not root.exists() and requests == before


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["native"], indirect=True)
def test_product_acquisition_and_repeat_preserve_state_and_guest(public_release, guest_store):
    contents, requests, _faults, environment, bootstrap, root, _base, _archive = public_release
    contents.update(release(compressed_archive()))
    store_link = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
    store_link.parent.mkdir(parents=True)
    guest_store.mkdir(parents=True)
    store_link.symlink_to(guest_store, target_is_directory=True)
    installed = run("/bin/bash", "--noprofile", "--norc", "-c",
                    'set -e\nbash "$BOOTSTRAP" --yes\ncommand -v safeyolo\nsafeyolo --version',
                    env={**environment, "BOOTSTRAP": str(bootstrap)})
    assert installed.returncode == 0, installed.stderr
    assert str(Path(environment["HOME"]) / ".local/bin/safeyolo") in installed.stdout
    state = ("config.toml", "policy.toml", "data/instance_id", "data/admin_token", "data/agent_token",
             "certs/mitmproxy-ca.pem", "certs/mitmproxy-ca-cert.pem", "share/guest-selection.json")
    agent_file = root / "data/agents/operator-state"
    agent_file.parent.mkdir(parents=True, exist_ok=True)
    agent_file.write_bytes(b"retained agent workspace state")
    credentials = root / "data/credentials.enc"
    credentials.write_bytes(b"opaque operator credential store; keep unchanged")
    (root / "policy.toml").write_text((root / "policy.toml").read_text() + "\n# operator policy edit\n")
    preserved = {name: (root / name).read_bytes() for name in (*state, "data/agents/operator-state", "data/credentials.enc")}
    guest_inode = (root / "share/rootfs-tree").stat().st_ino
    requests_before = list(requests)
    repeated = run("bash", str(bootstrap), "--yes", env=environment)
    assert repeated.returncode == 0, repeated.stderr
    assert requests == requests_before
    assert (root / "share/rootfs-tree").stat().st_ino == guest_inode
    assert all((root / name).read_bytes() == data for name, data in preserved.items())
    conflict = run("bash", str(bootstrap), "--release", "host-" + "0" * 40, env=environment)
    assert conflict.returncode != 0 and "not an upgrade" in conflict.stderr
    assert requests == requests_before
    assert all((root / name).read_bytes() == data for name, data in preserved.items())
    new_archive = compressed_archive(content=b"a different compatible guest")
    replacement = release(new_archive)
    blob_path = "blobs/" + digest(new_archive)
    original_blob = replacement[blob_path]
    replacement[blob_path] += b"corrupt guest transfer"
    contents.update(replacement)
    separate_root = root.parent / "second-instance"
    separate_commands = root.parent / "second-commands"
    refused = run("bash", str(bootstrap), "--yes", "--root", str(separate_root),
                  "--command-dir", str(separate_commands), env=environment)
    assert refused.returncode != 0 and "Guest acquisition failed" in refused.stderr
    assert not separate_root.exists() and not separate_commands.exists()
    assert all((root / name).read_bytes() == data for name, data in preserved.items())
    contents[blob_path] = original_blob
    retry = run("bash", str(bootstrap), "--yes", "--root", str(separate_root),
                "--command-dir", str(separate_commands), env=environment)
    assert retry.returncode == 0, retry.stderr
    assert (separate_root / "config.toml").exists()
    assert all((root / name).read_bytes() == data for name, data in preserved.items())


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["native"], indirect=True)
@pytest.mark.parametrize("conflict", ["instance", "command", "shadow"])
def test_state_created_during_guest_download_is_preserved(public_release, guest_store, conflict):
    contents, _requests, faults, environment, bootstrap, root, _base, archive = public_release
    guest_archive = compressed_archive()
    contents.update(release(guest_archive))
    store_link = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
    store_link.parent.mkdir(parents=True)
    guest_store.mkdir(parents=True)
    store_link.symlink_to(guest_store, target_is_directory=True)
    faults["pause"] = "blobs/" + digest(guest_archive)
    shadow_commands = root.parent / "first-bin"
    shadow_commands.mkdir()
    environment = {**environment, "PATH": f'{shadow_commands}:{environment["PATH"]}'}
    process = subprocess.Popen(["bash", str(bootstrap), "--yes"], env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert faults["entered"].wait(timeout=15), "installer did not reach guest download"
        if conflict == "instance":
            cli = archive.parent / archive.name.removesuffix(".tar.gz") / "bin/safeyolo"
            initialized = run(str(cli), "--root", str(root), "init", env=environment)
            assert initialized.returncode == 0, initialized.stderr
            state_root = root
        elif conflict == "command":
            state_root = Path(environment["HOME"]) / ".local/bin/safeyolo"
            state_root.mkdir()
            (state_root / "operator-file").write_bytes(b"keep this command directory unchanged")
        else:
            state_root = shadow_commands
            command = state_root / "safeyolo"
            command.write_text("#!/bin/sh\necho unrelated operator command\n")
            command.chmod(0o755)
        state = {path.relative_to(state_root): path.read_bytes() for path in state_root.rglob("*") if path.is_file()}
        faults["resume"].set()
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode != 0 and "was preserved" in stderr, (stdout, stderr)
        assert not (root / "bin").exists()
        assert all((state_root / name).read_bytes() == data for name, data in state.items())
        if conflict != "instance":
            assert not root.exists()
        if conflict == "command":
            assert not (state_root / "safeyolo").exists()
        assert not list(root.parent.glob("safeyolo-install.*"))
        assert not root.with_name(root.name + ".install-lock").exists()
    finally:
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("public_release", ["native"], indirect=True)
@pytest.mark.parametrize("target_exists", [True, False], ids=["executable", "dangling"])
def test_command_symlink_created_at_publication_is_preserved_and_refused(public_release, tmp_path, target_exists):
    _contents, _requests, _faults, environment, bootstrap, root, _base, _archive = public_release
    commands = Path(environment["HOME"]) / ".local/bin"
    command = commands / "safeyolo"
    target = tmp_path / "operator-command"
    original = b"#!/bin/sh\necho unrelated operator command\n"
    if target_exists:
        target.write_bytes(original)
        target.chmod(0o755)
    tools = tmp_path / "tools"
    tools.mkdir()
    mkdir = tools / "mkdir"
    # Create the collision after the installer's final directory creation,
    # beyond the conflict checks exercised by the paused-download controls.
    mkdir.write_text(
        '#!/bin/bash\nset -e\n"$PUBLIC_TEST_MKDIR" "$@"\n'
        'if [[ $# == 2 && $1 == -p && $2 == "$PUBLIC_TEST_COMMAND_DIR" ]]; then\n'
        '  ln -s "$PUBLIC_TEST_COMMAND_TARGET" "$PUBLIC_TEST_COMMAND_DIR/safeyolo"\n'
        'fi\n'
    )
    mkdir.chmod(0o755)
    environment = {**environment, "PATH": f"{tools}:{environment['PATH']}",
                   "PUBLIC_TEST_MKDIR": shutil.which("mkdir"),
                   "PUBLIC_TEST_COMMAND_DIR": str(commands), "PUBLIC_TEST_COMMAND_TARGET": str(target)}
    refused = run("bash", str(bootstrap), "--no-guest-download", env=environment)
    assert refused.returncode != 0, (refused.stdout, refused.stderr)
    assert "was preserved" in refused.stderr and "--command-dir" in refused.stderr
    assert "Installed SafeYolo" not in refused.stdout
    assert command.is_symlink() and command.readlink() == target
    if target_exists:
        assert target.read_bytes() == original
        invoked = run(str(command), "--version", env=environment)
        assert invoked.returncode == 0 and invoked.stdout == "unrelated operator command\n"
    else:
        assert not target.exists()
    # Activation can precede a late command conflict. Preserve that valid
    # installation so retry can select a separate command directory.
    assert (root / "config.toml").is_file()
    assert not list(root.parent.glob("safeyolo-install.*"))
    assert not root.with_name(root.name + ".install-lock").exists()
    state = {name: (root / name).read_bytes() for name in ("config.toml", "policy.toml", "data/instance_id")}
    recovered_commands = tmp_path / "recovered-commands"
    retried = run("bash", str(bootstrap), "--yes", "--command-dir", str(recovered_commands), env=environment)
    assert retried.returncode == 0, retried.stderr
    assert (recovered_commands / "safeyolo").resolve() == root / "bin/safeyolo"
    assert all((root / name).read_bytes() == data for name, data in state.items())
    assert command.is_symlink() and command.readlink() == target


@pytest.mark.parametrize("system,architecture", [("Darwin", "x86_64"), ("Linux", "riscv64"), ("Other", "arm64")])
def test_unsupported_target_refuses_before_download_or_root_changes(tmp_path, system, architecture):
    tools = tmp_path / "tools"
    tools.mkdir()
    uname = tools / "uname"
    uname.write_text(f'#!/bin/sh\ncase "$1" in -s) echo {system};; -m) echo {architecture};; esac\n')
    uname.chmod(0o755)
    marker = tmp_path / "download-called"
    curl = tools / "curl"
    curl.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 90\n')
    curl.chmod(0o755)
    root = tmp_path / "refused"
    environment = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "HOME": str(tmp_path / "home")}
    environment.pop("BASH_ENV", None)
    result = run("bash", str(REPO / "install.sh"), "--release", "host-" + "a" * 40,
                 "--root", str(root), env=environment)
    assert result.returncode != 0 and "Unsupported host" in result.stderr
    assert not root.exists() and not marker.exists()
    assert not Path(environment["HOME"]).exists()
