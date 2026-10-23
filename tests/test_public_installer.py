"""Drive public host acquisition over owned HTTPS with real curl and tar.

Controlled ELF packages test the installer boundary. Clean host and first-agent
proof remain separate. The TLS parent serves only this fixture's local server.
"""

import hashlib
import os
import shutil
import signal
import subprocess
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
from tests.test_host_packages import musl_runtime as _musl_runtime
from tests.test_host_packages import package_inputs as _package_inputs
from tests.test_host_packages import run

# Reuse fixtures in standalone and combined collection without plugin registration.
guest_store = _guest_store
registry = _registry
package_inputs = _package_inputs
musl_runtime = _musl_runtime
native_cli = _native_cli

REPO = Path(__file__).resolve().parents[1]
RELEASES = "/craigbalding/safeyolo/releases"


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
def test_bad_host_download_never_activates_and_retry_preserves_another_installation(public_release, tmp_path, fault):
    contents, requests, faults, environment, bootstrap, root, base, archive = public_release
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
        contents[f"{base}/SHA256SUMS"] = (
            f"{hashlib.sha256(changed.read_bytes()).hexdigest()}  {archive.name}\n".encode()
        )
    refused = run("bash", str(bootstrap), env=environment)
    assert refused.returncode != 0
    assert not root.exists()
    assert unrelated.read_bytes() == b"operator policy; keep unchanged"
    assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
    contents.update(original)
    faults["partial"] = None
    retried = run("bash", str(bootstrap), env=environment)
    assert retried.returncode == 0, retried.stderr
    assert (root / "config.toml").exists()
    assert unrelated.read_bytes() == b"operator policy; keep unchanged"
    assert requests.count(f"{base}/{archive.name}") == (1 if fault == "duplicate-checksum" else 2)


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
        assert not (store / "trees").exists()
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
@pytest.mark.parametrize("interruption", [signal.SIGINT, signal.SIGTERM])
def test_bootstrap_interrupt_reaps_active_guest_download(public_release, native_cli, interruption):
    contents, _requests, faults, environment, bootstrap, root, _base, _archive = public_release
    guest = compressed_archive()
    contents.update(release(guest))
    faults["pause"] = "blobs/" + digest(guest)
    environment = {**environment, "PACKAGE_GUEST_DOWNLOAD_CLI": str(native_cli)}
    process = subprocess.Popen(["bash", str(bootstrap)], env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert faults["entered"].wait(timeout=10), "bootstrap did not start the native guest transfer"
        process.send_signal(interruption)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 128 + interruption, (stdout, stderr)
        assert "guest download interrupted" in stderr
        assert not root.exists()
        assert not list((Path(environment["HOME"]) / ".cache").rglob("acquire.*"))
        store = Path(environment["HOME"]) / ".local/share/safeyolo/guests"
        assert not (store / "trees").exists()
        assert all(len(path.name) == 64 for path in (store / "blobs/sha256").iterdir())
    finally:
        faults["resume"].set()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    faults["pause"] = None
    retried = run("bash", str(bootstrap), env=environment)
    assert retried.returncode == 0, retried.stderr


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("fault", ["checksum", "partial", "source", "binding", "legacy", "offline"])
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
    arguments = ["--no-guest-download"] if fault == "offline" else []
    result = run("bash", str(bootstrap), *arguments, env=environment)
    if fault in ("legacy", "offline"):
        assert result.returncode == 0, result.stderr
        assert early_path not in requests
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
