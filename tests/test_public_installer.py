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
from pathlib import Path

import pytest

from tests.test_guest_acquisition import compressed_archive, digest, release
from tests.test_guest_acquisition import guest_store as _guest_store
from tests.test_guest_acquisition import registry as _registry
from tests.test_host_packages import package_inputs as _package_inputs
from tests.test_host_packages import run

# Reuse fixtures in standalone and combined collection without plugin registration.
guest_store = _guest_store
registry = _registry
package_inputs = _package_inputs

REPO = Path(__file__).resolve().parents[1]
RELEASES = "/craigbalding/safeyolo/releases"


@pytest.fixture
def public_release(package_inputs, registry, tmp_path, request):
    contents, requests, faults, environment = registry
    output = tmp_path / "release"
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
    archive, = output.glob("*.tar.gz")
    base = f"{RELEASES}/download/{tag}"
    contents[f"{base}/{archive.name}"] = archive.read_bytes()
    contents[f"{base}/SHA256SUMS"] = (
        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n".encode()
    )
    contents[f"{base}/install-safeyolo.sh"] = (output / "install-safeyolo.sh").read_bytes()
    contents[f"{RELEASES}/tag/{tag}"] = b"fixture release page"
    faults["host_release"] = tag
    home = tmp_path / "operator"
    commands = home / ".local/bin"
    commands.mkdir(parents=True)
    environment = {**environment, "HOME": str(home), "PATH": f"{commands}:/usr/local/bin:/usr/bin:/bin",
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
def test_downloaded_bootstrap_installs_without_checkout_and_exposes_same_terminal_command(public_release):
    _contents, requests, _faults, environment, bootstrap, root, base, archive = public_release
    environment = {**environment, "BOOTSTRAP": str(bootstrap)}
    # Additional commands observe the same shell after installation. They are
    # validation, not prerequisites hidden in the proposed user workflow.
    result = run("/bin/bash", "--noprofile", "--norc", "-c",
                 'set -e\nbash "$BOOTSTRAP"\ncommand -v safeyolo\nsafeyolo --version', env=environment)
    assert result.returncode == 0, result.stderr
    assert (root / "bin/safeyolo").read_bytes().startswith(b"\x7fELF")
    assert str(Path(environment["HOME"]) / ".local/bin/safeyolo") in result.stdout
    assert (root / "share/guest-selection.json").exists()
    assert (root / "install_native.sh").is_file()
    assert f"{base}/{archive.name}" in requests
    assert f"{RELEASES}/latest" not in requests
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
def test_unpinned_source_bootstrap_resolves_latest_once(public_release):
    _contents, requests, _faults, environment, bootstrap, root, _base, _archive = public_release
    shutil.copy2(REPO / "install.sh", bootstrap)
    result = run("bash", str(bootstrap), env=environment)
    assert result.returncode == 0, result.stderr
    assert (root / "config.toml").exists()
    assert requests.count(f"{RELEASES}/latest") == 1


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
                    'set -e\nbash "$BOOTSTRAP"\ncommand -v safeyolo\nsafeyolo --version',
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
    repeated = run("bash", str(bootstrap), env=environment)
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
    refused = run("bash", str(bootstrap), "--root", str(separate_root),
                  "--command-dir", str(separate_commands), env=environment)
    assert refused.returncode != 0 and "Guest acquisition failed" in refused.stderr
    assert not separate_root.exists() and not separate_commands.exists()
    assert all((root / name).read_bytes() == data for name, data in preserved.items())
    contents[blob_path] = original_blob
    retry = run("bash", str(bootstrap), "--root", str(separate_root),
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
    process = subprocess.Popen(["bash", str(bootstrap)], env=environment, stdout=subprocess.PIPE,
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
    retried = run("bash", str(bootstrap), "--command-dir", str(recovered_commands), env=environment)
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
