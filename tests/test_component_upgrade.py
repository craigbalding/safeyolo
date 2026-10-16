"""Drive native component selection with checked host fixtures and a TLS registry.

Controlled host executables establish failure controls, not installed release
acceptance. The real native client performs guest acquisition and activation.
"""

import ctypes
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile

import pytest

from tests import test_guest_acquisition as acquisition
from tests import test_host_packages as packages
from tests.test_guest_acquisition import (
    compressed_archive,
    digest,
    install,
    release,
)
from tests.test_guest_upgrade import assert_preserved, command, preserved
from tests.test_host_packages import build_bundle, executable

native_cli = acquisition.native_cli
registry = acquisition.registry
guest_store = acquisition.guest_store
package_inputs = packages.package_inputs


@pytest.fixture(autouse=True)
def remove_copied_test_upgrader(tmp_path):
    yield
    # The source binary remains available. Finished controls need no extra
    # full executable copy in each retained pytest directory.
    tools = tmp_path / "i/upgrade-tools"
    if tools.exists():
        shutil.rmtree(tools)


def checksums(bundle):
    (bundle / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(bundle)}\n"
        for path in sorted(bundle.rglob("*")) if path.is_file() and path.name != "SHA256SUMS"
    ))


@pytest.fixture
def host_pair(package_inputs, tmp_path):
    first = build_bundle(package_inputs, tmp_path)
    second = tmp_path / "target"
    shutil.copytree(first, second, symlinks=True)
    metadata = (second / "package-info").read_text()
    profile = dict(line.split("=", 1) for line in metadata.splitlines())["profile"]
    revision = "b" * 40
    (second / "package-info").write_text(metadata.replace(package_inputs[5], revision))
    for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        executable(second / "bin" / name, f"{name} 0.1.0 commit={revision} profile={profile}")
    for name in ("safeyolo-guest", "safeyolo-coord"):
        path = second / "assets/guest" / name
        identity = f"{name} 0.1.0 commit={revision} profile={profile}"
        executable(path, identity)
        path.with_suffix(".version").write_text(identity + "\n")
        path.with_suffix(".sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
    checksums(second)
    return first, second


def exchange_available(parent):
    left, right = parent / "exchange-left", parent / "exchange-right"
    left.mkdir()
    right.symlink_to(right)
    try:
        return ctypes.CDLL(None, use_errno=True).renameat2(-100, os.fsencode(left), -100, os.fsencode(right), 2) == 0
    finally:
        for path in (left, right):
            if path.is_symlink():
                path.unlink()
            else:
                path.rmdir()


def installation(binary, root, bundle, store, environment, *, legacy=False, omitted_installers=False):
    shutil.copytree(bundle, root, symlinks=True)
    acquired = install(binary, root, store, environment, root / "package-info")
    assert acquired.returncode == 0, acquired.stderr
    initialized = command(binary, root, environment, "init")
    assert initialized.returncode == 0, initialized.stderr
    credential = command(binary, root, {**environment, "UPGRADE_TEST_CREDENTIAL": "kept"},
                         "credentials", "add", "kept", "--value-env", "UPGRADE_TEST_CREDENTIAL")
    assert credential.returncode == 0, credential.stderr
    (root / "agents/kept/home").mkdir(parents=True)
    (root / "agents/retained/home").mkdir(parents=True)
    (root / "agents/retained/home/keep").write_bytes(b"keep agent home")
    (root / "logs/audit-canary").write_bytes(b"keep audit")
    if omitted_installers:
        # The original shipped installer omitted these three bundle files.
        for name in ("install.sh", "install_native.sh", "native_package.sh"):
            (root / name).unlink()
    if not legacy and not exchange_available(root):
        # gVisor's mounted filesystem lacks directory exchange. Start these
        # controls from the already-imported layout, using stopped fixtures.
        # Native hosts also exercise the first import below.
        initial = root / "versions/initial"
        (initial / "host").mkdir(parents=True)
        (root / "current").symlink_to(initial)
        for name in ("bin", "libexec", "lib", "assets", "package-info", "SHA256SUMS", "LICENSE",
                     "install.sh", "install_native.sh", "native_package.sh", "share"):
            if omitted_installers and name in ("install.sh", "install_native.sh", "native_package.sh"):
                continue
            target = initial / name if name == "share" else initial / "host" / name
            (root / name).rename(target)
            alias = root / "current" / name if name == "share" else root / "current/host" / name
            (root / name).symlink_to(alias)


def upgrade(binary, root, environment, *arguments):
    result = command(binary, root, environment, "upgrade", *map(str, arguments))
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_original_installer_layout_upgrades_and_rolls_back_without_rewriting_receipts(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, second = host_pair
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment, omitted_installers=True)
    original = upgrade(native_cli, root, environment, "status")["current"]
    saved = state_files(root)
    receipt = (root / "SHA256SUMS").read_bytes()
    before = len(requests)
    selected = upgrade(native_cli, root, environment, "--bundle", second)
    assert selected["previous"] == original
    assert selected["current"]["guest"] == original["guest"]
    restored = upgrade(native_cli, root, environment, "rollback")
    assert restored["current"] == original
    assert (root / "SHA256SUMS").read_bytes() == receipt
    assert len(requests) == before
    assert_preserved(root, saved)


@pytest.mark.parametrize("damage", ["legacy-runtime", "one-installer", "dangling-installer"])
def test_installed_layout_still_refuses_missing_or_changed_payload(
        native_cli, host_pair, registry, guest_store, tmp_path, damage):
    first, second = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment,
                 omitted_installers=damage == "legacy-runtime")
    if damage == "legacy-runtime":
        (root / "assets/guest/guest-sudo").write_bytes(b"changed runtime")
    else:
        (root / "install.sh").unlink()
        if damage == "dangling-installer":
            (root / "install.sh").symlink_to("missing-script")
    original = upgrade(native_cli, root, environment, "status")
    saved = preserved(root)
    refused = command(native_cli, root, environment, "upgrade", "--bundle", str(second))
    assert refused.returncode != 0
    assert upgrade(native_cli, root, environment, "status") == original
    assert_preserved(root, saved)


def state_files(root):
    return {name: data for name, data in preserved(root).items() if name != "package-info"}


def test_host_only_reuses_guest_and_retains_complete_pair_and_upgrader(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, second = host_pair
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    saved = state_files(root)
    original_selection = (root / "share/guest-selection.json").read_bytes()
    tree = (root / "share/rootfs-tree").resolve()
    inode = tree.stat().st_ino
    cache_inode = (root / "share/cache-paths.txt").stat().st_ino
    before = len(requests)
    selected = upgrade(native_cli, root, environment, "--bundle", second)
    assert len(requests) == before
    assert selected["current"]["host"]["source_commit"] == "b" * 40
    assert selected["previous"]["host"]["source_commit"] != "b" * 40
    assert selected["current"]["guest"] == selected["previous"]["guest"]
    assert (root / "share/guest-selection.json").read_bytes() == original_selection
    assert (root / "share/rootfs-tree").resolve() == tree
    assert tree.stat().st_ino == inode
    assert (root / "share/cache-paths.txt").stat().st_ino == cache_inode
    assert (root / "bin/safeyolo").read_bytes() == (second / "bin/safeyolo").read_bytes()
    assert_preserved(root, saved)
    link = os.readlink(root / "current")
    assert upgrade(native_cli, root, environment, "--bundle", second) == selected
    assert os.readlink(root / "current") == link
    helper = root / "safeyolo-upgrade"
    # The retained native helper still works when the selected host predates it.
    helper_status = subprocess.run([str(helper), "status"], env=environment,
                                   capture_output=True, text=True, timeout=30)
    assert helper_status.returncode == 0, helper_status.stderr
    assert json.loads(helper_status.stdout) == selected
    rolled_back = subprocess.run([str(helper), "rollback"], env=environment,
                                capture_output=True, text=True, timeout=30)
    assert rolled_back.returncode == 0, rolled_back.stderr
    assert json.loads(rolled_back.stdout)["current"] == selected["previous"]
    assert (root / "bin/safeyolo").read_bytes() == (first / "bin/safeyolo").read_bytes()
    assert_preserved(root, saved)
    assert len(requests) == before


def test_complete_target_pair_and_guest_only_interface_share_retained_inputs(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, second = host_pair
    contents, requests, _faults, environment = registry
    g1 = release(compressed_archive())
    g2 = release(compressed_archive(content=b"G2 base"), version="guest-2026-10-16.2")
    contents.update(g1)
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    saved = state_files(root)
    original = upgrade(native_cli, root, environment, "status")["current"]
    contents.update(g2)
    index = digest(g2["manifests/compat-v1"])
    contents["manifests/" + index] = g2["manifests/compat-v1"]
    selected = upgrade(native_cli, root, environment, "--bundle", second, "--guest-index", index)
    assert selected["current"]["guest"]["version"] == "guest-2026-10-16.2"
    assert selected["previous"] == original
    before = len(requests)
    assert upgrade(native_cli, root, environment, "--bundle", second, "--guest-index", index) == selected
    assert not any("/blobs/" in path for path in requests[before:])
    # Existing guest rollback and upgrade must still write inside the active pair.
    rolled_guest = command(native_cli, root, environment, "guest", "rollback")
    assert rolled_guest.returncode == 0, rolled_guest.stderr
    assert json.loads(rolled_guest.stdout) == original["guest"]
    repeated = command(native_cli, root, environment, "guest", "upgrade", "--index", index)
    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(repeated.stdout)["version"] == "guest-2026-10-16.2"
    assert upgrade(native_cli, root, environment, "rollback")["current"] == original
    assert_preserved(root, saved)


@pytest.mark.parametrize("fault", ["checksum", "omitted-checksum", "omitted-installers", "helper-source", "compatibility", "duplicate-metadata", "guest-blob", "upgrader-path"])
def test_bad_component_targets_leave_active_pair_and_state_unchanged(
        native_cli, host_pair, registry, guest_store, tmp_path, fault):
    first, second = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    saved = preserved(root)
    arguments = ["--bundle", str(second)]
    if fault == "checksum":
        with (second / "assets/guest/guest-sudo").open("ab") as stream:
            stream.write(b"corrupt")
    elif fault == "omitted-checksum":
        sums = second / "SHA256SUMS"
        sums.write_text("".join(line for line in sums.read_text().splitlines(keepends=True)
                                if not line.endswith("./assets/guest/guest-sudo\n")))
    elif fault == "omitted-installers":
        for name in ("install.sh", "install_native.sh", "native_package.sh"):
            (second / name).unlink()
    elif fault == "helper-source":
        (second / "assets/guest/safeyolo-guest.version").write_text("safeyolo-guest 0.1.0 commit=" + "c" * 40 + " profile=debug\n")
        checksums(second)
    elif fault in ("compatibility", "duplicate-metadata"):
        metadata = second / "package-info"
        text = metadata.read_text()
        metadata.write_text(text.replace("v1", "v2") if fault == "compatibility" else text + "guest_compatibility=v1\n")
        checksums(second)
    elif fault == "upgrader-path":
        (root / "safeyolo-upgrade").write_bytes(b"operator file; preserve")
    else:
        g2 = release(compressed_archive(content=b"new"), version="guest-2026-10-16.2")
        contents.update(g2)
        index = digest(g2["manifests/compat-v1"])
        contents["manifests/" + index] = g2["manifests/compat-v1"]
        archive = next(key.removeprefix("blobs/") for key, data in g2.items()
                       if key.startswith("blobs/") and data.startswith(b"\x28\xb5\x2f\xfd"))
        contents["blobs/" + archive] = b"corrupt blob"
        arguments += ["--guest-index", index]
    refused = command(native_cli, root, environment, "upgrade", *arguments)
    assert refused.returncode != 0
    assert upgrade(native_cli, root, environment, "status") == original
    assert_preserved(root, saved)
    if fault == "upgrader-path":
        assert (root / "safeyolo-upgrade").read_bytes() == b"operator file; preserve"


def test_explicit_incompatible_host_and_guest_change_together_and_roll_back(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, second = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")["current"]
    metadata = second / "package-info"
    metadata.write_text(metadata.read_text().replace("v1", "v2"))
    checksums(second)
    g2 = release(compressed_archive(content=b"new compatibility"),
                 version="guest-2026-10-16.2", compatibility="v2")
    contents.update(g2)
    index = digest(g2["manifests/compat-v1"])
    contents["manifests/" + index] = g2["manifests/compat-v1"]
    selected = upgrade(native_cli, root, environment, "--bundle", second, "--guest-index", index)
    assert selected["current"]["host"]["guest_compatibility"] == "v2"
    assert selected["current"]["guest"]["compatibility"] == "v2"
    assert selected["previous"] == original
    # A damaged new host must not prevent restoration through the retained tool.
    (root / "bin/safeyolo").write_bytes(b"damaged target executable")
    assert upgrade(native_cli, root, environment, "rollback")["current"] == original


def test_killed_component_pull_keeps_the_old_pair_and_recovers_on_retry(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, second = host_pair
    contents, _requests, faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    saved = preserved(root)
    archive = compressed_archive(content=b"G2 interrupted download")
    g2 = release(archive, version="guest-2026-10-16.2")
    contents.update(g2)
    index = digest(g2["manifests/compat-v1"])
    contents["manifests/" + index] = g2["manifests/compat-v1"]
    faults["pause"] = "blobs/" + digest(archive)
    arguments = [str(native_cli), "--root", str(root), "upgrade", "--bundle", str(second), "--guest-index", index]
    process = subprocess.Popen(arguments, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert faults["entered"].wait(timeout=20)
        process.kill()
        process.communicate(timeout=10)
        assert upgrade(native_cli, root, environment, "status") == original
        assert_preserved(root, saved)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        faults["pause"] = None
        faults["resume"].set()
    selected = upgrade(native_cli, root, environment, "--bundle", second, "--guest-index", index)
    assert selected["current"]["guest"]["archive"]["digest"] == digest(archive)
    assert selected["previous"] == original["current"]


def test_interrupted_legacy_import_resumes_without_reinitializing(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, second = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    if not exchange_available(tmp_path):
        pytest.skip("first-import directory exchange needs a native host; unsupported by this gVisor filesystem")
    installation(native_cli, root, first, guest_store, environment, legacy=True)
    saved = state_files(root)
    # This is the on-disk state after any one completed atomic import exchange.
    initial = root / "versions/initial"
    (initial / "host").mkdir(parents=True)
    (root / "current").symlink_to(initial)
    (root / "bin").rename(initial / "host/bin")
    (root / "bin").symlink_to(root / "current/host/bin")
    # The next exchange was prepared but not performed when the process died.
    (initial / "host/libexec").symlink_to(root / "current/host/libexec")
    selected = upgrade(native_cli, root, environment, "--bundle", second)
    assert selected["current"]["host"]["source_commit"] == "b" * 40
    assert_preserved(root, saved)


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("fault", [None, "checksum", "partial"])
def test_explicit_host_release_uses_the_existing_bootstrap_and_verified_cache(
        native_cli, host_pair, registry, guest_store, tmp_path, fault):
    first, second = host_pair
    contents, requests, faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    saved = state_files(root)
    original = upgrade(native_cli, root, environment, "status")
    name = f"safeyolo-{dict(line.split('=', 1) for line in (second / 'package-info').read_text().splitlines())['platform']}-production"
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as stream:
        stream.add(second, arcname=name)
    tag = "host-" + "b" * 40
    base = "/craigbalding/safeyolo/releases/download/" + tag
    archive_key = f"{base}/{name}.tar.gz"
    contents[archive_key] = archive.getvalue()
    contents[base + "/SHA256SUMS"] = (
        hashlib.sha256(archive.getvalue()).hexdigest() + f"  {name}.tar.gz\n"
    ).encode()
    environment = {**environment, "HOME": str(tmp_path / "consumer"),
                   "CURL_CA_BUNDLE": environment["SSL_CERT_FILE"]}
    if fault:
        if fault == "checksum":
            contents[archive_key] += b"wrong bytes"
        else:
            faults["partial"] = archive_key
        failed = command(native_cli, root, environment, "upgrade", "--release", tag)
        assert failed.returncode != 0
        assert upgrade(native_cli, root, environment, "status") == original
        contents[archive_key] = archive.getvalue()
        faults["partial"] = None
    selected = upgrade(native_cli, root, environment, "--release", tag)
    assert selected["current"]["host"]["source_commit"] == "b" * 40
    assert selected["current"]["guest"] == original["current"]["guest"]
    before = len(requests)
    assert upgrade(native_cli, root, environment, "--release", tag) == selected
    assert archive_key not in requests[before:]
    assert upgrade(native_cli, root, environment, "rollback")["current"]["host"]["source_commit"] != "b" * 40
    assert_preserved(root, saved)
