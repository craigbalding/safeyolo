"""Drive native component selection with checked host fixtures and a TLS registry.

Controlled host executables establish failure controls. The optional installed
case uses real bundles for proxy activation and recovery; it does not boot a guest.
"""

import ctypes
import hashlib
import io
import json
import os
import pty
import shutil
import socket
import sqlite3
import subprocess
import tarfile
import tomllib
from pathlib import Path

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
def host_pair(package_inputs, tmp_path, monkeypatch):
    # The controlled package identities use the real CLI for Coord validation.
    # Individual prior-writer controls select a different executable explicitly.
    monkeypatch.setenv("PACKAGE_COORD_CLI", str(os.environ.get(
        "SAFEYOLO_NATIVE_CLI", acquisition.REPO / "proxy/target/release/safeyolo",
    )))
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


def stock_runsc(bundle):
    """Use the exact retained stock pin with controlled executable identities."""
    metadata = bundle / "package-info"
    metadata.write_text(metadata.read_text().replace(
        "release-20261005.0-safeyolo.1", "release-20261005.0",
    ).replace(
        "https://github.com/google/gvisor/commit/97e8e896904cb364319cd9758241d3f0bd27a6f4",
        "https://github.com/google/gvisor/releases/tag/release-20261005.0",
    ))
    executable(bundle / "libexec/runsc", "runsc version release-20261005.0")
    for name in ("gvisor_sentry", "gvisor-sentry-prewarmer", "runsc-fd-parking"):
        shutil.copy2(bundle / "libexec/runsc", bundle / "libexec/gvisor-bin" / name)
    checksums(bundle)


@pytest.fixture
def stock_installation(native_cli, host_pair, registry, guest_store, tmp_path):
    first, second = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    # Acquisition sets up current-format guest inputs before we retain the
    # installed stock package. A fresh target cannot use that stock pin.
    stock_runsc(first)
    for name in ("package-info", "SHA256SUMS", "libexec/runsc",
                 "libexec/gvisor-bin/gvisor_sentry", "libexec/gvisor-bin/gvisor-sentry-prewarmer",
                 "libexec/gvisor-bin/runsc-fd-parking"):
        shutil.copy2(first / name, root / name)
    return root, second


@pytest.mark.parametrize("omitted_installers", [False, True])
@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
def test_stock_installed_pair_status_upgrade_and_rollback(
        native_cli, stock_installation, registry, omitted_installers):
    root, target = stock_installation
    _contents, requests, _faults, environment = registry
    if omitted_installers:
        for name in ("install.sh", "install_native.sh", "native_package.sh"):
            (root / name).unlink()
    original = upgrade(native_cli, root, environment, "status")
    assert original["current"]["host"]["runsc_version"] == "release-20261005.0"
    assert original["previous"] is None
    saved = state_files(root)
    receipt = (root / "SHA256SUMS").read_bytes()
    tree = (root / "share/rootfs-tree").resolve()
    tree_identity = tree.stat().st_ino, tree.stat().st_uid, tree.stat().st_gid
    before = len(requests)
    selected = upgrade(native_cli, root, environment, "--bundle", target)
    assert selected["current"]["host"]["runsc_version"] == "release-20261005.0-safeyolo.1"
    assert selected["previous"] == original["current"]
    assert selected["current"]["guest"] == original["current"]["guest"]
    assert upgrade(native_cli, root, environment, "status") == selected
    link = os.readlink(root / "current")
    assert upgrade(native_cli, root, environment, "--bundle", target) == selected
    assert os.readlink(root / "current") == link
    assert upgrade(native_cli, root, environment, "rollback") == original
    assert (root / "SHA256SUMS").read_bytes() == receipt
    assert (root / "share/rootfs-tree").resolve() == tree
    assert (tree.stat().st_ino, tree.stat().st_uid, tree.stat().st_gid) == tree_identity
    assert len(requests) == before
    assert_preserved(root, saved)


@pytest.mark.parametrize("fault", [
    "current-checksum", "current-runtime", "current-source", "target-checksum",
    "target-stock", "target-runtime", "target-source", "target-origin", "target-profile",
])
def test_runsc_pin_refusals_preserve_current_and_state(
        native_cli, stock_installation, registry, fault):
    root, target = stock_installation
    _contents, _requests, _faults, environment = registry
    saved = preserved(root)
    current = os.readlink(root / "current") if (root / "current").is_symlink() else None
    selection = (root / "share/guest-selection.json").read_bytes()
    package = (root / "package-info").resolve().parent if fault.startswith("current-") else target
    if fault.endswith("checksum"):
        with (package / "libexec/gvisor-bin/gvisor_sentry").open("ab") as stream:
            stream.write(b"tampered")
    elif fault == "target-stock":
        stock_runsc(target)
    elif fault.endswith("runtime"):
        version = "release-20261005.0-safeyolo.1" if fault.startswith("current-") else "release-20261005.0"
        executable(package / "libexec/runsc", f"runsc version {version}")
        checksums(package)
    else:
        metadata = package / "package-info"
        text = metadata.read_text()
        if fault.endswith("source"):
            text = text.replace("https://github.com/google/gvisor/", "https://example.test/")
        elif fault.endswith("origin"):
            text = text.replace("runsc_origin=bundled", "runsc_origin=system")
        else:
            text = text.replace("profile=debug", "profile=invalid")
        metadata.write_text(text)
        checksums(package)
    # Save after deliberate metadata damage; validation must make no changes.
    saved["package-info"] = (root / "package-info").read_bytes()
    original = upgrade(native_cli, root, environment, "status") if fault != "current-source" else None
    refused = command(native_cli, root, environment, "upgrade", "--bundle", str(target))
    assert refused.returncode != 0
    assert "gVisor" in refused.stderr or "checksum" in refused.stderr or "source/profile" in refused.stderr
    assert (os.readlink(root / "current") if (root / "current").is_symlink() else None) == current
    assert (root / "share/guest-selection.json").read_bytes() == selection
    assert_preserved(root, saved)
    if fault != "current-source":
        assert upgrade(native_cli, root, environment, "status") == original


@pytest.mark.parametrize("fault", ["checksum", "runtime"])
def test_bad_retained_stock_runtime_cannot_replace_current_on_rollback(
        native_cli, stock_installation, registry, fault):
    root, target = stock_installation
    _contents, _requests, _faults, environment = registry
    upgrade(native_cli, root, environment, "--bundle", target)
    current = os.readlink(root / "current")
    saved = preserved(root)
    previous = (root / "current/previous/host").resolve()
    if fault == "checksum":
        with (previous / "libexec/runsc").open("ab") as stream:
            stream.write(b"tampered")
    else:
        executable(previous / "libexec/runsc", "runsc version release-20261005.0-safeyolo.1")
        checksums(previous)
    # Record the deliberately changed receipt before checking refusal effects.
    selected = upgrade(native_cli, root, environment, "status")
    refused = command(native_cli, root, environment, "upgrade", "rollback")
    assert refused.returncode != 0
    assert "checksum" in refused.stderr or "incompatible gVisor runtime" in refused.stderr
    assert os.readlink(root / "current") == current
    assert upgrade(native_cli, root, environment, "status") == selected
    assert_preserved(root, saved)


@pytest.mark.parametrize("store_state", ["absent", "compatible", "incompatible", "corrupt", "identity"])
def test_rollback_checks_retained_coord_before_selection(
        native_cli, stock_installation, registry, tmp_path, store_state):
    """Run the prior CLI's real Coord contract, independently of package labels."""
    root, target = stock_installation
    _contents, requests, _faults, environment = registry
    prior = Path(os.environ.get("SAFEYOLO_ROLLBACK_PRIOR_CLI", native_cli))
    environment = {**environment, "PACKAGE_COORD_CLI": str(prior)}
    # Exercise the configured producer path rather than assuming ROOT/data.
    data = tmp_path / "retained-data"
    config = root / "config.toml"
    config.write_text(f"data_dir = {json.dumps(str(data))}\n" + config.read_text())
    store = data / "coord/v0.db"
    if store_state != "absent":
        produced = command(prior, root, environment, "coord", "room", "list")
        assert produced.returncode == 0, produced.stderr
    original = upgrade(native_cli, root, environment, "status")
    original_receipt = (root / "SHA256SUMS").read_bytes()
    selected = upgrade(native_cli, root, environment, "--bundle", target)
    if store_state == "incompatible":
        advanced = command(native_cli, root, environment, "coord", "room", "list")
        assert advanced.returncode == 0, advanced.stderr
    connection = sqlite3.connect(store) if store.exists() else None
    try:
        if connection is not None:
            connection.execute("PRAGMA journal_mode=WAL")
            # Retained work and schema changes must be copied from the WAL,
            # including while its writer still has the database open.
            if store_state == "incompatible" and prior.resolve() == native_cli.resolve():
                version, = connection.execute("PRAGMA user_version").fetchone()
                connection.execute(f"PRAGMA user_version={version + 1}")
            connection.execute("CREATE TABLE rollback_canary(value)")
            connection.execute("INSERT INTO rollback_canary VALUES ('retained work')")
            if store_state == "identity":
                connection.execute("UPDATE instance SET id='another-instance'")
            connection.commit()
            if store_state == "corrupt":
                connection.close()
                connection = None
                store.write_bytes(b"unreadable retained store")
        saved = state_files(root)
        current = os.readlink(root / "current")
        receipt = (root / "SHA256SUMS").read_bytes()
        selection = (root / "share/guest-selection.json").read_bytes()
        retained = {path.name: path.read_bytes() for path in store.parent.glob("v0.db*")
                    if path.name != "v0.db-shm"}
        before_requests = len(requests)
        result = command(native_cli, root, environment, "upgrade", "rollback")
        if store_state in ("absent", "compatible"):
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout) == original
        else:
            assert result.returncode != 0
            assert "rollback refused before changing selection" in result.stderr
            assert "selected pair and retained state are unchanged" in result.stderr
            assert "start" in result.stderr and str(root) in result.stderr
            assert os.readlink(root / "current") == current
            assert upgrade(native_cli, root, environment, "status") == selected
            if store_state == "incompatible":
                assert "expected version" in result.stderr
            if store_state == "identity":
                assert "identity differs" in result.stderr
        assert_preserved(root, saved)
        assert (root / "share/guest-selection.json").read_bytes() == selection
        assert (root / "SHA256SUMS").read_bytes() == (
            original_receipt if store_state in ("absent", "compatible") else receipt
        )
        assert {path.name: path.read_bytes() for path in store.parent.glob("v0.db*")
                if path.name != "v0.db-shm"} == retained
        assert not list(root.glob("rollback-coord-*"))
        assert len(requests) == before_requests
    finally:
        if connection is not None:
            connection.close()


@pytest.mark.parametrize("stock", [False, True])
@pytest.mark.parametrize("installed", [False, True])
def test_shell_verifier_distinguishes_installed_and_target_runsc_pins(host_pair, stock, installed):
    bundle, _target = host_pair
    if stock:
        stock_runsc(bundle)
    result = packages.run(
        "bash", "-c", 'source "$1"; verify_native_package "$2" "${3:-}"',
        "verify", str(packages.REPO / "scripts/native_package.sh"), str(bundle),
        "--installed" if installed else "",
    )
    assert (result.returncode == 0) == (installed or not stock), result.stderr


@pytest.mark.parametrize("fault", ["checksum", "runtime", "source", "origin", "missing", "unlisted"])
def test_shell_installed_stock_runtime_keeps_integrity_checks(host_pair, fault):
    bundle, _target = host_pair
    stock_runsc(bundle)
    if fault == "checksum":
        with (bundle / "libexec/gvisor-bin/gvisor_sentry").open("ab") as stream:
            stream.write(b"tampered")
    elif fault == "runtime":
        executable(bundle / "libexec/runsc", "runsc version release-20261005.0-safeyolo.1")
        checksums(bundle)
    elif fault in ("source", "origin"):
        metadata = bundle / "package-info"
        text = metadata.read_text()
        metadata.write_text(text.replace("releases/tag/release-20261005.0", "commit/unknown")
                            if fault == "source" else text.replace("runsc_origin=bundled", "runsc_origin=system"))
        checksums(bundle)
    elif fault == "missing":
        (bundle / "libexec/gvisor-bin/gvisor_sentry").unlink()
    else:
        sums = bundle / "SHA256SUMS"
        sums.write_text("".join(line for line in sums.read_text().splitlines(keepends=True)
                                if not line.endswith(" ./libexec/gvisor-bin/gvisor_sentry\n")))
    result = packages.run(
        "bash", "-c", 'source "$1"; verify_native_package "$2" --installed',
        "verify", str(packages.REPO / "scripts/native_package.sh"), str(bundle),
    )
    assert result.returncode != 0
    assert "gVisor" in result.stderr or "checksum" in result.stderr


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
                         "credentials", "add", "kept", "--storage", "local", "--value-env", "UPGRADE_TEST_CREDENTIAL")
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


def use_legacy_guest_location(root):
    """Seed the digest-only paths written by the original shipped host."""
    record = root / "share/guest-selection.json"
    selection = json.loads(record.read_bytes())
    archive_hex = selection["archive"]["digest"].removeprefix("sha256:")
    assets = Path(selection["assets"])
    legacy_assets = assets.with_name(archive_hex)
    assets.rename(legacy_assets)
    selection["assets"] = str(legacy_assets)
    inputs = Path(selection.get("installed_assets", root / "share"))
    if "installed_assets" in selection:
        legacy_inputs = inputs.with_name(archive_hex)
        inputs.rename(legacy_inputs)
        inputs = legacy_inputs
        selection["installed_assets"] = str(inputs)
    (inputs / "rootfs-tree").unlink()
    (inputs / "rootfs-tree").symlink_to(legacy_assets / "rootfs-tree")
    record.write_text(json.dumps(selection))
    return selection


@pytest.mark.parametrize("caller", ["guest", "complete-pair"])
def test_legacy_guest_locations_allow_mapping_specific_upgrade_reuse_and_rollback(
        native_cli, host_pair, registry, guest_store, tmp_path, caller):
    first, second = host_pair
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    g1 = use_legacy_guest_location(root)
    g2_release = release(compressed_archive(content=b"G2 base"), version="guest-2026-10-16.2")
    contents.update(g2_release)
    prepared = command(native_cli, root, environment, "guest", "upgrade")
    assert prepared.returncode == 0, prepared.stderr
    legacy_g2 = use_legacy_guest_location(root)
    rolled = command(native_cli, root, environment, "guest", "rollback")
    assert rolled.returncode == 0, rolled.stderr
    assert json.loads(rolled.stdout) == g1
    legacy_assets = Path(legacy_g2["assets"])
    legacy_inputs = Path(legacy_g2["installed_assets"])
    legacy_link = os.readlink(legacy_inputs / "rootfs-tree")
    legacy_inode = (legacy_assets / "rootfs-tree").stat().st_ino
    saved = state_files(root)
    original = upgrade(native_cli, root, environment, "status")
    active = (root / "share/guest-selection.json").read_bytes()
    index = digest(g2_release["manifests/compat-v1"])
    contents["manifests/" + index] = g2_release["manifests/compat-v1"]
    arguments = (["guest", "upgrade", "--index", index] if caller == "guest" else
                 ["upgrade", "--bundle", str(second), "--guest-index", index])
    rollback = ["guest", "rollback"] if caller == "guest" else ["upgrade", "rollback"]
    before = len(requests)
    selected = command(native_cli, root, environment, *arguments)
    assert selected.returncode == 0, selected.stderr
    g2 = json.loads((root / "share/guest-selection.json").read_bytes())
    assets, inputs = Path(g2["assets"]), Path(g2["installed_assets"])
    assert assets != legacy_assets and inputs != legacy_inputs
    assert inputs.name == assets.name and inputs.name.startswith(legacy_assets.name + "-uid")
    assert (inputs / "rootfs-tree").resolve() == assets / "rootfs-tree"
    assert (assets / "rootfs-tree").stat().st_ino != legacy_inode
    assert subprocess.check_output(["sudo", "-n", "cat", str(inputs / "rootfs-tree/command")]) == b"G2 base"
    assert g2["previous"] == g1
    expected_host = "b" * 40 if caller == "complete-pair" else original["current"]["host"]["source_commit"]
    assert upgrade(native_cli, root, environment, "status")["current"]["host"]["source_commit"] == expected_host
    identities = [path.stat().st_ino for path in (assets, assets / "rootfs-tree", inputs)]
    repeated = command(native_cli, root, environment, *arguments)
    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(repeated.stdout) == json.loads(selected.stdout)
    assert [path.stat().st_ino for path in (assets, assets / "rootfs-tree", inputs)] == identities
    assert not any("/blobs/" in path for path in requests[before:])
    restored = command(native_cli, root, environment, *rollback)
    assert restored.returncode == 0, restored.stderr
    assert upgrade(native_cli, root, environment, "status")["current"] == original["current"]

    # An existing mapping-specific location must still match the exact cached
    # root and its ownership. Neither refusal may change the active selection.
    unowned = guest_store / "unowned-root"
    unowned.mkdir()
    for target, error in ((legacy_assets / "rootfs-tree", "installed rootfs tree differs"),
                          (unowned, "prepared rootfs-tree must be a directory owned by")):
        link = inputs / "rootfs-tree"
        link.unlink()
        link.symlink_to(target)
        refused = command(native_cli, root, environment, *arguments)
        assert refused.returncode != 0 and error in refused.stderr
        assert (root / "share/guest-selection.json").read_bytes() == active
        assert upgrade(native_cli, root, environment, "status")["current"] == original["current"]
        link.unlink()
        link.symlink_to(assets / "rootfs-tree")
    retried = command(native_cli, root, environment, *arguments)
    assert retried.returncode == 0, retried.stderr
    assert [path.stat().st_ino for path in (assets, assets / "rootfs-tree", inputs)] == identities
    assert not any("/blobs/" in path for path in requests[before:])
    restored = command(native_cli, root, environment, *rollback)
    assert restored.returncode == 0, restored.stderr
    assert upgrade(native_cli, root, environment, "status")["current"] == original["current"]
    assert os.readlink(legacy_inputs / "rootfs-tree") == legacy_link
    assert (legacy_assets / "rootfs-tree").stat().st_ino == legacy_inode
    assert subprocess.check_output(["sudo", "-n", "cat", str(legacy_inputs / "rootfs-tree/command")]) == b"G2 base"
    assert subprocess.check_output(["sudo", "-n", "cat", str(root / "share/rootfs-tree/command")]) == b"guest bytes"
    assert_preserved(root, saved)


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
    published, archive_key = publish_host(contents, second)
    tag = published["tag_name"]
    archive_bytes = contents[archive_key]
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
        contents[archive_key] = archive_bytes
        faults["partial"] = None
    selected = upgrade(native_cli, root, environment, "--release", tag)
    assert selected["current"]["host"]["source_commit"] == "b" * 40
    assert selected["current"]["guest"] == original["current"]["guest"]
    before = len(requests)
    assert upgrade(native_cli, root, environment, "--release", tag) == selected
    assert archive_key not in requests[before:]
    assert upgrade(native_cli, root, environment, "rollback")["current"]["host"]["source_commit"] != "b" * 40
    assert_preserved(root, saved)


def publish_host(contents, bundle):
    """Expose the producer's host archive/checksum names through the TLS fixture."""
    metadata = dict(line.split("=", 1) for line in (bundle / "package-info").read_text().splitlines())
    name = f"safeyolo-{metadata['platform']}-production"
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as stream:
        stream.add(bundle, arcname=name)
    tag = "host-" + metadata["source_commit"]
    base = "/craigbalding/safeyolo/releases/download/" + tag
    archive_key = f"{base}/{name}.tar.gz"
    contents[archive_key] = archive.getvalue()
    contents[base + "/SHA256SUMS"] = (
        hashlib.sha256(archive.getvalue()).hexdigest() + f"  {name}.tar.gz\n"
    ).encode()
    return {"tag_name": tag, "draft": False, "prerelease": False,
            "published_at": "2026-11-09T12:00:00Z",
            "assets": [{"name": name + ".tar.gz", "size": len(archive.getvalue())},
                       {"name": "SHA256SUMS", "size": len(contents[base + "/SHA256SUMS"])}]}, archive_key


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
def test_guided_discovery_preview_and_failed_acquisition_reuse_verified_target(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, target = host_pair
    contents, requests, faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    saved = state_files(root)
    published, archive_key = publish_host(contents, target)
    # An input-transfer prerelease and a host for another platform must not be
    # offered as supported production upgrades for this consumer.
    contents["/repos/craigbalding/safeyolo/releases"] = json.dumps([
        {**published, "tag_name": "input-transfer", "prerelease": True},
        {**published, "assets": [{"name": "safeyolo-darwin-arm64-production.tar.gz", "size": 10}]},
        published,
    ]).encode()
    environment = {**environment, "HOME": str(tmp_path / "consumer"),
                   "CURL_CA_BUNDLE": environment["SSL_CERT_FILE"]}
    choices = upgrade(native_cli, root, environment, "releases")
    assert [choice["release"] for choice in choices["releases"]] == [published["tag_name"]]
    faults["partial"] = archive_key
    failed = command(native_cli, root, environment, "upgrade", "--preview")
    assert failed.returncode != 0
    failure = json.loads(failed.stdout)
    assert failure["outcome"] == "incomplete"
    assert failure["selected"] == original
    assert failure["root"] == str(root.resolve())
    assert "inspect" in failure["next_action"]
    assert "rollback" not in failure["next_action"]
    faults["partial"] = None
    view = upgrade(native_cli, root, environment, "--preview")
    assert view["outcome"] == "preview_only"
    assert view["selected"] == original
    assert view["proposed"]["host"]["source_commit"] == "b" * 40
    assert view["proposed"]["guest"] == original["current"]["guest"]
    assert view["observed"]["proxy"]["state"] == "unknown"
    assert not (root / "safeyolo-upgrade").exists()
    assert upgrade(native_cli, root, environment, "status") == original
    assert_preserved(root, saved)
    before = len(requests)
    view = upgrade(native_cli, root, environment, "--release", published["tag_name"], "--preview")
    assert view["proposed"]["guest"] == original["current"]["guest"]
    assert archive_key not in requests[before:]
    assert all("/v2/" not in path for path in requests[before:])
    assert upgrade(native_cli, root, environment, "status") == original


def test_guided_preview_pins_discovered_compatible_guest_and_reports_unknown_discovery(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, target = host_pair
    contents, requests, faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    saved = state_files(root)
    metadata = target / "package-info"
    metadata.write_text(metadata.read_text().replace("guest_compatibility=v1", "guest_compatibility=v2")
                        .replace("guest_discovery_tag=compat-v1", "guest_discovery_tag=compat-v2"))
    checksums(target)
    failed = command(native_cli, root, environment, "upgrade", "--bundle", str(target), "--preview")
    assert failed.returncode != 0
    failure = json.loads(failed.stdout)
    assert "compatible guest discovery unavailable" in failure["error"]
    assert "--guest-index" in failure["error"]
    assert failure["selected"] == original
    archive = compressed_archive(content=b"G2")
    discovered = release(archive, version="guest-2026-11-09.1", compatibility="v2")
    index = discovered.pop("manifests/compat-v1")
    contents.update(discovered)
    contents["manifests/compat-v2"] = index
    contents["manifests/" + digest(index)] = index
    before = len(requests)
    faults["partial"] = "blobs/" + digest(archive)
    failed = command(native_cli, root, environment, "upgrade", "--bundle", str(target), "--preview")
    assert failed.returncode != 0
    failure = json.loads(failed.stdout)
    retry = failure["next_action"]["retry_after_inspection"]
    assert retry[retry.index("--guest-index") + 1] == digest(index)
    assert failure["selected"] == original
    faults["partial"] = None
    assert requests[before:].count(acquisition.PREFIX + "manifests/compat-v2") == 1
    # Retry the exact pinned target even after discovery disappears.
    del contents["manifests/compat-v2"]
    view = upgrade(native_cli, root, environment, "--bundle", target,
                   "--guest-index", digest(index), "--preview")
    assert view["proposed"]["guest"]["compatibility"] == "v2"
    assert view["proposed"]["guest"]["index"]["digest"] == digest(index)
    assert upgrade(native_cli, root, environment, "status") == original
    assert_preserved(root, saved)


def test_guided_unavailable_host_discovery_retains_explicit_bundle_path(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, target = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    environment = {**environment, "CURL_CA_BUNDLE": environment["SSL_CERT_FILE"]}
    for response in (None, {}, []):
        if response is not None:
            contents["/repos/craigbalding/safeyolo/releases"] = json.dumps(response).encode()
        failed = command(native_cli, root, environment, "upgrade", "releases")
        assert failed.returncode != 0
        unavailable = json.loads(failed.stdout)
        assert unavailable["state"] == "unavailable"
        assert unavailable["root"] == str(root)
        assert "--bundle" in unavailable["explicit_selection"]
        assert upgrade(native_cli, root, environment, "status") == original
    preview = upgrade(native_cli, root, environment, "--bundle", target, "--preview")
    assert preview["selected"] == original
    assert preview["outcome"] == "preview_only"


@pytest.mark.parametrize("coord_state", ["compatible", "incompatible"])
def test_guided_activation_failure_reports_selected_pair_and_retained_rollback(
        native_cli, host_pair, registry, guest_store, tmp_path, coord_state):
    first, target = host_pair
    contents, _requests, _faults, environment = registry
    prior = (Path(os.environ.get("SAFEYOLO_ROLLBACK_PRIOR_CLI", native_cli))
             if coord_state == "incompatible" else native_cli)
    environment = {**environment, "PACKAGE_COORD_CLI": str(prior)}
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    saved = state_files(root)
    # This checked target intentionally exits instead of running a proxy.
    # The failure must describe the new selection without claiming activation.
    try:
        failed = command(native_cli, root, environment, "upgrade", "--bundle", str(target), "--activate")
        assert failed.returncode != 0
        failure = json.loads(failed.stdout)
        assert failure["outcome"] == "incomplete"
        assert failure["selected"]["current"]["host"]["source_commit"] == "b" * 40
        assert failure["selected"]["previous"] == original["current"]
        assert failure["observed"]["proxy"]["state"] != "running"
        assert failure["next_action"]["rollback"] == [str(root / "safeyolo-upgrade"), "--root", str(root), "rollback"]
        assert "can refuse without changing selection" in failure["next_action"]["limit"]
        assert "only after rollback succeeds" in failure["next_action"]["limit"]
        if coord_state == "compatible":
            assert upgrade(native_cli, root, environment, "rollback") == original
        else:
            store = root / "data/coord/v0.db"
            if prior.resolve() == native_cli.resolve():
                with sqlite3.connect(store) as connection:
                    version, = connection.execute("PRAGMA user_version").fetchone()
                    connection.execute(f"PRAGMA user_version={version + 1}")
            retained = store.read_bytes()
            link = os.readlink(root / "current")
            refused = command(native_cli, root, environment, "upgrade", "rollback")
            assert refused.returncode != 0
            assert "rollback refused before changing selection" in refused.stderr
            assert "expected version" in refused.stderr
            assert os.readlink(root / "current") == link
            assert store.read_bytes() == retained
            assert upgrade(native_cli, root, environment, "status") == failure["selected"]
        assert_preserved(root, saved)
    finally:
        assert command(native_cli, root, environment, "stop").returncode == 0



@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
def test_terminal_upgrade_can_defer_activation_after_choosing_a_release(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, target = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    saved = state_files(root)
    published, _archive_key = publish_host(contents, target)
    contents["/repos/craigbalding/safeyolo/releases"] = json.dumps([published]).encode()
    environment = {**environment, "HOME": str(tmp_path / "consumer"),
                   "CURL_CA_BUNDLE": environment["SSL_CERT_FILE"]}
    terminal, slave = pty.openpty()
    try:
        # Choose the displayed default release, then defer activation through
        # the real terminal interface, without spelling a release identifier.
        os.write(terminal, b"\nn\n")
        deferred = subprocess.run([str(native_cli), "--root", str(root), "upgrade"],
                                  env=environment, stdin=slave, stderr=slave,
                                  stdout=subprocess.PIPE, text=True, timeout=30)
        assert deferred.returncode == 0, deferred.stdout
        assert "Selection is unchanged" in deferred.stdout
    finally:
        os.close(slave)
        os.close(terminal)
    assert upgrade(native_cli, root, environment, "status") == original
    assert not (root / "safeyolo-upgrade").exists()
    assert not (root / "data/proxy-process.json").exists()
    assert_preserved(root, saved)


def test_guided_invalid_agent_choice_does_not_select_or_interrupt(
        native_cli, host_pair, registry, guest_store, tmp_path):
    first, target = host_pair
    contents, _requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "i"
    installation(native_cli, root, first, guest_store, environment)
    original = upgrade(native_cli, root, environment, "status")
    failed = command(native_cli, root, environment, "upgrade", "--bundle", str(target),
                     "--activate", "--restart-agent", "missing")
    assert failed.returncode != 0
    assert "agent not found: missing" in failed.stderr
    assert upgrade(native_cli, root, environment, "status") == original
    assert not (root / "safeyolo-upgrade").exists()


def test_guided_installed_upgrade_keeps_other_instance_live_and_recovers_failed_start(
        registry, tmp_path, guest_store):
    """Use two real packages; this proves proxy activation, not a guest boot."""
    baseline = os.environ.get("SAFEYOLO_UPGRADE_FROM_BUNDLE")
    target = os.environ.get("SAFEYOLO_NATIVE_BUNDLE")
    candidate_cli = os.environ.get("SAFEYOLO_NATIVE_CLI")
    nats = os.environ.get("SAFEYOLO_COORD_NATS_BINARY")
    if not all((baseline, target, candidate_cli, nats)):
        pytest.skip("set both verified bundles, candidate CLI and NATS for the installed upgrade")
    baseline, target, candidate_cli = Path(baseline), Path(target), Path(candidate_cli)
    before_metadata = dict(line.split("=", 1) for line in (baseline / "package-info").read_text().splitlines())
    target_metadata = dict(line.split("=", 1) for line in (target / "package-info").read_text().splitlines())
    assert before_metadata["source_commit"] != target_metadata["source_commit"]
    assert before_metadata["profile"] == target_metadata["profile"]
    assert before_metadata["platform"] == target_metadata["platform"]
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    # Disk-backed roots remain short enough for Unix listener paths.
    root, unrelated = tmp_path.parent / "u", tmp_path.parent / "v"
    environment = {**environment, "HOME": str(guest_store.parents[3]),
                   "SAFEYOLO_NATS_TEST_INSTANCE": "guided-upgrade-installed",
                   "TERM": "xterm-256color"}
    for instance in (root, unrelated):
        installed = subprocess.run([str(baseline / "install.sh"), "--root", str(instance),
                                    "--command-dir", str(instance / "commands"), "--yes"],
                                   env=environment, capture_output=True, text=True, timeout=30)
        assert installed.returncode == 0, installed.stderr
        config = instance / "config.toml"
        config.write_text(config.read_text().replace("admin_port = 9090", "admin_port = 0"))
    try:
        for instance in (root, unrelated):
            coord = command(candidate_cli, instance, environment, "coord", "start", "--binary", nats)
            assert coord.returncode == 0, coord.stderr
            started = command(candidate_cli, instance, environment, "start")
            assert started.returncode == 0, started.stderr
        other_proxy = (unrelated / "data/proxy-process.json").read_bytes()
        original = upgrade(candidate_cli, root, environment, "status")
        credential = command(candidate_cli, root, {**environment, "UPGRADE_PROOF_SECRET": "retained"},
                             "credentials", "add", "kept", "--storage", "local", "--value-env", "UPGRADE_PROOF_SECRET")
        assert credential.returncode == 0, credential.stderr
        (root / "agents/retained/home").mkdir(parents=True)
        (root / "agents/retained/home/keep").write_bytes(b"persistent home")
        (root / "logs/audit-canary").write_bytes(b"persistent audit")
        saved = state_files(root)
        saved.pop("config.toml")  # Startup updates reload_id; check operator values below.
        configured = tomllib.loads((root / "config.toml").read_text())
        configured.pop("reload_id", None)
        before_proxy = (root / "data/proxy-process.json").read_bytes()
        view = upgrade(candidate_cli, root, environment, "--bundle", target, "--preview")
        assert view["observed"]["proxy"]["matches_selected_host"] is True
        assert view["proposed"]["guest"] == original["current"]["guest"]
        assert (root / "data/proxy-process.json").read_bytes() == before_proxy
        assert (unrelated / "data/proxy-process.json").read_bytes() == other_proxy
        # A valid configuration can still fail activation on an occupied port.
        # Bind the port ourselves; do not change or signal an unrelated runtime.
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            config = root / "config.toml"
            config.write_text(config.read_text().replace("admin_port = 0", f"admin_port = {port}"))
            failed = command(candidate_cli, root, environment, "upgrade", "--bundle", str(target), "--activate")
            assert failed.returncode != 0
            failure = json.loads(failed.stdout)
            assert failure["outcome"] == "incomplete"
            assert failure["selected"]["current"]["host"]["source_commit"] == target_metadata["source_commit"]
            assert failure["selected"]["previous"] == original["current"]
            assert failure["observed"]["proxy"]["state"] != "running"
            assert (unrelated / "data/proxy-process.json").read_bytes() == other_proxy
        config.write_text(config.read_text().replace(f"admin_port = {port}", "admin_port = 0"))
        # Remove registry responses: this exact bundle and retained guest must
        # work without another acquisition, including the retry and rollback.
        contents.clear()
        before_requests = len(requests)
        activated = upgrade(candidate_cli, root, environment, "--bundle", target, "--activate")
        assert activated["outcome"] == "proxy_activated"
        assert activated["observed"]["proxy"]["matches_selected_host"] is True
        assert activated["agent_restart_commands_completed"] == []
        selected_link = os.readlink(root / "current")
        current_proxy = (root / "data/proxy-process.json").read_bytes()
        repeated = upgrade(candidate_cli, root, environment, "--bundle", target, "--activate")
        assert repeated["outcome"] == "proxy_activated"
        assert (root / "data/proxy-process.json").read_bytes() == current_proxy
        assert os.readlink(root / "current") == selected_link
        assert command(candidate_cli, root, environment, "stop").returncode == 0
        recovery = command(root / "safeyolo-upgrade", root, environment, "rollback")
        assert recovery.returncode == 0, recovery.stderr
        assert json.loads(recovery.stdout)["current"] == original["current"]
        assert command(candidate_cli, root, environment, "start").returncode == 0
        restored = upgrade(candidate_cli, root, environment, "--bundle", target, "--preview")
        assert restored["observed"]["proxy"]["matches_selected_host"] is True
        assert restored["selected"]["current"] == original["current"]
        assert len(requests) == before_requests
        assert_preserved(root, saved)
        restarted_config = tomllib.loads(config.read_text())
        restarted_config.pop("reload_id", None)
        assert restarted_config == configured
        assert (unrelated / "data/proxy-process.json").read_bytes() == other_proxy
        assert json.loads(command(candidate_cli, unrelated, environment, "status").stdout)["proxy_state"] == "running"
    finally:
        for instance in (root, unrelated):
            assert command(candidate_cli, instance, environment, "stop").returncode == 0
            assert command(candidate_cli, instance, environment, "coord", "stop").returncode == 0
