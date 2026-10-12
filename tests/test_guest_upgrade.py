"""Exercise explicit native selection, rollback and preserved installed state.

Local anonymous TLS registries exercise the native caller. These controls do
not establish the public GHCR or booted-platform results owned by issue #239.
"""

import copy
import hashlib
import json
import os
import subprocess
import tomllib
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests import test_guest_acquisition as acquisition
from tests.test_guest_acquisition import (
    PREFIX,
    compressed_archive,
    digest,
    install,
    release,
)

native_cli = acquisition.native_cli
registry = acquisition.registry
package_info = acquisition.package_info
guest_store = acquisition.guest_store


def command(binary, root, environment, *arguments):
    return subprocess.run([str(binary), "--root", str(root), *arguments], env=environment,
                          capture_output=True, text=True, timeout=30)


def installed(binary, root, store, environment, metadata):
    result = install(binary, root, store, environment, metadata)
    assert result.returncode == 0, result.stderr
    (root / "package-info").write_bytes(metadata.read_bytes())
    result = command(binary, root, environment, "init")
    assert result.returncode == 0, result.stderr
    result = command(binary, root, {**environment, "GUEST_UPGRADE_TEST_CREDENTIAL": "synthetic-kept-credential"},
                     "credentials", "add", "kept", "--value-env", "GUEST_UPGRADE_TEST_CREDENTIAL")
    assert result.returncode == 0, result.stderr
    home = root / "agents/retained/home"
    home.mkdir(parents=True)
    (home / "keep").write_bytes(b"persistent agent home")
    (root / "logs/audit-canary").write_bytes(b"persistent audit data")
    return (root / "share/guest-selection.json").read_bytes()


def preserved(root):
    names = ["package-info", "config.toml", "policy.toml", "data/admin_token", "data/agent_token",
             "data/instance_id", "data/credentials.key", "data/credentials.enc",
             "agents/retained/home/keep", "logs/audit-canary"]
    return {name: (root / name).read_bytes() for name in names}


def assert_preserved(root, original):
    changed = [name for name, data in original.items() if (root / name).read_bytes() != data]
    assert not changed, f"modified installed files: {', '.join(changed)}"


def test_explicit_upgrade_pins_reuses_and_rolls_back_without_changing_host_or_state(
        native_cli, registry, package_info, tmp_path, guest_store):
    contents, requests, faults, environment = registry
    first = release(compressed_archive())
    second = release(compressed_archive(content=b"G2 guest"), version="guest-2026-10-12.2")
    third = release(compressed_archive(content=b"G3 guest"), version="guest-2026-10-12.3")
    contents.update(first)
    root = tmp_path / "h"
    original_selection = installed(native_cli, root, guest_store, environment, package_info)
    original = preserved(root)
    g1 = json.loads(original_selection)
    old_root = (root / "share/rootfs-tree").resolve()
    old_inode = old_root.stat().st_ino
    contents.update(second)
    faults["advance"] = third
    before = len(requests)
    result = command(native_cli, root, environment, "guest", "upgrade")
    assert result.returncode == 0, result.stderr
    g2 = json.loads(result.stdout)
    assert g2["version"] == "guest-2026-10-12.2"
    assert g2["index"]["digest"] == digest(second["manifests/compat-v1"])
    assert g2["previous"] == g1
    assert requests[before:].count(PREFIX + "manifests/compat-v1") == 1
    assert all(path.startswith(PREFIX) or path in ("/v2/", "/token") for path in requests[before:])
    selected_tree = Path(g2["installed_assets"]) / "rootfs-tree"
    assert selected_tree.is_symlink() and selected_tree.resolve() != old_root
    assert selected_tree.stat().st_uid == selected_tree.stat().st_gid == 100000
    assert old_root.stat().st_ino == old_inode
    assert (root / "share/rootfs-tree").resolve() == old_root
    assert_preserved(root, original)

    before = len(requests)
    installed_inode = Path(g2["installed_assets"]).stat().st_ino
    tree_inode = Path(g2["assets"]).stat().st_ino
    contents["manifests/" + g2["index"]["digest"]] = second["manifests/compat-v1"]
    result = command(native_cli, root, environment, "guest", "upgrade", "--index", g2["index"]["digest"])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == g2
    assert Path(g2["installed_assets"]).stat().st_ino == installed_inode
    assert Path(g2["assets"]).stat().st_ino == tree_inode
    assert all("/blobs/" not in path and not path.endswith("compat-v1") for path in requests[before:])

    before = len(requests)
    for _ in range(2):
        result = command(native_cli, root, environment, "guest", "rollback")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == g1
        assert_preserved(root, original)
    assert len(requests) == before
    assert Path(g2["assets"]).exists() and Path(g2["installed_assets"]).exists()


@pytest.mark.parametrize("changed_first", [False, True], ids=["initial-selection", "existing-rollback"])
def test_metadata_only_upgrade_retains_previous_release_and_reuses_inputs(
        native_cli, registry, package_info, tmp_path, guest_store, changed_first):
    contents, requests, _faults, environment = registry
    archive = compressed_archive()
    contents.update(release(archive))
    root = tmp_path / "h"
    installed(native_cli, root, guest_store, environment, package_info)
    original = preserved(root)
    if changed_first:
        archive = compressed_archive(content=b"G2 guest")
        contents.update(release(archive, version="guest-2026-10-12.2"))
        result = command(native_cli, root, environment, "guest", "upgrade")
        assert result.returncode == 0, result.stderr
    current = json.loads((root / "share/guest-selection.json").read_bytes())
    previous = {name: value for name, value in current.items() if name != "previous"}
    assets = Path(current["assets"])
    inputs = Path(current.get("installed_assets", root / "share"))
    asset_inode = assets.stat().st_ino
    input_inode = inputs.stat().st_ino
    rootfs_inode = (inputs / "rootfs-tree").stat().st_ino
    metadata_release = release(archive, version="guest-2026-10-12.3")
    contents.update(metadata_release)
    before = len(requests)
    result = command(native_cli, root, environment, "guest", "upgrade")
    assert result.returncode == 0, result.stderr
    selected = json.loads(result.stdout)
    assert selected["version"] == "guest-2026-10-12.3"
    assert selected["index"] != current["index"] and selected["manifest"] != current["manifest"]
    assert selected.get("previous") == previous
    assert selected["archive"] == current["archive"] and selected["assets"] == current["assets"]
    assert selected.get("installed_assets") == current.get("installed_assets")
    assert all("/blobs/" not in path for path in requests[before:])
    assert assets.stat().st_ino == asset_inode and inputs.stat().st_ino == input_inode
    assert (inputs / "rootfs-tree").stat().st_ino == rootfs_inode
    assert_preserved(root, original)

    contents["manifests/" + selected["index"]["digest"]] = metadata_release["manifests/compat-v1"]
    before = len(requests)
    repeat = command(native_cli, root, environment, "guest", "upgrade", "--index", selected["index"]["digest"])
    assert repeat.returncode == 0, repeat.stderr
    assert json.loads(repeat.stdout) == selected
    assert all("/blobs/" not in path and not path.endswith("compat-v1") for path in requests[before:])
    before = len(requests)
    for _ in range(2):
        result = command(native_cli, root, environment, "guest", "rollback")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == previous
        assert assets.stat().st_ino == asset_inode and inputs.stat().st_ino == input_inode
        assert (inputs / "rootfs-tree").stat().st_ino == rootfs_inode
        assert_preserved(root, original)
    assert len(requests) == before


@pytest.mark.parametrize("fault", ["partial", "hash", "size", "warm-size", "compatibility", "missing-platform", "ambiguous-platform", "registry", "index-hash", "manifest-hash", "manifest-size"])
def test_upgrade_refusals_preserve_active_and_previous_selection(
        native_cli, registry, package_info, tmp_path, guest_store, fault):
    contents, _requests, faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "h"
    installed(native_cli, root, guest_store, environment, package_info)
    original = preserved(root)
    contents.update(release(compressed_archive(content=b"G2 guest"), version="guest-2026-10-12.2"))
    result = command(native_cli, root, environment, "guest", "upgrade")
    assert result.returncode == 0, result.stderr
    active = (root / "share/guest-selection.json").read_bytes()
    assert json.loads(active)["previous"]["version"] == "guest-2026-10-12.1"
    archive = compressed_archive(content=b"G2 guest" if fault == "warm-size" else b"G3 guest")
    edit = (lambda child: child["layers"][0].update(size=len(archive) + 1)) if fault in ("size", "warm-size") else None
    newer = release(archive, version="guest-2026-10-12.3", compatibility="v2" if fault == "compatibility" else "v1", edit_child=edit)
    if fault in ("missing-platform", "ambiguous-platform"):
        index = json.loads(newer["manifests/compat-v1"])
        if fault == "missing-platform":
            index["manifests"] = index["manifests"][:1]
        else:
            index["manifests"].append(copy.deepcopy(index["manifests"][1]))
        newer["manifests/compat-v1"] = json.dumps(index).encode()
    blob = "blobs/" + digest(archive)
    if fault == "partial":
        faults["partial"] = blob
    if fault == "hash":
        newer[blob] = b"!" + archive[1:]
    contents.update(newer)
    arguments = ["guest", "upgrade"]
    if fault == "index-hash":
        target = "sha256:" + "a" * 64
        contents["manifests/" + target] = newer["manifests/compat-v1"]
        arguments.extend(["--index", target])
    if fault == "manifest-hash":
        for key, data in newer.items():
            if key.startswith("manifests/sha256:"):
                contents[key] = b"!" + data[1:]
    if fault == "manifest-size":
        index = json.loads(newer["manifests/compat-v1"])
        for child in index["manifests"]:
            child["size"] += 1
        contents["manifests/compat-v1"] = json.dumps(index).encode()
    if fault == "registry":
        del contents["manifests/compat-v1"]
    result = command(native_cli, root, environment, *arguments)
    assert result.returncode != 0 and "panic" not in result.stderr.lower()
    assert (root / "share/guest-selection.json").read_bytes() == active
    assert_preserved(root, original)


def test_failed_activation_is_retryable_and_bad_selected_inputs_can_be_rolled_back(
        native_cli, registry, package_info, tmp_path, guest_store):
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "h"
    original_selection = installed(native_cli, root, guest_store, environment, package_info)
    original = preserved(root)
    versions = root / "share/guest-versions/sha256"
    versions.mkdir(parents=True)
    contents.update(release(compressed_archive(content=b"G2 guest"), version="guest-2026-10-12.2"))
    share = root / "share"
    try:
        share.chmod(0o500)
        result = command(native_cli, root, environment, "guest", "upgrade")
        assert result.returncode != 0, result.stdout
        assert (share / "guest-selection.json").read_bytes() == original_selection
        ready = list(versions.iterdir())
        assert len(ready) == 1 and ready[0].is_dir()
        identity = ready[0].stat().st_ino
    finally:
        share.chmod(0o755)
    before = len(requests)
    result = command(native_cli, root, environment, "guest", "upgrade")
    assert result.returncode == 0, result.stderr
    current = json.loads(result.stdout)
    assert Path(current["installed_assets"]).stat().st_ino == identity
    assert all("/blobs/" not in path for path in requests[before:])
    # Missing new inputs cannot prevent recovery to the previous runnable inputs.
    (Path(current["installed_assets"]) / "rootfs-tree").unlink()
    before = len(requests)
    result = command(native_cli, root, environment, "guest", "rollback")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == json.loads(original_selection)
    assert len(requests) == before
    assert_preserved(root, original)


def test_killed_archive_pull_preserves_selection_and_next_upgrade_recovers(
        native_cli, registry, package_info, tmp_path, guest_store):
    contents, requests, faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "h"
    active = installed(native_cli, root, guest_store, environment, package_info)
    original = preserved(root)
    archive = compressed_archive(content=b"G2 guest")
    contents.update(release(archive, version="guest-2026-10-12.2"))
    faults["pause"] = "blobs/" + digest(archive)
    process = subprocess.Popen([str(native_cli), "--root", str(root), "guest", "upgrade"],
                               env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert faults["entered"].wait(timeout=15)
        process.kill()
        process.communicate(timeout=10)
        assert (root / "share/guest-selection.json").read_bytes() == active
        assert_preserved(root, original)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        faults["pause"] = None
        faults["resume"].set()
    before = len(requests)
    result = command(native_cli, root, environment, "guest", "upgrade")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["archive"]["digest"] == digest(archive)
    assert requests[before:].count(PREFIX + "manifests/compat-v1") == 1
    assert_preserved(root, original)


@settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(invalid=st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=30),
                       st.lists(st.integers(), max_size=3), st.dictionaries(st.text(max_size=10), st.integers(), max_size=3)))
def test_generated_invalid_index_shapes_cannot_replace_the_active_guest(
        native_cli, registry, package_info, tmp_path, guest_store, invalid):
    contents, _requests, _faults, environment = registry
    root = tmp_path / "h"
    if not (root / "share/guest-selection.json").exists():
        contents.update(release(compressed_archive()))
        installed(native_cli, root, guest_store, environment, package_info)
    active = (root / "share/guest-selection.json").read_bytes()
    original = preserved(root)
    contents["manifests/compat-v1"] = json.dumps(invalid).encode()
    result = command(native_cli, root, environment, "guest", "upgrade")
    assert result.returncode != 0 and "panic" not in result.stderr.lower()
    assert (root / "share/guest-selection.json").read_bytes() == active
    assert_preserved(root, original)


@pytest.mark.parametrize("arguments", [("upgrade", "--index", "compat-v1"),
                                      ("upgrade", "--index"), ("upgrade", "--package-info", "untrusted"),
                                      ("rollback", "--index", "sha256:" + "a" * 64)])
def test_invalid_guest_command_options_do_not_change_the_instance(native_cli, registry, package_info, tmp_path, guest_store, arguments):
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    root = tmp_path / "h"
    active = installed(native_cli, root, guest_store, environment, package_info)
    original = preserved(root)
    before = len(requests)
    result = command(native_cli, root, environment, "guest", *arguments)
    assert result.returncode != 0
    assert len(requests) == before
    assert (root / "share/guest-selection.json").read_bytes() == active
    assert_preserved(root, original)


def test_verified_bundle_guest_updates_preserve_running_proxy_host_and_restart_state(
        registry, tmp_path, guest_store):
    bundle = os.environ.get("SAFEYOLO_NATIVE_BUNDLE")
    nats = os.environ.get("SAFEYOLO_COORD_NATS_BINARY")
    if not bundle or not nats:
        pytest.skip("set SAFEYOLO_NATIVE_BUNDLE and SAFEYOLO_COORD_NATS_BINARY for the installed caller")
    contents, requests, _faults, environment = registry
    contents.update(release(compressed_archive()))
    # Keep real Unix listener paths short; no guest or model is booted here.
    root = tmp_path.parent / "h"
    environment = {**environment, "HOME": str(guest_store.parents[3]),
                   "SAFEYOLO_NATS_TEST_INSTANCE": "guest-upgrade-installed", "TERM": "xterm-256color"}
    result = subprocess.run([str(Path(bundle) / "install.sh"), "--root", str(root),
                             "--command-dir", str(root / "commands")], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    cli = root / "bin/safeyolo"
    config = root / "config.toml"
    config.write_text(config.read_text().replace("admin_port = 9090", "admin_port = 0"))
    result = command(cli, root, {**environment, "GUEST_UPGRADE_TEST_CREDENTIAL": "synthetic-kept-credential"},
                     "credentials", "add", "kept", "--value-env", "GUEST_UPGRADE_TEST_CREDENTIAL")
    assert result.returncode == 0, result.stderr
    (root / "agents/retained/home").mkdir(parents=True)
    (root / "agents/retained/home/keep").write_bytes(b"persistent agent home")
    (root / "logs/audit-canary").write_bytes(b"persistent audit data")
    original = preserved(root)
    # Ordinary startup rewrites reload_id and omits an empty listener table.
    # Guest commands preserve bytes; restarts preserve all operator values.
    configured = tomllib.loads(original.pop("config.toml").decode())
    g1 = json.loads((root / "share/guest-selection.json").read_bytes())

    def host_digests():
        paths = [root / "bin" / name for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord")]
        paths.extend(root / "assets/guest" / name for name in ("safeyolo-guest", "safeyolo-coord"))
        values = []
        for path in paths:
            with path.open("rb") as file:
                values.append(hashlib.file_digest(file, "sha256").hexdigest())
        return values

    host = host_digests()
    try:
        result = command(cli, root, environment, "coord", "start", "--binary", nats)
        assert result.returncode == 0, result.stderr
        contents.update(release(compressed_archive(content=b"G2 guest"), version="guest-2026-10-12.2"))
        before = len(requests)
        for _ in range(2):
            result = command(cli, root, environment, "start")
            assert result.returncode == 0, result.stderr
            assert json.loads((root / "share/guest-selection.json").read_bytes()) == g1
            assert command(cli, root, environment, "stop").returncode == 0
        assert len(requests) == before
        result = command(cli, root, environment, "start")
        assert result.returncode == 0, result.stderr
        proxy_record = (root / "data/proxy-process.json").read_bytes()
        before_upgrade = preserved(root)
        result = command(cli, root, environment, "guest", "upgrade")
        assert result.returncode == 0, result.stderr
        g2 = json.loads(result.stdout)
        assert g2["version"] == "guest-2026-10-12.2" and g2["previous"] == g1
        assert (root / "data/proxy-process.json").read_bytes() == proxy_record
        assert json.loads(command(cli, root, environment, "status").stdout)["proxy_state"] == "running"
        assert host_digests() == host
        assert_preserved(root, before_upgrade)
        assert_preserved(root, original)
        before = len(requests)
        again = command(cli, root, environment, "guest", "upgrade")
        assert again.returncode == 0, again.stderr
        assert json.loads(again.stdout) == g2
        assert all("/blobs/" not in path for path in requests[before:])
        assert command(cli, root, environment, "stop").returncode == 0
        before = len(requests)
        assert command(cli, root, environment, "start").returncode == 0
        assert json.loads((root / "share/guest-selection.json").read_bytes()) == g2
        before_rollback = preserved(root)
        result = command(cli, root, environment, "guest", "rollback")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == g1
        assert_preserved(root, before_rollback)
        assert command(cli, root, environment, "stop").returncode == 0
        assert command(cli, root, environment, "start").returncode == 0
        assert json.loads((root / "share/guest-selection.json").read_bytes()) == g1
        assert len(requests) == before
        assert_preserved(root, original)
        restarted = tomllib.loads(config.read_text())
        restarted.pop("reload_id", None)
        restarted.setdefault("listeners", [])
        assert restarted == configured
        assert host_digests() == host
    finally:
        assert command(cli, root, environment, "stop").returncode == 0
        assert command(cli, root, environment, "coord", "stop").returncode == 0
        assert json.loads(command(cli, root, environment, "status").stdout)["proxy_state"] == "unavailable"
        assert json.loads(command(cli, root, environment, "coord", "status").stdout)["state"] == "stopped"
