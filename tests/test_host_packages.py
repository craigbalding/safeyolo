"""Native producer and installer checks with controlled executable identities.

These fixtures test packaging failures. The installed journey runs real product
binaries through tests/proxy_contracts/native-package-journey.sh.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def run(*arguments, **kwargs):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=30, **kwargs)


def executable(path, identity):
    # Real ELF header/architecture, controlled identity; never a runtime witness.
    source = path.with_suffix(".c")
    source.write_text(f'#include <stdio.h>\nint main(void){{puts("{identity}");return 0;}}\n')
    subprocess.run(["cc", str(source), "-o", str(path)], check=True, timeout=15)
    source.unlink()


@pytest.fixture
def package_inputs(tmp_path):
    if os.uname().sysname != "Linux":
        pytest.skip("controlled ELF producer fixture runs on Linux; macOS uses actual Tart artifacts")
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    for name in ("build_host_packages.sh", "native_package.sh", "install_native.sh", "install_host_package.sh", "tmux_runtime.sh"):
        shutil.copy2(REPO / "scripts" / name, scripts / name)
    assets = source / "cli/src/safeyolo"
    assets.mkdir(parents=True)
    for name in ("guest-init", "guest-init-static", "guest-init-per-run", "guest-proxy-forwarder", "guest-shell-bridge", "guest-desktop"):
        (assets / f"{name}.sh").write_text("#!/bin/sh\nexit 0\n")
    for name in ("launchers", "agent_context/skills/safeyolo", "services"):
        (assets / name).mkdir(parents=True)
    for name in ("tmux-common", "tmux-window", "tmux-pane"):
        (assets / "launchers" / f"{name}.sh").write_text("#!/bin/sh\nexit 0\n")
    (assets / "agent_context/skills/safeyolo/SKILL.md").write_text("fixture skill\n")
    (assets / "repo_map.py").write_text("# Remaining production helper fixture\n")
    (source / "repo-map.toml").write_text("# fixture\n")
    (source / "LICENSE").write_text("fixture project notice\n")
    (source / "docs").mkdir()
    (source / "docs/AGENTS.md").write_text("fixture baseline\n")
    (source / "guest/rootfs").mkdir(parents=True)
    (source / "guest/rootfs/safeyolo-sudo").write_text("#!/bin/sh\nexit 0\n")
    (source / "contrib/lib").mkdir(parents=True)
    for name in ("claude-host-setup", "codex-host-setup", "codex-coord-host-setup", "pi-host-setup", "pi-coord-host-setup", "mise-shell-host-setup", "coord-mcp-bootstrap", "safeyolo-coord-mcp-launcher"):
        (source / "contrib" / f"{name}.sh").write_text("#!/bin/sh\nexit 0\n")
    (source / "contrib/lib/stage-coord-native.sh").write_text("# fixture\n")
    (source / "contrib/pi-coord-extension.ts").write_text("// fixture\n")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "package fixture"], check=True)
    revision = run("git", "-C", str(source), "rev-parse", "HEAD").stdout.strip()
    host, guest, runtime = (tmp_path / name for name in ("host", "guest", "runtime"))
    for directory in (host, guest, runtime):
        directory.mkdir()
    for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        executable(host / name, f"{name} 0.1.0 commit={revision} profile=debug")
    for name in ("safeyolo-guest", "safeyolo-coord"):
        identity = f"{name} 0.1.0 commit={revision} profile=debug"
        executable(guest / name, identity)
        (guest / f"{name}.version").write_text(identity + "\n")
        (guest / f"{name}.sha256").write_text(hashlib.sha256((guest / name).read_bytes()).hexdigest() + "\n")
    shutil.copy2(shutil.which("tmux"), runtime / "tmux")
    (runtime / "licenses").mkdir()
    (runtime / "licenses/tmux.txt").write_text("fixture runtime notice\n")
    arguments = [str(scripts / "build_host_packages.sh"), "--profile", "debug", "--artifacts", str(host), "--guest-artifacts", str(guest), "--runtime-artifacts", str(runtime)]
    return source, host, guest, runtime, arguments, revision


def build_bundle(inputs, tmp_path):
    directory = tmp_path / "bundle"
    result = run(*inputs[4], "--directory", str(directory))
    assert result.returncode == 0, result.stderr
    return directory


def test_native_bundle_archives_checked_bytes_and_private_runtime(package_inputs, tmp_path):
    output = tmp_path / "output"
    result = run(*package_inputs[4], "--output", str(output))
    assert result.returncode == 0, result.stderr
    archive, = output.glob("*.tar.gz")
    with tarfile.open(archive) as stream:
        names = stream.getnames()
        assert any(name.endswith("/assets/skills/safeyolo/SKILL.md") for name in names)
        assert any(name.endswith("/libexec/tmux") for name in names)
        assert any(name.endswith("/assets/licenses/tmux.txt") for name in names)
        assert any(name.endswith("/LICENSE") for name in names)
        assert any("/lib/" in name for name in names)
        assert not any(name.endswith((".whl", "/dependencies.txt", "/verify.py")) for name in names)
        path, = [name for name in names if name.endswith("/bin/safeyolo-proxy")]
        assert stream.extractfile(path).read() == (package_inputs[1] / "safeyolo-proxy").read_bytes()


@pytest.mark.parametrize("damage", ["missing", "checksum", "profile", "source"])
def test_producer_rejects_incomplete_or_different_guest_inputs(package_inputs, tmp_path, damage):
    guest = package_inputs[2]
    if damage == "missing":
        (guest / "safeyolo-guest.sha256").unlink()
    elif damage == "checksum":
        (guest / "safeyolo-guest").write_bytes((guest / "safeyolo-guest").read_bytes() + b"damaged")
    else:
        receipt = guest / "safeyolo-guest.version"
        receipt.write_text(receipt.read_text().replace("debug", "production") if damage == "profile"
                           else receipt.read_text().replace(package_inputs[5], "b" * 40))
    result = run(*package_inputs[4], "--directory", str(tmp_path / "bundle"))
    assert result.returncode != 0
    assert "guest" in result.stderr.lower()
    assert not (tmp_path / "bundle").exists()


def test_producer_rejects_script_substitution(package_inputs, tmp_path):
    proxy = package_inputs[1] / "safeyolo-proxy"
    proxy.write_text(f'#!/bin/sh\necho "safeyolo-proxy 0.1.0 commit={package_inputs[5]} profile=debug"\n')
    result = run(*package_inputs[4], "--directory", str(tmp_path / "bundle"))
    assert result.returncode != 0
    assert "not a" in result.stderr and "executable" in result.stderr


def test_missing_bundle_input_is_reported_before_fresh_root_changes(package_inputs, tmp_path):
    bundle = build_bundle(package_inputs, tmp_path)
    (bundle / "bin/safeyolo-proxy").unlink()
    root = tmp_path / "fresh"
    result = run(str(bundle / "install.sh"), "--root", str(root), cwd=tmp_path)
    assert result.returncode != 0
    assert "required artifact is missing" in result.stderr and "safeyolo-proxy" in result.stderr
    assert not root.exists()


def test_installer_preserves_existing_instance(package_inputs, tmp_path):
    bundle = build_bundle(package_inputs, tmp_path)
    root = tmp_path / "existing"
    root.mkdir()
    (root / "config.toml").write_text("operator configuration\n")
    result = run(str(bundle / "install.sh"), "--root", str(root))
    assert result.returncode != 0 and "fresh root" in result.stderr
    assert (root / "config.toml").read_text() == "operator configuration\n"
    assert not (root / "bin").exists()
