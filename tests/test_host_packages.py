"""Native producer and installer checks with controlled executable identities.

These fixtures test packaging failures. The installed journey runs real product
binaries through tests/proxy_contracts/native-package-journey.sh.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts import build_host_packages as builder

REPO = Path(__file__).resolve().parents[1]
REVISION = "a" * 40


def run(*arguments, **kwargs):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=30, **kwargs)


def executable(path, identity):
    # Real ELF header/architecture, controlled identity; never a runtime witness.
    source = path.with_suffix(".c")
    source.write_text(f'#include <stdio.h>\nint main(void){{puts("{identity}");return 0;}}\n')
    subprocess.run(["cc", str(source), "-o", str(path)], check=True, timeout=15)
    source.unlink()



@pytest.fixture
def package_inputs(tmp_path, request):
    if os.uname().sysname != "Linux":
        pytest.skip("controlled ELF producer fixture runs on Linux; macOS uses actual Tart artifacts")
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    for name in ("build_host_packages.sh", "native_package.sh", "install_native.sh", "install_host_package.sh", "tmux_runtime.sh", "watch_backlog_factory.sh"):
        shutil.copy2(REPO / "scripts" / name, scripts / name)
    shutil.copytree(REPO / "proxy/licenses", source / "proxy/licenses")
    assets = source / "cli/src/safeyolo"
    assets.mkdir(parents=True)
    for name in ("guest-init", "guest-init-static", "guest-init-per-run", "guest-proxy-forwarder", "guest-shell-bridge", "guest-desktop"):
        (assets / f"{name}.sh").write_text("#!/bin/sh\nexit 0\n")
    for name in ("launchers", "agent_context/skills/safeyolo", "services"):
        (assets / name).mkdir(parents=True)
    for name in ("safeyolo-lab-controller", "safeyolo-factory"):
        shutil.copytree(
            REPO / "cli/src/safeyolo/agent_context/skills" / name,
            assets / "agent_context/skills" / name,
        )
    for name in ("tmux-common", "tmux-window", "tmux-pane"):
        (assets / "launchers" / f"{name}.sh").write_text("#!/bin/sh\nexit 0\n")
    skill = assets / "agent_context/skills/safeyolo"
    if getattr(request, "param", None) == "shipped-skill":
        shutil.copytree(REPO / "cli/src/safeyolo/agent_context/skills/safeyolo", skill, dirs_exist_ok=True)
    else:
        (skill / "scripts/__pycache__").mkdir(parents=True)
        (skill / "references").mkdir()
        (skill / "SKILL.md").write_text(
            "fixture skill\n- Read [GitHub composite checks](references/github-checks.md)\n"
            "  Optional repository tooling.\n- Keep the next instruction.\n",
        )
        (skill / "scripts/github_checks.py").write_text("# optional checker\n")
        (skill / "scripts/__pycache__/old.pyc").write_bytes(b"old cache")
        (skill / "references/github-checks.md").write_text("optional checker instructions\n")
    (source / "repo-map.toml").write_text("# fixture\n")
    (source / "LICENSE").write_text("fixture project notice\n")
    (source / "docs").mkdir()
    (source / "docs/AGENTS.md").write_text("fixture baseline\n")
    (source / "guest/rootfs").mkdir(parents=True)
    (source / "guest/rootfs/safeyolo-sudo").write_text("#!/bin/sh\nexit 0\n")
    shutil.copytree(REPO / "contrib", source / "contrib")
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


@pytest.mark.parametrize("platform,lane", [("Linux", "systrap"), ("Darwin", "vz")])
@pytest.mark.parametrize("separate_checkout", [False, True])
def test_blackbox_preparation_binds_available_native_inputs(tmp_path, monkeypatch, platform, lane, separate_checkout):
    """The maintained caller delegates prepared inputs to the normal installer."""
    checkout = tmp_path / "source"
    scripts = checkout / "tests/blackbox"
    scripts.mkdir(parents=True)
    shutil.copy2(REPO / "tests/blackbox/run-lane.sh", scripts / "run-lane.sh")
    tools, host, guest, runtime, vm, images, root = (tmp_path / name for name in
                                                ("tools", "host", "guest", "runtime", "vm", "images", "root"))
    for path in (tools, host, guest, runtime, vm, images):
        path.mkdir()
    for name in ("Image", "initramfs.cpio.gz", "rootfs-base.ext4"):
        (images / name).touch()
    (images / "rootfs-tree").mkdir()
    selected = tmp_path / "selected" if separate_checkout else checkout
    selected.mkdir(exist_ok=True)
    installer = selected / "install.sh"
    fixture_cli = '#!/bin/sh\nprintf "native %s\\n" "$*"\n'
    installer.write_text(f"#!{os.sys.executable}\nimport json,pathlib,sys\n"
        "options = dict(zip(sys.argv[1::2], sys.argv[2::2]))\n"
        "root = pathlib.Path(options['--root']); (root / 'bin').mkdir(parents=True)\n"
        "(root / 'native-inputs.json').write_text(json.dumps(options))\n"
        "cli = root / 'bin/safeyolo'\n"
        f"cli.write_text({fixture_cli!r})\ncli.chmod(0o755)\n")
    installer.chmod(0o755)
    for name in ('uv', 'runsc', 'newuidmap', 'newgidmap', 'setfacl', 'unshare'):
        path = tools / name
        path.write_text('#!/bin/sh\nexit 0\n')
        path.chmod(0o755)
    (tools / 'uname').write_text(f'#!/bin/sh\nprintf "{platform}\\n"\n')
    (tools / 'uname').chmod(0o755)
    activation = tmp_path / 'activation.sh'
    activation.write_text('export PATH="$PREPARE_TOOLS:$PATH"\n')
    monkeypatch.setenv('BASH_ENV', str(activation))
    monkeypatch.setenv('PREPARE_TOOLS', str(tools))
    monkeypatch.setenv('PATH', f'{tools}:{os.environ["PATH"]}')
    for name in ('SAFEYOLO_NATIVE_BUNDLE', 'SAFEYOLO_NATIVE_VM_ARTIFACTS'):
        monkeypatch.delenv(name, raising=False)
    for name, path in {'SAFEYOLO_CONFIG_DIR': root, 'SAFEYOLO_NATIVE_ARTIFACTS': host,
                       'SAFEYOLO_NATIVE_GUEST_ARTIFACTS': guest, 'SAFEYOLO_NATIVE_RUNTIME_ARTIFACTS': runtime,
                       'SAFEYOLO_PLATFORM_ASSETS': images}.items():
        monkeypatch.setenv(name, str(path))
    if platform == 'Darwin':
        monkeypatch.setenv('SAFEYOLO_NATIVE_VM_ARTIFACTS', str(vm))
    selection = ['--install-checkout', str(selected)] if separate_checkout else []
    result = run(str(scripts / 'run-lane.sh'), lane, *selection, '--prepare-only', cwd=checkout)
    assert result.returncode == 0, result.stderr
    options = json.loads((root / 'native-inputs.json').read_text())
    assert Path(options['--artifacts']) == host
    assert Path(options['--guest-artifacts']) == guest
    assert Path(options['--runtime-artifacts']) == runtime
    if platform == 'Darwin':
        assert Path(options['--vm-artifacts']) == vm
    assert Path(options['--platform-assets']) == images
    assert 'native --root' in result.stdout and 'coord stop' in result.stdout
    if separate_checkout:
        failed = run(str(scripts / 'run-lane.sh'), lane, '--install-checkout', str(tmp_path / 'missing'), cwd=checkout)
        assert failed.returncode == 2 and 'requires a source checkout' in failed.stderr
        assert (root / 'native-inputs.json').read_text() == json.dumps(options)


def test_native_bundle_archives_checked_bytes_and_private_runtime(package_inputs, tmp_path):
    output = tmp_path / "output"
    result = run(*package_inputs[4], "--output", str(output))
    assert result.returncode == 0, result.stderr
    archive, = output.glob("*.tar.gz")
    with tarfile.open(archive) as stream:
        names = stream.getnames()
        assert any(name.endswith("/assets/skills/safeyolo/SKILL.md") for name in names)
        assert not any(name.endswith(("/github_checks.py", "/github-checks.md", ".pyc")) for name in names)
        skill_path, = [name for name in names if name.endswith("/assets/skills/safeyolo/SKILL.md")]
        assert stream.extractfile(skill_path).read() == b"fixture skill\n- Keep the next instruction.\n"
        assert not any(name.endswith("/repo_map.py") for name in names)
        for relative in ("repo-map.toml", "docs/AGENTS.md", "contrib/codex-command.sh",
                         "contrib/coord-mcp-bootstrap.sh", "contrib/safeyolo-coord-mcp-launcher.sh",
                         "contrib/codex-coord-host-setup.sh", "contrib/pi-host-setup.sh",
                         "contrib/pi-coord-host-setup.sh", "contrib/pi-coord-extension.ts"):
            path, = [name for name in names if name.endswith(f"/assets/{relative}")]
            assert stream.extractfile(path).read() == (package_inputs[0] / relative).read_bytes()
        assert any(name.endswith("/libexec/tmux") for name in names)
        assert any(name.endswith("/assets/licenses/tmux.txt") for name in names)
        assert any(name.endswith("/LICENSE") for name in names)
        assert any("/lib/" in name for name in names)
        assert not any(name.endswith((".whl", "/dependencies.txt", "/verify.py")) for name in names)
        path, = [name for name in names if name.endswith("/bin/safeyolo-proxy")]
        assert stream.extractfile(path).read() == (package_inputs[1] / "safeyolo-proxy").read_bytes()
        watcher, = [name for name in names if name.endswith("/bin/watch-backlog-factory")]
        assert stream.extractfile(watcher).read() == (package_inputs[0] / "scripts/watch_backlog_factory.sh").read_bytes()
        assert stream.getmember(watcher).mode & 0o111
        for notice in (package_inputs[0] / "proxy/licenses").iterdir():
            path, = [name for name in names if name.endswith(f"/assets/licenses/{notice.name}")]
            assert stream.extractfile(path).read() == notice.read_bytes()


def packaged_flow_token_recipe(package_inputs, tmp_path):
    skill = build_bundle(package_inputs, tmp_path) / "assets/skills/safeyolo"
    source = REPO / "cli/src/safeyolo/agent_context/skills/safeyolo"
    for relative in ("references/agent-api.md", "references/graph/triage-credential-guard.yaml",
                     "references/graph/triage-request-failing.yaml"):
        assert (skill / relative).read_bytes() == (source / relative).read_bytes()
    assert not list(skill.rglob("*.py"))
    assert not (skill / "scripts/render_skill_graph.py").exists()
    reference = (skill / "references/agent-api.md").read_text()
    provision = reference.split("### Provision a read-all flow token\n", 1)[1]
    return provision.split("```sh\n", 1)[1].split("```", 1)[0]


def flow_token_environment(tmp_path):
    """Only host primitives are available; wrappers record real child argv."""
    tools = tmp_path / "product-tools"
    tools.mkdir()
    for name in ("mktemp", "od", "tr", "mv", "rm"):
        executable_path = shutil.which(name)
        assert executable_path is not None
        wrapper = tools / name
        wrapper.write_text('#!/bin/sh\nprintf "%s\\n" "$0" "$@" >> "$FLOW_RECIPE_ARGV"\n'
                           f'exec "{executable_path}" "$@"\n')
        wrapper.chmod(0o755)
    return dict(os.environ, PATH=str(tools), FLOW_RECIPE_ARGV=str(tmp_path / "argv"))


@pytest.mark.parametrize("package_inputs", ["shipped-skill"], indirect=True)
@pytest.mark.parametrize("custom_data", [False, True], ids=["default", "custom"])
def test_packaged_flow_token_creation_rotation_and_revocation_without_python(package_inputs, tmp_path, custom_data):
    recipe = packaged_flow_token_recipe(package_inputs, tmp_path)
    environment = flow_token_environment(tmp_path)
    environment.pop("flow_data_dir", None)
    environment["HOME"] = str(tmp_path / "operator")
    data = tmp_path / "custom data" if custom_data else Path(environment["HOME"]) / ".safeyolo/data"
    data.mkdir(parents=True, mode=0o700)
    if custom_data:
        environment["flow_data_dir"] = str(data)
    token = data / "flow_read_token"
    previous = None
    previous_inode = None
    for _ in range(2):
        result = run("/bin/sh", "-c", "umask 000\n" + recipe, env=environment)
        assert result.returncode == 0, result.stderr
        assert not result.stdout and not result.stderr
        metadata = token.lstat()
        assert stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
        contents = token.read_bytes()
        assert len(contents) == 65 and contents[-1:] == b"\n"
        assert all(byte in b"0123456789abcdef" for byte in contents[:-1])
        assert contents != previous and metadata.st_ino != previous_inode
        assert contents[:-1] not in (tmp_path / "argv").read_bytes()
        assert not list(data.glob(".flow_read_token.*"))
        previous, previous_inode = contents, metadata.st_ino
    reference = REPO / "cli/src/safeyolo/agent_context/skills/safeyolo/references/agent-api.md"
    revoke = reference.read_text().split("remove the file to revoke the credential:", 1)[1]
    revoke = revoke.split("```sh\n", 1)[1].split("```", 1)[0]
    result = run("/bin/sh", "-c", revoke, env=environment)
    assert result.returncode == 0 and not result.stdout and not token.exists()


@pytest.mark.parametrize("package_inputs", ["shipped-skill"], indirect=True)
@pytest.mark.parametrize("fault", ["random-error", "random-short", "rename-error", "directory"])
def test_packaged_flow_token_failure_preserves_original(package_inputs, tmp_path, fault):
    recipe = packaged_flow_token_recipe(package_inputs, tmp_path)
    environment = flow_token_environment(tmp_path)
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    environment["flow_data_dir"] = str(data)
    token = data / "flow_read_token"
    if fault == "directory":
        token.mkdir()
        original = token / "keep"
    else:
        original = token
    original.write_bytes(b"a" * 64 + b"\n")
    original.chmod(0o600)
    inode = original.stat().st_ino
    if fault != "directory":
        primitive = "mv" if fault == "rename-error" else "od"
        (Path(environment["PATH"]) / primitive).write_text(
            '#!/bin/sh\nprintf "%s\\n" "$0" >> "$FLOW_RECIPE_ARGV"\n'
            + ('printf "01\\n"\n' if primitive == "od" else "")
            + ("exit 0\n" if fault == "random-short" else "exit 73\n"),
        )
    result = run("/bin/sh", "-c", recipe, env=environment)
    assert result.returncode != 0
    assert not result.stdout
    assert original.read_bytes() == b"a" * 64 + b"\n" and original.stat().st_ino == inode
    assert stat.S_IMODE(original.stat().st_mode) == 0o600
    assert not list(data.glob(".flow_read_token.*"))
    if fault != "directory":
        assert primitive in (tmp_path / "argv").read_text()


@pytest.mark.parametrize("damage", ["missing", "checksum", "profile", "source", "mode"])
def test_producer_rejects_incomplete_or_different_guest_inputs(package_inputs, tmp_path, damage):
    guest = package_inputs[2]
    if damage == "missing":
        (guest / "safeyolo-guest.sha256").unlink()
    elif damage == "checksum":
        (guest / "safeyolo-guest").write_bytes((guest / "safeyolo-guest").read_bytes() + b"damaged")
    elif damage == "mode":
        (guest / "safeyolo-guest").chmod(0o644)
    else:
        receipt = guest / "safeyolo-guest.version"
        receipt.write_text(receipt.read_text().replace("debug", "production") if damage == "profile"
                           else receipt.read_text().replace(package_inputs[5], "b" * 40))
    result = run(*package_inputs[4], "--directory", str(tmp_path / "bundle"))
    assert result.returncode != 0
    assert "guest" in result.stderr.lower()
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("damage", ["source", "profile"])
def test_producer_rejects_a_different_host_coord_identity(package_inputs, tmp_path, damage):
    coord = package_inputs[1] / "safeyolo-coord"
    revision = "b" * 40 if damage == "source" else package_inputs[5]
    profile = "production" if damage == "profile" else "debug"
    executable(coord, f"safeyolo-coord 0.1.0 commit={revision} profile={profile}")
    result = run(*package_inputs[4], "--directory", str(tmp_path / "bundle"))
    assert result.returncode != 0
    assert "host source/profile identities differ: safeyolo-coord" in result.stderr
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
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"), cwd=tmp_path)
    assert result.returncode != 0
    assert "required artifact is missing" in result.stderr and "safeyolo-proxy" in result.stderr
    assert not root.exists()


def test_installer_preserves_existing_instance(package_inputs, tmp_path):
    bundle = build_bundle(package_inputs, tmp_path)
    root = tmp_path / "existing"
    root.mkdir()
    (root / "config.toml").write_text("operator configuration\n")
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"))
    assert result.returncode != 0 and "fresh root" in result.stderr
    assert (root / "config.toml").read_text() == "operator configuration\n"
    assert not (root / "bin").exists()


def test_fresh_install_preserves_prepared_platform_inputs(package_inputs, tmp_path):
    bundle = build_bundle(package_inputs, tmp_path)
    root = tmp_path / "prepared"
    (root / "share").mkdir(parents=True)
    image = root / "share/Image"
    image.write_bytes(b"prepared boot input")
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert image.read_bytes() == b"prepared boot input"
    assert (root / "LICENSE").read_bytes() == (bundle / "LICENSE").read_bytes()
    # Preserve the retired wheel fixture's sudo/helper byte and mode checks
    # through the native package consumed outside the source checkout.
    sudo = root / "assets/guest/guest-sudo"
    assert sudo.read_bytes() == (package_inputs[0] / "guest/rootfs/safeyolo-sudo").read_bytes()
    assert sudo.stat().st_mode & 0o777 == 0o755
    helper = root / "assets/guest/safeyolo-guest"
    assert helper.read_bytes() == (package_inputs[2] / "safeyolo-guest").read_bytes()
    assert helper.stat().st_mode & 0o777 == 0o755
    # The Codex setup script loads this adjacent command at agent preparation.
    assert (root / "assets/contrib/codex-command.sh").read_bytes() == (
        REPO / "contrib/codex-command.sh"
    ).read_bytes()
    skill_source = REPO / "cli/src/safeyolo/agent_context/skills"
    for name, relative in (
        ("safeyolo-lab-controller", "scripts/prepare-nested.sh"),
        ("safeyolo-factory", "SKILL.md"),
    ):
        assert (root / "assets/skills" / name / relative).read_bytes() == (
            skill_source / name / relative
        ).read_bytes()


@pytest.mark.parametrize("from_source", [False, True], ids=["bundle", "source"])
def test_install_discovers_command_in_fresh_shell_without_selection_overrides(package_inputs, tmp_path, from_source):
    bundle = build_bundle(package_inputs, tmp_path)
    home = tmp_path / "operator"
    commands = home / ".local/bin"
    if from_source:
        # A conventional PATH directory may itself be an operator symlink.
        actual_commands = tmp_path / "command-files"
        actual_commands.mkdir()
        commands.parent.mkdir(parents=True)
        commands.symlink_to(actual_commands, target_is_directory=True)
    else:
        commands.mkdir(parents=True)
    root = home / ".safeyolo"
    environment = dict(os.environ, HOME=str(home), PATH=f"{commands}:/usr/local/bin:/usr/bin:/bin")
    for key in ("SAFEYOLO_CONFIG_DIR", "SAFEYOLO_HOME", "SAFEYOLO_NATIVE_CONFIG_PATH", "BASH_ENV"):
        environment.pop(key, None)
    entry = bundle / "install.sh"
    arguments = []
    if from_source:
        entry = package_inputs[0] / "install.sh"
        shutil.copy2(REPO / "install.sh", entry)
        arguments = ["--bundle", str(bundle)]
    result = run(str(entry), "--root", str(root), *arguments, env=environment)
    assert result.returncode == 0, result.stderr
    assert (commands / "safeyolo").is_symlink()
    assert (commands / "safeyolo").resolve() == root / "bin/safeyolo"
    shell = run("/bin/bash", "--noprofile", "--norc", "-c",
                "command -v safeyolo; safeyolo --version", env=environment)
    assert shell.returncode == 0, shell.stderr
    assert shell.stdout.splitlines() == [
        str(commands / "safeyolo"),
        f"safeyolo 0.1.0 commit={package_inputs[5]} profile=debug",
    ]


@pytest.mark.parametrize("kind", ["file", "symlink", "directory"])
def test_install_preserves_unrelated_command_and_instance_state(package_inputs, tmp_path, kind):
    bundle = build_bundle(package_inputs, tmp_path)
    home = tmp_path / "operator"
    commands = home / ".local/bin"
    commands.mkdir(parents=True)
    unrelated = commands / "safeyolo"
    target = tmp_path / "unrelated-command"
    target.write_text("operator-owned command")
    if kind == "symlink":
        unrelated.symlink_to(target)
    elif kind == "directory":
        unrelated.mkdir()
        (unrelated / "marker").write_text("operator-owned directory")
    else:
        unrelated.write_text("operator-owned command")
        unrelated.chmod(0o755)
    root = home / ".safeyolo"
    (root / "share").mkdir(parents=True)
    boot = root / "share/prepared-image"
    boot.write_bytes(b"retained prepared boot input")
    environment = dict(os.environ, HOME=str(home), PATH=f"{commands}:/usr/local/bin:/usr/bin:/bin")
    environment.pop("BASH_ENV", None)
    result = run(str(bundle / "install.sh"), "--root", str(root), env=environment)
    assert result.returncode != 0
    assert f"Existing command {unrelated} was preserved" in result.stderr
    assert not (root / "config.toml").exists() and not (root / "bin").exists()
    assert boot.read_bytes() == b"retained prepared boot input"
    assert target.read_text() == "operator-owned command"
    if kind == "directory":
        assert (unrelated / "marker").read_text() == "operator-owned directory"
    else:
        assert unrelated.read_text() == "operator-owned command"


@pytest.mark.parametrize("with_cache_paths", [False, True])
def test_platform_install_stages_cache_paths_without_changing_prepared_tree(package_inputs, tmp_path, with_cache_paths):
    bundle = build_bundle(package_inputs, tmp_path)
    platform = tmp_path / "platform"
    tree = platform / "rootfs-tree"
    tree.mkdir(parents=True)
    (tree / "prepared-input").write_bytes(b"unchanged rootfs input")
    cache_paths = "/var/cache/apt\n/var/cache/apk\n"
    if with_cache_paths:
        (platform / "cache-paths.txt").write_text(cache_paths)
    root = tmp_path / "installed"
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"), "--platform-assets", str(platform))
    assert result.returncode == 0, result.stderr
    assert (root / "share/rootfs-tree").is_symlink()
    assert (root / "share/rootfs-tree").resolve() == tree.resolve()
    assert (tree / "prepared-input").read_bytes() == b"unchanged rootfs input"
    installed_caches = root / "share/cache-paths.txt"
    if with_cache_paths:
        assert installed_caches.read_text() == cache_paths
    else:
        assert not installed_caches.exists()


# Python saves CI debug metadata only; production uses the shell producer.

def test_component_settings_survive_artifact_json_roundtrip(monkeypatch):
    monkeypatch.setattr(builder, "output", lambda *args, **kwargs: "rustc pinned")
    monkeypatch.setenv("CARGO_TARGET_DIR", "/different/target/cache")
    settings = builder.proxy_settings("debug")
    assert settings == json.loads(json.dumps(settings))
    assert "CARGO_TARGET_DIR" not in settings["environment"]


def test_runtime_verification_rejects_test_and_script_outputs(tmp_path):
    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("#!/bin/sh\nprintf 'safeyolo-proxy fake'\n")
    binary.chmod(0o755)
    with pytest.raises(ValueError, match="host runtime"):
        builder.verify_proxy(binary, "debug")




def test_source_installer_runs_native_bundle_without_python_or_uv(tmp_path, package_inputs, monkeypatch):
    bundle = build_bundle(package_inputs, tmp_path)
    entry = package_inputs[0] / 'install.sh'
    shutil.copy2(REPO / 'install.sh', entry)
    canaries = tmp_path / 'canaries'
    canaries.mkdir()
    marker = tmp_path / 'python-fallback'
    for name in ('python', 'python3', 'uv', 'pip'):
        path = canaries / name
        path.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 99\n')
        path.chmod(0o755)
    # BASH_ENV may add mise's global commands; put canaries first after it.
    activation = tmp_path / 'activation.sh'
    activation.write_text('export PATH="$INSTALL_CANARIES:$PATH"\n')
    monkeypatch.setenv('BASH_ENV', str(activation))
    monkeypatch.setenv('INSTALL_CANARIES', str(canaries))
    monkeypatch.setenv('PATH', f'{canaries}:{os.environ["PATH"]}')
    root = tmp_path / 'selected root'
    result = run(str(entry), '--root', str(root), '--command-dir', str(root / 'commands'), '--bundle', str(bundle), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert (root / 'bin/safeyolo').read_bytes().startswith(b'\x7fELF')
    assert (root / 'package-info').read_bytes() == (bundle / 'package-info').read_bytes()
    assert (root / 'config.toml').exists()
    assert not marker.exists()
    assert not list(root.rglob('*.whl'))
    # Challenge the same detector with a disposable hidden-fallback fixture.
    fallback = tmp_path / 'hidden-fallback.sh'
    fallback.write_text('#!/bin/bash\nexec python3 -c "print(123)"\n')
    fallback.chmod(0o755)
    control = run(str(fallback), cwd=tmp_path)
    assert control.returncode == 99
    assert marker.exists()


def test_source_installer_preserves_missing_artifact_error_and_fresh_root(tmp_path, package_inputs):
    bundle = build_bundle(package_inputs, tmp_path)
    entry = package_inputs[0] / 'install.sh'
    shutil.copy2(REPO / 'install.sh', entry)
    (bundle / 'bin/safeyolo-proxy').unlink()
    root = tmp_path / 'fresh'
    result = run(str(entry), '--root', str(root), '--command-dir', str(root / 'commands'), '--bundle', str(bundle))
    assert result.returncode != 0
    assert 'required artifact is missing' in result.stderr and 'safeyolo-proxy' in result.stderr
    assert not root.exists()
