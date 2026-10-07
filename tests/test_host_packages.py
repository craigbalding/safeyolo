"""Native producer and installer checks with controlled executable identities.

These fixtures test packaging failures. The installed journey runs real product
binaries through tests/proxy_contracts/native-package-journey.sh.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import venv
import zipfile
from pathlib import Path

import pytest

from scripts import build_host_packages as builder
from scripts import verify_host_package as consumer

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


def preparation_interpreter(path):
    """Use a supported isolated interpreter with controlled NATS output."""
    venv.EnvBuilder(with_pip=False, symlinks=True).create(path)
    python = path / "bin/python"
    library = subprocess.check_output(
        [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        text=True, timeout=10,
    ).strip()
    package = Path(library) / "safeyolo/coord"
    package.mkdir(parents=True)
    for directory in (package.parent, package):
        (directory / "__init__.py").touch()
    (package / "nats_runtime.py").write_text("def ensure_binary(): return 'verified fixture NATS'\n")
    return python


@pytest.fixture
def package_inputs(tmp_path):
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
    for name in ("tmux-common", "tmux-window", "tmux-pane"):
        (assets / "launchers" / f"{name}.sh").write_text("#!/bin/sh\nexit 0\n")
    skill = assets / "agent_context/skills/safeyolo"
    (skill / "scripts/__pycache__").mkdir(parents=True)
    (skill / "references").mkdir()
    (skill / "SKILL.md").write_text(
        "fixture skill\n- Read [GitHub composite checks](references/github-checks.md)\n"
        "  Optional repository tooling.\n- Keep the next instruction.\n",
    )
    (skill / "scripts/github_checks.py").write_text("# optional checker\n")
    (skill / "scripts/__pycache__/old.pyc").write_bytes(b"old cache")
    (skill / "references/github-checks.md").write_text("optional checker instructions\n")
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


@pytest.mark.parametrize("platform,lane", [("Linux", "systrap"), ("Darwin", "vz")])
def test_blackbox_preparation_binds_available_native_inputs(tmp_path, monkeypatch, platform, lane):
    """Run the real preparation caller with controlled preceding tool outputs."""
    checkout = tmp_path / "source"
    scripts = checkout / "tests/blackbox"
    scripts.mkdir(parents=True)
    shutil.copy2(REPO / "tests/blackbox/run-lane.sh", scripts / "run-lane.sh")
    (scripts / "installed_host_smoke.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "def _installed_rust_binary(cli):\n"
        "    return Path(os.environ['PREPARE_HOST']) / 'safeyolo-proxy', {}\n"
    )
    tools, host, guest, root = (tmp_path / name for name in ("tools", "host", "guest", "root"))
    for path in (tools, host, guest, checkout / "scripts", checkout / "vm"):
        path.mkdir(parents=True, exist_ok=True)
    for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        (host / name).touch()
    (guest / "safeyolo-guest").touch()
    python = shutil.which("python3")
    interpreter = preparation_interpreter(tools / "python-environment")
    files = {
        checkout / "install.sh": "#!/bin/sh\nexit 0\n",
        tools / "uname": f"#!/bin/sh\nprintf '{platform}\\n'\n",
        tools / "tmux": "#!/bin/sh\nprintf 'tmux fixture\\n'\n",
        tools / "uv": '#!/bin/sh\nif [ "$1 $2" = "tool dir" ]; then printf "%s\\n" "$PREPARE_TOOLS"; fi\n',
        tools / "safeyolo": (
            f'#!{interpreter}\n'
            "import json,os,sys\nfrom pathlib import Path\n"
            "if '--check' in sys.argv:\n"
            "    print(json.dumps({'package_manager':'apt','missing_deps':[]}))\n"
            "else:\n"
            "    assert Path(os.environ['SAFEYOLO_CONFIG_DIR'], 'native-inputs.json').is_file()\n"
        ),
        tools / "make": (
            f"#!{python}\nimport pathlib,sys\n"
            "directory = pathlib.Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('INSTALL_DIR=')))\n"
            "directory.mkdir(parents=True)\n"
            "for name in ['safeyolo-vm','safeyolo-vm.build-info.json','vsock-term','vsock-term.version','vsock-term.sha256']:\n"
            "    (directory / name).touch()\n"
            "(directory / 'safeyolo-vm.dSYM').mkdir()\n"
        ),
        checkout / "scripts/install_native.sh": (
            f"#!{python}\nimport json,pathlib,sys\n"
            "options = dict(zip(sys.argv[1::2], sys.argv[2::2]))\n"
            "assert pathlib.Path(options['--runtime-artifacts'], 'tmux').is_file()\n"
            "if '--vm-artifacts' in options:\n"
            "    vm = pathlib.Path(options['--vm-artifacts'])\n"
            "    assert all((vm / n).exists() for n in ['safeyolo-vm','safeyolo-vm.dSYM','safeyolo-vm.build-info.json','vsock-term.version','vsock-term.sha256'])\n"
            "root = pathlib.Path(options['--root']); root.mkdir(exist_ok=True)\n"
            "(root / 'native-inputs.json').write_text(json.dumps(options))\n"
        ),
    }
    for path, content in files.items():
        path.write_text(content)
        path.chmod(0o755)
    # Preserve ordinary shell activation and mise discovery guards. Select
    # controlled test tools after activation adds the global toolset to PATH.
    activation = tmp_path / "shell-activation.sh"
    activation.write_text(
        'if [ -n "$PREPARE_ORIGINAL_BASH_ENV" ]; then . "$PREPARE_ORIGINAL_BASH_ENV"; fi\n'
        'export PATH="$PREPARE_TOOLS:$PATH"\n'
    )
    monkeypatch.setenv("PREPARE_ORIGINAL_BASH_ENV", os.environ.get("BASH_ENV", ""))
    monkeypatch.setenv("BASH_ENV", str(activation))
    for name in ("SAFEYOLO_NATIVE_BUNDLE", "SAFEYOLO_NATIVE_RUNTIME_ARTIFACTS", "SAFEYOLO_NATIVE_VM_ARTIFACTS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", f"{tools}:{os.environ['PATH']}")
    monkeypatch.setenv("PREPARE_HOST", str(host))
    monkeypatch.setenv("PREPARE_TOOLS", str(tools))
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.setenv("SAFEYOLO_GUEST_HELPER", str(guest / "safeyolo-guest"))
    result = run(str(scripts / "run-lane.sh"), lane, "--prepare-only", cwd=checkout)
    assert result.returncode == 0, result.stderr
    assert "verified fixture NATS" in result.stdout
    options = json.loads((root / "native-inputs.json").read_text())
    assert Path(options["--artifacts"]) == host
    assert Path(options["--guest-artifacts"]) == guest
    assert Path(options["--runtime-artifacts"]) == tools
    if platform == "Darwin":
        assert Path(options["--vm-artifacts"]) == root / "bin"


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
        assert any(name.endswith("/assets/repo_map.py") for name in names)
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


def test_fresh_install_preserves_prepared_platform_inputs(package_inputs, tmp_path):
    bundle = build_bundle(package_inputs, tmp_path)
    root = tmp_path / "prepared"
    (root / "share").mkdir(parents=True)
    image = root / "share/Image"
    image.write_bytes(b"prepared boot input")
    result = run(str(bundle / "install.sh"), "--root", str(root))
    assert result.returncode == 0, result.stderr
    assert image.read_bytes() == b"prepared boot input"
    assert (root / "LICENSE").read_bytes() == (bundle / "LICENSE").read_bytes()


# CI debug identity and the retained legacy wheel consumers remain active.

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


@pytest.fixture
def compiler_canaries(tmp_path, monkeypatch):
    tools = tmp_path / "compiler-canaries"
    tools.mkdir()
    for command in ("cargo", "rustc", "swift"):
        canary = tools / command
        canary.write_text("#!/bin/sh\nexit 99\n")
        canary.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tools}:{os.environ['PATH']}")


def test_wheel_hook_packages_the_selected_bytes_and_platform_without_compiling(tmp_path, compiler_canaries):
    binary = tmp_path / "selected-proxy"
    binary.write_bytes(b"selected debug runtime, different from checkout release bytes")
    binary.chmod(0o755)
    host_binaries = {name: tmp_path / name for name in ("safeyolo", "safeyolo-coord")}
    for name, path in host_binaries.items():
        path.write_bytes(f"selected host {name} bytes".encode())
        path.chmod(0o755)
    guest = tmp_path / "selected-guest"
    guest.write_bytes(b"selected Linux guest command bytes")
    guest.chmod(0o755)
    native = {"commit": REVISION, "profile": "debug", "platform": consumer.host_platform()}
    metadata = tmp_path / "native.json"
    metadata.write_text(json.dumps(native))
    tag = "linux_aarch64" if native["platform"] == "linux-arm64" else "linux_x86_64"
    destination = tmp_path / "dist"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(destination)], cwd=builder.ROOT, check=True,
        env={**os.environ, "SAFEYOLO_BUILD_REVISION": REVISION,
             "SAFEYOLO_NATIVE_BINARY": str(binary), "SAFEYOLO_NATIVE_BUILD_METADATA": str(metadata),
             "SAFEYOLO_GUEST_HELPER": str(guest),
             "SAFEYOLO_BUILD_PROFILE": "debug",
             "SAFEYOLO_NATIVE_PLATFORM_TAG": tag},
        capture_output=True, text=True,
    )
    wheel, = destination.glob("*.whl")
    assert wheel.name.endswith(f"-py3-none-{tag}.whl")
    assert f".dev0+g{REVISION}.debug-" in wheel.name
    with zipfile.ZipFile(wheel) as archive:
        assert "safeyolo/coord/mattermost.py" not in archive.namelist()
        assert "safeyolo/coord/mattermost_actions.py" not in archive.namelist()
        assert not any("legacy_mattermost" in name for name in archive.namelist())
        assert archive.read("safeyolo/bin/safeyolo-proxy") == binary.read_bytes()
        for name, path in host_binaries.items():
            assert archive.read(f"safeyolo/bin/{name}") == path.read_bytes()
        assert archive.read("safeyolo/bin/safeyolo-guest") == guest.read_bytes()
        assert json.loads(archive.read("safeyolo/_native_build.json")) == native
        wheel_metadata, = [name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")]
        assert b"Root-Is-Purelib: false" in archive.read(wheel_metadata)


def write_consumer_package(directory: Path, native: dict) -> dict:
    binary = b"known proxy bytes"
    native["proxy"] = {"sha256": hashlib.sha256(binary).hexdigest(), "settings": {"profile": "dev"}}
    wheel = directory / "safeyolo-0.1.0-py3-none-linux_x86_64.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("safeyolo/bin/safeyolo-proxy", binary)
        archive.writestr("safeyolo/_native_build.json", json.dumps(native))
        archive.writestr("safeyolo/_build_identity.json", json.dumps({
            "source_revision": REVISION, "build_identifier": "host-linux-amd64-debug",
        }))
    manifest = {"schema_version": 1, "native": native, "wheel": wheel.name,
                "compatibility": {"minimum_glibc": "2.39"}, "files": {wheel.name: consumer.sha256(wheel)}}
    write_manifest(directory, manifest)
    return manifest


def write_manifest(directory: Path, manifest: dict) -> None:
    path = directory / "manifest.json"
    path.write_text(json.dumps(manifest))
    sums = {**manifest["files"], "manifest.json": consumer.sha256(path)}
    (directory / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())))


@pytest.fixture
def consumer_package(tmp_path, monkeypatch):
    native = {"commit": REVISION, "platform": "linux-amd64", "profile": "debug"}
    manifest = write_consumer_package(tmp_path, native)
    monkeypatch.setattr(consumer, "host_platform", lambda: "linux-amd64")
    monkeypatch.setattr(consumer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(consumer.platform, "libc_ver", lambda: ("glibc", "2.39"))
    monkeypatch.setattr(consumer.subprocess, "check_output", lambda *args, **kwargs: f"safeyolo-proxy test commit={REVISION} profile=debug\n")
    return tmp_path, manifest


def test_consumer_checks_installed_runtime_identity_and_bytes(consumer_package):
    directory, manifest = consumer_package
    assert consumer.verify(directory) == manifest


@pytest.mark.parametrize("change", ["wheel-bytes", "source", "profile", "platform", "extra", "checksum-list", "runtime-version"])
def test_consumer_rejects_damaged_or_misidentified_download(consumer_package, monkeypatch, change):
    directory, manifest = consumer_package
    if change == "wheel-bytes":
        with (directory / manifest["wheel"]).open("ab") as stream:
            stream.write(b"damage")
    elif change in {"source", "profile", "platform"}:
        field = "commit" if change == "source" else change
        manifest["native"][field] = "b" * 40 if field == "commit" else "different"
        write_manifest(directory, manifest)
    elif change == "extra":
        (directory / "unexpected").write_text("unexpected")
    elif change == "checksum-list":
        (directory / "SHA256SUMS").write_text("")
    else:
        monkeypatch.setattr(consumer.subprocess, "check_output", lambda *args, **kwargs: "test executable 1.0")
    with pytest.raises(ValueError):
        consumer.verify(directory)


def test_consumer_checks_actual_glibc_requirement(consumer_package, monkeypatch):
    directory, _ = consumer_package
    monkeypatch.setattr(consumer.platform, "libc_ver", lambda: ("glibc", "2.38"))
    with pytest.raises(ValueError, match="requires glibc 2.39"):
        consumer.verify(directory)


def test_cli_version_uses_installed_commit_and_profile(monkeypatch):
    from typer.testing import CliRunner

    from safeyolo import runtime_identity
    from safeyolo.cli import app

    identity = runtime_identity.BuildIdentity(
        package_version=f"0.1.0.dev0+g{REVISION}.debug", source_revision=REVISION,
        build_identifier="host-linux-amd64-debug", provenance=runtime_identity.IdentityProvenance.BUILD_ENVIRONMENT,
        state=runtime_identity.EvidenceState.KNOWN,
    )
    monkeypatch.setattr(runtime_identity, "load_stamped_build_identity", lambda: identity)
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"commit={REVISION} profile=debug" in result.stdout
    assert identity.package_version in result.stdout
