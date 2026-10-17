"""Native producer and installer checks with controlled executable identities.

These fixtures test packaging failures. The installed journey runs real product
binaries through tests/proxy_contracts/native-package-journey.sh.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
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


@pytest.fixture(params=["gnu", "mac-short-options", "shasum"])
def checksum_bundle(tmp_path, monkeypatch, request):
    """Run real checksum tools and installers without compiling test binaries."""
    if os.uname().sysname != "Linux":
        pytest.skip("controlled shell identities run on Linux; macOS uses actual Tart tools")
    bundle = tmp_path / "bundle"
    for name in ("bin", "libexec", "assets/guest", "assets/launchers"):
        (bundle / name).mkdir(parents=True)
    platform = "linux-amd64" if os.uname().machine == "x86_64" else "linux-arm64"
    (bundle / "package-info").write_text(
        f"source_commit={REVISION}\nprofile=production\nplatform={platform}\nminimum_runtime=2.31\n"
        "guest_compatibility=test\nguest_repository=ghcr.io/craigbalding/safeyolo-guest\n"
        "guest_discovery_tag=compat-test\n",
    )
    for relative in ("bin/safeyolo", "bin/safeyolo-proxy", "bin/safeyolo-coord",
                     "assets/guest/safeyolo-guest", "assets/guest/safeyolo-coord"):
        path = bundle / relative
        identity = f"{path.name} 0.1.0 commit={REVISION} profile=production"
        path.write_text(
            '#!/bin/sh\nif [ "${3:-}" = init ]; then\n'
            ': > "$2/config.toml"; : > "$2/policy.toml"\nelse\n'
            f"printf '%s\\n' '{identity}'\nfi\n",
        )
        path.chmod(0o755)
        if relative.startswith("assets/"):
            path.with_suffix(".version").write_text(identity + "\n")
            path.with_suffix(".sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
    for relative in ("bin/tmux", "libexec/tmux", "bin/watch-backlog-factory"):
        path = bundle / relative
        path.write_text("#!/bin/sh\nprintf 'tmux fixture\\n'\n")
        path.chmod(0o755)
    for name in ("guest-init", "guest-init-static", "guest-init-per-run", "guest-proxy-forwarder",
                 "guest-shell-bridge", "guest-desktop", "guest-sudo"):
        (bundle / "assets/guest" / name).touch()
    for name in ("tmux-common", "tmux-window", "tmux-pane"):
        (bundle / "assets/launchers" / f"{name}.sh").touch()
    for source, destination in (("install_host_package.sh", "install.sh"),
                                ("install_native.sh", "install_native.sh"),
                                ("native_package.sh", "native_package.sh")):
        shutil.copy2(REPO / "scripts" / source, bundle / destination)
    (bundle / "LICENSE").write_text("fixture notice\n")
    (bundle / "payload with spaces").write_text("checked bundle bytes\n")
    (bundle / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(bundle)}\n"
        for path in sorted(bundle.rglob("*")) if path.is_file()
    ))

    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("bash", "uname", "getconf", "tr", "cat", "dirname", "mkdir", "mktemp", "rmdir",
                 "cp", "mv", "ln", "readlink", "cmp", "rm"):
        (tools / name).symlink_to(shutil.which(name))
    # Only architecture inspection is controlled. Every manifest and digest
    # check reads the real fixture bytes through the selected checksum tool.
    architecture = "3e00" if platform == "linux-amd64" else "b700"
    (tools / "od").write_text(f"#!/bin/sh\nprintf '7f454c460201000000000000000000000200{architecture}\\n'\n")
    (tools / "od").chmod(0o755)
    if request.param == "shasum":
        (tools / "shasum").symlink_to(shutil.which("shasum"))
    elif request.param == "gnu":
        (tools / "sha256sum").symlink_to(shutil.which("sha256sum"))
    else:
        backend = shlex.quote(shutil.which("sha256sum"))
        (tools / "sha256sum").write_text(
            '#!/bin/sh\ncheck=false; input=false\nfor argument do\ncase "$argument" in\n'
            '--*) echo "GNU long options are unsupported" >&2; exit 2;;\n'
            '-c) check=true;;\n-b|-t|-w|-z) ;;\n*) input=true;;\nesac\ndone\n'
            'if $check && ! $input; then echo "check requires an input operand" >&2; exit 2; fi\n'
            f'exec {backend} "$@"\n',
        )
        (tools / "sha256sum").chmod(0o755)
    # Keep inherited shell activation from adding an unselected backend.
    activation = tmp_path / "activation.sh"
    activation.write_text('export PATH="$CHECKSUM_TOOLS"\n')
    monkeypatch.setenv("BASH_ENV", str(activation))
    monkeypatch.setenv("CHECKSUM_TOOLS", str(tools))
    monkeypatch.setenv("PATH", str(tools))
    return bundle


@pytest.mark.parametrize("entry", ["source", "bundle"])
@pytest.mark.parametrize("damage", [None, "bytes", "missing", "malformed", "empty", "malformed-only"])
def test_checksum_backends_through_installers(checksum_bundle, tmp_path, entry, damage):
    bundle = checksum_bundle
    payload = bundle / "payload with spaces"
    if damage == "bytes":
        payload.write_text("changed bytes\n")
    elif damage == "missing":
        payload.unlink()
    elif damage == "malformed":
        manifest = bundle / "SHA256SUMS"
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        manifest.write_text(manifest.read_text().replace(digest, "g" * 64))
    elif damage == "empty":
        (bundle / "SHA256SUMS").write_text("")
    elif damage == "malformed-only":
        (bundle / "SHA256SUMS").write_text("malformed checksum\n")
    root = tmp_path / "installed"
    command = [str(bundle / "install.sh")]
    if entry == "source":
        command = [str(REPO / "install.sh"), "--bundle", str(bundle)]
    result = run(*command, "--root", str(root), "--command-dir", str(tmp_path / "commands"),
                 "--no-guest-download")
    if damage:
        assert result.returncode != 0
        assert "bundle checksum verification failed" in result.stderr
        assert not root.exists()
        assert not (tmp_path / "commands").exists()
    else:
        assert result.returncode == 0, result.stderr
        assert "Verified SafeYolo package" in result.stdout
        assert (root / "config.toml").exists()


def test_checksum_digest_preserves_tool_failure(checksum_bundle):
    payload = checksum_bundle / "payload with spaces"
    command = ("bash", "-c", 'source "$1"; file_sha256 "$2"',
               "digest", str(REPO / "scripts/native_package.sh"))
    result = run(*command, str(payload))
    assert result.returncode == 0
    assert result.stdout.strip() == hashlib.sha256(payload.read_bytes()).hexdigest()
    result = run(*command, str(checksum_bundle / "missing"))
    assert result.returncode != 0 and not result.stdout


def test_only_installed_layout_allows_original_installer_omissions(checksum_bundle):
    bundle = checksum_bundle
    command = ("bash", "-c", 'source "$1"; verify_native_package "$2" "${3:-}"',
               "verify", str(REPO / "scripts/native_package.sh"), str(bundle))
    for name in ("install.sh", "install_native.sh", "native_package.sh"):
        (bundle / name).unlink()
    assert run(*command).returncode != 0
    installed = run(*command, "--installed")
    assert installed.returncode == 0, installed.stderr
    manifest = bundle / "SHA256SUMS"
    complete = manifest.read_text()
    manifest.write_text("".join(line for line in complete.splitlines(keepends=True)
                                if line.endswith(("  ./install.sh\n", "  ./install_native.sh\n", "  ./native_package.sh\n"))))
    assert run(*command, "--installed").returncode != 0
    manifest.write_text(complete)
    # This exception never hides a present, changed script or a dangling link.
    (bundle / "install.sh").write_text("changed packaging script\n")
    assert run(*command, "--installed").returncode != 0
    (bundle / "install.sh").unlink()
    (bundle / "install.sh").symlink_to("missing-script")
    assert run(*command, "--installed").returncode != 0


def executable(path, identity, guest_exit=None, guest_assets=None):
    # Real ELF header/architecture, controlled identity; never a runtime witness.
    source = path.with_suffix(".c")
    guest_command = ""
    if guest_exit is not None or guest_assets is not None:
        guest_command = ('if(argc>3 && strcmp(argv[3],"guest")==0){'
                         'char *marker=getenv("PACKAGE_GUEST_CALLS");'
                         'if(marker){FILE *out=fopen(marker,"w");if(!out)return 90;'
                         'for(int i=1;i<argc;i++)fprintf(out,"%s\\n",argv[i]);fclose(out);}'
                         )
        if guest_exit is not None:
            guest_command += f'fprintf(stderr,"controlled guest acquisition refusal\\n");return {guest_exit};'
        else:
            guest_command += ('for(int i=1;i+1<argc;i++){if(strcmp(argv[i],"--write-selection")==0){'
                              'FILE *out=fopen(argv[i+1],"w");if(!out)return 91;fputs("{}",out);fclose(out);}}'
                              f'puts("{guest_assets}");return 0;')
        guest_command += '}'
    host_command = (
        'if(argc>4 && strcmp(argv[3],"host")==0 && strcmp(argv[4],"prepare")==0){'
        'char *installed="/fixture";char *settings=NULL;'
        'for(int i=5;i+1<argc;i++){if(strcmp(argv[i],"--installed-root")==0)installed=argv[i+1];'
        'if(strcmp(argv[i],"--write-settings")==0)settings=argv[i+1];}'
        'char *marker=getenv("PACKAGE_HOST_CALLS");if(marker){FILE *out=fopen(marker,"w");'
        'if(!out)return 92;for(int i=1;i<argc;i++)fprintf(out,"%s\\n",argv[i]);fclose(out);}'
        'if(settings){FILE *out=fopen(settings,"w");if(!out)return 93;'
        'fprintf(out,"[linux]\\nhost_uid=1000\\nhost_gid=1000\\nuid_base=100000\\ngid_base=100000\\nrunsc=\\\"%s/libexec/runsc\\\"\\nrunsc_origin=\\\"bundled\\\"\\n",installed);fclose(out);}return 0;}'
    )
    launch_command = (
        'if(argc>4 && strcmp(argv[3],"agent")==0 && strcmp(argv[4],"launch")==0){'
        'char *marker=getenv("PACKAGE_LAUNCH_CALLS");if(marker){FILE *out=fopen(marker,"w");'
        'if(!out)return 94;for(int i=1;i<argc;i++)fprintf(out,"%s\\n",argv[i]);fclose(out);}'
        'char *code=getenv("PACKAGE_LAUNCH_EXIT");return code?atoi(code):0;}'
    )
    source.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
                      f'int main(int argc,char **argv){{{host_command}{guest_command}{launch_command}puts("{identity}");return 0;}}\n')
    subprocess.run(["cc", str(source), "-o", str(path)], check=True, timeout=15)
    source.unlink()



@pytest.fixture
def package_inputs(tmp_path, request, monkeypatch):
    if os.uname().sysname != "Linux":
        pytest.skip("controlled ELF producer fixture runs on Linux; macOS uses actual Tart artifacts")
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    for name in ("build_host_packages.sh", "native_package.sh", "install_native.sh", "install_host_package.sh", "tmux_runtime.sh", "watch_backlog_factory.sh"):
        shutil.copy2(REPO / "scripts" / name, scripts / name)
    # Only upstream acquisition is controlled. The real producer, complete
    # payload reader, installer and architecture checks consume these bytes.
    (scripts / "acquire_runsc.sh").write_text(
        '#!/bin/bash\nset -euo pipefail\nmkdir "$1"\n'
        'cp -R "$PACKAGE_RUNSC_FIXTURE/"* "$1/"\n',
    )
    (scripts / "acquire_runsc.sh").chmod(0o755)
    shutil.copy2(REPO / "install.sh", source / "install.sh")
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
    # This producer and its executables belong to the committed fixture.
    # CI's inherited revision identifies the separately built real CLI.
    monkeypatch.setenv("SAFEYOLO_BUILD_REVISION", revision)
    host, guest, runtime = (tmp_path / name for name in ("host", "guest", "runtime"))
    for directory in (host, guest, runtime):
        directory.mkdir()
    prepared = tmp_path / "prepared-guest"
    (prepared / "rootfs-tree").mkdir(parents=True)
    (prepared / "cache-paths.txt").write_text("/var/cache/apt\n")
    profile = "production" if getattr(request, "param", None) == "production" else "debug"
    for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        executable(host / name, f"{name} 0.1.0 commit={revision} profile={profile}",
                   guest_assets=str(prepared) if name == "safeyolo" else None)
    for name in ("safeyolo-guest", "safeyolo-coord"):
        identity = f"{name} 0.1.0 commit={revision} profile={profile}"
        executable(guest / name, identity)
        (guest / f"{name}.version").write_text(identity + "\n")
        (guest / f"{name}.sha256").write_text(hashlib.sha256((guest / name).read_bytes()).hexdigest() + "\n")
    shutil.copy2(shutil.which("tmux"), runtime / "tmux")
    runsc = tmp_path / "gvisor"
    (runsc / "gvisor-bin").mkdir(parents=True)
    executable(runsc / "runsc", "runsc version release-20261005.0")
    for name in ("gvisor-bin/checkpointgofer", "gvisor-bin/gvisor-sentry-prewarmer",
                 "gvisor-bin/gvisor_sentry", "gvisor-bin/runsc-fd-parking", "gvisor-bin/runsc-metric-server"):
        shutil.copy2(runsc / "runsc", runsc / name)
    monkeypatch.setenv("PACKAGE_RUNSC_FIXTURE", str(runsc))
    (runtime / "licenses").mkdir()
    (runtime / "licenses/tmux.txt").write_text("fixture runtime notice\n")
    arguments = [str(scripts / "build_host_packages.sh"), "--profile", profile, "--artifacts", str(host), "--guest-artifacts", str(guest), "--runtime-artifacts", str(runtime)]
    return source, host, guest, runtime, arguments, revision


def build_bundle(inputs, tmp_path):
    directory = tmp_path / "bundle"
    result = run(*inputs[4], "--directory", str(directory))
    assert result.returncode == 0, result.stderr
    return directory


@pytest.mark.parametrize("bundle", [False, True], ids=["source", "bundle"])
@pytest.mark.parametrize("platform,lane", [("Linux", "systrap"), ("Darwin", "vz"),
                                          ("Linux", "proxy"), ("Darwin", "proxy")])
@pytest.mark.parametrize("separate_checkout", [False, True])
def test_blackbox_preparation_binds_available_native_inputs(tmp_path, monkeypatch, platform, lane, separate_checkout, bundle):
    """Guest lanes retain prepared inputs; proxy lanes opt out of acquisition."""
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
        "arguments = [arg for arg in sys.argv[1:] if arg not in {'--no-guest-download', '--yes'}]\n"
        "options = dict(zip(arguments[::2], arguments[1::2]))\n"
        "if '--no-guest-download' in sys.argv: options['--no-guest-download'] = True\n"
        "assert '--yes' in sys.argv\n"
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
    if bundle:
        monkeypatch.setenv('SAFEYOLO_NATIVE_BUNDLE', str(tmp_path / 'bundle'))
    selection = ['--install-checkout', str(selected)] if separate_checkout else []
    result = run(str(scripts / 'run-lane.sh'), lane, *selection, '--prepare-only', cwd=checkout)
    assert result.returncode == 0, result.stderr
    options = json.loads((root / 'native-inputs.json').read_text())
    if bundle:
        assert Path(options['--bundle']) == tmp_path / 'bundle'
        assert not {'--artifacts', '--guest-artifacts', '--runtime-artifacts', '--vm-artifacts'} & options.keys()
    else:
        assert Path(options['--artifacts']) == host
        assert Path(options['--guest-artifacts']) == guest
        assert Path(options['--runtime-artifacts']) == runtime
        if platform == 'Darwin':
            assert Path(options['--vm-artifacts']) == vm
    if lane == 'proxy':
        assert options['--no-guest-download'] is True
        assert '--platform-assets' not in options
    else:
        assert Path(options['--platform-assets']) == images
        assert '--no-guest-download' not in options
    assert 'native --root' in result.stdout and 'coord stop' in result.stdout
    if separate_checkout:
        failed = run(str(scripts / 'run-lane.sh'), lane, '--install-checkout', str(tmp_path / 'missing'), cwd=checkout)
        assert failed.returncode == 2 and 'requires a source checkout' in failed.stderr
        assert (root / 'native-inputs.json').read_text() == json.dumps(options)


@pytest.mark.parametrize("bundle", [False, True], ids=["source", "bundle"])
@pytest.mark.parametrize("prepared", [False, True], ids=["proxy-only", "prepared-assets"])
def test_native_policy_instance_selects_required_guest_inputs(tmp_path, monkeypatch, bundle, prepared):
    from tests.proxy_contracts import test_native_policy_cli as native_policy

    class InstallationBoundary(Exception):
        pass

    bundle_path = tmp_path / "bundle"
    if bundle:
        monkeypatch.setenv("SAFEYOLO_NATIVE_BUNDLE", str(bundle_path))
    else:
        monkeypatch.delenv("SAFEYOLO_NATIVE_BUNDLE", raising=False)
    assets = tmp_path / "prepared" if prepared else None
    observed = []

    def install(command, **kwargs):
        observed.append(command)
        assert command[0] == str(REPO / "scripts/install_native.sh")
        if bundle:
            assert command[command.index("--bundle") + 1] == str(bundle_path)
            assert "--artifacts" not in command
        else:
            assert "--artifacts" in command and "--bundle" not in command
            assert command[command.index("--profile") + 1] == "production"
        if prepared:
            assert command[command.index("--platform-assets") + 1] == str(assets)
            assert "--no-guest-download" not in command
        else:
            assert "--no-guest-download" in command and "--platform-assets" not in command
        raise InstallationBoundary

    monkeypatch.setattr(native_policy.subprocess, "run", install)
    with pytest.raises(InstallationBoundary), native_policy.native_instance(tmp_path, platform_assets=assets):
        pytest.fail("argv control must stop at installation")
    assert len(observed) == 1


@pytest.mark.parametrize("profile", ["production", "debug"])
def test_native_source_fixture_selects_matching_profile_inputs(monkeypatch, profile):
    from tests.proxy_contracts.test_native_policy_cli import native_inputs

    monkeypatch.setenv("SAFEYOLO_BUILD_PROFILE", profile)
    monkeypatch.delenv("SAFEYOLO_NATIVE_ARTIFACTS", raising=False)
    monkeypatch.delenv("SAFEYOLO_GUEST_ARTIFACTS", raising=False)
    host, guest, selected = native_inputs()
    directory = "release" if profile == "production" else "debug"
    assert selected == profile
    assert host == REPO / "proxy/target" / directory
    assert guest == REPO / "guest/command/target" / directory


def test_native_product_fixture_refuses_debug_bundle_when_production_is_selected(tmp_path, monkeypatch):
    from tests.proxy_contracts import test_native_policy_cli as native_policy

    monkeypatch.setenv("SAFEYOLO_NATIVE_BUNDLE", str(tmp_path / "bundle"))
    monkeypatch.setenv("SAFEYOLO_BUILD_PROFILE", "production")

    def install(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=f"safeyolo commit={REVISION} profile=debug\n", stderr="")

    monkeypatch.setattr(native_policy.subprocess, "run", install)
    with pytest.raises(AssertionError), native_policy.native_instance(tmp_path):
        pytest.fail("A wrong-profile bundle must fail before starting a product process")


@pytest.mark.parametrize("profile,wrong_profile", [("production", False), ("debug", False), ("production", True)])
@pytest.mark.parametrize("job,step_name", [("build", "Build Linux host test inputs"), ("macos-host", "Build and check Mac host test inputs")])
def test_shared_host_input_step_selects_release_and_refuses_wrong_profile(
    package_inputs, tmp_path, profile, wrong_profile, job, step_name,
):
    import yaml

    source, host, guest, _, _, revision = package_inputs
    selected = "release" if profile == "production" else "debug"
    actual = "debug" if wrong_profile else profile
    for directory, names in ((host, ("safeyolo", "safeyolo-proxy", "safeyolo-coord")),
                             (guest, ("safeyolo-guest", "safeyolo-coord"))):
        for name in names:
            executable(directory / name, f"{name} 0.1.0 commit={revision} profile={actual}")
            if directory == guest:
                (guest / f"{name}.version").write_text(f"{name} 0.1.0 commit={revision} profile={actual}\n")
                (guest / f"{name}.sha256").write_text(builder.sha256(guest / name) + "\n")
    shutil.copytree(host, source / "proxy/target" / selected)
    shutil.copytree(guest, source / "guest/command/target" / selected)
    # Capture Cargo arguments. The normal validator checks real controlled ELF
    # executables, not an assertion about the compiler output or Mac execution.
    cargo = source / "scripts/cargo_with_space.sh"
    cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CARGO_ARGUMENTS"\n')
    cargo.chmod(0o755)
    arguments = tmp_path / "cargo-arguments"
    workflow = yaml.safe_load((REPO / ".github/workflows/guest-test-inputs.yml").read_text())
    step = next(s for s in workflow["jobs"][job]["steps"] if s.get("name") == step_name)
    result = run("bash", "-euo", "pipefail", "-c", step["run"], cwd=source,
                 env={**os.environ, "SAFEYOLO_BUILD_PROFILE": profile, "CARGO_ARGUMENTS": str(arguments)})
    assert ("--release" in arguments.read_text().splitlines()) == (profile == "production")
    if wrong_profile:
        assert result.returncode != 0 and "build profile is incorrect" in result.stderr
    else:
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("package_inputs", ["production"], indirect=True)
@pytest.mark.parametrize("workflow_name,job,step_name", [
    ("ci.yml", "test-cli", "Restore native test executable permissions"),
    ("ci.yml", "test-addons", "Restore native test executable permissions"),
    ("proxy-rust.yml", "contracts", "Restore Linux guest executable permissions"),
])
@pytest.mark.parametrize("damage", [None, "missing-guest", "profile", "checksum"])
def test_workflow_consumers_validate_prepared_native_inputs(package_inputs, tmp_path, workflow_name, job, step_name, damage):
    import yaml

    source, host, guest, _, _, _ = package_inputs
    host_inputs = source / "proxy/target/release"
    guest_inputs = source / "guest/command/target/release"
    shutil.copytree(host, host_inputs)
    shutil.copytree(guest, guest_inputs)
    if damage == "missing-guest":
        (guest_inputs / "safeyolo-coord").unlink()
    elif damage == "profile":
        receipt = guest_inputs / "safeyolo-coord.version"
        receipt.write_text(receipt.read_text().replace("production", "debug"))
    elif damage == "checksum":
        (guest_inputs / "safeyolo-coord.sha256").write_text("0" * 64 + "\n")
    workflow = yaml.safe_load((REPO / ".github/workflows" / workflow_name).read_text())
    step = next(s for s in workflow["jobs"][job]["steps"] if s.get("name") == step_name)
    result = run("bash", "-euo", "pipefail", "-c", step["run"], cwd=source,
                 env={**os.environ, "SAFEYOLO_NATIVE_ARTIFACTS": str(host_inputs)})
    if damage is None:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert "safeyolo-coord" in result.stderr


def test_native_bundle_archives_checked_bytes_and_private_runtime(package_inputs, tmp_path):
    output = tmp_path / "output"
    result = run(*package_inputs[4], "--output", str(output))
    assert result.returncode == 0, result.stderr
    bootstrap = output / "install-safeyolo.sh"
    assert f"release=host-{package_inputs[5]}" in bootstrap.read_text()
    assert os.access(bootstrap, os.X_OK)
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


def test_native_bundle_metadata_records_guest_discovery_without_pinning_an_archive(package_inputs, tmp_path):
    bundle = build_bundle(package_inputs, tmp_path)
    fields = dict(line.split("=", 1) for line in (bundle / "package-info").read_text().splitlines())
    assert set(fields) == {"source_commit", "profile", "platform", "minimum_runtime",
                           "guest_compatibility", "guest_repository", "guest_discovery_tag",
                           "runsc_version", "runsc_source", "runsc_origin"}
    assert fields["runsc_version"] == "release-20261005.0"
    assert fields["runsc_origin"] == "bundled"
    assert fields["guest_compatibility"] == "v1"
    assert fields["guest_repository"] == "ghcr.io/craigbalding/safeyolo-guest"
    assert fields["guest_discovery_tag"] == "compat-v1"


@pytest.mark.parametrize("damage", ["missing", "corrupt", "architecture", "unlisted", "empty-metadata", "missing-metadata"])
def test_runtime_payload_refusal_preserves_other_installation(package_inputs, tmp_path, damage):
    bundle = build_bundle(package_inputs, tmp_path)
    sidecar = bundle / "libexec/gvisor-bin/gvisor_sentry"
    if damage == "missing":
        sidecar.unlink()
    elif damage == "corrupt":
        sidecar.write_bytes(sidecar.read_bytes() + b"corrupt")
    elif damage == "architecture":
        data = bytearray(sidecar.read_bytes())
        data[18:20] = (62 if os.uname().machine in ("arm64", "aarch64") else 183).to_bytes(2, "little")
        sidecar.write_bytes(data)
        sums = bundle / "SHA256SUMS"
        sums.write_text("".join(f"{builder.sha256(sidecar)}  ./libexec/gvisor-bin/gvisor_sentry\n" if line.endswith(" ./libexec/gvisor-bin/gvisor_sentry\n") else line
                                for line in sums.read_text().splitlines(keepends=True)))
    elif damage == "unlisted":
        sums = bundle / "SHA256SUMS"
        sums.write_text("".join(line for line in sums.read_text().splitlines(keepends=True)
                                if not line.endswith(" ./libexec/gvisor-bin/gvisor_sentry\n")))
    else:
        metadata = bundle / "package-info"
        metadata.write_text("".join((line.split("=")[0] + "=\n" if damage == "empty-metadata" else "")
                                    if line.startswith("runsc_") else line
                                    for line in metadata.read_text().splitlines(keepends=True)))
    other = tmp_path / "other-instance"
    other.mkdir()
    canary = other / "policy.toml"
    canary.write_bytes(b"kept operator policy")
    root = tmp_path / "refused"
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"))
    assert result.returncode != 0, result.stdout
    assert not root.exists()
    assert canary.read_bytes() == b"kept operator policy"
    assert "gvisor" in result.stderr.lower() or "checksum" in result.stderr


@pytest.mark.parametrize("change,diagnosis", [
    (lambda text: text.replace("guest_compatibility=v1\n", ""), "compatibility/discovery"),
    (lambda text: text.replace("guest_compatibility=v1", "guest_compatibility=../v1"), "compatibility/discovery"),
    (lambda text: text.replace("compat-v1", "compat-v2"), "compatibility/discovery"),
    (lambda text: text.replace("ghcr.io/craigbalding/safeyolo-guest", "example.test/guest"), "untrusted guest repository"),
    (lambda text: text + "guest_repository=ghcr.io/craigbalding/safeyolo-guest\n", "duplicate package field"),
    (lambda text: text + "source_commit=" + "b" * 40 + "\n", "duplicate package field"),
    (lambda text: text + "unknown=field", "unknown package field"),
])
def test_package_reader_refuses_invalid_guest_metadata_before_installation(package_inputs, tmp_path, change, diagnosis):
    bundle = build_bundle(package_inputs, tmp_path)
    metadata = bundle / "package-info"
    metadata.write_text(change(metadata.read_text()))
    root = tmp_path / "refused"
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"))
    assert result.returncode != 0 and diagnosis in result.stderr
    assert not root.exists()


def test_default_installer_calls_native_guest_before_creating_configuration(package_inputs, tmp_path):
    executable(package_inputs[1] / "safeyolo", f"safeyolo 0.1.0 commit={package_inputs[5]} profile=debug", guest_exit=31)
    bundle = build_bundle(package_inputs, tmp_path)
    root, marker = tmp_path / "fresh", tmp_path / "guest-argv"
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"),
                 env=dict(os.environ, PACKAGE_GUEST_CALLS=str(marker)))
    assert result.returncode == 31 and "controlled guest acquisition refusal" in result.stderr
    arguments = marker.read_text().splitlines()
    staging = Path(arguments[1])
    assert staging.parent == root.parent and staging.name.startswith("safeyolo-install.")
    assert arguments == ["--root", str(staging), "guest", "acquire", "--package-info", str(bundle / "package-info"), "--write-selection", str(staging / "guest-selection.json"), "--host-settings", str(staging / "host-settings.toml")]
    assert not staging.exists()
    assert not (root / "config.toml").exists()
    assert not (root / "bin").exists()
    assert not (root / "data").exists()
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"), "--no-guest-download")
    assert result.returncode == 0, result.stderr
    platform = tmp_path / "explicit"
    (platform / "rootfs-tree").mkdir(parents=True)
    supplied = tmp_path / "supplied"
    selection = supplied / "share/guest-selection.json"
    selection.parent.mkdir(parents=True)
    selection.write_bytes(b'{"index": "prepared acquisition selection"}\n')
    acquisition_call = marker.read_bytes()
    result = run(str(bundle / "install.sh"), "--root", str(supplied), "--command-dir", str(supplied / "commands"),
                 "--platform-assets", str(platform), env=dict(os.environ, PACKAGE_GUEST_CALLS=str(marker)))
    assert result.returncode == 0, result.stderr
    assert (supplied / "share/rootfs-tree").resolve() == (platform / "rootfs-tree").resolve()
    assert selection.read_bytes() == b'{"index": "prepared acquisition selection"}\n'
    assert marker.read_bytes() == acquisition_call


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


def test_producer_rejects_a_different_build_revision(package_inputs, tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_BUILD_REVISION", "b" * 40)
    result = run(*package_inputs[4], "--directory", str(tmp_path / "bundle"))
    assert result.returncode != 0
    assert "build revision differs from this source" in result.stderr
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
    result = run(str(bundle / "install.sh"), "--root", str(root), "--command-dir", str(root / "commands"), "--no-guest-download", cwd=tmp_path)
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


@pytest.mark.parametrize("guest_input", ["default", "offline", "proxy", "bad-checksum"])
def test_installed_package_wrapper_selects_the_archive_installer_without_source_fallback(tmp_path, guest_input):
    """Stop at the real shell caller boundary; no synthetic runtime is claimed."""
    repository = tmp_path / "test-driver"
    scripts = repository / "tests/blackbox"
    scripts.mkdir(parents=True)
    shutil.copy2(REPO / "tests/blackbox/run-installed-package.sh", scripts)
    (repository / "scripts").mkdir()
    shutil.copy2(REPO / "scripts/native_package.sh", repository / "scripts")
    bundle = tmp_path / "host-bundle"
    bundle.mkdir()
    calls = tmp_path / "installer-arguments"
    installer = bundle / "install.sh"
    installer.write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$INSTALLER_CALLS"\nexit 42\n')
    installer.chmod(0o755)
    archive = tmp_path / "host package.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(bundle, arcname="host-bundle")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    home = tmp_path / "owned-home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "INSTALLER_CALLS": str(calls),
           "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(tmp_path / "reports")}
    options = ["--package", str(archive), "--sha256", "0" * 64 if guest_input == "bad-checksum" else digest]
    if guest_input == "offline":
        options += ["--platform-assets", str(tmp_path / "offline guest")]
    elif guest_input == "proxy":
        options += ["--no-guest-download"]
    result = run(str(scripts / "run-installed-package.sh"), *options, cwd=tmp_path, env=env)
    if guest_input == "bad-checksum":
        assert result.returncode == 1 and "Host archive checksum differs" in result.stderr
        assert not calls.exists()
        assert not list(home.glob("*/archive"))
    else:
        assert result.returncode == 42, result.stdout + result.stderr
        arguments = calls.read_text().splitlines()
        root = Path(arguments[arguments.index("--root") + 1])
        assert root.parent.parent == home
        assert arguments[:4] == ["--root", str(root), "--command-dir", str(root / "commands")]
        assert arguments[4:] == options[4:]
        assert f"sha256:{digest}" in result.stdout
