"""Focused runtime reuse, wheel byte identity and consumer verification checks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts import build_host_packages as builder
from scripts import verify_host_package as consumer

REVISION = "a" * 40


@pytest.fixture
def debug_artifact(tmp_path, monkeypatch):
    directory = tmp_path / "debug-input"
    directory.mkdir()
    binary = directory / "safeyolo-proxy"
    binary.write_bytes(b"saved runtime bytes")
    settings = {"profile": "dev", "rustc": "pinned compiler", "environment": {}}
    metadata = {
        "commit": REVISION, "platform": "linux-amd64", "profile": "debug",
        "components": {"proxy": {"sha256": consumer.sha256(binary), "settings": json.loads(json.dumps(settings)),
                                 "files": {binary.name: consumer.sha256(binary)}}},
    }
    (directory / "build.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(builder, "commit", lambda: REVISION)
    monkeypatch.setattr(builder, "host_platform", lambda: "linux-amd64")
    monkeypatch.setattr(builder, "proxy_settings", lambda profile: {**settings, "profile": "release" if profile == "production" else "dev"})
    monkeypatch.setattr(builder, "verify_proxy", lambda path, profile: None)
    return directory, metadata, settings


def test_exact_debug_runtime_is_reused_without_a_compiler(debug_artifact, monkeypatch):
    directory, _, _ = debug_artifact
    monkeypatch.setattr(builder.subprocess, "run", lambda *args, **kwargs: pytest.fail("reused runtime compiled again"))
    paths, native = builder.build_runtimes("debug", directory)
    assert paths["proxy"].read_bytes() == b"saved runtime bytes"
    assert os.access(paths["proxy"], os.X_OK)
    assert native["proxy"]["origin"] == "master-ci"
    assert native["proxy"]["sha256"] == consumer.sha256(paths["proxy"])


@pytest.mark.parametrize("change", ["commit", "platform", "profile", "compiler", "flags", "bytes", "missing", "test-output", "invalid-json"])
def test_unusable_debug_output_takes_one_bounded_fallback(debug_artifact, tmp_path, monkeypatch, change):
    directory, metadata, _ = debug_artifact
    if change in {"commit", "platform", "profile"}:
        metadata[change] = "different"
    elif change == "compiler":
        metadata["components"]["proxy"]["settings"]["rustc"] = "another compiler"
    elif change == "flags":
        metadata["components"]["proxy"]["settings"]["environment"]["RUSTFLAGS"] = "-C opt-level=3"
    elif change == "bytes":
        (directory / "safeyolo-proxy").write_bytes(b"damaged artifact")
    elif change in {"missing", "test-output"}:
        (directory / "safeyolo-proxy").unlink()
        if change == "test-output":
            (directory / "deps").mkdir()
            (directory / "deps/safeyolo_proxy-test").write_bytes(b"test executable")
    (directory / "build.json").write_text("not JSON" if change == "invalid-json" else json.dumps(metadata))
    target = tmp_path / "target"
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target))
    calls = []

    def compile_once(args, **kwargs):
        calls.append(args)
        runtime = target / "debug/safeyolo-proxy"
        runtime.parent.mkdir(parents=True)
        runtime.write_bytes(b"new debug runtime")

    monkeypatch.setattr(builder.subprocess, "run", compile_once)
    paths, native = builder.build_runtimes("debug", directory)
    assert len(calls) == 1
    assert calls[0][1:] == ["build", "--locked", "--bin", "safeyolo-proxy"]
    assert paths["proxy"].read_bytes() == b"new debug runtime"
    assert native["proxy"]["origin"] == "postmerge-build"


def test_production_does_not_substitute_debug_bytes(debug_artifact, tmp_path, monkeypatch):
    directory, _, _ = debug_artifact
    target = tmp_path / "target"
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target))
    calls = []

    def compile_once(args, **kwargs):
        calls.append(args)
        runtime = target / "release/safeyolo-proxy"
        runtime.parent.mkdir(parents=True)
        runtime.write_bytes(b"production runtime")

    monkeypatch.setattr(builder.subprocess, "run", compile_once)
    paths, native = builder.build_runtimes("production", directory)
    assert len(calls) == 1 and calls[0][-1] == "--release"
    assert paths["proxy"].read_bytes() == b"production runtime"
    assert native["proxy"]["settings"]["profile"] == "release"


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
        assert archive.read("safeyolo/bin/safeyolo-proxy") == binary.read_bytes()
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


def macos_load_commands(minimum: str, command: str = "LC_BUILD_VERSION") -> str:
    # Fields and layout follow Apple's otool/ofile_print.c deployment and version printers.
    deployment = f"""
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 1
    minos {minimum}
      sdk 26.0
   ntools 1
     tool 3
  version 1267.0
""" if command == "LC_BUILD_VERSION" else f"""
      cmd LC_VERSION_MIN_MACOSX
  cmdsize 16
  version {minimum}
      sdk 26.0
"""
    return f"""test-runtime:
Load command 0
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 2048.1.2.3.4
Load command 1
{deployment}
Load command 2
          cmd LC_LOAD_DYLIB
      cmdsize 56
         name /usr/lib/libSystem.B.dylib (offset 24)
   time stamp 2 Thu Jan  1 00:00:02 1970
      current version 1345.100.2
compatibility version 1.0.0
Load command 3
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 4096.0
"""


@pytest.mark.parametrize("command", ["LC_BUILD_VERSION", "LC_VERSION_MIN_MACOSX"])
@pytest.mark.parametrize("minimum", ["11.0", "14.0", "15.2.1", "26.0"])
def test_macos_deployment_requirement_ignores_unrelated_versions(monkeypatch, command, minimum):
    monkeypatch.setattr(builder, "host_platform", lambda: "darwin-arm64")
    monkeypatch.setattr(builder, "output", lambda *args, **kwargs: macos_load_commands(minimum, command))
    major, minor, *_ = minimum.split(".")
    assert builder.runtime_compatibility({"proxy": Path("proxy"), "helper": Path("helper")}) == (
        f"macosx_{major}_{minor}_arm64", {"minimum_macos": minimum},
    )


@pytest.mark.parametrize("proxy_minimum,helper_minimum", [("11.0", "14.0"), ("14.0", "11.0"), ("15.2", "15.2.1")])
def test_macos_package_uses_the_highest_component_requirement(monkeypatch, proxy_minimum, helper_minimum):
    monkeypatch.setattr(builder, "host_platform", lambda: "darwin-arm64")
    outputs = {
        "proxy": macos_load_commands(proxy_minimum),
        "helper": macos_load_commands(helper_minimum, "LC_VERSION_MIN_MACOSX"),
    }
    monkeypatch.setattr(builder, "output", lambda *args: outputs[args[-1]])
    _, compatibility = builder.runtime_compatibility({"proxy": Path("proxy"), "helper": Path("helper")})
    expected = "15.2.1" if proxy_minimum == "15.2" else "14.0"
    assert compatibility == {"minimum_macos": expected}
    monkeypatch.setattr(consumer.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(consumer.platform, "mac_ver", lambda: (expected, ("", "", ""), "arm64"))
    consumer.verify_compatibility(compatibility)
    older = "15.2" if expected == "15.2.1" else "13.6"
    monkeypatch.setattr(consumer.platform, "mac_ver", lambda: (older, ("", "", ""), "arm64"))
    with pytest.raises(ValueError, match=f"requires macOS {expected}"):
        consumer.verify_compatibility(compatibility)


@pytest.mark.parametrize("missing_component", ["proxy", "helper"])
def test_macos_package_requires_each_component_deployment_minimum(monkeypatch, missing_component):
    monkeypatch.setattr(builder, "host_platform", lambda: "darwin-arm64")
    unrelated = """Load command 0
      cmd LC_SOURCE_VERSION
  cmdsize 16
  version 1267.0
Load command 1
      cmd LC_VERSION_MIN_IPHONEOS
  cmdsize 16
  version 18.0
      sdk 26.0
"""
    monkeypatch.setattr(builder, "output", lambda *args: unrelated if args[-1] == missing_component else macos_load_commands("14.0"))
    with pytest.raises(ValueError, match=f"deployment minimum is missing from {missing_component}"):
        builder.runtime_compatibility({"proxy": Path("proxy"), "helper": Path("helper")})


@pytest.mark.parametrize("profile", ["production", "debug"])
def test_macos_package_wheel_and_manifest_share_the_actual_minimum(tmp_path, monkeypatch, compiler_canaries, profile):
    proxy = tmp_path / "safeyolo-proxy"
    proxy.write_bytes(b"selected proxy bytes")
    proxy.chmod(0o755)
    helper = tmp_path / "safeyolo-vm"
    helper.write_bytes(b"selected helper bytes")
    symbols = tmp_path / "safeyolo-vm.dSYM"
    symbols.mkdir()
    (symbols / "symbols").write_bytes(b"debug symbols")
    helper_profile = "production" if profile == "production" else "development"
    helper_identity = {"git_sha": REVISION, "build_profile": helper_profile}
    (tmp_path / "safeyolo-vm.build-info.json").write_text(json.dumps(helper_identity))
    guest = tmp_path / "guest"
    guest.mkdir()
    (guest / "vsock-term").write_bytes(b"guest terminal bytes")
    (guest / "build.json").write_text(json.dumps({"commit": REVISION, "sha256": consumer.sha256(guest / "vsock-term")}))
    native = {
        "commit": REVISION, "platform": "darwin-arm64", "profile": profile,
        "proxy": {"sha256": consumer.sha256(proxy), "settings": {"profile": "release" if profile == "production" else "dev"}},
        "helper": {"sha256": consumer.sha256(helper), "profile": helper_profile, "identity": helper_identity},
    }
    monkeypatch.setattr(builder, "host_platform", lambda: "darwin-arm64")
    monkeypatch.setattr(consumer, "host_platform", lambda: "darwin-arm64")
    monkeypatch.setattr(consumer.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(consumer.platform, "mac_ver", lambda: ("15.2.1", ("", "", ""), "arm64"))
    real_output = builder.output

    def output(*args, **kwargs):
        if args[:2] == ("otool", "-l"):
            return macos_load_commands("14.0") if args[-1] == str(proxy) else macos_load_commands("15.2.1", "LC_VERSION_MIN_MACOSX")
        return real_output(*args, **kwargs)

    monkeypatch.setattr(builder, "output", output)
    # Linux cannot execute/sign Mac runtimes; packaging, wheel inspection and compatibility checks remain real.
    real_check_output = consumer.subprocess.check_output

    def check_output(args, **kwargs):
        if len(args) == 2 and Path(args[0]).name == "safeyolo-proxy" and args[1] == "--version":
            return f"safeyolo-proxy test commit={REVISION} profile={profile}\n"
        return real_check_output(args, **kwargs)

    monkeypatch.setattr(consumer.subprocess, "check_output", check_output)
    monkeypatch.setattr(consumer, "verify_helper", lambda *args: None)
    directory = tmp_path / f"package-{profile}"
    archive = builder.package(profile, {"proxy": proxy, "helper": helper}, native, directory, guest)
    assert archive.is_file()
    manifest = consumer.verify(directory)
    assert manifest["native"] == native
    assert manifest["compatibility"] == {"minimum_macos": "15.2.1"}
    assert manifest["wheel"].endswith("-py3-none-macosx_15_2_arm64.whl")
    with zipfile.ZipFile(directory / manifest["wheel"]) as wheel:
        wheel_metadata, = [name for name in wheel.namelist() if name.endswith(".dist-info/WHEEL")]
        assert b"Tag: py3-none-macosx_15_2_arm64" in wheel.read(wheel_metadata)
    monkeypatch.setattr(consumer.platform, "mac_ver", lambda: ("15.2", ("", "", ""), "arm64"))
    with pytest.raises(ValueError, match="requires macOS 15.2.1"):
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
