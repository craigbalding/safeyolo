"""Check guest build targets and the artifact paths used by package consumers."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("architecture", ["x86_64", "aarch64"])
@pytest.mark.parametrize("profile", ["production", "debug"])
@pytest.mark.parametrize("explicit_target", [False, True])
def test_guest_build_stages_matching_helpers(tmp_path, architecture, profile, explicit_target):
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/build_guest_command.sh", scripts)
    log = tmp_path / "calls.jsonl"
    (scripts / "cargo_with_space.sh").write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "target = args[args.index('--target') + 1]\n"
        "name = 'safeyolo-coord' if '--bin' in args else 'safeyolo-guest'\n"
        "directory = 'release' if '--release' in args else 'debug'\n"
        "output = pathlib.Path(os.environ['CARGO_TARGET_DIR']) / target / directory / name\n"
        "output.parent.mkdir(parents=True, exist_ok=True)\n"
        "output.write_bytes(name.encode())\n"
        "keys = ('CC_' + target.replace('-', '_'), 'CARGO_TARGET_' + target.upper().replace('-', '_') + '_LINKER')\n"
        "with open(os.environ['BUILD_CALLS'], 'a') as stream:\n"
        "    stream.write(json.dumps({'args': args, 'environment': {key: os.environ.get(key) for key in keys}}) + '\\n')\n"
    )
    (scripts / "cargo_with_space.sh").chmod(0o755)
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "uname").write_text(f"#!/bin/sh\ncase $1 in -s) echo Linux;; -m) echo {architecture};; esac\n")
    (tools / "uname").chmod(0o755)
    target = f"{architecture}-unknown-linux-" + ("gnu" if explicit_target else "musl")
    environment = os.environ | {
        "PATH": f"{tools}:{os.environ['PATH']}",
        "SAFEYOLO_BUILD_PROFILE": profile,
        "SAFEYOLO_BUILD_REVISION": "a" * 40,
        "SAFEYOLO_GUEST_TARGET_DIR": str(tmp_path / "guest-target"),
        "CARGO_TARGET_DIR": str(tmp_path / "proxy-target"),
        "BUILD_CALLS": str(log),
    }
    environment.pop("SAFEYOLO_GUEST_TARGET", None)
    if explicit_target:
        environment["SAFEYOLO_GUEST_TARGET"] = target
    result = subprocess.run([str(scripts / "build_guest_command.sh")], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(calls) == 2
    for call in calls:
        assert call["args"][call["args"].index("--target") + 1] == target
        if not explicit_target:
            assert call["environment"]["CC_" + target.replace("-", "_")] == "musl-gcc"
            assert call["environment"]["CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER"] == "musl-gcc"
    directory = "release" if profile == "production" else "debug"
    output = tmp_path / "guest-target"
    if explicit_target:
        output /= target
    output /= directory
    assert result.stdout.splitlines() == [str(output / name) for name in ("safeyolo-guest", "safeyolo-coord")]
    for name in ("safeyolo-guest", "safeyolo-coord"):
        assert (output / name).read_bytes() == name.encode()
        assert (output / f"{name}.version").read_text() == f"{name} 0.1.0 commit={'a' * 40} profile={profile}\n"
        assert (output / f"{name}.sha256").read_text() == hashlib.sha256(name.encode()).hexdigest() + "\n"
