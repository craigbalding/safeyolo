"""Focused controls for the unfinished Tart input producer; no Mac build runs."""

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.blackbox.hardware import build_inputs


def test_deadline_kills_and_reaps_the_owned_foreground_command(tmp_path):
    marker = tmp_path / "pid"
    command = [sys.executable, "-c",
               "import os,time; from pathlib import Path; "
               "Path(__import__('sys').argv[1]).write_text(str(os.getpid())); time.sleep(30)", str(marker)]
    with (tmp_path / "log").open("wb") as log:
        with pytest.raises(subprocess.TimeoutExpired):
            build_inputs.build_command(command, tmp_path, os.environ.copy(), log, time.monotonic() + 1)
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_expired_deadline_cannot_start_a_build(tmp_path):
    with pytest.raises(TimeoutError):
        build_inputs.build_command(["missing-command"], tmp_path, os.environ.copy(), io.BytesIO(), 0)


def test_real_command_failure_is_not_success(tmp_path):
    with (tmp_path / "log").open("wb") as log:
        with pytest.raises(subprocess.CalledProcessError) as failure:
            build_inputs.build_command([sys.executable, "-c", "raise SystemExit(7)"], tmp_path,
                                       os.environ.copy(), log, time.monotonic() + 5)
    assert failure.value.returncode == 7


def test_preparation_uses_isolated_helper_install_and_keeps_original_boot_identity(tmp_path, monkeypatch):
    checkout = tmp_path / "source"
    checkout.mkdir()
    boots = tmp_path / "boot"
    boots.mkdir()
    revision = "1" * 40
    origins = {}
    for name in build_inputs.BOOT_FILES:
        data = name.encode()
        (boots / name).write_bytes(data)
        origins[name] = {"source_revision": "2" * 40, "sha256": hashlib.sha256(data).hexdigest(),
                         "private_annotation": "do-not-copy"}
    provenance = tmp_path / "origins.json"
    provenance.write_text(json.dumps(origins))
    monkeypatch.setattr(build_inputs.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(build_inputs.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(build_inputs, "selected_source", lambda *args: None)
    output = tmp_path / "build"
    calls = []

    def command_fixture(command, source, env, log, deadline):
        calls.append((command, env))
        assert source == checkout and deadline > time.monotonic()
        if command[:2] == ["uv", "build"]:
            wheels = Path(command[-1])
            wheels.mkdir()
            (wheels / "safeyolo-fixture.whl").write_bytes(b"fixture")

    def package_fixture(source, selected, wheel, wheelhouse, prepared, origin_file, payload):
        assert source == checkout and selected == revision
        assert wheel.is_file() and wheelhouse.is_dir()
        assert all((prepared / "share" / name).read_bytes() == (boots / name).read_bytes()
                   for name in build_inputs.BOOT_FILES)
        assert json.loads(origin_file.read_text()) == {
            name: {key: origins[name][key] for key in ("source_revision", "sha256")}
            for name in build_inputs.BOOT_FILES
        }
        payload.mkdir()
        index = payload / "staged-inputs.json"
        index.write_text("{}")
        return index

    monkeypatch.setattr(build_inputs, "build_command", command_fixture)
    monkeypatch.setattr(build_inputs, "package_inputs", package_fixture)
    monkeypatch.setenv("GH_TOKEN", "fixture-private-token")
    monkeypatch.setenv("SAFEYOLO_BUILD_REVISION", "f" * 40)
    monkeypatch.setenv("HTTPS_PROXY", "http://fixture-proxy")
    index = build_inputs.build_payload(checkout, revision, boots, provenance, output, Path(sys.executable), 30)
    assert index == output / "payload/staged-inputs.json"
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert calls[0][0][-1] == "--prepare-only"
    assert sum(command[-1] == "--prepare-only" for command, _ in calls) == 1
    for _, env in calls:
        assert env["INSTALL_DIR"] == str(output / "prepared/bin")
        assert env["HTTPS_PROXY"] == "http://fixture-proxy"
        assert "GH_TOKEN" not in env and "SAFEYOLO_BUILD_REVISION" not in env
    downloads = [command for command, _ in calls if "download" in command]
    assert len(downloads) == 2 and all("--require-hashes" in command for command in downloads)
    assert "do-not-copy" not in (output / "boot-provenance.json").read_text()
    with pytest.raises(FileExistsError):
        build_inputs.build_payload(checkout, revision, boots, provenance, output, Path(sys.executable), 30)
    assert index.read_text() == "{}" and len(calls) == 6
