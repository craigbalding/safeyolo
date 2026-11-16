"""Check retained-result and owned-cleanup decisions without starting a VM."""

import hashlib
import json
import os
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from experiments.rootless_guest import macos_runtime_probe as probe


def test_failed_and_cancelled_preparations_preserve_external_target(tmp_path):
    """Exercise real extraction/cleanup; native live-VM use remains separate."""
    commands = tmp_path / "commands"
    commands.mkdir()
    for name in ("tar", "zstd", "rm"):
        (commands / name).symlink_to(shutil.which(name))
    observed = probe.preserve_during_runtime(tmp_path, dict(os.environ, PATH=str(commands)))
    assert len(observed["attempts"]) == 2
    for row in observed["attempts"]:
        assert row["exit"] != 0 and row["external_preserved"] and row["stage_removed"]
        assert row["preparation"]["result"] == "failed/cancelled; private stage removed"
    assert "Expected regular backend file: Image" in observed["attempts"][0]["stderr"]
    assert "Requested cancellation after child completion" in observed["attempts"][1]["stderr"]
    assert json.loads((tmp_path / "preservation.json").read_text()) == observed


@pytest.mark.parametrize("case", ["success", "early-exit", "stop-error", "inspection-error", "foreign", "survivor"])
def test_runtime_result_survives_cleanup_and_only_owned_births_fail(tmp_path, monkeypatch, case):
    install = tmp_path / "installed"
    assets = install / "assets/guest"
    assets.mkdir(parents=True)
    (install / "bin").mkdir()
    (install / "bin/safeyolo-vm").write_text("controlled helper\n")
    (install / "package-info").write_text(f"source_commit={probe.SOURCE}\n")
    for name in ("guest-init", "guest-init-static", "guest-init-per-run", "safeyolo-guest",
                 "guest-proxy-forwarder", "guest-shell-bridge", "guest-sudo", "guest-desktop"):
        (assets / name).write_text("controlled asset\n")
    wrapper = tmp_path / "wrapper"
    wrapper.write_text("controlled wrapper\n")
    prepared = tmp_path / "prepared"
    baseline = tmp_path / "baseline"
    for directory in (prepared, baseline):
        directory.mkdir()
        for name in probe.IMAGES:
            (directory / name).write_bytes(b"controlled image")
    monkeypatch.setattr(probe, "INSTALL", install)
    monkeypatch.setattr(probe, "PREPARED", prepared)
    monkeypatch.setattr(probe, "BASELINE", baseline)
    monkeypatch.setattr(probe, "WRAPPER", wrapper)
    monkeypatch.setattr(probe, "IMAGES", dict.fromkeys(probe.IMAGES, hashlib.sha256(b"controlled image").hexdigest()))
    monkeypatch.setattr(probe.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(probe.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(probe.os, "getuid", lambda: 502)
    monkeypatch.setattr(probe.shutil, "disk_usage", lambda path: SimpleNamespace(free=30 * 1024**3))
    monkeypatch.setattr(probe, "process_start_token", lambda pid: f"birth:{pid}")
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "ok", ""))
    output = tmp_path / "run"

    class Runner:
        pid = 123
        returncode = 7 if case == "early-exit" else None

        def __init__(self, *args, **kwargs):
            if case != "early-exit":
                (output / "status/probe.done").write_text("0\n")

        def poll(self):
            return self.returncode

        def terminate(self):
            if case == "stop-error":
                raise PermissionError("controlled stop denial")
            self.returncode = 143

        def wait(self, timeout):
            return self.returncode

    reads = 0

    def processes():
        nonlocal reads
        reads += 1
        if reads == 1:
            return []
        if case == "inspection-error":
            raise OSError("controlled inspection failure")
        if case in ("foreign", "survivor"):
            pid = 456 if case == "foreign" else Runner.pid
            return [{"pid": pid, "birth": f"birth:{pid}", "argv": ["controlled VM"]}]
        return []

    monkeypatch.setattr(probe.subprocess, "Popen", Runner)
    monkeypatch.setattr(probe, "vm_processes", processes)
    if case in ("success", "foreign"):
        probe.main(output)
    else:
        with pytest.raises(RuntimeError):
            probe.main(output)
    result = json.loads((output / "result.json").read_text())
    if case == "early-exit":
        assert result["early_wrapper_exit"] == 7
        assert result["result"] == "incomplete"
    else:
        assert result["guest_probe_exit"] == "0"
        assert result["result"].startswith("published preparation reached")
    if case == "stop-error":
        assert "controlled stop denial" in result["cleanup_error"]
    elif case == "inspection-error":
        assert "controlled inspection failure" in result["cleanup_inspection_error"]
    else:
        assert bool(result["owned_survivors"]) == (case == "survivor")
