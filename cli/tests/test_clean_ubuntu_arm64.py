"""Focused stock-image and owned-process checks; no external network or VM boot."""

import hashlib
import importlib.util
import io
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

spec = importlib.util.spec_from_file_location("clean_ubuntu", Path(__file__).resolve().parents[2]
    / "tests/blackbox/clean_ubuntu_arm64.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_diagnostic_guest_metadata_must_match_without_exporting_the_anonymous_token():
    raw = b'{"schemaVersion":2,"manifests":[]}'
    index = "sha256:" + hashlib.sha256(raw).hexdigest()
    replies = [io.BytesIO(b'{"token":"PRIVATE_ANONYMOUS_PULL_TOKEN"}'), io.BytesIO(raw)]
    with patch.object(m.urllib.request, "urlopen", autospec=True, side_effect=replies), \
            patch.object(m, "GUEST_INDEX", index):
        result = m.verify_diagnostic_guest()
    assert result["index"] == index
    assert "TOKEN" not in json.dumps(result)
    replies = [io.BytesIO(b'{"token":"PRIVATE_ANONYMOUS_PULL_TOKEN"}'), io.BytesIO(raw)]
    with patch.object(m.urllib.request, "urlopen", autospec=True, side_effect=replies):
        with pytest.raises(ValueError, match="No VM was started") as error:
            m.verify_diagnostic_guest()
    assert "TOKEN" not in str(error.value)


def test_stock_image_requires_both_pinned_size_and_hash(tmp_path):
    image = tmp_path / "ubuntu.img"
    image.write_bytes(b"verified stock disk")
    with patch.object(m, "IMAGE_BYTES", image.stat().st_size), patch.object(
            m, "IMAGE_SHA256", hashlib.sha256(image.read_bytes()).hexdigest()):
        m.verify_image(image)
        image.write_bytes(b"changed! stock disk")
        with pytest.raises(ValueError, match="size or SHA256"):
            m.verify_image(image)
        image.write_bytes(b"verified stock disk" + b"extra")
        with patch.object(m, "IMAGE_SHA256", hashlib.sha256(image.read_bytes()).hexdigest()), \
                pytest.raises(ValueError, match="size or SHA256"):
            m.verify_image(image)


def test_boot_receipt_keeps_reached_stages_and_failure_without_a_console_copy(tmp_path):
    console = tmp_path / "serial.log"
    console.write_bytes(b"Linux version 6.8.0-134-generic\r\n"
        b"\x1b[32mFinished apparmor.service - Load AppArmor profiles.\x1b[0m\r\n"
        b"Cloud-init running 'init-local'\nStarted systemd-networkd.service - Network Configuration.\n"
        b"FAILED to configure network\nJob systemd-networkd-wait-online.service/start running (2min)\n"
        b"unselected console output\n")
    result = m.boot_observation(console)
    assert result["stages"]["kernel"] == "Linux version 6.8.0-134-generic"
    assert result["stages"]["apparmor"].startswith("Finished apparmor.service")
    assert "cloud_init_local" in result["stages"]
    assert "network" in result["stages"]
    assert "wait-online" in result["stages"]["last_wait"]
    assert result["error_or_warning_lines"] == ["FAILED to configure network"]
    assert "unselected console output" not in json.dumps(result)
    assert "ssh" not in result["stages"]
    console.unlink()
    assert m.boot_observation(console)["available"] is False


def test_cleanup_reaps_only_the_owned_child_and_preserves_other_listener():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            assert not m.port_closed(port)
            result = m.stop_vm(child)
            assert result["reaped"]
            assert child.poll() is not None
            assert other.poll() is None
            assert not m.port_closed(port)
        assert m.port_closed(port)
        # A previously exited child is reaped without another signal.
        with patch.object(child, "terminate", autospec=True, side_effect=AssertionError("already exited")):
            assert m.stop_vm(child)["reaped"]
    finally:
        for process in [child, other]:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def test_cleanup_escalates_an_unresponsive_owned_child():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    original_wait = child.wait
    try:
        with patch.object(child, "terminate", autospec=True), patch.object(child, "wait", autospec=True, side_effect=lambda timeout:
                original_wait(timeout=0.05 if timeout == 30 else timeout)):
            result = m.stop_vm(child)
        assert result["reaped"]
        assert result["returncode"] == -9
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def test_existing_work_directory_is_preserved_before_acquisition(tmp_path):
    work = tmp_path / "existing"
    work.mkdir()
    marker = work / "operator-file"
    marker.write_text("keep")
    argv = ["clean_ubuntu_arm64.py", "--work-dir", str(work), "--observer-source", "test"]
    machine = os.uname_result(("Linux", "fixture", "6.8", "test", "aarch64"))
    with patch.object(sys, "argv", argv), patch.object(m.os, "uname", autospec=True, return_value=machine), \
            patch.object(m, "port_closed", autospec=True, return_value=True), \
            patch.object(subprocess, "run", autospec=True, side_effect=AssertionError("no external action")):
        with pytest.raises(FileExistsError):
            m.main()
    assert marker.read_text() == "keep"


@pytest.mark.parametrize("cold_seconds", [None, 1800])
@pytest.mark.parametrize("ssh_timeout", [False, True])
def test_main_propagates_cold_allowance_and_recovers_reached_result_after_ssh_timeout(tmp_path, cold_seconds, ssh_timeout):
    work = tmp_path / "vm"
    allowance = 900 if cold_seconds is None else cold_seconds
    observer_seconds = 1380 if cold_seconds is None else allowance + 900
    ssh_seconds = 1500 if cold_seconds is None else allowance + 1080
    recovery_seconds = 100 if cold_seconds is None else 180
    observed = {"cold_allowance_seconds": allowance, "execution_mode": "qemu-tcg", "observation_outcome": "partial"}

    def run(command, **kwargs):
        if command[0] == "ssh" and "timeout --signal=INT" in command[-1] and ssh_timeout:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        if command[0] == "ssh-keygen":
            (work / "ssh-key.pub").write_text("public-test-key")
        stdout = b""
        if command[:2] == ["qemu-img", "info"]:
            stdout = b'{"format":"qcow2"}'
        elif command[0] == "ssh" and command[-1] == "cat onboarding-observation/result.json":
            stdout = json.dumps(observed).encode()
        status = 37 if command[0] == "ssh" and "timeout --signal=INT" in command[-1] else 0
        return subprocess.CompletedProcess(command, status, stdout, b"")

    argv = [m.__file__, "--work-dir", str(work), "--observer-source", "test-source"]
    if cold_seconds is not None:
        argv += ["--cold-seconds", str(cold_seconds)]
    vm = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    machine = os.uname_result(("Linux", "fixture", "6.8", "test", "aarch64"))
    try:
        with patch.object(sys, "argv", argv), patch.object(m.os, "uname", autospec=True, return_value=machine), \
             patch.object(m, "port_closed", autospec=True, return_value=True), \
             patch.object(m, "verify_diagnostic_guest", autospec=True, return_value={}), \
             patch.object(m, "verify_image", autospec=True), patch.object(m.signal, "signal", autospec=True), \
             patch.object(m.subprocess, "Popen", autospec=True, return_value=vm), \
             patch.object(m.subprocess, "run", autospec=True, side_effect=run) as commands:
            assert m.main() == 1
        assert vm.poll() is not None
    finally:
        if vm.poll() is None:
            vm.kill()
        vm.wait(timeout=5)
    observer = [call for call in commands.call_args_list if call.args[0][0] == "ssh"
                and "timeout --signal=INT" in call.args[0][-1]]
    assert len(observer) == 1
    remote = shlex.split(observer[0].args[0][-1])
    assert remote[:4] == ["timeout", "--signal=INT", "--kill-after=120s", str(observer_seconds)]
    assert remote[remote.index("--cold-seconds") + 1] == str(allowance)
    assert remote[remote.index("--execution-mode") + 1] == "qemu-tcg"
    assert observer[0].kwargs["timeout"] == ssh_seconds
    recovery = [call for call in commands.call_args_list if "--cleanup-only" in call.args[0][-1]]
    assert len(recovery) == 1 and recovery[0].kwargs["timeout"] == recovery_seconds
    report = json.loads((work / "reports/fixture.json").read_text())
    assert report["cold_allowance_seconds"] == allowance
    assert report["execution_mode"] == "qemu-tcg"
    assert report["observer_timeout_seconds"] == observer_seconds
    assert report["ssh_timeout_seconds"] == ssh_seconds
    assert ("error" in report) == ssh_timeout
    assert report.get("observer_exit") == (None if ssh_timeout else 37)
    assert report["vm_cleanup"]["reaped"] and report["ssh_port_closed"]
    assert report["owned_disks_and_keys_removed"] and not (work / "ssh-key.pub").exists()
    assert json.loads((work / "reports/observation.json").read_text()) == observed


@pytest.mark.skipif(os.uname().machine != "aarch64", reason="the fixture executes only on native ARM64")
def test_sigterm_during_acquisition_removes_the_owned_partial_disk(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    curl = tools / "curl"
    curl.write_text(f"#!{sys.executable}\nimport pathlib, sys, time\n"
        'pathlib.Path(sys.argv[sys.argv.index("--output") + 1]).write_bytes(b"partial")\n'
        "time.sleep(120)\n")
    curl.chmod(0o755)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    work = tmp_path / "vm"
    marker = tmp_path / "unrelated"
    marker.write_text("keep")
    probe = ("import runpy\nfrom unittest.mock import patch\n"
             f"main=runpy.run_path({m.__file__!r})['main']\n"
             "with patch.dict(main.__globals__,verify_diagnostic_guest=lambda:{}):\n raise SystemExit(main())\n")
    process = subprocess.Popen([sys.executable, "-c", probe, "--work-dir", str(work),
        "--observer-source", "interruption-test", "--ssh-port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"]})
    try:
        deadline = time.monotonic() + 5
        while not (work / "ubuntu.img").exists() and time.monotonic() < deadline:
            assert process.poll() is None, process.communicate()
            time.sleep(0.02)
        assert (work / "ubuntu.img").exists()
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=10)
        result = json.loads((work / "reports/fixture.json").read_text())
        assert process.returncode != 0
        assert result["owned_disks_and_keys_removed"]
        assert result["ssh_port_closed"]
        assert not (work / "ubuntu.img").exists()
        assert marker.read_text() == "keep"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
