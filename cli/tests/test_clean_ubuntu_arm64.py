"""Focused stock-image and owned-process checks; no external network or VM boot."""

import hashlib
import importlib.util
import json
import os
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
    process = subprocess.Popen([sys.executable, str(Path(m.__file__)), "--work-dir", str(work),
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
