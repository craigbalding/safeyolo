"""Focused stock-image and owned-process checks; no external network or VM boot."""

import hashlib
import importlib.util
import socket
import subprocess
import sys
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
    with patch.object(sys, "argv", argv), patch.object(m, "port_closed", autospec=True, return_value=True), \
            patch.object(subprocess, "run", autospec=True, side_effect=AssertionError("no external action")):
        with pytest.raises(FileExistsError):
            m.main()
    assert marker.read_text() == "keep"
