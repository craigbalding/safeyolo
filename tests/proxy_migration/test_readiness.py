"""A retained marker cannot establish readiness for a different proxy child."""

import json
import os
import socket
import sys

import pytest

from tests.proxy_migration.harness import child_process, wait_ready


def test_readiness_waits_for_this_child(tmp_path):
    marker = tmp_path / "ready.json"
    marker.write_text(json.dumps({"ready": True, "pid": 2147483647}))
    script = """
import json, os, sys, time
from pathlib import Path
time.sleep(0.2)
Path(sys.argv[1]).write_text(json.dumps({'ready': True, 'pid': os.getpid(), 'backend': 'python'}))
time.sleep(30)
"""
    with child_process([sys.executable, "-c", script, str(marker)], tmp_path, os.environ.copy()) as child:
        wait_ready(
            child,
            [marker],
            tmp_path / "process.log",
            readiness_file=marker,
            expected_backend="python",
        )
        assert json.loads(marker.read_text())["pid"] == child.pid


def _marker_child(marker):
    script = """
import json, os, sys, time
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({'ready': True, 'pid': os.getpid(), 'backend': sys.argv[2]}))
time.sleep(30)
"""
    return [sys.executable, "-c", script, str(marker)]


def test_readiness_rejects_wrong_backend_marker(tmp_path):
    marker = tmp_path / "ready.json"
    with child_process(_marker_child(marker) + ["rust-m2"], tmp_path, os.environ.copy()) as child:
        with pytest.raises(AssertionError, match="Readiness timed out"):
            wait_ready(
                child,
                [marker],
                tmp_path / "process.log",
                readiness_file=marker,
                expected_backend="python",
                timeout=0.2,
            )


def test_readiness_rejects_stale_regular_file_for_socket(tmp_path):
    marker = tmp_path / "ready.json"
    socket_path = tmp_path / "alice.sock"
    socket_path.write_text("stale proxy path")
    with child_process(_marker_child(marker) + ["python"], tmp_path, os.environ.copy()) as child:
        with pytest.raises(AssertionError, match="Readiness timed out"):
            wait_ready(
                child,
                [marker, socket_path],
                tmp_path / "process.log",
                readiness_file=marker,
                expected_backend="python",
                timeout=0.2,
            )


def test_readiness_rejects_nonaccepting_unix_socket(tmp_path):
    marker = tmp_path / "ready.json"
    socket_path = tmp_path / "alice.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    try:
        with child_process(_marker_child(marker) + ["python"], tmp_path, os.environ.copy()) as child:
            with pytest.raises(AssertionError, match="Readiness timed out"):
                wait_ready(
                    child,
                    [marker, socket_path],
                    tmp_path / "process.log",
                    readiness_file=marker,
                    expected_backend="python",
                    timeout=0.2,
                )
    finally:
        listener.close()
