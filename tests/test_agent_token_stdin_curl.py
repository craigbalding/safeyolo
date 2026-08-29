"""Behavioural tests for the shipped Agent API curl authentication pattern."""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_CURL_SCRIPT = r"""
(
  agent_token=$(cat "$1") || exit
  printf 'Authorization: Bearer %s\n' "$agent_token" |
    curl -sS --header @- --max-time 5 "$2"
)
"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        self.server.authorization = self.headers.get("Authorization")  # type: ignore[attr-defined]
        self.server.request_seen.set()  # type: ignore[attr-defined]
        if not self.server.release_response.wait(5):  # type: ignore[attr-defined]
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, _format, *args):
        return


class _BlockingServer(ThreadingHTTPServer):
    authorization: str | None = None

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.request_seen = threading.Event()
        self.release_response = threading.Event()


def _process_tree_cmdlines(root_pid: int) -> dict[int, bytes]:
    """Return live Linux cmdlines for root_pid and all its descendants."""
    parents: dict[int, int] = {}
    for status_path in Path("/proc").glob("[0-9]*/status"):
        try:
            pid = int(status_path.parent.name)
            lines = status_path.read_text().splitlines()
            ppid = int(next(line for line in lines if line.startswith("PPid:")).split()[1])
        except (FileNotFoundError, PermissionError, StopIteration, ValueError):
            continue
        parents[pid] = ppid

    wanted = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, ppid in parents.items():
            if ppid in wanted and pid not in wanted:
                wanted.add(pid)
                changed = True

    cmdlines: dict[int, bytes] = {}
    for pid in wanted:
        try:
            cmdlines[pid] = (Path("/proc") / str(pid) / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError):
            continue
    return cmdlines


def _authenticated_request(token_path: Path, expected_token: str) -> None:
    server = _BlockingServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/health"
    proc = subprocess.Popen(
        ["sh", "-c", _CURL_SCRIPT, "sh", str(token_path), url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert server.request_seen.wait(5), "curl did not reach the test Agent API"
        cmdlines = _process_tree_cmdlines(proc.pid)
        assert any(b"curl" in cmdline for cmdline in cmdlines.values())
        assert expected_token.encode() not in b"\n".join(cmdlines.values())
        assert server.authorization == f"Bearer {expected_token}"
        server.release_response.set()
        stdout, stderr = proc.communicate(timeout=5)
        assert proc.returncode == 0, stderr
        assert stdout == "ok"
        assert expected_token not in stdout
        assert expected_token not in stderr
    finally:
        server.release_response.set()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(not Path("/proc").is_dir(), reason="requires Linux /proc")
def test_header_authenticates_reads_rotation_fresh_and_stays_out_of_cmdlines(tmp_path):
    if shutil.which("curl") is None:
        pytest.skip("curl is required")

    token_path = tmp_path / "agent_token"
    old_token = "argv-sentinel-old-395"
    new_token = "argv-sentinel-new-395"

    # Match the real token file, which is not required to end in a newline.
    token_path.write_text(old_token)
    _authenticated_request(token_path, old_token)

    token_path.write_text(new_token)
    _authenticated_request(token_path, new_token)


def test_curl_failure_does_not_print_or_persist_token(tmp_path):
    if shutil.which("curl") is None:
        pytest.skip("curl is required")

    token = "argv-sentinel-failure-395"
    token_path = tmp_path / "agent_token"
    token_path.write_text(token)

    # Port 1 is closed in the test environment, exercising curl's error path.
    result = subprocess.run(
        [
            "sh",
            "-c",
            _CURL_SCRIPT,
            "sh",
            str(token_path),
            "http://127.0.0.1:1/health",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        env=os.environ.copy(),
    )

    assert result.returncode != 0
    assert token not in result.stdout
    assert token not in result.stderr
    token_files = [
        path for path in tmp_path.rglob("*")
        if path.is_file() and token in path.read_text(errors="ignore")
    ]
    assert token_files == [token_path]
