"""Real watch commands distinguish failed attachments, recovery and new gaps.

The stream-failure control uses an owned HTTP/WebSocket peer. The gap control
uses the installed native proxy and its actual audit reader. No guest starts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import select
import socket
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from websockets.sync.client import connect

from tests.proxy_contracts.test_native_coord_operator import terminal
from tests.proxy_contracts.test_native_policy_cli import native_inputs, native_instance


def wait_for(condition):
    deadline = time.monotonic() + 8
    while not condition():
        assert time.monotonic() < deadline, "watch did not retry or refresh canonical state"
        time.sleep(0.02)


class StreamFailures(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        peer = self.server
        if self.path != "/admin/events":
            kind = "signals" if self.path.startswith("/admin/coord/signals?") else "approvals"
            assert self.path.startswith("/admin/coord/signals?") or self.path == "/admin/approvals"
            peer.reads[kind] += 1
            body = json.dumps({"items": [], "next_after": None} if kind == "signals" else {"approvals": []}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        peer.attachments += 1
        accept = base64.b64encode(hashlib.sha1(
            (self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(),
        ).digest()).decode()
        self.send_response(101)
        self.send_header("Connection", "Upgrade")
        self.send_header("Upgrade", "websocket")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        try:
            if peer.mode == "interrupt":
                self.wfile.write(b"\x88\x00")
                return
            self.event({"type": "operator_state", "log": "following"})
            while True:
                action = peer.actions.get(timeout=10)
                if action == "close":
                    self.wfile.write(b"\x88\x00")
                    break
                self.event(action)
        except (OSError, queue.Empty):
            pass
        finally:
            self.close_connection = True

    def event(self, value):
        event = json.dumps(value).encode()
        length = bytes([len(event)]) if len(event) < 126 else b"\x7e" + struct.pack("!H", len(event))
        self.wfile.write(b"\x81" + length + event)
        self.wfile.flush()


@pytest.mark.parametrize("interactive", [True, False])
def test_watch_reports_stream_failure_episodes_and_keeps_retrying(tmp_path, interactive):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    root = tmp_path / "watch"
    (root / "bin").mkdir(parents=True)
    (root / "bin/safeyolo").symlink_to(native_inputs()[0] / "safeyolo")
    (root / "admin-token").write_text("synthetic-watch-token")
    (root / "config.toml").write_text(f'admin_port={port}\nadmin_api_token_file="admin-token"\n')
    peer = ThreadingHTTPServer(("127.0.0.1", port), StreamFailures, bind_and_activate=False)
    peer.mode = "interrupt"
    peer.attachments = 0
    peer.reads = {"signals": 0, "approvals": 0}
    peer.actions = queue.Queue()
    started = False

    def exercise(until, process):
        nonlocal started
        # The selected port has no listener, matching a stopped proxy.
        output = until(b"Operator stream unavailable;")
        time.sleep(2.2)
        peer.server_bind()
        peer.server_activate()
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        started = True
        output += until(b"Operator stream interrupted;")
        wait_for(lambda: peer.attachments >= 3 and peer.reads["approvals"] >= 3)
        peer.mode = "live"
        output += until(b"Operator stream recovered;")
        assert output.count(b"Operator stream unavailable;") == 1, output
        assert output.count(b"Operator stream interrupted;") == 1, output
        assert output.count(b"Operator stream recovered;") == 1, output
        assert peer.reads["signals"] >= 3, peer.reads
        # The same interruption is visible again after actual recovery.
        peer.mode = "interrupt"
        peer.actions.put("close")
        repeated = until(b"Operator stream interrupted;")
        before = peer.attachments
        wait_for(lambda: peer.attachments >= before + 2)
        peer.mode = "live"
        repeated += until(b"Operator stream recovered;")
        assert repeated.count(b"Operator stream interrupted;") == 1, repeated
        assert repeated.count(b"Operator stream recovered;") == 1, repeated
        # Repeated state controls retain log status and the last gap. Neither
        # is a new notice, but a distinct same-reason gap must remain visible.
        state = {"type": "operator_state", "log": "unavailable", "history_gap": "invalid record", "history_gap_id": "one"}
        for value in [state, state, {**state, "history_gap_id": "two"},
                      {**state, "history_gap_id": "two", "log": "following"}]:
            peer.actions.put(value)
        notices = until(b"Recorded event feed recovered;")
        assert notices.count(b"Recorded event feed unavailable;") == 1, notices
        assert notices.count(b"Recorded event history gap:") == 2, notices
        assert notices.count(b"Recorded event feed recovered;") == 1, notices
        for value in [{**state, "history_gap_id": "two"},
                      {**state, "history_gap_id": "two", "log": "following"}]:
            peer.actions.put(value)
        notices = until(b"Recorded event feed recovered;")
        assert notices.count(b"Recorded event feed unavailable;") == 1, notices
        assert b"Recorded event history gap:" not in notices, notices
        assert process.poll() is None

    try:
        if interactive:
            instance = SimpleNamespace(root=root, environment={**os.environ, "TERM": "xterm-256color"})
            with terminal(instance, ["watch", "--no-color"]) as (process, fd, until):
                exercise(until, process)
                os.write(fd, b"q\n")
                assert process.wait(timeout=5) == 0
        else:
            process = subprocess.Popen([str(root / "bin/safeyolo"), "--instance-dir", str(root), "watch", "--json"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            captured = bytearray()

            def until(marker):
                deadline = time.monotonic() + 8
                while marker not in captured:
                    assert time.monotonic() < deadline, bytes(captured)
                    assert process.poll() is None, bytes(captured)
                    if select.select([process.stderr], [], [], 0.1)[0]:
                        captured.extend(os.read(process.stderr.fileno(), 65536))
                result = bytes(captured)
                captured.clear()
                return result

            try:
                exercise(until, process)
            finally:
                process.terminate()
                stdout, _ = process.communicate(timeout=5)
            assert stdout == b"", "stream notices must not enter JSON stdout"
    finally:
        peer.actions.put("close")
        if started:
            peer.shutdown()
        peer.server_close()


def test_native_feed_distinguishes_new_gaps_with_the_same_reason(tmp_path):
    with native_instance(tmp_path) as instance:
        with connect(f"ws://127.0.0.1:{instance.port}/admin/events",
                     additional_headers={"Authorization": f"Bearer {instance.token}"}, proxy=None) as events:
            def gap(previous=None):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    state = json.loads(events.recv(timeout=max(0.01, deadline - time.monotonic())))
                    if state.get("history_gap_id") and state["history_gap_id"] != previous:
                        return state
                pytest.fail("native audit reader did not report the new gap")

            audit = instance.root / "logs/audit.jsonl"
            with audit.open("a") as output:
                output.write("invalid first audit record\n")
            first = gap()
            # A fresh subscriber sees the retained observation, not a new gap.
            with connect(f"ws://127.0.0.1:{instance.port}/admin/events",
                         additional_headers={"Authorization": f"Bearer {instance.token}"}, proxy=None) as other:
                retained = json.loads(other.recv(timeout=5))
                assert retained["history_gap_id"] == first["history_gap_id"]
            with audit.open("a") as output:
                output.write("invalid second audit record\n")
            second = gap(first["history_gap_id"])
            assert second["history_gap"] == first["history_gap"]
            assert second["history_gap_id"] != first["history_gap_id"]
