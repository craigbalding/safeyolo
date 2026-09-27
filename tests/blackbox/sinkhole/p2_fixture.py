"""Finite owned HTTP, SSE, and WebSocket endpoints for installed P2 guests."""

from __future__ import annotations

import base64
import hashlib
import re
import ssl
import threading
from pathlib import Path
from urllib.parse import urlsplit

from tests.proxy_migration.websocket_peer import Peer

MARKER = re.compile(r"p2-[0-9a-f]{32}\Z")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PACKAGE_PATH = "/p2/package/safeyolo-p2-fixture.deb"
REPO_PREFIX = "/p2/repo.git/"


class P2Fixture:
    def __init__(self, directory: Path):
        self.directory = directory.resolve()
        self.lock = threading.Lock()
        self.streams: dict[str, dict] = {}
        self.websockets: list[dict] = []

    def state(self, marker: str) -> dict:
        with self.lock:
            stream = self.streams.get(marker)
            return {
                "first_sent": bool(stream and stream["first_sent"]),
                "released": bool(stream and stream["release"].is_set()),
                "finished": bool(stream and stream["finished"]),
                "websockets": [entry.copy() for entry in self.websockets if entry["marker"] == marker],
            }

    def release(self, marker: str) -> bool:
        with self.lock:
            stream = self.streams.get(marker)
            if stream is None:
                return False
            stream["release"].set()
            return True

    @staticmethod
    def _body(handler, body: bytes, content_type: str = "application/octet-stream") -> None:
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)

    def handle(self, handler) -> bool:
        path = urlsplit(handler.path).path
        if path == PACKAGE_PATH:
            package = self.directory / "safeyolo-p2-fixture.deb"
            if not package.is_file():
                handler.send_error(404, "P2 package is unavailable")
            else:
                self._body(handler, package.read_bytes())
            return True
        if path.startswith(REPO_PREFIX):
            if handler.command not in {"GET", "HEAD"}:
                handler.send_error(405, "P2 repository is read only")
                return True
            repo = self.directory / "repo.git"
            file = (repo / path.removeprefix(REPO_PREFIX)).resolve()
            if not file.is_relative_to(repo.resolve()) or not file.is_file():
                handler.send_error(404, "P2 repository path is unavailable")
            else:
                self._body(handler, file.read_bytes())
            return True
        if path.startswith("/p2/sse/"):
            marker = path.removeprefix("/p2/sse/")
            if not MARKER.fullmatch(marker):
                handler.send_error(400, "Invalid P2 marker")
            else:
                self._sse(handler, marker)
            return True
        if path.startswith("/p2/ws/"):
            marker = path.removeprefix("/p2/ws/")
            if not MARKER.fullmatch(marker):
                handler.send_error(400, "Invalid P2 marker")
            else:
                self._websocket(handler, marker)
            return True
        return False

    def _sse(self, handler, marker: str) -> None:
        stream = {"release": threading.Event(), "first_sent": False, "finished": False}
        with self.lock:
            if marker in self.streams:
                handler.send_error(409, "P2 stream marker already used")
                return
            self.streams[marker] = stream
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            handler.wfile.write(f"data: first:{marker}\n\n".encode())
            handler.wfile.flush()
            with self.lock:
                stream["first_sent"] = True
            if stream["release"].wait(15):
                handler.wfile.write(f"data: last:{marker}\n\n".encode())
                handler.wfile.flush()
        finally:
            with self.lock:
                stream["finished"] = True

    def _websocket(self, handler, marker: str) -> None:
        key = handler.headers.get("Sec-WebSocket-Key", "")
        if (handler.headers.get("Upgrade", "").lower() != "websocket"
                or handler.headers.get("Sec-WebSocket-Version") != "13"):
            handler.send_error(400, "P2 WebSocket handshake required")
            return
        try:
            if len(base64.b64decode(key, validate=True)) != 16:
                raise ValueError("invalid key length")
        except ValueError:
            handler.send_error(400, "Invalid P2 WebSocket key")
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        handler.send_response(101, "Switching Protocols")
        handler.send_header("Upgrade", "websocket")
        handler.send_header("Connection", "Upgrade")
        handler.send_header("Sec-WebSocket-Accept", accept)
        handler.end_headers()
        peer = Peer(handler.connection, client=False, compressed=False)
        observation = {"marker": marker, "tls": isinstance(handler.connection, ssl.SSLSocket)}
        try:
            opcode, payload = peer.receive()
            observation["client"] = payload.decode() if opcode == 1 else None
            if (opcode, payload) != (1, f"client:{marker}".encode()):
                raise ValueError("P2 WebSocket client marker differs")
            peer.send(1, f"server:{marker}".encode())
            close_opcode, _ = peer.receive()
            if close_opcode != 8:
                raise ValueError("P2 WebSocket client did not close")
            peer.close()
            observation["status"] = "complete"
        except (OSError, EOFError, UnicodeDecodeError, ValueError) as error:
            observation["status"] = f"failed: {error}"
        finally:
            with self.lock:
                self.websockets.append(observation)
