"""Unix Domain Socket utilities for SafeYolo."""

import json
import select
import socket
import threading
import tomllib
from pathlib import Path

from rich.console import Console

from .config import find_uds_config

console = Console()


def _load_uds_config() -> dict:
    """Load UDS configuration from uds.toml.

    Priority (highest to lowest):
    1. ~/.safeyolo/uds.toml (user override)
    2. cli/src/safeyolo/uds.toml (package default)
    3. Hardcoded fallback (if neither exists)
    """
    defaults = {
        "sockets": {
            "dir": "/tmp",
            "watch_id": "watch-unnamed",
            "tele_id": "tele-unnamed",
        }
    }

    # Check user config first (via centralized helper)
    user_config = find_uds_config()
    if user_config:
        return tomllib.loads(user_config.read_text())

    # Fall back to package default
    package_default = Path(__file__).parent / "uds.toml"
    if package_default.exists():
        return tomllib.loads(package_default.read_text())

    return defaults


def get_socket_path(service_id: str) -> Path:
    """Get socket path for a service (watch_id, tele_id, etc.).

    Args:
        service_id: The config key from [sockets] section (e.g., "watch_id")

    Returns:
        Path in format: {dir}/safeyolo_{id}.sock
    """
    config = _load_uds_config()
    sockets = config.get("sockets", {})
    base_dir = sockets.get("dir", "/tmp").rstrip("/")
    socket_id = sockets.get(service_id, f"{service_id.replace('_id', '')}-unnamed")
    return Path(f"{base_dir}/safeyolo_{socket_id}.sock")


class UDSServer:
    """Unix Domain Socket server for broadcasting JSONL events."""

    def __init__(self, socket_path: Path):
        self.socket_path = socket_path
        self._clients: list[socket.socket] = []
        self._lock = threading.Lock()
        self._server_socket: socket.socket | None = None
        self._running = False
        self._accept_thread: threading.Thread | None = None

    def start(self) -> bool:
        """Start the UDS server. Returns True if successful."""
        try:
            if self.socket_path.exists():
                self.socket_path.unlink()

            self.socket_path.parent.mkdir(parents=True, exist_ok=True)

            self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            self._server_socket.bind(str(self.socket_path))
            self._server_socket.listen(5)
            self._running = True

            self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._accept_thread.start()

            return True
        except Exception as e:
            console.print(f"[red]Failed to start socket server: {e}[/red]")
            return False

    def stop(self):
        """Stop the server and clean up."""
        self._running = False

        with self._lock:
            for client in self._clients:
                try:
                    client.close()
                except Exception:
                    pass
            self._clients.clear()

        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception:
                pass

    def broadcast(self, event: dict):
        """Broadcast an event to all connected clients."""
        if not self._running:
            return

        message = json.dumps(event) + "\n"
        data = message.encode("utf-8")

        with self._lock:
            dead_clients = []
            for client in self._clients:
                try:
                    client.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    dead_clients.append(client)

            for client in dead_clients:
                try:
                    client.close()
                except Exception:
                    pass
                self._clients.remove(client)

    def client_count(self) -> int:
        """Return number of connected clients."""
        with self._lock:
            return len(self._clients)

    def _accept_loop(self):
        """Accept new connections in a loop."""
        while self._running and self._server_socket:
            try:
                ready, _, _ = select.select([self._server_socket], [], [], 1.0)
                if ready:
                    client, _ = self._server_socket.accept()
                    client.setblocking(False)
                    with self._lock:
                        self._clients.append(client)
            except OSError:
                break
