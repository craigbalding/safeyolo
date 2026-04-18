"""
proxy_protocol.py — Port-based agent identity for bridge connections.

The proxy_bridge binds to a deterministic source port (PORT_BASE +
agent_index) before connecting to mitmproxy. This addon's
client_connected hook maps the source port back to the agent name
via agent_map.json, then overwrites client.peername with the agent's
attribution IP so service_discovery and all downstream addons work
unchanged.

No lo0 alias, no sudo, no PROXY protocol framing. Just bind() to
127.0.0.1:<known_port> — which always works because 127.0.0.1 is
always configured.
"""

import json
import logging
import time
from pathlib import Path
from threading import Lock

from mitmproxy import connection, ctx

log = logging.getLogger("safeyolo.proxy-protocol")

# Deterministic port range for bridge connections.
# Agent index 0 → port 30002, index 1 → 30003, etc.
# Matches the offset in proxy_bridge._handle_client's bind().
PORT_BASE = 30000


class PortIdentityAddon:
    """Map bridge source ports to agent identity at connection time."""

    name = "port-identity"

    def __init__(self):
        self._port_to_agent: dict[int, dict] = {}
        self._map_mtime: float = 0
        self._map_path: str = ""
        self._lock = Lock()

    def load(self, loader):
        loader.add_option(
            name="port_identity_map",
            typespec=str,
            default="",
            help="Path to agent_map.json (same file as service_discovery uses)",
        )

    def configure(self, updates):
        if "port_identity_map" in updates:
            self._map_path = ctx.options.port_identity_map
        if not self._map_path:
            # Fall back to agent_map_file (service_discovery's option)
            try:
                self._map_path = ctx.options.agent_map_file
            except AttributeError:
                pass
        if self._map_path:
            self._reload()

    def _reload(self):
        if not self._map_path:
            return
        path = Path(self._map_path)
        if not path.exists():
            return
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return
        if mtime == self._map_mtime:
            return
        try:
            data = json.loads(path.read_text())
            port_map: dict[int, dict] = {}
            for name, info in data.items():
                ip = info.get("ip", "")
                port = info.get("port")
                if port is not None:
                    port_map[int(port)] = {"name": name, "ip": ip}
            with self._lock:
                self._port_to_agent = port_map
                self._map_mtime = mtime
        except (json.JSONDecodeError, OSError, ValueError) as e:
            log.warning("port-identity: failed to load map: %s", e)

    def client_connected(self, client: connection.Client):
        """Rewrite peername if the source port matches a known agent."""
        if not client.peername:
            return
        src_port = client.peername[1]
        self._reload()
        with self._lock:
            entry = self._port_to_agent.get(src_port)
        if entry:
            ip = entry.get("ip", client.peername[0])
            client.peername = (ip, src_port)
            log.info("port-identity: port=%d -> agent=%s ip=%s",
                     src_port, entry["name"], ip)


addons = [PortIdentityAddon()]
