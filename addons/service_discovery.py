"""
service_discovery.py - Agent discovery via file-based IP map

Maps VM IPs to agent names for per-agent credential policies.
The CLI writes agent_map.json when VMs start/stop. This addon
reads the file (mtime-cached) to resolve IPs to agent names.
"""

import json
import logging
import os
import time
from pathlib import Path
from threading import Lock

from mitmproxy import ctx, http
from utils import get_client_ip, sanitize_for_log, write_event

from audit_schema import EventKind, Severity

log = logging.getLogger("safeyolo.discovery")


class ServiceDiscovery:
    """
    Agent registry via file-based IP map.

    The CLI writes ~/.safeyolo/data/agent_map.json with entries like:
        {"test": {"ip": "192.168.68.2", "started": "2026-04-06T..."}}

    This addon reads the file on each request (mtime-cached) and
    resolves client IPs to agent names.
    """

    name = "service-discovery"

    def __init__(self):
        self._agent_map: dict[str, dict] = {}  # name -> {ip, started}
        self._ip_to_name: dict[str, str] = {}  # ip -> name (reverse index)
        self._map_mtime: float = 0
        self._map_path: str = ""
        self._last_seen: dict[str, float] = {}  # agent_name -> epoch
        self._lock = Lock()

    def load(self, loader):
        loader.add_option(
            name="agent_map_file",
            typespec=str,
            default="",
            help="Path to agent IP map JSON file (written by CLI)",
        )

    def configure(self, updates):
        if "agent_map_file" in updates:
            self._map_path = ctx.options.agent_map_file
            if self._map_path:
                self._reload_map()

    def _reload_map(self):
        """Reload agent map if file has changed (mtime check)."""
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
            ip_to_name = {}
            for name, info in data.items():
                ip = info.get("ip")
                if ip:
                    ip_to_name[ip] = name

            with self._lock:
                old_names = set(self._ip_to_name.values())
                self._agent_map = data
                self._ip_to_name = ip_to_name
                self._map_mtime = mtime

                # Log newly discovered agents
                new_names = set(ip_to_name.values()) - old_names
                for name in new_names:
                    ip = next(k for k, v in ip_to_name.items() if v == name)
                    log.info("Agent discovered: %s at %s", name, ip)
                    write_event(
                        "agent.discovered",
                        kind=EventKind.AGENT,
                        severity=Severity.LOW,
                        summary=f"Discovered agent {sanitize_for_log(name)} at {ip}",
                        agent=name,
                        addon="service-discovery",
                        details={"ip": ip},
                    )
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Failed to load agent map: %s", e)

    def get_client_for_ip(self, ip: str) -> str:
        """Get agent name for an IP address. Thread-safe."""
        self._reload_map()

        with self._lock:
            name = self._ip_to_name.get(ip)

        if name:
            return name

        return "unknown"

    def request(self, flow: http.HTTPFlow):
        """Stamp agent identity on every flow for downstream addons/loggers."""
        client_ip = get_client_ip(flow)
        if client_ip != "unknown":
            agent = self.get_client_for_ip(client_ip)
            flow.metadata["agent"] = agent
            if agent != "unknown":
                with self._lock:
                    self._last_seen[agent] = time.time()

    def get_agents(self) -> dict:
        """Get agent overview for agent API /agents endpoint."""
        now = time.time()
        self._reload_map()

        with self._lock:
            agents: dict[str, dict] = {}
            for name, info in self._agent_map.items():
                entry = {"ip": info.get("ip")}
                if name in self._last_seen:
                    entry["last_seen"] = self._last_seen[name]
                    entry["idle_seconds"] = round(now - self._last_seen[name], 1)
                agents[name] = entry

        return {
            "agents": agents,
            "count": len(agents),
        }

    def get_stats(self) -> dict:
        """Get discovery statistics for admin API."""
        agents_data = self.get_agents()
        with self._lock:
            ip_count = len(self._ip_to_name)

        return {
            "map_file": self._map_path,
            "known_ips": ip_count,
            "agents": agents_data["agents"],
            "agents_seen": agents_data["count"],
        }


# Module-level singleton
_discovery: ServiceDiscovery | None = None


def get_service_discovery() -> ServiceDiscovery | None:
    return _discovery


discovery = ServiceDiscovery()
_discovery = discovery
addons = [discovery]
