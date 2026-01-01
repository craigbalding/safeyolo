"""
service_discovery.py - Native mitmproxy addon for Docker service discovery

Auto-discovers project containers via Docker API and makes them available
for routing/forwarding decisions.

Usage:
    mitmdump -s addons/service_discovery.py

Requires:
    - Docker socket mounted: -v /var/run/docker.sock:/var/run/docker.sock:ro
    - pip install aiodocker (async Docker client)

Features:
    - Discovers containers in same compose project
    - Extracts exposed ports and internal IPs
    - Refreshes on configurable interval
    - Admin API endpoints for status/refresh
"""

import asyncio
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from mitmproxy import ctx, http

log = logging.getLogger("safeyolo.service-discovery")

# Try to import aiodocker
try:
    import aiodocker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    aiodocker = None


@dataclass
class DiscoveredService:
    """A discovered service from Docker."""
    container_name: str
    container_id: str
    internal_ip: str
    ports: list[int]
    labels: dict[str, str]
    network: str
    discovered_at: float


class ServiceDiscovery:
    """
    Native mitmproxy addon for Docker service discovery.

    Discovers project containers and their network details.
    Other addons can use this for routing decisions.
    """

    name = "service-discovery"

    def __init__(self):
        self._services: dict[str, DiscoveredService] = {}  # container_name -> service
        self._port_map: dict[int, str] = {}  # port -> container_name
        self._lock = threading.RLock()

        self.network: str = "safeyolo-internal"
        self.skip_containers: list[str] = []
        self.refresh_interval: int = 30
        self.last_refresh: float = 0

        # Background refresh
        self._refresh_thread: Optional[threading.Thread] = None
        self._refresh_stop = threading.Event()

        # Stats
        self.discoveries_total = 0
        self.services_found = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="discovery_enabled",
            typespec=bool,
            default=True,
            help="Enable service discovery",
        )
        loader.add_option(
            name="discovery_network",
            typespec=str,
            default="safeyolo-internal",
            help="Docker network to discover containers on",
        )
        loader.add_option(
            name="discovery_skip_containers",
            typespec=str,
            default="safeyolo,claude-code",
            help="Comma-separated container names to skip",
        )
        loader.add_option(
            name="discovery_refresh_interval",
            typespec=int,
            default=30,
            help="Seconds between discovery refreshes",
        )

    def configure(self, updates):
        """Handle option changes."""
        if not DOCKER_AVAILABLE:
            log.warning("aiodocker not installed - service discovery disabled")
            return

        if "discovery_network" in updates:
            self.network = ctx.options.discovery_network

        if "discovery_skip_containers" in updates:
            self.skip_containers = [
                s.strip() for s in ctx.options.discovery_skip_containers.split(",")
                if s.strip()
            ]

        if "discovery_refresh_interval" in updates:
            self.refresh_interval = ctx.options.discovery_refresh_interval

        # Start background refresh if enabled
        if ctx.options.discovery_enabled and self._refresh_thread is None:
            self._start_refresh_thread()

    def _start_refresh_thread(self):
        """Start background refresh thread."""
        def refresh_loop():
            # Initial discovery
            self._do_refresh()

            while not self._refresh_stop.is_set():
                self._refresh_stop.wait(timeout=self.refresh_interval)
                if not self._refresh_stop.is_set():
                    self._do_refresh()

        self._refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self._refresh_thread.start()
        log.info(f"Service discovery started (network: {self.network})")

    def _do_refresh(self):
        """Perform service discovery (runs in background thread)."""
        try:
            # Run async discovery in new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                services = loop.run_until_complete(self._discover_services())
            finally:
                loop.close()

            with self._lock:
                self._services = services
                self._port_map = {}
                for name, svc in services.items():
                    for port in svc.ports:
                        self._port_map[port] = name

                self.discoveries_total += 1
                self.services_found = len(services)
                self.last_refresh = time.time()

            if services:
                log.info(f"Discovered {len(services)} services: {list(services.keys())}")

        except Exception as e:
            log.error(f"Service discovery failed: {type(e).__name__}: {e}")

    async def _discover_services(self) -> dict[str, DiscoveredService]:
        """Discover services via Docker API."""
        if not DOCKER_AVAILABLE:
            return {}

        services = {}

        try:
            docker = aiodocker.Docker()

            # List containers on the internal network
            containers = await docker.containers.list(
                filters={"network": [self.network]}
            )

            for container in containers:
                info = await container.show()
                name = info["Name"].lstrip("/")

                # Skip specified containers
                if any(skip in name for skip in self.skip_containers):
                    continue

                # Get network settings
                networks = info.get("NetworkSettings", {}).get("Networks", {})

                # Find IP on internal network (prefer) or any network
                internal_ip = None
                network_name = None

                for net_name, net_info in networks.items():
                    if "internal" in net_name.lower():
                        internal_ip = net_info.get("IPAddress")
                        network_name = net_name
                        break

                if not internal_ip:
                    for net_name, net_info in networks.items():
                        if net_info.get("IPAddress"):
                            internal_ip = net_info["IPAddress"]
                            network_name = net_name
                            break

                if not internal_ip:
                    continue

                # Get exposed ports
                exposed = info.get("Config", {}).get("ExposedPorts", {})
                ports = []
                for port_spec in exposed.keys():
                    port = int(port_spec.split("/")[0])
                    ports.append(port)

                # Get labels
                labels = info.get("Config", {}).get("Labels", {})

                services[name] = DiscoveredService(
                    container_name=name,
                    container_id=info["Id"][:12],
                    internal_ip=internal_ip,
                    ports=ports,
                    labels=labels,
                    network=network_name or "",
                    discovered_at=time.time(),
                )

            await docker.close()

        except Exception as e:
            log.error(f"Docker API error: {type(e).__name__}: {e}")

        return services

    def get_services(self) -> dict[str, DiscoveredService]:
        """Get all discovered services."""
        with self._lock:
            return dict(self._services)

    def get_service_by_port(self, port: int) -> Optional[DiscoveredService]:
        """Get service that exposes a given port."""
        with self._lock:
            name = self._port_map.get(port)
            if name:
                return self._services.get(name)
            return None

    def get_service_by_name(self, name: str) -> Optional[DiscoveredService]:
        """Get service by container name."""
        with self._lock:
            return self._services.get(name)

    def get_target_for_port(self, port: int) -> Optional[str]:
        """Get target host:port for a discovered service port."""
        service = self.get_service_by_port(port)
        if service:
            return f"{service.internal_ip}:{port}"
        return None

    def refresh(self):
        """Trigger manual refresh."""
        self._do_refresh()

    def done(self):
        """Cleanup on shutdown."""
        if self._refresh_thread:
            self._refresh_stop.set()
            self._refresh_thread.join(timeout=2.0)
            self._refresh_thread = None

    def get_stats(self) -> dict:
        """Get service discovery statistics."""
        with self._lock:
            services_info = {}
            for name, svc in self._services.items():
                services_info[name] = {
                    "container_id": svc.container_id,
                    "internal_ip": svc.internal_ip,
                    "ports": svc.ports,
                    "network": svc.network,
                    "discovered_at": svc.discovered_at,
                }

            return {
                "enabled": DOCKER_AVAILABLE and ctx.options.discovery_enabled,
                "docker_available": DOCKER_AVAILABLE,
                "network": self.network,
                "skip_containers": self.skip_containers,
                "refresh_interval": self.refresh_interval,
                "last_refresh": self.last_refresh,
                "discoveries_total": self.discoveries_total,
                "services_found": self.services_found,
                "services": services_info,
                "port_map": dict(self._port_map),
            }


# Global instance for other addons
_service_discovery: Optional[ServiceDiscovery] = None


def get_service_discovery() -> Optional[ServiceDiscovery]:
    """Get the service discovery instance."""
    return _service_discovery


# mitmproxy addon instance
service_discovery = ServiceDiscovery()
_service_discovery = service_discovery
addons = [service_discovery]
