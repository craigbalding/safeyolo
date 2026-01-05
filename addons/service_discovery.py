"""
service_discovery.py - Static service registry for project isolation

Maps container IPs to project IDs for per-project credential policies.
Reads from services.yaml (managed by CLI or provided by integrated users).

For managed users:
    CLI writes to services.yaml when running `safeyolo agent run`

For integrated users:
    Provide your own services.yaml with IP ranges for your services
"""

import logging
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path

import yaml
from mitmproxy import ctx

log = logging.getLogger("safeyolo.discovery")


@dataclass
class ServiceEntry:
    """A registered service."""
    name: str
    project: str
    ip: str | None = None
    ip_range: str | None = None


class ServiceDiscovery:
    """
    Static service registry for project isolation.

    Reads services.yaml to map client IPs to project IDs.
    Used by credential_guard for per-project policies.
    """

    name = "service-discovery"

    def __init__(self):
        self.network = "safeyolo-internal"
        self._services: dict[str, ServiceEntry] = {}  # name -> entry
        self._ip_to_project: dict[str, str] = {}  # exact IP -> project
        self._ranges: list[tuple] = []  # (ip_network, project)
        self._last_load: float = 0
        self._config_path: Path | None = None

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="discovery_network",
            typespec=str,
            default="safeyolo-internal",
            help="Docker network name (for documentation)",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "discovery_network" in updates:
            self.network = ctx.options.discovery_network

        # Load config on first configure
        if self._last_load == 0:
            self._load_config()

    def _find_config(self) -> Path | None:
        """Find services.yaml in standard locations."""
        search_paths = [
            Path("/app/data/services.yaml"),  # Container mount
            Path("/app/config/services.yaml"),  # Container config
            Path.home() / ".safeyolo" / "services.yaml",  # User global
            Path("./safeyolo/services.yaml"),  # Project local
        ]

        for path in search_paths:
            if path.exists():
                return path
        return None

    def _load_config(self):
        """Load services from services.yaml."""
        self._services.clear()
        self._ip_to_project.clear()
        self._ranges.clear()

        config_path = self._find_config()
        if not config_path:
            log.debug("No services.yaml found - using default project for all")
            return

        self._config_path = config_path

        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}

            services = config.get("services", {})
            for name, entry in services.items():
                project = entry.get("project", name)

                # Exact IP mapping
                if "ip" in entry:
                    ip = entry["ip"]
                    self._ip_to_project[ip] = project
                    self._services[name] = ServiceEntry(
                        name=name, project=project, ip=ip
                    )
                    log.debug(f"Registered: {ip} -> {project}")

                # IP range mapping
                elif "ip_range" in entry:
                    try:
                        network = ip_network(entry["ip_range"], strict=False)
                        self._ranges.append((network, project))
                        self._services[name] = ServiceEntry(
                            name=name, project=project, ip_range=entry["ip_range"]
                        )
                        log.debug(f"Registered: {entry['ip_range']} -> {project}")
                    except ValueError as e:
                        log.warning(f"Invalid IP range for {name}: {e}")

            self._last_load = time.time()
            log.info(f"Loaded {len(self._services)} services from {config_path}")

        except Exception as e:
            log.warning(f"Failed to load {config_path}: {type(e).__name__}: {e}")

    def get_project_for_ip(self, ip: str) -> str:
        """Get project ID for a client IP."""
        # Check exact IP match first
        if ip in self._ip_to_project:
            return self._ip_to_project[ip]

        # Check IP ranges
        try:
            client_ip = ip_address(ip)
            for network, project in self._ranges:
                if client_ip in network:
                    return project
        except ValueError:
            pass  # Invalid IP format, fall through to default

        return "default"

    def reload(self):
        """Reload configuration from disk."""
        self._load_config()

    def get_stats(self) -> dict:
        """Get discovery statistics."""
        return {
            "config_path": str(self._config_path) if self._config_path else None,
            "services_count": len(self._services),
            "ip_mappings": len(self._ip_to_project),
            "range_mappings": len(self._ranges),
            "last_load": self._last_load,
            "services": {
                name: {
                    "project": entry.project,
                    "ip": entry.ip,
                    "ip_range": entry.ip_range,
                }
                for name, entry in self._services.items()
            },
        }


_discovery: ServiceDiscovery | None = None


def get_service_discovery() -> ServiceDiscovery | None:
    """Get the service discovery instance."""
    return _discovery


discovery = ServiceDiscovery()
_discovery = discovery
addons = [discovery]
