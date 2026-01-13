"""
service_discovery.py - Dynamic service registry with hot reload

Maps container IPs to project IDs for per-project credential policies.
Watches services.yaml for changes and automatically reloads.

Canonical path: /app/data/services.yaml (in container)
    - Mounted from ~/.safeyolo/data/ on host
    - CLI writes via `safeyolo start` or `safeyolo sync`
    - Users with custom tooling can edit the host file directly

File format:
    services:
      agent-name:
        ip: "172.20.0.3"
        project: "agent-name"
"""

import logging
import time
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from threading import Lock, Thread

import yaml
from mitmproxy import ctx

log = logging.getLogger("safeyolo.discovery")

# Constants
DEFAULT_WATCH_INTERVAL_SECONDS = 5
THREAD_JOIN_TIMEOUT_SECONDS = 2
MAX_UNKNOWN_IPS_TRACKED = 1000  # Prevent unbounded memory growth


@dataclass
class ServiceEntry:
    """A registered service."""

    name: str
    project: str
    ip: str | None = None
    ip_range: str | None = None


class ServiceDiscovery:
    """
    Dynamic service registry with file watching.

    Reads services.yaml to map client IPs to project IDs.
    Automatically reloads when the file changes.
    """

    name = "service-discovery"

    def __init__(self):
        self.network = "safeyolo_internal"
        self._services: dict[str, ServiceEntry] = {}  # name -> entry
        self._ip_to_project: dict[str, str] = {}  # exact IP -> project
        self._ranges: list[tuple] = []  # (ip_network, project)
        self._last_load: float = 0
        self._config_path: Path | None = None
        self._file_mtime: float = 0
        self._watch_thread: Thread | None = None
        self._stop_watching = False
        self._watch_interval: int = DEFAULT_WATCH_INTERVAL_SECONDS
        self._unknown_ips: set[str] = set()  # Track unknown IPs for diagnostics
        self._lock = Lock()  # Protects _services, _ip_to_project, _ranges during reload

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="discovery_network",
            typespec=str,
            default="safeyolo_internal",
            help="Docker network name (for documentation)",
        )
        loader.add_option(
            name="discovery_watch",
            typespec=bool,
            default=True,
            help="Watch services.yaml for changes and auto-reload",
        )
        loader.add_option(
            name="discovery_watch_interval",
            typespec=int,
            default=DEFAULT_WATCH_INTERVAL_SECONDS,
            help="Seconds between file change checks",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "discovery_network" in updates:
            self.network = ctx.options.discovery_network

        if "discovery_watch_interval" in updates:
            self._watch_interval = ctx.options.discovery_watch_interval

        # Load config on first configure
        if self._last_load == 0:
            self._load_config()

        # Start file watcher if enabled and not already running
        if ctx.options.discovery_watch and self._watch_thread is None:
            self._start_watching()

    def done(self):
        """Cleanup on shutdown."""
        self._stop_watching = True
        if self._watch_thread:
            self._watch_thread.join(timeout=THREAD_JOIN_TIMEOUT_SECONDS)

    def _start_watching(self):
        """Start background thread to watch for config changes."""
        interval = self._watch_interval

        def watch_loop():
            while not self._stop_watching:
                time.sleep(interval)
                if self._check_file_changed():
                    log.info("services.yaml changed, reloading...")
                    self._load_config()

        self._watch_thread = Thread(target=watch_loop, daemon=True, name="discovery-watcher")
        self._watch_thread.start()
        log.info(f"Started watching services.yaml (interval={interval}s)")

    def _check_file_changed(self) -> bool:
        """Check if config file has been modified."""
        if not self._config_path:
            # Try to find config if we don't have one yet
            new_path = self._find_config()
            if new_path:
                self._config_path = new_path
                return True
            return False

        if not self._config_path.exists():
            # File was deleted - clear mappings under lock
            with self._lock:
                if self._services:
                    log.warning("services.yaml deleted, clearing mappings")
                    self._services = {}
                    self._ip_to_project = {}
                    self._ranges = []
            return False

        try:
            current_mtime = self._config_path.stat().st_mtime
            if current_mtime > self._file_mtime:
                self._file_mtime = current_mtime
                return True
        except OSError as err:
            log.debug(f"Cannot stat config file: {type(err).__name__}: {err}")

        return False

    def _find_config(self) -> Path | None:
        """Get canonical services.yaml path.

        Returns:
            /app/data/services.yaml if it exists, None otherwise.

        Note:
            This is the only supported location. The file is mounted from
            ~/.safeyolo/data/services.yaml on the host. Users with custom
            tooling should write to that host path.
        """
        canonical_path = Path("/app/data/services.yaml")
        if canonical_path.exists():
            return canonical_path
        return None

    def _load_config(self):
        """Load services from services.yaml.

        Thread-safe: builds new dicts, then atomically swaps them under lock.
        """
        # Build new mappings in local variables (no lock needed yet)
        new_services: dict[str, ServiceEntry] = {}
        new_ip_to_project: dict[str, str] = {}
        new_ranges: list[tuple] = []

        # Use pre-set _config_path (e.g., for testing) or find one
        config_path = self._config_path or self._find_config()
        if not config_path:
            log.debug("No services.yaml found - using 'unknown' project for all requests")
            # Atomically clear under lock
            with self._lock:
                self._services = new_services
                self._ip_to_project = new_ip_to_project
                self._ranges = new_ranges
            return

        self._config_path = config_path

        try:
            self._file_mtime = config_path.stat().st_mtime
        except OSError as exc:
            log.debug("Could not read mtime for %s: %s", config_path, exc)

        try:
            with open(config_path) as f:
                content = f.read()

            # Check for stale marker
            if "stale" in content.lower() and "safeyolo stopped" in content.lower():
                log.warning("services.yaml is marked as stale (SafeYolo was stopped)")
                # Clear mappings - don't use stale data
                with self._lock:
                    self._services = new_services
                    self._ip_to_project = new_ip_to_project
                    self._ranges = new_ranges
                return

            config = yaml.safe_load(content) or {}

            services = config.get("services", {})
            for name, entry in services.items():
                project = entry.get("project", name)

                # Exact IP mapping
                if "ip" in entry:
                    ip = entry["ip"]
                    new_ip_to_project[ip] = project
                    new_services[name] = ServiceEntry(name=name, project=project, ip=ip)
                    log.debug(f"Registered: {ip} -> {project}")

                # IP range mapping
                elif "ip_range" in entry:
                    try:
                        network = ip_network(entry["ip_range"], strict=False)
                        new_ranges.append((network, project))
                        new_services[name] = ServiceEntry(
                            name=name, project=project, ip_range=entry["ip_range"]
                        )
                        log.debug(f"Registered: {entry['ip_range']} -> {project}")
                    except ValueError as e:
                        log.warning(f"Invalid IP range for {name}: {e}")

            # Atomically swap in new mappings
            with self._lock:
                self._services = new_services
                self._ip_to_project = new_ip_to_project
                self._ranges = new_ranges

            self._last_load = time.time()
            log.info(f"Loaded {len(new_services)} services from {config_path}")

        except Exception as e:
            log.warning(f"Failed to load {config_path}: {type(e).__name__}: {e}")
            # On error, keep existing mappings (don't clear)

    def get_project_for_ip(self, ip: str) -> str:
        """Get project ID for a client IP.

        Thread-safe: reads mappings under lock.

        Returns:
            Project name if IP is mapped, otherwise "unknown".
            Policy should explicitly handle "unknown" principals.
        """
        # Take a snapshot under lock to avoid races with reload
        with self._lock:
            ip_to_project = self._ip_to_project
            ranges = self._ranges

        # Check exact IP match first (no lock needed - we have a snapshot)
        if ip in ip_to_project:
            return ip_to_project[ip]

        # Check IP ranges
        try:
            client_ip = ip_address(ip)
            for network, project in ranges:
                if client_ip in network:
                    return project
        except ValueError:
            pass  # Invalid IP format, fall through to unknown

        # Unknown IP - log warning (but only once per IP to avoid spam)
        # Thread-safe check-then-add under lock
        should_log = False
        with self._lock:
            if ip not in self._unknown_ips:
                # Prevent unbounded memory growth
                if len(self._unknown_ips) < MAX_UNKNOWN_IPS_TRACKED:
                    self._unknown_ips.add(ip)
                should_log = True

        if should_log:
            log.warning(f"Unknown source IP: {ip} - using 'unknown' principal")

        return "unknown"

    def reload(self):
        """Reload configuration from disk (for admin API)."""
        log.info("Manual reload triggered")
        self._load_config()

    def get_stats(self) -> dict:
        """Get discovery statistics for admin API.

        Thread-safe: takes snapshot under lock.
        """
        # Snapshot under lock
        with self._lock:
            services_snapshot = dict(self._services)
            ip_count = len(self._ip_to_project)
            range_count = len(self._ranges)

        return {
            "config_path": str(self._config_path) if self._config_path else None,
            "services_count": len(services_snapshot),
            "ip_mappings": ip_count,
            "range_mappings": range_count,
            "unknown_ips": list(self._unknown_ips)[:100],  # Limit output size
            "unknown_ips_count": len(self._unknown_ips),
            "last_load": self._last_load,
            "watching": self._watch_thread is not None and self._watch_thread.is_alive(),
            "watch_interval": self._watch_interval,
            "services": {
                name: {
                    "project": entry.project,
                    "ip": entry.ip,
                    "ip_range": entry.ip_range,
                }
                for name, entry in services_snapshot.items()
            },
        }


# Module-level singleton
_discovery: ServiceDiscovery | None = None


def get_service_discovery() -> ServiceDiscovery | None:
    """Get the service discovery instance."""
    return _discovery


# Create instance and register as mitmproxy addon
discovery = ServiceDiscovery()
_discovery = discovery
addons = [discovery]
