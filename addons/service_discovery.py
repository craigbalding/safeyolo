"""
service_discovery.py - Automatic service discovery via Docker DNS

Maps container IPs to client IDs for per-client credential policies.
Uses Docker's embedded DNS to resolve container IPs to names on first
request, with caching to avoid per-request DNS lookups.

Resolution order:
1. DNS cache hit (non-expired)
2. Reverse DNS lookup via Docker embedded DNS
3. Default: "unknown"
"""

import logging
import socket
import time
from threading import Lock

from mitmproxy import ctx, http
from utils import get_client_ip, sanitize_for_log, write_event

from audit_schema import EventKind, Severity

log = logging.getLogger("safeyolo.discovery")

# DNS-based discovery constants
DNS_CACHE_TTL_SECONDS = 300  # How long to trust a reverse DNS result
DNS_NEGATIVE_CACHE_TTL_SECONDS = 60  # Cache failed lookups to avoid repeated slow queries
DNS_CACHE_MAX_SIZE = 500  # Max cached DNS entries


class ServiceDiscovery:
    """
    Automatic service registry via Docker DNS.

    Resolves container IPs to client IDs using Docker's embedded DNS.
    Results are cached to avoid per-request DNS lookups.
    """

    name = "service-discovery"

    def __init__(self):
        self.network = "safeyolo_internal"
        self._dns_cache: dict[str, tuple[str, float]] = {}  # ip -> (client_name, expiry)
        self._dns_negative_cache: dict[str, float] = {}  # ip -> expiry (failed lookups)
        self._last_seen: dict[str, float] = {}  # agent_name -> epoch timestamp
        self._lock = Lock()

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="discovery_network",
            typespec=str,
            default="safeyolo_internal",
            help="Docker network name for DNS suffix stripping",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "discovery_network" in updates:
            self.network = ctx.options.discovery_network

    def done(self):
        """Cleanup on shutdown."""
        pass

    def _resolve_ip_via_dns(self, ip: str) -> str | None:
        """Resolve an IP to a client name via Docker's embedded reverse DNS.

        Docker's DNS returns "{container_name}.{network_name}" for containers
        on user-defined networks. We strip the network suffix to get the
        clean instance name.

        Returns:
            Client name (e.g., "claude") or None if resolution fails.
        """
        try:
            hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        except (socket.herror, socket.gaierror, OSError):
            return None

        if not hostname:
            return None

        # Docker returns "{container_name}.{network_name}" on user-defined networks
        network_suffix = f".{self.network}"
        if hostname.endswith(network_suffix):
            hostname = hostname[: -len(network_suffix)]

        # Skip the proxy container itself
        if hostname == "safeyolo":
            return None

        return hostname

    def get_client_for_ip(self, ip: str) -> str:
        """Get client ID for an IP address.

        Thread-safe: reads cache under lock.

        Resolution order:
        1. DNS cache (non-expired)
        2. Reverse DNS via Docker embedded DNS
        3. "unknown"

        Returns:
            Client ID if IP is resolved, otherwise "unknown".
            Policy should explicitly handle "unknown" principals.
        """
        now = time.time()

        # Take a snapshot under lock
        with self._lock:
            dns_entry = self._dns_cache.get(ip)
            dns_negative_expiry = self._dns_negative_cache.get(ip)

        # 1. Check DNS cache (non-expired)
        if dns_entry is not None:
            client_name, expiry = dns_entry
            if now < expiry:
                return client_name
            # Expired — will re-resolve below

        # 2. Reverse DNS lookup (skip if recently failed)
        if dns_negative_expiry is None or now >= dns_negative_expiry:
            resolved = self._resolve_ip_via_dns(ip)
            if resolved:
                expiry = now + DNS_CACHE_TTL_SECONDS
                with self._lock:
                    # Evict expired entries if at capacity
                    if len(self._dns_cache) >= DNS_CACHE_MAX_SIZE:
                        self._dns_cache = {
                            k: v for k, v in self._dns_cache.items() if v[1] > now
                        }
                    self._dns_cache[ip] = (resolved, expiry)
                if dns_entry is None:
                    log.info(f"DNS discovery: {ip} -> {resolved}")
                    write_event(
                        "agent.discovered",
                        kind=EventKind.AGENT,
                        severity=Severity.LOW,
                        summary=f"Discovered agent {sanitize_for_log(resolved)} at {ip}",
                        agent=resolved,
                        addon="service-discovery",
                        details={"ip": ip},
                    )
                else:
                    log.debug(f"DNS cache refresh: {ip} -> {resolved}")
                return resolved
            else:
                # Cache the failure to avoid repeated lookups
                with self._lock:
                    self._dns_negative_cache[ip] = now + DNS_NEGATIVE_CACHE_TTL_SECONDS

        # 3. Unknown IP — negative cache already throttles retries to every 60s
        log.warning(f"Unknown source IP: {ip} - using 'unknown' principal")

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
        """Get agent overview for agent API /agents endpoint.

        Returns per-agent info: IP, last seen timestamp, and seconds since
        last activity. Thread-safe.
        """
        now = time.time()
        with self._lock:
            dns_cached = {ip: (name, exp) for ip, (name, exp) in self._dns_cache.items() if exp > now}
            last_seen_snapshot = dict(self._last_seen)

        # Build agent -> {ip, last_seen, idle_seconds}
        # An agent may have multiple IPs (container restart), take the latest cache entry
        agents: dict[str, dict] = {}
        for ip, (name, _exp) in dns_cached.items():
            if name not in agents:
                agents[name] = {"ip": ip}
            # If duplicate, keep whichever — both are valid
        for name, ts in last_seen_snapshot.items():
            entry = agents.setdefault(name, {"ip": None})
            entry["last_seen"] = ts
            entry["idle_seconds"] = round(now - ts, 1)

        return {
            "agents": agents,
            "count": len(agents),
        }

    def get_stats(self) -> dict:
        """Get discovery statistics for admin API.

        Thread-safe: takes snapshot under lock.
        Includes full agent details so `safeyolo status` can display them.
        """
        agents_data = self.get_agents()
        now = time.time()
        with self._lock:
            dns_cached = {ip: name for ip, (name, exp) in self._dns_cache.items() if exp > now}
            dns_negative = {ip for ip, exp in self._dns_negative_cache.items() if exp > now}

        return {
            "dns_cache_size": len(dns_cached),
            "dns_cached_clients": dns_cached,
            "dns_negative_cache_size": len(dns_negative),
            "unresolved_ips_count": len(dns_negative),
            "agents": agents_data["agents"],
            "agents_seen": agents_data["count"],
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
