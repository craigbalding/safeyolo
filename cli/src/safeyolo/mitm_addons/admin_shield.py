"""
admin_shield.py - Block proxy access to admin API

Prevents coding agents from reaching the SafeYolo admin API through
the proxy. This is defense-in-depth - the admin API also requires
bearer token auth, but we don't want agents even reaching it.

Must be loaded FIRST in the addon chain to guarantee protection.

Usage:
    mitmdump -s addons/admin_shield.py --set admin_port=9090
"""

import ipaddress
import logging
import socket

from mitmproxy import ctx, http
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

log = logging.getLogger("safeyolo.admin-shield")


class AdminShield:  # DOC: SECURITY.md
    """Block proxy requests targeting the admin API port."""

    name = "admin-shield"

    def load(self, loader):
        # admin_port is registered by admin_api.py — read via ctx.options
        loader.add_option(
            name="shield_extra_ports",
            typespec=str,
            default="",
            help="Comma-separated additional ports to block (e.g., '9091,9092')",
        )

    def running(self):
        port = ctx.options.admin_port
        log.info(f"Admin shield active - blocking proxy access to port {port}")

    def _get_blocked_ports(self) -> set[int]:
        """Get set of ports to block."""
        ports = {ctx.options.admin_port}

        # Port 0 asks the OS to choose a port. A later option change can also
        # leave the existing listener on its original port. Protect the actual
        # bound listener in both cases, including after a server restart.
        try:
            admin_api = ctx.master.addons.get("admin-api")
        except (AttributeError, KeyError):
            admin_api = None
        if admin_api is not None and admin_api.server is not None:
            ports.add(admin_api.server.server_address[1])

        extra = ctx.options.shield_extra_ports.strip()
        if extra:
            for port_str in extra.split(","):
                port_str = port_str.strip()
                if port_str.isdigit():
                    try:
                        ports.add(int(port_str))
                    except ValueError:
                        # An unrepresentable extra entry must not disable the
                        # configured and currently bound admin-port checks.
                        pass

        return ports

    # Local/loopback hostnames the admin API might be reached through when
    # the agent misroutes under the current gVisor+microVM architecture.
    _LOCAL_HOSTS = frozenset({
        "localhost", "127.0.0.1", "::1", "0.0.0.0",
    })

    def _is_local(self, host: str) -> bool:
        """Recognize the protected listener's loopback address spellings."""
        name = host.lower().removesuffix(".")
        if name in self._LOCAL_HOSTS or name.endswith(".localhost"):
            return True
        try:
            address = ipaddress.ip_address(name)
        except ValueError:
            try:
                # inet_aton accepts historical IPv4 forms such as 127.1 and
                # 2130706433 that can also connect to 127.0.0.1.
                address = ipaddress.IPv4Address(socket.inet_aton(name))
            except OSError:
                return False
        if isinstance(address, ipaddress.IPv6Address):
            address = address.ipv4_mapped or address
        return address in (ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("0.0.0.0"),
                           ipaddress.ip_address("::1"))

    def http_connect(self, flow: http.HTTPFlow):
        """Apply the reserved-port boundary before admitting a tunnel."""
        self.request(flow)

    def server_connect(self, data: ServerConnectionHookData) -> None:
        """Keep reserved local ports unreachable at the transport boundary."""
        if data.server.address:
            host, port = data.server.address
            if port in self._get_blocked_ports() and self._is_local(host):
                data.server.error = "SafeYolo: admin API not accessible through proxy"

    def request(self, flow: http.HTTPFlow):
        """Block requests to admin API port on local destinations."""
        blocked_ports = self._get_blocked_ports()
        request_port = flow.request.port

        if request_port in blocked_ports and self._is_local(flow.request.host):
            host = flow.request.host
            log.warning(
                f"Blocked proxy request to admin port: {host}:{request_port} "
                f"(client: {flow.client_conn.peername})"
            )

            # Return 403 Forbidden with explanation
            flow.response = http.Response.make(
                403,
                b'{"error": "Forbidden", "message": "Admin API not accessible through proxy"}',
                {"Content-Type": "application/json", "X-Blocked-By": "admin-shield"},
            )

            # Mark as handled so other addons skip it
            flow.metadata["blocked_by"] = self.name
            flow.metadata["block_reason"] = "admin_port_access"


addons = [AdminShield()]
