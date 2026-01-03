"""
admin_shield.py - Block proxy access to admin API

Prevents coding agents from reaching the SafeYolo admin API through
the proxy. This is defense-in-depth - the admin API also requires
bearer token auth, but we don't want agents even reaching it.

Must be loaded FIRST in the addon chain to guarantee protection.

Usage:
    mitmdump -s addons/admin_shield.py --set admin_port=9090
"""

import logging
from mitmproxy import ctx, http

log = logging.getLogger("safeyolo.admin-shield")


class AdminShield:
    """Block proxy requests targeting the admin API port."""

    name = "admin-shield"

    def load(self, loader):
        loader.add_option(
            name="admin_port",
            typespec=int,
            default=9090,
            help="Admin API port to protect",
        )
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

        extra = ctx.options.shield_extra_ports.strip()
        if extra:
            for port_str in extra.split(","):
                port_str = port_str.strip()
                if port_str.isdigit():
                    ports.add(int(port_str))

        return ports

    def request(self, flow: http.HTTPFlow):
        """Block requests to admin API port."""
        blocked_ports = self._get_blocked_ports()
        request_port = flow.request.port

        if request_port in blocked_ports:
            host = flow.request.host
            log.warning(
                f"Blocked proxy request to admin port: {host}:{request_port} "
                f"(client: {flow.client_conn.peername})"
            )

            # Return 403 Forbidden with explanation
            flow.response = http.Response.make(
                403,
                b'{"error": "Forbidden", "message": "Admin API not accessible through proxy"}',
                {"Content-Type": "application/json"},
            )

            # Mark as handled so other addons skip it
            flow.metadata["blocked_by"] = self.name
            flow.metadata["block_reason"] = "admin_port_access"


addons = [AdminShield()]
