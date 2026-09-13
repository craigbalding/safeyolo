"""Destination ports and unambiguous policy endpoint keys."""

import ipaddress
import json


def validate_port(port: int) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    return port


def split_destination(value: str) -> tuple[str, int | None]:
    """Split a host pattern or host:port key; IPv6 endpoints require brackets."""
    if ":" not in value:
        return value, None
    if value.startswith("[") and "]:" in value:
        host, suffix = value[1:].split("]:", 1)
        host = str(ipaddress.IPv6Address(host))
    elif value.count(":") == 1:
        host, suffix = value.rsplit(":", 1)
    else:
        return str(ipaddress.IPv6Address(value)), None
    if not host or not suffix.isascii() or not suffix.isdecimal():
        raise ValueError("destination must be host:port or [IPv6]:port")
    return host, validate_port(int(suffix))


def destination_key(host: str, port: int | None = None) -> str:
    """Format an endpoint key; omitted port preserves the host-wide scope."""
    if port is None:
        return host
    validate_port(port)
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def network_approval_key(agent: str | None, host: str, port: int) -> str:
    """Keep approvals for different agents and ports in distinct groups."""
    return json.dumps([agent or "", host, validate_port(port)], separators=(",", ":"))
