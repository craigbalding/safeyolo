"""Per-agent UDS path conventions.

Filename `<ip>_<agent>.sock` is the single source of truth for agent
identity. Every downstream use (hostname, log field, attribution IP)
derives from this at parse-time — never stored or passed as a parallel
value. If you find yourself threading `(ip, agent)` through multiple
layers, re-parse the socket path instead.

The filename layout is unambiguous because SafeYolo agent names are
validated as RFC 1123 hostnames (lowercase alphanumeric + hyphens,
no underscores — see `commands/agent.py::_validate_instance_name`),
so `split('_', 1)` reliably splits the IP prefix from the agent
suffix.
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

from .config import get_bridge_sockets_dir

# sun_path cap: 108 bytes on Linux, 104 on BSD/macOS. Enforce the
# platform's own limit — cross-platform deployments don't share the
# same home prefix, so validating against the tighter one everywhere
# would spuriously reject valid Linux paths.
_SUN_PATH_MAX = 104 if sys.platform == "darwin" else 108

# Match commands/agent.py::_validate_instance_name.
_AGENT_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def sockets_dir() -> Path:
    """Directory containing per-agent listener sockets."""
    return get_bridge_sockets_dir()


def path_for(agent: str, ip: str) -> Path:
    """Host-side UDS path for an agent.

    Raises ValueError on invalid agent name, malformed IP, or a path
    that would exceed `sun_path` length on either supported platform.
    """
    if not _AGENT_NAME_RE.match(agent):
        raise ValueError(
            f"invalid agent name {agent!r}: must match RFC 1123 hostname "
            "(lowercase alphanumeric + hyphens, no underscores)"
        )
    # ipaddress.IPv4Address raises on malformed input.
    ipaddress.IPv4Address(ip)
    p = sockets_dir() / f"{ip}_{agent}.sock"
    if len(str(p).encode()) > _SUN_PATH_MAX:
        raise ValueError(
            f"socket path exceeds sun_path limit ({_SUN_PATH_MAX} bytes): {p}"
        )
    return p


def parse(path: Path | str) -> tuple[str, str]:
    """Return `(ip, agent)` from a socket path built by `path_for`.

    Raises ValueError if the filename doesn't match the expected shape.
    """
    name = Path(path).name
    if not name.endswith(".sock"):
        raise ValueError(f"expected .sock suffix: {path}")
    stem = name[: -len(".sock")]
    ip, sep, agent = stem.partition("_")
    if not sep:
        raise ValueError(f"expected '<ip>_<agent>.sock' layout: {path}")
    ipaddress.IPv4Address(ip)  # validate
    if not _AGENT_NAME_RE.match(agent):
        raise ValueError(f"invalid agent name in path: {path}")
    return ip, agent
