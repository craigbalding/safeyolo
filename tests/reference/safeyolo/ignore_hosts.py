"""Validation and mitmproxy pattern generation for TLS passthrough hosts."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable

# frp speaks its own protocol over this endpoint and cannot be intercepted.
BUILTIN_IGNORE_PATTERNS = (r"^api\.asterfold\.ai:7000$",)

# Refuse prefixes wider than this to avoid accidentally exempting a large
# portion of the internet from inspection.
_IGNORE_CIDR_MIN_PREFIX = 8
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_ignore_host(value: str) -> str:
    """Return a canonical exact ``host`` or ``host:port`` entry.

    The operator-facing surface deliberately does not accept wildcards or
    regular expressions. Values are escaped when converted to mitmproxy
    patterns, so a configuration entry can only exempt the named endpoint.
    """
    if not isinstance(value, str):
        raise ValueError("ignore host must be a string")

    raw = value.strip()
    if not raw:
        raise ValueError("ignore host must not be empty")
    if any(char in raw for char in "/?#@[]") or "://" in raw:
        raise ValueError("ignore host must be HOST or HOST:PORT (no URL, path, or IPv6 literal)")

    host = raw
    port: int | None = None
    if ":" in raw:
        if raw.count(":") != 1:
            raise ValueError("IPv6 literals are not supported; use a hostname or IPv4 address")
        host, raw_port = raw.rsplit(":", 1)
        if not raw_port.isascii() or not raw_port.isdecimal():
            raise ValueError("ignore host port must be an integer between 1 and 65535")
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError("ignore host port must be between 1 and 65535")

    if not host or host.endswith("."):
        raise ValueError("ignore host must be a hostname or IPv4 address")

    try:
        canonical_host = str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        if re.fullmatch(r"[0-9.]+", host):
            raise ValueError("ignore host must be a valid hostname or IPv4 address")
        try:
            canonical_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("ignore host must be a valid hostname or IPv4 address") from exc
        if len(canonical_host) > 253 or any(
            not _DNS_LABEL_RE.fullmatch(label) for label in canonical_host.split(".")
        ):
            raise ValueError("ignore host must be a valid hostname or IPv4 address")

    if port is None:
        return canonical_host
    return f"{canonical_host}:{port}"


def normalize_ignore_hosts(values: Iterable[str]) -> list[str]:
    """Validate, canonicalize, and de-duplicate exact host entries."""
    if not isinstance(values, (list, tuple)):
        raise ValueError("proxy.ignore_hosts must be a list of HOST or HOST:PORT strings")
    try:
        normalized = [normalize_ignore_host(value) for value in values]
    except TypeError as exc:
        raise ValueError("proxy.ignore_hosts must be a list of HOST or HOST:PORT strings") from exc
    return list(dict.fromkeys(normalized))


def ignore_host_to_regex(value: str) -> str:
    """Compile one exact operator entry into a mitmproxy host regex."""
    normalized = normalize_ignore_host(value)
    host, separator, port = normalized.rpartition(":")
    if separator:
        return rf"^{re.escape(host)}:{port}$"
    return rf"^{re.escape(normalized)}(?::\d+)?$"


def _octet_range_regex(lo: int, hi: int) -> str:
    """Return a regex fragment matching any integer in ``[lo, hi]``."""
    if lo == 0 and hi == 255:
        return r"\d+"
    return "(?:" + "|".join(str(n) for n in range(lo, hi + 1)) + ")"


def cidr_to_ignore_regex(cidr: str) -> str:
    """Convert a constrained IPv4 CIDR to a mitmproxy host regex."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR {cidr!r}: {exc}") from exc

    if isinstance(net, ipaddress.IPv6Network):
        raise ValueError(f"IPv6 CIDR not supported: {cidr!r}")
    if net.prefixlen < _IGNORE_CIDR_MIN_PREFIX:
        raise ValueError(
            f"CIDR {cidr!r} is too wide (prefix /{net.prefixlen} < "
            f"/{_IGNORE_CIDR_MIN_PREFIX}); refusing to exempt that large a range"
        )

    octets = net.network_address.packed
    full = net.prefixlen // 8
    partial = net.prefixlen % 8
    parts: list[str] = [str(octets[index]) for index in range(full)]

    if full < 4:
        if partial == 0:
            parts.extend([r"\d+"] * (4 - full))
        else:
            lo = octets[full]
            hi = lo + (1 << (8 - partial)) - 1
            parts.append(_octet_range_regex(lo, hi))
            parts.extend([r"\d+"] * (4 - full - 1))

    return r"^" + r"\.".join(parts) + r"(?::\d+)?$"


def parse_ignore_cidrs_env() -> list[str]:
    """Parse ``SAFEYOLO_IGNORE_CIDRS`` into validated regexes."""
    raw = os.environ.get("SAFEYOLO_IGNORE_CIDRS", "").strip()
    if not raw:
        return []
    return [
        cidr_to_ignore_regex(entry)
        for item in raw.split(",")
        if (entry := item.strip())
    ]


def build_ignore_patterns(hosts: Iterable[str]) -> list[str]:
    """Build the complete authoritative mitmproxy ignore-host pattern list."""
    normalized = normalize_ignore_hosts(hosts)
    patterns = [*BUILTIN_IGNORE_PATTERNS, *parse_ignore_cidrs_env()]
    patterns.extend(ignore_host_to_regex(host) for host in normalized)
    return list(dict.fromkeys(patterns))
