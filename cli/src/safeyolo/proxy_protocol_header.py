"""PROXY protocol v2 header builder for proxy_bridge.

Standalone module so the bridge daemon can build headers without
importing the full addons package. The canonical implementation
lives in addons/proxy_protocol.py — this is a minimal copy of
build_v2_header() only.
"""
from __future__ import annotations

import socket
import struct

PP2_SIGNATURE = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
PP2_VERSION = 0x20
PP2_CMD_PROXY = 0x01
PP2_FAM_INET_STREAM = 0x11
PP2_TYPE_SAFEYOLO_AGENT = 0xE0


def build_v2_header(
    src_ip: str,
    dst_ip: str = "127.0.0.1",
    src_port: int = 0,
    dst_port: int = 0,
    agent_name: str = "",
) -> bytes:
    """Build a PROXY protocol v2 header with optional agent name TLV."""
    addr_block = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!HH", src_port, dst_port)
    )

    tlv_block = b""
    if agent_name:
        name_bytes = agent_name.encode("utf-8")
        tlv_block = struct.pack("!BH", PP2_TYPE_SAFEYOLO_AGENT, len(name_bytes)) + name_bytes

    payload_len = len(addr_block) + len(tlv_block)

    return (
        PP2_SIGNATURE
        + struct.pack("!BBH", PP2_VERSION | PP2_CMD_PROXY, PP2_FAM_INET_STREAM, payload_len)
        + addr_block
        + tlv_block
    )
