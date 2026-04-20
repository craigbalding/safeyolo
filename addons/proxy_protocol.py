"""
proxy_protocol.py — PROXY protocol v2 identity via mitmproxy's layer system.

Uses the next_layer hook to detect PROXY protocol v2 headers. Parses the
header, rewrites client.peername with the agent's attribution IP, and
strips the header bytes from the buffered events so the HTTP parser
sees clean data.
"""

import logging
import struct
from typing import Any

from mitmproxy.proxy import events as mevents
from mitmproxy.proxy import layer

log = logging.getLogger("safeyolo.proxy-protocol")

# -- PROXY protocol v2 constants ------------------------------------------

PP2_SIGNATURE = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
PP2_SIGNATURE_LEN = 12
PP2_HEADER_LEN = 16
PP2_VERSION = 0x20
PP2_CMD_PROXY = 0x01
PP2_FAM_INET_STREAM = 0x11
PP2_ADDR_LEN_INET = 12
PP2_TYPE_SAFEYOLO_AGENT = 0xE0


# -- v2 builder (used by proxy_bridge) ------------------------------------

def build_v2_header(
    src_ip: str,
    dst_ip: str = "127.0.0.1",
    src_port: int = 0,
    dst_port: int = 0,
    agent_name: str = "",
) -> bytes:
    """Build a PROXY protocol v2 header with optional agent name TLV."""
    import socket as _socket

    addr_block = (
        _socket.inet_aton(src_ip)
        + _socket.inet_aton(dst_ip)
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


# -- v2 parser -------------------------------------------------------------

def _parse_v2_header(data: bytes) -> dict[str, Any] | None:
    if len(data) < PP2_HEADER_LEN:
        return None
    if data[:PP2_SIGNATURE_LEN] != PP2_SIGNATURE:
        return None

    ver_cmd, fam, payload_len = struct.unpack("!BBH", data[12:16])
    if (ver_cmd & 0xF0) != PP2_VERSION:
        return None

    total_len = PP2_HEADER_LEN + payload_len
    if len(data) < total_len:
        return None

    result: dict[str, Any] = {"header_len": total_len}
    payload = data[PP2_HEADER_LEN:total_len]

    if fam == PP2_FAM_INET_STREAM and len(payload) >= PP2_ADDR_LEN_INET:
        import socket as _socket
        result["src_ip"] = _socket.inet_ntoa(payload[0:4])
        result["dst_ip"] = _socket.inet_ntoa(payload[4:8])
        result["src_port"], result["dst_port"] = struct.unpack("!HH", payload[8:12])

        tlv_data = payload[PP2_ADDR_LEN_INET:]
        while len(tlv_data) >= 3:
            tlv_type = tlv_data[0]
            tlv_len = struct.unpack("!H", tlv_data[1:3])[0]
            if 3 + tlv_len > len(tlv_data):
                break
            tlv_value = tlv_data[3:3 + tlv_len]
            if tlv_type == PP2_TYPE_SAFEYOLO_AGENT:
                result["agent_name"] = tlv_value.decode("utf-8", errors="replace")
            tlv_data = tlv_data[3 + tlv_len:]

    return result


# -- Addon -----------------------------------------------------------------

class ProxyProtocolAddon:
    """Detect PROXY protocol v2 via next_layer hook."""

    name = "proxy-protocol"

    def next_layer(self, nextlayer: layer.NextLayer):
        data = nextlayer.data_client()
        if not data or len(data) < PP2_SIGNATURE_LEN:
            return
        if data[:PP2_SIGNATURE_LEN] != PP2_SIGNATURE:
            return

        parsed = _parse_v2_header(bytes(data))
        if not parsed:
            return

        header_len = parsed["header_len"]
        src_ip = parsed.get("src_ip", "127.0.0.1")
        src_port = parsed.get("src_port", 0)
        agent_name = parsed.get("agent_name", "")

        # Rewrite peername with the agent's attribution IP.
        nextlayer.context.client.peername = (src_ip, src_port)

        if agent_name:
            log.info("PROXY v2: agent=%s ip=%s", agent_name, src_ip)

        # Strip the PROXY header from the buffered events. NextLayer
        # stores DataReceived events in self.events. The header bytes
        # are in the first event(s). Replace the .data on those events
        # with the header stripped.
        remaining = header_len
        for event in nextlayer.events:
            if not isinstance(event, mevents.DataReceived):
                continue
            if event.connection != nextlayer.context.client:
                continue
            if remaining <= 0:
                break
            if remaining >= len(event.data):
                # This entire event's data is part of the header
                remaining -= len(event.data)
                event.data = b""
            else:
                # Header ends partway through this event
                event.data = event.data[remaining:]
                remaining = 0


addons = [ProxyProtocolAddon()]
