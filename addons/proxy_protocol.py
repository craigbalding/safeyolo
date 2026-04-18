"""
proxy_protocol.py — PROXY protocol v2 identity for agent connections.

Monkeypatches mitmproxy's connection accept path to parse a PROXY
protocol v2 header before the HTTP parser runs. The proxy_bridge
prepends this header to every connection, carrying the agent's
assigned IP and name as structured metadata.

This eliminates the need for per-agent lo0 aliases on macOS. The
bridge no longer bind()s to a synthetic loopback IP — identity is
conveyed in-band via the PROXY protocol, with no kernel involvement.

Load order: must be first in the addon chain so the monkeypatch is
installed before any connections arrive.

PROXY protocol v2 binary format:
  12-byte signature + 4 bytes (ver/cmd, fam, len) + address block + TLVs

Custom TLV:
  0xE0 = PP2_TYPE_SAFEYOLO_AGENT — agent name as UTF-8
"""

import asyncio
import logging
import struct
from typing import Any

from mitmproxy.proxy import mode_servers, server

log = logging.getLogger("safeyolo.proxy-protocol")

# -- PROXY protocol v2 constants ------------------------------------------

PP2_SIGNATURE = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
PP2_SIGNATURE_LEN = 12
PP2_HEADER_LEN = 16  # signature (12) + ver_cmd (1) + fam (1) + len (2)

PP2_VERSION = 0x20
PP2_CMD_PROXY = 0x01

PP2_FAM_INET_STREAM = 0x11   # AF_INET + SOCK_STREAM (TCP/IPv4)
PP2_ADDR_LEN_INET = 12       # 4+4+2+2 (src_ip, dst_ip, src_port, dst_port)

PP2_TYPE_SAFEYOLO_AGENT = 0xE0  # custom TLV: agent name (UTF-8)


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

    # Address block: 4-byte src IP, 4-byte dst IP, 2-byte src port, 2-byte dst port
    addr_block = (
        _socket.inet_aton(src_ip)
        + _socket.inet_aton(dst_ip)
        + struct.pack("!HH", src_port, dst_port)
    )

    # TLV: agent name
    tlv_block = b""
    if agent_name:
        name_bytes = agent_name.encode("utf-8")
        # TLV header: type (1 byte) + length (2 bytes big-endian) + value
        tlv_block = struct.pack("!BH", PP2_TYPE_SAFEYOLO_AGENT, len(name_bytes)) + name_bytes

    payload_len = len(addr_block) + len(tlv_block)

    header = (
        PP2_SIGNATURE
        + struct.pack("!BBH", PP2_VERSION | PP2_CMD_PROXY, PP2_FAM_INET_STREAM, payload_len)
        + addr_block
        + tlv_block
    )
    return header


# -- v2 parser -------------------------------------------------------------

def _parse_v2_header(data: bytes) -> dict[str, Any] | None:
    """Parse a PROXY protocol v2 header from raw bytes.

    Returns dict with src_ip, dst_ip, src_port, dst_port, agent_name
    (if TLV 0xE0 present), and header_len (total bytes consumed).
    Returns None if the data is not a valid v2 header.
    """
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

    # Parse address block based on family
    if fam == PP2_FAM_INET_STREAM and len(payload) >= PP2_ADDR_LEN_INET:
        import socket as _socket
        result["src_ip"] = _socket.inet_ntoa(payload[0:4])
        result["dst_ip"] = _socket.inet_ntoa(payload[4:8])
        result["src_port"], result["dst_port"] = struct.unpack("!HH", payload[8:12])

        # Parse TLVs after address block
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


# -- Monkeypatch -----------------------------------------------------------

_installed = False


def _install_monkeypatch() -> None:
    """Wrap handle_stream to parse PROXY protocol v2 before HTTP parsing."""
    global _installed
    if _installed:
        return
    _installed = True

    # Find the server instance class that has handle_stream.
    # On mitmproxy 10+, this is on the metaclass hierarchy. We patch
    # the base that ProxyConnectionHandler's server uses.
    target_cls = None
    for cls in mode_servers.ServerInstance.__mro__:
        if "handle_stream" in cls.__dict__:
            target_cls = cls
            break

    if target_cls is None:
        log.warning("Cannot find handle_stream to monkeypatch — "
                    "PROXY protocol identity will not work")
        return

    orig_handle_stream = target_cls.handle_stream

    async def _patched_handle_stream(self, reader, writer=None):
        # Try to read PROXY protocol v2 header. The 12-byte signature
        # is unambiguous — it cannot be a valid HTTP request start.
        peek = b""
        try:
            peek = await asyncio.wait_for(
                reader.readexactly(PP2_SIGNATURE_LEN),
                timeout=2.0,
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            # Connection closed or timed out before we got enough bytes.
            # Not a PROXY protocol connection — but we may have consumed
            # partial bytes, so wrap the reader to prepend them back.
            if peek:
                reader = _PrependReader(peek, reader)
            return await orig_handle_stream(self, reader, writer)

        if peek != PP2_SIGNATURE:
            # Not PROXY protocol — prepend consumed bytes and proceed
            reader = _PrependReader(peek, reader)
            return await orig_handle_stream(self, reader, writer)

        # Read the rest of the fixed header (4 more bytes)
        try:
            rest_header = await asyncio.wait_for(
                reader.readexactly(4),
                timeout=2.0,
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            log.warning("PROXY v2: incomplete header after signature")
            return

        _, _, payload_len = struct.unpack("!BBH", rest_header)

        # Read the payload (addresses + TLVs)
        try:
            payload = await asyncio.wait_for(
                reader.readexactly(payload_len),
                timeout=2.0,
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            log.warning("PROXY v2: incomplete payload (%d bytes expected)", payload_len)
            return

        full_header = peek + rest_header + payload
        parsed = _parse_v2_header(full_header)

        if parsed and writer is not None:
            src_ip = parsed.get("src_ip", "127.0.0.1")
            src_port = parsed.get("src_port", 0)
            agent_name = parsed.get("agent_name", "")

            # Patch writer.get_extra_info so LiveConnectionHandler.__init__
            # picks up our claimed peername instead of the real TCP source.
            _orig_get = writer.get_extra_info

            def _patched_get(key, default=None, *, _ip=src_ip, _port=src_port, _orig=_orig_get):
                if key == "peername":
                    return (_ip, _port)
                return _orig(key, default)

            writer.get_extra_info = _patched_get

            if agent_name:
                log.info("PROXY v2: agent=%s ip=%s", agent_name, src_ip)

        return await orig_handle_stream(self, reader, writer)

    target_cls.handle_stream = _patched_handle_stream
    log.info("PROXY protocol v2 monkeypatch installed on %s", target_cls.__name__)


class _PrependReader:
    """Wraps an asyncio.StreamReader with bytes prepended to the stream.

    When handle_stream peeks the first 12 bytes and they're NOT a PROXY
    protocol signature, we need to feed them back so the HTTP parser
    sees the complete request. asyncio.StreamReader has no unread(), so
    we wrap it.
    """

    def __init__(self, prepend: bytes, reader: asyncio.StreamReader):
        self._prepend = prepend
        self._reader = reader

    def __getattr__(self, name):
        return getattr(self._reader, name)

    async def read(self, n: int = -1) -> bytes:
        if self._prepend:
            if n < 0:
                data = self._prepend + await self._reader.read(n)
                self._prepend = b""
                return data
            if n <= len(self._prepend):
                data = self._prepend[:n]
                self._prepend = self._prepend[n:]
                return data
            data = self._prepend
            self._prepend = b""
            return data + await self._reader.read(n - len(data))
        return await self._reader.read(n)

    async def readexactly(self, n: int) -> bytes:
        if self._prepend:
            if n <= len(self._prepend):
                data = self._prepend[:n]
                self._prepend = self._prepend[n:]
                return data
            data = self._prepend
            self._prepend = b""
            return data + await self._reader.readexactly(n - len(data))
        return await self._reader.readexactly(n)

    async def readuntil(self, separator: bytes = b"\n") -> bytes:
        if self._prepend:
            idx = self._prepend.find(separator)
            if idx >= 0:
                end = idx + len(separator)
                data = self._prepend[:end]
                self._prepend = self._prepend[end:]
                return data
            data = self._prepend
            self._prepend = b""
            return data + await self._reader.readuntil(separator)
        return await self._reader.readuntil(separator)

    async def readline(self) -> bytes:
        return await self.readuntil(b"\n")


# -- Addon interface -------------------------------------------------------

class ProxyProtocolAddon:
    """mitmproxy addon that installs the PROXY protocol v2 monkeypatch."""

    name = "proxy-protocol"

    def load(self, loader):
        _install_monkeypatch()


addons = [ProxyProtocolAddon()]
