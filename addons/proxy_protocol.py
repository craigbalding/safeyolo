"""
proxy_protocol.py — PROXY protocol v2 identity for agent connections.

Monkeypatches mitmproxy's listen() method to wrap handle_stream with
a PROXY protocol v2 parser. The proxy_bridge prepends a v2 header to
every connection carrying the agent's attribution IP and name. The
parser reads the header before the HTTP parser sees it, rewrites
peername with the agent's IP, and passes the remaining bytes through.

Cross-platform: works identically on macOS and Linux. The bridge
sends the same v2 header regardless of the platform's isolation
mechanism (VZ microVM, gVisor userns).

Load order: must be first in the addon chain so the monkeypatch is
installed before any server starts listening.
"""

import asyncio
import logging
import struct
from typing import Any

from mitmproxy.proxy import mode_servers

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


# -- Monkeypatch -----------------------------------------------------------

_installed = False


def _install_monkeypatch() -> None:
    """Patch listen() to wrap handle_stream with PROXY v2 parsing.

    The patch is installed during addon load(), before the proxy
    server calls listen(). When listen() is called, it wraps
    handle_stream so asyncio.start_server captures the wrapped
    version. The wrapper reads the v2 header from the stream,
    rewrites peername, then delegates to the original handler.
    """
    global _installed
    if _installed:
        return
    _installed = True

    target_cls = mode_servers.AsyncioServerInstance
    orig_listen = target_cls.listen

    async def _pp2_handle_stream(orig_fn, self_inst, reader, writer=None):
        peek = b""
        try:
            peek = await asyncio.wait_for(
                reader.readexactly(PP2_SIGNATURE_LEN),
                timeout=2.0,
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            if peek:
                reader = _PrependReader(peek, reader)
            return await orig_fn(self_inst, reader, writer)

        if peek != PP2_SIGNATURE:
            reader = _PrependReader(peek, reader)
            return await orig_fn(self_inst, reader, writer)

        try:
            rest_header = await asyncio.wait_for(
                reader.readexactly(4), timeout=2.0,
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            log.warning("PROXY v2: incomplete header after signature")
            return

        _, _, payload_len = struct.unpack("!BBH", rest_header)

        try:
            payload = await asyncio.wait_for(
                reader.readexactly(payload_len), timeout=2.0,
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            log.warning("PROXY v2: incomplete payload (%d expected)", payload_len)
            return

        full_header = peek + rest_header + payload
        parsed = _parse_v2_header(full_header)

        if parsed and writer is not None:
            src_ip = parsed.get("src_ip", "127.0.0.1")
            src_port = parsed.get("src_port", 0)
            agent_name = parsed.get("agent_name", "")

            _orig_get = writer.get_extra_info

            def _patched_get(key, default=None, *, _ip=src_ip, _port=src_port, _orig=_orig_get):
                if key == "peername":
                    return (_ip, _port)
                return _orig(key, default)

            writer.get_extra_info = _patched_get

            if agent_name:
                log.info("PROXY v2: agent=%s ip=%s", agent_name, src_ip)

        return await orig_fn(self_inst, reader, writer)

    async def _patched_listen(self, host, port):
        import sys
        print(f"[PP2] _patched_listen called for {host}:{port}", file=sys.stderr, flush=True)
        orig_hs = self.handle_stream.__func__
        log.info("PROXY v2: patching handle_stream for %s:%s", host, port)

        async def _wrapped(reader, writer=None):
            log.info("PROXY v2: handle_stream called")
            return await _pp2_handle_stream(orig_hs, self, reader, writer)

        self.handle_stream = _wrapped
        try:
            result = await orig_listen(self, host, port)
        finally:
            # Don't delete — asyncio.start_server captured the bound
            # reference, but we need to keep it for the lifetime of
            # the server in case Python GC's the closure.
            pass
        return result

    target_cls.listen = _patched_listen
    log.info("PROXY v2 monkeypatch installed on %s.listen", target_cls.__name__)


class _PrependReader:
    """Wraps an asyncio.StreamReader with bytes prepended to the stream."""

    def __init__(self, prepend: bytes, reader):
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

# Install the monkeypatch at IMPORT time — before the addon lifecycle
# starts, before the master creates servers. Script addons are imported
# by mitmdump's ScriptLoader, which happens during configure(). The
# monkeypatch must be in place before ProxyServer.setup_servers() calls
# listen(). Import-time patching guarantees this regardless of addon
# ordering.
_install_monkeypatch()


class ProxyProtocolAddon:
    """mitmproxy addon (placeholder — the monkeypatch is installed at import)."""

    name = "proxy-protocol"


addons = [ProxyProtocolAddon()]
