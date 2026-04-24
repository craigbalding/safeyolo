"""Per-agent UDS ingress for mitmproxy.

Defines a custom ProxyMode + ServerInstance pair so mitmproxy terminates
agent connections directly on a Unix domain socket. Identity comes from
the socket filename (`<ip>_<agent>.sock`) — parsed once at bind, then
stamped onto every accepted connection as `client.peername = (ip, 0)`.

Mode spec: `unix:/absolute/path/to/<ip>_<agent>.sock`.

Loaded first in the addon chain so `UnixMode` is registered via
`ProxyMode.__init_subclass__` before `Proxyserver` parses `options.mode`.

Design note — SO_PEERCRED peer-UID check deferred. Socket-path ownership
(host-user-owned parent directory) is the current identity root. Future
hardening: read SO_PEERCRED at accept() and assert peer UID matches the
expected sandbox user.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from contextlib import suppress
from pathlib import Path
from typing import ClassVar, Literal

from mitmproxy import ctx
from mitmproxy.proxy import layers, mode_specs
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layer import Layer
from mitmproxy.proxy.mode_servers import (
    AsyncioServerInstance,
    ProxyConnectionHandler,
)

log = logging.getLogger("safeyolo.unix-listener")


# Local copy of the filename parser. `cli/src/safeyolo/sockets.py` has
# the same shape; the duplication is deliberate so the addon can be
# loaded by mitmproxy without pulling in the CLI package.
_AGENT_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _parse_sock_path(path: str) -> tuple[str, str]:
    """Return `(ip, agent)` from a socket path `.../<ip>_<agent>.sock`."""
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


class UnixMode(mode_specs.ProxyMode):
    """A SafeYolo per-agent Unix domain socket listener.

    Spec: `unix:/path/to/<ip>_<agent>.sock`. The path is the full socket
    location on disk; identity (ip, agent) is derived from its filename.
    """

    description = "UDS ingress"
    transport_protocol: ClassVar[Literal["tcp", "udp", "both"]] = "tcp"
    # UDS listeners don't bind a TCP port. `default_port=None` + the
    # overrides below keep `Proxyserver.configure`'s duplicate-address
    # dedup check from seeing N unix specs as N listeners on the same
    # host:port (which would abort startup with "Cannot spawn multiple
    # servers on the same address").
    default_port: ClassVar[int | None] = None

    def __post_init__(self) -> None:
        if not self.data:
            raise ValueError("unix mode requires a socket path: `unix:/path/...`")
        if not self.data.startswith("/"):
            raise ValueError(f"unix mode requires an absolute path: {self.data!r}")
        # Validate filename shape by parsing. Result is discarded — we
        # re-parse on demand via the `ip`/`agent` properties so that
        # the socket path remains the single source of truth.
        _parse_sock_path(self.data)

    def listen_host(self, default=None):
        # No IP host for a UDS listener. The socket path is the address.
        return ""

    def listen_port(self, default=None):
        # Return None so Proxyserver.configure skips this mode in its
        # host:port dedup list (see mitmproxy/addons/proxyserver.py —
        # `if port is None: continue`). `LocalMode` / `TunMode` use the
        # same pattern.
        return None

    @property
    def path(self) -> str:
        return self.data

    @property
    def ip(self) -> str:
        return _parse_sock_path(self.data)[0]

    @property
    def agent(self) -> str:
        return _parse_sock_path(self.data)[1]


class _PeeredStreamWriter:
    """Thin shim around `asyncio.StreamWriter` that reports a synthetic
    peername. `asyncio.start_unix_server` hands us a writer whose
    `get_extra_info("peername")` is `""`; mitmproxy's
    `LiveConnectionHandler.__init__` feeds that to
    `human.format_address`, which indexes `address[0]` and crashes
    (`IndexError: string index out of range`). Supplying the
    `(ip, 0)` tuple derived from the listener's socket path lets the
    base class build the `Client` normally and gives downstream addons
    a consistent attribution IP.
    """

    def __init__(self, writer: asyncio.StreamWriter, peername: tuple[str, int]) -> None:
        self._w = writer
        self._peername = peername

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return self._peername
        return self._w.get_extra_info(name, default)

    def __getattr__(self, name):
        # Delegate every other StreamWriter method/attr straight through.
        return getattr(self._w, name)


class UnixInstance(AsyncioServerInstance[UnixMode]):
    """Per-agent UDS listener. One instance per socket file."""

    def make_top_layer(self, context: Context) -> Layer:
        # Same top layer as RegularInstance — agent-side HTTP client
        # issues normal HTTP CONNECT / absolute-form requests.
        return layers.modes.HttpProxy(context)

    async def _start(self) -> None:
        assert not self._servers
        path = self.mode.path
        # Unlink a stale file from a previous run; asyncio.start_unix_server
        # will otherwise fail with EADDRINUSE on the bind() call.
        with suppress(FileNotFoundError):
            Path(path).unlink()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        server = await asyncio.start_unix_server(self.handle_stream, path=path)
        self._servers.append(server)

    async def _stop(self) -> None:
        assert self._servers
        try:
            for s in self._servers:
                s.close()
        finally:
            self._servers = []
            # Remove the socket file so a subsequent _start doesn't see
            # a stale listener entry.
            with suppress(FileNotFoundError, OSError):
                Path(self.mode.path).unlink()

    @property
    def listen_addrs(self) -> tuple:
        # Address tuples in mitmproxy are `(host, port)`. Encoding the
        # UDS path as host keeps the existing log format working
        # (`... listening at /path:0`). The port `0` is a placeholder.
        return ((self.mode.path, 0),)

    async def handle_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter | None = None,
    ) -> None:
        if writer is None:
            # UDS accepted connections always arrive with both halves.
            writer = reader  # pragma: no cover
        peered = _PeeredStreamWriter(writer, (self.mode.ip, 0))
        handler = ProxyConnectionHandler(
            ctx.master, reader, peered, ctx.options, self.mode
        )
        handler.layer = self.make_top_layer(handler.layer.context)
        with self.manager.register_connection(
            handler.layer.context.client.id, handler
        ):
            await handler.handle_client()


# No module-level addon instance needed — mitmproxy's addon loader
# accepts modules that only register ProxyMode/ServerInstance subclasses
# via __init_subclass__. Providing an empty `addons` list satisfies the
# loader while clarifying intent.
addons: list = []
