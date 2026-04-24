"""Populate mitmproxy's mode list from agent_map.json at startup.

Why this exists: mitmproxy parses `--set mode=unix:...` on the CLI
*before* `-s unix_listener.py` imports and registers `UnixMode` via
`__init_subclass__`, so the CLI path rejects the spec as unknown. We
work around that by passing no mode on the CLI (mitmproxy defaults to
`regular` on `listen_port=0`, an ephemeral loopback bind), then replace
it here in `running()` — at which point every addon has loaded and
`UnixMode` is registered.

Runtime add/remove uses the same pattern: `PUT /admin/proxy/mode` in
admin_api.py schedules the options update onto the event loop.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
from pathlib import Path

from mitmproxy import ctx

log = logging.getLogger("safeyolo.bootstrap-mode")

# Mirror commands/agent.py::_validate_instance_name so we skip entries
# with malformed names rather than crash the listener list.
_AGENT_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _data_dir() -> Path:
    override = os.environ.get("SAFEYOLO_DATA_DIR")
    if override:
        return Path(override)
    return Path.home() / ".safeyolo" / "data"


def _build_specs() -> list[str]:
    data_dir = _data_dir()
    map_path = data_dir / "agent_map.json"
    if not map_path.exists():
        return []
    try:
        data = json.loads(map_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("cannot read %s: %s: %s", map_path, type(exc).__name__, exc)
        return []
    sockets_dir = data_dir / "sockets"
    sockets_dir.mkdir(parents=True, exist_ok=True)
    specs: list[str] = []
    for name, entry in data.items():
        ip = entry.get("ip") if isinstance(entry, dict) else None
        if not ip or not _AGENT_NAME_RE.match(name):
            log.warning("skipping malformed agent_map entry: name=%r ip=%r", name, ip)
            continue
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            log.warning("skipping agent %r: invalid ip %r", name, ip)
            continue
        specs.append(f"unix:{sockets_dir}/{ip}_{name}.sock")
    return specs


class BootstrapMode:
    async def running(self) -> None:
        specs = _build_specs()
        ctx.options.update(mode=specs)
        # Yield so Servers.update (the coroutine fired by the options
        # changed signal) gets scheduled and the old `regular` listener
        # tears down before subsequent `running` hooks fire (e.g. pid
        # writer, which marks the CLI as ready). 0.5s is generous for a
        # handful of agents on local sockets and doesn't bottleneck
        # startup on realistic agent counts.
        await asyncio.sleep(0.5)
        log.info("bootstrap_mode: %d UDS listener(s) configured", len(specs))


addons = [BootstrapMode()]
