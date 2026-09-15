"""Launch the current UDS/network-policy path for migration comparisons.

This is the focused live-test chain, not the full production proxy. The Agent
API handler is deliberately absent, exercising its independent containment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
from pathlib import Path

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from pdp import PolicyClientConfig, configure_policy_client
from safeyolo.core.audit_writer import get_writer
from safeyolo.core.internal_api import is_agent_api_host
from safeyolo.core.probe import is_probe_host
from safeyolo.mitm_addons.agent_api_guard import AgentAPIRequestGuard
from safeyolo.mitm_addons.network_guard import NetworkGuard
from safeyolo.mitm_addons.probe_sink import ProbeSink
from safeyolo.mitm_addons.request_id import RequestIdGenerator
from safeyolo.mitm_addons.sse_streaming import SSEStreaming
from safeyolo.mitm_addons.transport_guard import TransportGuard
from safeyolo.proxy_modes.unix_listener import ensure_registered


class Observations:
    """Expose response attribution and the pre-DNS server-connect boundary."""

    def __init__(self, config):
        self.events = Path(config["event_log"])
        self.ready = Path(config["readiness_file"])

    def write(self, event):
        with self.events.open("a") as stream:
            stream.write(json.dumps(event) + "\n")

    def running(self):
        self.ready.write_text(json.dumps({"ready": True, "pid": os.getpid(), "backend": "python"}))

    def response(self, flow):
        assert get_writer().wait_for_drain(timeout_s=2)
        host = flow.request.host
        local = is_agent_api_host(host) or is_probe_host(host)
        self.write({
            "event": "proxy.request",
            "agent": flow.metadata.get("agent"),
            "request_id": flow.metadata.get("request_id"),
            "connection_id": flow.client_conn.id,
            "host": host,
            "port": flow.request.port,
            "status": flow.response.status_code,
            "decision": "local" if local else ("deny" if flow.metadata.get("blocked_by") else "allow"),
        })

    def server_connect(self, data):
        # mitmproxy emits this hook before resolution/socket connection. Record
        # the hook itself, including failures; do not infer successful contact.
        self.write({
            "event": "proxy.egress",
            "agent": getattr(data.client.proxy_mode, "agent", None),
            "connection_id": data.client.id,
            "host": data.server.address[0],
            "port": data.server.address[1],
            "observation": "mitmproxy.server_connect",
        })


async def run(config):
    ensure_registered()
    configure_policy_client(PolicyClientConfig(baseline_path=config["policy_file"]))
    options = Options(
        mode=[f"unix:{item['socket_path']}" for item in config["listeners"]],
        confdir=config["ca_directory"],
    )
    master = DumpMaster(options, with_termlog=False, with_dumper=False)
    master.options.update(connection_strategy="lazy")
    if config.get("upstream_ca_file"):
        master.options.update(ssl_verify_upstream_trusted_ca=config["upstream_ca_file"])
    master.addons.add(
        RequestIdGenerator(), AgentAPIRequestGuard(), NetworkGuard(),
        SSEStreaming(), ProbeSink(), TransportGuard(), Observations(config),
    )
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, master.shutdown)
    try:
        await master.run()
    finally:
        Path(config["readiness_file"]).unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(json.loads(args.config.read_text())))
