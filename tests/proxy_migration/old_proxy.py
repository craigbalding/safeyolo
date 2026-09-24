"""Launch the current UDS/network-policy path for migration comparisons.

This is the focused live-test chain, not the full production proxy. The Agent
API handler is opt-in; ordinary transport fixtures exercise its independent
containment while the handler is absent.
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
from safeyolo.mitm_addons.pattern_scanner import PatternScanner
from safeyolo.mitm_addons.probe_sink import ProbeSink
from safeyolo.mitm_addons.request_id import RequestIdGenerator
from safeyolo.mitm_addons.sse_streaming import SSEStreaming
from safeyolo.mitm_addons.transport_guard import TransportGuard
from safeyolo.proxy_modes.unix_listener import ensure_registered


class Observations:
    """Expose response attribution and the pre-DNS server-connect boundary."""

    def __init__(self, config, admin_api=None):
        self.events = Path(config["event_log"])
        self.ready = Path(config["readiness_file"])
        self.admin_api = admin_api

    def write(self, event):
        with self.events.open("a") as stream:
            stream.write(json.dumps(event) + "\n")

    def running(self):
        marker = {"ready": True, "pid": os.getpid(), "backend": "python"}
        if self.admin_api is not None:
            assert self.admin_api.server is not None, "Owned operator listener failed to start"
            marker["admin_port"] = self.admin_api.server.server_address[1]
        self.ready.write_text(json.dumps(marker))

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
    if config.get("fixture_credential_head_decision", False):
        from safeyolo.early_credential_response import install_early_credential_response

        install_early_credential_response()
    ensure_registered()
    configure_policy_client(PolicyClientConfig(baseline_path=config["policy_file"]))
    options = Options(
        mode=[f"unix:{item['socket_path']}" for item in config["listeners"]],
        confdir=config["ca_directory"],
    )
    master = DumpMaster(options, with_termlog=False, with_dumper=False)
    from safeyolo.ignore_hosts import build_ignore_patterns

    master.options.update(connection_strategy=config.get("connection_strategy", "lazy"),
                          ignore_hosts=build_ignore_patterns(config.get("ignore_hosts", [])))
    if "stream_large_bodies" in config:
        master.options.update(stream_large_bodies=config["stream_large_bodies"])
    if config.get("upstream_ca_file"):
        master.options.update(ssl_verify_upstream_trusted_ca=config["upstream_ca_file"])
    admin_api = None
    if config.get("admin_port") is not None:
        from safeyolo.mitm_addons.admin_api import AdminAPI
        from safeyolo.mitm_addons.admin_shield import AdminShield

        admin_api = AdminAPI()
        master.addons.add(AdminShield(), admin_api)
        master.options.update(admin_port=config["admin_port"],
                              admin_api_token_file=config.get("admin_api_token_file", ""))
    master.addons.add(RequestIdGenerator())
    if config.get("fixture_agent_api", False):
        from safeyolo.mitm_addons.agent_api import AgentAPI

        master.addons.add(AgentAPI())
    addons = [AgentAPIRequestGuard(), NetworkGuard(), SSEStreaming()]
    if config.get("fixture_credential_head_decision", False):
        from safeyolo.mitm_addons.credential_guard import CredentialGuard

        addons.append(CredentialGuard())
    master.addons.add(*addons, ProbeSink(), TransportGuard())
    master.options.update(**{name: config[name] for name in (
        "network_guard_enabled", "network_guard_block", "network_guard_homoglyph",
    ) if name in config})
    if "circuit_breaker_enabled" in config:
        from safeyolo.mitm_addons.circuit_breaker import CircuitBreaker

        # The real base addon reads this derived option with a true fallback;
        # CircuitBreaker.load itself registers only its persistence path.
        master.options.add_option("circuit_breaker_enabled", bool, True, "Enable the fixture circuit addon")
        master.addons.add(CircuitBreaker())
        master.options.update(circuit_breaker_enabled=config["circuit_breaker_enabled"],
                              circuit_state_file=config["circuit_state_file"])
    if inspection := config.get("inspection"):
        # The scanner obtains the real LocalPolicyClient sensor projection;
        # its policy source is the same one used by NetworkGuard in this seam.
        if Path(inspection["policy_file"]) != Path(config["policy_file"]):
            raise ValueError("The historical fixture uses one policy file")
        master.addons.add(PatternScanner())
        master.options.update(
            pattern_block_websocket_request=inspection.get("block_websocket_request", False),
            pattern_block_websocket_response=inspection.get("block_websocket_response", False),
        )
    master.addons.add(Observations(config, admin_api))
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
