"""Drive the maintained ingress reader against native policy and trace producers."""

import socket
import threading
from contextlib import closing

import pytest

from tests.blackbox import installed_ingress as host
from tests.blackbox import installed_ingress_pair as pair
from tests.blackbox.host.sinkhole_client import SinkholeClient
from tests.blackbox.isolation import installed_ingress as guest
from tests.proxy_contracts.harness import request
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN, native_instance
from tests.proxy_contracts.test_native_policy_cli import pytestmark as native_platform_marks
from tests.test_blackbox_sinkhole import _load_sinkhole_server

POLICY = '[hosts]\n"httpbin.org" = {egress="allow"}\n"evil.com" = {egress="deny"}\n'
pytestmark = native_platform_marks


@pytest.mark.parametrize("controls", ["", '[controls.network]\nenabled=true\naction="block"\n'])
@pytest.mark.parametrize("agent,peer,source", [("alice", "bob", "10.0.0.2"), ("bob", "alice", "10.0.0.3")])
def test_ingress_native_defaults_trace_and_origin(tmp_path, monkeypatch, controls, agent, peer, source):
    sinkhole = _load_sinkhole_server()
    sinkhole.clear_requests()
    servers = [sinkhole.NoReverseDNSThreadingHTTPServer(("127.0.0.1", 0), handler)
               for handler in (sinkhole.SinkholeHandler, sinkhole.ControlAPIHandler)]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    try:
        with closing(SinkholeClient(f"http://127.0.0.1:{servers[1].server_port}")) as client:
            with native_instance(tmp_path, POLICY + controls, agent_api=True,
                                 parent_proxy=f"http://127.0.0.1:{servers[0].server_port}") as instance:
                policy = host.read_native_policy(str(instance.root / "bin/safeyolo"), instance.root)
                assert host.check_ingress_policy(policy) == {"enabled": True, "action": "block", "homoglyph": True}
                assert policy["sources"]["controls.network.action"] == (str(instance.policy) if controls else "default")

                # Adapt only the guest's TCP transport to this owned UDS.
                # The native proxy produces every response and trace.
                def uds_request(proxy_host, proxy_port, target, headers):
                    status, response_headers, body = request(instance.paths[agent], target, headers=headers)
                    return {"status": status, "headers": [(key.lower(), value) for key, value in response_headers.items()],
                            "body_hex": body.hex()}

                monkeypatch.setattr(guest, "request", uds_request)
                marker = "p1-" + "a" * 32
                peer_source = "10.0.0.3" if agent == "alice" else "10.0.0.2"
                observation = {
                    "guest_socket": str(guest.GUEST_SOCKET), "guest_proxy": guest.GUEST_PROXY,
                    "forwarder": {"pid": 42, "argv": ["/run/sy-proxy-relay", "TCP-LISTEN:8080,bind=127.0.0.1",
                                                      f"UNIX-CONNECT:{guest.GUEST_SOCKET},retry=20"]},
                    "allow": guest.traced_request("unused", 0, agent, f"http://httpbin.org/{marker}", marker, AGENT_TOKEN,
                                                   claimed_agent=peer, claimed_source=peer_source),
                    "deny": guest.traced_request("unused", 0, agent, f"http://evil.com/{marker}-denied", marker, AGENT_TOKEN,
                                                  claimed_agent=peer, claimed_source=peer_source),
                }
                assert host.check_guest_and_origin(observation, client, marker, agent)["denied_origin_deliveries"] == 0
                rows = pair.request_attribution(instance.root / "logs/audit.jsonl", observation, {"agent_id": agent, "ip": source})
                assert len(rows) == 2
                for result in (observation["allow"], observation["deny"]):
                    instance.agent_api(peer, f'/trace?request_id={result["request_id"]}', status=404)
    finally:
        for server, thread in zip(servers, threads, strict=True):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


@pytest.mark.parametrize("control, message", [
    ("enabled=false", "disabled"), ('action="warn"', "does not block"),
])
def test_ingress_refuses_native_disabled_or_warn_control(tmp_path, control, message):
    with native_instance(tmp_path, POLICY + f"[controls.network]\n{control}\n") as instance:
        policy = host.read_native_policy(str(instance.root / "bin/safeyolo"), instance.root)
        with pytest.raises(AssertionError, match=message):
            host.check_ingress_policy(policy)


def test_peer_boundary_rejects_access_and_requires_own_positive_controls(tmp_path, monkeypatch):
    own = tmp_path / "own.sock"
    peer = tmp_path / "peer.sock"
    own_state = tmp_path / "own-state"
    peer_state = tmp_path / "peer-state"
    own_state.write_text("selected")
    peer_state.write_text("peer")
    monkeypatch.setattr(guest, "GUEST_SOCKET", own)
    with socket.socket(socket.AF_UNIX) as own_listener, socket.socket(socket.AF_UNIX) as peer_listener:
        own_listener.bind(str(own))
        own_listener.listen(8)
        peer_listener.bind(str(peer))
        peer_listener.listen(8)
        with pytest.raises(AssertionError, match="private socket"):
            guest.peer_boundary(str(peer), str(peer_state), str(own_state), "selected")
        peer.unlink()
        with pytest.raises(AssertionError, match="private state"):
            guest.peer_boundary(str(peer), str(peer_state), str(own_state), "selected")
        peer_state.unlink()
        result = guest.peer_boundary(str(peer), str(peer_state), str(own_state), "selected")
        assert len(result["refusals"]) == 2
        with pytest.raises(AssertionError, match="positive control"):
            guest.peer_boundary(str(peer), str(peer_state), str(own_state), "wrong")
