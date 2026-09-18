"""First shared HTTP contracts; transport/TLS/WS coverage remains explicit."""

import concurrent.futures

import pytest

from tests.proxy_migration.harness import connection, launch_proxy, request
from tests.proxy_migration.scenarios import POLICY, network_scenario, origin_server, reserved_scenario


@pytest.mark.parametrize("parent", [False, True], ids=["direct", "parent"])
def test_two_agent_http_policy_and_attribution(proxy_backend, tmp_path, parent):
    network_scenario(proxy_backend, tmp_path / proxy_backend, parent=parent)


def test_reserved_hosts_never_resolve_or_contact_parent(proxy_backend, tmp_path):
    reserved_scenario(proxy_backend, tmp_path / proxy_backend)


def test_concurrent_policy_decisions_keep_agent_scope(proxy_backend, tmp_path):
    """Exercise the real policy process beyond its Unix accept queue depth."""
    with origin_server() as origin:
        url = f"http://127.0.0.1:{origin.server_address[1]}/concurrent"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            def send(index):
                agent = "alice" if index % 2 == 0 else "bob"
                status, headers, body = request(proxy.paths[agent], url)
                expected = 200 if agent == "alice" else 403
                assert status == expected, (agent, status, body)
                if expected == 200:
                    assert body == b"hello"
                response_headers = {key.lower(): value for key, value in headers.items()}
                return agent, status, response_headers["x-safeyolo-request-id"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                outcomes = list(workers.map(send, range(160)))

        by_request = {identifier: (agent, status) for agent, status, identifier in outcomes}
        assert len(by_request) == 160
        events = proxy.events("proxy.request")
        assert len(events) == 160
        for event in events:
            assert by_request[event["request_id"]] == (event["agent"], event["status"])
            assert event["decision"] == ("allow" if event["agent"] == "alice" else "deny")
        egress = proxy.events("proxy.egress")
        assert len(egress) == 80
        assert all(event["agent"] == "alice" for event in egress)
        assert len(origin.requests) == origin.accepts == 80


def _persistent_request(client, url, *, forged_agent):
    client.request(
        "GET",
        url,
        headers={
            "Connection": "keep-alive",
            "X-SafeYolo-Agent": forged_agent,
        },
    )
    response = client.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()


def test_persistent_http1_requests_keep_routing_and_identity_isolated(proxy_backend, tmp_path):
    """Each trusted UDS identity keeps its scope across persistent HTTP/1.1."""
    with origin_server(keep_alive=True) as origin:
        target = f"http://127.0.0.1:{origin.server_address[1]}"
        with launch_proxy(proxy_backend, tmp_path / proxy_backend, POLICY) as proxy:
            alice = connection(proxy.paths["alice"])
            bob = connection(proxy.paths["bob"])
            try:
                alice_socket = alice.sock
                bob_socket = bob.sock
                alice_results = [
                    _persistent_request(alice, f"{target}/first?part=one", forged_agent="bob"),
                    _persistent_request(alice, f"{target}/second?part=two%2Fthree", forged_agent="bob"),
                ]
                bob_results = [
                    _persistent_request(bob, f"{target}/denied-one", forged_agent="alice"),
                    _persistent_request(bob, f"{target}/denied-two", forged_agent="alice"),
                ]
                assert alice.sock is alice_socket
                assert bob.sock is bob_socket
            finally:
                alice.close()
                bob.close()

        assert alice_results == [(200, b"hello"), (200, b"hello")]
        assert all(status == 403 for status, _ in bob_results)
        assert [request["target"] for request in origin.requests] == [
            "/first?part=one",
            "/second?part=two%2Fthree",
        ]
        assert origin.accepts >= 1
        assert all(request["connection_id"] for request in origin.requests)

    events = proxy.events("proxy.request")
    assert len(events) == 4
    assert [event["agent"] for event in events] == ["alice", "alice", "bob", "bob"]
    assert [event["status"] for event in events] == [200, 200, 403, 403]
    alice_event_ids = {event["connection_id"] for event in events[:2]}
    bob_event_ids = {event["connection_id"] for event in events[2:]}
    assert len(alice_event_ids) == len(bob_event_ids) == 1
    assert alice_event_ids.isdisjoint(bob_event_ids)
    egress = proxy.events("proxy.egress")
    assert egress
    assert all(event["agent"] == "alice" for event in egress)
