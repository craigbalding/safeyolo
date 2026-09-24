"""First shared HTTP contracts; transport/TLS/WS coverage remains explicit."""

import concurrent.futures
import http.client
import json
import socket
import ssl

import pytest
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import connection, launch_proxy, read_events, request
from tests.proxy_migration.run import (
    cancelled_sse_workload,
    concurrent_short_admin_workload,
    short_https_connections,
    streamed_control_workload,
    streamed_slow_admin_workload,
)
from tests.proxy_migration.scenarios import (
    FORGED_REQUEST_ID,
    POLICY,
    network_scenario,
    origin_server,
    request_evidence,
    reserved_scenario,
)
from tests.proxy_migration.test_http2_contract import origin_certificate
from tests.proxy_migration.test_http2_contract import origin_server as tls_origin_server
from tests.proxy_migration.test_websocket_contract import read_head


@pytest.mark.parametrize("parent", [False, True], ids=["direct", "parent"])
def test_two_agent_http_policy_and_attribution(proxy_backend, tmp_path, parent):
    network_scenario(proxy_backend, tmp_path / proxy_backend, parent=parent)


def test_connect_and_inner_request_ids_keep_scoped_connection_evidence(proxy_backend, tmp_path):
    """An admitted tunnel and its inner decision have distinct owned IDs."""
    directory = tmp_path / proxy_backend
    directory.mkdir()
    pem, public = origin_certificate(directory)
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    policy = '''[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { agent = "alice", method = "GET" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
'''
    observations = []
    run = "request-ids-connect"
    with tls_origin_server(pem, ("http/1.1",)) as origin:
        with launch_proxy(proxy_backend, directory, policy, native_policy=True, tls=True,
                          upstream_ca=public, eager_connect=True, agent_api=True,
                          flow_store_enabled=True) as proxy:
            for agent, expected in (("bob", 403), ("alice", 200)):
                before = (origin.accepts, len(origin.requests))
                raw = socket.socket(socket.AF_UNIX)
                raw.settimeout(5)
                try:
                    raw.connect(proxy.paths[agent])
                    connect_request = (f"CONNECT {origin.authority} HTTP/1.1\r\n"
                                       f"Host: {origin.authority}\r\n"
                                       f"X-SafeYolo-Request-Id: {FORGED_REQUEST_ID}\r\n"
                                       "X-SafeYolo-Trace: 1\r\n\r\n").encode()
                    raw.sendall(connect_request)
                    connect_status, connect_headers = read_head(raw)
                    assert connect_status.startswith("HTTP/1.1 200 "), connect_status
                    assert len(connect_headers["x-safeyolo-request-id"]) == 1
                    connect_id = connect_headers["x-safeyolo-request-id"][0]
                    outer = request_evidence(
                        proxy, agent, connect_id, host="127.0.0.1", port=origin.server_address[1],
                        method="CONNECT", status=200, decision="allow", run=run,
                    )
                    assert origin.accepts == before[0] + 1
                    context = ssl.create_default_context(cafile=directory / "ca/mitmproxy-ca-cert.pem")
                    stream = context.wrap_socket(raw, server_hostname="127.0.0.1")
                    client = http.client.HTTPConnection("127.0.0.1", origin.server_address[1], timeout=5)
                    client.sock = stream
                    try:
                        client.request("GET", "/inner", headers={
                            "X-SafeYolo-Agent": "alice" if agent == "bob" else "bob",
                            "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                            "X-SafeYolo-Trace": "1",
                            "X-SafeYolo-Test-Context": f"run={run};agent={agent};test=request-ids",
                        })
                        response = client.getresponse()
                        inner_headers = dict(response.getheaders())
                        body = response.read()
                        assert response.status == expected, body
                        inner_id = {name.lower(): value for name, value in inner_headers.items()}[
                            "x-safeyolo-request-id"]
                        assert inner_id != connect_id
                        inner = request_evidence(
                            proxy, agent, inner_id, host="127.0.0.1", port=origin.server_address[1],
                            method="GET", status=expected,
                            decision="allow" if expected == 200 else "deny", run=run,
                            path="/inner", flow_expected=expected == 200,
                        )
                        assert inner["connection_id"] == outer["connection_id"]
                        assert origin.accepts == before[0] + 1
                        assert len(origin.requests) == before[1] + int(expected == 200)
                        if expected == 200:
                            assert body == b"hello"
                            assert origin.requests[-1]["head"].startswith("GET /inner HTTP/1.1\r\n")
                        observations.append({
                            "agent": agent, "connect_request_hex": connect_request.hex(),
                            "connect_status": connect_status, "connect_headers": connect_headers,
                            "connect_id": connect_id, "outer": outer,
                            "inner_status": expected, "inner_headers": inner_headers,
                            "inner_body_hex": body.hex(), "inner_id": inner_id, "inner": inner,
                            "origin_accepts_before": before[0], "origin_accepts_after": origin.accepts,
                            "origin_requests_before": before[1],
                            "origin_requests_after": list(origin.requests),
                        })
                    finally:
                        client.close()
                finally:
                    raw.close()
            assert observations[0]["outer"]["connection_id"] != observations[1]["outer"]["connection_id"]
            for observation in observations:
                events = [event for event in proxy.events("proxy.request")
                          if event.get("request_id") == observation["inner_id"]]
                assert len(events) == 1 and events[0]["status"] == observation["inner_status"]
                assert events[0]["connection_id"] == observation["inner"]["connection_id"]
                assert events[0]["agent"] == observation["agent"]
        (directory / "connect-request-id-observations.json").write_text(
            json.dumps(observations, indent=2) + "\n"
        )


def test_reserved_hosts_never_resolve_or_contact_parent(proxy_backend, tmp_path):
    reserved_scenario(proxy_backend, tmp_path / proxy_backend)


def test_via_self_loop_stays_local_and_distinct_instance_reaches_parent(proxy_backend, tmp_path):
    """A received Via pseudonym names this instance only when it matches exactly."""
    directory = tmp_path / proxy_backend
    own_token = "fixture-via-instance"
    other_token = own_token + "-peer"
    policy = 'budget = 12000\n[hosts]\n"*" = { egress = "allow" }\n'
    loop_target = "http://target.invalid:8123/loop?canary=fixture-via-canary"
    distinct_target = "http://target.invalid:8123/distinct?canary=fixture-via-canary"
    control_target = "http://control.invalid:8123/control"
    with origin_server() as parent:
        parent_url = f"http://127.0.0.1:{parent.server_address[1]}"
        with launch_proxy(proxy_backend, directory, policy, parent_proxy=parent_url,
                          native_policy=True, via_token=own_token) as proxy:
            results = []
            for target, via, expected_status, expected_accepts in (
                (loop_target, f"1.0 earlier-instance, 1.1 {own_token.upper()}", 508, 0),
                (distinct_target, f"1.1 {other_token}", 200, 1),
                (control_target, None, 200, 2),
            ):
                headers = {"X-Fixture-Canary": "fixture-via-canary"}
                if via is not None:
                    headers["Via"] = via
                status, response_headers, body = request(
                    proxy.paths["alice"], target, headers=headers,
                )
                response_headers = {key.lower(): value for key, value in response_headers.items()}
                identifier = response_headers.get("x-safeyolo-request-id")
                assert identifier and identifier.startswith("req-")
                assert status == expected_status, (status, body, parent.accepts, parent.requests)
                assert parent.accepts == expected_accepts
                assert len(parent.requests) == expected_accepts
                assert len(proxy.events("proxy.egress")) == expected_accepts
                if expected_status == 508:
                    assert response_headers["x-blocked-by"] == "loop-guard"
                    assert b"proxy loop" in body.lower()
                else:
                    assert body == b"hello"
                results.append({"target": target, "via": via, "status": status,
                                "request_id": identifier})

            events = proxy.events("proxy.request")
            assert len(events) == 3
            for result, event in zip(results, events, strict=True):
                assert event["request_id"] == result["request_id"]
                assert event["agent"] == "alice"
                assert (event["host"], event["port"], event["status"]) == (
                    "control.invalid" if result["target"] == control_target else "target.invalid",
                    8123, result["status"],
                )
            assert [event["decision"] for event in events] == ["deny", "allow", "allow"]
            assert len({result["request_id"] for result in results}) == 3
            assert [item["target"] for item in parent.requests] == [
                distinct_target, control_target,
            ]
            assert parent.canary_headers == ["fixture-via-canary"] * 2
            assert len(parent.via_headers) == 2
            forwarded_via = ", ".join(parent.via_headers[0]).lower()
            assert f"1.1 {other_token}" in forwarded_via
            assert f"1.1 {own_token}" in forwarded_via
            assert f"1.1 {own_token}" in ", ".join(parent.via_headers[1]).lower()
            audit = read_events(directory / "audit.jsonl")
            loop_audit = [row for row in audit if row.get("request_id") == results[0]["request_id"]]
            if proxy_backend == "python":
                assert any(row["event"] == "security.loop_guard" and row["agent"] == "alice"
                           and row["decision"] == "deny" for row in loop_audit)
            else:
                assert any(row["event"] == "traffic.response" and row["agent"] == "alice"
                           and row["details"]["blocked_by"] == "loop-guard"
                           and row["details"]["block_reason"] == "proxy_loop"
                           for row in loop_audit)
            (directory / "via-loop-observation.json").write_text(json.dumps({
                "requests": results,
                "parent_accepts": parent.accepts,
                "parent_requests": parent.requests,
                "parent_via_headers": parent.via_headers,
                "parent_canary_headers": parent.canary_headers,
                "proxy_requests": events,
                "proxy_egress": proxy.events("proxy.egress"),
                "loop_audit": loop_audit,
            }, indent=2) + "\n")


def test_streamed_response_delivers_before_release_and_keeps_control_live(proxy_backend, tmp_path):
    result = streamed_control_workload(proxy_backend, tmp_path / proxy_backend)
    assert result["first_event_before_release"] is True
    assert result["control_completed_before_stream_release"] is True
    assert result["stream_released_after_control"] is True
    assert result["origin_observation"]["stream_finished_after_read"] is True


def test_slow_consumer_keeps_allowed_request_and_authenticated_admin_live(proxy_backend, tmp_path):
    result = streamed_slow_admin_workload(proxy_backend, tmp_path / proxy_backend)
    assert result["first_event_before_origin_completion"] is True
    assert result["control_completed_while_stream_active"] is True
    assert result["request_counts"] == {
        "origin_requests": 2,
        "origin_error_responses": 0,
        "proxy_request_events": 2,
        "proxy_error_responses": 0,
        "allowed_control_requests": 1,
        "authenticated_admin_operations": 1,
        "authenticated_admin_errors": 0,
    }
    assert result["admin"]["authenticated"] is True
    assert result["admin"]["status"] == 200
    assert result["admin"]["completed_while_stream_active"] is True
    assert result["origin_observation"]["stream_finished_after_read"] is True


def test_repeated_concurrent_short_requests_keep_authenticated_admin_live(proxy_backend, tmp_path):
    result = concurrent_short_admin_workload(proxy_backend, tmp_path / proxy_backend, 24, 8, 3)
    assert result["completed"] == 72
    assert result["failed_or_incomplete"] == 0
    assert result["origin_observation"]["accepted_connections"] == 72
    assert result["proxy_observation"] == {"request_events": 72, "error_responses": 0}
    assert all(batch["admin"]["started_while_batch_active"] for batch in result["batches_result"])
    assert all(batch["admin"]["completed_while_batch_active"] for batch in result["batches_result"])
    assert all(batch["admin"]["unauthenticated_status"] == 401 for batch in result["batches_result"])
    assert all(batch["admin"]["authenticated_status"] == 200 for batch in result["batches_result"])


def test_short_https_requests_record_counts_latency_resources_and_control(proxy_backend, tmp_path):
    result = short_https_connections(proxy_backend, tmp_path / proxy_backend, 8)
    assert result["workload"] == "sequential_short_https_connections"
    assert result["requests"] == 8
    assert result["completed"] == 8
    assert result["failed_or_incomplete"] == 0
    counts = result["request_counts"]
    assert counts["measured"] == {"expected": 8, "completed": 8, "failed_or_incomplete": 0}
    assert counts["control"] == {"expected": 1, "completed": 1, "failed_or_incomplete": 0}
    assert counts["total"]["expected"] == counts["total"]["origin_requests"] == 9
    assert counts["total"]["proxy_request_events"] == 9
    assert counts["total"]["proxy_events_total"] == 9 + (9 if proxy_backend == "rust" else 0)
    assert counts["total"]["connect_events"] == (9 if proxy_backend == "rust" else 0)
    assert counts["total"]["error_responses"] == 0
    assert len(result["latency_samples_ms"]) == 8
    assert result["control_observation"]["status"] == 200
    assert result["control_observation"]["body_bytes"] == 5
    assert len(result["resource_samples"]) >= 5
    assert len(result["origin_observation"]["requests"]) == 9
    assert result["proxy_observation"]["request_events"] == 9
    if proxy_backend == "rust":
        provenance = result["proxy_identity"]["native_policy_provenance"]["payload"]
        assert provenance["policy_mode"] == "native"
        assert provenance["temporary_policy_adapter"] is False


def test_short_requests_report_warmup_quiet_and_repeated_resource_phases(proxy_backend, tmp_path):
    result = concurrent_short_admin_workload(
        proxy_backend,
        tmp_path / proxy_backend,
        8,
        4,
        3,
        warmup=4,
        quiet_seconds=0.25,
    )
    assert result["warmup"]["requests"] == 4
    assert result["warmup"]["completed"] == 4
    assert result["warmup"]["failed_or_incomplete"] == 0
    assert result["quiet"]["elapsed_seconds"] >= 0.25
    assert result["quiet"]["origin_connections_before"] == 4
    assert result["quiet"]["origin_connections_after"] == 4
    assert result["quiet"]["proxy_request_events_before"] == 4
    assert result["quiet"]["proxy_request_events_after"] == 4
    assert result["origin_observation"]["expected_requests"] == 28
    assert result["request_counts"] == {
        "warmup": {"expected": 4, "completed": 4, "failed_or_incomplete": 0},
        "measured": {"expected": 24, "completed": 24, "failed_or_incomplete": 0},
        "total": {
            "expected": 28,
            "origin_connections": 28,
            "proxy_request_events": 28,
            "error_responses": 0,
        },
    }
    assert len(result["warmup"]["latency_samples_ms"]) == 4
    assert len(result["batches_result"]) == 3
    assert all(batch["completed"] == 8 for batch in result["batches_result"])
    assert all(batch["failed_or_incomplete"] == 0 for batch in result["batches_result"])
    assert all(batch["runtime_resources"]["before_batch"] for batch in result["batches_result"])
    assert all(batch["runtime_resources"]["during_batch"] for batch in result["batches_result"])
    assert all(batch["runtime_resources"]["after_batch"] for batch in result["batches_result"])
    if proxy_backend == "rust":
        provenance = result["proxy_identity"]["native_policy_provenance"]["payload"]
        assert provenance["policy_mode"] == "native"
        assert provenance["temporary_policy_adapter"] is False


def test_cancelled_sse_releases_upstream_and_keeps_other_request_live(proxy_backend, tmp_path, request):
    if proxy_backend == "python":
        # The comparator currently drains this response after the downstream
        # close.  Keep that concrete known defect visible as a strict xfail;
        # native Rust must still execute and pass the same assertions.
        request.node.add_marker(pytest.mark.xfail(
            strict=True,
            reason="Python comparator does not cancel the held upstream SSE after downstream close",
        ))
    result = cancelled_sse_workload(proxy_backend, tmp_path / proxy_backend)
    assert result["first_event_before_release"] is True
    assert result["downstream_closed_before_release"] is True
    assert result["control_status"] == 200
    assert result["control_completed_while_stream_held"] is True
    assert result["origin_observation"]["stream_cancelled"] is True
    assert result["origin_observation"]["write_error"] in {
        "BrokenPipeError",
        "ConnectionResetError",
        "OSError",
    }
    assert result["origin_observation"]["stream_bytes_sent_after_release"] < (
        result["origin_observation"]["stream_chunks_available"] * 16384
    )
    assert result["origin_observation"]["stream_finished_after_cancel"] is True
    events = [event for event in read_events(tmp_path / proxy_backend / "events.jsonl")
              if event.get("event") == "proxy.request"]
    assert len(events) == 2
    assert all(int(event.get("status", 500)) == 200 for event in events)


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
