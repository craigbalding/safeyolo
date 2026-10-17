"""Origin observations of intercepted H2 sessions and delayed request completion."""

import threading
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, monotonic_ns

import h2.config
import h2.connection
import h2.events
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from safeyolo.rust_proxy import _ensure_signing_ca
from tests.proxy_contracts.harness import launch_proxy
from tests.proxy_contracts.run import runtime_resources
from tests.proxy_contracts.test_http2_contract import (
    MIXED_STREAM_POLICY,
    POLICY,
    headers,
    origin_certificate,
    origin_server,
    tls_tunnel,
)
from tests.proxy_contracts.test_native_network_policy import replace_policy


class GatedClient:
    """One generator serves direct and intercepted connections without a bypass."""

    def __init__(self, stream, authority):
        self.stream = stream
        self.authority = authority
        self.connection = h2.connection.H2Connection(config=h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8"))
        self.connection.initiate_connection()
        self.results = {}
        self.next_id = 1
        self.withheld_ack = set()
        self.flush()
        # Wait for the peer's initial SETTINGS before staging the full batch.
        while not self.connection.remote_settings.max_concurrent_streams < 2**32:
            self.receive()

    def flush(self):
        if data := self.connection.data_to_send():
            self.stream.sendall(data)

    def receive(self):
        data = self.stream.recv(65536)
        assert data, self.results
        for event in self.connection.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                self.results[event.stream_id]["headers"] = dict(event.headers)
            elif isinstance(event, h2.events.DataReceived):
                self.results[event.stream_id]["body"].extend(event.data)
                if event.stream_id in self.withheld_ack:
                    # Replenish connection capacity while withholding only this
                    # stream's receive window, so siblings can still progress.
                    self.connection.increment_flow_control_window(event.flow_controlled_length)
                else:
                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, h2.events.StreamEnded):
                self.results[event.stream_id]["ended"] = True
            elif isinstance(event, h2.events.StreamReset):
                self.results[event.stream_id]["reset"] = int(event.error_code)
            elif isinstance(event, h2.events.ConnectionTerminated):
                pytest.fail(f"unexpected GOAWAY: {event}")
        self.flush()

    def stage(self, count, batch, *, body=b"prefix!", extra=()):
        identifiers = []
        assert count <= self.connection.remote_settings.max_concurrent_streams
        for index in range(count):
            identifier = self.next_id
            self.next_id += 2
            identifiers.append(identifier)
            self.results[identifier] = {"headers": {}, "body": bytearray(), "ended": False}
            request = headers(self.authority, f"/h2-mixed/gate/{batch}/{index}", [
                ("content-length", str(len(body))), *extra,
            ])
            request[0] = (":method", "POST" if body else "GET")
            self.connection.send_headers(identifier, request, end_stream=False)
            if body:
                self.connection.send_data(identifier, body[:-1])
        self.flush()
        return identifiers

    def release(self, identifiers, *, body=b"prefix!"):
        for identifier in identifiers:
            self.connection.send_data(identifier, body[-1:], end_stream=True)
        self.flush()

    def wait(self, identifiers):
        deadline = monotonic() + 10
        while not all(self.results[identifier]["ended"] for identifier in identifiers):
            assert monotonic() < deadline, self.results
            try:
                self.receive()
            except TimeoutError:
                pytest.fail(f"H2 response stalled: {[(identifier, self.results[identifier]) for identifier in identifiers]}")
        return [self.results[identifier] for identifier in identifiers]

    def finish(self, identifiers):
        results = self.wait(identifiers)
        for result in results:
            assert result["headers"][":status"] == "200", result
        return results


def wait_staged(origin, paths, body):
    with origin.changed:
        assert origin.changed.wait_for(
            lambda: len(rows := [row for row in origin.requests if row[":path"] in paths]) == len(paths)
            and all(bytes(row["body"]) == body[:-1] and not row.get("ended") for row in rows),
            timeout=5,
        ), [(row[":path"], bytes(row["body"]), row.get("ended")) for row in origin.requests]
        rows = [row for row in origin.requests if row[":path"] in paths]
        assert len({row["connection_id"] for row in rows}) == 1
        assert len({row["stream_id"] for row in rows}) == len(paths)
        assert {row["alpn"] for row in rows} == {"h2"}
        return rows


@pytest.mark.parametrize("count", [2, 20, 30])
@pytest.mark.parametrize("body", [b"prefix!", b""])
def test_cold_and_warm_h2_streams_reach_origin_before_gate(proxy_backend, tmp_path, count, body):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        assert stream.selected_alpn_protocol() == "h2"
        client = GatedClient(stream, origin.authority)
        for batch in ("cold", "warm"):
            identifiers = client.stage(count, batch, body=body)
            paths = {f"/h2-mixed/gate/{batch}/{index}" for index in range(count)}
            rows = wait_staged(origin, paths, body)
            staged_at = monotonic_ns()
            # No traffic or fabricated terminal may arrive during the hold.
            with origin.changed:
                assert not origin.changed.wait_for(lambda: any(row.get("ended") for row in rows), timeout=0.2)
                assert all(bytes(row["body"]) == body[:-1] for row in rows)
            client.release(identifiers, body=body)
            results = client.finish(identifiers)
            assert [bytes(result["body"]) for result in results] == [
                f"/h2-mixed/gate/{batch}/{index}".encode() for index in range(count)
            ]
            with origin.lock:
                assert all(bytes(row["body"]) == body and row["ended_ns"] - staged_at >= 200_000_000 for row in rows)
                assert origin.accepts == 1
                assert len({row["connection_id"] for row in origin.requests}) == 1
        events = proxy.events("proxy.request")
        inner = [row for row in events if row.get("coverage") == "native_network_guard_circuits_and_test_context"]
        assert len(inner) == 2 * count
        assert len({row["request_id"] for row in inner}) == 2 * count
        assert {row["agent"] for row in inner} == {"alice"}


def test_gated_stream_keeps_snapshot_while_new_streams_observe_reload(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        admitted = client.stage(20, "before-reload")
        rows = wait_staged(origin, {f"/h2-mixed/gate/before-reload/{index}" for index in range(20)}, b"prefix!")
        replace_policy(proxy, proxy_backend, directory, POLICY.replace('effect = "allow"', 'effect = "deny"'))
        denied = client.stage(1, "denied-after-reload")
        assert client.wait(denied)[0]["headers"][":status"] == "403"
        assert not any(row.get("ended") for row in rows)
        client.release(admitted)
        client.finish(admitted)
        replace_policy(proxy, proxy_backend, directory, POLICY + "\n# new admitted snapshot\n")
        new = client.stage(20, "new-generation")
        newer = wait_staged(origin, {f"/h2-mixed/gate/new-generation/{index}" for index in range(20)}, b"prefix!")
        assert newer[0]["connection_id"] != rows[0]["connection_id"]
        client.release(new)
        client.finish(new)
        assert origin.accepts == 2
        assert len(origin.requests) == 40


def test_stalled_old_tls_handshake_does_not_hold_new_runtime_session(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    release = threading.Event()
    with origin_server(pem, first_tls_gate=release) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        first = client.stage(1, "old-handshake")
        assert origin.first_tls_hello.wait(timeout=5)
        replace_policy(proxy, proxy_backend, directory, POLICY + "\n# new runtime\n")
        second = client.stage(1, "new-handshake")
        new = wait_staged(origin, {"/h2-mixed/gate/new-handshake/0"}, b"prefix!")
        assert not release.is_set()
        release.set()
        old = wait_staged(origin, {"/h2-mixed/gate/old-handshake/0"}, b"prefix!")
        assert old[0]["connection_id"] != new[0]["connection_id"]
        client.release(first + second)
        client.finish(first + second)


def test_held_and_mixed_policy_streams_do_not_share_approval_or_budget(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    policy = '''budget = 12000
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "deny"
condition = { agent = "alice", path_prefix = "/h2-mixed/gate/deny" }
[[permissions]]
action = "network:request"
resource = "127.0.0.1/*"
effect = "budget"
budget = 1
condition = { agent = "alice", path_prefix = "/h2-mixed/gate/limited" }
''' + MIXED_STREAM_POLICY.removeprefix("budget = 12000\n")
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, policy, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        allowed = client.stage(20, "allowed", extra=[("x-safeyolo-agent", "bob")])
        wait_staged(origin, {f"/h2-mixed/gate/allowed/{index}" for index in range(20)}, b"prefix!")
        denied = client.stage(1, "deny")
        approval = client.stage(1, "approval", extra=[("authorization", "Bearer key-approve")])
        # The existing rate=1 burst permits two requests. Pool reuse must not
        # spend an extra token, or skip a per-request charge.
        limited = client.stage(3, "limited")
        client.release(limited)
        results = client.wait(denied + approval + limited)
        assert [row["headers"][":status"] for row in results[:2]] == ["403", "428"]
        assert sorted(row["headers"][":status"] for row in results[2:]) == ["200", "200", "429"]
        with origin.lock:
            assert len(origin.requests) == 22
            assert not any(row.get("ended") for row in origin.requests if "/allowed/" in row[":path"])
            assert all("authorization" not in row for row in origin.requests)
        client.release(allowed)
        client.finish(allowed)
        assert origin.accepts == 1
        assert {row["agent"] for row in proxy.events("proxy.request")} == {"alice"}


@pytest.mark.parametrize("budget", ["global", "host"])
def test_shared_h2_charges_each_global_or_host_budget_once_and_keeps_reload_state(proxy_backend, tmp_path, budget):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    policy = ('budget = 1\n[hosts]\n"*" = { egress = "allow" }\n' if budget == "global"
              else 'budget = 12000\n[hosts]\n"127.0.0.1" = { egress = "allow", rate = 1 }\n')
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, policy, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        identifiers = client.stage(3, "shared-budget")
        with origin.changed:
            # CONNECT has its existing separate counter. The request budget's
            # rate=1 burst admits two streams, each with one charge.
            assert origin.changed.wait_for(lambda: len(origin.requests) == 2, timeout=5)
            assert not origin.changed.wait_for(lambda: any(row.get("ended") for row in origin.requests), timeout=0.2)
        replace_policy(proxy, proxy_backend, directory, policy + "\n# retain consumed budget\n")
        after_reload = client.stage(1, "budget-after-reload")
        assert client.wait(after_reload)[0]["headers"][":status"] == "429"
        admitted = [identifiers[int(row[":path"].rsplit("/", 1)[1])] for row in origin.requests]
        client.release(admitted)
        assert sorted(row["headers"][":status"] for row in client.wait(identifiers)) == ["200", "200", "429"]
        assert len(origin.requests) == 2
        assert all(row.get("ended") for row in origin.requests)
        assert origin.accepts == 1


def test_upstream_settings_limit_and_request_reset_keep_staged_siblings(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem, max_streams=2) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        identifiers = client.stage(20, "settings")
        with origin.changed:
            assert origin.changed.wait_for(lambda: len(origin.requests) == 2, timeout=5)
            assert not origin.changed.wait_for(lambda: len(origin.requests) > 2, timeout=0.2)
            cancelled = origin.requests[0]
        index = int(cancelled[":path"].rsplit("/", 1)[1])
        client.connection.reset_stream(identifiers[index])
        client.flush()
        with origin.changed:
            assert origin.changed.wait_for(lambda: "reset_code" in cancelled and len(origin.requests) == 3, timeout=5)
            assert not cancelled.get("ended")
        survivors = [identifier for identifier in identifiers if identifier != identifiers[index]]
        client.release(survivors)
        client.finish(survivors)
        assert origin.accepts == 1
        assert len(origin.requests) == 20
        assert sum(row.get("ended", False) for row in origin.requests) == 19
        assert not cancelled.get("ended")


def test_stalled_h2_response_reader_does_not_hold_gated_siblings(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    size = 8 * 1024 * 1024
    with origin_server(pem, response_bytes=size) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        slow = client.stage(1, "slow-reader", body=b"")
        client.withheld_ack.update(slow)
        client.release(slow, body=b"")
        while not client.results[slow[0]]["body"]:
            client.receive()
        with origin.changed:
            record = next(row for row in origin.requests if "/slow-reader/" in row[":path"])
            assert not origin.changed.wait_for(lambda: record.get("response_bytes_sent") == size, timeout=0.2)
        gated = client.stage(20, "while-reader-stalled")
        wait_staged(origin, {f"/h2-mixed/gate/while-reader-stalled/{index}" for index in range(20)}, b"prefix!")
        client.release(gated)
        client.finish(gated)
        assert not client.results[slow[0]]["ended"]
        held_bytes = len(client.results[slow[0]]["body"])
        client.connection.increment_flow_control_window(held_bytes, stream_id=slow[0])
        client.withheld_ack.clear()
        client.flush()
        assert len(client.finish(slow)[0]["body"]) == size
        assert origin.accepts == 1


def test_goaway_reconnects_without_replaying_requests(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem, goaway_after=20) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        for batch in ("before-goaway", "after-goaway"):
            identifiers = client.stage(20, batch)
            wait_staged(origin, {f"/h2-mixed/gate/{batch}/{index}" for index in range(20)}, b"prefix!")
            client.release(identifiers)
            client.finish(identifiers)
        assert origin.accepts == 2
        assert len(origin.requests) == len({row[":path"] for row in origin.requests}) == 40


def test_h2_to_h1_fallback_keeps_small_request_completion_barrier(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem, protocols=("http/1.1",)) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        cancelled = client.stage(1, "h1-cancel", body=b"")
        with origin.changed:
            assert not origin.changed.wait_for(lambda: bool(origin.requests), timeout=0.2)
        client.connection.reset_stream(cancelled[0], error_code=0)
        client.flush()
        sibling = client.stage(1, "h1-allowed", body=b"")
        client.release(sibling, body=b"")
        client.finish(sibling)
        assert len(origin.requests) == 1
        assert "/h1-allowed/" in origin.requests[0]["head"]


@pytest.mark.parametrize("reset_code", [0, 8])
@given(cancelled=st.sets(st.integers(min_value=0, max_value=19), min_size=1, max_size=8))
@settings(max_examples=6, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_reset_request_never_becomes_origin_eom_while_siblings_continue(proxy_backend, tmp_path, reset_code, cancelled):
    with TemporaryDirectory(dir=tmp_path) as directory:
        reset_request_batch(proxy_backend, Path(directory), reset_code, cancelled)


def reset_request_batch(proxy_backend, directory, reset_code, cancelled_indices):
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        identifiers = client.stage(20, "request-reset")
        rows = wait_staged(origin, {f"/h2-mixed/gate/request-reset/{index}" for index in range(20)}, b"prefix!")
        cancelled = [row for row in rows if int(row[":path"].rsplit("/", 1)[1]) in cancelled_indices]
        for index in cancelled_indices:
            client.connection.reset_stream(identifiers[index], error_code=reset_code)
        client.flush()
        with origin.changed:
            assert origin.changed.wait_for(lambda: all("reset_code" in row for row in cancelled), timeout=5)
            assert not origin.changed.wait_for(lambda: any(row.get("ended") for row in rows), timeout=0.2)
        survivors = [identifier for index, identifier in enumerate(identifiers) if index not in cancelled_indices]
        client.release(survivors)
        client.finish(survivors)
        assert all(not row.get("ended") for row in cancelled)
        assert origin.accepts == 1


def test_gated_h2_reuses_the_configured_parent_connect(proxy_backend, tmp_path):
    from tests.blackbox.harness.sinkhole_parent import Parent, Request

    class ObservedParent(Request):
        def do_CONNECT(self):
            self.server.tunnels.append(self.path)
            try:
                super().do_CONNECT()
            finally:
                self.server.finished.set()

    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem) as origin, Parent(None, None, request_handler=ObservedParent) as parent:
        parent.tunnels = []
        parent.finished = threading.Event()
        thread = threading.Thread(target=parent.serve_forever)
        thread.start()
        try:
            with launch_proxy(
                proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
                parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
            ) as proxy, tls_tunnel(
                proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
            ) as stream:
                client = GatedClient(stream, origin.authority)
                for batch in ("parent-cold", "parent-warm"):
                    identifiers = client.stage(20, batch)
                    wait_staged(origin, {f"/h2-mixed/gate/{batch}/{index}" for index in range(20)}, b"prefix!")
                    client.release(identifiers)
                    client.finish(identifiers)
                assert parent.tunnels == [origin.authority]
                assert origin.accepts == 1
            assert parent.finished.wait(timeout=2)
        finally:
            parent.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


def test_repeated_h2_batches_bound_fds_memory_and_close_origin_socket(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy:
        with tls_tunnel(proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem") as stream:
            client = GatedClient(stream, origin.authority)
            before = runtime_resources(proxy)["processes"]["proxy"]
            for batch in range(30):
                identifiers = client.stage(20, f"repeat-{batch}")
                wait_staged(origin, {f"/h2-mixed/gate/repeat-{batch}/{index}" for index in range(20)}, b"prefix!")
                client.release(identifiers)
                client.finish(identifiers)
            after = runtime_resources(proxy)["processes"]["proxy"]
            if before.get("available"):
                assert after["open_fds"] <= before["open_fds"] + 4, (before, after)
                assert after["rss_kib"] <= before["rss_kib"] + 64 * 1024, (before, after)
            assert origin.accepts == 1
        with origin.changed:
            assert origin.changed.wait_for(lambda: origin.closed_connections == {1}, timeout=2)


def test_shutdown_closes_active_h2_session_without_completing_gated_requests(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem, idle_timeout=30) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        client.stage(20, "shutdown")
        rows = wait_staged(origin, {f"/h2-mixed/gate/shutdown/{index}" for index in range(20)}, b"prefix!")
        proxy.process.terminate()
        assert proxy.process.wait(timeout=12) == 0
        with origin.changed:
            assert origin.changed.wait_for(lambda: origin.closed_connections == {1}, timeout=2)
            assert all(not row.get("ended") for row in rows)


@pytest.mark.parametrize("scope", ["body", "url"])
def test_applicable_h2_inspection_keeps_pre_egress_enforcement(proxy_backend, tmp_path, scope):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    pattern = "prefix!" if scope == "body" else "/h2-mixed/gate/blocked/"
    policy = POLICY + f'''
[[scan_patterns]]
name = "gate-block"
pattern = "{pattern}"
target = "request"
scope = ["{scope}"]
action = "block"
'''
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, policy, tls=True, upstream_ca=public,
        inspection={"block_request": True},
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        blocked = client.stage(1, "blocked")
        with origin.changed:
            assert not origin.changed.wait_for(lambda: bool(origin.requests), timeout=0.2)
        sibling = client.stage(1, "inspection-sibling", body=b"")
        client.release(sibling, body=b"")
        client.finish(sibling)
        if scope == "body":
            client.release(blocked)
        assert client.wait(blocked)[0]["headers"][":status"] == "403"
        assert [row[":path"] for row in origin.requests] == ["/h2-mixed/gate/inspection-sibling/0"]


@pytest.mark.parametrize("block_request,action", [(True, "block"), (False, "block"), (True, "log")])
def test_unavailable_h2_body_cannot_bypass_a_required_blocking_scan(proxy_backend, tmp_path, block_request, action):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    policy = POLICY + f'''
[[scan_patterns]]
name = "required-body"
pattern = "prefix!"
target = "request"
scope = ["body"]
action = "{action}"
'''
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, policy, tls=True, upstream_ca=public,
        inspection={"block_request": block_request},
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        identifier = client.next_id
        client.next_id += 2
        client.results[identifier] = {"headers": {}, "body": bytearray(), "ended": False}
        request = headers(origin.authority, "/required-body", [("content-length", str(10 * 1024 * 1024 + 1))])
        request[0] = (":method", "POST")
        client.connection.send_headers(identifier, request, end_stream=False)
        client.connection.send_data(identifier, b"prefix!")
        client.flush()
        required = block_request and action == "block"
        with origin.changed:
            admitted = origin.changed.wait_for(lambda: bool(origin.requests), timeout=0.2 if required else 5)
            assert admitted is not required, origin.requests
        if required:
            result = client.wait([identifier])[0]
            assert result["headers"][":status"] == "403", result
            assert b"body_unavailable" in result["body"]
        else:
            client.connection.reset_stream(identifier)
            client.flush()
        sibling = client.stage(1, "required-body-sibling", body=b"")
        client.release(sibling, body=b"")
        client.finish(sibling)
        rows = [row for row in origin.requests if row[":path"] == "/required-body"]
        assert len(rows) == (0 if required else 1)
        assert not any(row.get("ended") for row in rows)


@pytest.mark.parametrize("require_no_body", [True, False])
def test_gateway_h2_buffers_only_when_applicable_contract_needs_body(proxy_backend, tmp_path, require_no_body):
    from tests.proxy_contracts.test_gateway_redirect import _fixture_state, _gateway_token
    from tests.proxy_contracts.test_gateway_scope import SERVICE, _policy

    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    service = SERVICE.replace("            query:\n", "            transport:\n              require_no_body: true\n            query:\n") if require_no_body else SERVICE
    (directory / "services/redirect.yaml").write_text(service)
    with origin_server(pem) as origin, launch_proxy(
        proxy_backend, directory, _policy(origin.server_address[1]), tls=True, upstream_ca=public,
        agent_api=True, gateway_services_dir=directory / "services",
        gateway_builtin_services_dir=directory / "builtin",
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        token = _gateway_token(proxy)
        client = GatedClient(stream, origin.authority)
        identifier = client.next_id
        client.next_id += 2
        client.results[identifier] = {"headers": {}, "body": bytearray(), "ended": False}
        client.connection.send_headers(identifier, headers(origin.authority, "/v1/items?account=alpha", [
            ("authorization", f"Bearer {token}"), ("content-length", "7"),
        ]), end_stream=False)
        client.connection.send_data(identifier, b"prefix")
        client.flush()
        if require_no_body:
            with origin.changed:
                assert not origin.changed.wait_for(lambda: bool(origin.requests), timeout=0.2)
        else:
            wait_staged(origin, {"/v1/items?account=alpha"}, b"prefix!")
        client.release([identifier])
        assert client.wait([identifier])[0]["headers"][":status"] == ("403" if require_no_body else "200")
        if require_no_body:
            assert origin.requests == []
        else:
            assert bytes(origin.requests[0]["body"]) == b"prefix!"
