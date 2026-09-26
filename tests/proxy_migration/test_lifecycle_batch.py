"""Bounded mixed transport cancellation and same-state proxy restart."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import threading
import time
from contextlib import contextmanager

from tests.proxy_migration.harness import (
    RunningProxy,
    child_process,
    connection,
    launch_proxy,
    python_proxy_environment,
    request,
    wait_ready,
)
from tests.proxy_migration.run import process_resources
from tests.proxy_migration.scenarios import POLICY, origin_server
from tests.proxy_migration.test_request_streaming_inspection import head, observed_origin
from tests.proxy_migration.test_tunnel_contract import read_exact, tunnel

FIRST_EVENT = b"data: first-event\n\n"
GREETING = b"lifecycle-tunnel-ready\x00\n"
UPLOAD_SIZE = 10 * 1024 * 1024 + 1
BATCHES = 3


@contextmanager
def raw_origin():
    """Observe one complete opaque payload and the client-side disconnect."""
    result = {}
    finished = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)

        def serve():
            try:
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(5)
                    stream.sendall(GREETING)
                    body = bytearray()
                    while part := stream.recv(65536):
                        body.extend(part)
                    result["body"] = bytes(body)
            except Exception as error:
                result["error"] = error
            finally:
                finished.set()

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield f"127.0.0.1:{listener.getsockname()[1]}", result, finished
        finally:
            worker.join(timeout=6)
            assert not worker.is_alive(), "opaque origin worker did not finish"
            if "error" in result:
                raise result["error"]


def response_event(proxy, headers, *, agent, status):
    """Join a client response to its process event after asynchronous logging."""
    identifier = {name.lower(): value for name, value in headers.items()}[
        "x-safeyolo-request-id"
    ]
    deadline = time.monotonic() + 5
    while True:
        rows = [row for row in proxy.events("proxy.request")
                if row.get("request_id") == identifier]
        if rows or time.monotonic() >= deadline:
            break
        time.sleep(0.025)
    assert len(rows) == 1, (identifier, rows)
    assert rows[0]["agent"] == agent and rows[0]["status"] == status, rows[0]
    return identifier


def resource_sample(pid):
    """Require external descriptor and resident-memory data on Linux."""
    sample = process_resources(pid)
    if sys.platform == "linux":
        assert sample["available"] and sample["open_fds"] is not None
        assert sample["rss_kib"] is not None
    return sample


def run_batch(proxy, index):
    """Keep upload, event stream, WebSocket and tunnel live during a control request."""
    egress_before = len(proxy.events("proxy.egress"))
    prefix = (f"batch-{index}-".encode() * 8192)[:65536]
    payload = (f"opaque-{index}-".encode() * 1024)[:8192]
    upload_path = f"/cancel-{index}"
    upload = event_client = event_response = websocket = opaque = None
    with observed_origin(socket_timeout=5) as upload_origin, origin_server(
        stream_seconds=2.0
    ) as http_origin, raw_origin() as (authority, tunnel_result, tunnel_finished):
        url = f"http://127.0.0.1:{http_origin.server_address[1]}"
        try:
            # A short connection first proves ordinary forwarding on this listener.
            status, headers, body = request(proxy.paths["alice"], url + "/short")
            assert (status, body) == (200, b"hello")
            response_event(proxy, headers, agent="alice", status=200)

            upload = head(proxy, upload_origin, upload_path, length=UPLOAD_SIZE, first=prefix)
            upload_origin.wait_for(upload_path, lambda row: row["bytes"] == len(prefix))

            event_client = connection(proxy.paths["alice"])
            event_client.request("GET", url + "/stream-cancel")
            event_response = event_client.getresponse()
            assert event_response.status == 200
            assert event_response.read(len(FIRST_EVENT)) == FIRST_EVENT
            assert http_origin.stream_initial_sent.is_set()

            websocket = connection(proxy.paths["alice"])
            websocket.request("GET", url + "/ws", headers={
                "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            })
            upgrade = websocket.getresponse()
            assert upgrade.status == 101
            websocket.sock.sendall(b"\x81\x85\x00\x00\x00\x00hello")
            assert upgrade.fp.read(7) == b"\x81\x05hello"

            opaque = tunnel(proxy.paths["alice"], authority)
            assert read_exact(opaque, len(GREETING)) == GREETING
            opaque.sendall(payload)

            # Both requests run while all four other legs are still established.
            assert not http_origin.stream_release.is_set()
            assert not tunnel_finished.is_set()
            status, headers, body = request(proxy.paths["alice"], url + "/control")
            assert (status, body) == (200, b"hello")
            control_id = response_event(proxy, headers, agent="alice", status=200)
            before_denial = (http_origin.accepts, len(proxy.events("proxy.egress")))
            status, headers, _ = request(
                proxy.paths["bob"], url + "/denied",
                headers={"X-SafeYolo-Agent": "alice"},
            )
            headers = {name.lower(): value for name, value in headers.items()}
            assert status == 403 and headers.get("x-blocked-by") == "network-guard"
            denied_id = response_event(proxy, headers, agent="bob", status=403)
            assert (http_origin.accepts, len(proxy.events("proxy.egress"))) == before_denial
            websocket.sock.sendall(b"\x88\x80\x00\x00\x00\x00")
        finally:
            if event_response is not None:
                event_response.close()
            for client in (upload, event_client, websocket, opaque):
                if client is not None:
                    client.close()
            http_origin.stream_release.set()

        with upload_origin.condition:
            assert upload_origin.condition.wait_for(
                lambda: upload_path in upload_origin.requests
                and (upload_origin.requests[upload_path]["complete"]
                     or "error" in upload_origin.requests[upload_path]),
                timeout=7,
            ), upload_origin.requests
            upload_row = dict(upload_origin.requests[upload_path])
        assert upload_row["bytes"] == len(prefix), upload_row
        assert upload_row["partial_digest"] == hashlib.sha256(prefix).hexdigest()
        assert not upload_row["complete"] and upload_row["digest"] is None, upload_row
        assert upload_row["error"].startswith("AssertionError"), upload_row
        assert http_origin.websocket_ended.wait(5), "origin WebSocket remained established"
        assert http_origin.stream_finished.wait(7), "origin event stream did not finish"
        assert tunnel_finished.wait(5), "origin tunnel remained established"
        assert tunnel_result["body"] == payload
        assert http_origin.websocket_frames == [{
            "index": 0, "opcode": 1, "payload_bytes": 5,
            "payload_sha256": hashlib.sha256(b"hello").hexdigest(),
        }]
        assert http_origin.stream_cancelled.is_set(), "SSE kept draining after client close"
        egress = proxy.events("proxy.egress")[egress_before:]
        assert len(egress) == 6 and all(row["agent"] == "alice" for row in egress), egress
        assert {row["port"] for row in egress} == {
            http_origin.server_address[1], upload_origin.server_address[1],
            int(authority.rsplit(":", 1)[1]),
        }
        assert proxy.process.poll() is None
        return {
            "control_id": control_id,
            "denied_id": denied_id,
            "upload_bytes": upload_row["bytes"],
            "sse_cancelled_at_origin": http_origin.stream_cancelled.is_set(),
            "sse_bytes_after_release": http_origin.stream_bytes_sent,
            "tunnel_bytes": len(tunnel_result["body"]),
        }


def test_mixed_cancellation_batches_drain_and_restart_same_listener(proxy_backend, tmp_path):
    """Three bounded mixed batches release live legs; the same config starts again."""
    directory = tmp_path / proxy_backend
    with launch_proxy(
        proxy_backend, directory, POLICY, native_policy=True, eager_connect=True,
        stream_large_bodies="10m",
    ) as proxy:
        config_path = directory / "proxy.json"
        config_before = config_path.read_bytes()
        policy_before = (directory / "policy.toml").read_bytes()
        baseline = resource_sample(proxy.process.pid)
        batches = []
        samples = []
        for index in range(BATCHES):
            batches.append(run_batch(proxy, index))
            deadline = time.monotonic() + 5
            while True:
                sample = resource_sample(proxy.process.pid)
                if not sample["available"] or sample["open_fds"] <= baseline["open_fds"] + 4:
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
            samples.append(sample)
            if sample["available"]:
                assert sample["open_fds"] <= baseline["open_fds"] + 4, (baseline, samples)
        if samples[0]["available"]:
            assert samples[-1]["open_fds"] <= samples[0]["open_fds"] + 2, samples
            # Allocators retain arenas and the protocol stacks keep bounded caches.
            # Compare quiet batches rather than requiring a return to cold RSS.
            rss_allowance_kib = 16 * 1024 if proxy_backend == "python" else 8 * 1024
            assert max(sample["rss_kib"] for sample in samples[1:]) <= (
                samples[0]["rss_kib"] + rss_allowance_kib
            ), samples
        print(json.dumps({
            "backend": proxy_backend,
            "quiet_fds": [sample.get("open_fds") for sample in samples],
            "quiet_rss_kib": [sample.get("rss_kib") for sample in samples],
            "sse_cancelled_at_origin": [batch["sse_cancelled_at_origin"] for batch in batches],
        }), flush=True)

        first_pid = proxy.process.pid
        command = proxy.process.args
        proxy.process.terminate()
        assert proxy.process.wait(timeout=10) == 0
        assert not proxy.readiness_file.exists(), "stopped child left a ready marker"
        for path in proxy.paths.values():
            with socket.socket(socket.AF_UNIX) as closed:
                assert closed.connect_ex(path) != 0, path

        restart_directory = directory / "restart"
        restart_directory.mkdir()
        environment = python_proxy_environment(
            python_source=os.environ.get("SAFEYOLO_PYTHON_SOURCE")
        )
        environment["SAFEYOLO_LOG_PATH"] = str(directory / "audit.jsonl")
        with child_process(command, restart_directory, environment) as restarted_process:
            wait_ready(
                restarted_process,
                [proxy.readiness_file, *proxy.paths.values()],
                restart_directory / "process.log",
                readiness_file=proxy.readiness_file,
                expected_backend="python" if proxy_backend == "python" else "rust-m2",
            )
            restarted = RunningProxy(
                proxy.paths, proxy.event_log, restarted_process, proxy.readiness_file
            )
            assert restarted.process.pid != first_pid
            assert json.loads(proxy.readiness_file.read_text())["pid"] == restarted.process.pid
            assert config_path.read_bytes() == config_before
            assert (directory / "policy.toml").read_bytes() == policy_before
            with origin_server() as origin:
                url = f"http://127.0.0.1:{origin.server_address[1]}/after-restart"
                status, headers, body = request(restarted.paths["alice"], url)
                assert (status, body) == (200, b"hello")
                response_event(restarted, headers, agent="alice", status=200)
                status, headers, _ = request(restarted.paths["bob"], url)
                headers = {name.lower(): value for name, value in headers.items()}
                assert status == 403 and headers.get("x-blocked-by") == "network-guard"
                response_event(restarted, headers, agent="bob", status=403)
                assert origin.accepts == 1 and origin.requests == [
                    {"method": "GET", "target": "/after-restart"}
                ]
            assert resource_sample(restarted.process.pid)["available"] or sys.platform != "linux"
        assert not proxy.readiness_file.exists()
        assert all(sample["upload_bytes"] == 65536 for sample in batches)
