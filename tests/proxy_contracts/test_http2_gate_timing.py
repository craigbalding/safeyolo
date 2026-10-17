"""Opt-in origin timing comparison and an ordinary H2 race control.

Run the timing test on a controlled Linux host with
SAFEYOLO_H2_GATE_BENCHMARK=1. Set SAFEYOLO_H2_GATE_ORIGIN_PORT for an external
tcpdump capture. The test writes fixture TLS keys and observed H2 frames next
to its timing result. TLS reads are not TCP segments.
"""

import json
import math
import os
import platform
import socket
import ssl
import statistics
import subprocess
from contextlib import contextmanager
from time import monotonic, monotonic_ns

import pytest

from safeyolo.rust_proxy import _ensure_signing_ca
from tests.proxy_contracts.harness import launch_proxy
from tests.proxy_contracts.run import runtime_resources
from tests.proxy_contracts.test_http2_contract import POLICY, origin_certificate, origin_server, tls_tunnel
from tests.proxy_contracts.test_http2_gate import GatedClient, wait_staged


@contextmanager
def direct_stream(origin, public):
    context = ssl.create_default_context(cafile=public)
    context.set_alpn_protocols(["h2"])
    with socket.create_connection(origin.server_address, timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as stream:
            assert stream.selected_alpn_protocol() == "h2"
            yield stream


def batch(client, origin, name, *, count=20, serial=False, hold=0.2):
    body = b"prefix!"
    identifiers = client.stage(count, name, body=body)
    paths = {f"/h2-mixed/gate/{name}/{index}" for index in range(count)}
    rows = wait_staged(origin, paths, body)
    with origin.changed:
        assert not origin.changed.wait_for(lambda: any(row.get("ended") for row in rows), timeout=hold)
        assert all(bytes(row["body"]) == body[:-1] for row in rows)
    released_ns = monotonic_ns()
    if serial:
        results = []
        for identifier in identifiers:
            client.release([identifier], body=body)
            results.extend(client.finish([identifier]))
    else:
        client.release(identifiers, body=body)
        results = client.finish(identifiers)
    with origin.lock:
        ends = [row["ended_ns"] for row in rows]
        assert min(ends) >= released_ns
        return {
            "batch": name, "spread_ns": max(ends) - min(ends),
            "connection_id": rows[0]["connection_id"], "peer_port": rows[0]["peer_port"],
            "stream_ids": [row["stream_id"] for row in rows],
            "winners": sum(result["headers"].get("x-race-winner") == "1" for result in results),
        }


def test_gated_race_overlaps_direct_and_intercepted_but_serial_control_does_not(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem, race_window=0.02) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy:
        for lane in ("direct", "proxy"):
            connection = (direct_stream(origin, public) if lane == "direct" else tls_tunnel(
                proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem"))
            with connection as stream:
                client = GatedClient(stream, origin.authority)
                simultaneous = batch(client, origin, lane)
                serial = batch(client, origin, f"{lane}-serial", serial=True)
                assert simultaneous["winners"] > 1, simultaneous
                assert serial["winners"] == 1, serial
                assert simultaneous["connection_id"] == serial["connection_id"]


@pytest.mark.skipif(os.environ.get("SAFEYOLO_H2_GATE_LIFECYCLE") != "1", reason="real idle timeout witness is opt-in")
def test_idle_session_closes_at_origin_and_next_stream_reconnects(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    with origin_server(pem, idle_timeout=120, early_response=True) as origin, launch_proxy(
        proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
    ) as proxy, tls_tunnel(
        proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem",
    ) as stream:
        client = GatedClient(stream, origin.authority)
        first = batch(client, origin, "before-idle", count=2, hold=0)
        started = monotonic()
        with origin.changed:
            assert origin.changed.wait_for(lambda: first["connection_id"] in origin.closed_connections, timeout=65)
        assert monotonic() - started >= 55, "origin closed before the proxy's idle expiry"
        second = batch(client, origin, "after-idle", count=2, hold=0)
        assert first["connection_id"] != second["connection_id"]
        assert origin.accepts == 2
        early = client.stage(2, "early-response")
        rows = wait_staged(origin, {f"/h2-mixed/gate/early-response/{index}" for index in range(2)}, b"prefix!")
        client.finish(early)
        with origin.changed:
            # A completed response does not make its still-open upload idle.
            assert not origin.changed.wait_for(lambda: second["connection_id"] in origin.closed_connections, timeout=61)
            assert all(not row.get("ended") for row in rows)
        batch(client, origin, "alongside-early-response", count=2, hold=0)
        client.release(early)
        with origin.changed:
            assert origin.changed.wait_for(lambda: all(row.get("ended") for row in rows), timeout=5)
        assert origin.accepts == 2


@pytest.mark.skipif(os.environ.get("SAFEYOLO_H2_GATE_BENCHMARK") != "1", reason="controlled timing lane is opt-in")
def test_100_warm_batches_direct_and_intercepted(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _ensure_signing_ca(directory / "ca")
    pem, public = origin_certificate(directory)
    keylog = directory / "fixture-tls.keys"
    keylog.touch(mode=0o600)
    # Pin the common generator, origin threads and inherited proxy workers to
    # the same available CPUs. The report records the effective affinity.
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    selected_cpus = affinity[:2] if affinity else None
    if selected_cpus:
        os.sched_setaffinity(0, selected_cpus)
    result = {"environment": {
        "platform": platform.platform(), "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION, "affinity": selected_cpus,
        "tokio_worker_threads": os.environ.get("TOKIO_WORKER_THREADS", "default"),
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "hold_seconds": 0.2, "streams": 20,
    }, "lanes": {}, "tcp_segmentation": "not observed; inspect an external packet capture"}
    try:
        with origin_server(
            pem, capture_frames=True, keylog=keylog,
            port=int(os.environ.get("SAFEYOLO_H2_GATE_ORIGIN_PORT", "0")),
        ) as origin, launch_proxy(
            proxy_backend, directory, POLICY, tls=True, upstream_ca=public,
        ) as proxy:
            result["origin_port"] = origin.server_address[1]
            result["resources_before"] = runtime_resources(proxy)
            for lane in ("direct", "proxy"):
                connection = (direct_stream(origin, public) if lane == "direct" else tls_tunnel(
                    proxy.paths["alice"], origin.authority, directory / "ca/mitmproxy-ca-cert.pem"))
                with connection as stream:
                    client = GatedClient(stream, origin.authority)
                    batch(client, origin, f"{lane}-warmup")
                    samples = []
                    for index in range(100):
                        samples.append(batch(client, origin, f"{lane}-{index}"))
                        if index % 25 == 24:
                            print(f"{lane}: {index + 1}/100 warm batches", flush=True)
                    spreads = sorted(sample["spread_ns"] for sample in samples)
                    result["lanes"][lane] = {
                        "median_ns": statistics.median(spreads),
                        "p95_ns": spreads[math.ceil(0.95 * len(spreads)) - 1], "batches": samples,
                    }
            result["resources_after"] = runtime_resources(proxy)
            result["origin_frames"] = origin.h2_frames
            result["origin_connections"] = origin.accepts
            # Each lane has one independent TCP/TLS/H2 connection for all 2020 requests.
            assert origin.accepts == 2
            for lane in result["lanes"].values():
                assert len({sample["connection_id"] for sample in lane["batches"]}) == 1
    finally:
        if affinity:
            os.sched_setaffinity(0, affinity)
        report = directory / "h2-gate-timing.json"
        report.write_text(json.dumps(result, indent=2) + "\n")
        print(f"Origin timing report: {report}; TLS keys: {keylog}", flush=True)
    direct = result["lanes"]["direct"]
    proxied = result["lanes"]["proxy"]
    print(json.dumps({lane: {key: value for key, value in values.items() if key != "batches"}
                      for lane, values in result["lanes"].items()}), flush=True)
    result["median_inflation_ns"] = proxied["median_ns"] - direct["median_ns"]
    report.write_text(json.dumps(result, indent=2) + "\n")
    assert proxied["p95_ns"] <= max(2_000_000, 2 * direct["p95_ns"]), result["lanes"]
