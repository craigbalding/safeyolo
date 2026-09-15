"""Capture independently replayable HTTP contracts and a focused workload.

The comparator preserves ports, decisions, delivered bytes and failure statuses.
Generated identifiers are checked for uniqueness/attribution by the scenarios;
they are not compared as literals across independently started processes.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from tests.proxy_migration.harness import REPO, connection, launch_proxy, request
from tests.proxy_migration.scenarios import POLICY, network_scenario, origin_server, reserved_scenario


def memory_kib(pid):
    """Linux process measurements; unavailable platforms remain unmeasured."""
    path = Path(f"/proc/{pid}/status")
    if not path.exists():
        return None
    values = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"VmRSS", "VmHWM"}:
            values[key] = int(value.strip().split()[0])
    return values


def runtime_memory(proxy):
    processes = {"proxy": memory_kib(proxy.process.pid)}
    if proxy.policy_process:
        processes["temporary_policy_adapter"] = memory_kib(proxy.policy_process.pid)
    measured = [value for value in processes.values() if value is not None]
    return {"processes_kib": processes,
            "sum_rss_kib": sum(value.get("VmRSS", 0) for value in measured) if measured else None,
            "scope": "sum of process RSS double-counts shared pages; includes temporary policy adapter when present"}


def short_connections(backend, directory, count):
    """Sequential HTTP requests, a fresh agent and upstream socket each time."""
    with origin_server() as origin, launch_proxy(backend, directory, POLICY) as proxy:
        url = f"http://127.0.0.1:{origin.server_address[1]}/latency"
        samples = []
        ready_memory = runtime_memory(proxy)
        started = time.perf_counter()
        for _ in range(count):
            before = time.perf_counter()
            status, _, body = request(proxy.paths["alice"], url)
            assert status == 200 and body == b"hello"
            samples.append((time.perf_counter() - before) * 1000)
        elapsed = time.perf_counter() - started
        final_memory = runtime_memory(proxy)
        assert origin.accepts == count
        ordered = sorted(samples)
        return {"workload": "sequential_short_http_connections", "requests": count,
                "elapsed_seconds": elapsed, "requests_per_second": count / elapsed,
                "latency_median_ms": statistics.median(samples),
                "latency_p95_ms": ordered[max(0, int(count * .95) - 1)],
                "runtime_memory_ready": ready_memory,
                "runtime_memory_after": final_memory}


def stream_workload(backend, directory):
    """A paced 1.56 MiB SSE response proves early delivery and samples RSS."""
    with origin_server() as origin, launch_proxy(backend, directory, POLICY) as proxy:
        client = connection(proxy.paths["alice"])
        try:
            started = time.perf_counter()
            client.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/stream")
            response = client.getresponse()
            assert response.status == 200
            first = response.read(16384)
            first_seconds = time.perf_counter() - started
            early = not origin.stream_finished.is_set()
            steady = runtime_memory(proxy)
            total = len(first) + len(response.read())
            elapsed = time.perf_counter() - started
            assert total == 1638400
            assert early, "SSE was buffered until origin completion"
            return {"workload": "paced_sse", "bytes": total, "elapsed_seconds": elapsed,
                    "first_chunk_seconds": first_seconds, "first_chunk_before_completion": early,
                    "bytes_per_second": total / elapsed, "runtime_memory_during": steady,
                    "runtime_memory_after": runtime_memory(proxy),
                    "limitation": "two-second smoke workload, not long-duration bounded-memory proof"}
        finally:
            client.close()


def websocket_workload(backend, directory, count):
    """Round-trip complete small WS messages over one connection."""
    with origin_server() as origin, launch_proxy(backend, directory, POLICY) as proxy:
        client = connection(proxy.paths["alice"])
        try:
            client.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/ws", headers={
                "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            })
            response = client.getresponse()
            assert response.status == 101
            started = time.perf_counter()
            for _ in range(count):
                client.sock.sendall(b"\x81\x85\x00\x00\x00\x00hello")
                assert response.fp.read(7) == b"\x81\x05hello"
            elapsed = time.perf_counter() - started
            return {"workload": "small_websocket_echo", "messages": count, "payload_bytes": count * 5,
                    "elapsed_seconds": elapsed, "messages_per_second": count / elapsed,
                    "runtime_memory_after": runtime_memory(proxy),
                    "limitation": "five-byte messages only; no compression/fragmentation/inspection workload"}
        finally:
            client.close()


def local_api_workload(backend, directory, count):
    """Observe unavailable-handler responsiveness; this is not the normal API."""
    with launch_proxy(backend, directory, POLICY) as proxy:
        started = time.perf_counter()
        for _ in range(count):
            status, _, _ = request(proxy.paths["alice"], "http://_safeyolo.proxy.internal/health")
            assert status == 503
        elapsed = time.perf_counter() - started
        assert proxy.events("proxy.egress") == []
        return {"workload": "local_api_unavailable_handler", "requests": count,
                "elapsed_seconds": elapsed, "requests_per_second": count / elapsed,
                "runtime_memory_after": runtime_memory(proxy),
                "limitation": "normal authenticated API and approval creation/consumption are not measured"}


def capture(args):
    previous = json.loads(args.fixture_from.read_text()) if args.fixture_from else None
    args.evidence.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, parent in (("http_direct", False), ("http_parent", True)):
        port = previous["contracts"][name]["fixture_origin_port"] if previous else 0
        results[name] = network_scenario(args.backend, args.evidence / name, parent=parent, origin_port=port)
    results["local_containment"] = reserved_scenario(args.backend, args.evidence / "local")
    workloads = [short_connections(args.backend, args.evidence / "workload", args.requests)]
    if args.extended_workloads:
        workloads.extend([
            stream_workload(args.backend, args.evidence / "stream-workload"),
            websocket_workload(args.backend, args.evidence / "ws-workload", args.requests),
            local_api_workload(args.backend, args.evidence / "api-workload", args.requests),
        ])
    result = {
        "schema": 1, "backend": args.backend, "captured_at": datetime.now(UTC).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True)),
        "platform": platform.platform(), "machine": platform.machine(), "python": sys.version,
        "tools": {package: version(package) for package in ("pytest", "mitmproxy", "httpx")},
        "command": sys.argv, "contracts": results, "workloads": workloads,
        "scope": "focused real UDS/network-policy chain; full production chain not launched",
        "unmeasured": ["bounded memory during long-duration streams", "WebSocket inspection workload",
                       "concurrent approval/API responsiveness", "supported macOS host ingress"],
        "evidence_gaps": ["proxy.request is a fixture observation in Python; complete audit/trace parity is not claimed",
                          "Rust temporary PDP adapter does not reproduce approval audit/store side effects"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "contracts": list(results), "workloads": result["workloads"]}))


def compare(args):
    old, new = (json.loads(path.read_text()) for path in (args.baseline, args.candidate))
    names = args.scenario or list(old["contracts"])
    differences = {name: {"baseline": old["contracts"].get(name), "candidate": new["contracts"].get(name)}
                   for name in names if old["contracts"].get(name) != new["contracts"].get(name)}
    print(json.dumps({"compared": names, "equal": not differences, "differences": differences}, indent=2))
    return int(bool(differences))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("capture")
    run.add_argument("--backend", choices=("python", "rust"), required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--evidence", type=Path, required=True)
    run.add_argument("--fixture-from", type=Path)
    run.add_argument("--requests", type=int, default=100)
    run.add_argument("--extended-workloads", action="store_true", help="Run SSE, WS, and unavailable local API workloads")
    diff = commands.add_parser("compare")
    diff.add_argument("baseline", type=Path)
    diff.add_argument("candidate", type=Path)
    diff.add_argument("--scenario", action="append", choices=("http_direct", "http_parent", "local_containment"))
    args = parser.parse_args()
    if args.command == "compare":
        return compare(args)
    if args.requests < 1:
        parser.error("--requests must be positive")
    capture(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
