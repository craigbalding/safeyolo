"""Capture independently replayable HTTP contracts and a focused workload.

The comparator preserves ports, decisions, delivered bytes and failure statuses.
Generated identifiers are checked for uniqueness/attribution by the scenarios;
they are not compared as literals across independently started processes.
Capture output is schema-versioned evidence, not an automatic performance claim:
the selected process, configuration and external resource observations must be
reviewed together with the raw origin/control results.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from tests.proxy_migration.harness import REPO, connection, launch_proxy, read_events, request
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


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_identity(path):
    """Return the selected source checkout identity without changing it."""
    source = Path(path).resolve()
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True, stderr=subprocess.STDOUT
        ).strip()
        dirty = bool(subprocess.check_output(
            ["git", "-C", str(source), "status", "--porcelain"], text=True, stderr=subprocess.STDOUT
        ).strip())
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"selected source is not a Git checkout: {source}") from error
    return {"path": str(source), "commit": commit, "dirty": dirty}


def _command_version(command):
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _proc_cmdline(pid):
    path = Path(f"/proc/{pid}/cmdline")
    if not path.exists():
        return None
    return [part.decode(errors="replace") for part in path.read_bytes().split(b"\0") if part]


def process_resources(pid):
    """Read external process observations; never use proxy-reported counters."""
    status_path = Path(f"/proc/{pid}/status")
    if not status_path.exists():
        return {"pid": pid, "available": False}
    values = {}
    for line in status_path.read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"VmRSS", "VmHWM", "VmSize", "Threads"}:
            values[key] = int(value.strip().split()[0])
    fd_path = Path(f"/proc/{pid}/fd")
    try:
        fds = len(list(fd_path.iterdir()))
    except OSError:
        fds = None
    return {
        "pid": pid,
        "available": True,
        "rss_kib": values.get("VmRSS"),
        "high_water_rss_kib": values.get("VmHWM"),
        "virtual_memory_kib": values.get("VmSize"),
        "threads": values.get("Threads"),
        "open_fds": fds,
    }


def runtime_resources(proxy):
    processes = {"proxy": process_resources(proxy.process.pid)}
    if proxy.policy_process:
        processes["temporary_policy_adapter"] = process_resources(proxy.policy_process.pid)
    return {
        "sampled_at_utc": datetime.now(UTC).isoformat(),
        "sampled_at_monotonic": time.monotonic(),
        "processes": processes,
        "observation": "external /proc RSS, high-water RSS, thread and FD counts",
    }


def proxy_identity(proxy):
    """Capture exact child/config identities while the selected process lives."""
    config_path = proxy.event_log.parent / "proxy.json"
    config_bytes = config_path.read_bytes()
    binary_path = Path(f"/proc/{proxy.process.pid}/exe")
    identity = {
        "pid": proxy.process.pid,
        "argv": _proc_cmdline(proxy.process.pid),
        "config": {"path": str(config_path), "sha256": hashlib.sha256(config_bytes).hexdigest()},
        "config_payload": json.loads(config_bytes),
    }
    policy_path = Path(identity["config_payload"]["policy_file"])
    if policy_path.exists():
        identity["policy"] = {"path": str(policy_path), "sha256": _sha256(policy_path)}
    if binary_path.exists():
        resolved = binary_path.resolve()
        identity["executable"] = {
            "path": str(resolved),
            "sha256": _sha256(resolved),
            "size_bytes": resolved.stat().st_size,
        }
    provenance = config_path.parent / "native-policy-provenance.json"
    if provenance.exists():
        identity["native_policy_provenance"] = {
            "path": str(provenance), "sha256": _sha256(provenance),
            "payload": json.loads(provenance.read_text()),
        }
    return identity


@contextlib.contextmanager
def selected_process_environment(args):
    """Bind each capture to an explicit implementation and policy path."""
    names = (
        "SAFEYOLO_PYTHON_SOURCE", "SAFEYOLO_PYTHON_EXECUTABLE",
        "SAFEYOLO_RUST_PROXY", "SAFEYOLO_RUST_NATIVE_ONLY",
    )
    previous = {name: os.environ.get(name) for name in names}
    source = Path(args.python_source).expanduser().resolve()
    binary = Path(args.rust_binary).expanduser().resolve() if args.rust_binary else None
    if args.backend == "python":
        os.environ["SAFEYOLO_PYTHON_SOURCE"] = str(source)
        # Preserve a virtualenv launcher path. Resolving its symlink can select
        # the system interpreter and silently drop the locked dependencies.
        os.environ["SAFEYOLO_PYTHON_EXECUTABLE"] = str(Path(args.python_executable).expanduser())
        os.environ.pop("SAFEYOLO_RUST_PROXY", None)
        os.environ.pop("SAFEYOLO_RUST_NATIVE_ONLY", None)
    else:
        if binary is None or not binary.is_file():
            raise ValueError("--rust-binary must identify an existing native proxy executable")
        os.environ["SAFEYOLO_RUST_PROXY"] = str(binary)
        # A resource comparison must not include a Python policy bridge.
        os.environ["SAFEYOLO_RUST_NATIVE_ONLY"] = "1"
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


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
        resource_samples = [runtime_resources(proxy)]
        started = time.perf_counter()
        sample_every = max(1, count // 4)
        for index in range(count):
            before = time.perf_counter()
            status, _, body = request(proxy.paths["alice"], url)
            assert status == 200 and body == b"hello"
            samples.append((time.perf_counter() - before) * 1000)
            if (index + 1) % sample_every == 0:
                resource_samples.append(runtime_resources(proxy))
        elapsed = time.perf_counter() - started
        final_memory = runtime_memory(proxy)
        assert origin.accepts == count
        ordered = sorted(samples)
        return {"workload": "sequential_short_http_connections", "requests": count,
                "elapsed_seconds": elapsed, "requests_per_second": count / elapsed,
                "latency_median_ms": statistics.median(samples),
                "latency_p95_ms": ordered[max(0, int(count * .95) - 1)],
                "runtime_memory_ready": ready_memory,
                "runtime_memory_after": final_memory,
                "resource_samples": resource_samples,
                "origin_observation": {
                    "accepted_connections": origin.accepts,
                    "requests": list(origin.requests),
                    "expected_requests": count,
                },
                "proxy_identity": proxy_identity(proxy)}


def stream_workload(backend, directory, seconds=2.0):
    """Observe early SSE delivery and process memory throughout a paced stream."""
    with origin_server(stream_seconds=seconds) as origin, launch_proxy(backend, directory, POLICY) as proxy:
        client = connection(proxy.paths["alice"])
        try:
            started = time.perf_counter()
            client.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/stream")
            response = client.getresponse()
            assert response.status == 200
            first = response.read(16384)
            first_seconds = time.perf_counter() - started
            early = not origin.stream_finished.is_set()
            samples = [{"elapsed_seconds": first_seconds, **runtime_memory(proxy)}]
            resource_samples = [runtime_resources(proxy)]
            total = len(first)
            sampled_at = time.monotonic()
            while chunk := response.read(16384):
                total += len(chunk)
                if time.monotonic() - sampled_at >= 1:
                    samples.append({"elapsed_seconds": time.perf_counter() - started, **runtime_memory(proxy)})
                    resource_samples.append(runtime_resources(proxy))
                    sampled_at = time.monotonic()
            elapsed = time.perf_counter() - started
            assert total == origin.stream_chunks * 16384
            assert early, "SSE was buffered until origin completion"
            return {"workload": "paced_sse", "bytes": total, "elapsed_seconds": elapsed,
                    "first_chunk_seconds": first_seconds, "first_chunk_before_completion": early,
                    "bytes_per_second": total / elapsed, "runtime_memory_samples": samples,
                    "resource_samples": resource_samples,
                    "runtime_memory_after": runtime_memory(proxy),
                    "requested_stream_seconds": seconds,
                    "origin_observation": {
                        "accepted_connections": origin.accepts,
                        "requests": list(origin.requests),
                        "stream_finished_when_first_chunk_arrived": not early,
                        "stream_finished_after_read": origin.stream_finished.is_set(),
                    },
                    "proxy_identity": proxy_identity(proxy),
                    "limitation": "one paced stream; no concurrent load, content inspection, or slow-reader proof"}
        finally:
            client.close()


def streamed_control_workload(backend, directory, seconds=2.0):
    """Hold one streamed response while an independent request completes."""
    with origin_server(stream_seconds=seconds) as origin, launch_proxy(
        backend, directory, POLICY, native_policy=backend == "rust"
    ) as proxy:
        client = connection(proxy.paths["alice"])
        started = time.perf_counter()
        try:
            client.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/stream-control")
            response = client.getresponse()
            assert response.status == 200
            first = response.read(len(b"data: first-event\n\n"))
            first_seconds = time.perf_counter() - started
            assert first == b"data: first-event\n\n"
            assert origin.stream_initial_sent.is_set()
            assert not origin.stream_finished.is_set()
            assert not origin.stream_release.is_set()
            first_before_release = not origin.stream_release.is_set()

            control_started = time.perf_counter()
            status, _, body = request(
                proxy.paths["alice"], f"http://127.0.0.1:{origin.server_address[1]}/control"
            )
            control_seconds = time.perf_counter() - control_started
            assert status == 200 and body == b"hello"
            assert not origin.stream_finished.is_set()

            origin.stream_release.set()
            total = len(first)
            while chunk := response.read(16384):
                total += len(chunk)
            elapsed = time.perf_counter() - started
            expected = len(first) + max(0, origin.stream_chunks - 1) * 16384
            assert total == expected
            assert origin.stream_finished.is_set()
            assert origin.requests == [
                {"method": "GET", "target": "/stream-control"},
                {"method": "GET", "target": "/control"},
            ]
            return {
                "workload": "streamed_control",
                "bytes": total,
                "elapsed_seconds": elapsed,
                "first_event_seconds": first_seconds,
                "first_event_before_release": first_before_release,
                "control_elapsed_seconds": control_seconds,
                "control_completed_before_stream_release": True,
                "stream_released_after_control": origin.stream_release.is_set(),
                "runtime_memory_after": runtime_memory(proxy),
                "resource_samples": [runtime_resources(proxy)],
                "requested_stream_seconds": seconds,
                "origin_observation": {
                    "accepted_connections": origin.accepts,
                    "requests": list(origin.requests),
                    "stream_finished_after_read": origin.stream_finished.is_set(),
                },
                "proxy_identity": proxy_identity(proxy),
                "limitation": "one held stream and one independent allowed request; no slow consumer or admin API operation",
            }
        finally:
            origin.stream_release.set()
            client.close()


def streamed_slow_admin_workload(backend, directory, seconds=2.0):
    """Keep a paced response unread while independent traffic and /stats run.

    The reader deliberately pauses after the first event and between later
    chunks.  The second request uses Alice's separate trusted listener, while
    /stats uses the proxy's authenticated operator listener.  Both operations
    must complete while the origin stream is still active; this records
    responsiveness under a slow consumer without adding a product limit.
    """
    token = "stream-slow-admin-fixture-token"
    token_file = directory / "operator-token"
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    with origin_server(stream_seconds=seconds) as origin, launch_proxy(
        backend,
        directory,
        POLICY,
        native_policy=backend == "rust",
        admin_port=0,
        admin_api_token_file=token_file,
    ) as proxy:
        client = connection(proxy.paths["alice"])
        started = time.perf_counter()
        try:
            client.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/stream")
            response = client.getresponse()
            assert response.status == 200
            first = response.read(16384)
            first_seconds = time.perf_counter() - started
            assert first and not origin.stream_finished.is_set()

            # Do not consume the stream while its origin is still producing
            # data.  This is the controlled slow-consumer interval.
            time.sleep(max(0.05, seconds / 4))
            assert not origin.stream_finished.is_set()
            held_resources = runtime_resources(proxy)

            control_started = time.perf_counter()
            status, _, body = request(
                proxy.paths["alice"], f"http://127.0.0.1:{origin.server_address[1]}/control"
            )
            control_elapsed = time.perf_counter() - control_started
            assert status == 200 and body == b"hello"
            assert not origin.stream_finished.is_set()

            marker = json.loads(proxy.readiness_file.read_text())
            admin_port = marker["admin_port"]
            admin_started = time.perf_counter()
            admin = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=5)
            try:
                admin.request("GET", "/stats", headers={"Authorization": f"Bearer {token}"})
                admin_response = admin.getresponse()
                admin_body = admin_response.read()
                admin_status = admin_response.status
                admin_headers = dict(admin_response.getheaders())
            finally:
                admin.close()
            admin_elapsed = time.perf_counter() - admin_started
            assert admin_status == 200 and admin_body
            assert not origin.stream_finished.is_set()
            during_resources = runtime_resources(proxy)

            total = len(first)
            paced_chunks = 0
            while chunk := response.read(16384):
                total += len(chunk)
                paced_chunks += 1
                time.sleep(0.02)
            elapsed = time.perf_counter() - started
            assert origin.stream_finished.is_set()
            assert total == origin.stream_chunks * 16384
            request_events = [event for event in read_events(proxy.event_log)
                              if event.get("event") == "proxy.request"]
            error_events = [event for event in request_events if int(event.get("status", 200)) >= 400]
            assert origin.requests == [
                {"method": "GET", "target": "/stream"},
                {"method": "GET", "target": "/control"},
            ]
            return {
                "workload": "streamed_slow_consumer_admin",
                "bytes": total,
                "elapsed_seconds": elapsed,
                "first_event_seconds": first_seconds,
                "first_event_before_origin_completion": True,
                "slow_consumer_pause_seconds": max(0.05, seconds / 4),
                "paced_chunks_after_pause": paced_chunks,
                "control_elapsed_seconds": control_elapsed,
                "control_completed_while_stream_active": True,
                "request_counts": {
                    "origin_requests": len(origin.requests),
                    "origin_error_responses": 0,
                    "proxy_request_events": len(request_events),
                    "proxy_error_responses": len(error_events),
                    "allowed_control_requests": 1,
                    "authenticated_admin_operations": 1,
                    "authenticated_admin_errors": 0,
                },
                "admin": {
                    "method": "GET",
                    "path": "/stats",
                    "authenticated": True,
                    "status": admin_status,
                    "elapsed_seconds": admin_elapsed,
                    "body_bytes": len(admin_body),
                    "body_sha256": hashlib.sha256(admin_body).hexdigest(),
                    "content_type": admin_headers.get("Content-Type"),
                    "completed_while_stream_active": True,
                },
                "runtime_resources": {
                    "before_controls": held_resources,
                    "after_controls": during_resources,
                    "after_drain": runtime_resources(proxy),
                },
                "origin_observation": {
                    "accepted_connections": origin.accepts,
                    "requests": list(origin.requests),
                    "stream_active_during_controls": True,
                    "stream_finished_after_read": origin.stream_finished.is_set(),
                },
                "proxy_identity": proxy_identity(proxy),
                "limitation": "one paced slow consumer and one control/admin pair; no long-duration or repeated growth claim",
            }
        finally:
            client.close()


def websocket_workload(backend, directory, count, seconds=0.0, interval=0.0):
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
            samples = [{"elapsed_seconds": 0, **runtime_memory(proxy)}]
            resource_samples = [runtime_resources(proxy)]
            sampled_at = time.monotonic()
            sent = 0
            while sent < count or time.perf_counter() - started < seconds:
                client.sock.sendall(b"\x81\x85\x00\x00\x00\x00hello")
                assert response.fp.read(7) == b"\x81\x05hello"
                sent += 1
                if time.monotonic() - sampled_at >= 1:
                    samples.append({"elapsed_seconds": time.perf_counter() - started, **runtime_memory(proxy)})
                    resource_samples.append(runtime_resources(proxy))
                    sampled_at = time.monotonic()
                if interval:
                    time.sleep(interval)
            elapsed = time.perf_counter() - started
            origin_frames = list(origin.websocket_frames)
            assert len(origin_frames) == sent, (len(origin_frames), sent)
            return {"workload": "small_websocket_echo", "messages": sent, "payload_bytes": sent * 5,
                    "elapsed_seconds": elapsed, "messages_per_second": sent / elapsed,
                    "requested_session_seconds": seconds, "message_interval_seconds": interval,
                    "runtime_memory_samples": samples,
                    "resource_samples": resource_samples,
                    "runtime_memory_after": runtime_memory(proxy),
                    "origin_observation": {
                        "accepted_connections": origin.accepts,
                        "requests": list(origin.requests),
                        "messages_observed_by_origin": len(origin_frames),
                        "received_frames": origin_frames,
                    },
                    "proxy_identity": proxy_identity(proxy),
                    "limitation": "five-byte messages only; no compression/fragmentation/inspection workload"}
        finally:
            client.close()


def local_api_workload(backend, directory, count):
    """Observe unavailable-handler responsiveness; this is not the normal API."""
    with launch_proxy(backend, directory, POLICY) as proxy:
        started = time.perf_counter()
        statuses = []
        for _ in range(count):
            status, _, _ = request(proxy.paths["alice"], "http://_safeyolo.proxy.internal/health")
            statuses.append(status)
            assert status == 503
        elapsed = time.perf_counter() - started
        assert proxy.events("proxy.egress") == []
        return {"workload": "local_api_unavailable_handler", "requests": count,
                "elapsed_seconds": elapsed, "requests_per_second": count / elapsed,
                "runtime_memory_after": runtime_memory(proxy),
                "resource_samples": [runtime_resources(proxy)],
                "control_observation": {
                    "response_statuses": statuses,
                    "proxy_alive_after_workload": proxy.process.poll() is None,
                    "reserved_route_egress_events": proxy.events("proxy.egress"),
                },
                "proxy_identity": proxy_identity(proxy),
                "limitation": "normal authenticated API and approval creation/consumption are not measured"}


def candidate_identity(args):
    source = Path(args.python_source).expanduser().resolve()
    identity = {
        "backend": args.backend,
        "source_checkout": _git_identity(REPO),
        "python_source_checkout": _git_identity(source),
        "python_executable": {
            "path": str(Path(args.python_executable).expanduser()),
            "resolved_path": str(Path(args.python_executable).expanduser().resolve()),
            "version": _command_version([
                str(Path(args.python_executable).expanduser()), "-c", "import sys; print(sys.version)"
            ]),
        },
        "runner_python_version": sys.version,
        "platform": {"system": platform.platform(), "machine": platform.machine()},
        "selection": {
            "rust_native_policy_required": args.backend == "rust",
            "rust_build_profile": args.rust_build_profile if args.backend == "rust" else None,
        },
    }
    if args.backend == "rust":
        identity["rust_toolchain"] = {
            "rustc_version": _command_version(["rustc", "-Vv"]),
            "cargo_version": _command_version(["cargo", "-V"]),
        }
    python_executable = Path(args.python_executable).expanduser()
    identity["python_executable"]["sha256"] = _sha256(python_executable)
    identity["python_executable"]["size_bytes"] = python_executable.stat().st_size
    # A Python capture may inherit a stale SAFEYOLO_RUST_PROXY value. It is
    # irrelevant to that process and must not be hashed after the workload.
    executable = Path(args.rust_binary).expanduser().resolve() if args.backend == "rust" and args.rust_binary else None
    if executable is not None:
        identity["rust_executable"] = {
            "path": str(executable),
            "sha256": _sha256(executable),
            "size_bytes": executable.stat().st_size,
            "release_profile_declared": args.rust_build_profile == "release",
        }
    return identity


def capture(args):
    previous = json.loads(args.fixture_from.read_text()) if args.fixture_from else None
    args.evidence.mkdir(parents=True, exist_ok=True)
    results = {}
    with selected_process_environment(args):
        for name, parent in (("http_direct", False), ("http_parent", True)):
            port = previous["contracts"][name]["fixture_origin_port"] if previous else 0
            results[name] = network_scenario(args.backend, args.evidence / name, parent=parent, origin_port=port)
        results["local_containment"] = reserved_scenario(args.backend, args.evidence / "local")
        selected = args.workload or (["short", "sse", "websocket", "local-api"] if args.extended_workloads else ["short"])
        workloads = []
        for workload in selected:
            if workload == "short":
                workloads.append(short_connections(args.backend, args.evidence / "workload", args.requests))
            elif workload == "sse":
                workloads.append(stream_workload(args.backend, args.evidence / "stream-workload", args.stream_seconds))
            elif workload == "stream-control":
                workloads.append(streamed_control_workload(args.backend, args.evidence / "stream-control-workload",
                                                            args.stream_seconds))
            elif workload == "stream-slow-admin":
                workloads.append(streamed_slow_admin_workload(
                    args.backend, args.evidence / "stream-slow-admin-workload", args.stream_seconds
                ))
            elif workload == "websocket":
                workloads.append(websocket_workload(args.backend, args.evidence / "ws-workload", args.requests,
                                                    args.websocket_seconds, args.websocket_interval))
            else:
                workloads.append(local_api_workload(args.backend, args.evidence / "api-workload", args.requests))
    result = {
        "schema": 2, "backend": args.backend, "captured_at": datetime.now(UTC).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True)),
        "platform": platform.platform(), "machine": platform.machine(), "python": sys.version,
        "tools": {package: version(package) for package in ("pytest", "mitmproxy", "httpx")},
        "command": sys.argv, "candidate": candidate_identity(args),
        "contracts": results, "workloads": workloads,
        "tolerances": {
            "origin_request_counts": {"allowed_difference": 0, "basis": "controlled origin observer"},
            "delivered_body_bytes": {"allowed_difference": 0, "basis": "workload assertions"},
            "resource_growth": {"allowed_difference": None,
                                 "basis": "report RSS/high-water/FD samples first; no release threshold is invented"},
        },
        "raw_results": {
            "output": str(args.output),
            "evidence_directory": str(args.evidence),
            "event_logs": "one events.jsonl per fixture directory",
        },
        "prior_evidence": {
            "websocket_incomplete_cancellation": {
                "integrated_test_commit": "48761dbc",
                "owner_candidate_commit": "afa279b1",
                "scope": "four sequential incomplete-fragment cancellations for WS and WSS; zero retained anonymous spools and zero origin frames",
                "not_established": [
                    "RSS or allocator retention",
                    "concurrent, compressed or completed-message workloads",
                    "large-pattern scanner memory",
                ],
            },
        },
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
    run.add_argument("--python-source", type=Path, default=REPO,
                     help="explicit Python source checkout (recorded in candidate identity)")
    run.add_argument("--python-executable", type=Path, default=Path(sys.executable),
                     help="explicit Python interpreter used to launch the Python proxy")
    run.add_argument("--rust-binary", type=Path, default=os.environ.get("SAFEYOLO_RUST_PROXY"),
                     help="explicit native proxy executable; required for Rust captures")
    run.add_argument("--rust-build-profile", choices=("release", "debug", "unspecified"), default="unspecified",
                     help="declared Cargo profile for the selected native executable")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--evidence", type=Path, required=True)
    run.add_argument("--fixture-from", type=Path)
    run.add_argument("--requests", type=int, default=100)
    run.add_argument("--extended-workloads", action="store_true", help="Run SSE, WS, and unavailable local API workloads")
    run.add_argument("--workload", action="append",
                     choices=("short", "sse", "stream-control", "stream-slow-admin", "websocket", "local-api"),
                     help="Select individual workloads; overrides --extended-workloads")
    run.add_argument("--stream-seconds", type=float, default=2.0)
    run.add_argument("--websocket-seconds", type=float, default=0.0)
    run.add_argument("--websocket-interval", type=float, default=0.0)
    diff = commands.add_parser("compare")
    diff.add_argument("baseline", type=Path)
    diff.add_argument("candidate", type=Path)
    diff.add_argument("--scenario", action="append", choices=("http_direct", "http_parent", "local_containment"))
    args = parser.parse_args()
    if args.command == "compare":
        return compare(args)
    if args.requests < 1:
        parser.error("--requests must be positive")
    if args.backend == "rust" and args.rust_binary is None:
        parser.error("Rust capture requires --rust-binary or SAFEYOLO_RUST_PROXY")
    if not args.python_executable.is_file():
        parser.error(f"--python-executable is not a file: {args.python_executable}")
    if not args.python_source.is_dir():
        parser.error(f"--python-source is not a directory: {args.python_source}")
    if args.stream_seconds <= 0 or args.websocket_seconds < 0 or args.websocket_interval < 0:
        parser.error("stream duration must be positive; WebSocket duration and interval must be nonnegative")
    capture(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
