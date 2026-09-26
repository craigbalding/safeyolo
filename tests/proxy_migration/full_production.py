"""Run the real production proxy with isolated state and a private pseudo-terminal.

Only synthetic fixture tokens and owned ephemeral loopback/UDS endpoints are
used. Standard sandbox proxy and CA environment variables remain unchanged.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import errno
import fcntl
import hashlib
import http.client
import json
import os
import platform
import pty
import secrets
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from tests.proxy_migration.harness import REPO, request
from tests.proxy_migration.run import memory_kib as memory
from tests.proxy_migration.scenarios import origin_server


def json_write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def latencies(samples):
    values = sorted(samples)
    return {
        "count": len(values),
        "median_ms": statistics.median(values),
        "p95_ms": values[max(0, int(len(values) * 0.95) - 1)],
        "max_ms": max(values),
    }


def launch(settings_path):
    """Reuse the production command builder, then execute its traffic master."""
    from safeyolo.proxy import _build_command

    settings = json.loads(settings_path.read_text())
    root = Path(settings["root"])
    command = _build_command(
        cert_dir=root / "config/certs",
        config_dir=root / "config",
        data_dir=root / "config/data",
        logs_dir=root / "logs",
        admin_token="",
        admin_port=settings["admin_port"],
        proxy_config={"web_host": "127.0.0.1", "web_port": settings["web_port"]},
    )
    json_write(root / "command.json", command)
    os.execve(sys.executable, command, os.environ)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--launch-config", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--approvals", type=int, default=30, help="Network approval transactions")
    parser.add_argument("--api-requests", type=int, default=150, help="Authenticated calls per API worker")
    parser.add_argument("--api-workers", type=int, default=4, help="Concurrent authenticated API workers")
    args = parser.parse_args(arguments)
    if args.launch_config:
        launch(args.launch_config)
        return 0
    if args.output is None:
        parser.error("--output is required")
    if min(args.approvals, args.api_requests, args.api_workers) < 1:
        parser.error("workload counts must be positive")
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    config, data, logs = root / "config", root / "config/data", root / "logs"
    for path in (config, data, logs, config / "services", root / "coord"):
        path.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO / "config/addons.yaml", config / "addons.yaml")
    (config / "policy.toml").write_text(
        'budget = 60000\n[hosts]\n"*" = { egress = "prompt" }\n[agents.alice]\n[agents.bob]\n'
    )
    agent_token, admin_token, web_password = (secrets.token_hex(32) for _ in range(3))
    for name, value in [("agent_token", agent_token), ("admin_token", admin_token), ("web_password", web_password)]:
        target = data / name
        target.touch(mode=0o600)
        target.write_text(value + "\n")
    json_write(data / "agent_map.json", {"alice": {"ip": "10.0.0.2"}, "bob": {"ip": "10.0.0.3"}})
    admin_port, web_port = port(), port()
    result = {
        "schema": 1,
        "captured_at": datetime.now(UTC).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "production_source_dirty": bool(
            subprocess.check_output(["git", "diff", "--", "cli/src/safeyolo", "pdp"], cwd=REPO, text=True)
        ),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version,
        "versions": {name: version(name) for name in ["mitmproxy", "httpx", "pytest"]},
        "fixture_sha256": {
            str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (
                Path(__file__),
                REPO / "tests/proxy_migration/harness.py",
                REPO / "tests/proxy_migration/run.py",
                REPO / "tests/proxy_migration/scenarios.py",
            )
        },
        "command": sys.argv,
        "checks": [],
        "workloads": [],
        "status": "running",
        "scope": "real safeyolo.traffic_master and full production addon chain; private PTY console and loopback web/admin listeners",
        "isolation": {
            "config": str(config),
            "data": str(data),
            "logs": str(logs),
            "coord": str(root / "coord"),
            "origin": "owned ephemeral loopback HTTP server",
            "admin_port": admin_port,
            "web_port": web_port,
            "credentials": "fresh synthetic fixture tokens, removed after shutdown",
            "network_environment": "standard proxy and CA environment preserved; no live sandbox API queried",
        },
        "known_failures": [],
        "not_proven": [
            "approval expiry or one-shot service grant consumption",
            "interactive console/web operations",
            "service credential injection",
            "long-duration bounded memory",
            "macOS host ingress",
            "Rust API/approval parity",
        ],
    }
    source = ast.parse((REPO / "cli/src/safeyolo/mitm_addons/__init__.py").read_text())
    result["production_chain"] = ast.literal_eval(
        next(
            n.value
            for n in source.body
            if isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "ADDON_CHAIN" for x in n.targets)
        )
    )
    process = None
    console_master = None
    console_thread = None
    samples = []
    sampling_stop = threading.Event()
    started = time.perf_counter()
    try:
        with tempfile.TemporaryDirectory(prefix="sy-full-") as socket_root, origin_server() as origin:
            paths = {
                name: str(Path(socket_root) / f"10.0.0.{i}_{name}" / "proxy.sock")
                for i, name in enumerate(["alice", "bob"], 2)
            }
            settings = {"root": str(root), "admin_port": admin_port, "web_port": web_port}
            json_write(root / "settings.json", settings)
            env = dict(os.environ)
            # Remove only inherited SafeYolo application overrides. Never remove
            # the sandbox's standard HTTP(S)_PROXY or CA trust environment.
            for key in list(env):
                if key.startswith("SAFEYOLO_") or key in {
                    "MITMPROXY_LOG_PATH",
                    "CREDGUARD_HMAC_SECRET",
                    "NETWORK_GUARD_BLOCK",
                    "CREDGUARD_BLOCK",
                    "PATTERN_BLOCK",
                    "TEST_CONTEXT_BLOCK",
                    "PATTERN_BLOCK_WEBSOCKET_REQUEST",
                    "PATTERN_BLOCK_WEBSOCKET_RESPONSE",
                }:
                    env.pop(key)
            env.update(
                {
                    "PYTHONPATH": os.pathsep.join([str(REPO / "cli/src"), str(REPO)]),
                    "SAFEYOLO_CONFIG_DIR": str(config),
                    "SAFEYOLO_DATA_DIR": str(data),
                    "SAFEYOLO_LOGS_DIR": str(logs),
                    "SAFEYOLO_LOG_PATH": str(logs / "audit.jsonl"),
                    "MITMPROXY_LOG_PATH": str(logs / "mitmproxy.log"),
                    "SAFEYOLO_COORD_DATA_DIR": str(root / "coord"),
                    "SAFEYOLO_PROXY_PID_FILE": str(root / "ready"),
                    "SAFEYOLO_DEFER_PROXY_READY": "1",
                    "SAFEYOLO_INITIAL_MODES": json.dumps([f"unix:{p}" for p in paths.values()]),
                    "SAFEYOLO_WEB_PASSWORD_FILE": str(data / "web_password"),
                    "SAFEYOLO_VIA_TOKEN": "fixture-full-production",
                    "SAFEYOLO_DEV_MODE": "1",
                    "SAFEYOLO_DEV_SOURCE_ROOTS": json.dumps(
                        {"pdp": str(REPO / "pdp"), "safeyolo": str(REPO / "cli/src/safeyolo")}
                    ),
                    "TERM": "xterm-256color",
                }
            )
            console_master, console_slave = pty.openpty()
            fcntl.ioctl(console_slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "tests.proxy_migration.full_production",
                    "--launch-config",
                    str(root / "settings.json"),
                ],
                env=env,
                cwd=REPO,
                stdin=console_slave,
                stdout=console_slave,
                stderr=console_slave,
                start_new_session=True,
            )
            os.close(console_slave)
            result["proxy_pid"] = process.pid

            def read_console():
                with (logs / "console.log").open("wb") as stream:
                    while True:
                        try:
                            chunk = os.read(console_master, 16384)
                        except OSError as error:
                            # Linux PTY masters report EIO after the final slave
                            # closes. Other read failures must remain visible.
                            if error.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        for secret in [agent_token, admin_token, web_password]:
                            chunk = chunk.replace(secret.encode(), b"<synthetic-token-redacted>")
                        stream.write(chunk)

            console_thread = threading.Thread(target=read_console, daemon=True)
            console_thread.start()
            deadline = time.monotonic() + 30
            while not (root / "ready").exists():
                if process.poll() is not None:
                    raise RuntimeError(f"Production startup exited {process.returncode}; see console.log")
                if time.monotonic() > deadline:
                    raise TimeoutError("Production readiness deadline; see console.log")
                time.sleep(0.025)
            result["startup_seconds"] = time.perf_counter() - started
            assert (root / "ready").read_text().strip() == str(process.pid)
            assert all(Path(p).exists() for p in paths.values())
            result["checks"].append(
                "real production entrypoint ready marker matches PID; both trusted UDS listeners exist"
            )

            def admin(path, *, method="GET", body=None, auth=True):
                client = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
                headers = {"Authorization": "Bearer " + admin_token} if auth else {}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                try:
                    client.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
                    response = client.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    client.close()

            def api(path, agent="alice", auth=True):
                headers = (
                    {
                        "Authorization": "Bearer " + agent_token,
                        "X-SafeYolo-Agent": "bob" if agent == "alice" else "alice",
                    }
                    if auth
                    else {}
                )
                status, _, body = request(paths[agent], "http://_safeyolo.proxy.internal" + path, headers=headers)
                return status, json.loads(body)

            assert api("/health")[0] == 200 and api("/health")[1] == {"agent_api": "ok", "pdp": "ok"}
            assert api("/health", auth=False)[0] == 401
            assert admin("/stats", auth=False)[0] == 401
            assert admin("/health", auth=False)[0] == 200
            status, identity = admin("/admin/runtime-identity")
            assert status == 200
            json_write(root / "runtime-identity.json", identity)
            status, addons = admin("/debug/addons")
            assert status == 200
            json_write(root / "addons.json", addons)
            result["checks"].append(
                "authenticated Agent API and PDP healthy; absent agent/admin credentials return 401; admin health remains public"
            )
            # Prove a real requested network approval changes delivery only for Alice.
            origin_port = origin.server_address[1]
            target = f"http://127.0.0.1:{origin_port}/full-production-approval"
            before = origin.accepts
            status, _, body = request(paths["alice"], target)
            assert status == 428, (status, body)
            assert origin.accepts == before
            deadline = time.monotonic() + 3
            while True:
                status, pending = admin("/admin/approvals")
                assert status == 200
                if pending["approvals"]:
                    break
                assert time.monotonic() < deadline, "network prompt missing from durable pending approvals"
                time.sleep(0.02)
            json_write(root / "pending-before.json", pending)
            status, grant = admin(
                "/admin/policy/host/allow",
                method="POST",
                body={"host": "127.0.0.1", "port": origin_port, "agent": "alice"},
            )
            assert status == 200, (status, grant)
            status, _, body = request(paths["alice"], target)
            assert status == 200 and body == b"hello", (status, body)
            accepted = origin.accepts
            status, _, body = request(paths["bob"], target)
            assert status == 428, (status, body)
            assert origin.accepts == accepted
            for agent, effect in [("alice", "allow"), ("bob", "prompt")]:
                status, lookup = api(f"/lookup?host=127.0.0.1&port={origin_port}&scheme=http", agent)
                assert status == 200 and lookup["agent"] == agent and lookup["effect"] == effect, lookup
            status, lookup = api(
                f"/lookup?host=127.0.0.1&port={origin_port + 1 if origin_port < 65535 else origin_port - 1}&scheme=http"
            )
            assert status == 200 and lookup["effect"] == "prompt"
            assert api("/api/flows/search")[0] == 200
            assert api("/memory")[0] == 200 and api("/budgets")[0] == 200
            result["checks"].append(
                "428 creates durable approval; admin endpoint grants Alice exact host+port; allowed delivery reaches owned origin; Bob and another port remain prompt; spoofed agent header ignored"
            )
            result["memory_ready_kib"] = memory(process.pid)

            def sample_memory():
                while not sampling_stop.wait(0.05):
                    try:
                        samples.append({"elapsed_seconds": time.perf_counter() - started, **memory(process.pid)})
                    except FileNotFoundError:
                        # The process may exit between the interval and read.
                        # The main workload still checks its termination status.
                        return

            sampler = threading.Thread(target=sample_memory, daemon=True)
            sampler.start()
            api_samples, approval_samples = [], []
            barrier = threading.Barrier(args.api_workers + 1)

            def api_worker(worker):
                local = []
                barrier.wait()
                for index in range(args.api_requests):
                    path = [
                        "/health",
                        "/budgets",
                        "/status",
                        "/lookup?host=127.0.0.1&port=" + str(origin_port) + "&scheme=http",
                    ][index % 4]
                    tick = time.perf_counter()
                    status, payload = api(path, "alice" if worker % 2 == 0 else "bob")
                    assert status == 200, (path, status, payload)
                    local.append((time.perf_counter() - tick) * 1000)
                return local

            def approval_worker():
                barrier.wait()
                for index in range(args.approvals):
                    # CONNECT admission denies before DNS. Granting a synthetic
                    # .invalid endpoint is checked by lookup, never dialed.
                    host = f"approval-{index:04d}.invalid"
                    tick = time.perf_counter()
                    status, _, body = request(paths["alice"], f"{host}:443", method="CONNECT")
                    assert status == 428, (status, body)
                    status, grant = admin(
                        "/admin/policy/host/allow", method="POST", body={"host": host, "port": 443, "agent": "alice"}
                    )
                    assert status == 200, (status, grant)
                    status, lookup = api(f"/lookup?host={host}&port=443")
                    assert status == 200 and lookup["effect"] == "allow" and lookup["agent"] == "alice", lookup
                    status, lookup = api(f"/lookup?host={host}&port=443", "bob")
                    assert status == 200 and lookup["effect"] == "prompt" and lookup["agent"] == "bob", lookup
                    approval_samples.append((time.perf_counter() - tick) * 1000)

            load_started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.api_workers + 1) as pool:
                futures = [pool.submit(api_worker, index) for index in range(args.api_workers)]
                approval_future = pool.submit(approval_worker)
                for future in futures:
                    api_samples.extend(future.result())
                approval_future.result()
            elapsed = time.perf_counter() - load_started
            result["workloads"].append(
                {
                    "name": "concurrent_authenticated_api_and_network_approvals",
                    "api_workers": args.api_workers,
                    "api_requests": len(api_samples),
                    "approval_transactions": len(approval_samples),
                    "elapsed_seconds": elapsed,
                    "api_requests_per_second": len(api_samples) / elapsed,
                    "approval_transactions_per_second": len(approval_samples) / elapsed,
                    "api_latency": latencies(api_samples),
                    "approval_transaction_latency": latencies(approval_samples),
                    "approval_transaction": "CONNECT prompt + admin host/port/agent allow + Alice allow lookup + Bob prompt lookup",
                    "state_growth": "one new agent-scoped exact endpoint approval per transaction",
                    "scope": "all requests use fresh connections; rate is over combined workload wall time",
                }
            )
            time.sleep(0.25)
            result["memory_after_kib"] = memory(process.pid)
            assert result["memory_after_kib"] is not None
            assert "VmRSS" in result["memory_after_kib"]
            sampling_stop.set()
            sampler.join(timeout=2)
            json_write(root / "memory-samples.json", samples)
            rss = [sample["VmRSS"] for sample in samples]
            result["memory_measurement"] = {
                "samples": len(samples),
                "interval_seconds": 0.05,
                "peak_observed_rss_kib": max(rss) if rss else None,
                "steady_second_half_median_rss_kib": statistics.median(rss[len(rss) // 2 :]) if rss else None,
                "lifetime_high_water_kib": result["memory_after_kib"].get("VmHWM"),
                "scope": "single complete production traffic process including console/web/admin; RSS is Linux /proc measurement",
                "limitation": "short workload with intentionally growing approval/view state; not proof of a long-duration plateau",
            }
            status, pending = admin("/admin/approvals")
            assert status == 200
            json_write(root / "pending-after.json", pending)
            assert all(event.get("agent") != "alice" for event in pending["approvals"]), pending
            status, stats = admin("/stats")
            assert status == 200
            json_write(root / "stats-after.json", stats)
            result["origin_accepts"] = origin.accepts
            result["checks"].append(
                "all concurrent authenticated API calls and network approval transactions completed with expected agent-scoped results"
            )
            process.terminate()
            process.wait(timeout=10)
            console_thread.join(timeout=2)
            os.close(console_master)
            console_master = None
            assert process.returncode == 0, process.returncode
            assert not (root / "ready").exists()
            stale = [name for name, path in paths.items() if Path(path).exists()]
            stopped = {}
            for name, path in paths.items():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    try:
                        probe.connect(path)
                    except OSError as error:
                        if error.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
                            raise
                        stopped[name] = {"accepting": False, "errno": error.errno}
                    else:
                        stopped[name] = {"accepting": True}
            assert not any(item["accepting"] for item in stopped.values()), stopped
            result["shutdown"] = {
                "exit_code": process.returncode,
                "readiness_removed": not (root / "ready").exists(),
                "stale_socket_files": stale,
                "socket_accept_checks": stopped,
            }
            if stale:
                result["known_failures"].append(
                    {
                        "check": "shutdown_removes_socket_files",
                        "observed": stale,
                        "expected": [],
                        "reference": "cli/src/safeyolo/proxy.py::stop_proxy docstring says stopping removes socket files",
                        "impact": "dead socket pathnames remain; no live listener remains; fixture directory teardown removes them",
                    }
                )
            result["checks"].append("SIGTERM exits0 and removes readiness; no UDS listener accepts after exit")
            events = [json.loads(line) for line in (logs / "audit.jsonl").read_text().splitlines() if line.strip()]
            result["audit_event_counts"] = dict(Counter(event.get("event", "") for event in events))
            failures = [
                event
                for event in events
                if event.get("event")
                in {
                    "security.agent_api_reached_upstream",
                    "security.probe_reached_upstream",
                    "ops.flow_record_error",
                    "ops.proxy_start_failed",
                }
            ]
            assert not failures, failures
            result["checks"].append("no reserved-route egress, flow-record error, or startup-failure audit events")
            result["status"] = "completed_with_gaps" if result["known_failures"] else "passed"
    except Exception as error:
        result["status"] = "failed"
        result["failure"] = {"class": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    finally:
        sampling_stop.set()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if console_thread is not None:
            console_thread.join(timeout=2)
        if console_master is not None:
            os.close(console_master)
        # Evidence preserves no synthetic private token or CA key material.
        for name in ["agent_token", "admin_token", "web_password", "hmac_secret"]:
            (data / name).unlink(missing_ok=True)
        for name in ["mitmproxy-ca.pem", "mitmproxy-ca.p12"]:
            (config / "certs" / name).unlink(missing_ok=True)
        if result["status"] == "running":
            result["status"] = "interrupted"
        result["completed_at"] = datetime.now(UTC).isoformat()
        json_write(root / "result.json", result)
        print(
            json.dumps(
                {
                    "result": str(root / "result.json"),
                    "status": result["status"],
                    "checks": result["checks"],
                    "failure": result.get("failure"),
                    "known_failures": result["known_failures"],
                    "workloads": result["workloads"],
                    "memory": result.get("memory_measurement"),
                }
            )
        )
    return 0 if result["status"] in {"passed", "completed_with_gaps"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
