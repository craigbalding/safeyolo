"""Actual process circuit reload and restart, with the source watcher comparator.

Both lanes use their real policy loader, complete owned HTTP responses, and the
authenticated Agent API. Rust uses native policy with no temporary adapter. The
restart case retains the source's default-settings reconciliation before the
first ordinary request applies the current policy; no persisted bytes are edited.
"""

import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.proxy_migration.harness import python_proxy_environment
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.test_circuit_completion import circuits, completion_peer, wait_failure_count
from tests.proxy_migration.test_native_network_policy import ALLOW, policy_proxy, replace_policy
from tests.proxy_migration.test_operator_circuits import HOST, CircuitOrigin, hit


def policy(*, threshold, timeout):
    return (
        ALLOW
        + f"""
[addons.circuit_breaker]
failure_threshold = {threshold}
success_threshold = 1
timeout_seconds = {timeout}
use_exponential_backoff = false
jitter_factor = 0
"""
    )


@contextmanager
def reload_origin():
    origin = CircuitOrigin()
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    try:
        yield origin
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def assert_state(value, *, checks, opens, half_opens, recoveries, threshold, timeout, failures, state):
    assert {key: item for key, item in value.items() if key != "domains"} == {
        "enabled": True,
        "failure_threshold": threshold,
        "timeout_seconds": timeout,
        "checks_total": checks,
        "opens_total": opens,
        "half_opens_total": half_opens,
        "recoveries_total": recoveries,
    }
    assert list(value["domains"]) == [HOST]
    domain = value["domains"][HOST]
    assert domain["failure_count"] == failures and domain["state"] == state
    assert domain["failure_streak"] == 0
    if state != "open":
        assert domain["time_until_half_open"] is None
    else:
        assert 0 < domain["time_until_half_open"] <= timeout


def observe(proxy, stage, **expected):
    value = circuits(proxy)
    assert_state(value, **expected)
    with (proxy.event_log.parent / "circuit-reload.jsonl").open("a") as output:
        output.write(json.dumps({"stage": stage, "pid": proxy.process.pid, "circuits": value}) + "\n")
    return value


def assert_stopped(proxy, address, accepts):
    assert proxy.process.returncode == 0
    assert not proxy.readiness_file.exists()
    egress = proxy.events("proxy.egress")
    assert len(egress) == accepts
    assert all((row["host"], row["port"]) == address for row in egress)
    # launch_proxy owns and removes each instance's complete socket directory.
    for path in proxy.paths.values():
        with socket.socket(socket.AF_UNIX) as closed:
            assert closed.connect_ex(path) != 0


def git_head(path):
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def assert_comparator_source_is_clean(path):
    status = subprocess.check_output(
        ["git", "-C", str(path), "status", "--porcelain=v1", "--untracked-files=all"], text=True
    )
    assert not status, f"selected comparator source tree is dirty:\n{status}"
    ignored_source = subprocess.check_output(
        ["git", "-C", str(path), "ls-files", "--others", "--ignored", "--exclude-standard", "--", "cli/src"],
        text=True,
    )
    unexpected = [
        entry
        for entry in ignored_source.splitlines()
        if "__pycache__/" not in entry and not entry.endswith(".pyc")
    ]
    assert not unexpected, f"selected comparator has ignored source files: {unexpected}"


def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preserve_circuit_state(
    state_file, snapshot_file, *, backend, proxy, operation, effective
):
    shutil.copyfile(state_file, snapshot_file)
    raw = json.loads(snapshot_file.read_text())
    assert list(raw) == ["states", "saved_at"]
    assert list(raw["states"]) == [HOST]
    return {
        "backend": backend,
        "operation": operation,
        "file": snapshot_file.name,
        "sha256": file_sha256(snapshot_file),
        "raw": raw,
        "command": list(proxy.process.args),
        "exit_code": proxy.process.returncode,
        "effective": effective,
    }


def test_policy_reload_preserves_live_circuit_state_and_uses_new_settings(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with reload_origin() as origin:
        with policy_proxy(
            proxy_backend,
            directory,
            policy(threshold=3, timeout=120),
            agent_api=True,
            circuit_breaker_enabled=True,
        ) as proxy:
            hit(proxy, origin, "alice", "/failure", 500)
            wait_failure_count(proxy, 1)
            original = {
                "checks": 1,
                "opens": 0,
                "half_opens": 0,
                "recoveries": 0,
                "threshold": 3,
                "timeout": 120,
                "failures": 1,
                "state": "closed",
            }
            observe(proxy, "before-reload", **original)
            replace_policy(proxy, proxy_backend, directory, policy(threshold=2, timeout=120))
            # Reload preserves state; the API itself does not refresh settings.
            observe(proxy, "after-reload-before-request", **original)
            hit(proxy, origin, "bob", "/failure", 500)
            wait_failure_count(proxy, 2)
            opened = {
                "checks": 2,
                "opens": 1,
                "half_opens": 0,
                "recoveries": 0,
                "threshold": 2,
                "timeout": 120,
                "failures": 2,
                "state": "open",
            }
            observe(proxy, "new-threshold-opened", **opened)
            hit(proxy, origin, "alice", "/retry", 503)
            opened["checks"] = 3
            observe(proxy, "blocked-before-timeout-change", **opened)
            replace_policy(proxy, proxy_backend, directory, policy(threshold=4, timeout=0))
            observe(proxy, "after-timeout-reload-before-request", **opened)
            hit(proxy, origin, "bob", "/retry", 200)
            wait_failure_count(proxy, 0)
            observe(
                proxy,
                "new-timeout-recovered",
                checks=4,
                opens=1,
                half_opens=1,
                recoveries=1,
                threshold=4,
                timeout=0,
                failures=0,
                state="closed",
            )
        assert_stopped(proxy, origin.server_address, origin.accepts)
        assert origin.accepts == len(origin.requests) == 3


def test_old_admitted_response_uses_current_policy_after_reload(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with completion_peer("fixed") as peer:
        with policy_proxy(
            proxy_backend,
            directory,
            policy(threshold=10, timeout=120),
            agent_api=True,
            circuit_breaker_enabled=True,
        ) as proxy:
            target = f"http://{HOST}:{peer.address[1]}"
            status, _, body = send_request(proxy.paths["alice"], target + "/seed")
            assert status == 500 and body == b"seed"
            wait_failure_count(proxy, 1)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(5)
                client.connect(proxy.paths["bob"])
                client.sendall(
                    f"GET {target}/held HTTP/1.1\r\nHost: {HOST}:{peer.address[1]}\r\n"
                    "Connection: close\r\n\r\n".encode()
                )
                assert peer.held.wait(5), "origin never held the admitted response"
                pending = {
                    "checks": 2,
                    "opens": 0,
                    "half_opens": 0,
                    "recoveries": 0,
                    "threshold": 10,
                    "timeout": 120,
                    "failures": 1,
                    "state": "closed",
                }
                observe(proxy, "old-response-incomplete", **pending)
                try:
                    replace_policy(proxy, proxy_backend, directory, policy(threshold=2, timeout=90))
                    observe(proxy, "reloaded-before-old-completion", **pending)
                finally:
                    peer.release.set()
                response = http.client.HTTPResponse(client)
                response.begin()
                assert response.status == 500 and response.read() == b"abcdef"
                response.close()
                assert peer.finished.wait(5)
            wait_failure_count(proxy, 2)
            observe(
                proxy,
                "old-response-completed-with-current-settings",
                checks=2,
                opens=1,
                half_opens=0,
                recoveries=0,
                threshold=2,
                timeout=90,
                failures=2,
                state="open",
            )
            status, headers, _ = send_request(proxy.paths["alice"], target + "/blocked")
            assert status == 503 and {key.lower(): value for key, value in headers.items()}["x-circuit-state"] == "open"
            observe(
                proxy,
                "current-settings-remain-installed",
                checks=3,
                opens=1,
                half_opens=0,
                recoveries=0,
                threshold=2,
                timeout=90,
                failures=2,
                state="open",
            )
        assert_stopped(proxy, peer.address, peer.accepts)
        assert peer.accepts == 2


def test_graceful_restart_retains_saved_failure_state_and_resets_counters(proxy_backend, tmp_path):
    state_file = tmp_path / "persisted-circuit.json"
    source = policy(threshold=1, timeout=1)
    with reload_origin() as origin:
        first = tmp_path / "first" / proxy_backend
        with policy_proxy(
            proxy_backend,
            first,
            source,
            agent_api=True,
            circuit_breaker_enabled=True,
            circuit_state_file=state_file,
        ) as proxy:
            hit(proxy, origin, "alice", "/failure", 500)
            wait_failure_count(proxy, 1)
            observe(
                proxy,
                "before-graceful-stop",
                checks=1,
                opens=1,
                half_opens=0,
                recoveries=0,
                threshold=1,
                timeout=1,
                failures=1,
                state="open",
            )
        assert_stopped(proxy, origin.server_address, 1)
        first_pid = proxy.process.pid
        saved = json.loads(state_file.read_text())
        assert list(saved["states"]) == [HOST]
        failed = saved["states"][HOST]
        assert failed["state"] == "open" and failed["failure_count"] == 1
        assert failed["last_error"] == "HTTP 500"
        assert saved["saved_at"] >= failed["last_failure_time"] == failed["opened_at"]
        first_saved_bytes = state_file.read_bytes()
        # The next process reconciles with the source defaults (60 seconds),
        # then its first ordinary request applies the authored one-second retry.
        time.sleep(max(0, failed["opened_at"] + 1.05 - time.time()))
        second = tmp_path / "second" / proxy_backend
        with policy_proxy(
            proxy_backend,
            second,
            source,
            agent_api=True,
            circuit_breaker_enabled=True,
            circuit_state_file=state_file,
        ) as restarted:
            assert restarted.process.pid != first_pid
            observe(
                restarted,
                "restarted-before-first-request",
                checks=0,
                opens=0,
                half_opens=0,
                recoveries=0,
                threshold=5,
                timeout=60,
                failures=1,
                state="open",
            )
            assert state_file.read_bytes() == first_saved_bytes
            hit(restarted, origin, "bob", "/retry", 200)
            wait_failure_count(restarted, 0)
            observe(
                restarted,
                "restarted-and-recovered",
                checks=1,
                opens=0,
                half_opens=1,
                recoveries=1,
                threshold=1,
                timeout=1,
                failures=0,
                state="closed",
            )
        assert_stopped(restarted, origin.server_address, 1)
        recovered = json.loads(state_file.read_text())
        assert recovered["states"][HOST]["state"] == "closed"
        assert recovered["states"][HOST]["failure_count"] == 0
        assert recovered["states"][HOST]["last_failure_time"] == failed["last_failure_time"]
        assert recovered["saved_at"] >= saved["saved_at"]
        assert not list(state_file.parent.glob(f"{state_file.name}.*"))
        assert origin.accepts == len(origin.requests) == 2


def test_selected_python_native_python_circuit_state_transition(tmp_path, monkeypatch):
    """A real old/new process sequence keeps circuit state usable both ways."""
    comparator = os.environ.get("SAFEYOLO_CIRCUIT_COMPARATOR_SOURCE")
    binary = os.environ.get("SAFEYOLO_RUST_PROXY")
    if not comparator or not binary:
        pytest.skip("cross-backend rollback fixture requires pinned Python comparator and Rust binary")

    comparator = Path(comparator).expanduser().resolve()
    binary = Path(binary).expanduser().resolve()
    candidate = Path(__file__).resolve().parents[2]
    expected_comparator = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a"
    assert git_head(comparator) == expected_comparator
    assert_comparator_source_is_clean(comparator)
    assert binary.is_file()
    comparator_python = Path(
        os.environ.get("SAFEYOLO_POLICY_PYTHON", str(comparator / ".venv/bin/python"))
    ).expanduser()
    assert comparator_python.is_file()
    expected_comparator_python = comparator / ".venv/bin/python"
    assert comparator_python.samefile(expected_comparator_python)
    identity_script = (
        "import importlib.metadata,json,mitmproxy,safeyolo,sys; "
        "print(json.dumps({'program':sys.executable,"
        "'python_version':sys.version.split()[0],"
        "'safeyolo':importlib.metadata.version('safeyolo'),"
        "'mitmproxy':importlib.metadata.version('mitmproxy'),"
        "'safeyolo_file':safeyolo.__file__,"
        "'mitmproxy_file':mitmproxy.__file__}))"
    )
    identity = json.loads(
        subprocess.check_output(
            [str(comparator_python), "-c", identity_script],
            cwd=comparator,
            env=python_proxy_environment(python_source=comparator),
            text=True,
        )
    )
    assert Path(identity["program"]).resolve() == comparator_python.resolve()
    assert Path(identity["safeyolo_file"]).resolve().is_relative_to(comparator / "cli/src")
    assert Path(identity["mitmproxy_file"]).resolve().is_relative_to(comparator / ".venv")
    assert identity["python_version"] == "3.12.14"
    assert identity["safeyolo"] == "0.1.0"
    assert identity["mitmproxy"] == "12.2.3"

    # Only this rollback sequence runs the historical Python source. The suite's
    # selected Python backend remains the current candidate in other tests.
    monkeypatch.setenv("SAFEYOLO_PYTHON_SOURCE", str(comparator))
    comparator_fixture = comparator / "tests/proxy_migration/old_proxy.py"
    assert comparator_fixture.is_file()
    state_file = tmp_path / "shared-circuit.json"
    source = policy(threshold=1, timeout=1)
    manifest = {
        "comparator": {
            "path": str(comparator),
            "commit": git_head(comparator),
            "executable": str(comparator_python),
            **identity,
        },
        "candidate": {"path": str(candidate), "commit": git_head(candidate)},
        "rust_binary": {"path": str(binary), "sha256": file_sha256(binary)},
        "stages": [],
    }
    with reload_origin() as origin:
        python_before = tmp_path / "python-before"
        with policy_proxy(
            "python",
            python_before,
            source,
            agent_api=True,
            circuit_breaker_enabled=True,
            circuit_state_file=state_file,
            python_executable=comparator_python,
            python_fixture=comparator_fixture,
        ) as proxy:
            hit(proxy, origin, "alice", "/failure", 500)
            assert wait_failure_count(proxy, 1)["domains"][HOST]["state"] == "open"
            contacts = origin.accepts
            hit(proxy, origin, "bob", "/blocked-before-rollback", 503)
            assert origin.accepts == contacts
        assert_stopped(proxy, origin.server_address, 1)
        first_file = tmp_path / "01-python-open.json"
        first = preserve_circuit_state(
            state_file,
            first_file,
            backend="python",
            proxy=proxy,
            operation="write-open-and-block-before-rollback",
            effective={"open_block_status": 503, "origin_contacts": origin.accepts},
        )
        assert first["raw"]["states"][HOST]["state"] == "open"
        manifest["stages"].append(first)

        deadline = first["raw"]["states"][HOST]["opened_at"] + 1.05
        while time.time() < deadline:
            time.sleep(min(0.01, deadline - time.time()))

        native_before = tmp_path / "native-before"
        with policy_proxy(
            "rust",
            native_before,
            source,
            agent_api=True,
            circuit_breaker_enabled=True,
            circuit_state_file=state_file,
        ) as proxy:
            assert circuits(proxy)["domains"][HOST]["state"] == "open"
            contacts = origin.accepts
            hit(proxy, origin, "alice", "/rust-recovery", 200)
            assert origin.accepts == contacts + 1
            recovered = circuits(proxy)
            assert recovered["domains"][HOST]["state"] == "closed"
            assert recovered["domains"][HOST]["failure_count"] == 0
        assert_stopped(proxy, origin.server_address, 1)
        second_file = tmp_path / "02-rust-closed.json"
        second = preserve_circuit_state(
            state_file,
            second_file,
            backend="rust",
            proxy=proxy,
            operation="read-open-and-write-closed",
            effective={"loaded": "open", "wrote": "closed", "origin_contacts": origin.accepts},
        )
        assert second["raw"]["states"][HOST]["state"] == "closed"
        manifest["stages"].append(second)

        python_after = tmp_path / "python-after"
        with policy_proxy(
            "python",
            python_after,
            source,
            agent_api=True,
            circuit_breaker_enabled=True,
            circuit_state_file=state_file,
            python_executable=comparator_python,
            python_fixture=comparator_fixture,
        ) as proxy:
            assert circuits(proxy)["domains"][HOST]["state"] == "closed"
            hit(proxy, origin, "bob", "/failure", 500)
            assert wait_failure_count(proxy, 1)["domains"][HOST]["state"] == "open"
        assert_stopped(proxy, origin.server_address, 1)
        third_file = tmp_path / "03-python-reopened.json"
        third = preserve_circuit_state(
            state_file,
            third_file,
            backend="python",
            proxy=proxy,
            operation="read-closed-and-write-open",
            effective={"loaded": "closed", "wrote": "open", "origin_contacts": origin.accepts},
        )
        assert third["raw"]["states"][HOST]["state"] == "open"
        manifest["stages"].append(third)

        native_after = tmp_path / "native-after"
        with policy_proxy(
            "rust",
            native_after,
            source,
            agent_api=True,
            circuit_breaker_enabled=True,
            circuit_state_file=state_file,
        ) as proxy:
            assert circuits(proxy)["domains"][HOST]["state"] == "open"
            contacts = origin.accepts
            hit(proxy, origin, "alice", "/blocked-after-return", 503)
            assert origin.accepts == contacts
            deadline = third["raw"]["states"][HOST]["opened_at"] + 1.05
            while time.time() < deadline:
                time.sleep(min(0.01, deadline - time.time()))
            hit(proxy, origin, "alice", "/rust-final-recovery", 200)
            assert origin.accepts == contacts + 1
            assert circuits(proxy)["domains"][HOST]["state"] == "closed"
        assert_stopped(proxy, origin.server_address, 1)
        fourth_file = tmp_path / "04-rust-final-closed.json"
        fourth = preserve_circuit_state(
            state_file,
            fourth_file,
            backend="rust",
            proxy=proxy,
            operation="read-open-block-and-write-closed",
            effective={
                "loaded": "open",
                "open_block_status": 503,
                "wrote": "closed",
                "origin_contacts": origin.accepts,
            },
        )
        assert fourth["raw"]["states"][HOST]["state"] == "closed"
        manifest["stages"].append(fourth)
    assert origin.accepts == len(origin.requests) == 4
    assert all(stage["exit_code"] == 0 for stage in manifest["stages"])
    assert first["command"][:2] == third["command"][:2] == [str(comparator_python), str(comparator_fixture)]
    assert Path(second["command"][0]).resolve() == Path(fourth["command"][0]).resolve() == binary
    assert manifest["stages"][0]["sha256"] != manifest["stages"][1]["sha256"]
    for stage in manifest["stages"]:
        stage.pop("raw")
    (tmp_path / "cross-backend-circuit-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
