"""Process launch seam shared by old and Rust proxy contract scenarios."""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def read_events(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


@dataclass
class RunningProxy:
    paths: dict[str, str]
    event_log: Path
    process: subprocess.Popen
    readiness_file: Path
    policy_process: subprocess.Popen | None = None

    def events(self, kind):
        return [row for row in read_events(self.event_log) if row["event"] == kind]


@contextmanager
def child_process(command, directory, env):
    with (directory / "process.log").open("w") as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise AssertionError(f"Process did not shut down: {command}")


def wait_ready(process, paths, log, *, readiness_file=None):
    deadline = time.monotonic() + 15
    while True:
        if process.poll() is not None:
            raise AssertionError(f"Proxy process exited {process.returncode}:\n{log.read_text()}")
        ready = all(path.exists() for path in paths)
        if ready and readiness_file is not None:
            try:
                marker = json.loads(readiness_file.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                # The fixture may be replacing its marker; only a complete
                # marker naming this child can establish startup completion.
                ready = False
            else:
                ready = isinstance(marker, dict) and marker.get("ready") is True and marker.get("pid") == process.pid
        if ready:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"Readiness timed out: {paths}\n{log.read_text()}")
        time.sleep(0.025)


@contextmanager
def launch_proxy(backend, directory, policy_text, *, parent_proxy=None):
    """Start one explicitly selected implementation in isolated fixture state."""
    directory.mkdir(parents=True, exist_ok=True)
    policy = directory / "policy.toml"
    policy.write_text(policy_text)
    with tempfile.TemporaryDirectory(prefix="sy-migration-") as sockets, ExitStack() as stack:
        paths = {name: str(Path(sockets) / f"10.0.0.{index}_{name}" / "proxy.sock")
                 for index, name in enumerate(("alice", "bob"), 2)}
        config = {
            "listeners": [{"agent_id": name, "socket_path": path} for name, path in paths.items()],
            "readiness_file": str(directory / "ready"),
            "event_log": str(directory / "events.jsonl"),
        }
        env = {**os.environ,
               "PYTHONPATH": os.pathsep.join([str(REPO / "cli/src"), str(REPO)]),
               "SAFEYOLO_LOG_PATH": str(directory / "audit.jsonl")}
        bridge = None
        # The explicit product parent setting belongs to this fixture. Standard
        # HTTP(S)_PROXY and CA environment variables remain untouched.
        if parent_proxy:
            env["SAFEYOLO_UPSTREAM_PROXY"] = parent_proxy
            config["parent_proxy"] = parent_proxy
        else:
            env.pop("SAFEYOLO_UPSTREAM_PROXY", None)
        if backend == "python":
            config.update(policy_file=str(policy), ca_directory=str(directory / "ca"))
            command = [sys.executable, "-m", "tests.proxy_migration.old_proxy"]
        elif backend == "rust":
            policy_socket = str(Path(sockets) / "policy.sock")
            bridge_directory = directory / "policy-bridge"
            bridge_directory.mkdir()
            bridge = stack.enter_context(child_process(
                [sys.executable, str(REPO / "tools/proxy_migration/temporary_policy.py"),
                 "--socket", policy_socket, "--policy", str(policy)], bridge_directory, env,
            ))
            wait_ready(bridge, [Path(policy_socket)], bridge_directory / "process.log")
            config["temporary_policy_socket"] = policy_socket
            binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", str(REPO / "proxy/target/debug/safeyolo-proxy")))
            if not binary.is_file():
                raise FileNotFoundError(f"Build the Rust proxy or set SAFEYOLO_RUST_PROXY: {binary}")
            command = [str(binary)]
        else:
            raise ValueError(f"Unknown proxy backend: {backend}")
        config_path = directory / "proxy.json"
        config_path.write_text(json.dumps(config))
        process = stack.enter_context(child_process(command + ["--config", str(config_path)], directory, env))
        readiness = Path(config["readiness_file"])
        wait_ready(process, [readiness, *map(Path, paths.values())], directory / "process.log", readiness_file=readiness)
        yield RunningProxy(paths, Path(config["event_log"]), process, readiness, bridge)


def connection(path):
    """Speak ordinary HTTP proxy wire format over the trusted UDS listener."""
    client = http.client.HTTPConnection("fixture", timeout=5)
    client.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.sock.settimeout(5)
    try:
        client.sock.connect(path)
    except OSError:
        client.close()
        raise
    return client


def request(path, url, *, headers=None, method="GET", body=None):
    client = connection(path)
    try:
        client.request(method, url, headers=headers or {}, body=body)
        response = client.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        client.close()
