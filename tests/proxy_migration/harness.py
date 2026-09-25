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


class ReadinessError(AssertionError):
    """A selected proxy could not establish its owned startup contract."""


def python_proxy_command():
    """Launch the reviewed suite fixture by its file path.

    The source checkout selected for the product packages belongs on
    ``PYTHONPATH``.  The migration fixture itself belongs to this test suite,
    so invoking it as a module would let a selected source checkout shadow it.
    """
    return [sys.executable, str(REPO / "tests/proxy_migration/old_proxy.py")]


def python_proxy_environment(*, python_source=None):
    """Build the import path for a selected Python product checkout."""
    source_root = Path(python_source).expanduser().resolve() if python_source else REPO
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            [str(source_root / "cli/src"), str(source_root), str(REPO)]
        ),
    }


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
        process = subprocess.Popen(
            command,
            cwd=directory,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
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


def _connectable_unix_socket(path, *, timeout=0.25):
    """Return whether ``path`` is a real, accepting Unix stream socket."""
    try:
        if not path.is_socket():
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
    except OSError:
        return False
    return True


def wait_ready(process, paths, log, *, readiness_file=None, expected_backend=None,
               timeout=15, socket_timeout=0.25):
    paths = [Path(path) for path in paths]
    marker_path = Path(readiness_file) if readiness_file is not None else None
    if marker_path is not None and expected_backend is None:
        raise ValueError("expected_backend is required with a readiness marker")
    socket_paths = [path for path in paths if path != marker_path]
    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            raise ReadinessError(f"Proxy process exited {process.returncode}:\n{log.read_text()}")
        ready = all(_connectable_unix_socket(path, timeout=socket_timeout) for path in socket_paths)
        if ready and marker_path is not None:
            try:
                marker = json.loads(marker_path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                # The fixture may be replacing its marker; only a complete
                # marker naming this child can establish startup completion.
                ready = False
            else:
                ready = (
                    isinstance(marker, dict)
                    and marker.get("ready") is True
                    and marker.get("pid") == process.pid
                    and (expected_backend is None or marker.get("backend") == expected_backend)
                )
        if ready:
            return
        if time.monotonic() >= deadline:
            raise ReadinessError(f"Readiness timed out: {paths}\n{log.read_text()}")
        time.sleep(min(0.025, max(0, deadline - time.monotonic())))


@contextmanager
def launch_proxy(backend, directory, policy_text, *, parent_proxy=None, tls=False, upstream_ca=None,
                 ignore_hosts=(), eager_connect=False, inspection=None, native_policy=False,
                 network_guard_enabled=None, network_guard_block=None, network_guard_homoglyph=None,
                 agent_api=False, agent_api_token=b"fixture-agent-api-token-one", policy_format="toml",
                 admin_port=None, admin_api_token_file=None,
                 circuit_breaker_enabled=None, circuit_state_file=None, python_executable=None,
                 agent_map=None, stream_large_bodies=None, credential_head_decision=False,
                 flow_store_enabled=False, via_token=None,
                 gateway_services_dir=None, gateway_builtin_services_dir=None):
    """Start one explicitly selected implementation in isolated fixture state."""
    if policy_format not in {"toml", "yaml", "json"}:
        raise ValueError(f"Unknown fixture policy format: {policy_format}")
    directory.mkdir(parents=True, exist_ok=True)
    policy = directory / f"policy.{policy_format}"
    policy.write_text(policy_text)
    # Darwin's default temp root leaves too little sun_path for reloaded listeners.
    socket_root = "/tmp" if sys.platform == "darwin" else None
    with tempfile.TemporaryDirectory(prefix="sy-migration-", dir=socket_root) as sockets, ExitStack() as stack:
        if agent_map is None:
            paths = {name: str(Path(sockets) / f"10.0.0.{index}_{name}" / "proxy.sock")
                     for index, name in enumerate(("alice", "bob"), 2)}
        else:
            from safeyolo.sockets import path_for

            if not isinstance(agent_map, dict) or not all(
                isinstance(name, str) and isinstance(ip, str)
                for name, ip in agent_map.items()
            ):
                raise ValueError("agent_map must map agent names to IPv4 strings")
            data_dir = directory / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            (data_dir / "agent_map.json").write_text(
                json.dumps({name: {"ip": ip} for name, ip in agent_map.items()})
            )
            paths = {name: str(path_for(name, ip)) for name, ip in agent_map.items()}
        config = {
            "listeners": [{"agent_id": name, "socket_path": path} for name, path in paths.items()],
            # Native policy startup creates its process-owned credential HMAC
            # file even when the gateway fixture is not enabled.  Keep that
            # state inside this run so the selected Rust process never falls
            # back to the host's /safeyolo/data path.
            "readiness_file": str(directory / "ready"),
            "audit_log_path": str(directory / "audit.jsonl"),
            "event_log": str(directory / "events.jsonl"),
            # Keep native policy/evidence state inside this fixture. The Rust
            # default (/safeyolo/data) is unavailable in ordinary runs.
            "data_dir": str(directory / "data"),
            "flow_store_enabled": flow_store_enabled,
            "flow_store_db_path": str(directory / "flows.sqlite3"),
        }
        Path(config["data_dir"]).mkdir(parents=True, exist_ok=True)
        if agent_map is not None:
            config["agent_map_file"] = str(directory / "data" / "agent_map.json")
        if inspection is not None:
            config["inspection"] = {"policy_file": str(policy), **inspection}
        for name, value in (("network_guard_enabled", network_guard_enabled),
                            ("network_guard_block", network_guard_block),
                            ("network_guard_homoglyph", network_guard_homoglyph)):
            if value is not None:
                config[name] = value
        if upstream_ca:
            config["upstream_ca_file"] = str(upstream_ca)
        if via_token is not None:
            config["via_token"] = via_token
        if gateway_services_dir is not None:
            if gateway_builtin_services_dir is None:
                raise ValueError("Gateway fixture requires both service directories")
            config["gateway_services_dir"] = str(gateway_services_dir)
            config["gateway_builtin_services_dir"] = str(gateway_builtin_services_dir)
        if admin_port is not None:
            config["admin_port"] = admin_port
        if admin_api_token_file is not None:
            config["admin_api_token_file"] = str(admin_api_token_file)
        if circuit_breaker_enabled is not None or circuit_state_file is not None:
            config["circuit_breaker_enabled"] = True if circuit_breaker_enabled is None else circuit_breaker_enabled
            config["circuit_state_file"] = str(directory / "circuit-state.json") if circuit_state_file is None else str(circuit_state_file)
        # An explicit source checkout is part of backend identity.  Keep the
        # test modules from this checkout on the inherited path while making
        # the launched Python proxy import the caller-selected package.
        python_source = os.environ.get("SAFEYOLO_PYTHON_SOURCE")
        env = python_proxy_environment(python_source=python_source)
        env["SAFEYOLO_LOG_PATH"] = str(directory / "audit.jsonl")
        if agent_api:
            api_data = directory / "api-data"
            api_data.mkdir()
            if agent_api_token is not None:
                token_file = api_data / "agent_token"
                token_file.touch(mode=0o600)
                token_file.write_bytes(agent_api_token)
            env["SAFEYOLO_DATA_DIR"] = str(api_data)
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
            config.update(ignore_hosts=list(ignore_hosts), connection_strategy="eager" if eager_connect else "lazy")
            if stream_large_bodies is not None:
                config["stream_large_bodies"] = stream_large_bodies
            if credential_head_decision:
                config["fixture_credential_head_decision"] = True
                env["SAFEYOLO_DATA_DIR"] = config["data_dir"]
            config["fixture_agent_api"] = agent_api
            if gateway_services_dir is not None:
                config["fixture_gateway"] = True
            selected_python = python_executable or os.environ.get("SAFEYOLO_PYTHON_EXECUTABLE")
            command = [str(selected_python or sys.executable), str(REPO / "tests/proxy_migration/old_proxy.py")]
        elif backend == "rust":
            config["ignore_hosts"] = list(ignore_hosts)
            config["agent_api_enabled"] = agent_api
            # Release acceptance must exercise the native policy/inspection
            # path.  Keep the temporary adapter available for direct,
            # development comparisons, but let the selected runner force
            # native policy for every Rust fixture.
            native_policy_only = os.environ.get("SAFEYOLO_RUST_NATIVE_ONLY") == "1"
            use_native_policy = native_policy or native_policy_only
            if use_native_policy:
                config["policy_file"] = str(policy)
            else:
                policy_socket = str(Path(sockets) / "policy.sock")
                bridge_directory = directory / "policy-bridge"
                bridge_directory.mkdir()
                bridge = stack.enter_context(child_process(
                    [sys.executable, str(REPO / "tools/proxy_migration/temporary_policy.py"),
                     "--socket", policy_socket, "--policy", str(policy)], bridge_directory, env,
                ))
                wait_ready(bridge, [Path(policy_socket)], bridge_directory / "process.log")
                config["temporary_policy_socket"] = policy_socket
            (directory / "native-policy-provenance.json").write_text(
                json.dumps(
                    {
                        "backend": "rust",
                        "policy_mode": "native" if use_native_policy else "temporary_adapter",
                        "policy_file": config.get("policy_file"),
                        "temporary_policy_socket": config.get("temporary_policy_socket"),
                        "temporary_policy_adapter": bridge is not None,
                    },
                    indent=2,
                )
                + "\n"
            )
            if tls:
                config["tls_ca_file"] = str(directory / "ca/mitmproxy-ca.pem")
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
        wait_ready(
            process,
            [readiness, *map(Path, paths.values())],
            directory / "process.log",
            readiness_file=readiness,
            expected_backend="python" if backend == "python" else "rust-m2",
        )
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
