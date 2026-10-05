"""Tests for safeyolo doctor command."""

import json
import ssl
import subprocess
from types import SimpleNamespace
from unittest.mock import create_autospec

import httpx
import pytest
import yaml

from safeyolo.commands.doctor import (
    DiagResult,
    _build_bundle,
    _check_admin_api,
    _check_baseline,
    _check_ca_cert,
    _check_config_dir,
    _check_coord_message_plane,
    _check_firewall,
    _check_flow_store,
    _check_guest_images,
    _check_isolation_platform,
    _check_log_health,
    _check_pipeline_probe,
    _check_proxy_process,
    _check_runtime_identity,
    _check_sandbox_runtime,
    _check_tokens,
    _check_upstream_ca_cert,
    _check_vsock_term,
    _run_checks,
)


class _OpenSocket:
    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestCheckConfigDir:
    def test_config_dir_exists(self, tmp_config_dir):
        result = _check_config_dir()
        assert result.status == "pass"
        assert "Found" in result.message

    def test_config_dir_missing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "nonexistent"))
        result = _check_config_dir()
        assert result.status == "fail"
        assert "safeyolo init" in result.remediation


class TestCheckProxyRunning:
    def test_native_process_reports_binary_and_readiness(self, monkeypatch):
        from safeyolo import rust_proxy

        process = SimpleNamespace(pid=12345, binary_path="/usr/bin/safeyolo-proxy", config_file="/state/native.json")
        monkeypatch.setattr(rust_proxy, "read_process", lambda: process)
        monkeypatch.setattr(rust_proxy, "is_alive", lambda current: current is process)
        monkeypatch.setattr(rust_proxy, "readiness", lambda current: {"ready": True})
        result = _check_proxy_process()
        assert result.status == "pass"
        assert "PID 12345" in result.message
        assert "/usr/bin/safeyolo-proxy" in result.detail

    def test_native_process_missing_or_not_ready(self, monkeypatch):
        from safeyolo import rust_proxy

        monkeypatch.setattr(rust_proxy, "read_process", lambda: None)
        assert _check_proxy_process().status == "fail"
        process = SimpleNamespace(pid=12345, binary_path=None, config_file=None)
        monkeypatch.setattr(rust_proxy, "read_process", lambda: process)
        monkeypatch.setattr(rust_proxy, "is_alive", lambda current: True)
        monkeypatch.setattr(rust_proxy, "readiness", lambda current: None)
        assert _check_proxy_process().status == "fail"


class TestCheckRuntimeIdentity:
    def test_native_binary_identity_and_missing_path(self, monkeypatch, tmp_path):
        from safeyolo import rust_proxy

        binary = tmp_path / "safeyolo-proxy"
        binary.write_text("owned")
        process = SimpleNamespace(pid=12345, binary_path=str(binary))
        monkeypatch.setattr(rust_proxy, "read_process", lambda: process)
        monkeypatch.setattr(rust_proxy, "is_alive", lambda current: True)
        assert _check_runtime_identity().status == "pass"
        binary.unlink()
        assert _check_runtime_identity().status == "warn"
        monkeypatch.setattr(rust_proxy, "is_alive", lambda current: False)
        assert _check_runtime_identity().status == "fail"


class TestCheckCoordMessagePlane:
    def test_not_running_result_is_stable_and_credential_free(
        self, monkeypatch
    ):
        raw_secret = "credential-value-that-must-not-render"
        monkeypatch.setattr(
            "safeyolo.coord.nats_runtime.status",
            lambda: {
                "state": "not-running",
                "binary": "/tmp/nats-server",
                "listen": "127.0.0.1:4222",
                "config": "/tmp/nats.conf",
                "log_file": "/tmp/nats-server.log",
                "credential": raw_secret,
            },
        )

        result = _check_coord_message_plane()

        assert result.name == "Coord message plane"
        assert result.status == "warn"
        assert result.message == "nats-server not running; coord API will 503"
        if raw_secret in repr(result):
            pytest.fail("coord doctor result rendered a raw NATS credential")


class TestCheckVsockTerm:
    def test_skips_on_linux(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        result = _check_vsock_term()
        assert result.status == "skip"

    def test_fails_on_macos_when_missing(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        result = _check_vsock_term()
        assert result.status == "fail"
        assert "vsock-term" in result.message
        assert result.remediation == "make -C vm install"

    def test_fails_on_macos_when_not_executable(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        bin_dir = tmp_config_dir / "bin"
        bin_dir.mkdir()
        vsock_term = bin_dir / "vsock-term"
        vsock_term.write_text("#!/bin/sh\n")
        vsock_term.chmod(0o644)

        result = _check_vsock_term()

        assert result.status == "fail"
        assert "not executable" in result.message
        assert result.remediation == "make -C vm install"

    def test_passes_on_macos_when_executable(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        bin_dir = tmp_config_dir / "bin"
        bin_dir.mkdir()
        vsock_term = bin_dir / "vsock-term"
        vsock_term.write_text("#!/bin/sh\n")
        vsock_term.chmod(0o755)

        result = _check_vsock_term()

        assert result.status == "pass"
        assert str(vsock_term) in result.message


class TestCheckDarwinSandboxRuntime:
    def test_pass_requires_successful_helper_probe(self, monkeypatch, tmp_path):
        helper = tmp_path / "safeyolo-vm"
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("platform.machine", lambda: "arm64")
        monkeypatch.setattr(
            "safeyolo.vm.probe_vm_helper",
            lambda: helper,
        )

        result = _check_sandbox_runtime()

        assert result.status == "pass"
        assert "capability check passed" in result.message
        assert str(helper) in result.message

    @pytest.mark.parametrize(
        "failure",
        [
            "safeyolo-vm is not executable",
            "Could not launch safeyolo-vm capability check",
            "safeyolo-vm capability check timed out after 3s",
            "safeyolo-vm capability check failed with exit code 1: Error: Virtualization is not supported",
        ],
    )
    def test_probe_failures_never_report_pass(self, monkeypatch, failure):
        from safeyolo.vm import VMError

        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("platform.machine", lambda: "arm64")

        def fail_probe():
            raise VMError(failure)

        monkeypatch.setattr("safeyolo.vm.probe_vm_helper", fail_probe)

        result = _check_sandbox_runtime()

        assert result.status == "fail"
        assert failure in result.message
        assert result.remediation

    def test_isolation_platform_does_not_claim_vz_when_probe_fails(self, monkeypatch):
        from safeyolo.vm import VMError

        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("platform.machine", lambda: "arm64")

        def fail_probe():
            raise VMError("Virtualization is not supported on this machine")

        monkeypatch.setattr("safeyolo.vm.probe_vm_helper", fail_probe)

        result = _check_isolation_platform()

        assert result.status == "fail"
        assert "capability check failed" in result.message
        assert "hardware isolation" not in result.message


class TestCheckGuestImages:
    def test_macos_guest_images_show_share_dir(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        share = tmp_config_dir / "share"
        share.mkdir()
        (share / "Image").write_bytes(b"kernel")
        (share / "initramfs.cpio.gz").write_bytes(b"initrd")
        (share / "rootfs-base.ext4").write_bytes(b"rootfs")

        result = _check_guest_images()

        assert result.status == "pass"
        assert str(share) in result.message
        assert "rootfs-base.ext4" in result.message

    def test_linux_guest_images_show_rootfs_tree(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        tree = tmp_config_dir / "share" / "rootfs-tree"
        (tree / "etc").mkdir(parents=True)

        result = _check_guest_images()

        assert result.status == "pass"
        assert str(tree) in result.message


class TestCheckBaseline:
    @pytest.fixture(autouse=True)
    def _remove_default_toml(self, tmp_config_dir):
        """Remove conftest's policy.toml so tests can use policy.yaml."""
        toml = tmp_config_dir / "policy.toml"
        if toml.exists():
            toml.unlink()

    def test_valid_baseline(self, tmp_config_dir):
        baseline = tmp_config_dir / "policy.yaml"
        baseline.write_text(
            yaml.dump(
                {
                    "metadata": {"version": "1.0"},
                    "permissions": [
                        {"action": "network:request", "resource": "*", "effect": "allow"},
                    ],
                }
            )
        )
        result = _check_baseline()
        assert result.status == "pass"
        assert "1 permissions" in result.message
        assert str(baseline) in result.message

    def test_missing_baseline(self, tmp_config_dir):
        result = _check_baseline()
        assert result.status == "fail"
        assert "not found" in result.message

    def test_invalid_yaml(self, tmp_config_dir):
        baseline = tmp_config_dir / "policy.yaml"
        baseline.write_text("invalid: yaml: [broken")
        result = _check_baseline()
        assert result.status == "fail"

    def test_missing_permissions(self, tmp_config_dir):
        baseline = tmp_config_dir / "policy.yaml"
        baseline.write_text(yaml.dump({"metadata": {"version": "1.0"}}))
        result = _check_baseline()
        assert result.status == "warn"


class TestCheckLogHealth:
    def test_healthy_logs(self, tmp_config_dir, monkeypatch):
        from collections import namedtuple

        from safeyolo.config import get_logs_dir

        logs_dir = get_logs_dir()
        jsonl = logs_dir / "safeyolo.jsonl"
        jsonl.write_text('{"event": "test"}\n' * 10)
        DiskUsage = namedtuple("usage", ["total", "used", "free"])
        monkeypatch.setattr("shutil.disk_usage", lambda path: DiskUsage(100e9, 50e9, 50e9))
        result = _check_log_health()
        assert result.status == "pass"
        assert str(logs_dir) in result.message

    def test_no_logs_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "nonexistent"))
        result = _check_log_health()
        assert result.status == "pass"


class TestCheckCaCert:
    def test_no_cert(self, tmp_config_dir):
        result = _check_ca_cert()
        assert result.status == "warn"

    def test_invalid_cert(self, tmp_config_dir):
        cert_path = tmp_config_dir / "certs" / "mitmproxy-ca-cert.pem"
        cert_path.write_text("not a valid cert")
        result = _check_ca_cert()
        assert result.status == "fail"


class TestCheckUpstreamCaCert:
    def test_default_trust_is_healthy(self, tmp_config_dir, monkeypatch):
        monkeypatch.delenv("SAFEYOLO_CA_CERT", raising=False)

        result = _check_upstream_ca_cert()

        assert result.status == "pass"
        assert "system and certifi" in result.message

    def test_missing_persistent_bundle_fails(self, tmp_config_dir, tmp_path):
        config_path = tmp_config_dir / "config.yaml"
        config = yaml.safe_load(config_path.read_text())
        config["proxy"]["upstream_ca_cert"] = str(tmp_path / "missing.pem")
        config_path.write_text(yaml.safe_dump(config, sort_keys=False))

        result = _check_upstream_ca_cert()

        assert result.status == "fail"
        assert "CA cert not found" in result.message

    def test_environment_override_warns_that_it_is_transient(
        self, tmp_config_dir, tmp_path, monkeypatch
    ):
        bundle = tmp_path / "environment-ca.pem"
        bundle.write_text("test fixture")
        context = create_autospec(ssl.SSLContext, instance=True, spec_set=True)
        context_factory = create_autospec(ssl.SSLContext, spec_set=True)
        context_factory.return_value = context
        monkeypatch.setattr(
            "safeyolo.commands.doctor.resolve_upstream_ca_cert",
            lambda _test, _proxy: (bundle, "SAFEYOLO_CA_CERT"),
        )
        monkeypatch.setattr(
            "safeyolo.commands.doctor.ssl.SSLContext",
            context_factory,
        )

        result = _check_upstream_ca_cert()

        assert result.status == "warn"
        assert "not restart-persistent" in result.message
        assert "proxy upstream-ca set" in result.remediation


class TestCheckTokens:
    def test_both_tokens_present(self, tmp_config_dir):
        data_dir = tmp_config_dir / "data"
        admin_token = data_dir / "admin_token"
        agent_token = data_dir / "agent_token"
        admin_token.write_text("test-admin-token")
        admin_token.chmod(0o600)
        agent_token.write_text("test-agent-token")
        agent_token.chmod(0o600)
        result = _check_tokens()
        assert result.status == "pass"
        assert "present" in result.message
        assert str(data_dir) in result.message

    def test_admin_token_missing(self, tmp_config_dir):
        result = _check_tokens()
        assert result.status == "warn"
        assert "admin_token missing" in result.message

    def test_admin_token_loose_perms(self, tmp_config_dir):
        data_dir = tmp_config_dir / "data"
        admin_token = data_dir / "admin_token"
        admin_token.write_text("test-admin-token")
        admin_token.chmod(0o644)
        result = _check_tokens()
        assert result.status == "warn"
        assert "permissions" in result.message

    def test_agent_token_missing_is_ok(self, tmp_config_dir):
        data_dir = tmp_config_dir / "data"
        admin_token = data_dir / "admin_token"
        admin_token.write_text("test-admin-token")
        admin_token.chmod(0o600)
        result = _check_tokens()
        assert result.status == "pass"
        assert "pending" in result.message


class TestCheckFlowStore:
    def test_no_database(self, tmp_config_dir):
        result = _check_flow_store()
        assert result.status == "pass"
        assert "not yet created" in result.message.lower()

    def test_healthy_database(self, tmp_config_dir):
        import sqlite3

        from safeyolo.config import get_logs_dir

        logs_dir = get_logs_dir()
        db_path = logs_dir / "flows.sqlite3"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE flows (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO flows VALUES (1)")
        conn.execute("INSERT INTO flows VALUES (2)")
        conn.commit()
        conn.close()
        result = _check_flow_store()
        assert result.status == "pass"
        assert "2 flows" in result.message
        assert str(db_path) in result.message

    def test_large_database_warns(self, tmp_config_dir, monkeypatch):
        import sqlite3

        from safeyolo.config import get_logs_dir

        logs_dir = get_logs_dir()
        db_path = logs_dir / "flows.sqlite3"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE flows (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()
        # Lower the warn threshold so the test doesn't need a 500MB file
        monkeypatch.setattr("safeyolo.commands.doctor._FLOW_STORE_WARN_MB", 0)
        result = _check_flow_store()
        assert result.status == "warn"

    def test_corrupted_database(self, tmp_config_dir):
        from safeyolo.config import get_logs_dir

        logs_dir = get_logs_dir()
        db_path = logs_dir / "flows.sqlite3"
        db_path.write_bytes(b"not a sqlite database")
        result = _check_flow_store()
        assert result.status == "warn"
        assert "Cannot read" in result.message


class _FakeSocket:
    """Minimal stand-in for `socket.socket(AF_UNIX, ...)` used by the
    pipeline probe. Captures the request and replays a canned response."""

    def __init__(self, response: bytes, raise_on_connect: type[OSError] | None = None):
        self._response = response
        self._raise = raise_on_connect
        self._sent = b""
        self._read_pos = 0
        self.connected_to: str | None = None

    def settimeout(self, _timeout):
        pass

    def connect(self, addr):
        if self._raise is not None:
            raise self._raise("simulated")
        self.connected_to = addr

    def sendall(self, data):
        self._sent += data

    def recv(self, n):
        chunk = self._response[self._read_pos : self._read_pos + n]
        self._read_pos += len(chunk)
        return chunk

    def close(self):
        pass


def _install_fake_socket(monkeypatch, fake: _FakeSocket) -> None:
    """Patch `socket.socket` in the doctor module to return `fake`."""
    monkeypatch.setattr(
        "safeyolo.commands.doctor.socket.socket",
        lambda *a, **kw: fake,
    )


def _make_agent_socket(tmp_config_dir, name: str = "127.0.0.2_demo.sock"):
    """Create a fake `<ip>_<agent>/proxy.sock` for the probe."""
    socks_dir = tmp_config_dir / "data" / "sockets"
    socks_dir.mkdir(parents=True, exist_ok=True)
    identity = name.removesuffix(".sock")
    sock = socks_dir / identity / "proxy.sock"
    sock.parent.mkdir()
    sock.touch()
    ip, agent = identity.split("_", 1)
    (tmp_config_dir / "data" / "agent_map.json").write_text(
        json.dumps({agent: {"ip": ip}})
    )
    return sock


def _write_agent_token(tmp_config_dir, value: str = "tok-abc"):
    (tmp_config_dir / "data" / "agent_token").write_text(value)


class TestCheckPipelineProbe:
    """Tests for _check_pipeline_probe()."""

    def test_no_sockets_dir_skips(self, tmp_config_dir):
        # tmp_config_dir creates data/ but not data/sockets/
        result = _check_pipeline_probe()
        assert result.status == "skip"
        assert "sockets" in result.message.lower()

    def test_no_sockets_present_skips(self, tmp_config_dir):
        (tmp_config_dir / "data" / "sockets").mkdir()
        result = _check_pipeline_probe()
        assert result.status == "skip"
        assert "no agents" in result.message.lower()

    def test_orphaned_socket_without_registered_agent_skips(self, tmp_config_dir):
        socks_dir = tmp_config_dir / "data" / "sockets"
        socks_dir.mkdir()
        (socks_dir / "10.200.0.1_old-agent.sock").touch()
        (tmp_config_dir / "data" / "agent_map.json").write_text("{}")

        result = _check_pipeline_probe()

        assert result.status == "skip"
        assert "no agents" in result.message.lower()

    def test_missing_token_warns(self, tmp_config_dir):
        _make_agent_socket(tmp_config_dir)
        result = _check_pipeline_probe()
        assert result.status == "warn"
        assert "token" in result.message.lower()

    def test_empty_token_warns(self, tmp_config_dir):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir, "   ")
        result = _check_pipeline_probe()
        assert result.status == "warn"
        assert "empty" in result.message.lower()

    def test_connect_failure_fails(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        _install_fake_socket(
            monkeypatch, _FakeSocket(b"", raise_on_connect=ConnectionRefusedError)
        )
        result = _check_pipeline_probe()
        assert result.status == "fail"
        assert "ConnectionRefusedError" in result.message

    def test_empty_response_fails(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        _install_fake_socket(monkeypatch, _FakeSocket(b""))
        result = _check_pipeline_probe()
        assert result.status == "fail"
        assert "no response" in result.message.lower()

    def test_503_log(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        body = b'{"reason_code":"agent_api_unavailable"}'
        response = (
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"X-SafeYolo-Agent-API: true\r\n"
            b"Content-Type: application/json\r\n\r\n" + body
        )
        _install_fake_socket(monkeypatch, _FakeSocket(response))
        result = _check_pipeline_probe()
        assert result.status == "fail"
        assert "503" in result.message
        assert "safeyolo logs" in result.remediation
        assert "--security" not in result.remediation

    def test_401_uses_security_log(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        response = (
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"X-SafeYolo-Agent-API: true\r\n\r\n"
        )
        _install_fake_socket(monkeypatch, _FakeSocket(response))

        result = _check_pipeline_probe()

        assert result.status == "fail"
        assert result.remediation == "safeyolo logs --tail 20"

    def test_pdp_unavailable_warns(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        body = b'{"agent_api":"ok","pdp":"unavailable"}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"X-SafeYolo-Agent-API: true\r\n"
            b"Content-Type: application/json\r\n\r\n" + body
        )
        _install_fake_socket(monkeypatch, _FakeSocket(response))
        result = _check_pipeline_probe()
        assert result.status == "warn"
        assert "pdp" in result.message.lower()

    def test_pdp_healthy_passes(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir, name="127.0.0.2_demo.sock")
        _write_agent_token(tmp_config_dir, "tok-abc")
        body = b'{"agent_api":"ok","pdp":"ok"}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"x-sAfEyOlO-aGeNt-ApI: TrUe\r\n"
            b"Content-Type: application/json\r\n\r\n" + body
        )
        fake = _FakeSocket(response)
        _install_fake_socket(monkeypatch, fake)
        result = _check_pipeline_probe()
        assert result.status == "pass"
        assert "proxy.sock" in result.message
        # The probe sent the request through the fake socket
        assert b"GET /health HTTP/1.0" in fake._sent
        assert b"Host: _safeyolo.proxy.internal" in fake._sent
        assert b"Authorization: Bearer tok-abc" in fake._sent

    def test_non_json_body_warns(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"X-SafeYolo-Agent-API: true\r\n\r\nnot-json"
        )
        _install_fake_socket(monkeypatch, _FakeSocket(response))
        result = _check_pipeline_probe()
        assert result.status == "warn"
        assert "not json" in result.message.lower()

    def test_unmarked_200_fails(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        _install_fake_socket(monkeypatch, _FakeSocket(response))

        result = _check_pipeline_probe()

        assert result.status == "fail"
        assert "handler marker" in result.message
        assert "safeyolo logs" in result.remediation

    def test_1200_status_fails(self, tmp_config_dir, monkeypatch):
        _make_agent_socket(tmp_config_dir)
        _write_agent_token(tmp_config_dir)
        response = b"HTTP/1.1 1200 Not-A-Status\r\n\r\n"
        _install_fake_socket(monkeypatch, _FakeSocket(response))

        result = _check_pipeline_probe()

        assert result.status == "fail"
        assert "malformed" in result.message.lower()


class TestCheckAdminApi:
    """Tests for _check_admin_api()."""

    def test_check_admin_api_healthy(self, tmp_config_dir, monkeypatch):
        """Returns pass when admin API responds with 200 and port is open."""
        from safeyolo import rust_proxy

        monkeypatch.setattr(rust_proxy, "read_process", lambda: SimpleNamespace(admin_port=9090))

        def mock_create_connection(address, timeout=None):
            return _OpenSocket()

        monkeypatch.setattr("socket.create_connection", mock_create_connection)
        monkeypatch.setattr("safeyolo.config.get_admin_token", lambda: "test-token")

        get = create_autospec(httpx.get, spec_set=True)
        get.return_value = httpx.Response(200)
        monkeypatch.setattr(httpx, "get", get)

        result = _check_admin_api()
        assert result.status == "pass"
        assert "200 OK" in result.message
        assert "http://127.0.0.1:9090/health" in result.message


class TestRunChecks:
    def test_proxy_down_skips_dependents(self, tmp_config_dir, monkeypatch):
        """When the proxy is down, dependent Admin API and pipeline checks are skipped."""
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)
        results = _run_checks()
        names = {r.name: r.status for r in results}
        assert names["Proxy running"] == "fail"
        assert names["Admin API"] == "skip"
        assert names["Pipeline probe"] == "skip"

    def test_linux_run_checks_omits_vsock_term(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)

        results = _run_checks()

        assert "Interactive terminal" not in {r.name for r in results}

    def test_macos_run_checks_omits_user_namespaces(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("platform.machine", lambda: "arm64")
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)
        bin_dir = tmp_config_dir / "bin"
        bin_dir.mkdir()
        for name in ("safeyolo-vm", "vsock-term"):
            path = bin_dir / name
            path.write_text("#!/bin/sh\n")
            path.chmod(0o755)

        results = _run_checks()
        names = {r.name for r in results}

        assert "User namespaces" not in names
        assert "Interactive terminal" in names

    def test_macos_helper_failure_skips_isolation_claim(self, tmp_config_dir, monkeypatch):
        from safeyolo.vm import VMError

        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("platform.machine", lambda: "arm64")
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)

        def fail_probe():
            raise VMError("Virtualization is not supported on this machine")

        monkeypatch.setattr("safeyolo.vm.probe_vm_helper", fail_probe)

        results = {result.name: result for result in _run_checks()}

        assert results["Sandbox runtime"].status == "fail"
        assert results["Isolation platform"].status == "skip"
        assert "hardware isolation" not in results["Isolation platform"].message

    def test_macos_runtime_and_isolation_reuse_one_probe(
        self, tmp_config_dir, monkeypatch
    ):
        from safeyolo.vm import VMError

        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("platform.machine", lambda: "arm64")
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)
        calls = 0

        def changing_probe():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise VMError("capability changed between rows")
            return tmp_config_dir / "bin" / "safeyolo-vm"

        monkeypatch.setattr("safeyolo.vm.probe_vm_helper", changing_probe)

        results = {result.name: result for result in _run_checks()}

        assert calls == 1
        assert results["Sandbox runtime"].status == "pass"
        assert results["Isolation platform"].status == "pass"


class TestBuildBundle:
    def test_bundle_structure(self):
        results = [
            DiagResult(name="test1", status="pass", message="ok"),
            DiagResult(name="test2", status="fail", message="bad", detail="traceback here"),
        ]
        bundle = _build_bundle(results)
        assert "timestamp" in bundle
        assert len(bundle["checks"]) == 2
        assert bundle["summary"]["pass"] == 1
        assert bundle["summary"]["fail"] == 1
        assert "platform" in bundle["system"]


class TestDoctorCLI:
    def test_doctor_runs(self, cli_runner, tmp_config_dir, monkeypatch):
        """Smoke test that doctor command runs without crashing."""
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)
        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "", ""),
        )

        from safeyolo.cli import app

        result = cli_runner.invoke(app, ["doctor"])
        assert "SafeYolo Doctor" in result.output
        assert "PASS" in result.output or "FAIL" in result.output

    def test_doctor_json(self, cli_runner, tmp_config_dir, monkeypatch):
        """--json emits the diagnostic bundle as a single JSON object on stdout.

        Previous semantics wrote a timestamped file under ~/.safeyolo/data/;
        now it streams to stdout so `safeyolo doctor --json | jq ...` works.
        Exit code preserved (1 on any fail).
        """
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)
        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "", ""),
        )

        from safeyolo.cli import app

        result = cli_runner.invoke(app, ["doctor", "--json"])

        # Stdout must be pure JSON (no rich prefix like "SafeYolo Doctor")
        assert "SafeYolo Doctor" not in result.output
        bundle = json.loads(result.output)
        assert "checks" in bundle
        assert "summary" in bundle
        assert isinstance(bundle["checks"], list)
        assert set(bundle["summary"].keys()) == {"pass", "fail", "warn", "skip"}

        # Exit code = 1 whenever any check failed (this fixture forces failures).
        if bundle["summary"]["fail"] > 0:
            assert result.exit_code == 1

    def test_doctor_raw(self, cli_runner, tmp_config_dir, monkeypatch):
        """--raw emits human output with no color / no wrap; long tokens survive."""
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)
        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "", ""),
        )

        from safeyolo.cli import app

        result = cli_runner.invoke(app, ["doctor", "--raw"])
        assert "SafeYolo Doctor" in result.output
        # No ANSI escape sequences in --raw output.
        assert "\x1b[" not in result.output

    def test_doctor_json_fix_incompatible(self, cli_runner, tmp_config_dir, monkeypatch):
        """--json + --fix is refused (fix output would corrupt the JSON stream)."""
        monkeypatch.setattr("safeyolo.rust_proxy.read_process", lambda: None)

        from safeyolo.cli import app

        result = cli_runner.invoke(app, ["doctor", "--json", "--fix"])
        assert result.exit_code != 0
        # Assert on a distinctive phrase that survives rich's ANSI colouring
        # (typer's BadParameter renderer wraps individual flag names in
        # `\x1b[...m` sequences, so `"--fix" in result.output` breaks on CI).
        assert "cannot be combined" in result.output


class TestCheckEgressStructural:
    """Both platforms use structural isolation — mitmproxy itself owns
    the per-agent UDS listeners. The sandbox has no external interface
    and no kernel firewall in the critical path; 'mitmproxy running' is
    the readiness signal."""

    @pytest.fixture(params=["Darwin", "Linux"], autouse=True)
    def _platform(self, request, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: request.param)

    def test_pass_when_proxy_running(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.proxy.is_proxy_running", lambda: True,
        )
        result = _check_firewall()
        assert result.status == "pass"

    def test_warn_when_proxy_not_running(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.proxy.is_proxy_running", lambda: False,
        )
        result = _check_firewall()
        assert result.status == "warn"
        assert "Rust proxy not running" in result.message
        assert result.remediation == "safeyolo start"


class TestCheckFirewallUnsupportedPlatform:
    def test_skip_on_unknown_platform(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "OpenBSD")
        result = _check_firewall()
        assert result.status == "skip"
