"""Exercise retained blackbox consumers against an owned installed native proxy.

Only the sandbox status/shell leg of the restart control is simulated here.
Real full-platform runs still prove that leg with the same running guest.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.blackbox import installed_host_smoke as smoke
from tests.blackbox import installed_lifecycle as lifecycle
from tests.proxy_contracts.harness import connection, request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN, native_instance

BLACKBOX = Path(__file__).resolve().parents[1] / "blackbox"
ADMIN_TOKEN = "synthetic-blackbox-admin-token"


@pytest.mark.parametrize("change", ["watcher", "admin"])
def test_native_lifecycle_observes_changed_policy_while_admitted_sse_stays_live(tmp_path, change):
    with origin_server(stream_seconds=0.04) as origin:
        host = f"127.0.0.1:{origin.server_address[1]}"
        allowed_source = f'[hosts]\n"*"={{egress="deny"}}\n"{host}"={{egress="allow"}}\n'
        denied_source = allowed_source.replace('egress="allow"', 'egress="deny"')
        with native_instance(tmp_path, source=allowed_source) as instance:
            audit = instance.root / "logs/audit.jsonl"
            before = lifecycle.wait_policy_load(audit, 0)
            legacy_before = sum(row["event"] == "ops.policy_reload" for row in lifecycle.event_rows(audit))
            stream = connection(instance.paths["alice"])
            try:
                stream.request("GET", f"http://{host}/stream-control")
                response = stream.getresponse()
                assert response.status == 200
                first = b"data: first-event\n\n"
                assert response.read(len(first)) == first
                assert origin.stream_initial_sent.is_set()
                assert not origin.stream_release.is_set() and not origin.stream_finished.is_set()

                if change == "watcher":
                    instance.policy.write_text(denied_source)
                else:
                    instance.admin("POST", "/admin/policy/host/deny", {"host": host})
                denied_load = lifecycle.wait_policy_load(audit, before)
                origin_before = len(origin.requests)
                status, headers, body = request(instance.paths["alice"], f"http://{host}/echo")
                assert status == 403, body
                assert headers["x-blocked-by"] == "network-guard"
                assert len(origin.requests) == origin_before
                assert not origin.stream_release.is_set() and not origin.stream_finished.is_set()

                origin.stream_release.set()
                assert response.read() == b"data: " + b"x" * (16384 - 8) + b"\n\n"
                assert origin.stream_finished.wait(5)
                assert not origin.stream_cancelled.is_set()
                instance.admin("POST", "/admin/policy/host/allow", {"host": host, "rate": 600})
                assert lifecycle.wait_policy_load(audit, denied_load) > denied_load
                status, _, body = request(instance.paths["alice"], f"http://{host}/echo")
                assert (status, body) == (200, b"hello")
                assert len(origin.requests) == origin_before + 1
                assert sum(row["event"] == "ops.policy_reload" for row in lifecycle.event_rows(audit)) == legacy_before
            finally:
                origin.stream_release.set()
                stream.close()
        assert instance.process.poll() is not None


def test_native_lifecycle_load_observation_distinguishes_old_rejected_and_unapplied_policy(tmp_path):
    with origin_server() as origin:
        host = f"127.0.0.1:{origin.server_address[1]}"
        source = f'[hosts]\n"*"={{egress="deny"}}\n"{host}"={{egress="allow"}}\n'
        denied_source = source.replace('egress="allow"', 'egress="deny"')
        with native_instance(tmp_path, source=source) as instance:
            audit = instance.root / "logs/audit.jsonl"
            initial_load = lifecycle.wait_policy_load(audit, 0)
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, initial_load, timeout=0.05)

            instance.apply('[hosts\n', valid=False)
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, initial_load, timeout=0.05)

            unapplied_source = denied_source + "\n[credential.activation_failure]\nmatch = ['\\uD800']\n"
            failed = instance.apply(unapplied_source, valid=False)
            assert "activation failed" in failed.stderr
            assert instance.policy.read_text() == source
            assert instance.show()["saved_matches_active"]
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, initial_load, timeout=0.05)

            # The real watcher emits before Runtime preparation. The compiler
            # accepts this string, but detector activation rejects its regex.
            instance.policy.write_text(unapplied_source)
            unapplied_load = lifecycle.wait_policy_load(audit, initial_load)
            status, _, body = request(instance.paths["alice"], f"http://{host}/echo")
            assert (status, body) == (200, b"hello")
            assert len(origin.requests) == 1
            assert instance.show()["status"] == "saved_differs"
            with pytest.raises(AssertionError, match="did not load the changed policy"):
                lifecycle.wait_policy_load(audit, unapplied_load, timeout=0.05)

            instance.apply(denied_source)
            assert instance.show()["saved_matches_active"]
            status, _, body = request(instance.paths["alice"], f"http://{host}/echo")
            assert status == 403, body
            assert len(origin.requests) == 1
        assert instance.process.poll() is not None


@pytest.mark.parametrize("control", ["clean", "stale_receipt", "admin_operand", "agent_operand", "missing_agent_token"])
def test_native_process_secrecy_consumer_observes_tokens_and_owned_process(tmp_path, monkeypatch, control):
    monkeypatch.syspath_prepend(str(BLACKBOX))
    from installed_host_smoke import SmokeError

    from tests.blackbox.host.security.test_firewall_structural import TestProcessSecrecy

    directory = tmp_path / {"admin_operand": ADMIN_TOKEN, "agent_operand": AGENT_TOKEN}.get(control, "owned")
    directory.mkdir()
    admin_token = directory / "admin-auth"
    admin_token.write_text(ADMIN_TOKEN)
    with native_instance(directory, agent_api=True, extra_config=(
        f'admin_api_token_file={json.dumps(str(admin_token))}\n'
        'tls_ca_file="certs/mitmproxy-ca.pem"\n'
    )) as instance:
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(instance.root))
        receipt = instance.root / "data/proxy-process.json"
        if control == "stale_receipt":
            original = receipt.read_bytes()
            record = json.loads(original)
            record["token"] = "wrong-process-birth"
            receipt.write_text(json.dumps(record))
            try:
                with pytest.raises(SmokeError, match="does not own"):
                    TestProcessSecrecy().test_no_tokens_in_process_cmdline()
            finally:
                receipt.write_bytes(original)
        elif control == "missing_agent_token":
            (instance.root / "data/agent_token").unlink()
            with pytest.raises(FileNotFoundError):
                TestProcessSecrecy().test_no_tokens_in_process_cmdline()
        elif control.endswith("operand"):
            with pytest.raises(AssertionError, match="token appears"):
                TestProcessSecrecy().test_no_tokens_in_process_cmdline()
        else:
            TestProcessSecrecy().test_no_tokens_in_process_cmdline()
        ca = Path(smoke._native_config(instance.root / "config.toml", directory)["raw"]["tls_ca_file"])
        assert ca.is_file() and ca.parent == instance.root / "certs"


@pytest.mark.parametrize("changed", [None, "run_id", "agent_id", "socket_directory"])
def test_native_restart_consumer_uses_real_start_and_checks_sandbox_continuity(tmp_path_factory, monkeypatch, changed):
    monkeypatch.syspath_prepend(str(BLACKBOX))
    from tests.blackbox.host.lifecycle.test_token_lifecycle import TestLiveAgentLifecycle

    directory = tmp_path_factory.mktemp("restart")
    with native_instance(directory, agent_api=True, agent_map={"alice": "10.0.0.2"}) as instance:
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(instance.root))
        monkeypatch.setenv("SAFEYOLO_TEST_AGENT", "alice")
        listener = smoke._agent_map(instance.root)[0]
        socket_path = Path(listener["path"])
        sandbox = {"name": "alice", "agent_id": "ag-owned", "run_id": "0123456789abcdef0123456789abcdef",
                   "runtime_state": "running"}
        operations = []

        def command(*arguments, **kwargs):
            operations.append(arguments)
            if arguments == ("agent", "status", "alice"):
                value = dict(sandbox)
                if ("start",) in operations and changed in {"run_id", "agent_id"}:
                    value[changed] = "different-incarnation"
                return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr="")
            result = instance.cli(*arguments, **kwargs)
            if arguments == ("start",) and changed == "socket_directory":
                # Preserve the old directory so inode reuse cannot mask replacement.
                old = socket_path.parent.with_name("old-directory")
                socket_path.parent.rename(old)
                socket_path.parent.mkdir()
                (old / "proxy.sock").rename(socket_path)
            return result

        consumer = TestLiveAgentLifecycle()
        monkeypatch.setattr(consumer, "_safeyolo", command)
        monkeypatch.setattr(consumer, "_agent_api_health", lambda _name: smoke._probe_agent_health(
            listener, instance.root,
        )["status"])
        # Exercise the real native stop/start and API sockets. Only the guest
        # inventory/shell observations use the controlled retained status shape.
        try:
            if changed:
                with pytest.raises(AssertionError, match="sandbox identity|socket directory"):
                    consumer.test_agent_api_survives_proxy_restart()
            else:
                consumer.test_agent_api_survives_proxy_restart()
            assert operations == [("agent", "status", "alice"), ("stop",), ("start",),
                                  ("agent", "status", "alice")]
            assert instance.process.wait(timeout=10) == 0
        finally:
            stopped = instance.cli("stop")
            assert stopped.returncode == 0, stopped.stderr


def test_native_lifecycle_consumer_retains_inactive_receipt_and_uses_configured_readiness(tmp_path, monkeypatch):
    with native_instance(tmp_path, agent_api=True) as instance:
        stopped = instance.cli("stop")
        assert stopped.returncode == 0, stopped.stderr
        assert instance.process.wait(timeout=10) == 0
        config = instance.root / "config.toml"
        document = tomlkit.parse(config.read_text())
        document["readiness_file"] = "data/selected-ready.json"
        config.write_text(tomlkit.dumps(document))
        started = instance.cli("start")
        assert started.returncode == 0, started.stderr
        native = smoke._native_config(instance.root / "config.toml", tmp_path)
        listener = Path(instance.paths["alice"])
        try:
            runtime = smoke._runtime_observation(
                instance.root, native, instance.root / "bin/safeyolo-proxy",
                config_path=config, working_directory=tmp_path,
                require_running=True, require_authenticated_identity=True,
            )
            # Only the guest/origin legs are controlled here. The owner's
            # configured marker, kernel process birth and live API are real.
            owner = {"runtime": runtime, "config_sha256": smoke._sha256(config),
                     "policy_sha256": smoke._sha256(instance.policy)}
            monkeypatch.setattr(lifecycle, "guest", lambda _cli, _agent, phase, _marker, **_kwargs: {
                "status": 200 if phase == "echo" else 403,
            })
            marker = "p4-owned"
            sinkhole = SimpleNamespace(get_requests=lambda **kwargs: (
                [SimpleNamespace(path=f"/p4/echo/{marker}")] if kwargs["host"] == lifecycle.FIXTURE else []
            ))
            assert lifecycle.owner_controls(str(instance.root / "bin/safeyolo"), instance.root, listener,
                                            owner, instance.environment, marker, sinkhole)["pid"] == runtime["pid"]
            with monkeypatch.context() as clock:
                clock.setattr(lifecycle.time, "monotonic", iter((0, 13)).__next__)
                with pytest.raises(AssertionError, match="did not withdraw readiness"):
                    lifecycle.assert_proxy_stopped(instance.root, listener, runtime)
        finally:
            stopped = instance.cli("stop")
            assert stopped.returncode == 0, stopped.stderr
        # Native stop preserves its inactive identity record, and withdraws
        # the actual configured readiness and accepting listener.
        assert (instance.root / "data/proxy-process.json").is_file()
        lifecycle.assert_proxy_stopped(instance.root, listener, runtime)
        assert not Path(native["readiness_file"]).exists()


@pytest.mark.parametrize("missing_ca", [False, True])
def test_native_host_smoke_preserves_configured_ca_failure_and_owned_cleanup(tmp_path, monkeypatch, missing_ca):
    with native_instance(tmp_path, source=None, agent_api=True,
                         extra_config='tls_ca_file="certs/mitmproxy-ca.pem"\n') as instance:
        stopped = instance.cli("stop")
        assert stopped.returncode == 0, stopped.stderr
        assert instance.process.wait(timeout=10) == 0
        root = instance.root
        (root / ".safeyolo-platform-smoke").touch()
        monkeypatch.setenv("SAFEYOLO_NATIVE_CONFIG_PATH", str(root / "config.toml"))
        ca = root / "certs/mitmproxy-ca.pem"
        original = smoke._sha256(ca)
        held_ca = ca.with_suffix(".held")
        if missing_ca:
            ca.rename(held_ca)
        try:
            report, exit_code = smoke._native_smoke(SimpleNamespace(
                config_dir=str(root), rust_config=str(root / "config.toml"),
                rust_bin=str(root / "bin/safeyolo-proxy"), cli=str(root / "bin/safeyolo"),
                working_directory=str(tmp_path), http_port=0, agent="alice",
                install_commit=smoke._cli_identity(root / "bin/safeyolo")["source_revision"],
            ))
            assert report["cleanup"] == {"status": "stopped", "errors": []}
            if missing_ca:
                assert exit_code == 2 and report["status"] == "infrastructure_failure"
                assert "proxy exited during startup" in report["error"]
                assert "No such file" in (root / "logs/proxy.log").read_text()
            else:
                assert exit_code == 0 and report["status"] == "host_package_passed", report
                assert report["origin"]["allowed_status"] == 200 and report["origin"]["denied_status"] == 403
                assert smoke._sha256(ca) == original
        finally:
            if missing_ca:
                held_ca.rename(ca)
