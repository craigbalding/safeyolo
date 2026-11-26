"""Focused controls for the installed Linux UDS and VZ vsock guest routes."""

import json
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.blackbox import installed_ingress as host_ingress
from tests.blackbox import installed_workloads as host_workloads
from tests.blackbox.isolation import installed_ingress
from tests.blackbox.isolation.installed_ingress import forwarder_identity

BLACKBOX = Path(__file__).parent / "blackbox"
LISTENER = "TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork,su=agent"
UPSTREAM = "UNIX-CONNECT:/safeyolo/proxy/proxy.sock,retry=20,interval=0.25"
RELAY = ["/run/sy-proxy-relay", "-t", "600"]
VZ_LISTENER = LISTENER + ",max-children=232,backlog=128"


def _process(proc_root: Path, pid: int, argv: list[str]) -> None:
    directory = proc_root / str(pid)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cmdline").write_bytes(b"\0".join(part.encode() for part in argv) + b"\0")


@pytest.mark.parametrize("platform", ["systrap", "vz"])
def test_current_guest_launcher_is_recognized(tmp_path, monkeypatch, platform):
    """Capture the real launch command without starting a network relay."""
    socat = tmp_path / "socat"
    socat.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv))\n")
    socat.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path), prepend=":")
    monkeypatch.setenv("HTTP_PROXY", installed_ingress.GUEST_PROXY)
    source = BLACKBOX.parents[1] / "cli/src/safeyolo/guest-proxy-forwarder.sh"
    script = tmp_path / "forwarder.sh"
    script.write_text(source.read_text().replace("/run/sy-proxy-relay", str(tmp_path / "sy-proxy-relay")))
    # Keep the real UDS within macOS's sockaddr_un path limit.
    with tempfile.TemporaryDirectory(prefix="sy-relay-", dir="/tmp") as directory:
        path = Path(directory) / "proxy.sock"
        monkeypatch.setattr(installed_ingress, "GUEST_SOCKET", path)
        with socket.socket(socket.AF_UNIX) as listener:
            if platform == "systrap":
                listener.bind(str(path))
            argv = json.loads(subprocess.check_output(["sh", str(script), "8080", str(path)], text=True))
            _process(tmp_path / "proc", 42, argv)
            assert installed_ingress.bridge(platform, tmp_path / "proc") == {"pid": 42, "argv": argv}


def test_unrelated_localhost_proxy_cannot_satisfy_guest_route(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(BLACKBOX))
    from tests.blackbox.installed_ingress import check_guest_route

    proc_root = tmp_path / "proc"
    _process(proc_root, 42, ["python3", "-m", "http.server", "8080"])
    with pytest.raises(AssertionError, match="no running SafeYolo UDS forwarder"):
        forwarder_identity(proc_root)
    guest = {
        "guest_socket": "/safeyolo/proxy/proxy.sock",
        "guest_proxy": "http://127.0.0.1:8080",
        "forwarder": {"pid": 42, "argv": ["python3", "-m", "http.server", "8080"]},
    }
    with pytest.raises(AssertionError):
        check_guest_route(guest)

    _process(proc_root, 45, ["socat", "-t", "600", LISTENER, UPSTREAM])
    with pytest.raises(AssertionError, match="no running SafeYolo UDS forwarder"):
        forwarder_identity(proc_root)

    # A running relay bound to localhost must also name this guest's UDS.
    _process(proc_root, 43, [*RELAY, LISTENER, "UNIX-CONNECT:/tmp/unrelated.sock"])
    with pytest.raises(AssertionError, match="no running SafeYolo UDS forwarder"):
        forwarder_identity(proc_root)

    _process(proc_root, 44, [*RELAY, LISTENER, UPSTREAM])
    guest["forwarder"] = forwarder_identity(proc_root)
    check_guest_route(guest)
    guest["forwarder"] = {"pid": 43, "argv": [*RELAY, LISTENER, "UNIX-CONNECT:/tmp/unrelated.sock"]}
    with pytest.raises(AssertionError, match="not wired to the mounted SafeYolo UDS"):
        check_guest_route(guest)


@pytest.mark.parametrize("upstream", [
    "VSOCK-CONNECT:3:1080,retry=20", "VSOCK-CONNECT:2:1081,retry=20", UPSTREAM,
])
def test_vz_route_requires_its_forwarder_and_does_not_require_a_linux_socket(tmp_path, monkeypatch, upstream):
    monkeypatch.setenv("HTTP_PROXY", installed_ingress.GUEST_PROXY)
    monkeypatch.setattr(installed_ingress, "GUEST_SOCKET", tmp_path / "absent-linux.sock")
    _process(tmp_path / "proc", 42, [*RELAY, VZ_LISTENER, "VSOCK-CONNECT:2:1080,retry=20,interval=0.25"])
    assert installed_ingress.bridge("vz", tmp_path / "proc")["pid"] == 42
    (tmp_path / "proc/42/cmdline").unlink()
    _process(tmp_path / "proc", 43, [*RELAY, VZ_LISTENER, upstream])
    with pytest.raises(AssertionError, match="no VZ forwarder"):
        installed_ingress.bridge("vz", tmp_path / "proc")


def test_linux_route_still_requires_its_mounted_agent_socket(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", installed_ingress.GUEST_PROXY)
    # Reuse the short socket fixture layout: macOS pytest roots can exceed
    # sockaddr_un's path limit even though the guest route is Linux-shaped.
    with tempfile.TemporaryDirectory(prefix="sy-sock-", dir="/tmp") as directory:
        path = Path(directory) / "proxy.sock"
        monkeypatch.setattr(installed_ingress, "GUEST_SOCKET", path)
        _process(tmp_path / "proc", 42, [*RELAY, LISTENER, f"UNIX-CONNECT:{path},retry=20,interval=0.25"])
        with pytest.raises(AssertionError):
            installed_ingress.bridge("systrap", tmp_path / "proc")
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            assert installed_ingress.bridge("systrap", tmp_path / "proc")["pid"] == 42


@pytest.mark.parametrize("argv, accepted", [
    ([*RELAY, LISTENER, UPSTREAM], True),
    (["socat", "-t", "600", LISTENER, UPSTREAM], False),
    ([*RELAY, LISTENER.replace("127.0.0.1", "0.0.0.0"), UPSTREAM], False),
    ([*RELAY, LISTENER.replace("8080", "8081"), UPSTREAM], False),
    ([*RELAY, LISTENER, "UNIX-CONNECT:/tmp/unrelated.sock,retry=20"], False),
    ([*RELAY, LISTENER, "VSOCK-CONNECT:2:1080,retry=20"], False),
])
def test_host_ingress_and_workloads_validate_current_relay(argv, accepted):
    guest = {
        "guest_socket": str(installed_ingress.GUEST_SOCKET), "guest_proxy": installed_ingress.GUEST_PROXY,
        "forwarder": {"pid": 42, "argv": argv},
        "phase": "package", "marker": "current-relay", "result": {"observed": True},
    }
    output = "P2_OBSERVATION=" + json.dumps(guest)
    if accepted:
        host_ingress.check_guest_route(guest)
        assert host_workloads.observation(output, "package", "current-relay") == {"observed": True}
    else:
        with pytest.raises(AssertionError, match="not wired to the mounted SafeYolo UDS"):
            host_ingress.check_guest_route(guest)
        with pytest.raises(AssertionError, match="lost its mounted UDS forwarder"):
            host_workloads.observation(output, "package", "current-relay")


@pytest.mark.parametrize("platform", ["systrap", "vz"])
@pytest.mark.parametrize("argv", [
    [],
    [*RELAY],
    ["/run/sy-proxy-relay", "-x", "600", LISTENER],
    ["socat", "-t", "600", LISTENER],
    [*RELAY, LISTENER.replace("127.0.0.1", "0.0.0.0")],
    [*RELAY, LISTENER.replace("8080", "8081")],
])
def test_bridge_refuses_missing_or_wrong_listener(tmp_path, monkeypatch, platform, argv):
    monkeypatch.setenv("HTTP_PROXY", installed_ingress.GUEST_PROXY)
    upstream = UPSTREAM if platform == "systrap" else "VSOCK-CONNECT:2:1080,retry=20,interval=0.25"
    _process(tmp_path / "proc", 42, [*argv, upstream])
    with pytest.raises(AssertionError, match="no running SafeYolo UDS forwarder|no VZ forwarder"):
        installed_ingress.bridge(platform, tmp_path / "proc")


@pytest.mark.parametrize("network", [None, [], {},
    {"enabled": "true", "action": "block"}, {"enabled": 1, "action": "block"},
    {"enabled": True}, {"enabled": True, "action": ["block"]},
])
def test_ingress_refuses_missing_or_malformed_effective_network(network):
    with pytest.raises(AssertionError, match="effective.*network"):
        host_ingress.check_ingress_policy({"effective": {
            "hosts": {"evil.com": {"egress": "deny"}}, "controls": {"network": network},
        }})


@pytest.mark.parametrize("stdout, returncode, message", [
    ("not-json", 0, "malformed JSON"), ("[]", 0, "return an object"),
    ("", 1, "policy show failed"),
])
def test_ingress_policy_show_reports_failure(tmp_path, monkeypatch, stdout, returncode, message):
    def command(argv, **kwargs):
        assert argv == ["selected-cli", "--instance-dir", str(tmp_path), "--json", "policy", "show"]
        assert kwargs["timeout"] == 45
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="fixture error")

    monkeypatch.setattr(host_ingress.subprocess, "run", command)
    with pytest.raises(AssertionError, match=message):
        host_ingress.read_native_policy("selected-cli", tmp_path)


@pytest.mark.parametrize("failure", ["policy", "origin"])
def test_ingress_retains_inputs_and_guest_before_failed_assertion(tmp_path, monkeypatch, failure):
    revision = "a" * 40
    output = tmp_path / "ingress.json"
    runtime_file = tmp_path / "runtime.json"
    listener = {"agent_id": "alice", "path": str(tmp_path / "proxy.sock")}
    runtime_file.write_text(json.dumps({"guest_ingress": {"agents": [listener]}, "runtime": {"listeners": [listener]}}))
    (tmp_path / "platform.json").write_text('{"platform":"kvm"}')
    (tmp_path / "config.toml").write_text(f'parent_proxy="http://127.0.0.1:8888"\nupstream_ca_file="{runtime_file}"\n')
    monkeypatch.setattr(sys, "argv", ["installed_ingress", "--config-dir", str(tmp_path), "--agent", "alice",
                                     "--runtime", str(runtime_file), "--output", str(output), "--install-commit", revision])
    monkeypatch.setenv("SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT", str(tmp_path))
    monkeypatch.setattr(host_ingress.subprocess, "check_output", lambda *args, **kwargs: revision)
    monkeypatch.setattr(host_ingress, "installed_identity", lambda *args, **kwargs: {"cli": {"path": "selected-cli"}})
    monkeypatch.setattr(host_ingress, "runsc_identity", lambda *args, **kwargs: {"platform": "kvm"})
    policy = {"effective": {"hosts": {"evil.com": {"egress": "deny"}},
                            "controls": {"network": {"enabled": failure != "policy", "action": "block"}}}}
    monkeypatch.setattr(host_ingress, "read_native_policy", lambda *args: policy)
    monkeypatch.setattr(host_ingress, "guest_observation", lambda *args: {"observed": True})
    closed = []
    monkeypatch.setattr(host_ingress.SinkholeClient, "wait_for_receiver_ready", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_ingress.SinkholeClient, "close", lambda self: (self._client.close(), closed.append(True)))

    def reject_origin(*args):
        raise AssertionError("fixture origin assertion")

    monkeypatch.setattr(host_ingress, "check_guest_and_origin", reject_origin)
    with pytest.raises(AssertionError, match="disabled" if failure == "policy" else "fixture origin assertion"):
        host_ingress.main()
    report = json.loads(output.read_text())
    assert report["status"] == "ingress_incomplete" and report["policy"] == policy
    assert report["marker"].startswith("p1-") and report["gvisor"]["platform"] == "kvm"
    assert "origin" not in report
    if failure == "origin":
        assert report["guest"] == {"observed": True} and closed == [True]
