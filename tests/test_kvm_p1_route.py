"""Focused controls for the installed Linux UDS and VZ vsock guest routes."""

import socket
from pathlib import Path

import pytest

from tests.blackbox.isolation import installed_ingress
from tests.blackbox.isolation.installed_ingress import forwarder_identity

BLACKBOX = Path(__file__).parent / "blackbox"
LISTENER = "TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork,su=agent"
UPSTREAM = "UNIX-CONNECT:/safeyolo/proxy/proxy.sock,retry=20,interval=0.25"


def _process(proc_root: Path, pid: int, argv: list[str]) -> None:
    directory = proc_root / str(pid)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cmdline").write_bytes(b"\0".join(part.encode() for part in argv) + b"\0")


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

    # A running socat bound to localhost must also name this guest's UDS.
    _process(proc_root, 43, ["socat", LISTENER, "UNIX-CONNECT:/tmp/unrelated.sock"])
    with pytest.raises(AssertionError, match="no running SafeYolo UDS forwarder"):
        forwarder_identity(proc_root)

    _process(proc_root, 44, ["socat", LISTENER, UPSTREAM])
    guest["forwarder"] = forwarder_identity(proc_root)
    check_guest_route(guest)
    guest["forwarder"] = {"pid": 43, "argv": ["socat", LISTENER, "UNIX-CONNECT:/tmp/unrelated.sock"]}
    with pytest.raises(AssertionError, match="not wired to the mounted SafeYolo UDS"):
        check_guest_route(guest)


def test_vz_route_requires_its_forwarder_and_does_not_require_a_linux_socket(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", installed_ingress.GUEST_PROXY)
    monkeypatch.setattr(installed_ingress, "GUEST_SOCKET", tmp_path / "absent-linux.sock")
    _process(tmp_path / "proc", 42, ["socat", LISTENER, "VSOCK-CONNECT:2:1080,retry=20,interval=0.25"])
    assert installed_ingress.bridge("vz", tmp_path / "proc")["pid"] == 42
    (tmp_path / "proc/42/cmdline").unlink()
    _process(tmp_path / "proc", 43, ["socat", LISTENER, "VSOCK-CONNECT:3:1080,retry=20"])
    with pytest.raises(AssertionError, match="no VZ forwarder"):
        installed_ingress.bridge("vz", tmp_path / "proc")


def test_linux_route_still_requires_its_mounted_agent_socket(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", installed_ingress.GUEST_PROXY)
    path = tmp_path / "proxy.sock"
    monkeypatch.setattr(installed_ingress, "GUEST_SOCKET", path)
    _process(tmp_path / "proc", 42, ["socat", LISTENER, f"UNIX-CONNECT:{path},retry=20"])
    with pytest.raises(AssertionError):
        installed_ingress.bridge("systrap", tmp_path / "proc")
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        assert installed_ingress.bridge("systrap", tmp_path / "proc")["pid"] == 42
