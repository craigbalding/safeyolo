"""Focused controls for the #637 KVM P1 guest proxy route."""

from pathlib import Path

import pytest

from tests.blackbox.isolation.p1_guest_requests import forwarder_identity

BLACKBOX = Path(__file__).parent / "blackbox"
LISTENER = "TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork,su=agent"
UPSTREAM = "UNIX-CONNECT:/safeyolo/proxy/proxy.sock,retry=20,interval=0.25"


def _process(proc_root: Path, pid: int, argv: list[str]) -> None:
    directory = proc_root / str(pid)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cmdline").write_bytes(b"\0".join(part.encode() for part in argv) + b"\0")


def test_unrelated_localhost_proxy_cannot_satisfy_guest_route(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(BLACKBOX))
    from tests.blackbox.kvm_p1_ingress import check_guest_route

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
