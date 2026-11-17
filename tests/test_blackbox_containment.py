"""Challenge the exact absence/refusal checkers with observable violations."""

import ctypes
import errno
import http.client
import importlib.util
import json
import socket
import sys
from pathlib import Path

import pytest

from tests.blackbox.harness import containment
from tests.blackbox.isolation import installed_ingress


def test_receiver_selection_uses_assigned_nonloopback_addresses():
    interfaces = [{"addr_info": [{"local": value} for value in
                                ("127.0.0.1", "::1", "169.254.169.254", "192.0.2.8", "2001:db8::8")]}]
    assert containment.receiver_addresses(interfaces, None, None) == ["192.0.2.8", "2001:db8::8"]
    for ipv4, ipv6 in (("127.0.0.1", None), (None, "::1"), ("192.0.2.9", None)):
        with pytest.raises(AssertionError, match="assigned non-loopback"):
            containment.receiver_addresses(interfaces, ipv4, ipv6)


@pytest.mark.parametrize("metadata,family", [(False, 4), (False, 6), (True, 4)])
def test_missing_owned_target_is_incomplete_not_success(monkeypatch, metadata, family):
    monkeypatch.setattr(containment, "manifest", lambda: {"network_supported": True, "receivers": []})
    with pytest.raises(AssertionError, match="incomplete"):
        containment.attempt_network("tcp", family, metadata=metadata)


def test_receiver_local_to_guest_is_not_an_external_route(monkeypatch):
    monkeypatch.setattr(containment.subprocess, "check_output", lambda *args, **kwargs:
                        json.dumps([{"addr_info": [{"local": "192.0.2.8"}]}]).encode())
    with pytest.raises(AssertionError, match="local to the guest"):
        containment.guest_destination({"address": "192.0.2.8"})


def test_tcp_delivery_followed_by_protocol_failure_is_not_containment():
    with containment.DeliveryReceiver("127.0.0.1", "tcp") as receiver:
        controls = [receiver.control()]
        client = http.client.HTTPConnection("127.0.0.1", receiver.endpoint["port"], timeout=2)
        try:
            client.request("POST", "/owned-violation", body=b"unique-delivery")
            with pytest.raises(http.client.BadStatusLine):
                client.getresponse()
        finally:
            client.close()
        controls.append(receiver.control())
        receiver.close()
        with pytest.raises(AssertionError, match="unauthorized delivery"):
            receiver.assert_no_delivery(controls)


def test_delivered_dns_without_a_reply_is_not_containment():
    with containment.DeliveryReceiver("127.0.0.1", "udp") as receiver:
        controls = [receiver.control()]
        question = b"\x01\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0dunique-canary\x04test\x00\x00\x01\x00\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.1)
            client.sendto(question, ("127.0.0.1", receiver.endpoint["port"]))
            with pytest.raises(TimeoutError):
                client.recvfrom(512)
        controls.append(receiver.control())
        receiver.close()
        assert any(row["sha256"] == containment.digest(question) for row in receiver.rows)
        with pytest.raises(AssertionError, match="unauthorized delivery"):
            receiver.assert_no_delivery(controls)


@pytest.mark.parametrize("transport", ["tcp", "udp"])
def test_allowed_receiver_controls_and_missing_observer(transport):
    with containment.DeliveryReceiver("127.0.0.1", transport) as receiver:
        controls = [receiver.control(), receiver.control()]
        receiver.close()
        receiver.assert_no_delivery(controls)
        receiver.rows.pop()
        with pytest.raises(AssertionError):
            receiver.assert_no_delivery(controls)


@pytest.mark.parametrize("result,error,accepted", [
    (-1, errno.EPERM, True), (-1, errno.ENOSYS, True), (-1, errno.EACCES, True),
    (-1, errno.EINVAL, False), (-1, errno.EFAULT, False), (-1, 0, False), (0, 0, False), (17, 0, False),
])
def test_refusal_rejects_invalid_input_and_nonnegative_descriptors(result, error, accepted):
    if accepted:
        containment.assert_refused(result, error, "owned syscall")
    else:
        with pytest.raises(AssertionError, match="invalid input is not containment"):
            containment.assert_refused(result, error, "owned syscall")


@pytest.mark.parametrize("architecture,bpf,getpid", [("x86_64", 321, 39), ("aarch64", 280, 172)])
def test_bpf_uses_valid_attributes_and_only_the_actual_architecture(monkeypatch, architecture, bpf, getpid):
    calls = []
    class Syscall:
        def __call__(self, number, *args):
            calls.append(number)
            if number == getpid:
                return containment.os.getpid()
            assert number == bpf and args[0] == 0
            attributes = ctypes.cast(args[1], ctypes.POINTER(ctypes.c_uint32))
            assert [attributes[i] for i in range(4)] == [1, 4, 4, 1]
            assert args[2] == 144
            ctypes.set_errno(errno.EPERM)
            return -1
    class Libc:
        syscall = Syscall()
    monkeypatch.setattr(containment.platform, "machine", lambda: architecture)
    monkeypatch.setattr(containment.ctypes, "CDLL", lambda *args, **kwargs: Libc())
    containment.check_bpf_refusal()
    assert calls == [getpid, bpf]


@pytest.mark.parametrize("descriptor", [0, 17])
def test_actual_bpf_checker_closes_and_rejects_a_successful_descriptor(monkeypatch, descriptor):
    closed = []
    class Syscall:
        def __call__(self, number, *args):
            ctypes.set_errno(0)
            return containment.os.getpid() if number == 39 else descriptor
    class Libc:
        syscall = Syscall()
    monkeypatch.setattr(containment.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(containment.ctypes, "CDLL", lambda *args, **kwargs: Libc())
    monkeypatch.setattr(containment.os, "close", closed.append)
    with pytest.raises(AssertionError, match=f"result={descriptor}"):
        containment.check_bpf_refusal()
    assert closed == [descriptor]


def test_exposed_host_file_and_process_canaries_fail_but_pid_collision_is_allowed(tmp_path, monkeypatch):
    private = tmp_path / "private"
    command = tmp_path / "cmdline"
    marker = b"host-canary-unique-owned-fixture"
    commitments = {"host_canaries": [{"path": str(path), "sha256": containment.digest(marker)}
                                      for path in (private, command)]}
    monkeypatch.setattr(containment, "manifest", lambda: commitments)
    command.write_bytes(b"guest-init\x00")
    containment.assert_host_canaries_absent()
    private.write_bytes(marker)
    with pytest.raises(AssertionError, match="host canary exposed"):
        containment.assert_host_canaries_absent()
    private.unlink()
    command.write_bytes(b"python\x00" + marker + b"\x00")
    with pytest.raises(AssertionError, match="host canary exposed"):
        containment.assert_host_canaries_absent()


@pytest.mark.parametrize("exposure", ["file", "socket"])
def test_peer_checker_rejects_exposed_live_peer(tmp_path, monkeypatch, exposure):
    own_state = tmp_path / "own"
    own_state.write_text("own-canary")
    own_socket = tmp_path / "own.sock"
    peer_socket = tmp_path / "peer.sock"
    peer_state = tmp_path / "peer"
    monkeypatch.setattr(installed_ingress, "GUEST_SOCKET", own_socket)
    with socket.socket(socket.AF_UNIX) as own, socket.socket(socket.AF_UNIX) as peer:
        own.bind(str(own_socket))
        own.listen(2)
        if exposure == "file":
            peer_state.write_text("peer-canary")
        else:
            peer.bind(str(peer_socket))
            peer.listen(2)
        with pytest.raises(AssertionError, match="peer's private"):
            installed_ingress.peer_boundary(str(peer_socket), str(peer_state), str(own_state), "own-canary")


@pytest.mark.parametrize("encoding", ["plain", "json"])
def test_exact_secret_canaries_fail_without_forbidding_provisioned_credentials(tmp_path, encoding):
    # An intentionally invalid PEM payload exercises extraction, not crypto.
    label = b"PRIVATE" + b" KEY"
    key = b"-----BEGIN " + label + b"-----\nQUJDREVGR0g=\n-----END " + label + b"-----\n"
    vault = "p3-native-" + "a" * 40
    path = tmp_path / "ca.pem"
    path.write_bytes(key)
    fingerprints = containment.secret_commitments(path, vault)
    for secret in (key, vault.encode()):
        data = json.dumps({"value": secret.decode()}).encode() if encoding == "json" else secret
        with pytest.raises(AssertionError, match="host secret exposed") as failure:
            containment.assert_no_secret(data, fingerprints, "isolated-fixture")
        assert vault not in str(failure.value) and "QUJD" not in str(failure.value)
    containment.assert_no_secret(b"p3-native-" + b"b" * 40, fingerprints, "provisioned-client")
    containment.assert_no_secret(key.replace(b"QUJDREVGR0g=", b"different-client-key"), fingerprints, "provisioned-client")


@pytest.mark.parametrize("exposure", [None, "file", "environment", "api"])
def test_installed_custody_scans_real_files_environment_and_scoped_api(tmp_path, monkeypatch, exposure):
    # The guest module normally imports this package via its pytest conftest.
    monkeypatch.syspath_prepend(str(Path(__file__).parent / "blackbox"))
    path = Path(__file__).parent / "blackbox/isolation/test_key_isolation.py"
    spec = importlib.util.spec_from_file_location("custody_guest_probe", path)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    from tests.blackbox.isolation import installed_access
    secret = "p3-native-" + "d" * 40
    commitments = [containment.digest(secret.encode()), containment.digest(b"other-signing-key")]
    (tmp_path / "client.json").write_text("deliberately provisioned client credential")
    if exposure == "file":
        (tmp_path / "unexpected.cache").write_text(secret)
    if exposure == "environment":
        monkeypatch.setenv("EXPOSED_SYNTHETIC_FIXTURE", secret)
    monkeypatch.setattr(installed_access, "api", lambda *args, **kwargs: (200, {}, {"canary": secret if exposure == "api" else "redacted"}))
    if exposure is None:
        assert probe.check_host_secret_custody(commitments, (tmp_path,))["files_inspected"] == 1
    else:
        with pytest.raises(AssertionError, match="host secret exposed") as failure:
            probe.check_host_secret_custody(commitments, (tmp_path,))
        assert secret not in str(failure.value)


def test_host_canary_and_live_observer_output_stay_outside_guest_workspace(tmp_path, monkeypatch):
    share = tmp_path / "instance/agents/bbtest/config-share"
    share.mkdir(parents=True)
    output = tmp_path / "instance/data/containment-guest-agent.json"
    # No network receiver is selected for this focused placement/control test.
    # The real process and private-file controls still run.
    monkeypatch.setattr(containment.sys, "platform", "darwin")
    code = ("import json,sys; from pathlib import Path; "
            "v=json.loads(Path(sys.argv[1]).read_text()); "
            "p=Path(v['host_canaries'][0]['path']); "
            "assert p.is_file() and p.parent.parent == Path(sys.argv[2])")
    result = containment.run_phase(["--share", str(share), "--output", str(output), "--phase", "guest-agent", "--",
                                    sys.executable, "-c", code, str(share / "containment.json"), str(output.parent)])
    report = json.loads(output.read_text())
    assert result == 0 and report["status"] == "passed"
    assert report["network_supported"] is False and report["host_canaries_live_after"] is True
    assert not (share / "containment.json").exists()
