"""Reject syscall mistakes that could produce a false keyring refusal pass."""

import ctypes
import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def keyring_probe(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / "blackbox"))
    from tests.blackbox.isolation.test_vm_isolation import TestSyscallSeccompEquivalents

    return TestSyscallSeccompEquivalents()


@pytest.mark.parametrize("arch,getpid,keyctl,add_key", [("aarch64", 172, 219, 217), ("x86_64", 39, 250, 248)])
@pytest.mark.parametrize("operation", ["keyctl", "add_key"])
@pytest.mark.parametrize("result,error", [(-1, errno.ENOSYS), (-1, errno.EPERM), (-1, errno.EACCES),
                                         (-1, errno.EINVAL), (-1, errno.EFAULT), (-1, errno.ENOKEY),
                                         (-1, 0), (0, 0), (123, 0)])
def test_keyring_probe_requires_valid_operation_and_specific_refusal(
    keyring_probe, monkeypatch, arch, getpid, keyctl, add_key, operation, result, error,
):
    monkeypatch.setattr("platform.machine", lambda: arch)
    calls = []

    def syscall(number, *arguments):
        calls.append(number)
        if number == getpid:
            assert not arguments
            return os.getpid()
        assert number == (keyctl if operation == "keyctl" else add_key)
        arguments = tuple(arg.value if isinstance(arg, ctypes.c_long) else arg for arg in arguments)
        if operation == "keyctl":
            assert arguments == (0, -1, 1, 0, 0)
        else:
            kind, description, payload, length, ring = arguments
            assert kind == b"user" and description.startswith(b"safeyolo-isolation-")
            assert payload == b"probe" and length == len(payload) and ring == -1
        ctypes.set_errno(error)
        return result

    monkeypatch.setattr(keyring_probe, "_libc", lambda: SimpleNamespace(syscall=syscall))
    probe = getattr(keyring_probe, f"test_{operation}_blocked")
    if result == -1 and error in (errno.ENOSYS, errno.EPERM, errno.EACCES):
        probe()
    else:
        with pytest.raises(AssertionError, match="syscall succeeded|expected an unavailable syscall"):
            probe()
    assert calls == [getpid, keyctl if operation == "keyctl" else add_key]


def test_keyring_probe_requires_working_positive_control(keyring_probe, monkeypatch):
    calls = []

    def syscall(number, *arguments):
        calls.append(number)
        ctypes.set_errno(errno.ENOSYS)
        return -1

    monkeypatch.setattr(keyring_probe, "_libc", lambda: SimpleNamespace(syscall=syscall))
    with pytest.raises(AssertionError, match="getpid syscall positive control failed"):
        keyring_probe.test_keyctl_blocked()
    assert len(calls) == 1
