"""Keep the guest syslog socket exception separate from device admission."""

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def dev_whitelist(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / "blackbox"))
    from tests.blackbox.isolation import test_vm_isolation

    return test_vm_isolation


@pytest.mark.parametrize("microvm", [False, True])
@pytest.mark.parametrize("mode,uid,gid,accepted", [
    (None, 0, 0, True),
    (stat.S_IFSOCK | 0o666, 0, 0, True),
    (stat.S_IFREG | 0o666, 0, 0, False),
    (stat.S_IFCHR | 0o666, 0, 0, False),
    (stat.S_IFBLK | 0o666, 0, 0, False),
    (stat.S_IFIFO | 0o666, 0, 0, False),
    (stat.S_IFLNK | 0o777, 0, 0, False),
    (stat.S_IFSOCK | 0o666, 1000, 0, False),
    (stat.S_IFSOCK | 0o666, 0, 1000, False),
])
def test_dev_whitelist_checks_syslog_type_and_guest_owner(dev_whitelist, monkeypatch, microvm, mode, uid, gid, accepted):
    metadata = os.stat_result((mode, 1, 1, 1, uid, gid, 0, 0, 0, 0)) if mode is not None else None
    inspected = []

    def lstat(path):
        inspected.append(path)
        return metadata

    monkeypatch.setattr(dev_whitelist, "_is_microvm", lambda: microvm)
    monkeypatch.setattr(dev_whitelist, "os", SimpleNamespace(
        listdir=lambda path: ["log"] if mode is not None else [],
        lstat=lstat, path=SimpleNamespace(isdir=lambda path: False),
    ))
    probe = dev_whitelist.TestSandboxExposure().test_dev_whitelist
    if accepted:
        probe()
    else:
        with pytest.raises(AssertionError, match="guest-root-owned syslog socket"):
            probe()
    assert inspected == (["/dev/log"] if mode is not None else [])
