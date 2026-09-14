"""VM-helper signing posture is observed from a bounded executable protocol."""

import json
import sys

import pytest

from safeyolo.agent_diag import _check_vm_helper_identity as agent_identity
from safeyolo.commands.doctor import _check_vm_helper_identity as doctor_identity
from safeyolo.vm import VMError
from safeyolo.vm_identity import read_vm_helper_identity


def _identity(**changes):
    result = {
        "schema_version": 1, "version": "0.1.0", "helper_version": "0.3.1",
        "git_sha": "a" * 40, "git_dirty": False, "build_profile": "production",
        "architecture": "arm64", "swift_compiler": "Apple Swift 6.4",
        "optimization": "release", "symbols": "DWARF+dSYM",
        "get_task_allow": False, "hardened_runtime": True,
    }
    result.update(changes)
    return result


def _helper(tmp_path, raw):
    path = tmp_path / "helper"
    path.write_text(f"#!{sys.executable}\nprint({raw!r})\n")
    path.chmod(0o755)
    return path


def test_production_identity_and_both_diagnostic_renderings(tmp_path, monkeypatch):
    binary = _helper(tmp_path, json.dumps(_identity()))
    monkeypatch.setenv("SAFEYOLO_VM_HELPER", str(binary))
    identity = read_vm_helper_identity()
    assert not identity.warning
    assert "debuggable=no" in identity.summary
    assert "a" * 40 in identity.summary
    assert doctor_identity().status == "pass"
    assert agent_identity().status == "PASS"


def test_debuggable_helper_explains_actual_authority(tmp_path, monkeypatch):
    binary = _helper(tmp_path, json.dumps(_identity(build_profile="development", get_task_allow=True)))
    monkeypatch.setenv("SAFEYOLO_VM_HELPER", str(binary))
    doctor = doctor_identity()
    agent = agent_identity()
    assert doctor.status == "warn"
    assert agent.status == "WARN"
    assert "debuggable=yes" in doctor.message
    assert "inspect or modify" in doctor.detail
    assert "get-task-allow" in agent.message


def test_unknown_signing_state_cannot_be_reported_as_production_safe(tmp_path):
    binary = _helper(tmp_path, json.dumps(_identity(get_task_allow=None, hardened_runtime=None)))
    identity = read_vm_helper_identity(binary)
    assert "debuggable=unknown" in identity.summary
    assert "could not determine" in identity.warning


@pytest.mark.parametrize("changes", [
    {"schema_version": True}, {"schema_version": 2},
    {"get_task_allow": "false"}, {"hardened_runtime": 0},
    {"architecture": "arm64\nPASS"}, {"git_sha": "x" * 513},
])
def test_malformed_identity_is_not_accepted(tmp_path, changes):
    binary = _helper(tmp_path, json.dumps(_identity(**changes)))
    with pytest.raises(VMError):
        read_vm_helper_identity(binary)


@pytest.mark.parametrize("raw", ["safeyolo-vm 0.3.1", "[]", "x" * 17000],
                         ids=["old-helper", "array", "oversized"])
def test_old_or_invalid_helper_is_reported_as_unknown(tmp_path, monkeypatch, raw):
    binary = _helper(tmp_path, raw)
    monkeypatch.setenv("SAFEYOLO_VM_HELPER", str(binary))
    assert doctor_identity().status == "warn"
    assert agent_identity().status == "WARN"


def test_identity_timeout_is_bounded(tmp_path):
    binary = tmp_path / "helper"
    binary.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
    binary.chmod(0o755)
    with pytest.raises(VMError, match="timed out"):
        read_vm_helper_identity(binary, timeout=0.05)
