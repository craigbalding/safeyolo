"""Tests for explicit Linux isolation-platform selection."""

import pytest

from safeyolo.commands import doctor
from safeyolo.platform import linux
from safeyolo.platform.linux import _apply_runsc_platform_override


def _detected_kvm() -> dict:
    return {
        "platform": "kvm",
        "kvm_exists": True,
        "kvm_operator_access": True,
        "kvm_subordinate_access": True,
        "forced": False,
        "reason": "KVM available with full access",
    }


def test_systrap_override_replaces_detected_kvm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAFEYOLO_RUNSC_PLATFORM", "systrap")

    info = _apply_runsc_platform_override(_detected_kvm())

    assert info["platform"] == "systrap"
    assert info["forced"] is True
    assert info["reason"] == "forced by SAFEYOLO_RUNSC_PLATFORM"


@pytest.mark.parametrize("value", ["", "auto", " AUTO "])
def test_auto_selection_preserves_detected_platform(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("SAFEYOLO_RUNSC_PLATFORM", value)
    info = _detected_kvm()

    assert _apply_runsc_platform_override(info) == info


def test_kvm_cannot_be_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAFEYOLO_RUNSC_PLATFORM", "kvm")

    with pytest.raises(RuntimeError, match="must be 'auto' or 'systrap'"):
        _apply_runsc_platform_override(_detected_kvm())


def test_doctor_reports_forced_systrap(monkeypatch: pytest.MonkeyPatch) -> None:
    info = _detected_kvm()
    info.update(
        platform="systrap",
        forced=True,
        reason="forced by SAFEYOLO_RUNSC_PLATFORM",
    )
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(linux, "detect_runsc_platform", lambda: info)

    result = doctor._check_isolation_platform()

    assert result.status == "pass"
    assert result.message == ("systrap (software isolation) — forced by SAFEYOLO_RUNSC_PLATFORM")
