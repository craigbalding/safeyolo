"""Tests for the blackbox runtime-evidence gate."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tests" / "blackbox" / "assert-platform.py"


@pytest.mark.parametrize(
    ("expected", "message"),
    [
        ("systrap", "systrap (software isolation) — /dev/kvm not found"),
        (
            "systrap",
            "systrap (software isolation) — forced by SAFEYOLO_RUNSC_PLATFORM",
        ),
        ("kvm", "KVM (hardware isolation)"),
        ("vz", "Apple Virtualization.framework (hardware isolation)"),
    ],
)
def test_assert_platform_accepts_matching_doctor_evidence(tmp_path: Path, expected: str, message: str) -> None:
    evidence = tmp_path / "doctor.json"
    evidence.write_text(json.dumps({"checks": [{"name": "Isolation platform", "message": message}]}))

    result = subprocess.run(
        [sys.executable, str(SCRIPT), expected, str(evidence)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert f"Isolation platform: {expected}" in result.stdout


def test_assert_platform_rejects_fallback(tmp_path: Path) -> None:
    evidence = tmp_path / "doctor.json"
    evidence.write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "name": "Isolation platform",
                        "message": "systrap (software isolation) — /dev/kvm not found",
                    }
                ]
            }
        )
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "kvm", str(evidence)],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "expected 'kvm'" in result.stderr


def test_reported_platform_requires_named_doctor_check() -> None:
    spec = importlib.util.spec_from_file_location("bb_assert_platform", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with pytest.raises(ValueError, match="no 'Isolation platform'"):
        module.reported_platform({"checks": []})
