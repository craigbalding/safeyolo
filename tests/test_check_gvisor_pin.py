"""Tests for the decisions of the pinned gVisor release check."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from scripts import check_gvisor_pin as check

ROOT = Path(__file__).resolve().parents[1]
PIN = "release-20261005.0"


def advisory(identifier, *, patched=None, published="2026-10-20T00:00:00Z"):
    return {
        "ghsa_id": identifier, "cve_id": None, "severity": "high", "summary": "fixture",
        "html_url": f"https://github.com/google/gvisor/security/advisories/{identifier}",
        "published_at": published,
        "vulnerabilities": [{"patched_versions": patched}],
    }


def test_the_repository_pin_is_readable():
    pin = check.pinned_release((ROOT / "scripts/build_runsc.sh").read_text())
    assert check.release_order(pin)[0] >= datetime.date(2026, 10, 5)


def test_an_unreadable_pin_fails_instead_of_reporting_nothing():
    with pytest.raises(ValueError):
        check.pinned_release("version=unknown\n")
    with pytest.raises(ValueError):
        check.newest_release(["v1.0"])


def test_newest_release_orders_by_date_then_sequence():
    tags = ["release-20261123.0", "release-20261123.1", "release-20261116.0", "nightly"]
    assert check.newest_release(tags) == "release-20261123.1"


@pytest.mark.parametrize("patched,published,reported", [
    ("20260831.0", "2026-10-15T00:00:00Z", False),          # fixed before the pin, published later
    ("release-20261005.0", "2026-10-15T00:00:00Z", False),  # fixed in the pin
    ("20261109.0", "2026-11-10T00:00:00Z", True),           # fixed after the pin
    ("0.0.0-20261109120000-abcdef123456", "2026-11-10T00:00:00Z", True),
    (None, "2026-09-01T00:00:00Z", False),                  # no fixed release, older than the pin
    (None, "2026-11-01T00:00:00Z", True),                   # no fixed release, newer than the pin
])
def test_an_advisory_is_reported_only_when_the_pin_may_lack_its_fix(patched, published, reported):
    findings = check.advisory_findings([advisory("GHSA-aaaa-bbbb-cccc", patched=patched, published=published)], PIN)
    assert [finding["key"] for finding in findings] == (["advisory GHSA-aaaa-bbbb-cccc"] if reported else [])


@pytest.mark.parametrize("newest,today,reported", [
    ("release-20261123.1", datetime.date(2026, 11, 27), False),  # 53 days
    ("release-20261123.1", datetime.date(2026, 12, 4), False),   # exactly 60 days
    ("release-20261130.0", datetime.date(2026, 12, 5), True),
    (PIN, datetime.date(2027, 3, 1), False),                     # nothing newer to move to
])
def test_the_pin_is_stale_only_past_the_limit_with_a_newer_release(newest, today, reported):
    finding = check.stale_finding(PIN, newest, today)
    assert (finding is not None) == reported
    if reported:
        assert finding["key"] == f"stale {PIN}"
