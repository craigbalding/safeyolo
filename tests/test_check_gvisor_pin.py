"""Tests for the decisions of the pinned gVisor release check."""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

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
    ("release-20261005.1", "2026-10-15T00:00:00Z", True),   # later on the pin's day
    ("20261005.10", "2026-10-15T00:00:00Z", True),          # bare version retains its sequence
    ("20261109.0", "2026-11-10T00:00:00Z", True),           # fixed after the pin
    ("0.0.0-20261109120000-abcdef123456", "2026-11-10T00:00:00Z", True),
    (None, "2026-09-01T00:00:00Z", False),                  # no fixed release, older than the pin
    (None, "2026-11-01T00:00:00Z", True),                   # no fixed release, newer than the pin
])
def test_an_advisory_is_reported_only_when_the_pin_may_lack_its_fix(patched, published, reported):
    findings = check.advisory_findings([advisory("GHSA-aaaa-bbbb-cccc", patched=patched, published=published)], PIN)
    assert [finding["key"] for finding in findings] == (["advisory GHSA-aaaa-bbbb-cccc"] if reported else [])


@pytest.mark.parametrize("newest,reported", [
    ("release-20261102.0", False),   # 28 days between releases, regardless of today's date
    ("release-20261103.0", False),   # 29 days
    ("release-20261104.0", False),   # exactly 30 days
    ("release-20261105.0", True),    # 31 days
    ("release-20261005.1", False),   # same day, newer sequence
    ("release-20261004.0", False),   # older than the pin
    (PIN, False),                   # nothing newer to move to
])
def test_the_pin_is_stale_only_past_the_limit_with_a_newer_release(newest, reported):
    finding = check.stale_finding(PIN, newest)
    assert (finding is not None) == reported
    if reported:
        assert finding["key"] == f"stale {PIN}"
        assert "31 days older than the newest upstream release" in finding["lines"][0]


def test_advisory_release_sequences_are_compared_numerically():
    assert not check.advisory_findings([advisory("GHSA-fixture", patched="release-20261005.2")],
                                       "release-20261005.10")
    finding, = check.advisory_findings([advisory("GHSA-fixture", patched="release-20261005.10")],
                                      "release-20261005.2")
    assert "release-20261005.10, after the pin" in finding["lines"][-1]


def test_workflow_separates_pr_authority_and_serializes_all_issue_writers():
    workflow = yaml.safe_load((ROOT / ".github/workflows/gvisor-pin.yml").read_text())
    assert workflow["permissions"] == {"contents": "read"}
    verify = workflow["jobs"]["verify"]
    assert verify["if"] == "github.event_name == 'pull_request'"
    assert verify["permissions"] == {"contents": "read"}
    writer, = [job for job in workflow["jobs"].values() if job.get("permissions", {}).get("issues") == "write"]
    assert writer["if"] == "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    assert writer["permissions"] == {"contents": "read", "issues": "write"}
    # A fixed group serializes scheduled/manual runs even on different refs.
    assert writer["concurrency"]["group"] and "${{" not in writer["concurrency"]["group"]
    assert writer["concurrency"]["cancel-in-progress"] is False
    for job in (verify, writer):
        checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        assert checkout["with"]["persist-credentials"] is False


@pytest.fixture
def monitor_cli(tmp_path):
    """Run the real CLI with local upstream and issue API subprocess fixtures."""
    subject = tmp_path / "subject"
    (subject / "scripts/gvisor").mkdir(parents=True)
    for source in ("check_gvisor_pin.py", "gvisor/nofollow.patch", "gvisor/portforward.patch"):
        shutil.copyfile(ROOT / "scripts" / source, subject / "scripts" / source)
    # Keep decision fixtures independent of future upgrades to the real pin.
    (subject / "scripts/build_runsc.sh").write_text(f"version={PIN}-safeyolo.1\n")
    tools = tmp_path / "tools"
    tools.mkdir()
    data = tmp_path / "data.json"
    calls = tmp_path / "calls.jsonl"
    tool = tools / "fixture-tool"
    tool.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
        import json, os, sys
        from pathlib import Path
        from urllib.parse import parse_qs, urlsplit

        name, args = Path(sys.argv[0]).name, sys.argv[1:]
        data = json.loads(Path(os.environ["MONITOR_DATA"]).read_text())
        with Path(os.environ["MONITOR_CALLS"]).open("a") as output:
            output.write(json.dumps([name, *args]) + "\\n")
        if name == "git":
            if args[0] == "ls-remote":
                print("fixture\\trefs/tags/" + data["newest"])
            elif args[:2] == ["apply", "--check"]:
                sys.exit(1 if Path(args[-1]).name == "nofollow.patch" else 0)
            elif args[0] != "clone":
                raise AssertionError(args)
        elif args[0] == "api":
            endpoint = args[-1]
            kind = "advisories" if "security-advisories" in endpoint else "issues"
            if data.get("failed_read") == kind:
                print("fixture " + kind + " read denied", file=sys.stderr)
                sys.exit(1)
            rows = data[kind]
            if kind == "issues":
                query = parse_qs(urlsplit(endpoint).query)
                assert query["labels"] == ["gvisor-pin"]
                rows = [row for row in rows if query.get("state") == ["all"] or row["state"] == "open"]
            pages = [rows[i:i+100] for i in range(0, len(rows), 100)] or [[]]
            print(json.dumps(pages if "--paginate" in args and "--slurp" in args else pages[0]))
        elif args[:2] == ["issue", "create"]:
            print("https://github.com/fixture/repo/issues/1")
        else:
            raise AssertionError(args)
        '''))
    tool.chmod(0o755)
    for name in ("git", "gh"):
        (tools / name).symlink_to(tool)

    def execute(*, issues=(), advisories=(), newest="release-20261105.0", failed_read=None, job=None):
        data.write_text(json.dumps({"issues": list(issues), "advisories": list(advisories),
                                    "newest": newest, "failed_read": failed_read}))
        calls.write_text("")
        environment = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                       "MONITOR_DATA": str(data), "MONITOR_CALLS": str(calls),
                       "GH_TOKEN": "fixture-token", "GH_REPO": "fixture/repo", "TMPDIR": str(tmp_path)}
        command = [sys.executable, str(subject / "scripts/check_gvisor_pin.py")]
        if job is not None:
            workflow = yaml.safe_load((ROOT / ".github/workflows/gvisor-pin.yml").read_text())
            step, = [step for step in workflow["jobs"][job]["steps"] if "run" in step]
            command = ["bash", "-e", "-c", step["run"]]
        result = subprocess.run(command, cwd=subject, env=environment, capture_output=True, text=True, timeout=20)
        return result, [json.loads(line) for line in calls.read_text().splitlines()]

    return execute


@pytest.mark.parametrize("state,preceding", [("open", 0), ("closed", 0), ("open", 600), ("closed", 600)])
def test_cli_deduplicates_keys_through_complete_open_and_closed_history(monitor_cli, state, preceding):
    issues = [{"body": None, "state": "closed"}] * preceding
    issues.append({"body": f"Existing issue\n\nCheck key: stale {PIN}\n", "state": state})
    result, calls = monitor_cli(issues=issues, job="check")
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"already reported: stale {PIN}" in result.stdout
    assert not any(call[1:3] == ["issue", "create"] for call in calls)


@pytest.mark.parametrize("job,created", [("verify", False), ("check", True)])
def test_workflow_commands_report_findings_and_only_the_writer_creates_issues(monitor_cli, job, created):
    result, calls = monitor_cli(job=job)
    assert result.returncode == 0, result.stdout + result.stderr
    writes = [call for call in calls if call[1:3] == ["issue", "create"]]
    assert len(writes) == int(created)
    body = writes[0][writes[0].index("--body") + 1] if created else result.stdout
    assert "31 days older than the newest upstream release" in body
    assert "`nofollow.patch`: does not apply; upstream may contain it, or it needs a rebase" in body
    assert "`portforward.patch`: applies" in body


def test_duplicate_advisory_rows_create_only_one_issue(monitor_cli):
    row = advisory("GHSA-fixture", patched="release-20261005.1")
    result, calls = monitor_cli(advisories=[row, row], newest=PIN)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len([call for call in calls if call[1:3] == ["issue", "create"]]) == 1


@pytest.mark.parametrize("failed_read", ["advisories", "issues"])
def test_failed_reads_expose_the_tool_error_and_create_nothing(monitor_cli, failed_read):
    result, calls = monitor_cli(failed_read=failed_read)
    assert result.returncode != 0
    assert f"fixture {failed_read} read denied" in result.stderr
    assert not any(call[1:3] == ["issue", "create"] for call in calls)


def test_cli_reports_no_findings_for_a_release_gap_below_the_threshold(monitor_cli):
    result, calls = monitor_cli(newest="release-20261102.0")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 finding(s)" in result.stdout
    assert not any(call[1:3] == ["issue", "create"] for call in calls)
