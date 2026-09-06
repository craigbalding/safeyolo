"""Tests for the UI-independent audit stream reader."""

from __future__ import annotations

import json
import threading
import time

from safeyolo.core.audit_stream import (
    AuditLineParser,
    follow_jsonl,
    scan_pending_approvals,
)


def _event(event_id: str, summary: str = "event") -> dict:
    return {
        "event_id": event_id,
        "event": "ops.test",
        "kind": "ops",
        "severity": "low",
        "summary": summary,
        "details": {},
    }


def test_parser_rejects_bad_json_and_deduplicates_event_ids():
    parser = AuditLineParser()
    event = _event("evt-one")

    assert parser.parse("not json") is None
    assert parser.parse(json.dumps(event)) == event
    assert parser.parse(json.dumps(event)) is None


def test_parser_reports_schema_drift_without_dropping_event():
    drift = []
    parser = AuditLineParser(on_schema_drift=drift.append, seen_event_ids=None)
    event = {"event_id": "evt-drift", "event": "made.up", "summary": "old producer"}

    assert parser.parse(json.dumps(event)) == event
    assert len(drift) == 1


def test_parser_reports_and_skips_non_object_json():
    drift = []
    parser = AuditLineParser(on_schema_drift=drift.append)

    assert parser.parse('["not", "an", "event"]') is None
    assert len(drift) == 1


def test_pending_scan_skips_non_object_json(tmp_path):
    log = tmp_path / "safeyolo.jsonl"
    log.write_text('["not", "an", "event"]\n')

    assert scan_pending_approvals(log) == ([], set())


def test_non_following_reader_reads_existing_file(tmp_path):
    log = tmp_path / "safeyolo.jsonl"
    events = [_event("evt-one"), _event("evt-two")]
    log.write_text("\n".join(json.dumps(event) for event in events) + "\n")

    assert list(follow_jsonl(log, parse_line=AuditLineParser().parse, follow=False)) == events


def test_desktop_presented_resolves_its_exact_pending_request(tmp_path):
    log = tmp_path / "safeyolo.jsonl"
    request = {
        **_event("evt-request"),
        "event": "agent.desktop_present_requested",
        "approval": {
            "required": True,
            "approval_type": "desktop_present",
            "key": "desktop.present",
            "target": "desktop:ag-lens",
        },
    }
    resolution = {
        **_event("evt-resolution"),
        "event": "admin.desktop_presented",
        "details": {"agent_id": "ag-lens"},
    }
    log.write_text(f"{json.dumps(request)}\n{json.dumps(resolution)}\n")

    pending, resolved = scan_pending_approvals(log)

    assert pending == []
    assert "desktop.present:desktop:ag-lens" in resolved


def _replace_later(log, event, *, replace: bool) -> threading.Thread:
    def update() -> None:
        time.sleep(0.2)
        content = json.dumps(event) + "\n"
        if replace:
            replacement = log.with_suffix(".replacement")
            replacement.write_text(content)
            replacement.replace(log)
        else:
            log.write_text(content)

    thread = threading.Thread(target=update)
    thread.start()
    return thread


def test_following_reader_reopens_replaced_file(tmp_path):
    log = tmp_path / "safeyolo.jsonl"
    log.write_text(json.dumps(_event("evt-before", "x" * 300)) + "\n")
    expected = _event("evt-after")
    statuses = []
    thread = _replace_later(log, expected, replace=True)

    reader = follow_jsonl(
        log,
        parse_line=AuditLineParser().parse,
        on_status=statuses.append,
        reopen_check_interval=0.05,
    )
    assert next(reader) == expected
    thread.join()
    reader.close()
    assert "rotated" in statuses


def test_following_reader_reopens_truncated_file(tmp_path):
    log = tmp_path / "safeyolo.jsonl"
    log.write_text(json.dumps(_event("evt-before", "x" * 300)) + "\n")
    expected = _event("evt-after")
    statuses = []
    thread = _replace_later(log, expected, replace=False)

    reader = follow_jsonl(
        log,
        parse_line=AuditLineParser().parse,
        on_status=statuses.append,
        reopen_check_interval=0.05,
    )
    assert next(reader) == expected
    thread.join()
    reader.close()
    assert "truncated" in statuses
