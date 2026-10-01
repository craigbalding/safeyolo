"""Actual source audit-envelope bytes and existing reader consumption, no I/O sink."""
import argparse
import copy
import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

root = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(root / "cli/src"), str(root)]
import yaml  # noqa: E402

from safeyolo.core import audit_schema, audit_writer, utils  # noqa: E402
from safeyolo.core.audit_stream import AuditLineParser  # noqa: E402


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)


def generate():
    base = {"event": "traffic.request", "kind": "traffic", "severity": "low", "summary": "fixture"}
    cases = [{"name": "minimal", "input": base}]
    for kind in ["security", "gateway", "traffic", "ops", "admin", "agent", "plumb", "coord"]:
        cases.append({"name": "kind_" + kind, "input": base | {"event": kind + ".fixture", "kind": kind}})
    cases += [
        {"name": "trusted_attribution", "input": base | {"request_id": "req-" + "0" * 32, "agent": "alice", "addon": "request-logger", "host": "fixture.invalid", "evidence_owner": "alice", "trusted_transport_identity": "alice", "initiator": "unknown", "attribution_status": "resolved", "attribution_provenance": {"transport_source": "uds", "uds_agent": "alice"}}, "details_json": '{"method":"POST","size":7,"client":null}'},
        {"name": "nested_attribution_removed", "input": base, "details_json": '{"first":1,"attribution":{"evidence_owner":"forged","kept":2},"last":3}'},
        {"name": "nested_attribution_order", "input": base | {"evidence_owner": "alice"}, "details_json": '{"first":1,"attribution":{"evidence_owner":"forged","kept":2},"last":3}'},
        {"name": "nonfinite", "input": base, "details_json": '{"values":[NaN,Infinity,-Infinity,-0.0,1e-07,1e20,1e21],"null":null}'},
        {"name": "unicode_control", "input": base | {"summary": "é\n\u2028 fixture", "host": "例.example"}, "details_json": '{"é":"/\\n\\t😀"}'},
        {"name": "falsy_details", "input": base, "details_json": '[]'},
        {"name": "invalid_details", "input": base, "details_json": '[1]'},
        {"name": "empty_summary", "input": base | {"summary": ""}},
        {"name": "wrong_prefix", "input": base | {"event": "proxy.fixture"}},
        {"name": "approval", "input": base | {"event": "security.fixture", "kind": "security", "decision": "require_approval", "approval": {"required": True, "approval_type": "network_egress", "key": "synthetic-key", "target": "fixture.invalid", "scope_hint": {"port": 443, "nested": None}}}},
        {"name": "integer_401", "input": base, "details_json": '{"n":' + '1' + '0' * 400 + '}'},
        {"name": "temporal_value", "input": base, "details_yaml": 'date: 2025-01-02\ntime: 2025-01-02T03:04:05.000123+00:00\n'},
        {"name": "temporal_nested_key", "input": base, "details_yaml": 'nested:\n  2025-01-02: typed\n  "2025-01-02": quoted\n'},
        {"name": "temporal_top_key", "input": base, "details_yaml": '2025-01-02: typed\n'},
    ]
    for depth in [254, 255, 256]:
        cases.append({"name": f"depth_{depth}", "input": base, "depth": depth})
    logging.disable(logging.CRITICAL)
    with patch.object(audit_schema, "datetime", FixedDatetime), patch.object(utils, "datetime", FixedDatetime):
        for case in cases:
            args = copy.deepcopy(case["input"])
            if "details_json" in case:
                args["details"] = json.loads(case["details_json"])
            if "details_yaml" in case:
                args["details"] = yaml.safe_load(case["details_yaml"])
            if "depth" in case:
                value = None
                for _ in range(case["depth"]):
                    value = {"nested": value}
                args["details"] = value
            if "approval" in args:
                args["approval"] = audit_schema.ApprovalRequest(**args["approval"])
            captured = []
            with patch.object(audit_writer, "put_event", side_effect=captured.append):
                utils.write_event(**args)
            assert len(captured) == 1
            encoded = json.dumps(captured[0]) + "\n"
            drift = []
            parsed = AuditLineParser(on_schema_drift=lambda _error, drift=drift: drift.append(True)).parse(encoded)
            assert parsed == captured[0]
            case["line_hex"] = encoded.encode().hex()
            case["schema_valid"] = not drift
    return {"rows": cases}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--consume", type=Path)
    args = parser.parse_args()
    if args.consume:
        drift = []
        reader = AuditLineParser(on_schema_drift=drift.append)
        records = [reader.parse(line) for line in args.consume.read_text().splitlines()]
        assert all(record is not None for record in records)
        print(json.dumps({"native_records": len(records), "schema_drift": len(drift)}))
        return
    document = generate()
    if args.check:
        assert json.loads(args.check.read_text()) == document
    if args.output:
        args.output.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps({"source_rows": len(document["rows"]), "matched": True}))


if __name__ == "__main__":
    main()
