"""Source operator HTTP target/header parsing and canonical authentication audit.

Only the standard request parser and reached auth hook run, in memory. This is
not a source listener or transport-completion comparison.
"""

import argparse
import io
import json
import logging
import os
import sys
from pathlib import Path
from unittest.mock import patch

root = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(root / "cli/src"), str(root)]
from safeyolo.core import audit_writer  # noqa: E402
from safeyolo.mitm_addons.admin_api import AdminRequestHandler  # noqa: E402


def observe():
    logging.disable(logging.CRITICAL)
    rows = []
    for target, headers in [
        ("/unknown?query=value", b""),
        ("//unknown?query=value", b"X-Forwarded-For: \xa0caf\xe9\xa0, ignored\r\nX-Forwarded-For: second\r\n"),
        ("http://owned.invalid/unknown?query=value", b"X-Forwarded-For: , ignored\r\n"),
    ]:
        handler = AdminRequestHandler.__new__(AdminRequestHandler)
        handler.raw_requestline = f"GET {target} HTTP/1.1\r\n".encode()
        handler.rfile = io.BytesIO(b"Host: owned.invalid\r\n" + headers + b"\r\n")
        handler.wfile = io.BytesIO()
        handler.client_address = ("127.0.0.1", 12345)
        handler.admin_token = "owned-fixture"
        replies, events = [], []
        handler._send_json = lambda value, status=200, replies=replies: replies.append(status)
        assert handler.parse_request()
        with patch.object(audit_writer, "put_event", side_effect=events.append):
            handler.do_GET()
        assert replies == [401] and len(events) == 1
        events[0].pop("ts")
        rows.append({"target": target, "headers_hex": headers.hex(), "event": events[0]})
    return rows


def observe_failures():
    logging.disable(logging.CRITICAL)
    handler = AdminRequestHandler.__new__(AdminRequestHandler)
    handler.raw_requestline = b"GET /unknown?query=value HTTP/1.1\r\n"
    handler.rfile = io.BytesIO(b"Host: owned.invalid\r\n\r\n")
    handler.wfile = io.BytesIO()
    handler.client_address = ("127.0.0.1", 12345)
    handler.admin_token = "owned-fixture"
    attempts, accepted, replies = [], [], []
    handler._send_json = lambda value, status=200: replies.append(
        {"status": status, "body": value}
    )
    assert handler.parse_request()

    def submit(event):
        attempts.append({key: value for key, value in event.items() if key != "ts"})
        raise RuntimeError("synthetic queue submission failure")

    error = None
    with patch.object(audit_writer, "put_event", side_effect=submit):
        try:
            handler.do_GET()
        except RuntimeError as exc:
            error = type(exc).__name__
    return {
        "failure_rows": [
            {
                "name": "auth_submission_fails_before_401",
                "attempted": attempts,
                "accepted": accepted,
                "replies": replies,
                "exception": error,
            }
        ]
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--failures",
        action="store_true",
        help="observe the isolated synchronous auth audit failure",
    )
    args = parser.parse_args()
    rows = observe_failures() if args.failures else observe()
    if args.check:
        assert json.loads(args.check.read_text()) == rows
    if args.output:
        args.output.write_text(json.dumps(rows, indent=2) + "\n")
    count = len(rows["failure_rows"]) if args.failures else len(rows)
    print(json.dumps({"auth_failure_rows" if args.failures else "auth_parser_rows": count}))
