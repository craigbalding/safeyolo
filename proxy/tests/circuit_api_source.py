"""Finite actual circuit API hooks; synthetic state/auth, no network or watcher.

The management handler uses its real JSON parser/reset/writer validation. Only
its response transport, addon lookup and the writer queue sink are supplied by
this controlled direct-hook fixture. Agent requests retain real auth/dispatch.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import logging
import os
import tempfile
from contextlib import ExitStack
from datetime import date
from pathlib import Path
from unittest.mock import patch

from mitmproxy.test import taddons, tflow

from safeyolo.mitm_addons import admin_api, agent_api, circuit_breaker

HOST = "owned.invalid"
NOW = 1000.0


def run():
    logging.disable(logging.CRITICAL)
    rows, reads, events = [], [], []
    specs = [
        ("absent", b""),
        ("empty_object", b"{}"),
        ("false_host", b'{"host":false}'),
        ("exact", b'{"host":"owned.invalid"}'),
        ("literal_wildcard", b'{"host":"*"}'),
        ("true_host", b'{"host":true}'),
        ("integer_host", b'{"host":17}'),
        ("float_host", b'{"host":1e20}'),
        ("infinity_host", b'{"host":1e400}'),
        ("array_host", b'{"host":["owned.invalid"]}'),
        ("object_host", b'{"host":{"x":1}}'),
        ("truthy_nonobject", b"[1]"),
        ("malformed", b"{"),
        ("invalid_utf8", b"\xff"),
    ]
    with tempfile.TemporaryDirectory(prefix="circuit-api-source-") as temporary, ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": temporary}))
        stack.enter_context(patch("safeyolo.core.audit_writer.put_event", side_effect=events.append))
        stack.enter_context(patch.object(circuit_breaker.time, "time", return_value=NOW))
        for target in ("socket.getaddrinfo", "socket.create_connection", "socket.socket.connect"):
            stack.enter_context(patch(target, side_effect=AssertionError("Unexpected source network")))
        for name, payload in specs:
            cb = circuit_breaker.CircuitBreaker()
            cb.force_open(HOST)
            events.clear()
            replies = []
            handler = admin_api.AdminRequestHandler.__new__(admin_api.AdminRequestHandler)
            handler.headers = {"Content-Length": str(len(payload))}
            handler.rfile = io.BytesIO(payload)
            handler.client_address = ("127.0.0.1", 43210)
            handler._get_addon = lambda _name, selected=cb: selected
            handler._send_json = lambda value, status=200, output=replies: output.append(
                {"status": status, "text": json.dumps(value, indent=2)}
            )
            error = None
            try:
                handler._handle_post_circuit_breaker_reset()
            except (AttributeError, TypeError) as exception:
                error = type(exception).__name__
            # Times are actual audit-envelope metadata; retain all semantic
            # fields without writing nondeterministic timestamps into a golden.
            selected = [{key: value for key, value in event.items() if key != "ts"} for event in events]
            rows.append(
                {
                    "name": name,
                    "input_hex": payload.hex(),
                    "replies": replies,
                    "exception": error,
                    "events": selected,
                    "retained": cb._state.all_domains(),
                }
            )
        token = "synthetic-circuit-api-token"
        (Path(temporary) / "agent_token").write_text(token)
        for name in ("absent", "defaults", "disabled", "nan", "infinity", "date", "half_open", "partial_error"):
            cb = circuit_breaker.CircuitBreaker()
            if name in {"nan", "infinity"}:
                cb._state.set(HOST, {"state": "closed", "failure_count": float("nan" if name == "nan" else "inf")})
            if name in {"date", "partial_error"}:
                cb.failure_threshold = date(2001, 2, 3)
            if name in {"half_open", "partial_error"}:
                cb._state.set(HOST, {"state": "open", "opened_at": 0, "failure_count": 5})
            api = agent_api.AgentAPI()
            events.clear()
            with taddons.context(api) as context:
                context.options.add_option("circuit_breaker_enabled", bool, name != "disabled", "owned bool")
                api._find_addon = lambda _name, selected=cb, absent=name == "absent": None if absent else selected
                flow = tflow.tflow()
                flow.request.url = "http://_safeyolo.proxy.internal/circuits///?agent=forged"
                flow.request.headers["Authorization"] = "Bearer " + token
                asyncio.run(api.request(flow))
                assert flow.response is not None
                reads.append(
                    {
                        "name": name,
                        "status": flow.response.status_code,
                        "text": flow.response.content.decode(),
                        "events": [{key: value for key, value in event.items() if key != "ts"} for event in events],
                    }
                )
        failure_rows = []
        for fail_on in (1, 2):
            cb = circuit_breaker.CircuitBreaker()
            cb.force_open(HOST)
            assert cb._state.all_domains() == [HOST]
            attempts, accepted, replies = [], [], []

            def submit(event, *, attempts=attempts, accepted=accepted, fail_on=fail_on):
                entry = {key: value for key, value in event.items() if key != "ts"}
                attempts.append(entry)
                if len(attempts) == fail_on:
                    raise RuntimeError("synthetic queue submission failure")
                accepted.append(entry)

            payload = json.dumps({"host": HOST}).encode()
            handler = admin_api.AdminRequestHandler.__new__(
                admin_api.AdminRequestHandler
            )
            handler.headers = {"Content-Length": str(len(payload))}
            handler.rfile = io.BytesIO(payload)
            handler.client_address = ("127.0.0.1", 43210)
            handler._get_addon = lambda _name, selected=cb: selected
            handler._send_json = (
                lambda value, status=200, output=replies: output.append(
                    {"status": status, "text": json.dumps(value, indent=2)}
                )
            )
            error = None
            with patch("safeyolo.core.audit_writer.put_event", side_effect=submit):
                try:
                    handler._handle_post_circuit_breaker_reset()
                except RuntimeError as exc:
                    error = type(exc).__name__
            failure_rows.append(
                {
                    "name": f"submission_{fail_on}_fails",
                    "fail_on": fail_on,
                    "input_hex": payload.hex(),
                    "attempted": attempts,
                    "accepted": accepted,
                    "replies": replies,
                    "exception": error,
                    "retained": cb._state.all_domains(),
                }
            )
    paths = [
        "cli/src/safeyolo/mitm_addons/circuit_breaker.py",
        "cli/src/safeyolo/mitm_addons/agent_api.py",
        "cli/src/safeyolo/mitm_addons/admin_api.py",
        "cli/src/safeyolo/core/utils.py",
        "cli/src/safeyolo/core/audit_schema.py",
    ]
    return {
        "admin": rows,
        "agent": reads,
        "failure_rows": failure_rows,
        "source_sha256": {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in paths},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = run()
    if args.check:
        assert result == json.loads(args.check.read_text()), "Source circuit API oracle changed"
        print("22 actual source circuit API rows and 2 submission failures match")
    else:
        print(json.dumps(result, indent=2))
