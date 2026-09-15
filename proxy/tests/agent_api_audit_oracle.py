"""Actual AgentAPI producer envelopes and post-mutation submission failures.

No server, socket, operational token or background writer is used. Only the
writer's put_event boundary is replaced, after real AuditEvent validation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]

from mitmproxy.test import taddons, tflow  # noqa: E402

from safeyolo.core import audit_schema, audit_writer, config_cache, utils  # noqa: E402
from safeyolo.mitm_addons.agent_api import AgentAPI  # noqa: E402
from safeyolo.mitm_addons.agent_api_guard import AgentAPIRequestGuard  # noqa: E402
from safeyolo.mitm_addons.test_context import TestContext  # noqa: E402
from safeyolo.proxy_modes.unix_listener import UnixMode  # noqa: E402

SOURCE = "10.0.0.2"
NATIVE_ID = "native-backstop-fixture"
SOURCE_ID = "trusted-source-metadata-fixture"
BODY = b'{"context":"run=R;agent=claimed;test=T","ttl":7}'


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)


def cases():
    rows = []
    for method, prime in [("POST", False), ("DELETE", True), ("DELETE", False)]:
        for source_id in [None, SOURCE_ID]:
            rows.append({"name": f"{method}_{prime}_{source_id is not None}", "method": method,
                         "prime": prime, "source_id": source_id, "failure": None, "guard": False})
    for method in ["POST", "DELETE"]:
        for failure in ["RuntimeError", "OSError"]:
            rows.append({"name": f"{method}_{failure}", "method": method, "prime": True,
                         "source_id": None, "failure": failure, "guard": False})
    rows.append({"name": "wrong_auth", "method": "GET", "prime": False,
                 "source_id": SOURCE_ID, "failure": None, "guard": False, "wrong_auth": True})
    for failure in [None, "RuntimeError"]:
        rows.append({"name": f"guard_{failure}", "method": "POST", "prime": False,
                     "source_id": NATIVE_ID, "failure": failure, "guard": True})
    return rows


def state(owner):
    current = owner.get_declaration(SOURCE, "alice")
    return None if current is None else {"context": current[0], "expires_in": current[1]}


def observe(spec, token):
    owner, api, guard = TestContext(), AgentAPI(), AgentAPIRequestGuard()
    sensor = {"policy_hash": "fixture", "addons": {"test_context": {}}}
    flow = tflow.tflow()
    flow.request.url = "http://_safeyolo.proxy.internal/api/test-context/current///?agent=forged"
    flow.request.method = spec["method"]
    flow.request.headers["Authorization"] = "Bearer " + ("wrong" if spec.get("wrong_auth") else token)
    flow.request.headers["X-SafeYolo-Request-Id"] = "caller-id-is-not-metadata"
    flow.request.raw_content = BODY
    flow.client_conn.proxy_mode = UnixMode.parse("unix:/tmp/10.0.0.2_alice/proxy.sock")
    flow.client_conn.peername = (SOURCE, 0)
    if spec["source_id"] is not None:
        flow.metadata["request_id"] = spec["source_id"]
    attempts = []

    def put_event(entry):
        attempts.append({"line": json.dumps(entry) + "\n", "state": state(owner),
                         "response_already_present": flow.response is not None})
        if spec["failure"] == "RuntimeError":
            raise RuntimeError("owned synchronous producer failure")
        if spec["failure"] == "OSError":
            raise OSError("owned synchronous producer failure")

    with (
        patch.object(config_cache, "get_or_raise", return_value=sensor),
        patch.object(config_cache, "addon_section", side_effect=lambda name: sensor["addons"].get(name, {})),
        patch("safeyolo.mitm_addons.test_context.time.monotonic", return_value=1000.0),
        patch.object(audit_schema, "datetime", FixedDatetime),
        patch.object(utils, "datetime", FixedDatetime),
        patch.object(audit_writer, "put_event", side_effect=put_event),
        taddons.context(api, owner, guard),
    ):
        api._find_addon = lambda name: owner if name == "test-context" else None
        if spec["prime"]:
            owner.set_declaration(SOURCE, "alice", {"run": "prior", "agent": "alice"}, 9)
        before = state(owner)
        if spec["guard"]:
            guard.request(flow)
        else:
            asyncio.run(api.request(flow))
        assert flow.response is not None
        assert len(attempts) == 1
        result = {
            "status": flow.response.status_code,
            "body": flow.response.content.decode(),
            "before": before, "after": state(owner), "attempts": attempts,
            "request_id_after": flow.metadata.get("request_id"),
        }
        if spec["failure"] and not spec["guard"]:
            assert result["status"] == 500
            assert result["after"] == attempts[0]["state"]
            assert result["after"] != before
        assert attempts[0]["response_already_present"] == spec["guard"]
        event = json.loads(attempts[0]["line"])
        assert "approval" not in event and "attribution" not in event["details"]
        return {"input": spec, "result": result}


def generate():
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory() as directory:
        token = secrets.token_urlsafe(24)
        Path(directory, "agent_token").write_text(token)
        with patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": directory}):
            rows = [observe(spec, token) for spec in cases()]
        encoded = json.dumps(rows)
        assert token not in encoded and token.encode().hex() not in encoded
    return {"rows": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = generate()
    if args.check:
        assert json.loads(args.check.read_text()) == result
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"source_rows": len(result["rows"]), "matched": True}))


if __name__ == "__main__":
    main()
