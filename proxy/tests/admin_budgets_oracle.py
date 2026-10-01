"""Finite actual operator budget hooks, real local PDP, no sockets or tokens.

Method/auth/listener validation belongs to native/source wire tests. Malformed
budget resets preserve the exhausted source state after one error response.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import platform
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

REPO = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
sys.path[:0] = [str(REPO), str(REPO / "cli/src")]

from pdp.client import LocalPolicyClient, PolicyClientConfig  # noqa: E402
from safeyolo.core import audit_writer, utils  # noqa: E402
from safeyolo.core.audit_schema import sanitize_for_log  # noqa: E402
from safeyolo.mitm_addons import admin_api  # noqa: E402
from safeyolo.policy import engine as engine_module  # noqa: E402
from safeyolo.policy import loader as loader_module  # noqa: E402

KEY = "network:request:alpha.invalid"
POLICY = {
    "permissions": [
        {"action": "network:request", "resource": "alpha.invalid/*", "effect": "budget", "budget": 1, "condition": {}}
    ]
}
CASES = [
    ("absent", b""),
    ("null_body", b"null"),
    ("false_body", b"false"),
    ("zero_body", b"0"),
    ("empty_string_body", b'""'),
    ("empty_array_body", b"[]"),
    ("empty_object_body", b"{}"),
    ("exact_key", json.dumps({"resource": KEY}).encode()),
    ("wildcard_literal", b'{"resource":"network:request:*"}'),
    ("truthy_nonobject", b"[1]"),
    ("true_resource", b'{"resource":true}'),
    ("float_resource", b'{"resource":1e20}'),
    ("underflow_resource", b'{"resource":1e-1000}'),
    ("negative_zero_resource", b'{"resource":-0.0}'),
    ("huge_integer_resource", b'{"resource":' + b"1" + b"0" * 400 + b"}"),
    ("control_resource", b'{"resource":"synthetic\\n\\u001b[31mline"}'),
    ("list_resource", b'{"resource":["synthetic"]}'),
    ("object_resource", b'{"resource":{"synthetic":true}}'),
    ("duplicate_last_wins", b'{"resource":"missing","resource":null}'),
    ("authored_number_object", b'{"resource":{"$serde_json::private::Number":"17"}}'),
    ("malformed_json", b"{"),
    ("invalid_utf8", b"\xff"),
]


def run():
    logging.disable(logging.CRITICAL)
    events, network = [], []

    def no_network(*_args, **_kwargs):
        network.append(True)
        raise AssertionError("unexpected source network")

    def record(name, **fields):
        resource = fields.get("details", {}).get("resource")
        canonical = []
        with patch.object(audit_writer, "put_event", side_effect=canonical.append):
            utils.write_event(name, **fields)
        assert len(canonical) == 1
        canonical[0].pop("ts")
        events.append(
            {
                "name": name,
                "addon": fields.get("addon"),
                "kind": fields.get("kind"),
                "severity": fields.get("severity"),
                "summary": fields.get("summary"),
                "resource_json": json.dumps(resource),
                "safe_resource": sanitize_for_log(resource) if resource else "all",
                "resource_falsy": not bool(resource),
                "canonical": canonical[0],
            }
        )

    rows = []
    with tempfile.TemporaryDirectory(prefix="operator-budget-source-") as temporary, ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": temporary}))
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        stack.enter_context(patch("safeyolo.policy.budget_tracker.time.time", return_value=1000.0))
        for module in (loader_module, engine_module, admin_api):
            stack.enter_context(patch.object(module, "write_event", side_effect=record))
        for target in ("socket.getaddrinfo", "socket.create_connection", "socket.socket.connect"):
            stack.enter_context(patch(target, side_effect=no_network))
        path = Path(temporary) / "policy.json"
        path.write_text(json.dumps(POLICY))
        client = LocalPolicyClient(PolicyClientConfig(baseline_path=path))
        stack.callback(client.shutdown)
        stack.enter_context(patch.object(admin_api, "get_policy_client", return_value=client))
        engine = client._pdp._engine
        for name, body in CASES:
            client.reset_budgets()
            for expected in ("allow", "allow", "budget_exceeded"):
                assert engine.evaluate_request("alpha.invalid", path="/").effect == expected
            count = engine._evaluations
            events.clear()
            replies = []
            handler = admin_api.AdminRequestHandler.__new__(admin_api.AdminRequestHandler)
            handler.headers = {"Content-Length": str(len(body))}
            handler.rfile = io.BytesIO(body)
            handler.client_address = ("127.0.0.1", 54321)
            handler._send_json = lambda value, status=200, output=replies: output.append(
                {"status": status, "text": json.dumps(value, indent=2)}
            )
            error = None
            try:
                handler._handle_post_budgets_reset()
            except Exception as exc:
                error = type(exc).__name__
            rows.append(
                {
                    "name": name,
                    "input_hex": body.hex(),
                    "replies": replies,
                    "exception": error,
                    "events": list(events),
                    "tracked_keys": len(engine._budget_tracker.get_stats()["keys"]),
                    "evaluations_unchanged": count == engine._evaluations,
                }
            )
        client.reset_budgets()
        for _ in range(2):
            engine.evaluate_request("alpha.invalid", path="/")
        events.clear()
        before = engine._evaluations
        replies = []
        handler._send_json = lambda value, status=200: replies.append(
            {"status": status, "text": json.dumps(value, indent=2)}
        )
        handler._handle_get_budgets()
        get = {"replies": replies, "events": events, "evaluations_unchanged": engine._evaluations == before}

        # Keep the successful rows untouched. These controls run the actual
        # source envelope and fail only its queue submission after mutation.
        failure_rows = []
        with (
            patch.object(engine_module, "write_event", utils.write_event),
            patch.object(admin_api, "write_event", utils.write_event),
        ):
            for fail_on in (1, 2):
                with patch.object(audit_writer, "put_event"):
                    client.reset_budgets()
                for expected in ("allow", "allow", "budget_exceeded"):
                    assert (
                        engine.evaluate_request("alpha.invalid", path="/").effect
                        == expected
                    )
                before = engine._evaluations
                attempts, accepted, replies = [], [], []

                def submit(
                    event, *, attempts=attempts, accepted=accepted, fail_on=fail_on
                ):
                    entry = {key: value for key, value in event.items() if key != "ts"}
                    attempts.append(entry)
                    if len(attempts) == fail_on:
                        raise RuntimeError("synthetic queue submission failure")
                    accepted.append(entry)

                body = json.dumps({"resource": KEY}).encode()
                handler.headers = {"Content-Length": str(len(body))}
                handler.rfile = io.BytesIO(body)
                handler._send_json = (
                    lambda value, status=200, output=replies: output.append(
                        {"status": status, "text": json.dumps(value, indent=2)}
                    )
                )
                error = None
                with patch.object(audit_writer, "put_event", side_effect=submit):
                    try:
                        handler._handle_post_budgets_reset()
                    except RuntimeError as exc:
                        error = type(exc).__name__
                failure_rows.append(
                    {
                        "name": f"submission_{fail_on}_fails",
                        "fail_on": fail_on,
                        "input_hex": body.hex(),
                        "attempted": attempts,
                        "accepted": accepted,
                        "replies": replies,
                        "exception": error,
                        "tracked_keys": len(engine._budget_tracker.get_stats()["keys"]),
                        "evaluations_unchanged": engine._evaluations == before,
                    }
                )
    assert not network
    assert all(row["evaluations_unchanged"] for row in rows)
    assert all(
        len(row["events"]) == (2 if row["replies"] and row["replies"][-1]["status"] == 200 else 0) for row in rows
    )
    assert all(
        [reply["status"] for reply in row["replies"]] == [400]
        and row["events"] == []
        and row["tracked_keys"] == 1
        for row in rows
        if row["name"] in ("malformed_json", "invalid_utf8")
    )
    paths = [
        "cli/src/safeyolo/mitm_addons/admin_api.py",
        "pdp/client.py",
        "pdp/core.py",
        "cli/src/safeyolo/policy/engine.py",
        "cli/src/safeyolo/policy/budget_tracker.py",
        "cli/src/safeyolo/core/audit_schema.py",
        "cli/src/safeyolo/core/utils.py",
        "cli/src/safeyolo/core/audit_writer.py",
    ]
    return {
        "python": platform.python_version(),
        "scope": "actual source hooks and PDP; no HTTP/auth/listener",
        "policy": POLICY,
        "rows": rows,
        "get": get,
        "failure_rows": failure_rows,
        "network_attempts": len(network),
        "tokens_read_or_minted": 0,
        "source_sha256": {path: hashlib.sha256((REPO / path).read_bytes()).hexdigest() for path in paths},
    }


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("admin_budgets_source.json")
    target.write_text(json.dumps(run(), indent=2) + "\n")
