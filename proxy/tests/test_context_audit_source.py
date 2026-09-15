"""Selected TestContext hooks with private files and canonical audit interception."""

import json
import logging
import os
import socket
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


def run(source):
    sys.path[:0] = [str(source), str(source / "cli/src")]
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="test-context-audit-") as directory:
        os.environ["SAFEYOLO_LOG_PATH"] = directory + "/unused-audit.jsonl"
        os.environ["MITMPROXY_LOG_PATH"] = directory + "/unused-diagnostic.log"
        os.environ["SAFEYOLO_DATA_DIR"] = directory
        from mitmproxy import ctx, http
        from mitmproxy.test import taddons, tflow

        from safeyolo.core import audit_writer, config_cache
        from safeyolo.mitm_addons import test_context
        from safeyolo.proxy_modes.unix_listener import UnixMode

        def no_network(*_args, **_kwargs):
            raise AssertionError("selected hook control must not access the network")

        rows = []
        for case in (
            "applied", "applied_request_error", "applied_response_error",
            "deny", "deny_error", "warn", "warn_error",
            "optional", "optional_error", "malformed",
        ):
            optional = case.startswith("optional")
            applied = case.startswith("applied")
            events = []
            errors = []
            submission = {"failed": False, "events": events}
            sensor = {"policy_hash": "owned", "addons": {"test_context": {
                "target_hosts": [] if optional else ["owned.invalid"],
            }}}
            addon = test_context.TestContext()
            flow = tflow.tflow(resp=False)
            flow.client_conn.id = "owned-connection"
            flow.client_conn.proxy_mode = UnixMode.parse("unix:/tmp/192.0.2.10_alice/proxy.sock")
            flow.request = http.Request.make("POST", "http://owned.invalid:8123/path?raw=1", b"body")
            flow.metadata.update(agent="alice", request_id="owned-request", start_time=0)
            if applied:
                flow.request.headers[test_context.TEST_CONTEXT_HEADER] = "run=owned;agent=claim;test=T1"
            elif optional or case == "malformed":
                flow.request.headers[test_context.TEST_CONTEXT_HEADER] = "invalid"

            def submit(entry, state=submission):
                if state["failed"]:
                    raise OSError("synthetic synchronous audit failure")
                state["events"].append(entry)

            with (
                taddons.context(addon),
                patch.object(socket, "getaddrinfo", side_effect=no_network),
                patch.object(socket, "create_connection", side_effect=no_network),
                patch.object(config_cache, "get_or_raise", return_value=sensor),
                patch.object(config_cache, "addon_section", return_value=sensor["addons"]["test_context"]),
                patch.object(audit_writer, "put_event", side_effect=submit),
            ):
                ctx.options.update(test_context_block=not case.startswith("warn"))
                submission["failed"] = case.endswith("error") and case != "applied_response_error"
                try:
                    addon.request(flow)
                except OSError:
                    errors.append("request")
                request_counts = [addon.stats.checks, addon.stats.allowed,
                                  addon.stats.blocked, addon.stats.warned,
                                  addon._declared_injections_total]
                request_status = flow.response.status_code if flow.response else None
                if applied:
                    submission["failed"] = case.endswith("error")
                    flow.response = http.Response.make(200, b"reply")
                    try:
                        addon.response(flow)
                    except OSError:
                        errors.append("response")
                for event in events:
                    event.pop("ts")
                rows.append({
                    "case": case, "events": events, "errors": errors,
                    "counts": request_counts, "request_status": request_status,
                    "context_applied": "test_context" in flow.metadata,
                    "header_contained": test_context.TEST_CONTEXT_HEADER not in flow.request.headers,
                })
        return rows


if __name__ == "__main__":
    print(json.dumps(run(Path(os.environ["SAFEYOLO_SOURCE_ROOT"]))))
