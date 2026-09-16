"""Selected real production-child dispatch for RequestLogger -> Metrics reachability."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import tempfile
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from production_dispatch import source_root


def one_case(name, source_modules):
    """Build owned state; the caller dispatches actual source hooks asynchronously."""
    addonmanager, options, http, tflow, production, logger_module, metrics_module, ignored, unix_mode = source_modules
    logger = logger_module.RequestLogger()
    quiet = name.startswith("quiet")
    logger._load_quiet_hosts_from_pdp({
        "addons": {"request_logger": {"quiet_hosts": {"hosts": ["owned.invalid"] if quiet else []}}},
    })
    timeline = []
    phase = ["constructor"]

    def metrics_clock():
        value = {"constructor": 100.0, "request": 110.0, "response": 160.0}[phase[0]]
        timeline.append({"clock": "metrics", "hook": phase[0], "value": value})
        return value

    def logger_clock():
        assert phase[0] == "response"
        timeline.append({"clock": "request-logger", "hook": phase[0], "value": 150.0})
        return 150.0

    with patch.object(metrics_module, "time", SimpleNamespace(time=metrics_clock)):
        metrics = metrics_module.MetricsCollector()
    children = [logger, ignored.IgnoredHostLogger(), metrics]
    assert not hasattr(children[1], "request") and not hasattr(children[1], "response")
    # Reuse production_dispatch.py's selected-child construction. __init__ would
    # import/start unrelated owners; the real class/dispatcher are unchanged.
    container = production.ProductionAddons.__new__(production.ProductionAddons)
    container.addons = children
    master = SimpleNamespace(options=options.Options())
    manager = addonmanager.AddonManager(master)
    master.addons = manager
    manager.chain = [container]
    manager.lookup = {child.name: child for child in children}
    flow = tflow.tflow(resp=False)
    flow.request = http.Request.make("POST", "http://owned.invalid/a", b"owned request")
    flow.client_conn.peername = ("192.0.2.10", 10000)
    flow.client_conn.proxy_mode = unix_mode.parse("unix:/tmp/192.0.2.10_dispatch-agent/proxy.sock")
    # Earlier request-id stage is an explicit input to this selected suffix.
    flow.metadata.update(request_id="req-" + "1" * 32, start_time=90.0)
    if name in {"request_decode", "quiet_invalid_bodies"}:
        flow.request.headers["Content-Encoding"] = "gzip"
        flow.request.raw_content = b"owned invalid gzip"
    return SimpleNamespace(
        name=name, logger=logger, metrics=metrics, master=master, manager=manager,
        flow=flow, timeline=timeline, phase=phase, metrics_clock=metrics_clock,
        logger_clock=logger_clock, attempts=[], errors=[],
    )


def snapshot(case):
    return {
        "logger": case.logger.get_stats(),
        "metrics": case.metrics.get_stats(),
        "metrics_requests_error": case.metrics.requests_error,
        "domains": {name: asdict(stats) for name, stats in case.metrics._domain_stats.items()},
        "metadata": {key: case.flow.metadata[key] for key in (
            "request_id", "start_time", "metrics_start_time", "quieted", "blocked_by",
        ) if key in case.flow.metadata},
        "timeline": copy.deepcopy(case.timeline),
        "audit_attempts": copy.deepcopy(case.attempts),
        "dispatcher_errors": list(case.errors),
    }


async def run(source):
    sys.path[:0] = [str(source), str(source / "cli/src")]
    with tempfile.TemporaryDirectory(prefix="metrics-dispatch-") as temporary, patch.dict(os.environ, {
        "SAFEYOLO_DATA_DIR": temporary,
        "SAFEYOLO_LOG_PATH": temporary + "/unused-audit.jsonl",
        "MITMPROXY_LOG_PATH": temporary + "/unused-diagnostic.log",
    }):
        from mitmproxy import addonmanager, ctx, http, options
        from mitmproxy.net import encoding
        from mitmproxy.proxy.layers.http._hooks import HttpRequestHook, HttpResponseHook
        from mitmproxy.test import tflow

        import safeyolo.mitm_addons as production
        from pdp import is_policy_client_configured
        from safeyolo.core import audit_writer
        from safeyolo.mitm_addons import ignored_host_logger as ignored
        from safeyolo.mitm_addons import metrics as metrics_module
        from safeyolo.mitm_addons import request_logger as logger_module
        from safeyolo.proxy_modes.unix_listener import UnixMode

        assert not is_policy_client_configured()  # Actual startup getter raises; no PDP or files opened.
        assert audit_writer._writer is None
        chain = production.ADDON_CHAIN
        at = chain.index("request_logger.py")
        assert chain[at:at + 3] == ["request_logger.py", "ignored_host_logger.py", "metrics.py"]
        selected = (addonmanager, options, http, tflow, production, logger_module, metrics_module, ignored, UnixMode)
        rows = []
        network_attempts = []

        def no_network(*_args, **_kwargs):
            network_attempts.append(True)
            raise AssertionError("no network in selected dispatch proof")

        async def dispatch_case(name):
            case = one_case(name, selected)

            class Errors(logging.Handler):
                def emit(self, record):
                    if record.exc_info:
                        case.errors.append({"hook": case.phase[0], "class": record.exc_info[0].__name__})

            def put_event(entry):
                assert entry["schema_version"] == 1
                entry = copy.deepcopy(entry)
                entry.pop("ts")  # Only wall-clock audit timestamp is normalized.
                failed = case.name == case.phase[0] + "_audit"
                case.timeline.append({"put_event": entry["event"], "accepted": not failed})
                case.attempts.append({
                    "hook": case.phase[0], "accepted": not failed, "event": entry,
                    "logger_at_submit": case.logger.get_stats(), "metrics_at_submit": case.metrics.get_stats(),
                })
                if failed:
                    raise RuntimeError("owned synchronous audit submission failure")

            codes = {
                logger_module.RequestLogger.request.__code__: "request-logger.request",
                logger_module.RequestLogger.response.__code__: "request-logger.response",
                metrics_module.MetricsCollector.request.__code__: "metrics.request",
                metrics_module.MetricsCollector.response.__code__: "metrics.response",
            }

            def entered(frame, event, _arg):
                if event == "call" and frame.f_code in codes:
                    case.timeline.append({"entered": codes[frame.f_code]})

            manager_log = logging.getLogger("mitmproxy.addonmanager")
            sink = Errors()
            manager_log.addHandler(sink)
            old_profile = sys.getprofile()
            try:
                with (
                    patch.object(manager_log, "propagate", False),
                    patch.object(ctx, "master", case.master, create=True),
                    patch.object(logger_module, "time", SimpleNamespace(time=case.logger_clock)),
                    patch.object(metrics_module, "time", SimpleNamespace(time=case.metrics_clock)),
                    patch.object(audit_writer, "put_event", side_effect=put_event),
                ):
                    sys.setprofile(entered)
                    case.phase[0] = "request"
                    await case.manager.trigger_event(HttpRequestHook(case.flow))
                    request = snapshot(case)
                    case.phase[0] = "response"
                    case.flow.response = http.Response.make(200, b"owned response")
                    if case.name in {"response_decode", "quiet_invalid_bodies", "quiet_blocked_decode"}:
                        case.flow.response.headers["Content-Encoding"] = "gzip"
                        case.flow.response.raw_content = b"owned invalid gzip"
                    if case.name.startswith("quiet_blocked"):
                        case.flow.metadata["blocked_by"] = "pattern-scanner"
                    await case.manager.trigger_event(HttpResponseHook(case.flow))
                    response = snapshot(case)
            finally:
                sys.setprofile(old_profile)
                manager_log.removeHandler(sink)
            return {"case": name, "request": request, "response": response}

        with (
            patch.object(socket, "getaddrinfo", side_effect=no_network),
            patch.object(socket, "create_connection", side_effect=no_network),
        ):
            for name in (
                "normal", "quiet_invalid_bodies", "request_decode", "request_audit",
                "response_decode", "response_audit", "quiet_blocked_valid", "quiet_blocked_decode",
            ):
                rows.append(await dispatch_case(name))
        assert not network_attempts and audit_writer._writer is None
        assert not list(Path(temporary).iterdir())
        paths = [
            "proxy/tests/production_dispatch.py", "cli/src/safeyolo/mitm_addons/__init__.py",
            "cli/src/safeyolo/mitm_addons/request_logger.py", "cli/src/safeyolo/mitm_addons/ignored_host_logger.py",
            "cli/src/safeyolo/mitm_addons/metrics.py", "cli/src/safeyolo/core/identity.py",
            "cli/src/safeyolo/core/utils.py", "cli/src/safeyolo/core/audit_schema.py", "pdp/client.py",
        ]
        files = {path: source / path for path in paths}
        files.update({"mitmproxy/addonmanager.py": Path(addonmanager.__file__),
                      "mitmproxy/http.py": Path(http.__file__), "mitmproxy/net/encoding.py": Path(encoding.__file__)})
        metadata = {"python": platform.python_version(), "mitmproxy": version("mitmproxy"),
                    "sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()}}
    verify(rows)
    return {"rows": rows, "metadata": metadata, "network_attempts": 0,
            "audit_writer_created": False, "temporary_directory_removed": not Path(temporary).exists(),
            "selected_children": ["request-logger", "ignored-host-logger", "metrics"],
            "ignored_host_logger_ordinary_hooks": [],
            "boundary": "real selected ProductionAddons child container and AddonManager.trigger_event; owned in-memory completed flows, module clocks, actual quiet config loader and final audit put_event seam; no full startup or protocol proof"}


def verify(rows):
    for row in rows:
        name, request, response = row["case"], row["request"], row["response"]
        request_ok = name not in {"request_decode", "request_audit"}
        response_ok = name not in {"response_decode", "response_audit", "quiet_blocked_decode"}
        blocked = name == "quiet_blocked_valid"
        assert request["logger"]["requests_total"] == 1
        assert request["metrics"]["requests_total"] == int(request_ok)
        assert ("metrics_start_time" in request["metadata"]) == request_ok
        assert response["metrics"]["requests_total"] == int(request_ok)
        assert response["metrics"]["requests_success"] == int(response_ok and not blocked)
        assert response["metrics"]["requests_blocked"] == int(blocked)
        expected_hooks = ["request-logger.request"] + (["metrics.request"] if request_ok else [])
        expected_hooks += ["request-logger.response"] + (["metrics.response"] if response_ok else [])
        assert [item["entered"] for item in response["timeline"] if "entered" in item] == expected_hooks
        failures = []
        if not request_ok:
            failures.append({"hook": "request", "class": "ValueError" if name.endswith("decode") else "RuntimeError"})
        if not response_ok:
            failures.append({"hook": "response", "class": "ValueError" if name.endswith("decode") else "RuntimeError"})
        assert response["dispatcher_errors"] == failures
        domain = response["domains"]["owned.invalid"]
        if response_ok and not blocked:
            assert domain["latency_count"] == 1
            assert domain["latency_sum_ms"] == (50000.0 if request_ok else 0.0)
        else:
            assert domain["latency_count"] == 0
        if name == "quiet_invalid_bodies":
            assert response["audit_attempts"] == []
            assert response["logger"]["requests_quieted"] == 1
            assert response["logger"]["responses_total"] == 0
        if name.startswith("quiet_blocked"):
            assert response["logger"]["blocks_total"] == 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = asyncio.run(run(source_root(args.source)))
    if args.check is not None:
        assert result == json.loads(args.check.read_text()), "selected source dispatch fixture changed"
        print("8 actual selected source dispatch controls checked", file=sys.stderr)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(encoded)
    elif args.check is None:
        sys.stdout.write(encoded)


if __name__ == "__main__":
    main()
