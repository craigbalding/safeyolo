"""Actual source container dispatch; synthetic flows and private SQLite only."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def source_root(explicit: Path | None) -> Path:
    selected = explicit or os.environ.get("SAFEYOLO_SOURCE_ROOT")
    candidates = [Path(selected)] if selected else [Path.cwd(), *Path(__file__).parents]
    for candidate in candidates:
        if (candidate / "cli/src/safeyolo").is_dir() and (candidate / "pdp").is_dir():
            return candidate.resolve()
    raise SystemExit("set SAFEYOLO_SOURCE_ROOT or --source to the SafeYolo repository")


def metadata(source: Path, addonmanager, http) -> dict:
    from mitmproxy.net import encoding

    source_paths = (
        "cli/src/safeyolo/traffic_master.py",
        "cli/src/safeyolo/mitm_addons/__init__.py",
        "cli/src/safeyolo/mitm_addons/request_id.py",
        "cli/src/safeyolo/mitm_addons/test_context.py",
        "cli/src/safeyolo/mitm_addons/flow_recorder.py",
        "cli/src/safeyolo/mitm_addons/request_logger.py",
        "cli/src/safeyolo/core/trace.py",
        "cli/src/safeyolo/core/flow_writer.py",
        "cli/src/safeyolo/storage/flow_store.py",
    )
    files = {path: source / path for path in source_paths}
    files.update(
        {
            "mitmproxy/addonmanager.py": Path(addonmanager.__file__),
            "mitmproxy/http.py": Path(http.__file__),
            "mitmproxy/net/encoding.py": Path(encoding.__file__),
        }
    )
    return {
        "python": platform.python_version(),
        "mitmproxy": version("mitmproxy"),
        "sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()},
    }


async def run(source: Path) -> dict:
    # This oracle runs as a child process: redirect import-time log defaults to
    # private temporary paths before importing the real source components.
    sys.path[:0] = [
        str(source),
        str(source / "cli/src"),
        str(source / "cli/src/safeyolo/mitm_addons"),
    ]
    with tempfile.TemporaryDirectory(prefix="logger-dispatch-") as temporary:
        os.environ["SAFEYOLO_LOG_PATH"] = temporary + "/unused-audit.jsonl"
        os.environ["MITMPROXY_LOG_PATH"] = temporary + "/unused-diagnostic.log"
        os.environ["SAFEYOLO_DATA_DIR"] = temporary
        from mitmproxy import addonmanager, ctx, http, options
        from mitmproxy.proxy.layers.http._hooks import HttpRequestHook, HttpResponseHook
        from mitmproxy.test import tflow

        from safeyolo.core import config_cache, flow_writer
        from safeyolo.mitm_addons import ProductionAddons
        from safeyolo.mitm_addons import flow_recorder as recording
        from safeyolo.mitm_addons import request_logger as logging_addon
        from safeyolo.mitm_addons import test_context as context
        from safeyolo.mitm_addons.request_id import RequestIdGenerator
        from safeyolo.proxy_modes.unix_listener import UnixMode
        from safeyolo.storage.flow_store import FlowStore

        network_attempts = []
        errors = []

        def no_network(*_args, **_kwargs):
            network_attempts.append(True)
            raise AssertionError("no network is permitted in this source control")

        class Errors(logging.Handler):
            def emit(self, record):
                if record.exc_info:
                    errors.append(record.exc_info[0].__name__)

        sink = Errors()
        manager_log = logging.getLogger("mitmproxy.addonmanager")
        manager_log.addHandler(sink)
        manager_log.propagate = False
        sensor = {
            "policy_hash": "owned",
            "addons": {
                "test_context": {"target_hosts": ["owned.invalid"]},
            },
        }
        rows = []
        try:
            with (
                patch.object(socket, "getaddrinfo", side_effect=no_network),
                patch.object(socket, "create_connection", side_effect=no_network),
                patch.object(config_cache, "get_or_raise", return_value=sensor),
                patch.object(
                    logging_addon,
                    "get_policy_client",
                    return_value=SimpleNamespace(get_sensor_config=lambda: sensor),
                ),
                patch.object(
                    ctx,
                    "options",
                    SimpleNamespace(flow_store_enabled=True),
                    create=True,
                ),
            ):
                for mode in ("production_container", "separate_addons_control"):
                    for case in (
                        "valid",
                        "request_content_error",
                        "response_content_error",
                        "both_content_errors",
                    ):
                        events = []
                        before_errors = len(errors)
                        addon = context.TestContext()
                        recorder = recording.FlowRecorder()
                        logger = logging_addon.RequestLogger()
                        store = FlowStore(str(Path(temporary) / f"{mode}-{case}.sqlite3"))
                        store.init_db()
                        recorder.store = store
                        writer = flow_writer.install(store)
                        children = [RequestIdGenerator(), addon, recorder, logger]
                        # Preserve the exact production container type/dispatch
                        # boundary, avoiding unrelated addon startup/imports.
                        production = ProductionAddons.__new__(ProductionAddons)
                        production.addons = children
                        master = SimpleNamespace(options=options.Options())
                        manager = addonmanager.AddonManager(master)
                        master.addons = manager
                        manager.chain = [production] if mode == "production_container" else children
                        manager.lookup = {child.name: child for child in children}
                        flow = tflow.tflow(resp=False)
                        flow.request = http.Request.make("POST", "http://owned.invalid/a", b"request")
                        flow.request.headers["X-SafeYolo-Test-Context"] = "run=owned;agent=declared;test=t1"
                        flow.client_conn.peername = ("192.0.2.10", 10000)
                        flow.client_conn.proxy_mode = UnixMode.parse("unix:/tmp/192.0.2.10_alice/proxy.sock")
                        if case in ("request_content_error", "both_content_errors"):
                            flow.request.headers["Content-Encoding"] = "gzip"
                            flow.request.raw_content = b"invalid owned gzip"
                        with (
                            patch.object(ctx, "master", master, create=True),
                            patch.object(
                                context,
                                "write_event",
                                side_effect=lambda event, _events=events, **_kw: _events.append(event),
                            ),
                            patch.object(
                                logging_addon,
                                "write_event",
                                side_effect=lambda event, _events=events, **_kw: _events.append(event),
                            ),
                        ):
                            await manager.trigger_event(HttpRequestHook(flow))
                            request_snapshot = {
                                "context_applied": "test_context" in flow.metadata,
                                "context_allowed": addon.stats.allowed,
                                "logger": logger.get_stats(),
                                "events": list(events),
                                "errors": errors[before_errors:],
                            }
                            flow.response = http.Response.make(200, b"response")
                            if case in (
                                "response_content_error",
                                "both_content_errors",
                            ):
                                flow.response.headers["Content-Encoding"] = "gzip"
                                flow.response.raw_content = b"invalid owned gzip"
                            await manager.trigger_event(HttpResponseHook(flow))
                        writer._shutdown()
                        assert writer._thread is None or not writer._thread.is_alive()
                        count = store._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
                        rows.append(
                            {
                                "mode": mode,
                                "case": case,
                                "request": request_snapshot,
                                "logger": logger.get_stats(),
                                "recorder": recorder.get_stats(),
                                "events": list(events),
                                "errors": errors[before_errors:],
                                "persisted_rows": count,
                            }
                        )
                        store.close()
                        flow_writer._writer = None
        finally:
            manager_log.removeHandler(sink)
        assert not network_attempts
        pairs = {(row["mode"], row["case"]): row for row in rows}
        for mode in ("production_container", "separate_addons_control"):
            assert pairs[mode, "valid"]["persisted_rows"] == 1
            assert pairs[mode, "valid"]["logger"]["requests_total"] == 1
            assert pairs[mode, "valid"]["logger"]["responses_total"] == 1
        assert pairs["production_container", "request_content_error"]["request"]["logger"]["requests_total"] == 0
        assert pairs["separate_addons_control", "request_content_error"]["request"]["logger"]["requests_total"] == 1
        assert pairs["production_container", "request_content_error"]["recorder"]["errors"] == 1
        assert pairs["production_container", "request_content_error"]["logger"]["responses_total"] == 1
        for case in ("response_content_error", "both_content_errors"):
            assert pairs["production_container", case]["recorder"]["errors"] == 0
            assert pairs["production_container", case]["logger"]["responses_total"] == 0
            assert pairs["separate_addons_control", case]["recorder"]["errors"] == 1
            assert pairs["separate_addons_control", case]["logger"]["responses_total"] == 1
        result = {
            "rows": rows,
            "network_attempts": 0,
            "writer_threads_joined": True,
            "boundary": "real AddonManager trigger_event with ProductionAddons.__new__ container and four real children; synthetic completed flows, captured audit enqueue only; no full startup or transport proof",
            "metadata": metadata(source, addonmanager, http),
        }
    result["temporary_stores_removed"] = not Path(temporary).exists()
    assert result["temporary_stores_removed"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = asyncio.run(run(source_root(args.source)))
    if args.check is not None:
        assert result == json.loads(args.check.read_text()), "source dispatch fixture changed"
        print("8 actual source dispatch controls checked", file=sys.stderr)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(encoded)
    elif args.check is None:
        sys.stdout.write(encoded)


if __name__ == "__main__":
    main()
