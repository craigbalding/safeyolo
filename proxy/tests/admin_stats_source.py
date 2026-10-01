"""Actual operator stats aggregation over selected, owned in-memory addons.

No server, policy watcher, persistent store or production addon chain is started.
Actual discovery, get_stats methods, canonical serialization and JSON response
rendering run; only their external inputs and final audit queue are supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import os
import socket
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

NOW = 1000.0
ROOT = Path(os.environ.get("SAFEYOLO_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
CASES = (
    "discovery_order", "network_disabled", "lazy_context_unloaded",
    "lazy_context_cached", "declaration_expiry", "addon_exception_continues",
    "circuit_half_open", "circuit_submission_error", "circuit_later_domain_error",
    "policy_wrapper_error", "typed_nan_real_policy",
)


def policy_client():
    """Run the real stats chain with only the reached in-memory fields installed."""
    from pdp.client import LocalPolicyClient
    from pdp.core import PDPCore
    from safeyolo.policy.budget_tracker import BudgetState, GCRABudgetTracker
    from safeyolo.policy.engine import PolicyEngine
    from safeyolo.policy.models import UnifiedPolicy

    baseline = UnifiedPolicy.model_validate({
        "permissions": [{"action": "network:request", "resource": "*", "effect": "allow"}],
        "required": ["network_guard"],
    })
    engine = PolicyEngine.__new__(PolicyEngine)
    engine._loader = SimpleNamespace(
        baseline=baseline, task_policy=None,
        baseline_path=Path("/owned/policy.yaml"), task_policy_path=None,
    )
    engine._evaluations = 17
    engine._budget_tracker = GCRABudgetTracker()
    engine._budget_tracker._budgets = {
        "network:request:first.invalid": BudgetState(),
        "network:connect:second.invalid": BudgetState(),
    }
    core = PDPCore.__new__(PDPCore)
    core._engine = engine
    core._task_policies = {"owned-task": {}}
    client = LocalPolicyClient.__new__(LocalPolicyClient)
    client._pdp = core
    return client


def observe(case, modules):
    """One exact aggregate call; observers wrap rather than replace get_stats."""
    (ctx, pdp, admin, network, circuits, context, recording, logger,
     policy, config_cache, flow_writer, audit_writer) = modules
    network_addon = network.NetworkGuard()
    network_addon.stats.checks = 7
    network_addon.stats.allowed = 3
    network_addon.stats.blocked = 2
    network_addon.stats.warned = 2
    network_addon.rate_limited = 1
    circuit = circuits.CircuitBreaker()
    circuit.use_exponential_backoff = False
    test_context = context.TestContext()
    recorder = recording.FlowRecorder()
    request_logger = logger.RequestLogger()
    configurator = policy.PolicyClientConfigurator()
    lookup = {
        "policy-engine": configurator,
        "network-guard": network_addon,
        "circuit-breaker": circuit,
        "test-context": test_context,
        "flow-recorder": recorder,
        "request-logger": request_logger,
    }
    sensor = {"policy_hash": "owned-new-policy", "addons": {
        "test_context": {"target_hosts": ["new.invalid"], "declared_ttl_max": 3600},
        "circuit_breaker": {"failure_threshold": 99},
    }}
    if case == "discovery_order":
        replacement = network.NetworkGuard()
        replacement.stats.checks = 42
        lookup["network-alias"] = replacement
        lookup["nameless"] = SimpleNamespace(get_stats=lambda: {"ignored": True})
        lookup["noncallable"] = SimpleNamespace(name="not-stats", get_stats=42)
    if case in {"lazy_context_cached", "declaration_expiry"}:
        test_context._target_hosts = ["old.invalid", "other.invalid"]
        test_context._last_policy_hash = "owned-old-policy"
    if case == "addon_exception_continues":
        test_context._target_hosts = 42
    if case.startswith("circuit_"):
        circuit._state.set("first.invalid", {"state": "open", "failure_count": 3, "opened_at": 0})
        circuit._state.set("second.invalid", {
            "state": "invalid" if case == "circuit_later_domain_error" else "open",
            "failure_count": 4,
            "opened_at": 980 if case == "circuit_half_open" else 0,
        })
        circuit._state.set("third.invalid", {"state": "open", "failure_count": 5, "opened_at": 0})
    if case == "typed_nan_real_policy":
        circuit.failure_threshold = float("nan")
        circuit._state.set("typed.invalid", {"state": "closed", "failure_count": float("nan")})
        request_logger.requests_total = 2**80
    client = policy_client()
    if case == "policy_wrapper_error":
        client._pdp._engine._loader = None
    registry = SimpleNamespace(lookup=lookup, get=lookup.get)
    handler = admin.AdminRequestHandler.__new__(admin.AdminRequestHandler)
    handler.wfile = io.BytesIO()
    statuses, headers, timeline, attempts, submitted, config_reads = [], [], [], [], [], []
    handler.send_response = statuses.append
    handler.send_header = lambda name, value: headers.append([name, value])
    handler.end_headers = lambda: timeline.append("response_headers")

    def put_event(event):
        value = {key: item for key, item in event.items() if key != "ts"}
        attempts.append(value)
        timeline.append("audit:" + event["event"] + ":" + event.get("host", ""))
        if case == "circuit_submission_error":
            raise RuntimeError("synthetic audit submission failure")
        submitted.append(value)

    def sensor_read():
        config_reads.append(True)
        return sensor

    options = SimpleNamespace(network_guard_enabled=case != "network_disabled",
                              circuit_breaker_enabled=case != "network_disabled")
    with ExitStack() as stack:
        for target, name, kwargs in (
            (ctx, "master", {"new": SimpleNamespace(addons=registry), "create": True}),
            (ctx, "options", {"new": options, "create": True}),
            (config_cache, "get_or_raise", {"side_effect": sensor_read}),
            (config_cache, "addon_section", {"return_value": sensor["addons"]["test_context"]}),
            (flow_writer, "get_writer", {"return_value": None}),
            (audit_writer, "put_event", {"side_effect": put_event}),
            (pdp, "is_policy_client_configured", {"return_value": case in {"policy_wrapper_error", "typed_nan_real_policy"}}),
            (pdp, "get_policy_client", {"return_value": client}),
            (circuits.time, "time", {"return_value": NOW}),
            (context.time, "monotonic", {"return_value": NOW}),
            (admin.AdminRequestHandler, "addons_with_stats", {"new": {}}),
            (admin.AdminRequestHandler, "_addons_obj", {"new": None}),
            (admin.AdminRequestHandler, "credential_guard", {"new": None}),
        ):
            stack.enter_context(patch.object(target, name, **kwargs))
        if case == "declaration_expiry":
            with patch.object(context.time, "monotonic", return_value=900.0):
                for name, ttl in (("expired", 99), ("at_boundary", 100), ("live", 101)):
                    test_context.set_declaration(name, "alice", {"run": "owned", "test": name}, ttl)
        before_declarations = list(test_context._declarations)
        admin.AdminAPI.__new__(admin.AdminAPI)._discover_addons()
        discovered = list(handler.addons_with_stats)
        for name, addon in handler.addons_with_stats.items():
            real = addon.get_stats

            def observed(*, name=name, real=real):
                timeline.append("get:" + name)
                try:
                    value = real()
                except Exception as error:
                    timeline.append("error:" + name + ":" + type(error).__name__)
                    raise
                timeline.append("done:" + name)
                return value

            stack.enter_context(patch.object(addon, "get_stats", side_effect=observed))
        handler._handle_get_stats()
        body = handler.wfile.getvalue().decode()
        value = json.loads(body)
        row = {
            "name": case, "discovered": discovered,
            "field_order": list(value), "status": statuses, "headers": headers,
            "body_text": body, "timeline": timeline,
            "attempted": attempts, "submitted": submitted,
            "config_reads": len(config_reads),
            "context_cached_hash": test_context._last_policy_hash,
            "declarations_before": before_declarations,
            "declarations_after": list(test_context._declarations),
            "circuit_states_json": json.dumps({domain: circuit._state.get(domain)
                for domain in circuit._state.all_domains()}),
            "circuit_half_opens": circuit.half_opens_total,
        }
        assert statuses == [200]
        assert headers == [["Content-Type", "application/json"], ["Content-Length", str(len(body.encode()))]]
        assert row["config_reads"] == 0
        if case == "typed_nan_real_policy":
            row["typed_fields"] = {
                "threshold_type": type(value["circuit-breaker"]["failure_threshold"]).__name__,
                "request_count_type": type(value["request-logger"]["requests_total"]).__name__,
            }
        return row


def run():
    logging.disable(logging.CRITICAL)
    sys.path[:0] = [str(ROOT / "cli/src"), str(ROOT)]
    with tempfile.TemporaryDirectory(prefix="admin-stats-source-") as directory:
        os.environ["SAFEYOLO_LOG_PATH"] = directory + "/unused-audit.jsonl"
        os.environ["MITMPROXY_LOG_PATH"] = directory + "/unused-diagnostic.log"
        os.environ["SAFEYOLO_DATA_DIR"] = directory
        from mitmproxy import ctx

        import pdp
        from safeyolo.core import audit_writer, config_cache, flow_writer
        from safeyolo.mitm_addons import (
            ADDON_CHAIN,
            admin_api,
            circuit_breaker,
            flow_recorder,
            network_guard,
            policy_engine,
            request_logger,
            test_context,
        )

        network_attempts = []

        def no_network(*_args, **_kwargs):
            network_attempts.append(True)
            raise AssertionError("no network is allowed in the selected stats control")

        modules = (ctx, pdp, admin_api, network_guard, circuit_breaker, test_context,
                   flow_recorder, request_logger, policy_engine, config_cache,
                   flow_writer, audit_writer)
        with (patch.object(socket, "getaddrinfo", side_effect=no_network),
              patch.object(socket, "create_connection", side_effect=no_network)):
            rows = [observe(case, modules) for case in CASES]
        assert not network_attempts
        paths = [
            "cli/src/safeyolo/mitm_addons/__init__.py",
            "cli/src/safeyolo/mitm_addons/admin_api.py",
            "cli/src/safeyolo/mitm_addons/network_guard.py",
            "cli/src/safeyolo/mitm_addons/circuit_breaker.py",
            "cli/src/safeyolo/mitm_addons/test_context.py",
            "cli/src/safeyolo/mitm_addons/policy_engine.py",
            "cli/src/safeyolo/mitm_addons/flow_recorder.py",
            "cli/src/safeyolo/mitm_addons/request_logger.py",
            "cli/src/safeyolo/policy/engine.py", "cli/src/safeyolo/policy/budget_tracker.py",
            "cli/src/safeyolo/policy/models.py", "cli/src/safeyolo/core/base.py",
            "cli/src/safeyolo/core/audit_schema.py", "cli/src/safeyolo/core/utils.py",
            "pdp/client.py", "pdp/core.py",
        ]
        selected = {"policy_engine.py", "network_guard.py", "circuit_breaker.py",
                    "test_context.py", "flow_recorder.py", "request_logger.py"}
        return {"now": NOW, "selected_chain_files": [name for name in ADDON_CHAIN if name in selected],
                "rows": rows, "source_sha256": {
            path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    if args.check:
        assert result == json.loads(args.check.read_text()), "source operator stats changed"
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"source_stats_rows": len(result["rows"])}))
