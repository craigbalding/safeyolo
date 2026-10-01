"""Actual local PDP reset against keys created by network/credential checks.

No listener, tokens or network. Temporary policy state, watcher startup, clock
and audit delivery are controlled; reset/evaluation/reporting run unchanged.
"""

import json
import logging
import pathlib
import sys
import tempfile
from contextlib import ExitStack
from unittest.mock import patch

from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.policy import engine as engine_module
from safeyolo.policy import loader as loader_module


def run(fixture):
    rows = []
    with tempfile.TemporaryDirectory(prefix="budget-reset-oracle-") as directory, ExitStack() as stack:
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher", return_value=None))
        for module in (loader_module, engine_module):
            stack.enter_context(patch.object(module, "write_event", return_value=None))
        for target in ("socket.getaddrinfo", "socket.create_connection", "socket.socket.connect"):
            stack.enter_context(patch(target, side_effect=AssertionError("No network in reset oracle")))
        stack.enter_context(patch("safeyolo.policy.budget_tracker.time.time", return_value=1000.0))
        path = pathlib.Path(directory) / "policy.json"
        path.write_text(json.dumps(fixture["policy"]))
        client = LocalPolicyClient(PolicyClientConfig(baseline_path=path))
        stack.callback(client.shutdown)
        engine = client._pdp._engine
        for case in fixture["cases"]:
            client.reset_budgets()
            for host, method, port in [("zeta.invalid", "GET", None), ("alpha.invalid", "GET", None),
                                       ("zeta.invalid", "CONNECT", 8443)]:
                assert engine.evaluate_request(host, method=method, port=port).effect == "allow"
            assert engine.evaluate_credential("fixture", "credential.invalid").effect == "allow"
            before = engine._evaluations
            resource = json.loads(case["resource_json"]) if "resource_json" in case else case.get("resource")
            result = client.reset_budgets(resource)
            assert engine._evaluations == before
            if case.get("recharge"):
                assert engine.evaluate_request("zeta.invalid").effect == "allow"
            rows.append({"name": case["name"], "result": result,
                         "keys": engine._budget_tracker.get_stats()["keys"],
                         "report": engine.get_budget_stats()})
    return rows


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    json.dump(run(json.load(sys.stdin)), sys.stdout)
