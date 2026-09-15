"""Actual PolicyEngine reporting after a real charge and loader replacement."""

import copy
import json
import logging
import pathlib
import sys
import tempfile
from contextlib import ExitStack
from unittest.mock import patch

from safeyolo.policy import engine as engine_module
from safeyolo.policy import loader as loader_module
from safeyolo.policy.engine import PolicyEngine


def run(cases):
    outputs = []
    with ExitStack() as stack:
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher", return_value=None))
        stack.enter_context(patch.object(loader_module, "write_event", return_value=None))
        stack.enter_context(patch.object(engine_module, "write_event", return_value=None))
        for case in cases:
            with tempfile.TemporaryDirectory(prefix="native-budget-oracle-") as directory:
                path = pathlib.Path(directory) / "policy.json"
                path.write_text(json.dumps(case["initial"]))
                engine = PolicyEngine(baseline_path=path)
                try:
                    with patch("safeyolo.policy.budget_tracker.time.time", return_value=1000):
                        decision = engine.evaluate_request(case["host"], method=case["method"], port=case["port"])
                    assert decision.effect == "allow", case["name"]
                    path.write_text(json.dumps(case["reporting"]))
                    assert engine._loader.reload(), case["name"]
                    before = copy.deepcopy(engine._budget_tracker._budgets)
                    evaluations = engine._evaluations
                    with patch("safeyolo.policy.budget_tracker.time.time", return_value=case["now_ms"] / 1000):
                        try:
                            result = {"body": engine.get_budget_stats()}
                        except (OverflowError, ValueError) as error:
                            result = {"error": type(error).__name__}
                    assert engine._budget_tracker._budgets == before
                    assert engine._evaluations == evaluations
                    outputs.append(result)
                finally:
                    engine.done()
    return outputs


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    json.dump(run(json.load(sys.stdin)), sys.stdout)
