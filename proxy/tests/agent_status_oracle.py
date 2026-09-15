# ruff: noqa: E402 -- Establish isolated source roots before imports.
"""Actual authenticated status handler with synthetic process-local task writes."""

import asyncio
import hashlib
import json
import logging
import os
import platform
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO), str(REPO / "cli/src")]
from mitmproxy.test import taddons, tflow

from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.mitm_addons import agent_api
from safeyolo.policy import engine as engine_module
from safeyolo.policy import loader as loader_module
from safeyolo.proxy_modes.unix_listener import UnixMode

BASELINE = {"permissions": [{"action": "network:request", "resource": "*", "effect": "budget", "budget": 1}]}
TASK = {"permissions": [{"action": "network:request", "resource": "task.invalid/*", "effect": "deny"}]}
STEPS = [
    {"kind": "status"},
    {"kind": "upsert", "id": "alpha", "policy": {}},
    {"kind": "upsert", "id": "alpha", "policy": TASK},
    {"kind": "upsert", "id": "beta", "policy": {}},
    {"kind": "upsert", "id": "../invalid", "policy": {}},
    {"kind": "upsert", "id": "gamma", "policy": {"permissions": 3}},
    {"kind": "task"},
    {"kind": "lookup"},
    {"kind": "lookup"},
    {"kind": "network"},
    {"kind": "reads"},
    {"kind": "status", "agent": "bob", "path": "/status///?agent=forged&task_id=alpha&host=%ff"},
    {"kind": "status", "auth": "missing"},
    {"kind": "status", "method": "HEAD", "auth": "missing"},
    {"kind": "status", "state": "missing"},
]
ATTEMPTS = []


def reject_network(*_args, **_kwargs):
    ATTEMPTS.append(True)
    raise AssertionError("status facade oracle cannot contact peers or mint credentials")


async def main():
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="agent-status-") as directory, ExitStack() as stack:
        root = Path(directory)
        stack.enter_context(
            patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": directory, "SAFEYOLO_LOG_PATH": str(root / "unused-audit")})
        )
        stack.enter_context(patch.object(loader_module.PolicyLoader, "start_watcher"))
        stack.enter_context(patch("safeyolo.policy.budget_tracker.time.time", return_value=1000.0))
        stack.enter_context(patch("safeyolo.policy.compiler.mint_gateway_token", side_effect=reject_network))
        for name in ["socket.getaddrinfo", "socket.create_connection", "asyncio.open_connection"]:
            stack.enter_context(patch(name, side_effect=reject_network))
        for module in [agent_api, loader_module, engine_module]:
            stack.enter_context(patch.object(module, "write_event"))
        (root / "agent_token").write_text("synthetic-agent-status-fixture")
        baseline = root / "baseline.json"
        baseline.write_text(json.dumps(BASELINE))
        client = LocalPolicyClient(PolicyClientConfig(baseline_path=baseline))
        stack.callback(client.shutdown)
        api = agent_api.AgentAPI()
        output = []

        async def read(path, step=None):
            step = step or {}
            flow = tflow.tflow()
            flow.request.method = step.get("method", "GET")
            flow.request.url = "http://_safeyolo.proxy.internal/"
            flow.request.path = path
            flow.request.headers.clear()
            if step.get("auth") != "missing":
                flow.request.headers["authorization"] = "Bearer synthetic-agent-status-fixture"
            flow.client_conn.proxy_mode = UnixMode.parse(f"unix:/tmp/10.0.0.5_{step.get('agent', 'alice')}/proxy.sock")
            flow.metadata["request_id"] = "req-status-fixture"
            dependency = None if step.get("state") == "missing" else client
            with patch.object(api, "_get_policy_client", return_value=dependency):
                await api.request(flow)
            raw = flow.response.content.decode()
            return {
                "status": flow.response.status_code,
                "body_hex": raw.replace(str(root), "$ROOT").encode().hex(),
                "headers": [
                    [name.decode(), value.decode()]
                    for name, value in flow.response.headers.fields
                    if name.lower() != b"content-length"
                ],
                "handler_owned": flow.metadata.get("safeyolo_agent_api_response") is True,
                "blocked_by": flow.metadata.get("blocked_by"),
            }

        with taddons.context(api):
            for step in STEPS:
                kind = step["kind"]
                if kind == "upsert":
                    client.upsert_task_policy(step["id"], step["policy"])
                elif kind == "task":
                    task = root / "task.json"
                    task.write_text(json.dumps(TASK))
                    assert client._pdp._engine.load_task_policy(task)
                elif kind == "lookup":
                    await read("/lookup?host=allowed.invalid")
                elif kind == "network":
                    assert client._pdp._engine.evaluate_request("allowed.invalid", port=80).effect == "allow"
                elif kind == "reads":
                    for path in ["/config", "/policy", "/budgets", "/health"]:
                        await read(path)
                count = client._pdp._engine.get_stats()["evaluations"]
                response = await read(step.get("path", "/status"), step)
                assert client._pdp._engine.get_stats()["evaluations"] == count
                output.append({"step": step, "response": response, "evaluations": count})
        assert not ATTEMPTS
        result = {
            "source_commit": "838319a1a6a97a5317350e678fda6abc5a44fed1",
            "python": platform.python_version(),
            "source_hashes": {
                name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
                for name in ["cli/src/safeyolo/mitm_addons/agent_api.py", "pdp/core.py", "pdp/client.py"]
            },
            "baseline": BASELINE,
            "task": TASK,
            "rows": output,
            "network_and_mint_attempts": 0,
        }
        if "--emit" in sys.argv:
            print(json.dumps(result))
        else:
            Path(__file__).with_name("agent_status_source.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps({"cases": len(output), "final_evaluations": output[-1]["evaluations"]}))


if __name__ == "__main__":
    asyncio.run(main())
