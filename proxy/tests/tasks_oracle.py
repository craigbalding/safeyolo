"""Actual task registration schema, using synthetic in-memory source clients."""

import asyncio
import json
import logging
import os
import socket
import sys
import tempfile
from contextlib import ExitStack
from unittest.mock import patch

from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.policy.loader import PolicyLoader


def main():
    logging.disable(logging.CRITICAL)
    request = json.load(sys.stdin)
    attempts = {"network": 0, "mint": 0}

    def reject_network(*_args, **_kwargs):
        attempts["network"] += 1
        raise AssertionError("task oracle cannot contact peers")

    def reject_mint():
        attempts["mint"] += 1
        raise AssertionError("task oracle cannot issue credentials")

    rows = []
    with tempfile.TemporaryDirectory(prefix="tasks-oracle-") as directory, ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": directory}))
        stack.enter_context(patch.object(PolicyLoader, "start_watcher"))
        stack.enter_context(patch("safeyolo.policy.loader.write_event"))
        stack.enter_context(patch("safeyolo.policy.compiler.mint_gateway_token", side_effect=reject_mint))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=reject_network))
        stack.enter_context(patch.object(socket, "create_connection", side_effect=reject_network))
        stack.enter_context(patch.object(asyncio, "open_connection", side_effect=reject_network))
        for case in request["cases"]:
            raw = json.loads(case["document"])
            client = LocalPolicyClient(PolicyClientConfig())
            try:
                before_hash = client._pdp.policy_hash
                result = client.upsert_task_policy(case["task_id"], raw)
                retained = client.get_task_policy(case["task_id"])
                rows.append(
                    {
                        "name": case["name"],
                        "result": result,
                        "retained": retained,
                        "count": len(client._pdp._task_policies),
                        "active_task": client._pdp._engine.get_task_policy() is not None,
                        "hash_unchanged": client._pdp.policy_hash == before_hash,
                    }
                )
            finally:
                client.shutdown()
    assert attempts == {"network": 0, "mint": 0}
    json.dump({"rows": rows, "attempts": attempts}, sys.stdout)


if __name__ == "__main__":
    main()
