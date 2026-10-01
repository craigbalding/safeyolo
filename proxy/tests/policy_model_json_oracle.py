"""Actual source model/hash oracle, restricted to synthetic local fixture inputs."""

import asyncio
import json
import logging
import os
import socket
import struct
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from pydantic_core import to_json

from pdp.client import LocalPolicyClient, PolicyClientConfig
from safeyolo.policy.loader import PolicyLoader


def main():
    logging.disable(logging.CRITICAL)
    request = json.load(sys.stdin)
    attempts = {"network": 0, "mint": 0}

    def reject_network(*_args, **_kwargs):
        attempts["network"] += 1
        raise AssertionError("model oracle cannot contact peers")

    def reject_mint():
        attempts["mint"] += 1
        raise AssertionError("model oracle cannot issue credentials")

    rows = []
    with tempfile.TemporaryDirectory(prefix="model-json-oracle-") as directory, ExitStack() as stack:
        root = Path(directory)
        stack.enter_context(patch.dict(os.environ, {"SAFEYOLO_DATA_DIR": directory}))
        stack.enter_context(patch.object(PolicyLoader, "start_watcher"))
        stack.enter_context(patch("safeyolo.policy.loader.write_event"))
        stack.enter_context(patch("safeyolo.policy.compiler.mint_gateway_token", side_effect=reject_mint))
        stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=reject_network))
        stack.enter_context(patch.object(socket, "create_connection", side_effect=reject_network))
        stack.enter_context(patch.object(asyncio, "open_connection", side_effect=reject_network))
        for index, row in enumerate(request["rows"]):
            case_root = root / str(index)
            case_root.mkdir()
            source = row["source"]
            path = case_root / ("policy." + row["format"])
            if source is not None:
                path.write_text(source)
            client = LocalPolicyClient(PolicyClientConfig(baseline_path=path if source is not None else None))
            try:
                loader = client._pdp._engine._loader
                if source is not None:
                    assert loader._load_baseline()
                if row["task"] is not None:
                    task_path = case_root / ("task." + row["task_format"])
                    task_path.write_text(row["task"])
                    assert loader.load_task_policy(task_path)
                result = {"name": row["name"]}
                for label, model in (
                    ("baseline", client._pdp._engine.get_baseline()),
                    ("task", client._pdp._engine.get_task_policy()),
                ):
                    try:
                        result[label + "_hex"] = model.model_dump_json().encode().hex() if model is not None else ""
                        result[label + "_error"] = None
                    except Exception as error:
                        result[label + "_error"] = type(error).__name__
                try:
                    result["policy_hash"] = client._pdp.policy_hash
                    result["hash_error"] = None
                except Exception as error:
                    result["hash_error"] = type(error).__name__
                rows.append(result)
            finally:
                client.shutdown()
    assert attempts == {"network": 0, "mint": 0}
    numbers = [to_json(struct.unpack(">d", bytes.fromhex(bits))[0]).decode() for bits in request["bits"]]
    json.dump({"rows": rows, "numbers": numbers, "attempts": attempts}, sys.stdout)


if __name__ == "__main__":
    main()
