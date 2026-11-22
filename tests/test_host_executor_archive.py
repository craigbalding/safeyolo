"""The standalone archive carries its usable guide, definitions and agent client.

The controlled producer here verifies archive contents, not target execution.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_standalone_archive_ships_the_exact_workflow_inputs(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "scripts"))
    spec = importlib.util.spec_from_file_location("host_executor_builder", REPO / "scripts/build_host_executor.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    binary = tmp_path / "safeyolo-host-executor"
    binary.write_bytes(b"controlled native producer bytes")
    revision = "1" * 40
    monkeypatch.setattr(builder, "commit", lambda: revision)
    monkeypatch.setattr(builder, "build_executor", lambda *_args: binary)
    monkeypatch.setattr(builder, "output", lambda *args: "host: fixture-target" if args[0] == "rustc"
                        else f"commit={revision} profile=production target=fixture-target")
    archive = tmp_path / "executor.zip"
    monkeypatch.setattr(sys, "argv", ["build_host_executor.py", "--output", str(archive)])
    builder.main()
    with zipfile.ZipFile(archive) as result:
        assert result.read("HOST-OPERATIONS.md") == (REPO / "docs/host-operations.md").read_bytes()
        assert result.read("examples/windows-starter.json") == (REPO / "host-executor/examples/windows-starter.json").read_bytes()
        assert result.read("agent/host-operation.py") == (REPO / "cli/src/safeyolo/agent_context/skills/safeyolo/scripts/host-operation.py").read_bytes()
        metadata = json.loads(result.read("host-executor.json"))
        assert metadata["git_sha"] == revision
        assert metadata["binary_sha256"] == hashlib.sha256(result.read(binary.name)).hexdigest()
