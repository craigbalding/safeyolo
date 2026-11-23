"""Prepare or run the finite installed Claude Factory witnesses.

Run with the repository's frozen Python environment on the owned Linux or
macOS host. ROOT must contain the installed candidate, an active proxy, pinned
NATS and a compatible prepared guest. Preparation starts no guest or model.
Before the run phase, provision each stopped role's own client and supported
login/provider through the existing host interfaces. No credentials are copied.
Use readback --direction-sequence N to inspect an accepted direction without
repeating preparation, sending, native Work or a model turn.
Use pending-work only on the retained stopped witness to interrupt one new
claimed Work and resume it. Inspect any failed attempt before running it again.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path


def readback_direction(repository, root, contract, sequence):
    """Reuse the maintained envelope checks without invoking the installed journey."""
    sys.path.insert(0, str(repository))
    # Match pytest's conftest import path when reading without the test runner.
    sys.path.insert(0, str(repository / "tests/reference"))
    from tests.proxy_contracts.test_native_factory_cli import installed_claude_direction

    agent = next(role["agent"] for role in contract["roles"].values() if role.get("harness") == "claude")
    identity = tomllib.loads((root / "policy.toml").read_text())["agents"][agent]["agent_id"]
    direction = installed_claude_direction(root, agent, identity, sequence)
    print(json.dumps({"room": f"{agent}-agent", "direction": direction,
                      "scope": "retained direction only; installed Work/model outcome unverified"}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="separately owned installed host root")
    parser.add_argument("fixture", choices=("one-role", "mixed"))
    parser.add_argument("phase", choices=("prepare", "run", "readback", "pending-work"))
    parser.add_argument("--direction-sequence", type=int,
                        help="recover this accepted direction without setup, sending or model execution")
    arguments = parser.parse_args()
    if (arguments.phase == "readback") != (arguments.direction_sequence is not None):
        parser.error("readback requires --direction-sequence; other phases do not accept it")
    root = arguments.root.resolve(strict=True)
    fixtures = Path(__file__).resolve().parent
    repository = fixtures.parents[3]
    directory = root / "factory-proof" / arguments.fixture
    source = directory / (arguments.fixture + ".toml")
    contract = tomllib.loads((fixtures / source.name).read_text())
    workspaces = {role: str(directory / "workspaces" / role) for role in contract["roles"]}
    if arguments.phase == "readback":
        readback_direction(repository, root, contract, arguments.direction_sequence)
        return
    if arguments.phase == "prepare":
        directory.mkdir(parents=True, exist_ok=True)
        for workspace in workspaces.values():
            Path(workspace).mkdir(parents=True, exist_ok=True)
        for name in (source.name, "role.md"):
            destination = directory / name
            if destination.exists():
                assert destination.read_bytes() == (fixtures / name).read_bytes(), destination
            else:
                destination.write_bytes((fixtures / name).read_bytes())
        command = [str(root / "bin/safeyolo"), "--root", str(root), "factory"]
        subprocess.run([*command, "check", str(source)], check=True, timeout=30)
        policy = (root / "policy.toml").read_bytes()
        approved = root / "factories" / contract["name"] / "approved"
        assert not approved.exists(), "inspect retained preparation before repeating this first phase"
        preview_command = [*command, "setup", str(source), "--preview", "--yes"]
        for role, workspace in workspaces.items():
            preview_command += ["--workspace", f"{role}={workspace}"]
        preview = subprocess.run(preview_command, capture_output=True, text=True, check=True, timeout=60)
        (directory / "preview.json").write_text(preview.stdout)
        assert json.loads(preview.stdout)["approved"] is False
        assert not approved.exists() and (root / "policy.toml").read_bytes() == policy
    else:
        assert source.is_file(), "run preparation before provisioning role-local authentication"
    environment = dict(os.environ, SAFEYOLO_FACTORY_ACCEPTANCE_ROOT=str(root),
                       SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE=str(source),
                       SAFEYOLO_FACTORY_ACCEPTANCE_NAME=contract["name"],
                       SAFEYOLO_FACTORY_ACCEPTANCE_WORKSPACES=json.dumps(workspaces))
    test = {"prepare": "test_factory_setup_interruption_preserves_prepared_roles",
            "run": "test_factory_run_executes_staged_worker_commands",
            "pending-work": "test_factory_pending_claude_work_survives_restart"}[arguments.phase]
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-s",
                    f"tests/proxy_contracts/test_native_factory_cli.py::{test}"],
                   cwd=repository, env=environment, check=True)
    if arguments.phase == "prepare":
        policy = tomllib.loads((root / "policy.toml").read_text())["agents"]
        snapshot = (root / "factories" / contract["name"] / "approved").read_text().strip()
        for role, declaration in contract["roles"].items():
            agent = declaration["agent"]
            home = root / "agents" / agent / "home"
            staged = json.loads((home / ".safeyolo/coord-supervisor.json").read_text())
            assert policy[agent]["folder"] == workspaces[role]
            assert staged["agent_name"] == agent and staged["harness"] == declaration["harness"]
            assert staged["factory"]["snapshot_id"] == snapshot and staged["factory"]["role"] == role
            assert staged["native_work"] is True
            assert os.access(home / ".safeyolo-interactive-command", os.X_OK)
            print(json.dumps({"role": role, "agent": agent, "harness": staged["harness"],
                              "home": str(home), "workspace": workspaces[role], "snapshot": snapshot,
                              "authentication": "unverified; provision this role before the run phase"}))


if __name__ == "__main__":
    main()
