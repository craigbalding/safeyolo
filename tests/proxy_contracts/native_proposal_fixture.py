"""Real retained Coord inputs for the completion/proposal command consumers.

Reuse the existing native host/UDS boundary and pinned NATS owner. No guest,
model or package build is needed. The fixture runs identified native binaries
outside the checkout; Python drives only the fixture. Existing readiness and
command deadlines are 15 seconds. Keep large artifacts on disk-backed storage.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.proxy_contracts.harness import child_process, wait_ready
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN, DENY, NativeInstance

REPO = Path(__file__).resolve().parents[2]
ROOM = "proposal-proof"


class ProposalInstance(NativeInstance):
    def command(self, *args, agent=False, check=True):
        if agent:
            command = [str(self.root / "bin/safeyolo-coord"), *args]
            environment = dict(self.environment, SAFEYOLO_COORD_SOCKET=self.paths["relay"],
                               SAFEYOLO_COORD_TOKEN_PATH=str(self.root / "data/agent_token"),
                               SAFEYOLO_COORD_DATA_DIR=str(self.root / "data/coord"))
        else:
            command = [str(self.root / "bin/safeyolo"), "--root", str(self.root), "coord", *args]
            environment = self.environment
        result = subprocess.run(command, cwd=self.root.parent, env=environment, text=True,
                                capture_output=True, timeout=15)
        if check:
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout)
        return result

    def send(self, body, sender="lens", **extra):
        return self.agent_api(sender, f"/api/coord/rooms/{ROOM}/send", method="POST",
                              body={"body": body, "notify": "none", **extra})["envelope"]

    def operator(self, body):
        return self.command("send", ROOM, body)["envelope"]

    def observe(self, envelope, observation, coverage=None, *, agent=True, check=True):
        verified = self.root.parent / f"verified-{envelope['sequence']}.json"
        verified.write_text(json.dumps({"observation": observation, "coverage": coverage}))
        return self.command("proposals", "observe", ROOM, str(envelope["sequence"]),
                            "--verified", str(verified), agent=agent, check=check)


@pytest.fixture
def native_proposals(tmp_path):
    artifacts = Path(os.environ.get("SAFEYOLO_NATIVE_ARTIFACTS", REPO / "proxy/target/debug"))
    proxy = Path(os.environ.get("SAFEYOLO_TEST_PROXY", artifacts / "safeyolo-proxy"))
    root = tmp_path / "native"
    environment = dict(os.environ, SAFEYOLO_NATS_TEST_INSTANCE=f"proposal-{tmp_path.name}",
                       SAFEYOLO_HOME=str(root), SAFEYOLO_CONFIG_DIR=str(root))
    initialized = subprocess.run([str(artifacts / "safeyolo"), "--root", str(root), "init"],
                                 cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=15)
    assert initialized.returncode == 0, initialized.stderr
    (root / "bin").mkdir()
    for name in ("safeyolo", "safeyolo-coord"):
        (root / "bin" / name).symlink_to(artifacts / name)
    # Verify which executables run. A retained unchanged server can be selected
    # separately from the changed CLI; this fixture does not claim package proof.
    for path in (root / "bin/safeyolo", root / "bin/safeyolo-coord", proxy):
        version = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=15)
        assert version.returncode == 0 and "commit=" in version.stdout, version.stderr
    environment["PATH"] = str(root / "bin")
    environment.pop("PYTHONPATH", None)
    (root / "policy.toml").write_text(DENY + '\n[agents.relay]\nagent_id="ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
                                    '[agents.lens]\nagent_id="ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"\n')
    (root / "data/agent_token").write_text(AGENT_TOKEN)
    with tempfile.TemporaryDirectory(prefix="sy-proposal-", dir="/tmp") as socket_parent:
        paths = {name: str(Path(socket_parent) / f"{name}.sock") for name in ("relay", "lens")}
        source = 'admin_port=0\nagent_api_enabled=true\nflow_store_enabled=false\n'
        for index, (name, path) in enumerate(paths.items(), 2):
            source += (f'[[listeners]]\nagent_id={json.dumps(name)}\nsocket_path={json.dumps(path)}\n'
                       f'source_id="10.0.0.{index}"\n')
        (root / "config.toml").write_text(source)
        with child_process([str(proxy), "--config", str(root / "config.toml")], root, environment) as process:
            ready = root / "data/ready.json"
            wait_ready(process, [ready, *map(Path, paths.values())], root / "process.log",
                       readiness_file=ready, expected_backend="rust-m2")
            instance = ProposalInstance(root, process, paths, environment)
            binary = os.environ.get("SAFEYOLO_COORD_NATS_BINARY")
            assert binary, "select the existing pinned NATS binary with SAFEYOLO_COORD_NATS_BINARY"
            instance.nats = instance.command("start", "--binary", binary)
            try:
                instance.command("room", "create", ROOM)
                for name in paths:
                    instance.command("grant", ROOM, name)
                yield instance
            finally:
                stopped = instance.command("stop")
                assert stopped["state"] == "stopped"
                assert instance.command("status")["state"] == "stopped"
