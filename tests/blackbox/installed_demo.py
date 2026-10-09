#!/usr/bin/env python3
"""Observe native Demo on one owned, prepared Ubuntu/systrap instance.

Python is this external acceptance driver, and may also be the model's app
workload. Native Demo entry, staging, guest control and approval run no Python.
W2 uses a deterministic Codex startup fixture, not a model. --real-agent selects
one stopped Demo guest with its own normal configured Codex authentication for
W1. That path runs only W1, preserves W2 evidence, and asks the human for the actual approval decision. The driver stops only its created
guests and Demo's selected runtime. Use an instance allocated for this witness;
its stopped test guest homes remain until the owner removes that disposable
instance through the existing harness teardown.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import select
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import tomllib
import uuid
from pathlib import Path


class DemoProcess:
    def __init__(self, command: list[str]):
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        self.output = ""

    def send(self, value: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(value.encode())
        self.process.stdin.flush()

    def until(self, text: str, timeout: float = 150) -> str:
        assert self.process.stdout is not None
        deadline = time.monotonic() + timeout
        while text not in self.output:
            remaining = deadline - time.monotonic()
            assert remaining > 0, f"Demo did not reach {text!r}: {self.output[-1500:]}"
            readable, _, _ = select.select([self.process.stdout], [], [], min(remaining, 1))
            if readable:
                chunk = os.read(self.process.stdout.fileno(), 4096)
                assert chunk, f"Demo ended before {text!r}: {self.output[-1500:]}"
                self.output = (self.output + chunk.decode(errors="replace"))[-65536:]
        return self.output

    def finish(self) -> int:
        assert self.process.stdin is not None
        self.process.stdin.close()
        self.process.stdin = None
        output, _ = self.process.communicate(timeout=45)
        self.output = (self.output + output.decode(errors="replace"))[-65536:]
        return self.process.returncode

    def cancel(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            self.finish()


def run(args: argparse.Namespace) -> None:
    root = args.config_dir.resolve(strict=True)
    executable = root / "bin/safeyolo"
    command = [str(executable), "--root", str(root)]
    if root == (Path.home() / ".safeyolo").resolve():
        # Exercise the ordinary command/default-root path after installation.
        for key in ("SAFEYOLO_CONFIG_DIR", "SAFEYOLO_HOME", "SAFEYOLO_NATIVE_CONFIG_PATH"):
            assert not os.environ.get(key), f"default-root witness must omit {key}"
        discovered = shutil.which("safeyolo")
        assert discovered and Path(discovered).resolve() == executable.resolve(), "normal PATH must discover this installation"
        command = [discovered]

    def cli(*arguments: str, timeout: float = 150) -> str:
        result = subprocess.run(command + list(arguments), capture_output=True, text=True, timeout=timeout)
        assert result.returncode == 0, result.stderr[-1500:]
        return result.stdout

    def policy() -> dict:
        return tomllib.loads((root / "policy.toml").read_text())

    def stopped(name: str) -> None:
        assert json.loads(cli("agent", "status", name))["runtime_state"] == "stopped"

    def closed(port: int) -> None:
        with socket.socket() as stream:
            stream.settimeout(2)
            assert stream.connect_ex(("127.0.0.1", port)) != 0, "Demo fixture listener survived"

    identity = cli("--version").strip()
    assert f"commit={args.commit} " in identity, "installed native CLI is not this candidate"
    assert f"commit={args.commit} " in subprocess.check_output([str(root / "bin/safeyolo-proxy"), "--version"], text=True)
    assert f"commit={args.commit} " in (root / "assets/guest/safeyolo-guest.version").read_text()
    before = json.loads(cli("status"))
    owned: list[str] = []
    result = {"commit": args.commit, "native_cli": identity, "real_model": False}
    with tempfile.TemporaryDirectory(prefix="demo-proof-", dir=root / "data") as temporary:
        directory = Path(temporary)
        peer_name = f"demo-peer-{uuid.uuid4().hex[:12]}"
        peer_workspace = directory / "peer"
        peer_workspace.mkdir()
        (peer_workspace / "marker").write_text("independent agent")
        (peer_workspace / "marker").chmod(0o640)
        cli("agent", "create", peer_name, "--workspace", str(peer_workspace), "--memory", "512",
            "--launcher", "supervisor", "--command", "echo $$ > /workspace/process; exec sleep 600")
        owned.append(peer_name)
        active: DemoProcess | None = None
        try:
            cli("agent", "start", peer_name)
            peer_policy = policy()["agents"][peer_name]

            def peer_survives() -> None:
                assert policy()["agents"][peer_name] == peer_policy
                assert (peer_workspace / "marker").read_text() == "independent agent"
                assert (peer_workspace / "marker").stat().st_mode & 0o777 == 0o640
                cli("agent", "shell", peer_name, "-c", "kill -0 $(cat /workspace/process)")
                assert json.loads(cli("agent", "status", peer_name))["runtime_state"] == "running"

            def start(workspace: Path, extra: list[str] | None = None, *, select_task: bool = False) -> tuple[DemoProcess, str, int, Path]:
                nonlocal active
                selection = [] if select_task else ["--task", "tiny-web-app"]
                process = DemoProcess(command + ["demo", *selection, "--workspace", str(workspace)] + (extra or []))
                active = process
                if select_task:
                    process.until("Choose 1 for the tiny web-app task")
                    process.send("1\n")
                output = process.until("Runtime is ready.")
                match = re.search(r"Demo guest: ([a-z0-9-]+) \((ag-[a-f0-9]+)\)", output)
                assert match is not None
                name, agent_id = match.groups()
                assert policy()["agents"][name]["agent_id"] == agent_id
                task = (workspace / "TASK.md").read_text()
                fixture = re.search(r"http://127\.0\.0\.1:(\d+)/demo/([a-f0-9]+)\.json", task)
                assert fixture is not None
                port, marker = fixture.groups()
                record = root / "logs" / f"demo-{marker}-requests.jsonl"
                assert record.read_text() == "", "fixture delivered before the task/approval"
                return process, name, int(port), record

            if not args.real_agent:
                # W2: actual native workspace and runtime creation, then cancellation.
                cancelled_workspace = directory / "cancel"
                active, name, port, record = start(cancelled_workspace)
                active.send("cancel\n")
                assert active.finish() != 0 and "cancelled after runtime creation" in active.output
                assert name not in policy()["agents"]
                assert not cancelled_workspace.exists()
                assert record.read_text() == ""
                closed(port)
                peer_survives()
                result["cancel_after_runtime"] = {"owned_runtime_removed": True, "zero_deliveries": True, "peer_unchanged": True}

                # W2: controlled Codex executable succeeds readiness/auth, then fails
                # its real guest exec after setup. No model is invoked for this case.
                fixture_name = f"demo-startup-{uuid.uuid4().hex[:12]}"
                prior = directory / "prior"
                prior.mkdir()
                cli("agent", "create", fixture_name, "--workspace", str(prior))
                owned.append(fixture_name)
                home = root / "agents" / fixture_name / "home"
                binary = home / ".local/bin/codex"
                binary.parent.mkdir(parents=True)
                binary.write_text(
                    "#!/bin/sh\n"
                    'for arg in "$@"; do\n'
                    '  case "$arg" in --version) echo deterministic-codex-startup-fixture; exit 0;;\n'
                    '    login) exit 0;; exec) echo reached >/workspace/harness-started; exit 41;; esac\n'
                    "done\nexit 42\n"
                )
                binary.chmod(0o755)
                auth = home / ".codex"
                auth.mkdir(mode=0o700)
                (auth / "auth.json").write_text("synthetic deterministic authentication fixture")
                (auth / "auth.json").chmod(0o600)
                (auth / ".safeyolo-provenance.json").write_text(json.dumps({"schema":"safeyolo.codex-provenance/v1", "state":"agent-local"}))
                (auth / ".safeyolo-provenance.json").chmod(0o600)
                failed_workspace = directory / "failure"
                active, name, port, record = start(failed_workspace, ["--agent", fixture_name, "--keep"])
                active.send("\n")
                assert active.finish() != 0 and "Codex harness failed after setup" in active.output
                assert (failed_workspace / "harness-started").read_text().strip() == "reached"
                stopped(name)
                assert policy()["agents"][name]["folder"] == str(prior)
                assert not policy()["agents"][name].get("hosts")
                assert record.read_text() == ""
                closed(port)
                peer_survives()
                result["startup_failure"] = {"actual_guest_exec_exit":41, "owned_runtime_stopped":True, "keep_observed":True, "permission_removed":True, "peer_unchanged":True}

                fresh_workspace = directory / "fresh"
                active, name, port, record = start(fresh_workspace)
                active.send("cancel\n")
                assert active.finish() != 0 and "cancelled after runtime creation" in active.output
                assert name not in policy()["agents"] and not fresh_workspace.exists()
                closed(port)
                peer_survives()
                result["fresh_start"] = True

            if args.real_agent:
                # W1: a single actual ordinary Codex task. Its model/provider and
                # authentication are the selected guest's existing configuration.
                stopped(args.real_agent)
                workspace = directory / "real-app"
                active, name, port, record = start(workspace, ["--agent", args.real_agent], select_task=True)
                active.send("\n")
                active.until("Type approve, reject, evidence, or cancel:", timeout=600)
                assert record.read_text() == "", "origin delivery preceded the human approval"
                print(active.output, flush=True)
                decision = input("Inspect the real pending evidence above. Approve the fixture request? Type approve or reject: ").strip()
                assert decision in {"approve", "reject"}, "an explicit human decision is required"
                active.send(decision + "\n")
                assert decision == "approve", "operator rejected W1; do not count it as a pass"
                active.until("Result is ready.", timeout=600)
                app = json.loads(cli("agent", "shell", name, "-c", "curl -fsS http://127.0.0.1:8000/", timeout=15))
                records = [json.loads(line) for line in record.read_text().splitlines()]
                assert records and all(row["marker"] == app["marker"] for row in records)
                assert app == {"title":"Demo tasks", "count":3, "total_minutes":20, "marker":records[0]["marker"]}
                descriptor = os.open(workspace / "app.py", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "r") as app_file:
                    assert stat.S_ISREG(os.fstat(app_file.fileno()).st_mode)
                    source = app_file.read(128 * 1024 + 1)
                assert len(source) <= 128 * 1024, "app source exceeds the retained diagnostic bound"
                assert source.strip(), "actual app source is missing"
                active.send("\n")
                assert active.finish() == 0, active.output[-1500:]
                stopped(name)
                closed(port)
                peer_survives()
                result.update({"real_model":True, "app_response":app, "fixture_records":records, "app_code_created":True, "app_source":source, "zero_preapproval_deliveries":True})
        finally:
            if active is not None:
                active.cancel()
            for name in reversed(owned):
                cli("agent", "stop", name)
                stopped(name)
            remaining = json.loads(cli("status"))["agents"]
            if before["proxy_state"] != "running" and all(
                agent["runtime_state"] == "stopped" for agent in remaining
            ):
                cli("stop")
            result["stopped_test_guests"] = owned
    print(json.dumps(result))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--real-agent", help="existing stopped Demo guest with its own configured Codex authentication")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
