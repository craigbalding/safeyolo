"""Driver controls are synthetic; they do not accept an installed Demo result."""

import argparse
import copy
import json
import shutil
import subprocess

import pytest

from tests.blackbox import installed_demo as demo


@pytest.mark.parametrize("finish_exit,peer_failure", [(0, False), (1, False), (0, True)])
def test_completion_retains_source_before_failure_and_observes_peer_after_finish(
    tmp_path, monkeypatch, capsys, finish_exit, peer_failure
):
    root = tmp_path / "instance"
    (root / "data").mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "assets/guest").mkdir(parents=True)
    (root / "assets/guest/safeyolo-guest.version").write_text("commit=candidate ")
    (root / "policy.toml").write_text("controlled policy reader")
    agents, runtimes, processes = {}, {}, []
    finished = False
    marker = "a" * 32
    app = {"title": "Demo tasks", "count": 3, "total_minutes": 20, "marker": marker}

    def create(name, workspace):
        agents[name] = {"agent_id": f"ag-{len(agents):032x}", "folder": str(workspace)}
        runtimes[name] = "stopped"
        (root / "agents" / name / "home").mkdir(parents=True)

    def cli(command, **kwargs):
        args = command[3:]
        status, output = 0, ""
        if args == ["--version"]:
            output = "safeyolo commit=candidate profile=production"
        elif args == ["status"]:
            output = json.dumps({"proxy_state": "stopped", "agents": [
                {"name": name, "runtime_state": state} for name, state in runtimes.items()
            ]})
        elif args[:2] == ["agent", "create"]:
            create(args[2], args[args.index("--workspace") + 1])
        elif args[:2] == ["agent", "start"]:
            runtimes[args[2]] = "running"
        elif args[:2] == ["agent", "stop"]:
            runtimes[args[2]] = "stopped"
        elif args[:2] == ["agent", "status"]:
            output = json.dumps({"runtime_state": runtimes[args[2]]})
        elif args[:2] == ["agent", "shell"]:
            if "curl" in args[-1]:
                output = json.dumps(app)
            elif finished and peer_failure:
                status = 1
        else:
            assert args == ["stop"], args
        return subprocess.CompletedProcess(command, status, output, "controlled peer failure")

    class Process:
        def __init__(self, command):
            from pathlib import Path

            self.workspace = Path(command[command.index("--workspace") + 1])
            self.workspace.mkdir()
            self.keep = "--keep" in command
            self.reused = "--agent" in command
            self.name = command[command.index("--agent") + 1] if self.reused else f"demo-new-{len(processes)}"
            if not self.reused:
                create(self.name, self.workspace)
            self.prior = agents[self.name]["folder"]
            agents[self.name]["folder"] = str(self.workspace)
            runtimes[self.name] = "running"
            self.record = root / "logs" / f"demo-{marker}-requests.jsonl"
            self.record.write_text("")
            (self.workspace / "TASK.md").write_text(f"http://127.0.0.1:12345/demo/{marker}.json")
            self.output = f"Demo guest: {self.name} ({agents[self.name]['agent_id']})\nRuntime is ready."
            self.done = False
            processes.append(self)

        def send(self, value):
            assert value in {"1\n", "\n", "cancel\n", "approve\n"}

        def until(self, text, **kwargs):
            if text == "Result is ready.":
                self.record.write_text(json.dumps({"marker": marker}) + "\n")
                (self.workspace / "app.py").write_text(demo.COMPLETION_APP)
            self.output += "\n" + text
            return self.output

        def finish(self):
            nonlocal finished
            self.done = True
            runtimes[self.name] = "stopped"
            if self.reused:
                agents[self.name]["folder"] = self.prior
            else:
                del agents[self.name]
                del runtimes[self.name]
            if self.workspace.name == "failure":
                (self.workspace / "harness-started").write_text("reached")
                self.output += "Codex harness failed after setup"
                return 41
            if not self.keep:
                shutil.rmtree(self.workspace)
            if self.workspace.name == "real-app":
                finished = True
                return finish_exit
            self.output += "cancelled after runtime creation"
            return 1

        def cancel(self):
            assert self.done

    monkeypatch.setattr(demo.subprocess, "run", cli)
    monkeypatch.setattr(demo.subprocess, "check_output", lambda *a, **k: "commit=candidate ")
    monkeypatch.setattr(demo.tomllib, "loads", lambda *a: {"agents": copy.deepcopy(agents)})
    monkeypatch.setattr(demo, "DemoProcess", Process)
    monkeypatch.setattr(demo.socket.socket, "connect_ex", lambda *a: 111)
    args = argparse.Namespace(config_dir=root, commit="candidate", real_agent=None, deterministic_completion=True)
    if finish_exit or peer_failure:
        with pytest.raises(AssertionError):
            demo.run(args)
    else:
        demo.run(args)
    observations = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    before_finish = observations[0]
    assert before_finish["real_model"] is False
    assert before_finish["deterministic_completion"] is True
    assert before_finish["app_source"] == demo.COMPLETION_APP
    assert before_finish["app_response"] == app
    assert before_finish["demo_finish_completed"] is False
    assert before_finish["peer_after_finish_verified"] is False
    if not finish_exit and not peer_failure:
        assert observations[-1]["demo_finish_completed"] is True
        assert observations[-1]["peer_after_finish_verified"] is True
    else:
        assert len(observations) == 1
    assert all(state == "stopped" for state in runtimes.values())
    assert all(process.done for process in processes)
    compile(demo.COMPLETION_APP, "controlled-app.py", "exec")
