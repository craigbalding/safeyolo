"""Driver controls are synthetic; they do not accept an installed Demo result."""

import argparse
import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.blackbox import installed_demo as demo


@pytest.mark.parametrize("completion", [False, True])
def test_controlled_codex_selected_offline_by_shipped_wrapper(tmp_path, completion):
    mise = shutil.which("mise")
    assert mise, "the native Codex package selection needs mise"
    home = tmp_path / "home"
    demo.stage_controlled_codex(home)
    tools = tmp_path / "tools"
    tools.mkdir()
    # Use real mise for local selection. Refuse remote resolution and client
    # installation; completion stops at the controlled Python workload boundary.
    (tools / "mise").write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MISE_CALLS"\n'
        'case "$1" in\n'
        '  link|where|settings) exec "$REAL_MISE" "$@";;\n'
        '  latest) [ "$2" = --installed ] && exec "$REAL_MISE" "$@";;\n'
        '  use) [ "$*" = "use -g python@3.12" ] && exit 0;;\n'
        'esac\nexit 97\n'
    )
    (tools / "mise").chmod(0o755)
    (tools / "python3").write_text('#!/bin/sh\n[ "$*" = app.py ] || exit 98\necho controlled-python-workload\n')
    (tools / "python3").chmod(0o755)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("MISE_", "SAFEYOLO_CODEX_")) and key not in {"BASH_ENV", "SAFEYOLO_MIN_RELEASE_AGE"}}
    environment.update(HOME=str(home), PATH=f"{tools}:/usr/bin:/bin", REAL_MISE=mise,
                       MISE_CALLS=str(tmp_path / "mise-calls"))
    wrapper = Path(__file__).resolve().parents[1] / "contrib/codex-command.sh"
    ready = subprocess.run([str(wrapper), "--version"], env=environment, capture_output=True, text=True, timeout=15)
    assert ready.returncode == 0, ready.stderr
    # Demo runs authentication in a new process without the wrapper's PATH.
    login_environment = {**environment, "MISE_DATA_DIR": str(home / ".mise"),
                         "MISE_CONFIG_DIR": str(home / ".mise"), "MISE_CACHE_DIR": str(home / ".mise/cache"),
                         "PATH": f"{home}/.local/bin:{home}/.mise/shims:{environment['PATH']}"}
    login = subprocess.run(["/bin/sh", "-c", "codex login status"], env=login_environment,
                           capture_output=True, text=True, timeout=15)
    assert login.returncode == 0, login.stderr
    if completion:
        demo.stage_controlled_codex(home, completion=True)
    result = subprocess.run([str(wrapper), "exec", "-C", str(tmp_path)], env=environment,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == (0 if completion else 41), result.stderr
    assert "codex-host-setup: codex 0.0.0" in result.stderr
    imported = home / ".safeyolo/codex-package/payload"
    selected = home / ".mise/installs/github-openai-codex/0.0.0"
    assert selected.samefile(imported)
    assert (home / ".local/bin/codex").samefile(selected / "bin/codex")
    calls = (tmp_path / "mise-calls").read_text().splitlines()
    assert calls[0].startswith("link --force github:openai/codex[asset_pattern=codex-package-")
    assert calls[0].endswith(f"]@0.0.0 {imported}")
    assert not any(call.startswith(("install ", "use ")) and call != "use -g python@3.12" for call in calls)
    if completion:
        assert result.stdout.strip() == "controlled-python-workload"
        assert (tmp_path / "app.py").read_text() == demo.COMPLETION_APP
    else:
        assert (tmp_path / "harness-started").read_text().strip() == "reached"


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
        diagnostics = demo.DemoProcess.diagnostics

        def __init__(self, command):
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
    args = argparse.Namespace(config_dir=root, commit="candidate", guest_commit=None,
                              preview=False, real_agent=None, deterministic_completion=True)
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
