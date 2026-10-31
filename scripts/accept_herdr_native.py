#!/usr/bin/env python3
"""Exercise one real, finite two-Codex-agent Herdr 0.9.5 journey on a trusted host.

Run as python3 -m scripts.accept_herdr_native from the source checkout.
The preparation file names Sylab's existing runtime and two owned sandboxes.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pty
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import uuid
from pathlib import Path

from scripts.safeyolo_herdr import Herdr, HerdrError, native_status


class JourneyError(RuntimeError):
    """An observed journey criterion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise JourneyError(message)


def until(check, deadline: float, drain=lambda: None):
    while time.monotonic() < deadline:
        drain()
        observed = check()
        if observed:
            return observed
        time.sleep(0.2)
    raise JourneyError("journey deadline reached; inspect private host diagnostics")


def identity(status: dict) -> tuple:
    return tuple(status.get(key) for key in ("agent_id", "run_id", "launch_id"))


def prepared_agents(preparation: dict) -> dict[str, dict]:
    agents = {}
    for step in preparation["preflight"]:
        if step["command"][-3:-1] == ["agent", "status"] and step["exit"] == 0:
            status = json.loads(step["stdout"])
            agents[status["name"]] = status
    require(len(agents) == 2, "preparation must identify exactly two agents")
    require(len({status["agent_id"] for status in agents.values()}) == 2, "agent identities must differ")
    require(len({status["run_id"] for status in agents.values()}) == 2, "sandbox generations must differ")
    return agents


def check_initial(expected: dict, actual: dict) -> None:
    require(identity(expected) == identity(actual), "prepared native identity changed; do not replay")
    require(bool(actual["run_id"]) and actual["runtime_state"] == "running" and actual["agent_state"] == "stopped"
            and actual["terminal_state"] == "absent" and actual["harness"] == "codex",
            "expected a prepared sandbox with no coding command; inspect before retrying")


def check_continuity(expected: dict, actual: dict) -> None:
    require(identity(expected) == identity(actual) and all(identity(actual)),
            "native agent/run/launch identity changed")
    require(actual["runtime_state"] == "running" and actual["agent_state"] == "running",
            "native coding command is not confirmed running")


def rollout_turn(path: Path, prompt: str, answer: str) -> str | None:
    """Observe current Codex response_item records, never terminal echoes.

    Codex rust-v0.164.0: history/src/rollout_payload.rs serializes the
    response_item payload directly. rollout/src/policy.rs persists messages
    and tool calls. Read only complete lines while the harness appends.
    """
    session_id = None
    received = False
    used_tool = False
    with path.open() as stream:
        for line in stream:
            if not line.endswith("\n"):
                break
            record = json.loads(line)
            payload = record.get("payload", {})
            if record.get("type") == "session_meta":
                require(payload.get("cli_version") == "0.164.0", "unexpected Codex rollout version")
                session_id = payload.get("id")
            if record.get("type") != "response_item":
                continue
            kind = payload.get("type")
            if kind == "message":
                text = "".join(item.get("text", "") for item in payload.get("content", []))
                if payload.get("role") == "user":
                    received = prompt in text
                    used_tool = False
                elif (received and used_tool and payload.get("role") == "assistant"
                      and payload.get("phase") in (None, "final_answer") and text.strip() == answer):
                    return session_id
            elif received and kind in ("function_call", "custom_tool_call", "local_shell_call"):
                used_tool = True
    return None


def turn_proof(paths: list[Path], prompt: str, answer: str, receipt: Path) -> dict | None:
    if not receipt.is_file() or receipt.read_text().strip() != answer:
        return None
    for path in paths:
        session_id = rollout_turn(path, prompt, answer)
        if session_id:
            return {"session_id": session_id, "received_by_codex": True,
                    "tool_call_observed": True, "assistant_answer_observed": True,
                    "workspace_receipt_matches": True, "answer_sha256": answer}
    return None


class TuiClient:
    """Own one PTY client; Herdr's server and native agents survive its detach."""

    def __init__(self, binary: str, environment: dict, cwd: Path):
        self.binary, self.environment, self.cwd = binary, environment, cwd
        self.output = b""
        self.pid = None
        self.fd = None
        self.exit_code = None

    def __enter__(self):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(self.cwd)
            os.execve(self.binary, [self.binary, "client"], self.environment)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 180, 0, 0))
        return self

    def drain(self):
        while select.select([self.fd], [], [], 0)[0]:
            try:
                chunk = os.read(self.fd, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    return  # Linux PTYs return EIO after the client exits.
                raise
            if not chunk:
                return
            self.output = (self.output + chunk)[-262144:]

    def __exit__(self, _kind, _error, _traceback):
        try:
            os.write(self.fd, b"\x02q")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                self.drain()
                done, status = os.waitpid(self.pid, os.WNOHANG)
                if done:
                    self.pid = None
                    self.exit_code = os.waitstatus_to_exitcode(status)
                    require(self.exit_code == 0, "Herdr TUI detach failed")
                    return
                time.sleep(0.05)
            raise JourneyError("Herdr TUI did not detach within ten seconds")
        finally:
            if self.pid is not None:
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # The owned client can exit between waitpid and kill.
                os.waitpid(self.pid, 0)
            os.close(self.fd)


def prompt_for(token: str, receipt: str, continued: bool) -> tuple[str, str]:
    suffix = "continued" if continued else "first"
    introduction = ("Use the ASCII token from my previous request." if continued
                    else f"Remember this ASCII token for the next turn: {token}.")
    prompt = (f"Harmless terminal smoke test. {introduction} Use your shell tool to compute SHA-256 of the token "
              f"followed immediately by :{suffix}, without quotes or a newline in the hashed bytes. "
              "Write only the lowercase digest and a newline to "
              f"/workspace/{receipt}. Reply with only that digest. Do not change other files or use the network.")
    return prompt, hashlib.sha256(f"{token}:{suffix}".encode()).hexdigest()


class Journey:
    def __init__(self, preparation: dict, output: Path, timeout: float):
        self.preparation, self.output = preparation, output
        self.deadline = time.monotonic() + timeout
        route = preparation["route"]
        self.command = [route["cli"], "--root", route["root"]]
        self.binary = preparation["herdr"]["path"]
        self.agents = prepared_agents(preparation)
        self.panes = {}
        self.live = {}
        self.previous_rollouts = {}
        self.tokens = {name: uuid.uuid4().hex for name in self.agents}
        self.owned = []
        self.server = None
        self.log = None
        self.runtime = None
        self.herdr = None
        self.result = {"passed": False, "scope": "phase-one real two-agent journey only",
                       "native_source_from_preparation": route["native_source"],
                       "observations": {}, "turns": {}, "cleanup": {}}

    def sessions(self, name: str) -> Path:
        return Path(self.preparation["route"]["root"]) / "agents" / name / "home/.codex/sessions"

    def read_pane(self, name: str) -> str:
        return self.herdr.call("pane.read", {"pane_id": self.panes[name], "source": "recent",
                                             "format": "text", "lines": 200})["text"]

    def snapshot(self, label: str) -> None:
        observations = self.result["observations"][label] = {}
        for name in self.agents:
            status = native_status(self.command, name)
            observations[name] = status
            check_continuity(self.live[name], status)
            display = self.herdr.call("agent.get", {"target": name})["agent"]
            require(display["pane_id"] == self.panes[name], "Herdr name selected another pane")
            require(display["agent_status"] == "unknown", "Herdr invented semantic harness activity")
            require(all(display.get("tokens", {}).get(key) == status[key]
                        for key in ("agent_id", "run_id", "launch_id")), "Herdr identity projection is stale")

    def prepare(self) -> None:
        require(hashlib.sha256(Path(self.binary).read_bytes()).hexdigest() == self.preparation["herdr"]["sha256"],
                "Herdr binary does not match preparation")
        free = shutil.disk_usage(self.preparation["route"]["root"]).free
        self.result["free_bytes_before"] = free
        require(free >= self.preparation["reserve_bytes"], "existing build-filesystem reserve is unavailable")
        for name, expected in self.agents.items():
            actual = native_status(self.command, name)
            self.result["observations"].setdefault("initial", {})[name] = actual
            check_initial(expected, actual)
            self.previous_rollouts[name] = set(self.sessions(name).rglob("*.jsonl"))
        self.owned = list(self.agents)
        self.runtime = Path(tempfile.mkdtemp(prefix="h572-"))  # Only the short Unix socket lives in /tmp.
        config = self.output / "herdr.toml"
        config.write_text('onboarding = false\n[terminal]\ndefault_shell = "/bin/sh"\n'
                          'shell_mode = "non_login"\n[update]\nversion_check = false\nmanifest_check = false\n'
                          '[session]\nresume_agents_on_restore = false\n')
        self.environment = dict(os.environ)
        self.environment.pop("TMUX", None)
        self.environment.pop("TMUX_PANE", None)
        self.environment.update({"XDG_CONFIG_HOME": str(self.output / "config"),
                                 "XDG_STATE_HOME": str(self.output / "state"),
                                 "XDG_CACHE_HOME": str(self.output / "cache"),
                                 "XDG_RUNTIME_DIR": str(self.runtime), "HERDR_CONFIG_PATH": str(config),
                                 "HERDR_SOCKET_PATH": str(self.runtime / "api.sock"),
                                 "HERDR_SESSION": f"sy572-{uuid.uuid4().hex[:8]}", "TERM": "xterm-256color"})
        self.log = (self.output / "server.log").open("w")
        self.herdr = Herdr(self.environment["HERDR_SOCKET_PATH"])
        self.server = subprocess.Popen([self.binary, "server"], env=self.environment, cwd=self.output,
                                       stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        until(lambda: (self.runtime / "api.sock").exists(), self.deadline)
        ping = self.herdr.call("ping")
        self.result["herdr"] = {key: ping[key] for key in ("version", "protocol")}
        require(ping["version"] == "0.9.5", "expected Herdr TUI 0.9.5")

    def launch(self) -> None:
        workspace = self.herdr.call("workspace.create", {"cwd": str(self.output), "label": "SafeYolo 572",
                                                         "focus": True})
        pane = workspace["root_pane"]["pane_id"]
        for index, name in enumerate(self.agents):
            if index:
                pane = self.herdr.call("pane.split", {"target_pane_id": pane, "direction": "right",
                                                      "focus": True})["pane"]["pane_id"]
            self.panes[name] = pane
            wrapper = Path(__file__).with_name("safeyolo_herdr.py")
            command = shlex.join([sys.executable, str(wrapper), name, "--safeyolo", self.command[0],
                                  "--root", self.command[2]])
            subprocess.run([self.binary, "pane", "run", pane, command], env=self.environment,
                           check=True, capture_output=True, timeout=15)

    def ready(self, name: str) -> dict | None:
        status = native_status(self.command, name)
        if status["agent_state"] == "running" and status["launch_id"] and "›" in self.read_pane(name):
            require(identity(status)[:2] == identity(self.agents[name])[:2], "sandbox changed during launch")
            return status
        return None

    def turn(self, name: str, continued: bool, client: TuiClient) -> None:
        label = "continued" if continued else "first"
        receipt_name = f".herdr572-{uuid.uuid4().hex}-{label}"
        receipt = Path(self.agents[name]["effective_configuration"]["workspace"]) / receipt_name
        require(not receipt.exists(), "fresh journey receipt already exists; do not replay")
        prompt, answer = prompt_for(self.tokens[name], receipt_name, continued)
        require(answer not in prompt, "oracle answer leaked into pane input")
        focused = self.herdr.call("agent.focus", {"target": name})["agent"]
        require(focused["focused"] and focused["pane_id"] == self.panes[name], "agent focus failed")
        self.herdr.call("pane.send_input", {"pane_id": self.panes[name], "text": prompt, "keys": ["enter"]})

        def observe():
            paths = sorted(set(self.sessions(name).rglob("*.jsonl")) - self.previous_rollouts[name])
            proof = turn_proof(paths, prompt, answer, receipt)
            return proof if proof and answer in self.read_pane(name) else None

        proof = until(observe, self.deadline, client.drain)
        proof["answer_visible_in_pane"] = True
        turns = self.result["turns"].setdefault(name, {})
        turns[label] = proof
        if continued:
            require(proof["session_id"] == turns["first"]["session_id"], "Codex session changed after reattach")
        receipt.unlink()  # Remove only this journey's verified finite answer.

    def exercise(self) -> None:
        self.prepare()
        self.launch()
        with TuiClient(self.binary, self.environment, self.output) as first:
            for name in self.agents:
                self.live[name] = until(lambda name=name: self.ready(name), self.deadline, first.drain)
                self.turn(name, False, first)
            # Let the wrapper's next refresh publish each newly created launch.
            until(lambda: all(self.herdr.call("agent.get", {"target": name})["agent"].get("tokens", {})
                              .get("launch_id") == self.live[name]["launch_id"] for name in self.agents),
                  self.deadline, first.drain)
            self.snapshot("before_detach")
            require(all(name.encode() in first.output for name in self.agents), "TUI did not display both agents")
        self.result["first_detach_exit"] = first.exit_code
        self.snapshot("detached")
        with TuiClient(self.binary, self.environment, self.output) as second:
            until(lambda: all(name.encode() in second.output for name in self.agents), self.deadline, second.drain)
            self.snapshot("reattached")
            for name in self.agents:
                self.turn(name, True, second)
            self.snapshot("after_continuation")
        self.result["second_detach_exit"] = second.exit_code

    def cleanup(self) -> bool:
        clean = True
        for name in self.owned:
            try:
                current = native_status(self.command, name)
                require(identity(current)[:2] == identity(self.agents[name])[:2],
                        "cleanup preserved a changed native generation")
                subprocess.run([*self.command, "agent", "stop", name], check=True,
                               capture_output=True, timeout=140)
                stopped = native_status(self.command, name)
                self.result["cleanup"][name] = stopped
                require(stopped["runtime_state"] == "stopped" and stopped["agent_state"] == "stopped"
                        and stopped["terminal_state"] == "absent", "normal native stop is incomplete")
            except (OSError, ValueError, subprocess.SubprocessError, JourneyError) as error:
                self.result["cleanup"][name] = {"error": str(error) if isinstance(error, JourneyError)
                                               else type(error).__name__}
                clean = False
        if self.server is not None:
            try:
                require(self.server.poll() is None, "Herdr server exited before normal stop")
                self.herdr.call("server.stop")
                require(self.server.wait(timeout=10) == 0, "Herdr server stop failed")
                self.result["cleanup"]["herdr_normal_stop"] = True
            except (OSError, ValueError, subprocess.SubprocessError, HerdrError, JourneyError):
                self.result["cleanup"]["herdr_normal_stop"] = False
                clean = False
            finally:
                if self.server.poll() is None:
                    self.server.kill()
                    self.server.wait()
        if self.log:
            self.log.close()
        if self.runtime:
            self.result["cleanup"]["socket_absent"] = not (self.runtime / "api.sock").exists()
            clean = clean and self.result["cleanup"]["socket_absent"]
            shutil.rmtree(self.runtime)
        return clean


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preparation", required=True, type=Path, help="verified Sylab preparation JSON")
    parser.add_argument("--output", required=True, type=Path, help="new private host output directory")
    parser.add_argument("--timeout", type=float, default=1800, help="journey seconds, plus bounded cleanup (default 1800)")
    args = parser.parse_args()
    require(0 < args.timeout <= 3600, "choose a finite session of at most one hour, plus preparation/cleanup")
    os.umask(0o077)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700)  # Never overwrite an uncertain previous run.
    preparation = json.loads(args.preparation.read_text())
    journey = Journey(preparation, args.output, args.timeout)
    started = time.monotonic()
    completed = False

    def terminate(signum, _frame):
        journey.result["failure"] = f"terminated by signal {signum}"
        raise SystemExit(128 + signum)

    previous_terminate = signal.signal(signal.SIGTERM, terminate)
    try:
        journey.exercise()
        completed = True
    except (OSError, ValueError, subprocess.SubprocessError, HerdrError, JourneyError) as error:
        journey.result["failure"] = str(error) if isinstance(error, (HerdrError, JourneyError)) else type(error).__name__
    finally:
        clean = journey.cleanup()
        journey.result["passed"] = completed and clean
        journey.result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (args.output / "result.json").write_text(json.dumps(journey.result, indent=2) + "\n")
        signal.signal(signal.SIGTERM, previous_terminate)
    print(json.dumps({"passed": journey.result["passed"], "result": str(args.output / "result.json")}))
    return 0 if journey.result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
