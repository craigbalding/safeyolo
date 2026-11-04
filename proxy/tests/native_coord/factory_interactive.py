"""Actual interactive Codex producer and native Factory reviewer, on owned sockets.

Invoked by the ignored Rust native_coord test. Native records decide results;
terminal markers only wake the observer. Existing client sessions retain their
own history. No second task state or conversation transcript is written here.
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path


def run(arguments, *, environment=None, payload=None, timeout=420):
    result = subprocess.run(
        list(map(str, arguments)), env=environment, input=payload,
        text=True, capture_output=True, timeout=timeout,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def client_environment(role_home, root, name):
    return {**os.environ, "HOME": str(role_home), "CODEX_HOME": str(role_home / ".codex"),
            "SAFEYOLO_COORD_SOCKET": str(root / f"{name}.sock"),
            "SAFEYOLO_COORD_TOKEN_PATH": str(root / "data/agent_token")}


def mcp_arguments(coord, root, name):
    settings = {
        "command": str(coord), "args": ["mcp"],
        "env.SAFEYOLO_COORD_SOCKET": str(root / f"{name}.sock"),
        "env.SAFEYOLO_COORD_TOKEN_PATH": str(root / "data/agent_token"),
    }
    result = []
    for key, value in settings.items():
        result.extend(["-c", f"mcp_servers.safeyolo-coord.{key}={json.dumps(value)}"])
    return result


class Interactive:
    def __init__(self, command, environment):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
        self.process = subprocess.Popen(command, env={**environment, "TERM": "xterm-256color"},
                                        stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        self.buffer = bytearray()

    def send(self, prompt):
        self.buffer.clear()
        os.write(self.master, b"\x1b[200~" + prompt.encode() + b"\x1b[201~")
        # Let the TUI finish its paste event before a separate submit key.
        # An Enter in the same input burst can remain in the composer.
        time.sleep(0.2)
        os.write(self.master, b"\r")

    def until(self, marker, timeout=360):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if marker.encode() in self.buffer:
                return
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    raise AssertionError(bytes(self.buffer[-16000:])) from None
                if b"\x1b[6n" in chunk:
                    os.write(self.master, b"\x1b[1;1R")
                for color, value in [(b"10", b"ffff/ffff/ffff"), (b"11", b"0000/0000/0000")]:
                    if b"\x1b]" + color + b";?" in chunk:
                        os.write(self.master, b"\x1b]" + color + b";rgb:" + value + b"\x1b\\")
                self.buffer.extend(chunk)
                if len(self.buffer) > 2 * 1024 * 1024:
                    del self.buffer[:-1024 * 1024]
            assert self.process.poll() is None, bytes(self.buffer[-16000:])
        raise AssertionError(f"interactive client did not finish {marker}: {bytes(self.buffer[-16000:])!r}")

    def close(self):
        try:
            if self.process.poll() is None:
                os.write(self.master, b"/quit\r")
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # This unreaped leader owns the group created above.
                    os.killpg(self.process.pid, signal.SIGTERM)
                    try:
                        self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(self.process.pid, signal.SIGKILL)
                        self.process.wait(timeout=5)
        finally:
            os.close(self.master)


def main():
    root, retained, coord, alice_home, bob_home, snapshot = map(Path, sys.argv[1:7])
    work_id = sys.argv[7]
    host = coord.with_name("safeyolo")
    codex = os.environ.get("SAFEYOLO_CODEX_BIN") or shutil.which("codex")
    assert codex, "native Codex executable is required"
    assert not (alice_home / ".safeyolo/coord-supervisor-state.json").exists()
    selected = json.loads(snapshot.read_text())
    assert {r["agent"] for r in selected["roles"].values()} == {"bob"}, "interactive Alice has no Factory supervisor"

    def read(work):
        return json.loads(run([coord, "call", "read_work"], environment=client_environment(alice_home, root, "alice"),
                              payload=json.dumps({"room_name": "shared", "work_id": work}), timeout=65))

    configuration = retained / "factory-supervisor.json"
    instructions = retained / "reviewer-instructions.md"
    instructions.write_text("Use only the owned proof, current native Work and the supplied role. Keep credentials private.\n")
    run([coord, "factory-stage", configuration, instructions, "bob", snapshot, "reviewer", "codex"])
    configured = json.loads(configuration.read_text())
    assert configured["native_work"] and configured["factory"]["snapshot_id"] == snapshot.stem
    # The owned process fixture substitutes its workspace for a guest mount.
    # Policy, identities and the approved snapshot binding remain unchanged.
    configured["workspace"] = str(retained)
    configured["wait_seconds"] = 1
    configured["work_timeout_seconds"] = 360
    configuration.write_text(json.dumps(configured))
    (retained / "AGENTS.md").write_text(
        "This is an owned native Coord proof. Follow your operator prompt and authenticated identity. "
        "Read current Work before mutations. Retain immutable artifacts before publication. "
        "Use native operations and operation-ID recovery. Do not read credentials or another role home.\n")

    def supervise():
        return run([coord, "supervise", "--once", "--confirm-fresh-identity", "--config", configuration,
                    "--state", retained / "factory-supervisor-state.json", "--", "--sandbox", "danger-full-access",
                    "--ask-for-approval", "never", *mcp_arguments(coord, root, "bob"),
                    "-c", f"developer_instructions={json.dumps(instructions.read_text())}"],
                   environment=client_environment(bob_home, root, "bob"), timeout=480)

    prompt = (
        f"You are Alice, the operator-directed interactive native Coord producer. Your assigned Work is {work_id} "
        "in room shared. You are not supervised. Use the authenticated native Coord MCP tools; read current Work, "
        "claim your assignment, and choose operation IDs before writes. Do not change selected policy or send messages. "
        f"Create the immutable artifact {retained / 'report-v1.md'} with exactly '# Observation\\nThe required result is absent.\\n' "
        "(actual newlines). Compute SHA-256, publish its file:// absolute reference ending #sha256=DIGEST with execution_outcome=succeeded, "
        "then complete your execution through complete_work using current expectations. Keep the artifact. "
        "Confirm current native state, then end your answer with the three words ALICE FIRST DONE joined by underscores. "
        "Do not print that joined marker before the native effects have succeeded."
    )
    command = [codex, "--no-daemon", "--no-alt-screen", "--sandbox", "danger-full-access", "--ask-for-approval", "never",
               "--cd", str(retained), "-c", f"projects.{json.dumps(str(retained))}.trust_level=\"trusted\"",
               *mcp_arguments(coord, root, "alice"), prompt]
    terminal = Interactive(command, client_environment(alice_home, root, "alice"))
    try:
        terminal.until("ALICE_FIRST_DONE")
        work = read(work_id)
        assert work["state"] == "done" and work["target_generation"] == 1, work
        assert work["output"]["producer"]["id"] == "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        first_check = work["factory"]["current_checks"][0]
        supervise()
        assert read(first_check)["check"]["answer"]["verdict"] == "reject"
        terminal.send(
            f"Continue your same Work {work_id}. Read its independent rejected check and retained original report. "
            "Raise a native challenge against output generation 1: it omits the required result. Name yourself as responder "
            "and the selected acceptance decider as independent challenge decider. Claim your response work. "
            f"Create {retained / 'report-v2.md'} with exactly '# Observation\\nThe required result is recorded here.\\n' "
            "(actual newlines), retain and hash it, then publish this correction under your retained claim and current output generation. "
            "Respond to the challenge with that exact output correction. Do not resolve it or change policy. "
            "After native effects succeed, end your answer with ALICE CORRECTION DONE joined by underscores."
        )
        terminal.until("ALICE_CORRECTION_DONE")
        work = read(work_id)
        assert work["target_generation"] == 2 and work["state"] == "done", work
        reviews = json.loads(run([coord, "call", "list_work_reviews"],
                                 environment=client_environment(alice_home, root, "alice"),
                                 payload=json.dumps({"room_name": "shared", "work_id": work_id})))
        related = [read(r["work_id"]) for r in reviews["items"]]
        challenges = [r for r in related if r.get("challenge") is not None]
        assert len(challenges) == 1, reviews
        challenge = challenges[0]
        assert challenge["challenge"]["response"] and not challenge["challenge"]["disposition"]
        current = work["acceptance_requirements"]
        checks = [{"work_id": r["work_id"], "version": read(r["work_id"])["version"]} for r in current["checks"]]
        # The operator selects this objection explicitly. An unselected advisory
        # challenge is not a universal veto, and Alice cannot amend this policy.
        run([host, "--root", root, "coord", "work", "set-requirements", "shared", work_id,
             "--expected-version", work["version"], "--expected-generation", work["claim_generation"],
             "--expected-requirements-version", current["version"], "--authorities", json.dumps(current["authorities"]),
             "--deciders", json.dumps(current["deciders"]), "--independent", "true", "--checks", json.dumps(checks),
             "--challenges", json.dumps([{"work_id": challenge["work_id"], "version": challenge["version"]}]),
             "--reason", "Require explicit independent disposition of the interactive producer's objection",
             "--operation-id", "select-interactive-objection"])
        for _ in range(3):
            supervise()
            if read(work_id)["acceptance_status"]["state"] == "accepted":
                break
        work = read(work_id)
        assert work["acceptance_status"]["state"] == "accepted", work
        assert read(challenge["work_id"])["challenge"]["disposition"]["author"]["id"] == "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        terminal.send(f"Read current native Work {work_id} and its acceptance. Make no further mutation. "
                      "After confirming the independent result, end your answer with ALICE FINAL DONE joined by underscores.")
        terminal.until("ALICE_FINAL_DONE")
        assert terminal.process.poll() is None, "interactive producer remains operator-directed while reviewer uses supervision"
        print(json.dumps({"result": "passed", "work_id": work_id, "factory_snapshot": snapshot.stem,
                          "interactive_producer": work["output"]["producer"], "acceptance": work["acceptance_status"]["state"]}))
    finally:
        terminal.close()


if __name__ == "__main__":
    main()
