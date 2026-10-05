"""Approved service calls for trusted hardware invocations.

Rundeck's documented API returns invocation identities and output, not product
acceptance. The existing Tart client owns its mailbox. Bristol uses the
operator's existing SSH binding. None of their credentials reach candidates.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib import request
from urllib.parse import urlsplit

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli/src"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from tests.blackbox.hardware.attempt_results import HardwareAttempt, integer, read_json
    from tests.blackbox.hardware.publish_results import GitHubResults
else:
    from .attempt_results import HardwareAttempt, integer, read_json
    from .publish_results import GitHubResults

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def select_source(attempt: HardwareAttempt, github: GitHubResults, authorized_commit: str | None = None) -> str:
    """Only overnight default-branch selection or an operator's exact SHA."""
    return github.select_source(attempt, authorized_commit)


class Rundeck:
    """Project acceptance script submission through the configured service URL.

    API reference: https://docs.rundeck.com/docs/api/
    The operator binds the URL and its existing principal at deployment.
    """

    def __init__(self, url: str, token_file: Path | None = None):
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Rundeck needs a service URL without embedded credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("Rundeck service URL cannot contain query credentials")
        self.url = url.rstrip("/") + "/api/59/"
        self.token_file = token_file

    def api(self, endpoint: str, *, body: dict | None = None) -> dict:
        headers = {"Accept": "application/json"}
        # Use the existing authorization route. A token file is optional when
        # the operator's approved transport already supplies authentication.
        # Never create, copy, log or save a credential here.
        if self.token_file is not None:
            token = self.token_file.read_text().strip()
            if not token or "\n" in token or "\r" in token:
                raise ValueError("Rundeck principal is unavailable")
            headers["X-Rundeck-Auth-Token"] = token
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        call = request.Request(self.url + endpoint, data=data, headers=headers)
        with request.urlopen(call, timeout=60) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Rundeck response exceeds the bounded read")
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get("error"):
            raise ValueError("Rundeck did not return a usable response")
        return result

    def submit(self, script: str) -> int:
        result = self.api("project/acceptance/run/script", body={
            "project": "acceptance", "script": script, "scriptInterpreter": "/bin/bash",
        })
        return integer(result["execution"]["id"], minimum=1)

    def state(self, execution: int) -> dict:
        integer(execution, minimum=1)
        result = self.api(f"execution/{execution}/state")
        if (result["executionId"] != execution or type(result["completed"]) is not bool
                or result["executionState"] not in {"WAITING", "RUNNING", "SUCCEEDED", "FAILED", "ABORTED", "INCOMPLETE"}):
            raise ValueError("Rundeck returned a mismatched execution state")
        return {name: result[name] for name in ("executionId", "completed", "executionState")}

    def wait(self, execution: int, timeout: int) -> dict:
        if timeout <= 0:
            raise ValueError("Rundeck wait needs a positive deadline")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.state(execution)
            if state["completed"]:
                if state["executionState"] in {"RUNNING", "WAITING"}:
                    raise ValueError("Rundeck completed flag contradicts execution state")
                return state
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise TimeoutError("Rundeck execution deadline expired; host cleanup remains required")

    def abort(self, execution: int) -> str:
        integer(execution, minimum=1)
        result = self.api(f"execution/{execution}/abort")
        if result["execution"]["id"] != execution or result["abort"]["status"] not in {"pending", "failed", "aborted"}:
            raise ValueError("Rundeck returned a mismatched abort response")
        # 'pending' and 'aborted' say nothing about guest/domain teardown.
        return result["abort"]["status"]

    def output(self, execution: int, private_path: Path) -> None:
        """Retrieve bounded output privately; never publish execution logs."""
        integer(execution, minimum=1)
        offset, written = 0, 0
        with private_path.open("xb") as stream:
            while True:
                result = self.api(f"execution/{execution}/output?format=json&offset={offset}&maxlines=50&compacted=false")
                if result["id"] != execution or type(result["completed"]) is not bool or type(result["execCompleted"]) is not bool:
                    raise ValueError("Rundeck returned mismatched execution output")
                following = integer(result["offset"])
                for entry in result["entries"]:
                    log = entry["log"]
                    if not isinstance(log, str):
                        raise ValueError("Rundeck returned an invalid output entry")
                    line = log.encode() + b"\n"
                    written += len(line)
                    if written > MAX_RESPONSE_BYTES:
                        raise ValueError("Rundeck private output exceeds the bounded read")
                    stream.write(line)
                if result["completed"] and result["execCompleted"]:
                    return
                if following <= offset:
                    # Call after wait. Partial logs never become a report.
                    raise ValueError("Rundeck output is unfinished or its cursor did not advance")
                offset = following


def tart_command(client: Path, mailbox: Path, script: Path, timeout: int) -> dict:
    """Use the existing foreground client and then its canonical response."""
    if timeout <= 0:
        raise ValueError("Tart command needs a positive deadline")
    process = subprocess.run([str(client), "--timeout", str(timeout), "--file", str(script)],
                             capture_output=True, text=True, timeout=timeout + 35, check=False)
    # The client prints the request ID first. Command prose/exit status does
    # not establish that the command ran or produced the requested artifact.
    first = process.stdout.splitlines()[0] if process.stdout else ""
    match = re.fullmatch(r"tart job=([0-9a-f]{32})", first)
    if match is None:
        raise ValueError("Tart client did not return an invocation identity")
    result = read_json(mailbox / "responses" / f"{match[1]}.json")
    if (type(result["timed_out"]) is not bool
            or (result["exit_code"] is not None and type(result["exit_code"]) is not int)
            or not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str)):
        raise ValueError("Tart returned a malformed command response")
    return {"job_id": match[1], **{name: result[name] for name in ("exit_code", "timed_out", "stdout", "stderr")}}


def bristol_command(config: Path, command: str, stdin, private_output, timeout: int) -> int:
    """Use the approved sy-agent SSH-stdin route with bounded foreground work."""
    if timeout <= 0:
        raise ValueError("Bristol command needs a positive deadline")
    result = subprocess.run(["ssh", "-F", str(config), "-o", "BatchMode=yes", "seatbelt-mac", command],
                            stdin=stdin, stdout=private_output, stderr=private_output, timeout=timeout, check=False)
    # Lost SSH/timeout always leaves independent host cleanup outstanding.
    return result.returncode


def main() -> int:
    """Submit one existing Rundeck script and retain its canonical invocation."""
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--rundeck-url", required=True)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10800)
    args = parser.parse_args()
    client = Rundeck(args.rundeck_url, args.token_file)
    execution = client.submit(args.script.read_text())
    # Keep the invocation even if this observer dies or the wait times out.
    # Neither condition authorizes aborting the independently running host job.
    with args.receipt.open("x") as stream:
        json.dump({"execution_id": execution}, stream)
    state = client.wait(execution, args.timeout_seconds)
    client.output(execution, args.output)
    print(json.dumps(state))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
