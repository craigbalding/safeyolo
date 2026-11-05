#!/usr/bin/env python3
"""Consume trusted blackbox events in the existing Rundeck acceptance account.

Rundeck supplies the schedule and private GitHub binding. Each Actions attempt has
one private attempt directory. An existing directory prevents resubmission,
including after an interrupted or uncertain execution.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

if __package__:
    from .select_blackbox_artifacts import HOST_WORKFLOW, REPOSITORY, digest, utc
else:
    from select_blackbox_artifacts import HOST_WORKFLOW, REPOSITORY, digest, utc

EVENT_WORKFLOW = ".github/workflows/blackbox.yml"
HOST_ARTIFACT = "nightly-host-linux-amd64-production"


class GitHub:
    def __init__(self, log):
        self.log = log

    def api(self, endpoint: str, payload: dict | None = None, *, raw: bool = False):
        path = f"repos/{REPOSITORY}" + (f"/{endpoint}" if endpoint else "")
        command = ["gh", "api", path]
        if payload is not None:
            command += ["--method", "POST", "--input", "-"]
        result = subprocess.run(command, input=json.dumps(payload).encode() if payload is not None else None,
                                stdout=subprocess.PIPE, stderr=self.log, check=True, timeout=180)
        return result.stdout if raw else json.loads(result.stdout or b"null")

    def pages(self, endpoint: str, field: str) -> list[dict]:
        rows = []
        page = 1
        while True:
            separator = "&" if "?" in endpoint else "?"
            batch = self.api(f"{endpoint}{separator}per_page=100&page={page}")[field]
            rows.extend(batch)
            if len(batch) < 100:
                return rows
            page += 1


def request_for_run(github: GitHub, run: dict, branch: str) -> dict:
    """Read only the fixed request artifact from a trusted default-branch run."""
    if (run["path"] != EVENT_WORKFLOW or run["head_branch"] != branch
            or run["repository"]["full_name"] != REPOSITORY
            or run["event"] not in {"schedule", "workflow_dispatch", "workflow_run"}):
        raise ValueError("untrusted Claude event run")
    artifacts = github.pages(f"actions/runs/{run['id']}/artifacts", "artifacts")
    artifacts = [row for row in artifacts if row["name"] == f"claude-event-{run['run_attempt']}"]
    if len(artifacts) != 1 or artifacts[0]["expired"]:
        raise ValueError("trusted Claude event artifact is unavailable or ambiguous")
    artifact = artifacts[0]
    data = github.api(f"actions/artifacts/{artifact['id']}/zip", raw=True)
    if "sha256:" + hashlib.sha256(data).hexdigest() != digest(artifact["digest"]):
        raise ValueError("Claude event artifact checksum differs")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.namelist() != ["claude-event.json"]:
            raise ValueError("Claude event artifact has unexpected files")
        request = json.loads(archive.read("claude-event.json"))
    expected = {"schedule": "nightly", "workflow_dispatch": "manual", "workflow_run": "merge"}[run["event"]]
    if (request["trigger"] != expected or request["ref"] != f"refs/heads/{branch}"
            or request["event_run"] != run["id"] or request["event_attempt"] != run["run_attempt"]):
        raise ValueError("Claude request differs from its trusted event")
    if request.get("host_run") is not None:
        if not re.fullmatch(r"[0-9]+", str(request["host_run"])) or int(request["host_run"]) <= 0:
            raise ValueError("host_run must be a positive production run ID")
        request["host_run"] = int(request["host_run"])
    if request.get("guest_index") is not None:
        digest(request["guest_index"])
    if expected == "merge":
        if not re.fullmatch(r"[0-9a-f]{40}", request["source_revision"] or ""):
            raise ValueError("merge requires a full source revision")
        push = github.api(f"actions/runs/{int(request['push_run'])}")
        if (push["path"] != HOST_WORKFLOW or push["event"] != "push"
                or push["head_branch"] != branch or push["head_sha"] != request["source_revision"]
                or push["head_repository"]["full_name"] != REPOSITORY
                or push["status"] != "completed" or push["conclusion"] != "success"):
            raise ValueError("merge request does not bind successful default-branch push checks")
    return request


def production_run(github: GitHub, branch: str, source: str, attempt: Path, timeout: int) -> int:
    """Reuse exact production or dispatch the supported packages-only producer once."""
    query = urlencode({"head_sha": source, "branch": branch})
    deadline = time.monotonic() + timeout
    dispatched = False
    while True:
        runs = github.pages(f"actions/workflows/proxy-rust.yml/runs?{query}", "workflow_runs")
        pending = False
        for run in runs:
            if (run["path"] != HOST_WORKFLOW or run["event"] not in {"schedule", "workflow_dispatch"}
                    or run["head_branch"] != branch or run["head_sha"] != source):
                continue
            jobs = github.pages(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
            ready = any(job["name"] == "guest-inputs (amd64) / build"
                        and job["status"] == "completed" and job["conclusion"] == "success" for job in jobs)
            artifacts = github.pages(f"actions/runs/{run['id']}/artifacts", "artifacts")
            if ready and any(row["name"] == HOST_ARTIFACT and not row["expired"] for row in artifacts):
                return run["id"]
            pending |= run["status"] != "completed"
        if not dispatched and not pending:
            if github.api(f"commits/{branch}")["sha"] != source:
                raise ValueError("exact production is missing and merge is no longer the default-branch head")
            # Record intent before POST. A lost response never causes another POST.
            (attempt / "production-dispatch.json").write_text(json.dumps({"source_revision": source}))
            github.api("actions/workflows/proxy-rust.yml/dispatches", {
                "ref": branch, "inputs": {"packages_only": "true", "source_revision": source,
                                           "package_architecture": "amd64"}})
            dispatched = True
        if time.monotonic() >= deadline:
            raise ValueError("exact production artifact did not become ready before the deadline")
        time.sleep(min(30, max(0, deadline - time.monotonic())))


def remote_command(config: dict, request: dict, output: str) -> str:
    arguments = [".venv/bin/python", "scripts/run_claude_blackbox.py", request["trigger"],
                 "--ref", request["ref"], "--output", output]
    for field in ("source_revision", "host_run", "guest_index"):
        if request.get(field) is not None:
            arguments += ["--" + field.replace("_", "-"), str(request[field])]
    return ("set -euo pipefail\numask 077\n"
            f"cd {shlex.quote(config['controller'])}\n"
            f"test \"$(git rev-parse HEAD)\" = {shlex.quote(config['controller_revision'])}\n"
            f"export CLAUDE_EVENT_RUN={shlex.quote(str(request['event_run']))}\n"
            f"export CLAUDE_EVENT_OUTPUT={shlex.quote(output)}\n"
            f"source {shlex.quote(config['binding'])}\n"
            ": \"${CLAUDE_PROVISION:?}\" \"${CLAUDE_CREDENTIAL:?}\"\n"
            + shlex.join(arguments) + ' --provision "$CLAUDE_PROVISION" --credential "$CLAUDE_CREDENTIAL"\n')


def harness(config: dict, attempt: Path, name: str, *arguments: str) -> tuple[int, dict]:
    """Keep wrapper output private and decode its final existing receipt."""
    path = attempt / f"{name}-private.log"
    with path.open("xb") as log:
        result = subprocess.run(["bash", str(Path(config.get("jobs", "/var/lib/rundeck/harness/jobs")) / f"{name}.sh"),
                                 config["host"], *arguments], stdout=log, stderr=subprocess.STDOUT, check=False)
    receipts = [line.removeprefix(b"HARNESS_JSON:") for line in path.read_bytes().splitlines()
                if line.startswith(b"HARNESS_JSON:")]
    if not receipts:
        raise ValueError(f"{name} did not return a receipt; inspect the existing attempt before any resubmission")
    return result.returncode, json.loads(receipts[-1])


def fetch_report(config: dict, attempt: Path, remote_output: str) -> str:
    code, receipt = harness(config, attempt, "ssh_fetch", remote_output + "/result.json", "8388608")
    if code != 0 or receipt.get("truncated") is not False:
        raise ValueError("report fetch failed or was truncated")
    data = base64.b64decode(receipt["content_b64"], validate=True)
    checksum = hashlib.sha256(data).hexdigest()
    if checksum != receipt["sha256"]:
        raise ValueError("returned report checksum differs")
    report = json.loads(data)
    if not isinstance(report, dict) or type(report.get("exit")) is not int:
        raise ValueError("returned report is invalid")
    (attempt / "result.json").write_bytes(data)
    return checksum


def execute(config: dict, request: dict, attempt: Path) -> dict:
    remote_output = str(Path(config["remote_attempts"]) / f"{request['event_run']}-{request['event_attempt']}")
    receipt = {"event": request, "controller_revision": config["controller_revision"],
               "remote_output": remote_output, "exit": 2, "guest_exit": None,
               "timed_out": None, "report_sha256": None}
    command = base64.b64encode(remote_command(config, request, remote_output).encode()).decode()
    try:
        code, execution = harness(config, attempt, "ssh_exec", command, str(config.get("execution_timeout", 7200)))
        timed_out = execution["timed_out"]
        if type(timed_out) is not bool:
            raise ValueError("invalid SSH execution receipt")
        receipt.update(wrapper_exit=code, timed_out=timed_out)
        if timed_out:
            receipt["exit"] = 124
        guest_exit = execution.get("exit_code")
        if guest_exit is not None or not timed_out:
            if type(guest_exit) is not int or not 0 <= guest_exit <= 255:
                raise ValueError("invalid SSH guest exit")
            receipt["guest_exit"] = guest_exit
        if not timed_out:
            receipt["exit"] = guest_exit or code
    except (OSError, ValueError, KeyError, TypeError) as exc:
        receipt["execution_failure"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    # Fetch is deliberately independent of guest exit and wrapper success.
    try:
        receipt["report_sha256"] = fetch_report(config, attempt, remote_output)
        report = json.loads((attempt / "result.json").read_bytes())
        if report["exit"] != receipt["guest_exit"]:
            raise ValueError("report exit differs from the actual guest exit")
        if (report.get("trigger") != request["trigger"] or report.get("ref") != request["ref"]
                or report.get("controller_revision") != config["controller_revision"]):
            raise ValueError("returned report differs from the invocation")
        if request["trigger"] == "merge" and (report.get("requested_revision") != request["source_revision"]
                or report.get("selection", {}).get("host", {}).get("source_revision") != request["source_revision"]):
            raise ValueError("returned report does not bind the merged source")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        receipt["report_failure"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        receipt["exit"] = receipt["exit"] or 2
    return receipt


def consume(config: dict, github: GitHub, run: dict, branch: str) -> dict | None:
    if run["event"] == "workflow_run":
        jobs = github.pages(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
        if any(job["name"] == "Record trusted Claude invocation" and job["conclusion"] == "skipped" for job in jobs):
            # Native scheduled, dispatched and PR producers do not emit merge requests.
            return None
    attempt = Path(config["attempts"]) / f"{run['id']}-{run['run_attempt']}"
    try:
        attempt.mkdir(mode=0o700)
    except FileExistsError:
        # Existing evidence may describe a completed or uncertain launch. Never replay it.
        return None
    result = {"event_run": run["id"], "exit": 2, "stage": "event-admission"}
    try:
        request = request_for_run(github, run, branch)
        (attempt / "event.json").write_text(json.dumps(request, indent=2) + "\n")
        if request["trigger"] == "merge":
            result["stage"] = "exact-production"
            request["host_run"] = production_run(github, branch, request["source_revision"], attempt,
                                                 config.get("production_timeout", 7200))
        result = execute(config, request, attempt)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        result["failure"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    result["finished_at"] = datetime.now(UTC).isoformat()
    (attempt / "transport.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="Private operator-owned deployment JSON")
    parser.add_argument("--event-run", type=int, help="Consume one Actions run; omit to collect completed events since activation")
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_bytes())
    root = Path(config["attempts"])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Rundeck's multipleExecutions=false serializes this job. The atomic attempt
    # mkdir also prevents two manual submissions from launching the same event.
    with (root / "github-private.log").open("ab") as log:
        github = GitHub(log)
        branch = github.api("")["default_branch"]
        if args.event_run is not None:
            runs = [github.api(f"actions/runs/{args.event_run}")]
        else:
            query = urlencode({"status": "completed", "branch": branch, "created": ">=" + config["enabled_since"]})
            utc(config["enabled_since"])
            runs = github.pages(f"actions/workflows/blackbox.yml/runs?{query}", "workflow_runs")
        status = 0
        for run in sorted(runs, key=lambda row: row["id"]):
            result = consume(config, github, run, branch)
            if result is not None:
                report = root / f"{run['id']}-{run['run_attempt']}" / "result.json"
                if result.get("report_sha256"):
                    print("CLAUDE_RESULT:" + json.dumps(json.loads(report.read_bytes())))
                print("CLAUDE_TRANSPORT:" + json.dumps(result))
                status = status or result["exit"]
        return status


if __name__ == "__main__":
    raise SystemExit(main())
