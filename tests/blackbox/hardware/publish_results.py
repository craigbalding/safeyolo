"""Retain independent hardware attempts and publish only selected result fields.

The GitHub comment client and bounded report reader reuse the #889 wrappers at
4fc6e11c07ea308d053873bbec59a07baa43e1a7. Installed results now identify retained
host/guest artifacts, separately from the trusted test controller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    from tests.blackbox.installed_sections import SECTIONS
else:
    from ..installed_sections import SECTIONS

REPOSITORY = "craigbalding/safeyolo"
ISSUE = 889
MAX_REPORT_BYTES = 8 * 1024 * 1024


def read_json(path: Path) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ValueError("report must be a bounded regular file")
        data = stream.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("report grew beyond the read bound")
    document = json.loads(data)
    if not isinstance(document, dict):
        raise ValueError("report must contain a JSON mapping")
    return document


def check_ports() -> None:
    """Reuse #889's read-only fixture-port probe; never signal another owner."""
    for port in (*range(46370, 46376), 46377, 46378):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))


class GitHubResults:
    """Reuse the operator's gh principal, outside candidate authority."""

    def api(self, endpoint: str, method: str = "GET", body: str | None = None) -> dict:
        command = ["gh", "api", f"repos/{REPOSITORY}/{endpoint}", "--method", method]
        options = {"capture_output": True, "text": True, "timeout": 60, "check": True}
        if body is not None:
            command += ["--input", "-"]
            options["input"] = json.dumps({"body": body})
        data = json.loads(subprocess.run(command, **options).stdout)
        if not isinstance(data, dict):
            raise ValueError("GitHub returned an invalid comment")
        return data

    def comment(self, body: str, comment_id: int | None = None) -> dict:
        if comment_id is not None:
            previous = self.api(f"issues/comments/{comment_id}")
            if previous.get("body", "").splitlines()[:1] != body.splitlines()[:1]:
                raise ValueError("index update does not belong to this hardware attempt")
        endpoint = f"issues/{ISSUE}/comments" if comment_id is None else f"issues/comments/{comment_id}"
        response = self.api(endpoint, "POST" if comment_id is None else "PATCH", body)
        identifier = response["id"]
        url = f"https://github.com/{REPOSITORY}/issues/{ISSUE}#issuecomment-{identifier}"
        if type(identifier) is not int or identifier <= 0 or response.get("html_url") != url or response.get("body") != body:
            raise ValueError("GitHub comment response differs from submitted report")
        observed = self.api(f"issues/comments/{identifier}")
        if observed.get("id") != identifier or observed.get("html_url") != url or observed.get("body") != body:
            raise ValueError("published report could not be read back exactly")
        return {"id": identifier, "url": url, "sha256": hashlib.sha256(body.encode()).hexdigest()}


def save(directory: Path, attempt: dict) -> None:
    temporary = directory / "attempt.json.tmp"
    temporary.write_text(json.dumps(attempt, indent=2) + "\n")
    temporary.replace(directory / "attempt.json")


def publish(directory: Path, attempt: dict, github: GitHubResults) -> None:
    marker = f"Hardware attempt `{attempt['run_id']}` — {attempt['lane']}"
    # Only this explicitly selected record reaches GitHub. Private logs,
    # instance paths, exception text and arbitrary candidate JSON stay private.
    public = {key: attempt[key] for key in ("run_id", "lane", "trigger", "controller_revision", "started_at",
                                          "finished_at", "exit", "cleanup", "stage", "inputs", "result")}
    body = marker + "\n\n```json\n" + json.dumps(public, indent=2) + "\n```\n\n"
    body += "Independent hardware acceptance remains with Lens. Separate nightly inputs are not an exact-release pass."
    previous = attempt.get("publication")
    if attempt.get("publication_uncertain") and previous is None:
        raise ValueError("initial publication is uncertain; inspect the existing attempt marker before any replay")
    attempt["publication_uncertain"] = True
    save(directory, attempt)
    attempt["publication"] = github.comment(body, previous["id"] if previous else None)
    attempt["publication_uncertain"] = False
    save(directory, attempt)


def begin(root: Path, lane: str, trigger: str) -> Path:
    run_id = uuid.uuid4().hex
    directory = root / run_id
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    revision = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"], text=True).strip():
        raise ValueError("hardware controller must be a clean pinned checkout")
    attempt = {"run_id": run_id, "owner": f"issue889-{run_id}", "controller_revision": revision,
               "lane": lane, "trigger": trigger, "started_at": datetime.now(UTC).isoformat(),
               "finished_at": None, "exit": None, "cleanup": "unverified", "stage": "selection",
               "inputs": None, "result": None, "publication": None}
    save(directory, attempt)
    print(directory, flush=True)
    publish(directory, attempt, GitHubResults())
    return directory


def finish(directory: Path, code: int, cleanup: str, stage: str, reports: Path | None) -> int:
    attempt = read_json(directory / "attempt.json")
    if attempt["finished_at"] is not None:
        raise ValueError("finished attempt is retained; retry in a new directory")
    attempt.update(exit=code, cleanup=cleanup, stage=stage, finished_at=datetime.now(UTC).isoformat())
    try:
        selection = read_json(directory / "inputs/selection.json")
        attempt["inputs"] = {key: selection[key] for key in ("platform", "default_branch_head", "controller_revision",
                                                            "host_build_age_seconds", "host", "guest")}
        if reports is not None:
            attempt["result"] = installed_result(reports, attempt["lane"], selection)
        if code == 0 and (cleanup != "verified" or not attempt["result"] or not attempt["result"]["complete"]):
            attempt.update(exit=2, stage="report")
    except (OSError, ValueError, TypeError, KeyError):
        # Keep the raw failed selection/report private, including added fields.
        if code == 0:
            attempt.update(exit=2, stage="report")
    save(directory, attempt)
    publish(directory, attempt, GitHubResults())
    return attempt["exit"]


def installed_result(reports: Path, lane: str, selection: dict) -> dict:
    run = read_json(reports / "retained-run.json")
    if read_json(reports / "selection.json") != selection:
        raise ValueError("hardware result contains a different frozen input selection")
    installed = read_json(reports / "installed-inputs.json")
    sections = read_json(reports / "guest/installed-sections.json")
    if (run["lane"] != lane or run["finished_at"] is None or sections["lane"] != lane
            or run["controller_dirty"] is not False or run["controller_revision"] != selection["controller_revision"]
            or sections["source_revision"] != selection["host"]["source_revision"]
            or installed["host_source_revision"] != selection["host"]["source_revision"]
            or installed["profile"] != "production" or installed["platform"] != selection["platform"]):
        raise ValueError("hardware report differs from selected installed artifacts")
    selected_at = datetime.fromisoformat(selection["selected_at"])
    if not selected_at <= datetime.fromisoformat(run["started_at"]) <= datetime.fromisoformat(run["finished_at"]) <= datetime.now(UTC):
        raise ValueError("hardware report is stale or has an invalid execution interval")
    for field, expected in (("index", "index"), ("manifest", "child"), ("archive", "archive")):
        if any(installed["guest"][field][key] != selection["guest"][expected][key] for key in ("digest", "size")):
            raise ValueError("hardware guest report differs from selected descriptors")
    rows = section_rows(sections["sections"], lane)
    names = [row["section"] for row in rows]
    identities = {name: installed["installed_files_sha256"][name] for name in selection["host"]["executables_sha256"]}
    if identities != selection["host"]["executables_sha256"]:
        raise ValueError("hardware executable bytes differ from the selected package")
    if any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in identities.values()):
        raise ValueError("hardware report has invalid executable hashes")
    if run["host_system"] != ("Darwin" if lane == "vz" else "Linux") or run["host_architecture"] not in {
        "arm64", "aarch64", "x86_64",
    }:
        raise ValueError("hardware report has invalid host identity")
    complete = (run["exit"] == 0 and sections["preparation"]["exit"] == 0 and names == list(SECTIONS[lane])
                and all(row == {"section": row["section"], "exit": 0, "result": "passed", "cleanup": "stopped"} for row in rows))
    return {"complete": complete, "sections": rows,
            "unexecuted_sections": [name for name in SECTIONS[lane] if name not in names],
            "skipped_assertions": None, "installed_files_sha256": identities,
            "host_system": run["host_system"], "host_architecture": run["host_architecture"]}


def section_rows(sections: list[dict], lane: str) -> list[dict]:
    rows = [{key: row[key] for key in ("section", "exit", "result", "cleanup")} for row in sections]
    for row in rows:
        if (type(row["exit"]) is not int or not 0 <= row["exit"] <= 255
                or row["cleanup"] not in {"stopped", "failed"}
                or row["result"] not in {"passed", "assertion_failure", "preparation_failure", "cleanup_failure"}):
            raise ValueError("hardware section has invalid result fields")
    names = [row["section"] for row in rows]
    if len(set(names)) != len(names) or set(names) - set(SECTIONS[lane]):
        raise ValueError("hardware report has duplicate or unsupported sections")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("begin", "finish", "publish", "ports"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--lane", choices=("kvm", "vz"))
    parser.add_argument("--trigger", choices=("overnight", "on-demand"))
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--exit", type=int, default=2)
    parser.add_argument("--cleanup", choices=("unverified", "failed", "verified"), default="unverified")
    parser.add_argument("--stage", choices=("selection", "preflight", "allocation", "transfer", "execution", "cleanup", "report", "complete"), default="execution")
    parser.add_argument("--reports", type=Path)
    args = parser.parse_args()
    if args.operation == "ports":
        check_ports()
        return 0
    if args.operation == "begin":
        if args.root is None or args.lane is None or args.trigger is None:
            parser.error("begin requires --root, --lane and --trigger")
        begin(args.root, args.lane, args.trigger)
        return 0
    if args.attempt is None:
        parser.error("--attempt is required")
    if args.operation == "publish":
        publish(args.attempt, read_json(args.attempt / "attempt.json"), GitHubResults())
        return 0
    return finish(args.attempt, args.exit, args.cleanup, args.stage, args.reports)


if __name__ == "__main__":
    raise SystemExit(main())
