#!/usr/bin/env python3
"""Publish one new bot mention per material assurance delta, using trusted reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import quote

REPOSITORY = "craigbalding/safeyolo"
BOT = "github-actions[bot]"
MARKER = re.compile(r"<!-- safeyolo-bb-delta:([0-9a-f]{64}) -->")
SHA = re.compile(r"[0-9a-f]{40}")
MAX_REPORT = 1024 * 1024


def api(endpoint: str, payload: dict | None = None):
    """Use the provisioned GitHub CLI; never put its token in arguments."""
    command = ["gh", "api", f"repos/{REPOSITORY}/{endpoint}"]
    if payload is not None:
        command.extend(["--method", "POST", "--input", "-"])
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True, check=True, timeout=120)
    if len(result.stdout) > 8 * MAX_REPORT:
        raise ValueError("GitHub response exceeds byte bound")
    return json.loads(result.stdout)


def pages(endpoint: str) -> list[dict]:
    rows = []
    for page in range(1, 21):
        separator = "&" if "?" in endpoint else "?"
        batch = api(f"{endpoint}{separator}per_page=100&page={page}")
        if not isinstance(batch, list):
            raise ValueError("expected a GitHub list")
        rows.extend(batch)
        if len(batch) < 100:
            return rows
    raise ValueError("GitHub history exceeds page bound; deduplication is unknown")


def event_context(event: dict, kind: str) -> dict:
    """Use canonical event operands, never PR titles, labels or author verdicts."""
    if event["repository"]["full_name"] != REPOSITORY:
        raise ValueError("unexpected repository")
    branch = event["repository"]["default_branch"]
    if kind == "pull_request_target":
        pr = event["pull_request"]
        if pr["base"]["repo"]["full_name"] != REPOSITORY or pr["base"]["ref"] != branch:
            raise ValueError("PR does not target the default branch")
        number = pr["number"]
        if type(number) is not int or number < 1:
            raise ValueError("invalid PR number")
        context = {"base": pr["base"]["sha"], "head": pr["head"]["sha"], "pr": number}
    elif kind == "push":
        if event["ref"] != "refs/heads/" + branch or event.get("deleted") or event.get("created"):
            raise ValueError("expected an update to the existing default branch")
        context = {"base": event["before"], "head": event["after"], "pr": None}
    else:
        raise ValueError("unsupported event; nightly execution cannot publish change notices")
    if not all(SHA.fullmatch(context[key]) and context[key] != "0" * 40 for key in ("base", "head")):
        raise ValueError("event must supply full nonzero commits")
    return context


def validate_report(report: dict, context: dict) -> list[dict]:
    if (report.get("schema") != 1 or report.get("status") != "complete"
            or report.get("trusted_base") != context["base"] or report.get("head") != context["head"]
            or not isinstance(report.get("base"), str) or not SHA.fullmatch(report["base"])
            or context["pr"] is None and report["base"] != context["base"]):
        raise ValueError("analysis is missing, failed or bound to a different event")
    rows = report.get("changes")
    if not isinstance(rows, list) or len(rows) > 500:
        raise ValueError("invalid report rows")
    material = []
    for row in rows:
        if (not isinstance(row, dict) or row.get("status") not in {"material", "mechanical", "context", "unclassified"}
                or not isinstance(row.get("path"), str) or len(row["path"]) > 600
                or not isinstance(row.get("reason"), str) or len(row["reason"]) > 200
                or not isinstance(row.get("controls"), list) or len(row["controls"]) > 37
                or any(not isinstance(control, str) or not re.fullmatch(r"BB-(?:0[1-9]|[12][0-9]|3[0-7])", control) for control in row["controls"])):
            raise ValueError("invalid change record")
        if row["status"] == "material":
            if row["reason"] not in {"notification, catalogue or trusted analysis definition changed",
                                     "effective test configuration changed (dependencies are excluded)",
                                     "executable witness, helper, oracle or required selection changed"}:
                raise ValueError("unknown notification reason")
            edits = row.get("edits", [])
            if (not isinstance(edits, list) or len(edits) > 1000
                    or any(not isinstance(edit, dict) or edit.get("change") not in {"added", "removed", "changed"}
                           or not isinstance(edit.get("unit"), str) or len(edit["unit"]) > 200 for edit in edits)):
                raise ValueError("invalid executable delta")
            material.append(row)
    delta = report.get("delta_id")
    if (material and (not isinstance(delta, str) or not re.fullmatch(r"[0-9a-f]{64}", delta))
            or not material and delta is not None):
        raise ValueError("invalid material delta identity")
    return material


def notices(comments: list[dict]) -> set[str]:
    return {match[1] for comment in comments
            if comment.get("user", {}).get("login") == BOT and comment["user"].get("type") == "Bot"
            for match in MARKER.finditer(comment.get("body", ""))}


def notice_body(report: dict, context: dict, material: list[dict]) -> str:
    prefix = f"https://github.com/{REPOSITORY}"
    controls = sorted({control for row in material for control in row["controls"]})
    target = f"[PR #{context['pr']}]({prefix}/pull/{context['pr']})" if context["pr"] else "Direct default-branch change"
    lines = [f"@craigbalding {target} changes blackbox assurance" + (f" ({', '.join(controls)})" if controls else " (control IDs not mapped)") + ".", ""]
    for row in material[:8]:
        # Candidate text cannot inject another mention, Markdown or a destination.
        path = quote(row["path"], safe="/")
        label = row["path"].rsplit("/", 1)[-1]
        label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
        changes = ", ".join(re.sub(r"[^A-Za-z0-9_<># .-]", "_", edit["change"] + " " + edit["unit"]) for edit in row.get("edits", [])[:3])
        detail = f"; {changes}" if changes else ""
        lines.append(f"- [{label}]({prefix}/blob/{context['head']}/{path}): {row['reason']}{detail}.")
    if len(material) > 8:
        lines.append(f"- {len(material) - 8} more affected inputs are listed in the check report.")
    separator = "..." if context["pr"] else ".."
    lines += ["", f"[Base {context['base'][:12]}]({prefix}/commit/{context['base']}) · "
              f"[head {context['head'][:12]}]({prefix}/commit/{context['head']}) · "
              f"[exact diff]({prefix}/compare/{context['base']}{separator}{context['head']})", "",
              "Change awareness only; this notice requests no approval.",
              f"<!-- safeyolo-bb-delta:{report['delta_id']} -->"]
    return "\n".join(lines)


def publish(report: dict, event: dict, kind: str) -> dict:
    context = event_context(event, kind)
    material = validate_report(report, context)
    context = context | {"base": report["base"]}
    if not material:
        return {"status": "quiet", "reason": "no material assurance delta"}
    delta = report["delta_id"]
    if context["pr"]:
        # A delayed event must not publish obsolete assurance as the current PR.
        current = api(f"pulls/{context['pr']}")
        if current["head"]["sha"] != context["head"]:
            return {"status": "superseded", "reason": "PR head advanced before publication"}
        endpoint = f"issues/{context['pr']}/comments"
        known = notices(pages(endpoint)) | notices(pages("issues/1557/comments"))
    else:
        # Use the existing assurance epic rather than granting contents:write
        # solely to create commit comments. Exact commits and diff remain linked.
        endpoint = "issues/1557/comments"
        known = notices(pages(endpoint))
        # Suppress a merge already notified through its PR, including squash and
        # rebase merges. A direct change without a matching notice still publishes.
        for pr in pages(f"commits/{context['head']}/pulls"):
            if pr.get("merged_at") and pr["base"]["repo"]["full_name"] == REPOSITORY:
                known.update(notices(pages(f"issues/{int(pr['number'])}/comments")))
    if delta in known:
        return {"status": "duplicate", "delta_id": delta}
    body = notice_body(report, context, material)
    # No automatic POST retry: after an ambiguous response, the next invocation
    # first reads canonical bot comments and recovers the original marker.
    comment = api(endpoint, {"body": body})
    if comment.get("user", {}).get("login") != BOT or comment["user"].get("type") != "Bot":
        raise ValueError("comment was not published by the required trusted bot")
    if comment.get("body") != body or not comment.get("html_url"):
        raise ValueError("GitHub did not return the exact published notice")
    return {"status": "published", "delta_id": delta, "url": comment["html_url"],
            "comment_id": comment["id"], "body_sha256": hashlib.sha256(body.encode()).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise ValueError("publication requires the Actions bot's scoped GITHUB_TOKEN")
        if args.report.stat().st_size > MAX_REPORT:
            raise ValueError("analysis report exceeds byte bound")
        report = json.loads(args.report.read_text())
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        result = publish(report, event, os.environ["GITHUB_EVENT_NAME"])
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        # A broken analysis or publication is visible, never a quiet success.
        result = {"status": "failed", "error": type(error).__name__ + ": " + str(error)[:500]}
    args.result.write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
