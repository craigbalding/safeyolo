#!/usr/bin/env python3
"""Use a task-bound host binding through the ordinary Agent API; never retry."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = "http://_safeyolo.proxy.internal"
TOKEN_PATH = Path("/app/agent_token")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RequestFailed(Exception):
    def __init__(self, value: dict[str, Any]):
        self.value = value


def request(path: str, value: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if value is None else json.dumps(value).encode()
    operation = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers={
            "Authorization": "Bearer " + TOKEN_PATH.read_text().strip(),
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(operation, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Preserve private assessments/refusals as returned. A notification or
        # challenge is not permission to submit the original invocation again.
        try:
            result = json.load(error)
        except (ValueError, UnicodeDecodeError):
            result = {"error": "Agent API returned a non-JSON error", "http_status": error.code}
        raise RequestFailed(result) from error
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        raise RequestFailed({
            "error": str(error), "request_id": None if value is None else value.get("request_id"),
            "execution_outcome": "uncertain" if value and value["action"]["kind"] == "invoke" else "unavailable",
            "next_action": "Inspect the original request/job through this binding or ask its target operator; no request was retried.",
        }) from error


def call(binding: str, request_id: str, action: dict[str, Any], expected: Any = None) -> dict[str, Any]:
    return request("/gateway/host/" + urllib.parse.quote(binding, safe=":"), {
        "request_id": request_id, "expected": expected, "action": action,
    })


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "bindings":
        return request("/gateway/host")
    if args.command == "discover":
        return call(args.binding, args.request_id, {"kind": "discover"})
    if args.command == "invoke":
        preparation = json.loads(Path(args.prepared).read_text())["prepared"]
        return call(args.binding, args.request_id, {
            "kind": "invoke", "invocation": preparation["invocation"],
        }, preparation["revisions"])
    discovery = call(args.binding, args.request_id + "-discovery", {"kind": "discover"})["discovery"]
    if args.command == "propose":
        operation = next((op for op in discovery["operations"] if op["operation_id"] == args.operation), None)
        if operation is None:
            raise RequestFailed({"error": "Operation is unavailable in current discovery", "operation": args.operation,
                                 "next_action": "Propose missing capability for private assessment; discovery cannot adopt code or widen the target ceiling."})
        arguments = {} if args.arguments is None else json.loads(Path(args.arguments).read_text())
        return call(args.binding, args.request_id, {"kind": "propose", "invocation": {
            "operation_id": args.operation, "resource_id": args.resource,
            "operation_sha256": operation["operation_sha256"],
            "implementation_sha256": operation["implementation_sha256"],
            "arguments": arguments, "expected_assessment_sha256": None,
        }}, operation["revisions"])
    action = {"kind": args.command, "job_id": args.job}
    if args.command == "output":
        action.update(offset=args.offset, max_bytes=args.bytes)
    if args.command == "cancel":
        action["expected_revision"] = args.revision
    return call(args.binding, args.request_id, action, discovery["revisions"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bindings", help="Current bindings for this trusted run and active task")
    for command in ("discover", "propose", "invoke", "job", "output", "cancel"):
        sub = commands.add_parser(command)
        sub.add_argument("binding")
        sub.add_argument("--request-id", required=True, help="Retain this exact ID with the original result")
        if command == "propose":
            sub.add_argument("--operation", required=True)
            sub.add_argument("--resource", required=True)
            sub.add_argument("--arguments", help="JSON object; literal typed values, never script text")
        elif command == "invoke":
            sub.add_argument("--prepared", required=True, help="Unchanged successful proposal JSON")
        elif command in ("job", "output", "cancel"):
            sub.add_argument("--job", required=True)
            if command == "output":
                sub.add_argument("--offset", type=int, default=0)
                sub.add_argument("--bytes", type=int, default=65536)
            if command == "cancel":
                sub.add_argument("--revision", type=int, required=True)
    args = parser.parse_args()
    try:
        result = run(args)
    except RequestFailed as error:
        print(json.dumps(error.value, indent=2))
        return 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"error": str(error), "next_action": "Check the selected input and original result; no automatic retry."}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
