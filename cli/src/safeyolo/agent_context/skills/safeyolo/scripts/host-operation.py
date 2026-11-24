#!/usr/bin/env python3
"""Use a task-bound host binding through the ordinary Agent API; never retry."""

from __future__ import annotations

import argparse
import hashlib
import http.client
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
    http_status = None
    try:
        try:
            response = urllib.request.build_opener(NoRedirect()).open(operation, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
            http_status = error.code
        # Error responses can also be truncated or undecodable after an effect.
        # Read both kinds through the same uncertain/unavailable failure path.
        with response:
            result = json.load(response)
    except (http.client.HTTPException, urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        failure = {
            "error": str(error), "request_id": None if value is None else value.get("request_id"),
            "execution_outcome": "uncertain" if value and value["action"]["kind"] in {"invoke", "cancel"} else "unavailable",
            "next_action": "Inspect the original request/job through this binding or ask its target operator; no request was retried.",
        }
        if http_status is not None:
            failure["http_status"] = http_status
        raise RequestFailed(failure) from error
    if http_status is not None:
        # Preserve valid private assessments/refusals as returned. A notification
        # or challenge is not permission to submit the original invocation again.
        raise RequestFailed(result) from response
    return result


def call(binding: str, request_id: str, action: dict[str, Any], expected: Any = None) -> dict[str, Any]:
    return request("/gateway/host/" + urllib.parse.quote(binding, safe=":"), {
        "request_id": request_id, "expected": expected, "action": action,
    })


def invoke(args: argparse.Namespace) -> dict[str, Any]:
    preparation = json.loads(Path(args.prepared).read_text())["prepared"]
    bindings = request("/gateway/host")["host_bindings"]
    binding = next((item for item in bindings if item["binding"] == args.binding), None)
    if binding is None:
        raise RequestFailed({"error": "Binding is unavailable to this current run/task", "request_id": args.request_id,
                             "next_action": "Rediscover the selected binding; no invocation was sent."})
    # Match the native ledger's canonical tuple before sending the effect.
    # Retain this original target context if the complete reply is lost.
    identity = [binding["target_id"], binding["issuer_id"], args.request_id]
    job_id = "job-" + hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    try:
        return call(args.binding, args.request_id, {
            "kind": "invoke", "invocation": preparation["invocation"],
        }, preparation["revisions"])
    except RequestFailed as error:
        if error.value.get("execution_outcome") == "uncertain":
            # A received gateway diagnostic has its own authoritative job
            # context. Supply the pre-dispatch context only when absent.
            error.value.setdefault("possible_job_id", job_id)
            error.value.setdefault("target_id", binding["target_id"])
            error.value.setdefault("host_binding", args.binding)
        raise


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "bindings":
        return request("/gateway/host")
    if args.command == "discover":
        return call(args.binding, args.request_id, {"kind": "discover"})
    if args.command == "invoke":
        return invoke(args)
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
    if args.command in {"output", "file"}:
        action.update(offset=args.offset, max_bytes=args.bytes)
    if args.command == "file":
        action.update(path=args.path, expected_file_revision=args.file_revision)
    if args.command == "cancel":
        action["expected_revision"] = args.revision
    try:
        return call(args.binding, args.request_id, action, discovery["revisions"])
    except RequestFailed as error:
        if args.command == "cancel" and error.value.get("execution_outcome") == "uncertain":
            error.value.setdefault("possible_job_id", args.job)
            error.value.setdefault("target_id", discovery["target_id"])
            error.value.setdefault("host_binding", args.binding)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bindings", help="Current bindings for this trusted run and active task")
    for command in ("discover", "propose", "invoke", "job", "output", "file", "cancel"):
        sub = commands.add_parser(command)
        sub.add_argument("binding")
        sub.add_argument("--request-id", required=True, help="Retain this exact ID with the original result")
        if command == "propose":
            sub.add_argument("--operation", required=True)
            sub.add_argument("--resource", required=True)
            sub.add_argument("--arguments", help="JSON object; literal typed values, never script text")
        elif command == "invoke":
            sub.add_argument("--prepared", required=True, help="Unchanged successful proposal JSON")
        elif command in ("job", "output", "file", "cancel"):
            sub.add_argument("--job", required=True)
            if command in {"output", "file"}:
                sub.add_argument("--offset", type=int, default=0)
                sub.add_argument("--bytes", type=int, default=65536)
            if command == "file":
                sub.add_argument("--path", required=True, help="Absolute target path within the job's selected writable scope")
                sub.add_argument("--file-revision", help="Observed file revision required for subsequent chunks")
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
