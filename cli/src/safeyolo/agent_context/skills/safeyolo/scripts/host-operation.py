#!/usr/bin/env python3
"""Use a task-bound host binding through the ordinary Agent API; never retry."""

from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
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
            "error": str(error), "request_id": None if value is None else value.get("request_id", value.get("operation_id")),
            "execution_outcome": "uncertain" if value and (value.get("action", {}).get("kind") in {"invoke", "cancel", "adopt"} or path == "/gateway/host-setup" or path.endswith("/resume")) else "unavailable",
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


def adopt_code(args: argparse.Namespace, script: str | None = None) -> dict[str, Any]:
    bindings = request("/gateway/host")["host_bindings"]
    binding = next((item for item in bindings if item["binding"] == args.binding), None)
    if binding is None or not binding.get("task_active", True):
        raise RequestFailed({"error": "Binding requires its eligible active task", "host_binding": args.binding,
                             "next_action": "Read the binding, then resume its adopted task when permitted; no code was sent."})
    discovery = call(args.binding, args.request_id + "-discovery", {"kind": "discover"})["discovery"]
    if getattr(args, "definition", None):
        operation = json.loads(Path(args.definition).read_text())
    else:
        family = next((item for item in binding.get("agent_code_classes", [])
                       if args.operation.startswith(item["prefix"]) and args.operation not in item["excluded"]), None)
        if family is None:
            raise RequestFailed({"error": "No standing agent-code class covers this operation", "operation": args.operation,
                                 "next_action": "Prepare the specific authority expansion through private policy assessment and existing review."})
        operation = copy.deepcopy(family["rule"]["ceiling"])
        if operation["execution"]["argv"][:1] != [{"kind": "literal", "value": "-c"}]:
            raise ValueError("The selected class uses another command recipe; supply its complete --definition")
        if script is None:
            script = Path(args.script).read_text()
        operation["execution"]["argv"] = [{"kind": "literal", "value": "-c"}, {"kind": "literal", "value": script}]
        if args.command == "stage":
            # A byte-staging job has no service to start. Do not inherit a
            # listening socket or reserve the service's candidate ports.
            operation["execution"]["network"] = {"destinations": [], "listeners": [], "ipc": []}
            # Drop the Mac class's broader process lifetime for this fixed
            # single-interpreter recipe. Other backends retain their runtime
            # overhead budget (Linux pids.max includes its sandbox launcher).
            if "processes" in operation["execution"].get("broader", []):
                operation["execution"]["resources"]["processes"] = 1
            if "broader" in operation["execution"]:
                operation["execution"]["broader"] = [bound for bound in operation["execution"]["broader"] if bound not in {"network_ipc", "processes"}]
        if getattr(args, "dependencies", None):
            operation["execution"]["dependencies"] = json.loads(Path(args.dependencies).read_text())
    try:
        return call(args.binding, args.request_id, {"kind": "adopt", "operation_id": args.operation,
                    "operation": operation, "base_package_sha256": discovery["package_sha256"]}, discovery["revisions"])
    except RequestFailed as error:
        if error.value.get("execution_outcome") == "uncertain":
            error.value.setdefault("host_binding", args.binding)
            error.value.setdefault("target_id", binding["target_id"])
            error.value["next_action"] = "Read adoption --original-request-id with this original request ID. No program was invoked or request retried."
        raise


def stage(args: argparse.Namespace) -> dict[str, Any]:
    # POSIX printf avoids a target-side decoder dependency and carries NUL and
    # non-UTF-8 bytes without putting either into an argv string.
    encoded = "".join(f"\\0{byte:03o}" for byte in Path(args.file).read_bytes())
    script = "printf '%b' " + shlex.quote(encoded) + " > " + shlex.quote(args.path)
    adoption_args = copy.copy(args)
    adoption_args.operation = "task:stage"
    adoption_args.command = "stage"
    adoption_args.request_id += "-adopt"
    adoption = adopt_code(adoption_args, script)
    try:
        return stage_adopted(args, adoption)
    except RequestFailed as error:
        error.value["adoption"] = adoption
        error.value["stage_request_id"] = args.request_id
        error.value.setdefault("host_binding", args.binding)
        error.value["next_action"] = error.value.get("next_action", "Inspect the original result before another effect.") + " The completed code adoption is retained below; inspect it before preparing another stage."
        raise


def stage_adopted(args: argparse.Namespace, adoption: dict[str, Any]) -> dict[str, Any]:
    """Prepare and invoke the selected staging revision, retaining its adoption."""
    original = adoption["original"]["request"]
    discovery = call(args.binding, args.request_id + "-discovery", {"kind": "discover"})["discovery"]
    operation = next((item for item in discovery["operations"] if item["operation_id"] == "task:stage"), None)
    if discovery["target_id"] != original["target_id"] or operation is None or operation["operation_sha256"] != adoption["operation_sha256"]:
        raise RequestFailed({"error": "The staging target or operation changed after this call adopted its selected bytes",
                             "request_id": args.request_id, "adoption": adoption, "host_binding": args.binding,
                             "execution_outcome": "unavailable",
                             "next_action": "Inspect this original adoption and the current catalogue before preparing another stage. No staging program was invoked."})
    preparation = call(args.binding, args.request_id + "-propose", {"kind": "propose", "invocation": {
        "operation_id": "task:stage", "resource_id": "task:workspace", "operation_sha256": operation["operation_sha256"],
        "implementation_sha256": operation["implementation_sha256"], "arguments": {}, "expected_assessment_sha256": None,
    }}, operation["revisions"])["prepared"]
    try:
        result = call(args.binding, args.request_id + "-invoke", {"kind": "invoke", "invocation": preparation["invocation"]}, preparation["revisions"])
    except RequestFailed as error:
        if error.value.get("execution_outcome") == "uncertain":
            error.value.setdefault("host_binding", args.binding)
            identity = [original["target_id"], original["issuer_id"], args.request_id + "-invoke"]
            error.value.setdefault("possible_job_id", "job-" + hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest())
            error.value.setdefault("target_id", original["target_id"])
            error.value["next_action"] = "Inspect the original stage invocation's target job before any retry. The file may already exist."
        raise
    return {"request_id": args.request_id, "adoption": adoption, "target_result": result,
            "file_state": "inspect the target job and selected file; admission alone does not establish a completed write"}


def setup(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "setup-status":
        owner = "/approvals/" if getattr(args, "submitted", False) else "/gateway/host-setup/"
        return request(owner + urllib.parse.quote(args.original_request_id, safe=""))
    field = "plan" if args.command == "setup" else "enrolment"
    value = {"kind": "prepare" if args.command == "setup" else "submit", "operation_id": args.request_id,
             field: json.loads(Path(getattr(args, field)).read_text())}
    try:
        return request("/gateway/host-setup", value)
    except RequestFailed as error:
        error.value.setdefault("request_id", args.request_id)
        submitted = " --submitted" if args.command == "submit-setup" else ""
        error.value["recovery_command"] = f"setup-status{submitted} --original-request-id {shlex.quote(args.request_id)}"
        raise


def resume(args: argparse.Namespace) -> dict[str, Any]:
    return request("/gateway/host/" + urllib.parse.quote(args.binding, safe=":") + "/resume", {"request_id": args.request_id})


def run(args: argparse.Namespace) -> dict[str, Any]:
    handler = {"setup": setup, "submit-setup": setup, "setup-status": setup, "resume": resume, "adopt": adopt_code, "stage": stage}.get(args.command)
    if handler is not None:
        return handler(args)
    if args.command == "bindings":
        return request("/gateway/host")
    if args.command == "discover":
        return call(args.binding, args.request_id, {"kind": "discover"})
    if args.command == "invoke":
        return invoke(args)
    if args.command == "adoption":
        # Recovery must work when the target committed code but the issuer
        # still has its old package. Discovery deliberately refuses that split.
        return call(args.binding, args.request_id, {"kind": "adoption", "request_id": args.original_request_id})
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
    for command in ("setup", "submit-setup"):
        sub = commands.add_parser(command)
        sub.add_argument("--request-id", default="req-" + uuid.uuid4().hex)
        sub.add_argument("--plan" if command == "setup" else "--enrolment", required=True)
    sub = commands.add_parser("setup-status")
    sub.add_argument("--original-request-id", required=True)
    sub.add_argument("--submitted", action="store_true", help="Read the original submitted policy-change request instead of its signing preparation")
    for command in ("discover", "propose", "invoke", "job", "output", "file", "cancel", "resume", "adopt", "adoption", "stage"):
        sub = commands.add_parser(command)
        sub.add_argument("binding")
        sub.add_argument("--request-id", default="req-" + uuid.uuid4().hex, help="Generated when absent; retain the exact ID with the original result")
        if command == "propose":
            sub.add_argument("--operation", required=True)
            sub.add_argument("--resource", required=True)
            sub.add_argument("--arguments", help="JSON object; literal typed values, never script text")
        elif command == "invoke":
            sub.add_argument("--prepared", required=True, help="Unchanged successful proposal JSON")
        elif command == "adopt":
            sub.add_argument("--operation", required=True)
            source = sub.add_mutually_exclusive_group(required=True)
            source.add_argument("--script", help="Task script for the adopted shell class")
            source.add_argument("--definition", help="Complete typed operation inside the adopted code class")
            sub.add_argument("--dependencies", help="Selected target dependency paths and exact SHA256/byte pins")
        elif command == "adoption":
            sub.add_argument("--original-request-id", required=True)
        elif command == "stage":
            sub.add_argument("--file", required=True)
            sub.add_argument("--path", required=True)
        elif command in ("job", "output", "file", "cancel"):
            sub.add_argument("--job", required=True)
            if command in {"output", "file"}:
                sub.add_argument("--offset", type=int, default=0)
                sub.add_argument("--bytes", type=int, default=65536)
            if command == "file":
                sub.add_argument("--path", required=True, help="Absolute target path within the job's selected writable scope")
                sub.add_argument("--file-revision", help="Refuse the read if the observed file revision changed")
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
