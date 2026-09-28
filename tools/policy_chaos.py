"""Run native policy histories and guarded disposable-VM recovery cuts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from tests.blackbox.proxy_backend import validate_rust_binary

ROOT = Path(__file__).resolve().parents[1]
HOST_TEST = "tests/proxy_migration/test_native_policy_host_chaos.py"
STATE_TEST = "tests/proxy_migration/test_native_policy_state_chaos.py"
CONTENTION_TEST = "tests/proxy_migration/test_native_policy_contention.py"
FAILURE_TEST = "tests/proxy_migration/test_native_policy_failure_stages.py"
CRASH_TEST = "tests/proxy_migration/test_native_policy_crash_recovery.py"
EXISTING_TEST = "tests/proxy_migration/test_native_policy_mutation.py"
SEEDS = (26082601, 26082602, 26082603)
GROUPS = {
    "existing-state": (EXISTING_TEST, "native Admin and retained operator approval client",
                       "Only the scoped approval changes; lists, HMAC, controls, audit and fresh state agree"),
    "host-properties": (f"{HOST_TEST}::test_host_permission_properties", "retained policy-host CLI",
                        "Generated policy deltas match live and fresh Rust decisions"),
    "host-histories": (f"{HOST_TEST}::test_host_mutation_histories", "retained policy-host CLI",
                       "Each completed host edit matches the intent model and fresh Rust"),
    "host-boundary": (f"{HOST_TEST}::test_written_wildcard_has_dns_label_boundary",
                      "retained policy-host CLI", "A wildcard child is allowed and its suffix-sharing sibling stays blocked"),
    "host-budget": (f"{HOST_TEST}::test_unrated_allow_stays_under_aggregate_budget",
                    "retained policy-host CLI", "An unrated allow still consumes the aggregate budget"),
    "host-rate": (f"{HOST_TEST}::test_rate_change_limits_live_and_fresh_requests",
                  "retained policy-host CLI", "A changed rate bounds live and fresh requests"),
    "credential-histories": (f"{STATE_TEST}::test_credential_approval_histories",
                             "native Admin and retained policy-host CLI",
                             "Credential approvals and removals keep exact scope live and fresh"),
    "service-histories": (f"{STATE_TEST}::test_agent_service_binding_histories",
                          "native Admin and retained agent-store writer",
                          "Service bindings and grants match each completed operation live and fresh"),
    "writer-contention": (CONTENTION_TEST, "native Admin and retained Python writers",
                          "Both completed disjoint edits survive real lock overlap and publication"),
    "failure-stages": (FAILURE_TEST, "native Admin and retained Python writers",
                       "Stage-specific failure results agree with policy bytes, audit, live and fresh state"),
    "crash-recovery": (CRASH_TEST, "native Admin",
                       "Process cuts preserve checkpoint-specific complete state; VM guards reject unsafe cuts"),
}
# The default-release guard needs a separately built release binary. It is a
# C5 control, not a debug-profile case, and remains selectable with pytest.
GROUP_FILTERS = {"failure-stages": "not default_release_build_cannot_activate_stage_control"}
GENERATED = {"host-properties", "host-histories", "credential-histories", "service-histories"}
EXAMPLES = {"host-properties": 40, "host-histories": 8,
            "credential-histories": 8, "service-histories": 8}
GROUP_TIMEOUT_SECONDS = 600


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run selected hermetic policy groups")
    run.add_argument("--group", action="append", choices=GROUPS,
                     help="select a group (default: all implemented groups)")
    run.add_argument("--seed", type=int, help="one generated seed (default: three published seeds)")
    run.add_argument("--binary", type=Path,
                     default=ROOT / "proxy/target/debug/safeyolo-proxy")
    run.add_argument("--output", type=Path, default=Path.home() / "policy-chaos.json",
                     help="write one report and any failing trace beside it (default: ~/policy-chaos.json)")
    replay = commands.add_parser("replay", help="replay one saved failing operation trace")
    replay.add_argument("trace", type=Path)
    replay.add_argument("--binary", type=Path,
                        default=ROOT / "proxy/target/debug/safeyolo-proxy")
    fault = commands.add_parser("fault", help="guarded native disposable-VM recovery protocol")
    fault_commands = fault.add_subparsers(dest="fault_command", required=True)
    prepare = fault_commands.add_parser("prepare-power-cut")
    prepare.add_argument("--checkpoint", choices=(
        "before-rename", "after-rename-before-directory-sync", "after-acknowledged-response",
    ), required=True)
    prepare.add_argument("--config-dir", type=Path, required=True)
    prepare.add_argument("--state-dir", type=Path, required=True)
    prepare.add_argument("--binary", type=Path, default=ROOT / "proxy/target/debug/safeyolo-proxy")
    prepare.add_argument("--runtime-dir", type=Path, default=Path("/tmp"))
    prepare.add_argument("--run-id")
    prepare.add_argument("--confirm-disposable-vm", action="store_true")
    ready = fault_commands.add_parser("ready", help="validate outside-VM checkpoint observation")
    ready.add_argument("--manifest", type=Path, required=True)
    ready.add_argument("--observation", type=Path, required=True)
    recover = fault_commands.add_parser("recover")
    recover.add_argument("--run-id", required=True)
    recover.add_argument("--config-dir", type=Path, required=True)
    recover.add_argument("--state-dir", type=Path, required=True)
    recover.add_argument("--observation", type=Path, required=True)
    recover.add_argument("--cut-record", type=Path, required=True)
    recover.add_argument("--runtime-dir", type=Path, default=Path("/tmp"))
    recover.add_argument("--output", type=Path, required=True)
    recover.add_argument("--confirm-disposable-vm", action="store_true")
    return parser.parse_args()


def _binary(path: Path) -> tuple[Path, str, str]:
    binary, version = validate_rust_binary(path)
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return binary, version, digest


def _replay_command(trace: Path, binary: Path) -> str:
    return (f"{shlex.quote(sys.executable)} -m tools.policy_chaos replay "
            f"{shlex.quote(str(trace))} --binary {shlex.quote(str(binary))}")


def _pytest(command: list[str], environment: dict[str, str],
            timeout: float = GROUP_TIMEOUT_SECONDS) -> tuple[int | None, str, str]:
    """Bound a selected group and stop only processes started in its group."""
    process = subprocess.Popen(
        command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            # The group exited between the timeout and the kill request.
            pass
        stdout, stderr = process.communicate()
        return None, stdout, stderr + f"\nSelected group timed out after {timeout:g} seconds"
    return process.returncode, stdout, stderr


def _cases(path: Path) -> list[dict]:
    """Read pytest's own case accounting; missing or empty XML is not a pass."""
    if not path.is_file() or not path.stat().st_size:
        return []
    root = ET.parse(path).getroot()
    cases = []
    for case in root.iter("testcase"):
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        status = "FINDING" if failure is not None else (
            "INCOMPLETE" if error is not None or skipped is not None else "PASS"
        )
        detail = failure if failure is not None else error if error is not None else skipped
        cases.append({
            "name": f"{case.get('classname', '')}::{case.get('name', '')}",
            "status": status,
            "observed": ((detail.get("message") or detail.text or "")[:2000]
                         if detail is not None else "assertions passed"),
        })
    return cases


def _status(returncode: int | None, cases: list[dict]) -> str:
    if returncode is None or not cases:
        return "INCOMPLETE"
    if any(case["status"] == "FINDING" for case in cases):
        return "FINDING"
    if any(case["status"] == "INCOMPLETE" for case in cases):
        return "INCOMPLETE"
    return "PASS" if returncode == 0 else "INCOMPLETE"


def _observations(stdout: str) -> list[dict]:
    prefix = "CHAOS_OBSERVATION="
    return [json.loads(line[len(prefix):]) for line in stdout.splitlines()
            if line.startswith(prefix)]


def _run(args: argparse.Namespace) -> int:
    binary, version, digest = _binary(args.binary)
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    trace_root = output.parent / f"{output.stem}-traces-{uuid.uuid4().hex[:12]}"
    selected = list(dict.fromkeys(args.group or GROUPS))
    if not selected:
        raise ValueError("No policy-chaos group was selected")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
    ).strip()
    dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True,
    ).strip())
    selection = [(group, seed) for group in selected for seed in (
        ((args.seed,) if args.seed is not None else SEEDS) if group in GENERATED else (None,)
    )]
    results = []
    with tempfile.TemporaryDirectory(prefix="sy-chaos-pytest-", dir=Path.home()) as temporary:
        for index, (group, seed) in enumerate(selection):
            trace_dir = trace_root / f"{group}-{seed}"
            xml = Path(temporary) / f"{index}.xml"
            command = [sys.executable, "-m", "pytest", "-q", "-s",
                       f"--junitxml={xml}", GROUPS[group][0]]
            if group in GROUP_FILTERS:
                command += ["-k", GROUP_FILTERS[group]]
            if seed is not None:
                command += [f"--hypothesis-seed={seed}", "--hypothesis-show-statistics"]
            environment = os.environ.copy()
            environment["SAFEYOLO_RUST_PROXY"] = str(binary)
            environment["SAFEYOLO_CHAOS_TRACE_DIR"] = str(trace_dir)
            started = time.monotonic()
            returncode, stdout, stderr = _pytest(command, environment)
            try:
                cases = _cases(xml)
                observations = _observations(stdout)
            except (ET.ParseError, ValueError) as error:
                cases, observations = [], []
                stderr += f"\nInvalid pytest report: {error}"
            status = _status(returncode, cases)
            traces = sorted(trace_dir.glob("*.json"))
            operation_traces = []
            for path in traces:
                try:
                    operation_traces.append({"path": str(path), "trace": json.loads(path.read_text()),
                                             "replay": _replay_command(path, binary)})
                except (OSError, ValueError) as error:
                    status = "INCOMPLETE" if status == "PASS" else status
                    stderr += f"\nUnreadable operation trace {path}: {error}"
            results.append({
                "group": group, "seed": seed, "status": status,
                "writer": GROUPS[group][1],
                "stage": [case["name"].rsplit("::", 1)[-1] for case in cases],
                "expected": GROUPS[group][2],
                "max_examples": EXAMPLES.get(group),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "returncode": returncode, "selected_selector": GROUPS[group][0],
                "selection_filter": GROUP_FILTERS.get(group),
                "collected_cases": len(cases),
                "executed_cases": sum(case["status"] != "INCOMPLETE" for case in cases),
                "cases": cases, "observations": observations,
                "operation_traces": operation_traces,
                "output_tail": (stdout[-2500:] + stderr[-1000:]) if status != "PASS" else "",
            })
            print(f"{status:10} {group} seed={seed}")
            if status != "PASS":
                print(stdout[-2500:] + stderr[-1000:])
    status = ("FINDING" if any(item["status"] == "FINDING" for item in results)
              else "INCOMPLETE" if any(item["status"] == "INCOMPLETE" for item in results)
              else "PASS")
    report = {
        "family": "native-policy-chaos", "status": status,
        "source_commit": commit, "source_dirty": dirty,
        "binary": str(binary), "binary_version": version, "binary_sha256": digest,
        "created_at": datetime.now(UTC).isoformat(),
        "selected_groups": selected, "selected_runs": len(selection),
        "attempted_runs": len(results),
        "executed_runs": sum(item["executed_cases"] > 0 for item in results),
        "collected_cases": sum(len(item["cases"]) for item in results),
        "executed_cases": sum(
            item["executed_cases"] for item in results),
        "environment": {"system": platform.system(), "machine": platform.machine(),
                        "python": platform.python_version(),
                        "limitations": ["No VM power cut in the hermetic profile",
                                        "Binary SHA-256 identifies the build bytes; the binary does not embed a source revision"]},
        "results": results,
    }
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"Report: {output}")
    return {"PASS": 0, "FINDING": 1, "INCOMPLETE": 2}[status]


def _replay(args: argparse.Namespace) -> int:
    binary, _, _ = _binary(args.binary)
    trace = json.loads(args.trace.read_text())
    if not isinstance(trace, dict):
        raise ValueError("Trace must be a JSON object")
    family = trace.get("family")
    if family in {"properties", "history", "wildcard", "budget", "rate"}:
        from tests.proxy_migration.test_native_policy_host_chaos import execute_trace
    elif family in {"credential", "gateway"}:
        from tests.proxy_migration.test_native_policy_state_chaos import (
            execute_credential_trace,
            execute_gateway_trace,
        )
        execute_trace = execute_credential_trace if family == "credential" else execute_gateway_trace
    else:
        raise ValueError(f"Unsupported trace family: {family!r}")

    previous_binary = os.environ.get("SAFEYOLO_RUST_PROXY")
    os.environ["SAFEYOLO_RUST_PROXY"] = str(binary)
    try:
        with tempfile.TemporaryDirectory(prefix="safeyolo-chaos-replay-", dir=Path.home()) as temporary:
            result = execute_trace(Path(temporary) / "case", trace)
    except AssertionError as error:
        print(f"FINDING: {error}", file=sys.stderr)
        return 1
    finally:
        if previous_binary is None:
            os.environ.pop("SAFEYOLO_RUST_PROXY", None)
        else:
            os.environ["SAFEYOLO_RUST_PROXY"] = previous_binary
    print(json.dumps({
        "status": "PASS", "trace": str(args.trace),
        "operations": result["operations"], "fresh_matches": result["fresh_matches"],
    }, ensure_ascii=False))
    return 0


def main() -> int:
    """Run selected native policy groups or replay one saved trace."""
    args = _args()
    try:
        if args.command == "run":
            return _run(args)
        if args.command == "replay":
            return _replay(args)
        from tools import policy_chaos_recovery

        return {
            "prepare-power-cut": policy_chaos_recovery.prepare_vm_cut,
            "ready": policy_chaos_recovery.ready_vm_cut,
            "recover": policy_chaos_recovery.recover_vm_cut,
        }[args.fault_command](args)
    except (OSError, ValueError, KeyError, AssertionError, subprocess.TimeoutExpired) as error:
        print(f"INCOMPLETE: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
