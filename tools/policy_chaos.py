"""Run native policy histories and guarded disposable-VM recovery cuts."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST_TEST = "tests/proxy_migration/test_native_policy_host_chaos.py"
STATE_TEST = "tests/proxy_migration/test_native_policy_state_chaos.py"
CONTENTION_TEST = "tests/proxy_migration/test_native_policy_contention.py"
FAILURE_TEST = "tests/proxy_migration/test_native_policy_failure_stages.py"
CRASH_TEST = "tests/proxy_migration/test_native_policy_crash_recovery.py"
SEEDS = (26082601, 26082602, 26082603)
GROUPS = {
    "host-properties": f"{HOST_TEST}::test_host_permission_properties",
    "host-histories": f"{HOST_TEST}::test_host_mutation_histories",
    "host-boundary": f"{HOST_TEST}::test_written_wildcard_has_dns_label_boundary",
    "host-budget": f"{HOST_TEST}::test_unrated_allow_stays_under_aggregate_budget",
    "host-rate": f"{HOST_TEST}::test_rate_change_limits_live_and_fresh_requests",
    "credential-histories": f"{STATE_TEST}::test_credential_approval_histories",
    "service-histories": f"{STATE_TEST}::test_agent_service_binding_histories",
    "writer-contention": CONTENTION_TEST,
    "failure-stages": FAILURE_TEST,
    "crash-recovery": CRASH_TEST,
}
GENERATED = {"host-properties", "host-histories", "credential-histories", "service-histories"}
EXAMPLES = {"host-properties": 40, "host-histories": 8,
            "credential-histories": 8, "service-histories": 8}


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run selected hermetic policy groups")
    run.add_argument("--group", action="append", choices=GROUPS,
                     help="select a group (default: all implemented groups)")
    run.add_argument("--seed", type=int, help="one generated seed (default: three published seeds)")
    run.add_argument("--binary", type=Path,
                     default=ROOT / "proxy/target/debug/safeyolo-proxy")
    run.add_argument("--output", type=Path, required=True,
                     help="write the focused report and any failing trace beside it")
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


def _binary(path: Path) -> Path:
    binary = path.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"Selected native proxy is not executable: {binary}")
    return binary


def _replay_command(trace: Path, binary: Path) -> str:
    return (f"{shlex.quote(sys.executable)} -m tools.policy_chaos replay "
            f"{shlex.quote(str(trace))} --binary {shlex.quote(str(binary))}")


def _pytest(command: list[str], environment: dict[str, str]) -> tuple[int | None, str, str]:
    """Bound a selected group and stop only processes started in its group."""
    process = subprocess.Popen(
        command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        return None, stdout, stderr + "\nSelected group timed out after 600 seconds"
    return process.returncode, stdout, stderr


def _run(args: argparse.Namespace) -> int:
    binary = _binary(args.binary)
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    trace_root = output.parent / f"{output.stem}-traces-{datetime.now(UTC):%Y%m%dT%H%M%S}"
    selected = list(dict.fromkeys(args.group or GROUPS))
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
    ).strip()
    dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True,
    ).strip())
    results = []
    for group in selected:
        seeds = ((args.seed,) if args.seed is not None else SEEDS) if group in GENERATED else (None,)
        for seed in seeds:
            trace_dir = trace_root / f"{group}-{seed}"
            command = [sys.executable, "-m", "pytest", "-q", GROUPS[group]]
            if seed is not None:
                command += [f"--hypothesis-seed={seed}", "--hypothesis-show-statistics"]
            environment = os.environ.copy()
            environment["SAFEYOLO_RUST_PROXY"] = str(binary)
            environment["SAFEYOLO_CHAOS_TRACE_DIR"] = str(trace_dir)
            started = time.monotonic()
            returncode, stdout, stderr = _pytest(command, environment)
            status = "PASS" if returncode == 0 else "FINDING"
            if returncode is None or returncode in {2, 3, 4, 5}:
                status = "INCOMPLETE"
            traces = sorted(trace_dir.glob("*.json"))
            results.append({
                "group": group, "seed": seed, "status": status,
                "max_examples": EXAMPLES.get(group),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "returncode": returncode,
                "command": command,
                "stdout": stdout, "stderr": stderr,
                "traces": [str(path) for path in traces],
                "replay": [_replay_command(path, binary) for path in traces],
            })
            print(f"{status:10} {group} seed={seed}")
            if status != "PASS":
                print(stdout[-2500:] + stderr[-1000:])
    report = {
        "family": "native-policy-chaos", "source_commit": commit, "source_dirty": dirty,
        "binary": str(binary), "created_at": datetime.now(UTC).isoformat(),
        "selected_groups": selected, "executed_runs": len(results), "results": results,
    }
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"Report: {output}")
    return int(any(item["status"] != "PASS" for item in results))


def _replay(args: argparse.Namespace) -> int:
    binary = _binary(args.binary)
    trace = json.loads(args.trace.read_text())
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
    except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        print(f"INCOMPLETE: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
