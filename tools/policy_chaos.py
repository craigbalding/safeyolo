"""Deterministic policy transaction chaos runner.

The default command is hermetic.  The fault subcommands require an explicit
disposable-VM contract and implement a two-phase protocol for an outer KVM VPS
controller to cut and restore guest power.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import tomlkit

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_RUNNER = ROOT / "experiments" / "policy_assurance" / "run_experiments.py"
DEFAULT_GROUPS = (
    "catalogue",
    "properties",
    "sequences-clean",
    "host-canonicalization",
    "writer-matrix",
    "failure-stages",
    "crash-recovery",
    "known-no-rate",
    "known-persistence-failure",
    "known-public-concurrency",
)
SENTINEL = ".safeyolo-chaos-disposable"
REPORT_VERSION = 1


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _git_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write_report(path: Path, report: dict[str, Any]) -> None:
    _atomic_json(path, report)


def _aggregate_exit(results: list[dict[str, Any]]) -> int:
    statuses = {result.get("status") for result in results}
    if "INFRASTRUCTURE_ERROR" in statuses:
        return 2
    if statuses & {"FINDING", "REPRODUCED", "CONTAMINATED"}:
        return 1
    return 0


def run_hermetic(args: argparse.Namespace) -> int:
    groups = tuple(args.group or DEFAULT_GROUPS)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="safeyolo-policy-chaos-") as temporary:
        raw_report = Path(temporary) / "experiment-report.json"
        command = [sys.executable, str(EXPERIMENT_RUNNER), *groups, "--output", str(raw_report)]
        if args.published_seeds:
            command.append("--published-seeds")
        elif args.seed is not None:
            command.extend(("--hypothesis-seed", str(args.seed)))
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        if raw_report.exists():
            experiment = json.loads(raw_report.read_text())
            results = experiment.get("results", [])
            assertion_hashes = experiment.get("assertion_hashes", {})
        else:
            results = [
                {
                    "status": "INFRASTRUCTURE_ERROR",
                    "error": "experiment runner produced no JSON report",
                }
            ]
            assertion_hashes = {}

    report = {
        "report_version": REPORT_VERSION,
        "run_id": uuid.uuid4().hex,
        "generated_at": _now(),
        "git_commit": _git_commit(),
        "mode": "hermetic",
        "seed": args.seed,
        "published_seeds": bool(args.published_seeds),
        "groups": groups,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "assertion_hashes": assertion_hashes,
        "replay_command": [
            sys.executable,
            "-m",
            "tools.policy_chaos",
            "run",
            *(item for group in groups for item in ("--group", group)),
            *(["--published-seeds"] if args.published_seeds else []),
            *(["--seed", str(args.seed)] if args.seed is not None else []),
            "--output",
            str(args.output),
        ],
        "runner_stdout": completed.stdout,
        "runner_stderr": completed.stderr,
        "results": results,
    }
    _write_report(args.output, report)
    exit_code = _aggregate_exit(results)
    print(json.dumps({"run_id": report["run_id"], "status": "PASS" if exit_code == 0 else "FAIL", "report": str(args.output)}))
    return exit_code


def _safe_fault_paths(config_dir: Path, state_dir: Path, confirmed: bool) -> tuple[Path, Path]:
    if not confirmed or os.environ.get("SAFEYOLO_CHAOS_DISPOSABLE_VM") != "1":
        raise RuntimeError(
            "fault mode requires --confirm-disposable-vm and "
            "SAFEYOLO_CHAOS_DISPOSABLE_VM=1"
        )
    config_dir = config_dir.resolve()
    state_dir = state_dir.resolve()
    home = Path.home().resolve()
    forbidden = {Path("/").resolve(), home, ROOT.resolve()}
    if config_dir in forbidden or state_dir in forbidden:
        raise RuntimeError("refusing unsafe chaos config/state path")
    if ROOT.resolve() in config_dir.parents or ROOT.resolve() in state_dir.parents:
        raise RuntimeError("fault mode paths must be outside the source worktree")
    if not (config_dir / SENTINEL).is_file():
        raise RuntimeError(f"missing KVM VPS sentinel: {config_dir / SENTINEL}")
    policy_path = config_dir / "policy.toml"
    if not policy_path.is_file():
        raise RuntimeError(f"policy.toml not found: {policy_path}")
    state_dir.mkdir(parents=True, exist_ok=True)
    return policy_path, state_dir


def _decision(path: Path, host: str) -> str:
    from safeyolo.policy.engine import PolicyEngine

    # The engineering command has a JSON-only output contract. Policy loading
    # may log operational events, so keep those internal while still allowing
    # exceptions to reach the structured top-level error response.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        engine = PolicyEngine(baseline_path=path)
        try:
            return engine.evaluate_request(host).effect
        finally:
            engine._loader.stop_watcher()


def _network_surface(path: Path, document: dict[str, Any], chaos_host: str) -> dict[str, str]:
    hosts = document.get("hosts", {}) if isinstance(document, dict) else {}
    probes = [
        host
        for host in hosts
        if host != "*" and not str(host).startswith("$") and "*" not in str(host)
    ][:20]
    probes.append(chaos_host)
    return {host: _decision(path, host) for host in dict.fromkeys(probes)}


def _expected_mutation(original: bytes, chaos_host: str) -> tuple[str, bytes, dict[str, str]]:
    from safeyolo.policy.toml_roundtrip import upsert_host

    document = tomlkit.parse(original.decode())
    with tempfile.TemporaryDirectory(prefix="policy-chaos-oracle-") as temporary:
        old_path = Path(temporary) / "old.toml"
        new_path = Path(temporary) / "new.toml"
        old_path.write_bytes(original)
        before = _decision(old_path, chaos_host)
        if before == "allow":
            operation = "deny"
            upsert_host(document, chaos_host, {"egress": "deny"})
        else:
            operation = "allow"
            budget = document.get("budget")
            if budget is not None:
                upsert_host(document, chaos_host, {"egress": "allow"})
            else:
                upsert_host(document, chaos_host, {"rate": 1000})
        expected = tomlkit.dumps(document).encode()
        new_path.write_bytes(expected)
        after = _decision(new_path, chaos_host)
        if before == after:
            raise RuntimeError("selected chaos mutation did not change effective behavior")
        surface = _network_surface(old_path, tomlkit.parse(original.decode()).unwrap(), chaos_host)
    return operation, expected, surface


def prepare_power_cut(args: argparse.Namespace) -> int:
    policy_path, state_dir = _safe_fault_paths(
        args.config_dir, args.state_dir, args.confirm_disposable_vm
    )
    run_id = args.run_id or uuid.uuid4().hex
    run_dir = state_dir / run_id
    state_path = run_dir / "state.json"
    if state_path.exists():
        raise RuntimeError(f"run already exists: {run_id}")

    original = policy_path.read_bytes()
    chaos_host = f"chaos-{run_id[:12]}.invalid"
    operation, expected, before_surface = _expected_mutation(original, chaos_host)
    state = {
        "report_version": REPORT_VERSION,
        "run_id": run_id,
        "git_commit": _git_commit(),
        "mode": "fault-engine",
        "evidence_kind": "abrupt-virtual-machine-death",
        "physical_power_loss_claimed": False,
        "checkpoint": args.checkpoint,
        "phase": "preparing",
        "policy_path": str(policy_path),
        "chaos_host": chaos_host,
        "operation": operation,
        "original_b64": base64.b64encode(original).decode(),
        "original_hash": _sha256(original),
        "expected_hash": _sha256(expected),
        "before_surface": before_surface,
        "started_at": _now(),
    }
    _atomic_json(state_path, state)

    from safeyolo.policy.toml_roundtrip import locked_policy_mutate, upsert_host

    def mutate(document):
        config = {"egress": operation}
        if operation == "allow" and document.get("budget") is None:
            config = {"rate": 1000}
        upsert_host(document, chaos_host, config)

    def ready() -> None:
        state["phase"] = "ready-for-power-cut"
        state["ready_at"] = _now()
        _atomic_json(state_path, state)
        print(
            json.dumps(
                {
                    "status": "READY_FOR_POWER_CUT",
                    "run_id": run_id,
                    "checkpoint": args.checkpoint,
                    "state": str(state_path),
                }
            ),
            flush=True,
        )
        threading.Event().wait()

    if args.checkpoint == "before-rename":
        with patch("safeyolo.policy.toml_roundtrip.shutil.move", side_effect=lambda *_a, **_k: ready()):
            locked_policy_mutate(policy_path, mutate)
    else:
        real_fsync = os.fsync
        calls = 0

        def checkpoint_fsync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                ready()
            return real_fsync(descriptor)

        with patch("safeyolo.policy.toml_roundtrip.os.fsync", side_effect=checkpoint_fsync):
            locked_policy_mutate(policy_path, mutate)
    raise RuntimeError("power-cut checkpoint unexpectedly resumed")


def recover_power_cut(args: argparse.Namespace) -> int:
    _policy_path, state_dir = _safe_fault_paths(
        args.config_dir, args.state_dir, args.confirm_disposable_vm
    )
    state_path = state_dir / args.run_id / "state.json"
    if not state_path.is_file():
        raise RuntimeError(f"unknown chaos run: {args.run_id}")
    state = json.loads(state_path.read_text())
    policy_path = Path(state["policy_path"]).resolve()
    if policy_path.parent != args.config_dir.resolve():
        raise RuntimeError("saved chaos policy path does not match requested config")

    visible = policy_path.read_bytes()
    visible_hash = _sha256(visible)
    allowed_hashes = {state["original_hash"], state["expected_hash"]}
    results: list[dict[str, Any]] = []
    if visible_hash not in allowed_hashes:
        results.append(
            {
                "status": "FINDING",
                "family": "vm-death-atomicity",
                "error": "visible policy is neither the complete old nor complete new policy",
            }
        )
    else:
        try:
            document = tomlkit.parse(visible.decode()).unwrap()
            surface = _network_surface(policy_path, document, state["chaos_host"])
            unrelated = {
                host: effect
                for host, effect in state["before_surface"].items()
                if host != state["chaos_host"]
            }
            preserved = all(surface.get(host) == effect for host, effect in unrelated.items())
            results.append(
                {
                    "status": "PASS" if preserved else "FINDING",
                    "family": "vm-death-recovery",
                    "visible_version": "old" if visible_hash == state["original_hash"] else "new",
                    "toml_valid": True,
                    "unrelated_decisions_preserved": preserved,
                    "temporary_files": sorted(
                        str(path) for path in policy_path.parent.glob("*.toml")
                        if path != policy_path
                    ),
                }
            )
        except Exception as exc:
            results.append(
                {
                    "status": "FINDING",
                    "family": "vm-death-parseability",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    original = base64.b64decode(state["original_b64"])
    restore_descriptor, restore_name = tempfile.mkstemp(
        prefix=".policy-chaos-restore-", suffix=".toml", dir=policy_path.parent
    )
    try:
        with os.fdopen(restore_descriptor, "wb") as handle:
            handle.write(original)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(restore_name, policy_path)
        directory = os.open(policy_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(restore_name):
            os.unlink(restore_name)

    report = {
        **{key: value for key, value in state.items() if key != "original_b64"},
        "phase": "recovered",
        "recovered_at": _now(),
        "visible_hash": visible_hash,
        "restored_hash": _sha256(policy_path.read_bytes()),
        "results": results,
        # Every argument argparse requires for `fault recover`. The
        # previous emit was `--run-id` only, which the parser rejects
        # with a "the following arguments are required" error — so the
        # advertised replay was unusable. Reviewer finding, merge dogfood.
        "replay_command": [
            sys.executable,
            "-m",
            "tools.policy_chaos",
            "fault",
            "recover",
            "--run-id", args.run_id,
            "--config-dir", str(args.config_dir),
            "--state-dir", str(args.state_dir),
            "--output", str(args.output),
            "--confirm-disposable-vm",
        ],
        # The disposable-VM contract is guarded at THREE points: the
        # CLI flag above, this env var, and the sentinel file already
        # in config-dir. The env var is the one a caller most often
        # forgets, so surface it alongside the command rather than
        # leaving them to discover exit 2 the hard way.
        "replay_env": {"SAFEYOLO_CHAOS_DISPOSABLE_VM": "1"},
    }
    _write_report(args.output, report)
    exit_code = _aggregate_exit(results)
    print(json.dumps({"run_id": args.run_id, "status": "PASS" if exit_code == 0 else "FAIL", "report": str(args.output)}))
    return exit_code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="run hermetic policy assurance groups")
    run.add_argument("--seed", type=int)
    run.add_argument("--published-seeds", action="store_true")
    run.add_argument("--group", action="append")
    run.add_argument("--output", type=Path, required=True)
    run.set_defaults(handler=run_hermetic)

    fault = subcommands.add_parser("fault", help="opt-in disposable-VM fault engine")
    fault_commands = fault.add_subparsers(dest="fault_command", required=True)
    prepare = fault_commands.add_parser("prepare-power-cut")
    prepare.add_argument(
        "--checkpoint",
        choices=("before-rename", "after-rename-before-directory-fsync"),
        required=True,
    )
    prepare.add_argument("--config-dir", type=Path, required=True)
    prepare.add_argument("--state-dir", type=Path, required=True)
    prepare.add_argument("--run-id")
    prepare.add_argument("--confirm-disposable-vm", action="store_true")
    prepare.set_defaults(handler=prepare_power_cut)

    recover = fault_commands.add_parser("recover")
    recover.add_argument("--run-id", required=True)
    recover.add_argument("--config-dir", type=Path, required=True)
    recover.add_argument("--state-dir", type=Path, required=True)
    recover.add_argument("--output", type=Path, required=True)
    recover.add_argument("--confirm-disposable-vm", action="store_true")
    recover.set_defaults(handler=recover_power_cut)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        return args.handler(args)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "INFRASTRUCTURE_ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
