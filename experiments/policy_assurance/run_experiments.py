#!/usr/bin/env python3
"""Run policy assurance groups independently and retain comparable evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = "experiments/policy_assurance"
sys.path.insert(0, str(ROOT))
PUBLISHED_SEEDS = (26082601, 26082602, 26082603)
GROUPS = {
    "catalogue": [f"{BASE}/experiment_permissions.py::test_decision_surface_detects_catalogue_defects"],
    "properties": [
        f"{BASE}/experiment_permissions.py::test_toml_round_trip_preserves_effective_decisions",
        f"{BASE}/experiment_permissions.py::test_agent_approval_changes_only_selected_scope",
        f"{BASE}/experiment_permissions.py::test_denial_never_increases_permission",
    ],
    "sequences-clean": [f"{BASE}/experiment_sequences_clean.py"],
    "host-canonicalization": [f"{BASE}/experiment_host_canonicalization.py"],
    "writer-matrix": [f"{BASE}/experiment_writer_matrix.py"],
    "failure-stages": [f"{BASE}/experiment_failure_stages.py"],
    "crash-recovery": [f"{BASE}/experiment_crash_recovery.py"],
    "known-no-rate": [f"{BASE}/experiment_sequences.py::test_known_finding_no_rate_allowance_is_durable"],
    "known-persistence-failure": [f"{BASE}/experiment_sequences.py::test_failed_persistence_cannot_report_success"],
    "known-public-concurrency": [
        f"{BASE}/experiment_concurrency.py::test_policy_host_writers_do_not_lose_completed_changes"
    ],
    "locked-concurrency": [f"{BASE}/experiment_concurrency.py::test_locked_writers_preserve_both_changes"],
    "holdouts": [],
}
KNOWN_FINDING_GROUPS = {
    "known-no-rate",
    "known-persistence-failure",
    "known-public-concurrency",
}
GENERATED_GROUPS = {"catalogue", "properties", "sequences-clean"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("groups", nargs="*", choices=tuple(GROUPS), help="groups to run (default: all)")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--hypothesis-seed", type=int)
    parser.add_argument(
        "--published-seeds",
        action="store_true",
        help="run generated groups with the three published replay seeds",
    )
    return parser.parse_args()


def _assertion_hashes() -> dict[str, str]:
    files = sorted((ROOT / BASE).glob("experiment_*.py"))
    files.extend(ROOT / BASE / name for name in ("harness.py", "strategies.py", "conftest.py"))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def _status(group: str, returncode: int, output: str) -> str:
    if "Failed: INFRASTRUCTURE_ERROR:" in output or returncode in {2, 3, 4, 5}:
        return "INFRASTRUCTURE_ERROR"
    if group in KNOWN_FINDING_GROUPS:
        return "RESOLVED" if returncode == 0 else "REPRODUCED"
    return "PASS" if returncode == 0 else "FINDING"


def _read_observations(path: Path) -> list[dict]:
    if not path.exists():
        return []
    observations = []
    for line in path.read_text().splitlines():
        try:
            observations.append(json.loads(line))
        except json.JSONDecodeError as exc:
            observations.append({"status": "INFRASTRUCTURE_ERROR", "error": str(exc)})
    return observations


def _run_pytest(group: str, repetition: int, seed: int | None) -> dict:
    command = [sys.executable, "-m", "pytest", "-q", *GROUPS[group]]
    if seed is not None:
        command.append(f"--hypothesis-seed={seed}")
    descriptor, observation_name = tempfile.mkstemp(prefix="policy-observations-", suffix=".jsonl")
    os.close(descriptor)
    observation_path = Path(observation_name)
    environment = os.environ.copy()
    environment["POLICY_ASSURANCE_OBSERVATIONS"] = str(observation_path)
    started = time.monotonic()
    completed = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - started
    output = completed.stdout + completed.stderr
    result = {
        "group": group,
        "repetition": repetition,
        "hypothesis_seed": seed,
        "status": _status(group, completed.returncode, output),
        "returncode": completed.returncode,
        "elapsed_seconds": round(elapsed, 3),
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "observations": _read_observations(observation_path),
    }
    observation_path.unlink(missing_ok=True)
    return result


def main() -> int:
    args = _parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be positive")

    frozen_hashes = _assertion_hashes()
    results: list[dict] = []
    selected_groups = args.groups or tuple(GROUPS)
    for group in selected_groups:
        if group == "holdouts":
            # Import only after assertion hashes are frozen.
            from experiments.policy_assurance.holdouts import run_holdouts

            holdout_results = run_holdouts(ROOT)
            for result in holdout_results:
                result.update(group="holdouts")
                results.append(result)
                print(f"{result['status']:20} holdouts/{result['holdout']}")
            if _assertion_hashes() != frozen_hashes:
                results.append(
                    {
                        "group": "holdouts",
                        "status": "INFRASTRUCTURE_ERROR",
                        "error": "experiment assertions changed during isolated holdouts",
                    }
                )
            continue

        if args.published_seeds and group in GENERATED_GROUPS:
            seeds: tuple[int | None, ...] = PUBLISHED_SEEDS
        else:
            seeds = tuple(
                args.hypothesis_seed + index if args.hypothesis_seed is not None else None
                for index in range(args.repeat)
            )
        for repetition, seed in enumerate(seeds, 1):
            result = _run_pytest(group, repetition, seed)
            results.append(result)
            print(f"{result['status']:20} {group:28} {result['elapsed_seconds']:8.3f}s")

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "published_seeds": PUBLISHED_SEEDS,
        "assertion_hashes": frozen_hashes,
        "results": results,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")

    bad_statuses = {"FINDING", "INFRASTRUCTURE_ERROR", "CONTAMINATED"}
    return int(any(result.get("status") in bad_statuses for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
