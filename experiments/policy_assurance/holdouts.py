"""Isolated source-level holdouts, defined after experiment assertions freeze."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Holdout:
    name: str
    group: str
    relative_source: str
    mutate: Callable[[str], str]
    detection_target: str
    effect_probe: str | None


def _replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError(f"holdout source anchor count is {source.count(old)}, expected 1")
    return source.replace(old, new, 1)


def _case_sensitive(source: str) -> str:
    old = """        host = parts[0].lower()
        path = normalize_path("/" + parts[1]) if len(parts) > 1 else "/"
        resource = host + path
    elif resource.startswith("/"):
        # Pure path
        resource = normalize_path(resource)
    else:
        # Pure host
        resource = resource.lower()

    pattern = pattern.lower()
"""
    new = (
        old.replace("parts[0].lower()", "parts[0]")
        .replace("resource = resource.lower()", "resource = resource")
        .replace("pattern = pattern.lower()", "pattern = pattern")
    )
    return _replace_once(source, old, new)


def _wildcard_without_boundary(source: str) -> str:
    old = """    pattern = pattern.lower()

    # Exact match (fast path)
"""
    new = """    pattern = pattern.lower().replace("*.", "*")

    # Exact match (fast path)
"""
    return _replace_once(source, old, new)


def _drop_agent_condition(source: str) -> str:
    method = source.index("    def add_host_allowance(")
    next_method = source.index("    def add_host_denial(", method)
    method_source = source[method:next_method]
    mutated = _replace_once(
        method_source,
        "                if agent:\n                    self._write_agent_host(document, agent, host, config)",
        "                if False and agent:  # holdout: agent scope lost\n                    self._write_agent_host(document, agent, host, config)",
    )
    return source[:method] + mutated + source[next_method:]


def _load_before_lock(source: str) -> str:
    old = """    lf = open(lock)
    try:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            if create_if_missing and not policy_path.exists():
                doc = tomlkit.document()
            else:
                doc = load_roundtrip(policy_path)
            result = mutate_fn(doc)
"""
    new = """    if create_if_missing and not policy_path.exists():
        doc = tomlkit.document()
    else:
        doc = load_roundtrip(policy_path)  # holdout: stale pre-lock snapshot
    lf = open(lock)
    try:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            result = mutate_fn(doc)
"""
    return _replace_once(source, old, new)


def _swallow_save_failure(source: str) -> str:
    old = """            result = mutate_fn(doc)
            save_roundtrip(policy_path, doc)
            return result
"""
    new = """            result = mutate_fn(doc)
            try:
                save_roundtrip(policy_path, doc)
            except (OSError, ValueError):
                pass  # holdout: false success
            return result
"""
    return _replace_once(source, old, new)


COMMON_EFFECT_IMPORTS = """
from pathlib import Path
import tempfile
from experiments.policy_assurance.harness import make_world, write_policy, engine_from_path
w = make_world(("atlas", "boris", "cody"), ("api.example", "deny.example", "review.example", "own.example"), ("alpha", "beta", "gamma"))
d = tempfile.TemporaryDirectory()
p = Path(d.name) / "policy.toml"
write_policy(p, w.policy)
e = engine_from_path(p)
"""


HOLDOUTS = (
    Holdout(
        "case-sensitive-host-matching",
        "host-canonicalization",
        "cli/src/safeyolo/core/utils.py",
        _case_sensitive,
        "experiments/policy_assurance/experiment_host_canonicalization.py::test_wildcard_dns_case_is_insensitive_at_real_ingress",
        COMMON_EFFECT_IMPORTS
        + '\ne.add_host_allowance("*.trusted.example", rate=100000)\nassert e.evaluate_request("CHILD.TRUSTED.EXAMPLE").effect == "deny"\n',
    ),
    Holdout(
        "wildcard-without-label-boundary",
        "host-canonicalization",
        "cli/src/safeyolo/core/utils.py",
        _wildcard_without_boundary,
        "experiments/policy_assurance/experiment_host_canonicalization.py::test_wildcards_keep_dns_label_boundaries",
        COMMON_EFFECT_IMPORTS
        + '\ne.add_host_allowance("*.trusted.example", rate=100000)\nassert e.evaluate_request("eviltrusted.example").effect == "allow"\n',
    ),
    Holdout(
        "agent-scoped-mutation-loses-condition",
        "sequences-clean",
        "cli/src/safeyolo/policy/engine.py",
        _drop_agent_condition,
        "experiments/policy_assurance/experiment_sequences_clean.py::test_shared_observation_captures_a_rated_agent_transaction",
        COMMON_EFFECT_IMPORTS
        + '\ne.add_host_allowance("scoped.example", rate=100000, agent="atlas")\nassert e.evaluate_request("scoped.example").effect == "allow"\n',
    ),
    Holdout(
        "locked-mutation-loads-before-lock",
        "writer-matrix",
        "cli/src/safeyolo/policy/toml_roundtrip.py",
        _load_before_lock,
        "experiments/policy_assurance/experiment_writer_matrix.py::test_locked_mutation_loads_only_after_acquiring_lock",
        None,
    ),
    Holdout(
        "shared-mutation-swallows-save-failure",
        "failure-stages",
        "cli/src/safeyolo/policy/toml_roundtrip.py",
        _swallow_save_failure,
        "experiments/policy_assurance/experiment_failure_stages.py::test_precommit_failure_preserves_old_policy[rename]",
        COMMON_EFFECT_IMPORTS
        + '\nfrom unittest.mock import patch\nfrom safeyolo.policy.toml_roundtrip import locked_policy_mutate\nwith patch("safeyolo.policy.toml_roundtrip.save_roundtrip", side_effect=OSError("boom")):\n    locked_policy_mutate(p, lambda doc: None)\n',
    ),
)


def _copy_source(root: Path, destination: Path) -> None:
    for relative in ("cli/src", "pdp", "experiments"):
        shutil.copytree(root / relative, destination / relative, dirs_exist_ok=True)


def _run(command: list[str], cwd: Path) -> tuple[subprocess.CompletedProcess[str], float]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(cwd / "cli" / "src"), str(cwd), environment.get("PYTHONPATH", "")))
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return completed, time.monotonic() - started


def run_holdouts(root: Path) -> list[dict]:
    """Run each mutation in its own temporary source copy."""
    results = []
    for holdout in HOLDOUTS:
        with tempfile.TemporaryDirectory(prefix="safeyolo-holdout-") as temporary:
            isolated = Path(temporary)
            _copy_source(root, isolated)
            baseline, baseline_runtime = _run(
                [sys.executable, "-m", "pytest", "-q", holdout.detection_target],
                isolated,
            )
            record = {
                "holdout": holdout.name,
                "responsible_group": holdout.group,
                "baseline_returncode": baseline.returncode,
                "baseline_runtime_seconds": round(baseline_runtime, 3),
            }
            if baseline.returncode != 0:
                record.update(
                    status="CONTAMINATED",
                    detection="not-awarded",
                    baseline_stdout=baseline.stdout,
                    baseline_stderr=baseline.stderr,
                )
                results.append(record)
                continue

            source = isolated / holdout.relative_source
            try:
                source.write_text(holdout.mutate(source.read_text()))
            except (OSError, ValueError) as exc:
                record.update(status="INFRASTRUCTURE_ERROR", error=str(exc))
                results.append(record)
                continue

            effect_changed = True
            effect_output = "sequencing assertion is the effect probe"
            if holdout.effect_probe:
                effect, _ = _run([sys.executable, "-c", holdout.effect_probe], isolated)
                effect_changed = effect.returncode == 0
                effect_output = effect.stdout + effect.stderr

            mutant, mutant_runtime = _run(
                [sys.executable, "-m", "pytest", "-q", holdout.detection_target],
                isolated,
            )
            if not effect_changed:
                status = "EQUIVALENT"
                detection = "equivalent"
            elif mutant.returncode == 1:
                status = "DETECTED"
                detection = "detected"
            elif mutant.returncode == 0:
                status = "MISSED"
                detection = "missed"
            else:
                status = "INFRASTRUCTURE_ERROR"
                detection = "not-awarded"
            record.update(
                status=status,
                detection=detection,
                effective_behavior_changed=effect_changed,
                mutant_returncode=mutant.returncode,
                mutant_runtime_seconds=round(mutant_runtime, 3),
                runtime_seconds=round(baseline_runtime + mutant_runtime, 3),
                effect_output=effect_output,
                mutant_stdout=mutant.stdout,
                mutant_stderr=mutant.stderr,
            )
            results.append(record)
    return results
