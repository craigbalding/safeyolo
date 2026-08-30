"""Supply-chain and syntax contracts for shipped GitHub Actions workflows."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
ACTION_LINE = re.compile(
    r"^\s*(?:-\s*)?uses:\s+(?P<action>[^@\s]+)@(?P<ref>[^\s#]+)"
    r"(?:\s+#\s+(?P<version>\S+))?\s*$"
)
FULL_SHA = re.compile(r"[0-9a-f]{40}")
EXPECTED_ACTIONS = {
    "actions/checkout": (
        "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "v7.0.1",
    ),
    "astral-sh/setup-uv": (
        "20cfd1bf945f4377ade1205e4dbc17946fc9a30d",
        "v10.0.1",
    ),
}


def workflow_paths() -> list[Path]:
    return sorted((*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")))


def test_workflows_parse_as_yaml() -> None:
    for path in workflow_paths():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict), f"{path}: workflow root must be a mapping"
        assert isinstance(workflow.get("jobs"), dict), f"{path}: jobs must be a mapping"


def test_external_actions_use_documented_full_sha_pins() -> None:
    migrated_actions: set[str] = set()

    for path in workflow_paths():
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "uses:" not in line:
                continue
            match = ACTION_LINE.fullmatch(line)
            assert match is not None, f"{path}:{line_number}: cannot validate action pin"

            action = match["action"]
            if action.startswith("./"):
                continue
            assert FULL_SHA.fullmatch(match["ref"]), (
                f"{path}:{line_number}: {action} must use an immutable full SHA"
            )
            assert match["version"], (
                f"{path}:{line_number}: {action} must document its release version"
            )

            expected = EXPECTED_ACTIONS.get(action)
            if expected is not None:
                migrated_actions.add(action)
                assert (match["ref"], match["version"]) == expected, (
                    f"{path}:{line_number}: unexpected {action} release pin"
                )

    assert migrated_actions == EXPECTED_ACTIONS.keys()


def test_setup_uv_preserves_v5_cache_pruning_behavior() -> None:
    for path in workflow_paths():
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if not str(step.get("uses", "")).startswith("astral-sh/setup-uv@"):
                    continue
                assert step.get("with", {}).get("version") == "0.9.24"
                assert step.get("with", {}).get("prune-cache") is True
