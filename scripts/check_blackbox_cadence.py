#!/usr/bin/env python3
"""Keep documented blackbox cadence aligned with scheduled automation.

The workflow is the implementation source of truth. Documentation tables opt
into this contract with ``blackbox-cadence-contract`` markers and a structured
``Scheduled`` yes/no column. This checker derives scheduled full lanes from
``.github/workflows/blackbox.yml`` and rejects documentation which claims a
hardware nightly that the workflow does not implement.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "blackbox.yml"
CADENCE_DOCS = (
    REPO_ROOT / "tests" / "blackbox" / "README.md",
    REPO_ROOT / "docs" / "security-testing-design.md",
)
FULL_LANES = frozenset({"systrap", "kvm", "vz"})
START_MARKER = "<!-- blackbox-cadence-contract:start -->"
END_MARKER = "<!-- blackbox-cadence-contract:end -->"
RUN_LANE_RE = re.compile(
    r"(?:^|\s)(?:\./)?tests/blackbox/run-lane\.sh\s+"
    r"(?P<lane>systrap|kvm|vz)(?:\s|$)",
)


def scheduled_lanes_from_workflow(path: Path = WORKFLOW_PATH) -> dict[str, bool]:
    """Return scheduled full lanes mapped to artifact-publication presence."""
    data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: workflow root must be a mapping")

    triggers = data.get("on")
    if not isinstance(triggers, dict) or not triggers.get("schedule"):
        return {}

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        raise ValueError(f"{path}: scheduled workflow has no jobs mapping")

    scheduled: dict[str, bool] = {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError(f"{path}: job {job_name!r} steps must be a list")

        lanes: set[str] = set()
        artifact_specs: list[tuple[str, str]] = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            if isinstance(run, str):
                lanes.update(match.group("lane") for match in RUN_LANE_RE.finditer(run))
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith("actions/upload-artifact@"):
                options = step.get("with", {})
                if isinstance(options, dict):
                    artifact_specs.append(
                        (str(options.get("name", "")), str(options.get("path", "")))
                    )

        for lane in lanes:
            if lane in scheduled:
                raise ValueError(f"{path}: scheduled lane {lane!r} appears in multiple jobs")
            scheduled[lane] = any(
                lane in name and "tests/blackbox/artifacts/" in artifact_path
                for name, artifact_path in artifact_specs
            )

    return scheduled


def cadence_table_from_doc(path: Path) -> dict[str, bool]:
    """Parse one marked cadence table as ``lane -> scheduled``."""
    text = path.read_text()
    if text.count(START_MARKER) != 1 or text.count(END_MARKER) != 1:
        raise ValueError(
            f"{path}: expected exactly one {START_MARKER!r}/{END_MARKER!r} block"
        )
    block = text.split(START_MARKER, 1)[1].split(END_MARKER, 1)[0]
    rows = [line for line in block.splitlines() if line.strip().startswith("|")]
    if len(rows) < 3:
        raise ValueError(f"{path}: cadence contract table is missing rows")

    def cells(row: str) -> list[str]:
        return [cell.strip() for cell in row.strip().strip("|").split("|")]

    headers = cells(rows[0])
    try:
        lane_index = headers.index("Lane")
        scheduled_index = headers.index("Scheduled")
    except ValueError as exc:
        raise ValueError(f"{path}: cadence table needs Lane and Scheduled columns") from exc

    parsed: dict[str, bool] = {}
    for row in rows[2:]:
        values = cells(row)
        if len(values) != len(headers):
            raise ValueError(f"{path}: malformed cadence row: {row}")
        lane = values[lane_index].strip("`")
        scheduled_text = values[scheduled_index].lower()
        if lane not in FULL_LANES:
            raise ValueError(f"{path}: unexpected full lane {lane!r}")
        if scheduled_text not in {"yes", "no"}:
            raise ValueError(
                f"{path}: Scheduled for {lane!r} must be exactly yes or no"
            )
        if lane in parsed:
            raise ValueError(f"{path}: duplicate cadence row for {lane!r}")
        parsed[lane] = scheduled_text == "yes"

    if set(parsed) != FULL_LANES:
        missing = sorted(FULL_LANES - set(parsed))
        raise ValueError(f"{path}: cadence table missing full lanes: {missing}")
    return parsed


def contract_problems(
    workflow_path: Path = WORKFLOW_PATH,
    doc_paths: tuple[Path, ...] = CADENCE_DOCS,
) -> list[str]:
    """Return cadence/artifact mismatches without exiting."""
    try:
        scheduled = scheduled_lanes_from_workflow(workflow_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [str(exc)]

    problems: list[str] = []
    missing_artifacts = sorted(lane for lane, uploads in scheduled.items() if not uploads)
    if missing_artifacts:
        problems.append(
            "scheduled full lanes lack actions/upload-artifact evidence: "
            f"{missing_artifacts}"
        )

    implemented = set(scheduled)
    for path in doc_paths:
        try:
            documented = cadence_table_from_doc(path)
        except (OSError, ValueError) as exc:
            problems.append(str(exc))
            continue
        claimed = {lane for lane, is_scheduled in documented.items() if is_scheduled}
        if claimed != implemented:
            problems.append(
                f"{path}: scheduled lanes {sorted(claimed)} do not match "
                f"{workflow_path} implementation {sorted(implemented)}"
            )
    return problems


def main() -> int:
    problems = contract_problems()
    if not problems:
        return 0
    print("check-blackbox-cadence: documentation drifted from automation:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
