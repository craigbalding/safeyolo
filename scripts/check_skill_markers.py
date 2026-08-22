#!/usr/bin/env python3
"""Enforce that source lines carrying a SKILL: marker cannot change without
a matching update to the skill reference they cite.

Convention
----------

Any source line with a comment of the form::

    # SKILL: <reference-file>[#<anchor>]

declares that the fact expressed on that line is documented in the named
SafeYolo skill reference (under
``cli/src/safeyolo/agent_context/skills/safeyolo/references/``). If the
marker line changes -- either added, removed, or edited -- the referenced
reference file must also appear in the same diff. Otherwise the source and
its agent-facing documentation are drifting.

The anchor is advisory in v1: presence of the file in the diff is enough.
A later version can enforce that the specific section is touched.

Usage
-----

    scripts/check_skill_markers.py                # staged changes (pre-commit)
    scripts/check_skill_markers.py --range A..B   # commit range (CI)

Exit codes
----------

    0  -- all touched markers have matching skill updates
    1  -- one or more markers were touched without a matching skill update
    2  -- environment problem (not a git repo, script layout wrong, ...)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

MARKER_RE = re.compile(r"#\s*SKILL:\s*([\w./#-]+)")
REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_REF_DIR = REPO_ROOT / "cli/src/safeyolo/agent_context/skills/safeyolo/references"
SUPPORTED_SOURCE_SUFFIXES = {".py"}


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO_ROOT).decode()


def _changed_files(range_spec: str | None) -> set[Path]:
    if range_spec is None:
        out = _git("diff", "--cached", "--name-only")
    else:
        out = _git("diff", "--name-only", range_spec)
    return {Path(line) for line in out.splitlines() if line}


def _markers_in_diff(path: Path, range_spec: str | None) -> set[str]:
    """Return every marker reference found on an added or removed line of `path`.

    Uses ``-U0`` so context lines are excluded -- only genuinely changed
    lines are inspected. Both ``+`` and ``-`` lines count: removing a
    marker without touching the doc is also a drift risk.
    """
    if range_spec is None:
        cmd = ["diff", "--cached", "-U0", "--", str(path)]
    else:
        cmd = ["diff", "-U0", range_spec, "--", str(path)]
    diff = _git(*cmd)
    markers: set[str] = set()
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if not (line.startswith("+") or line.startswith("-")):
            continue
        match = MARKER_RE.search(line[1:])
        if match:
            markers.add(match.group(1))
    return markers


def _reference_relpath(ref: str) -> Path | None:
    """Convert 'agent-api.md#flow-inspection' to a repo-relative Path.

    Returns None if the reference escapes the skill tree.
    """
    file_part = ref.split("#", 1)[0]
    resolved = (SKILL_REF_DIR / file_part).resolve()
    try:
        return resolved.relative_to(REPO_ROOT)
    except ValueError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--range",
        default=None,
        help="Git range like origin/master..HEAD; default is --cached (staged).",
    )
    args = parser.parse_args()

    if not SKILL_REF_DIR.is_dir():
        print(
            f"check-skill-markers: skill reference dir not found: {SKILL_REF_DIR}",
            file=sys.stderr,
        )
        return 2

    changed = _changed_files(args.range)
    if not changed:
        return 0

    problems: list[tuple[Path, str, str]] = []
    for path in sorted(changed):
        if path.suffix not in SUPPORTED_SOURCE_SUFFIXES:
            continue
        for ref in _markers_in_diff(path, args.range):
            ref_path = _reference_relpath(ref)
            if ref_path is None:
                problems.append((path, ref, "reference escapes the skill tree"))
                continue
            if not (REPO_ROOT / ref_path).exists():
                problems.append((path, ref, f"reference file missing: {ref_path}"))
                continue
            if ref_path not in changed:
                problems.append(
                    (path, ref, f"reference {ref_path} was not modified in this diff"),
                )

    if problems:
        print(
            "check-skill-markers: SKILL: markers changed without a matching skill update",
            file=sys.stderr,
        )
        for source, ref, why in problems:
            print(f"  {source}: SKILL: {ref} -- {why}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
