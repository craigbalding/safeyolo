#!/usr/bin/env python3
"""Enforce that source lines carrying a SKILL: or DOC: marker cannot change
without a matching update to the doc they cite.

Convention
----------

Any source line with a comment of one of these forms::

    # SKILL: <reference-file>[#<anchor>]
    # DOC:   <doc-file>[#<anchor>][, <doc-file>[#<anchor>], ...]

declares that the fact expressed on that line is documented in the named
file(s). If the marker line changes -- either added, removed, or edited --
every referenced doc must also appear in the same diff. Otherwise the
source and its user-facing documentation are drifting.

- ``SKILL:`` targets live under
  ``cli/src/safeyolo/agent_context/skills/safeyolo/references/``.
- ``DOC:`` targets live in the shipped-docs allowlist
  (``ALL_SHIPPED_DOCS`` = ``USER_FACING_DOCS`` ∪ ``SKILL_FILES``, from
  ``scripts/doc_allowlist.toml``). A ``DOC:`` ref pointing anywhere
  else is a hard error, so accidental targeting of design docs or
  scratch files fails loudly.

Anchors (``#section``) are advisory in v1: presence of the file in the
diff is enough. A later version can enforce that the specific section
is touched.

Both ``.py`` and ``.sh`` sources are scanned so shell scripts whose
constants back user-facing prose (e.g. ``guest/build-rootfs.sh``) can
carry markers too.

Usage
-----

    scripts/check_skill_markers.py                # staged changes (pre-commit)
    scripts/check_skill_markers.py --range A..B   # commit range (CI)

Exit codes
----------

    0  -- all touched markers have matching doc updates
    1  -- one or more markers were touched without a matching doc update
    2  -- environment problem (not a git repo, script layout wrong, ...)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SKILL_MARKER_RE = re.compile(r"#\s*SKILL:\s*([\w./#-]+)")
DOC_MARKER_RE = re.compile(r"#\s*DOC:\s*([\w./#, -]+?)(?:\s*(?:#(?!\w).*)?)?$")

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_REF_DIR = REPO_ROOT / "cli/src/safeyolo/agent_context/skills/safeyolo/references"
SUPPORTED_SOURCE_SUFFIXES = {".py", ".sh"}

# Path prefixes excluded from marker scanning. Test files legitimately embed
# marker syntax as test fixtures — treating those as real markers would create
# false positives and cascade churn onto docs the tests don't actually document.
EXCLUDED_PATH_PREFIXES: tuple[str, ...] = ("tests/",)

# Allowlist of shipped docs that DOC: markers may target — both
# operator-facing (USER_FACING_DOCS) and agent-facing skill docs
# (SKILL_FILES). A DOC: ref outside the union is rejected, preventing
# accidental coverage of design/planning docs (which describe intent,
# not runtime behavior). Sourced from scripts/doc_allowlist.toml.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_config import ALL_SHIPPED_DOCS  # noqa: E402


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO_ROOT).decode()


def _changed_files(range_spec: str | None) -> set[Path]:
    if range_spec is None:
        out = _git("diff", "--cached", "--name-only")
    else:
        out = _git("diff", "--name-only", range_spec)
    return {Path(line) for line in out.splitlines() if line}


def _markers_in_diff(
    path: Path, range_spec: str | None,
) -> tuple[set[str], set[str], set[str], set[str]]:
    """Return four ref sets describing the marker deltas for `path`.

    Returns ``(added_skill, added_doc, drift_skill, drift_doc)`` where:

    - ``added_skill``/``added_doc``: refs that appear on any ``+`` line.
      Used for structural validation (invalid target must fail even if
      it's a pure declarative add — otherwise typos slip in).
    - ``drift_skill``/``drift_doc``: refs whose *presence on the line*
      indicates a co-change is required. A marker on a ``-`` line always
      counts (edit/removal). A marker only on ``+`` lines with no matching
      ``-`` side is a pure declarative add — declaring "this line's
      meaning is captured by that doc" — and is NOT drift by itself.
    """
    if range_spec is None:
        cmd = ["diff", "--cached", "-U0", "--", str(path)]
    else:
        cmd = ["diff", "-U0", range_spec, "--", str(path)]
    diff = _git(*cmd)

    def collect(sign: str) -> tuple[set[str], set[str]]:
        skill: set[str] = set()
        doc: set[str] = set()
        for line in diff.splitlines():
            if line.startswith("+++") or line.startswith("---"):
                continue
            if not line.startswith(sign):
                continue
            body = line[1:]
            m_skill = SKILL_MARKER_RE.search(body)
            if m_skill:
                skill.add(m_skill.group(1))
            m_doc = DOC_MARKER_RE.search(body)
            if m_doc:
                for ref in m_doc.group(1).split(","):
                    ref = ref.strip()
                    if ref:
                        doc.add(ref)
        return skill, doc

    added_skill, added_doc = collect("+")
    removed_skill, removed_doc = collect("-")

    # Drift: removed refs always; added-and-also-removed = edit
    drift_skill = removed_skill | (added_skill & removed_skill)
    drift_doc = removed_doc | (added_doc & removed_doc)

    return added_skill, added_doc, drift_skill, drift_doc


def _skill_relpath(ref: str) -> Path | None:
    """Convert 'agent-api.md#flow-inspection' to a repo-relative Path.

    Returns None if the reference escapes the skill tree.
    """
    file_part = ref.split("#", 1)[0]
    resolved = (SKILL_REF_DIR / file_part).resolve()
    try:
        return resolved.relative_to(REPO_ROOT)
    except ValueError:
        return None


def _doc_relpath(ref: str) -> Path | None:
    """Convert 'docs/AGENTS.md#section' to a repo-relative Path.

    Returns None if the reference is outside the shipped-docs allowlist
    (user-facing docs plus skill files).
    """
    file_part = ref.split("#", 1)[0]
    if file_part not in ALL_SHIPPED_DOCS:
        return None
    return Path(file_part)


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

    problems: list[tuple[Path, str, str, str]] = []  # (source, kind, ref, why)
    for path in sorted(changed):
        if path.suffix not in SUPPORTED_SOURCE_SUFFIXES:
            continue
        path_str = str(path)
        if any(path_str.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES):
            continue
        added_skill, added_doc, drift_skill, drift_doc = _markers_in_diff(
            path, args.range,
        )

        # Structural validation applies to every ref that appears on any
        # `+` line: typos must fail even for pure declarative adds.
        for ref in added_skill:
            ref_path = _skill_relpath(ref)
            if ref_path is None:
                problems.append((path, "SKILL", ref, "reference escapes the skill tree"))
                continue
            if not (REPO_ROOT / ref_path).exists():
                problems.append((path, "SKILL", ref, f"reference file missing: {ref_path}"))
        for ref in added_doc:
            ref_path = _doc_relpath(ref)
            if ref_path is None:
                problems.append(
                    (path, "DOC", ref, "reference is not in shipped-docs allowlist "
                     "(user_facing_docs + skill_files in doc_allowlist.toml)"),
                )
                continue
            if not (REPO_ROOT / ref_path).exists():
                problems.append((path, "DOC", ref, f"reference file missing: {ref_path}"))

        # Drift validation: only refs from edited/removed marker lines
        # require the referenced doc to appear in the diff.
        for ref in drift_skill:
            ref_path = _skill_relpath(ref)
            if ref_path is None or not (REPO_ROOT / ref_path).exists():
                continue  # already reported above (or was on a removed line only)
            if ref_path not in changed:
                problems.append(
                    (path, "SKILL", ref, f"reference {ref_path} was not modified in this diff"),
                )
        for ref in drift_doc:
            ref_path = _doc_relpath(ref)
            if ref_path is None or not (REPO_ROOT / ref_path).exists():
                continue
            if ref_path not in changed:
                problems.append(
                    (path, "DOC", ref, f"reference {ref_path} was not modified in this diff"),
                )

    if problems:
        print(
            "check-skill-markers: markers changed without a matching doc update",
            file=sys.stderr,
        )
        for source, kind, ref, why in problems:
            print(f"  {source}: {kind}: {ref} -- {why}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
