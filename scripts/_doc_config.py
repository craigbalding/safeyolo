"""Shared config loader for the doc-drift detection scripts.

Reads ``scripts/doc_allowlist.toml`` and exposes three frozensets of
repo-relative paths:

- ``USER_FACING_DOCS`` — human-operator docs (README.md, SECURITY.md,
  docs/*, guest/README.md, cli/README.md, contrib/*.md)
- ``SKILL_FILES``     — agent-facing shipped skill docs (SKILL.md +
  references/*.md); glob patterns in the TOML are expanded at load time
- ``ALL_SHIPPED_DOCS`` — union of the above; used by checks that scan
  every shipped doc irrespective of audience

All doc-drift scripts import from here so the allowlist has exactly one
source of truth. Glob expansion means adding a new skill reference file
brings it under coverage automatically.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_ALLOWLIST_PATH = REPO_ROOT / "scripts" / "doc_allowlist.toml"


def _expand_patterns(patterns: list[str]) -> frozenset[str]:
    """Expand shell-style globs relative to REPO_ROOT.

    Non-glob entries pass through as literal repo-relative strings.
    Missing literal paths are still included so the caller can detect
    "config lists a file that doesn't exist" as a real error, rather
    than silently dropping it here.
    """
    resolved: set[str] = set()
    for pattern in patterns:
        if any(ch in pattern for ch in "*?["):
            for path in REPO_ROOT.glob(pattern):
                if path.is_file():
                    resolved.add(str(path.relative_to(REPO_ROOT)))
        else:
            resolved.add(pattern)
    return frozenset(resolved)


def _load() -> tuple[frozenset[str], frozenset[str]]:
    if not _ALLOWLIST_PATH.exists():
        raise FileNotFoundError(
            f"doc allowlist config missing: {_ALLOWLIST_PATH}",
        )
    with _ALLOWLIST_PATH.open("rb") as f:
        cfg = tomllib.load(f)

    def _require_str_list(key: str, allow_missing: bool) -> list[str]:
        value = cfg.get(key)
        if value is None and allow_missing:
            return []
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ValueError(
                f"{_ALLOWLIST_PATH}: '{key}' must be a list of strings",
            )
        return value

    user_facing = _expand_patterns(_require_str_list("user_facing_docs", False))
    skill_files = _expand_patterns(_require_str_list("skill_files", True))
    return user_facing, skill_files


USER_FACING_DOCS, SKILL_FILES = _load()
ALL_SHIPPED_DOCS: frozenset[str] = USER_FACING_DOCS | SKILL_FILES
