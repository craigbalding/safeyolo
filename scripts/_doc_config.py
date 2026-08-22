"""Shared config loader for the doc-drift detection scripts.

Reads ``scripts/doc_allowlist.toml`` and exposes ``USER_FACING_DOCS`` as a
``frozenset[str]`` of repo-relative paths. All four drift-check scripts
import from here, so the allowlist has exactly one source of truth.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_ALLOWLIST_PATH = REPO_ROOT / "scripts" / "doc_allowlist.toml"


def _load_allowlist() -> frozenset[str]:
    if not _ALLOWLIST_PATH.exists():
        raise FileNotFoundError(
            f"doc allowlist config missing: {_ALLOWLIST_PATH}",
        )
    with _ALLOWLIST_PATH.open("rb") as f:
        cfg = tomllib.load(f)
    docs = cfg.get("user_facing_docs")
    if not isinstance(docs, list) or not all(isinstance(d, str) for d in docs):
        raise ValueError(
            f"{_ALLOWLIST_PATH}: 'user_facing_docs' must be a list of strings",
        )
    return frozenset(docs)


USER_FACING_DOCS: frozenset[str] = _load_allowlist()
