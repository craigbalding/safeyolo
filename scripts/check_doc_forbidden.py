#!/usr/bin/env python3
"""Fail when a user-facing doc contains a blacklisted phrase.

For the drift class where the code that used to defend the claim has been
removed. No enforcement site left to bind a `# DOC:` marker to, and no
pinned value to extract with check_doc_constants.py — only prose
vigilance catches these.

Rule set lives in ``scripts/doc_forbidden.toml``. Each rule names the
phrases that must NOT appear in a specified set of user-facing docs, plus
a ``reason`` string that gets printed on failure.

Complements the other three checks:

- check_skill_markers.py   -- source drift → doc must update
- check_doc_cli_flags.py   -- docs can't reference nonexistent CLI surface
- check_doc_constants.py   -- pinned source values must match doc quotes
- check_doc_forbidden.py   -- (this) stale mechanism claims can't survive

Exit codes
----------

    0  -- no blacklisted phrases found
    1  -- one or more phrases found
    2  -- config missing, unparseable, or malformed
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "scripts" / "doc_forbidden.toml"


def _load_rules() -> list[dict]:
    if not CONFIG_PATH.exists():
        print(
            f"check-doc-forbidden: config missing: {CONFIG_PATH}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    with CONFIG_PATH.open("rb") as f:
        cfg = tomllib.load(f)
    return cfg.get("rule", [])


def _check_rule(rule: dict) -> list[str]:
    """Return a list of error strings; empty on success."""
    name = rule.get("name", "<unnamed>")
    docs = rule.get("docs")
    forbidden = rule.get("forbidden")
    reason = rule.get("reason", "")

    if not isinstance(docs, list) or not docs:
        return [f"{name}: rule has no docs list"]
    if not isinstance(forbidden, list) or not forbidden:
        return [f"{name}: rule has no forbidden list"]

    problems: list[str] = []
    for doc_rel in docs:
        doc_path = REPO_ROOT / doc_rel
        if not doc_path.exists():
            problems.append(f"{name}: doc not found: {doc_rel}")
            continue
        text = doc_path.read_text()
        for phrase in forbidden:
            if phrase in text:
                suffix = f" — {reason}" if reason else ""
                problems.append(
                    f"{name}: {doc_rel} contains blacklisted phrase '{phrase}'{suffix}",
                )
    return problems


def main() -> int:
    try:
        rules = _load_rules()
    except SystemExit as e:
        return int(e.code) if e.code is not None else 2

    all_problems: list[str] = []
    for rule in rules:
        all_problems.extend(_check_rule(rule))

    if all_problems:
        print(
            "check-doc-forbidden: forbidden phrases found in user-facing docs:",
            file=sys.stderr,
        )
        for p in all_problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
