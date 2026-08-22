#!/usr/bin/env python3
"""Fail when a value pinned in source code doesn't match the value quoted
in user-facing docs (or when the doc still contains a stale phrase blacklisted
by the assertion).

Complements ``check_skill_markers.py`` and ``check_doc_cli_flags.py``:

- check_skill_markers.py: co-change contract for marked lines
- check_doc_cli_flags.py: docs cannot reference non-existent CLI surface
- check_doc_constants.py: pinned values (versions, sizes, IPs, uids)
  quoted in docs must match the source

Assertions live in scripts/doc_constants.toml — see that file for schema.

Exit codes
----------

    0  -- every assertion holds
    1  -- one or more assertions failed (constant absent or forbidden phrase present)
    2  -- environment problem (missing config, broken TOML, unresolvable pattern)
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "scripts" / "doc_constants.toml"


def _load_assertions() -> list[dict]:
    if not CONFIG_PATH.exists():
        print(f"check-doc-constants: config missing: {CONFIG_PATH}", file=sys.stderr)
        raise SystemExit(2)
    with CONFIG_PATH.open("rb") as f:
        cfg = tomllib.load(f)
    return cfg.get("assertion", [])


def _check_one(assertion: dict) -> list[str]:
    """Return a list of error strings; empty on success.

    Supports two forms of "must appear" assertion:

    - ``must_contain``: single templated string; must appear verbatim.
    - ``must_contain_any``: list of templated alternatives; at least one
      must appear. Use for the "these all mean the same thing in prose"
      case (e.g. ``["127.0.0.1", "loopback only"]``) so a rewrite doesn't
      trigger spurious failures.

    Using both on the same assertion is a config error — pick one.
    """
    name = assertion.get("name", "<unnamed>")
    source_rel = assertion["source"]
    pattern = assertion["pattern"]
    docs = assertion["docs"]
    must_template = assertion.get("must_contain", "")
    must_any_templates: list[str] = assertion.get("must_contain_any", []) or []
    forbidden = assertion.get("forbidden", [])

    if must_template and must_any_templates:
        return [
            f"{name}: use either 'must_contain' OR 'must_contain_any', not both",
        ]

    source_path = REPO_ROOT / source_rel
    if not source_path.exists():
        return [f"{name}: source file not found: {source_rel}"]

    try:
        rx = re.compile(pattern)
    except re.error as e:
        return [f"{name}: invalid regex: {e}"]

    match = rx.search(source_path.read_text())
    if match is None:
        return [
            f"{name}: pattern did not match in {source_rel}. Update the assertion "
            "or the source.",
        ]

    captures = match.groupdict()
    try:
        must_have = must_template.format(**captures) if must_template else ""
        must_have_alternatives = [t.format(**captures) for t in must_any_templates]
    except KeyError as e:
        return [
            f"{name}: must_contain/must_contain_any template references "
            f"unknown capture: {e}",
        ]

    problems: list[str] = []
    for doc_rel in docs:
        doc_path = REPO_ROOT / doc_rel
        if not doc_path.exists():
            problems.append(f"{name}: doc not found: {doc_rel}")
            continue
        doc_text = doc_path.read_text()
        if must_have and must_have not in doc_text:
            problems.append(
                f"{name}: {doc_rel} is missing required substring "
                f"'{must_have}' (source pins it in {source_rel})",
            )
        if must_have_alternatives and not any(
            alt in doc_text for alt in must_have_alternatives
        ):
            alt_list = " OR ".join(f"'{a}'" for a in must_have_alternatives)
            problems.append(
                f"{name}: {doc_rel} is missing any of {alt_list} "
                f"(source pins the value in {source_rel})",
            )
        for bad in forbidden:
            if bad in doc_text:
                problems.append(
                    f"{name}: {doc_rel} still contains stale phrase '{bad}' "
                    f"(pattern in {source_rel} indicates it should be gone)",
                )
    return problems


def main() -> int:
    try:
        assertions = _load_assertions()
    except SystemExit as e:
        return int(e.code) if e.code is not None else 2

    all_problems: list[str] = []
    for a in assertions:
        all_problems.extend(_check_one(a))

    if all_problems:
        print(
            "check-doc-constants: pinned values drifted from user-facing docs:",
            file=sys.stderr,
        )
        for p in all_problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
