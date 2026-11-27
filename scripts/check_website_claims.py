#!/usr/bin/env python3
"""Fail when a website page does not name the evidence for its claims.

Each page under ``website/`` (``index.html`` files) lists, in its front
matter, the maintained claims its prose relies on:

    claims:
    - BB-01                      # tests/blackbox/controls.toml control
    - decision:credentials       # docs/assurance-map.toml decision
    - factory:FACTORY-RUN-REQUIRES-COORD  # tests/assurance.toml behavior

This check confirms that every page has a non-empty list, that each ID exists
in its source, and that each black-box control has at least one witness. It
does not judge whether the prose matches the claim; reviewers do that, with
these IDs as the starting point.

Exit codes
----------
    0  -- every page names existing, witnessed claims
    1  -- page claims are malformed, missing, unknown, duplicated or unwitnessed
    2  -- a claim source is missing or unparseable
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE = "website"
CONTROLS = "tests/blackbox/controls.toml"
ASSURANCE_MAP = "docs/assurance-map.toml"
TEST_ASSURANCE = "tests/assurance.toml"

def _load_toml(relative: str) -> dict:
    path = REPO_ROOT / relative
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"check-website-claims: cannot read {relative}: {error}", file=sys.stderr)
        raise SystemExit(2) from error

def known_claims() -> dict[str, str | None]:
    """Map each claim ID to None when usable, or to the reason it is not."""
    controls = _load_toml(CONTROLS)
    witnessed = {control for witness in controls.get("witnesses", []) for control in witness["controls"]}
    claims: dict[str, str | None] = {}
    for control in controls.get("controls", []):
        identifier = control["id"]
        claims[identifier] = None if identifier in witnessed else f"{identifier} has no witness in {CONTROLS}"
    for decision in _load_toml(ASSURANCE_MAP).get("decisions", []):
        claims[f"decision:{decision['id']}"] = None
    for behavior in _load_toml(TEST_ASSURANCE).get("factory_acceptance", []):
        claims[f"factory:{behavior['id']}"] = None
    return claims

def page_claims(text: str) -> list[str] | None:
    """Parse YAML claims, returning None when front matter or claims are absent."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    try:
        end = lines.index("---", 1)
    except ValueError:
        return None
    front = yaml.safe_load("\n".join(lines[1:end]))
    if front is None:
        return None
    if not isinstance(front, dict):
        raise ValueError("front matter must be a YAML mapping")
    if "claims" not in front:
        return None
    claims = front.get("claims")
    if not isinstance(claims, list) or not claims or not all(isinstance(claim, str) for claim in claims):
        raise ValueError("front matter needs a non-empty claims list of strings")
    return claims

def pages() -> list[Path]:
    return sorted((REPO_ROOT / WEBSITE).rglob("index.html"))

def check() -> list[str]:
    known = known_claims()
    problems: list[str] = []
    for page in pages():
        relative = page.relative_to(REPO_ROOT)
        try:
            claims = page_claims(page.read_text())
        except (yaml.YAMLError, ValueError) as error:
            problems.append(f"{relative}: invalid front matter: {error}")
            continue
        if not claims:
            problems.append(f"{relative}: front matter needs a non-empty claims list")
            continue
        seen: set[str] = set()
        for claim in claims:
            if claim in seen:
                problems.append(f"{relative}: {claim} is listed twice")
            seen.add(claim)
            if claim not in known:
                problems.append(f"{relative}: unknown claim {claim}")
            elif known[claim]:
                problems.append(f"{relative}: {known[claim]}")
    return problems

def main() -> int:
    try:
        problems = check()
    except SystemExit as error:
        return int(error.code) if error.code is not None else 2
    if problems:
        print("check-website-claims: website claims are not grounded:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
