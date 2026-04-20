"""Docstring schema for blackbox tests.

Classes (threat categories) — docstring schema:
    Title on first line
    Why: block explaining the threat / security value

Functions (specific properties) — docstring schema:
    Title on first line
    What: block describing the probe
    Why: block describing the security consequence if the property didn't hold

The same docstrings drive docs/blackbox-coverage.md. Any test lacking the
schema fails at collection time so contributors see it locally on first run.
"""
import re


def check_function(docstring: str | None, qualname: str) -> list[str]:
    """Return a list of violation messages for a test function."""
    if not docstring or not docstring.strip():
        return [f"{qualname}: missing docstring"]
    lines = docstring.strip().splitlines()
    title = lines[0].strip()
    if not title or title.startswith(("What:", "Why:")):
        return [f"{qualname}: first line must be a Title (not 'What:'/'Why:')"]
    violations = []
    if not re.search(r"(?m)^\s*What:", docstring):
        violations.append(f"{qualname}: missing 'What:' section")
    if not re.search(r"(?m)^\s*Why:", docstring):
        violations.append(f"{qualname}: missing 'Why:' section")
    return violations


def check_class(docstring: str | None, qualname: str) -> list[str]:
    """Return a list of violation messages for a test class."""
    if not docstring or not docstring.strip():
        return [f"{qualname}: missing class docstring"]
    lines = docstring.strip().splitlines()
    if not lines[0].strip():
        return [f"{qualname}: first line must be a Title"]
    if not re.search(r"(?m)^\s*Why:", docstring):
        return [f"{qualname}: missing 'Why:' section"]
    return []


def validate_items(items) -> None:
    """Raise RuntimeError if any collected pytest item fails the schema."""
    violations = []
    seen_classes = set()
    for item in items:
        if not hasattr(item, "function"):
            continue
        func = item.function
        qualname = f"{item.module.__name__}::{func.__qualname__}"
        violations.extend(check_function(func.__doc__, qualname))
        if item.cls and item.cls.__name__ not in seen_classes:
            seen_classes.add(item.cls.__name__)
            cls_qualname = f"{item.module.__name__}::{item.cls.__name__}"
            violations.extend(check_class(item.cls.__doc__, cls_qualname))

    if violations:
        msg = "\n".join(f"  {v}" for v in violations)
        raise RuntimeError(
            f"Blackbox test docstring violations:\n{msg}\n\n"
            f"Schema:\n"
            f"  Class: Title (first line) + 'Why:' section\n"
            f"  Function: Title + 'What:' section + 'Why:' section\n"
        )
