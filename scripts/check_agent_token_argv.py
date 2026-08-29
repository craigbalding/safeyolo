#!/usr/bin/env python3
"""Reject Agent API curl examples that put bearer tokens in process argv.

The Agent API token is read from ``/app/agent_token`` (or the host-side
equivalent). Expanding that value inside ``curl -H``/``--header`` makes the
bearer visible through process listings. Shipped examples instead pipe one
header line to ``curl --header @-``.

This check scans documentation, skill graphs, shell examples, and blackbox
tests. It is deliberately source-aware: placeholder headers, admin/service
credentials, and in-process HTTP test fixtures are outside its scope.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_TEXT_SUFFIXES = frozenset({".md", ".mmd", ".py", ".sh", ".yaml", ".yml"})
_SCAN_DIRS = ("cli", "contrib", "docs", "guest", "scripts", "tests", "vm")
_EXCLUDED = frozenset({
    "scripts/check_agent_token_argv.py",
    "tests/test_check_agent_token_argv.py",
})

_AUTH = r"authorization\s*:\s*bearer"
_TOKEN_SOURCE = (
    r"(?:/app\s*/\s*agent_token"
    r"|\b(?:[a-z_][a-z0-9_]*_)?agent_token\b"
    r"|\$\{?(?:[a-z_][a-z0-9_]*_)?token_file\}?)"
)
_TOKEN_READ_SUBSTITUTION = (
    r"(?:\$\((?:(?!\)).){0,300}"
    + _TOKEN_SOURCE
    + r"(?:(?!\)).)*\)"
    + r"|`(?:(?!`).){0,300}"
    + _TOKEN_SOURCE
    + r"(?:(?!`).)*`)"
)

# Unsafe direct form, allowing normal quote/spacing variations and a wrapped
# command substitution. Requiring the token read to occur *after* the header
# prefix avoids rejecting the safe ``read token; printf header | curl @-``
# pattern when it is represented on one graph-label line.
_DIRECT_HEADER_SUBSTITUTION_RE = re.compile(
    _AUTH
    + r"(?:(?!\n\s*\n).){0,400}"
    + _TOKEN_READ_SUBSTITUTION,
    re.IGNORECASE | re.DOTALL,
)

# Track the common two-step variant:
#   token=$(cat /app/agent_token)
#   curl -H "Authorization: Bearer $token" ...
_TOKEN_ASSIGNMENT_RE = re.compile(
    r"(?m)^\s*(?:(?:local|readonly|export)\s+)?"
    r"(?P<name>[a-z_][a-z0-9_]*)\s*=\s*"
    r"[\"']?(?P<read>" + _TOKEN_READ_SUBSTITUTION + r")[\"']?",
    re.IGNORECASE,
)

# Python blackbox helpers can build curl argv without shell syntax. Limit the
# rule to a curl argument list (or a list added to an existing curl command),
# leaving in-process request/header fixtures alone.
_PYTHON_ARG_LIST_RE = re.compile(
    r"(?:subprocess\.(?:run|popen)\s*\(\s*|"
    r"(?:cmd|command|args)\s*=\s*|\.(?:extend|append)\s*\(\s*)"
    r"\[(?P<body>(?:(?!\]\s*\)?).){0,1600})\]",
    re.IGNORECASE | re.DOTALL,
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_token_read(value: str) -> bool:
    return re.search(_TOKEN_SOURCE, value, re.IGNORECASE) is not None


def _unsafe_curl_header_for_var(text: str, name: str) -> re.Match[str] | None:
    """Find a curl header argument that interpolates ``name`` directly."""
    logical = text.replace("\\\n", " ")
    variable = rf"\$(?:\{{\s*)?{re.escape(name)}(?:\s*\}})?"
    pattern = re.compile(
        r"curl\b[^\n;]{0,1200}(?:-H\s*|--header(?:\s+|=))"
        r"(?!@-\b)[^\n;]{0,300}"
        + _AUTH
        + r"[^\n;]{0,300}"
        + variable,
        re.IGNORECASE,
    )
    return pattern.search(logical)


def find_unsafe_token_argv(text: str) -> list[tuple[int, str]]:
    """Return ``(line, reason)`` findings for one text file."""
    findings: list[tuple[int, str]] = []

    for match in _DIRECT_HEADER_SUBSTITUTION_RE.finditer(text):
        findings.append((
            _line_number(text, match.start()),
            "Agent API token command substitution is inside a curl header argument",
        ))

    for assignment in _TOKEN_ASSIGNMENT_RE.finditer(text):
        if not _is_token_read(assignment.group("read")):
            continue
        tail = text[assignment.end():]
        header = _unsafe_curl_header_for_var(tail, assignment.group("name"))
        if header is not None:
            findings.append((
                _line_number(text, assignment.end() + header.start()),
                "Agent API token variable is interpolated into a curl header argument",
            ))

    for match in _PYTHON_ARG_LIST_RE.finditer(text):
        body = match.group("body")
        if not re.search(r"[\"']curl[\"']", body, re.IGNORECASE):
            # ``cmd.extend([...])`` usually omits curl because the base command
            # was built just above; the method spelling is enough there.
            prefix = text[match.start():match.start("body")]
            if not re.search(r"\.(?:extend|append)\s*\(", prefix, re.IGNORECASE):
                continue
        if not re.search(r"[\"'](?:-H|--header)[\"']", body, re.IGNORECASE):
            continue
        if not re.search(_AUTH, body, re.IGNORECASE):
            continue
        if not re.search(r"(?:\{[^}]*token[^}]*\}|\+\s*\w*token\b)", body, re.IGNORECASE):
            continue
        findings.append((
            _line_number(text, match.start()),
            "Agent API bearer value is constructed inside a curl argv list",
        ))

    return sorted(set(findings))


def _scan_files(root: Path) -> list[Path]:
    files: set[Path] = set()
    for path in root.iterdir():
        if path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES:
            files.add(path)
    for directory in _SCAN_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES:
                files.add(path)
    return sorted(
        path for path in files
        if path.relative_to(root).as_posix() not in _EXCLUDED
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
    )


def main() -> int:
    problems: list[tuple[Path, int, str]] = []
    for path in _scan_files(REPO_ROOT):
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(REPO_ROOT)
        for line, reason in find_unsafe_token_argv(text):
            problems.append((rel, line, reason))

    if problems:
        print(
            "check-agent-token-argv: Agent API bearer would be exposed in process argv:",
            file=sys.stderr,
        )
        for path, line, reason in problems:
            print(f"  {path}:{line}: {reason}", file=sys.stderr)
        print(
            "  read the token at call time, pipe the header line, and use curl --header @-",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
