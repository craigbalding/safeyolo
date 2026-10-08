"""Parser and formatter contract for ``X-SafeYolo-Test-Context`` provenance."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path

TEST_CONTEXT_HEADER = "X-SafeYolo-Test-Context"  # SKILL: agent-api.md#flow-inspection
REQUIRED_KEYS = ("run", "agent")
CANONICAL_KEYS = (
    "run",
    "agent",
    "role",
    "suite",
    "subject",
    "step",
    "test",
    "intent",
    "expect",
)
MAX_CONTEXT_PAIRS = 20

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_CANONICAL_ORDER = {key: index for index, key in enumerate(CANONICAL_KEYS)}


class TestContextError(ValueError):
    """An ``X-SafeYolo-Test-Context`` value does not satisfy the shared contract."""


def validate_context_pair(key: str, value: str) -> tuple[str, str]:
    """Validate and return one context key/value pair without rewriting it."""
    if not isinstance(key, str) or not key:
        raise TestContextError("context key must be a non-empty string")
    if not isinstance(value, str) or not value:
        raise TestContextError(f"context value for {key!r} must be a non-empty string")
    if not _SAFE_TOKEN_RE.fullmatch(key):
        raise TestContextError(f"context key {key!r} contains characters outside [A-Za-z0-9_.:-]")
    if not _SAFE_TOKEN_RE.fullmatch(value):
        raise TestContextError(f"context value for {key!r} contains characters outside [A-Za-z0-9_.:-]")
    return key, value


def _validate_pairs(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for pair in pairs:
        try:
            key, value = pair
        except (TypeError, ValueError) as exc:
            raise TestContextError("context fields must be key/value pairs") from exc
        key, value = validate_context_pair(key, value)
        if key in fields:
            raise TestContextError(f"duplicate context key: {key}")
        fields[key] = value
        if len(fields) > MAX_CONTEXT_PAIRS:
            raise TestContextError(f"context has more than {MAX_CONTEXT_PAIRS} key/value pairs")

    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        raise TestContextError(f"missing required context field(s): {', '.join(missing)}")
    return fields


def parse_test_context(value: str) -> dict[str, str]:
    """Parse and validate a semicolon-delimited context header value."""
    if not isinstance(value, str) or not value.strip():
        raise TestContextError("context header value must not be empty")

    pairs: list[tuple[str, str]] = []
    for raw_part in value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        if "=" not in part:
            raise TestContextError(f"context field has no '=' separator: {part!r}")
        key, _, field_value = part.partition("=")
        pairs.append((key.strip(), field_value.strip()))
    return _validate_pairs(pairs)


def format_test_context(
    fields: Mapping[str, str] | Iterable[tuple[str, str]],
) -> str:
    """Validate and deterministically format an ``X-SafeYolo-Test-Context`` value."""
    pairs = fields.items() if isinstance(fields, Mapping) else fields
    validated = _validate_pairs(pairs)
    ordered = sorted(
        validated,
        key=lambda key: (
            0 if key in _CANONICAL_ORDER else 1,
            _CANONICAL_ORDER.get(key, 0),
            key,
        ),
    )
    return ";".join(f"{key}={validated[key]}" for key in ordered)


def format_test_context_header(
    fields: Mapping[str, str] | Iterable[tuple[str, str]],
) -> str:
    """Return a complete ``X-SafeYolo-Test-Context: <value>`` header line."""
    return f"{TEST_CONTEXT_HEADER}: {format_test_context(fields)}"


def atomic_write_test_context(path: Path, value: str) -> None:
    """Atomically replace a watched context file with a validated value."""
    parsed = parse_test_context(value)
    canonical_value = format_test_context(parsed)
    if canonical_value != value:
        raise TestContextError("context file value must already be in canonical form")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_file.write(value)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_path = Path(temp_file.name)
        os.replace(temp_path, path)
        temp_path = None

        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
