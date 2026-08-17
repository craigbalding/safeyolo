"""Build canonical ``X-Test-Context`` values for test harnesses."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from ..test_context_contract import (
    CANONICAL_KEYS,
    TestContextError,
    atomic_write_test_context,
    format_test_context,
    format_test_context_header,
)


def _single_value(name: str, values: list[str] | None) -> str | None:
    if not values:
        return None
    if len(values) > 1:
        raise TestContextError(f"duplicate helper field: {name}")
    return values[0]


def _collect_fields(
    canonical: dict[str, list[str] | None],
    additional: list[str] | None,
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for key in CANONICAL_KEYS:
        value = _single_value(key, canonical[key])
        if value is not None:
            pairs.append((key, value))

    extra_keys: set[str] = set()
    for field in additional or []:
        if "=" not in field:
            raise TestContextError(f"--field must be KEY=VALUE, got {field!r}")
        key, _, value = field.partition("=")
        if key in CANONICAL_KEYS:
            raise TestContextError(f"canonical field {key!r} must use --{key}, not --field")
        if key in extra_keys:
            raise TestContextError(f"duplicate helper field: {key}")
        extra_keys.add(key)
        pairs.append((key, value))
    return pairs


def test_context(
    run: Optional[list[str]] = typer.Option(None, "--run", help="Campaign or session identifier"),
    agent: Optional[list[str]] = typer.Option(None, "--agent", help="Declared actor or tool attribution"),
    role: Optional[list[str]] = typer.Option(None, "--role", help="Identity used by the request"),
    suite: Optional[list[str]] = typer.Option(None, "--suite", help="Test collection identifier"),
    subject: Optional[list[str]] = typer.Option(None, "--subject", help="Thing or control under test"),
    step: Optional[list[str]] = typer.Option(None, "--step", help="Ordinal within the journey or test"),
    test: Optional[list[str]] = typer.Option(None, "--test", help="Specific test-case identifier"),
    intent: Optional[list[str]] = typer.Option(None, "--intent", help="Purpose of this request"),
    expect: Optional[list[str]] = typer.Option(None, "--expect", help="Expected outcome"),
    field: Optional[list[str]] = typer.Option(
        None,
        "--field",
        help="Additional safe KEY=VALUE field; repeatable",
    ),
    header: bool = typer.Option(False, "--header", help="Print a complete header line"),
    write: Optional[Path] = typer.Option(
        None,
        "--write",
        metavar="FILE",
        help="Atomically replace a watched context file",
    ),
) -> None:
    """Build a deterministic X-Test-Context value."""
    canonical = {
        "run": run,
        "agent": agent,
        "role": role,
        "suite": suite,
        "subject": subject,
        "step": step,
        "test": test,
        "intent": intent,
        "expect": expect,
    }
    try:
        pairs = _collect_fields(canonical, field)
        value = format_test_context(pairs)
        if write is not None:
            atomic_write_test_context(write, value)
    except (OSError, TestContextError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc

    typer.echo(format_test_context_header(pairs) if header else value)
