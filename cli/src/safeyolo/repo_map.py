#!/usr/bin/env python3
"""Compact structural maps of a Git working tree."""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


class RepoMapError(RuntimeError):
    """The requested repository map cannot be produced."""


@dataclass(frozen=True)
class RepoMap:
    """Rendered map and small observability summary."""

    root: Path
    scope: Path
    text: str
    files: int
    symbols: int
    elapsed_ms: int


_SOURCE_SUFFIXES = {".c", ".h", ".py", ".sh", ".swift", ".toml", ".yaml", ".yml"}
_SOURCE_NAMES = {"AGENTS.md", "Makefile", "README.md", "SECURITY.md", "uv.lock"}
_SHELL_FUNCTION = re.compile(
    r"^\s*(?:function\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\(\s*\))?"
    r"|([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\))\s*\{"
)


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RepoMapError(detail or "Git command failed")
    return completed.stdout


def _repository_root(path: Path) -> Path:
    probe = path if path.is_dir() else path.parent
    try:
        value = _git(probe, "rev-parse", "--show-toplevel").strip()
    except RepoMapError as exc:
        raise RepoMapError(f"not inside a Git working tree: {path}") from exc
    return Path(value).resolve()


def _relative_scope(root: Path, requested: Path) -> Path:
    resolved = requested.resolve()
    try:
        return resolved.relative_to(root)
    except ValueError as exc:
        raise RepoMapError(f"path is outside repository: {requested}") from exc


def _source_files(root: Path, scope: Path) -> list[Path]:
    entries = _git(
        root,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        scope.as_posix() if scope != Path(".") else ".",
    ).split("\0")
    paths: list[Path] = []
    for value in entries:
        if not value:
            continue
        relative = Path(value)
        if relative.suffix not in _SOURCE_SUFFIXES and relative.name not in _SOURCE_NAMES:
            continue
        absolute = root / relative
        if absolute.is_file():
            paths.append(relative)
    return sorted(paths, key=lambda item: item.as_posix())


def _argument_names(arguments: ast.arguments, *, method: bool) -> str:
    positional = [*arguments.posonlyargs, *arguments.args]
    names = [argument.arg for argument in positional]
    if method and names and names[0] in {"self", "cls"}:
        names.pop(0)
    if arguments.posonlyargs:
        boundary = len(arguments.posonlyargs) - (1 if method and positional[0].arg in {"self", "cls"} else 0)
        if boundary > 0:
            names.insert(boundary, "/")
    if arguments.vararg:
        names.append(f"*{arguments.vararg.arg}")
    elif arguments.kwonlyargs:
        names.append("*")
    names.extend(argument.arg for argument in arguments.kwonlyargs)
    if arguments.kwarg:
        names.append(f"**{arguments.kwarg.arg}")
    return ", ".join(names)


def _python_symbols(path: Path, *, overview: bool) -> tuple[list[str], int]:
    try:
        source = path.read_text(encoding="utf-8")
        module = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return [], 0

    lines: list[str] = []
    count = 0
    for node in module.body:
        if isinstance(node, ast.ClassDef):
            if overview and node.name.startswith("_"):
                continue
            lines.append(f"  class {node.name} @{node.lineno}")
            count += 1
            if overview:
                continue
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    prefix = "async " if isinstance(child, ast.AsyncFunctionDef) else ""
                    args = _argument_names(child.args, method=True)
                    lines.append(f"    {prefix}def {child.name}({args}) @{child.lineno}")
                    count += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if overview and node.name.startswith("_"):
                continue
            prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
            if overview:
                lines.append(f"  {prefix}def {node.name} @{node.lineno}")
            else:
                args = _argument_names(node.args, method=False)
                lines.append(f"  {prefix}def {node.name}({args}) @{node.lineno}")
            count += 1
    return lines, count


def _shell_symbols(path: Path) -> tuple[list[str], int]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return [], 0
    lines = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        match = _SHELL_FUNCTION.match(line)
        if match:
            lines.append(f"  function {match.group(1) or match.group(2)}() @{lineno}")
    return lines, len(lines)


def _omit_from_overview(path: Path) -> bool:
    parts = path.parts
    return (
        "tests" in parts
        or path.name.startswith("test_")
        or parts[:4] == ("cli", "src", "safeyolo", "agent_context")
    )


def build_repo_map(path: Path | str = ".") -> RepoMap:
    """Build a deterministic structural map for ``path`` within its Git tree."""

    started = time.perf_counter()
    requested = Path(path)
    if not requested.exists():
        raise RepoMapError(f"path does not exist: {requested}")
    root = _repository_root(requested)
    scope = _relative_scope(root, requested)
    files = _source_files(root, scope)
    overview = scope == Path(".")
    if overview:
        files = [path for path in files if not _omit_from_overview(path)]

    output: list[str] = []
    symbol_count = 0
    for relative in files:
        absolute = root / relative
        if relative.suffix == ".py":
            symbols, count = _python_symbols(absolute, overview=overview)
        elif relative.suffix == ".sh" or relative.name == "Makefile":
            symbols, count = _shell_symbols(absolute)
        else:
            symbols, count = [], 0
        output.append(relative.as_posix())
        output.extend(symbols)
        symbol_count += count

    elapsed_ms = round((time.perf_counter() - started) * 1000)
    return RepoMap(
        root=root,
        scope=scope,
        text="\n".join(output),
        files=len(files),
        symbols=symbol_count,
        elapsed_ms=elapsed_ms,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the standalone agent-oriented repository map command."""

    parser = argparse.ArgumentParser(
        prog="repo-map",
        description="Show files and symbols in the current Git checkout.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=Path("."),
        type=Path,
        help="repository path to map (default: current directory)",
    )
    args = parser.parse_args(argv)
    try:
        result = build_repo_map(args.path)
    except RepoMapError as exc:
        print(f"repo-map: {exc}", file=sys.stderr)
        return 2

    scope = "." if result.scope == Path(".") else result.scope.as_posix()
    mode = "overview" if result.scope == Path(".") else "detail"
    print(
        f"# repo-map scope={scope} mode={mode} files={result.files} "
        f"symbols={result.symbols} elapsed_ms={result.elapsed_ms}"
    )
    if mode == "overview":
        print("# pass a repository-relative path for private symbols and class methods")
    if result.text:
        print(result.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
