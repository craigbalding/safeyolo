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
_OVERVIEW_SYMBOL_LIMIT = 4
_DETAIL_IMPORT_LIMIT = 8
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


def _argument_name(argument: ast.arg) -> str:
    if argument.annotation is None:
        return argument.arg
    return f"{argument.arg}: {ast.unparse(argument.annotation)}"


def _argument_names(arguments: ast.arguments, *, method: bool) -> str:
    positional = [*arguments.posonlyargs, *arguments.args]
    omit_receiver = method and bool(positional) and positional[0].arg in {"self", "cls"}
    names = [_argument_name(argument) for argument in positional]
    if omit_receiver:
        names.pop(0)
    if arguments.posonlyargs:
        boundary = len(arguments.posonlyargs) - (1 if omit_receiver else 0)
        if boundary > 0:
            names.insert(boundary, "/")
    if arguments.vararg:
        names.append(f"*{_argument_name(arguments.vararg)}")
    elif arguments.kwonlyargs:
        names.append("*")
    names.extend(_argument_name(argument) for argument in arguments.kwonlyargs)
    if arguments.kwarg:
        names.append(f"**{_argument_name(arguments.kwarg)}")
    return ", ".join(names)


def _return_annotation(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    if node.returns is None:
        return ""
    return f" -> {ast.unparse(node.returns)}"


def _decorators(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [f"@{ast.unparse(decorator)}" for decorator in node.decorator_list]


def _internal_imports(module: ast.Module) -> list[str]:
    imports: list[str] = []
    for node in module.body:
        if isinstance(node, ast.Import):
            names = [
                alias
                for alias in node.names
                if alias.name == "safeyolo" or alias.name.startswith("safeyolo.")
            ]
            if names:
                imports.append(ast.unparse(ast.Import(names=names)))
        elif isinstance(node, ast.ImportFrom) and (
            node.level
            or node.module == "safeyolo"
            or (node.module or "").startswith("safeyolo.")
        ):
            imports.append(ast.unparse(node))
    if len(imports) > _DETAIL_IMPORT_LIMIT:
        omitted = len(imports) - _DETAIL_IMPORT_LIMIT
        return [*imports[:_DETAIL_IMPORT_LIMIT], f"+{omitted} internal imports"]
    return imports


def _python_symbols(path: Path, *, overview: bool) -> tuple[list[str], int]:
    try:
        source = path.read_text(encoding="utf-8")
        module = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return [], 0

    lines: list[str] = []
    count = 0
    if not overview:
        lines.extend(f"  uses {statement}" for statement in _internal_imports(module))
    for node in module.body:
        if isinstance(node, ast.ClassDef):
            if overview and node.name.startswith("_"):
                continue
            if not overview:
                lines.extend(f"  {decorator}" for decorator in _decorators(node))
            bases = ""
            if not overview and node.bases:
                bases = f"({', '.join(ast.unparse(base) for base in node.bases)})"
            lines.append(f"  class {node.name}{bases} @{node.lineno}")
            count += 1
            if overview:
                continue
            for child in node.body:
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                    annotation = ast.unparse(child.annotation)
                    lines.append(f"    {child.target.id}: {annotation} @{child.lineno}")
                    count += 1
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    lines.extend(
                        f"    {decorator}" for decorator in _decorators(child)
                    )
                    prefix = "async " if isinstance(child, ast.AsyncFunctionDef) else ""
                    args = _argument_names(child.args, method=True)
                    returns = _return_annotation(child)
                    lines.append(
                        f"    {prefix}def {child.name}({args}){returns} @{child.lineno}"
                    )
                    count += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if overview and node.name.startswith("_"):
                continue
            prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
            if overview:
                lines.append(f"  {prefix}def {node.name} @{node.lineno}")
            else:
                lines.extend(f"  {decorator}" for decorator in _decorators(node))
                args = _argument_names(node.args, method=False)
                returns = _return_annotation(node)
                lines.append(f"  {prefix}def {node.name}({args}){returns} @{node.lineno}")
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


def _overview_line(relative: Path, symbols: list[str], count: int) -> str:
    """Render one bounded, token-dense line for a directory map."""

    if "tests" in relative.parts or relative.name.startswith("test_"):
        return relative.as_posix()
    shown = [symbol.strip() for symbol in symbols[:_OVERVIEW_SYMBOL_LIMIT]]
    if count > len(shown):
        shown.append(f"+{count - len(shown)} symbols")
    suffix = f" | {'; '.join(shown)}" if shown else ""
    return f"{relative.as_posix()}{suffix}"


def build_repo_map(path: Path | str = ".") -> RepoMap:
    """Build a deterministic structural map for ``path`` within its Git tree."""

    started = time.perf_counter()
    requested = Path(path)
    if not requested.exists():
        raise RepoMapError(f"path does not exist: {requested}")
    root = _repository_root(requested)
    scope = _relative_scope(root, requested)
    files = _source_files(root, scope)
    overview = requested.is_dir()
    if scope == Path("."):
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
        if overview:
            output.append(_overview_line(relative, symbols, count))
        else:
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


def _compact_requested_paths(paths: list[Path]) -> list[Path]:
    """Keep distinct, most-specific scopes from one working tree."""

    resolved: list[tuple[Path, Path, Path]] = []
    for requested in paths:
        if not requested.exists():
            raise RepoMapError(f"path does not exist: {requested}")
        root = _repository_root(requested)
        scope = _relative_scope(root, requested)
        if resolved and root != resolved[0][1]:
            raise RepoMapError("all paths must belong to the same Git working tree")
        if not any(scope == seen_scope for _, _, seen_scope in resolved):
            resolved.append((requested, root, scope))

    return [
        requested
        for requested, _, scope in resolved
        if not any(
            scope != other_scope and scope in other_scope.parents
            for _, _, other_scope in resolved
        )
    ]


def main(argv: list[str] | None = None) -> int:
    """Run the standalone agent-oriented repository map command."""

    parser = argparse.ArgumentParser(
        prog="repo-map",
        description="Show files and symbols in the current Git checkout.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        metavar="PATH",
        help=(
            "repository file or directory to map; multiple paths are allowed "
            "(default: current directory)"
        ),
    )
    args = parser.parse_args(argv)
    try:
        paths = _compact_requested_paths(args.paths or [Path(".")])
        results = [build_repo_map(path) for path in paths]
    except RepoMapError as exc:
        print(f"repo-map: {exc}", file=sys.stderr)
        return 2

    for index, result in enumerate(results):
        if index:
            print()
        scope = "." if result.scope == Path(".") else result.scope.as_posix()
        mode = "overview" if paths[index].is_dir() else "detail"
        print(
            f"# repo-map scope={scope} mode={mode} files={result.files} "
            f"symbols={result.symbols} elapsed_ms={result.elapsed_ms}"
        )
        if mode == "overview":
            print("# pass repository-relative paths for private symbols and class methods")
        if result.text:
            print(result.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
