#!/usr/bin/env python3
"""Compact structural maps of a Git working tree."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import tomllib
from collections import Counter
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


@dataclass(frozen=True)
class RepoQuery:
    """Task-conditioned locations, guidance, and observability."""

    root: Path
    head: str
    text: str
    files: int
    indexed_files: int
    cached_files: int
    elapsed_ms: int


@dataclass(frozen=True)
class _QuerySymbol:
    name: str
    kind: str
    line: int
    end_line: int | None = None


@dataclass(frozen=True)
class _QueryRecord:
    path: str
    terms: Counter[str]


@dataclass(frozen=True)
class _QueryHint:
    identifier: str
    triggers: tuple[str, ...]
    advice: str
    paths: tuple[str, ...]
    source: str


_SOURCE_SUFFIXES = {".c", ".h", ".py", ".sh", ".swift", ".toml", ".yaml", ".yml"}
_SOURCE_NAMES = {"AGENTS.md", "Makefile", "README.md", "SECURITY.md", "uv.lock"}
_QUERY_SUFFIXES = _SOURCE_SUFFIXES | {".conf", ".json", ".md"}
_OVERVIEW_SYMBOL_LIMIT = 4
_DETAIL_IMPORT_LIMIT = 8
_QUERY_TERM_LIMIT = 32
_QUERY_FILE_LIMIT = 10
_QUERY_FILE_BYTES = 1_000_000
_QUERY_CACHE_VERSION = 2
_SHELL_FUNCTION = re.compile(
    r"^\s*(?:function\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\(\s*\))?"
    r"|([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\))\s*\{"
)
_SHELL_ASSIGNMENT = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=")
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.\-/]*|[0-9]+(?:\.[0-9]+)*")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WORK_ITEM_REFERENCE = re.compile(
    r"(?ix)"
    r"(?<![A-Za-z0-9_])"
    r"(?:pull[\s_-]+requests?|prs?|issues?)[\s:/#_-]*\d+\b"
    r"|(?<![A-Za-z0-9_])\#\d+\b"
)
_STOP_WORDS = {
    "about",
    "actual",
    "after",
    "again",
    "against",
    "also",
    "and",
    "any",
    "already",
    "an",
    "are",
    "around",
    "as",
    "at",
    "be",
    "before",
    "being",
    "both",
    "but",
    "by",
    "can",
    "change",
    "changes",
    "current",
    "do",
    "does",
    "each",
    "ensure",
    "every",
    "existing",
    "for",
    "from",
    "has",
    "have",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "keep",
    "make",
    "may",
    "more",
    "must",
    "no",
    "not",
    "of",
    "on",
    "one",
    "only",
    "or",
    "other",
    "our",
    "outcome",
    "over",
    "preserve",
    "required",
    "same",
    "should",
    "than",
    "that",
    "the",
    "their",
    "then",
    "this",
    "through",
    "to",
    "under",
    "up",
    "use",
    "using",
    "was",
    "we",
    "what",
    "when",
    "where",
    "which",
    "will",
    "with",
    "without",
    "work",
    "workflow",
    "you",
}


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


def _head_identity(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "--verify", "HEAD").strip()
    except RepoMapError:
        return "unborn"


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


def _line_range(line: int, end_line: int | None) -> str:
    if end_line is None or end_line == line:
        return f"@{line}"
    return f"@{line}-{end_line}"


def _internal_imports(module: ast.Module) -> list[str]:
    imports: list[str] = []
    for node in module.body:
        if isinstance(node, ast.Import):
            names = [alias for alias in node.names if alias.name == "safeyolo" or alias.name.startswith("safeyolo.")]
            if names:
                imports.append(ast.unparse(ast.Import(names=names)))
        elif isinstance(node, ast.ImportFrom) and (
            node.level or node.module == "safeyolo" or (node.module or "").startswith("safeyolo.")
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
            lines.append(f"  class {node.name}{bases} {_line_range(node.lineno, node.end_lineno)}")
            count += 1
            if overview:
                continue
            for child in node.body:
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                    annotation = ast.unparse(child.annotation)
                    lines.append(f"    {child.target.id}: {annotation} @{child.lineno}")
                    count += 1
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    lines.extend(f"    {decorator}" for decorator in _decorators(child))
                    prefix = "async " if isinstance(child, ast.AsyncFunctionDef) else ""
                    args = _argument_names(child.args, method=True)
                    returns = _return_annotation(child)
                    lines.append(
                        f"    {prefix}def {child.name}({args}){returns} {_line_range(child.lineno, child.end_lineno)}"
                    )
                    count += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if overview and node.name.startswith("_"):
                continue
            prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
            if overview:
                lines.append(f"  {prefix}def {node.name} {_line_range(node.lineno, node.end_lineno)}")
            else:
                lines.extend(f"  {decorator}" for decorator in _decorators(node))
                args = _argument_names(node.args, method=False)
                returns = _return_annotation(node)
                lines.append(f"  {prefix}def {node.name}({args}){returns} {_line_range(node.lineno, node.end_lineno)}")
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
    return "tests" in parts or path.name.startswith("test_") or parts[:4] == ("cli", "src", "safeyolo", "agent_context")


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


def _split_query_token(value: str) -> list[str]:
    normalized = value.casefold().strip("./-")
    if not normalized:
        return []
    pieces = [normalized]
    for path_piece in re.split(r"[./-]+", value):
        for snake_piece in path_piece.split("_"):
            pieces.extend(_CAMEL_BOUNDARY.sub(" ", snake_piece).casefold().split())
    return list(dict.fromkeys(piece for piece in pieces if piece))


def _query_terms(text: str, *, remove_stop_words: bool = False) -> Counter[str]:
    result: Counter[str] = Counter()
    for match in _TOKEN.finditer(text):
        for token in _split_query_token(match.group(0)):
            if len(token) < 2 or (remove_stop_words and token in _STOP_WORDS):
                continue
            result[token] += 1
    return result


def _task_query_terms(text: str) -> Counter[str]:
    """Tokenize a task without letting its work-item identifier drive ranking."""
    return _query_terms(_WORK_ITEM_REFERENCE.sub(" ", text), remove_stop_words=True)


def _query_files(root: Path) -> list[Path]:
    entries = _git(
        root,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    ).split("\0")
    paths = []
    for value in entries:
        if not value:
            continue
        relative = Path(value)
        if relative.name == "repo-map.toml":
            continue
        if not (relative.suffix in _QUERY_SUFFIXES or relative.name in _SOURCE_NAMES or not relative.suffix):
            continue
        absolute = root / relative
        if absolute.is_file() and absolute.stat().st_size <= _QUERY_FILE_BYTES:
            paths.append(relative)
    return sorted(paths, key=lambda item: item.as_posix())


def _python_query_symbols(source: str) -> list[_QuerySymbol]:
    try:
        module = ast.parse(source)
    except SyntaxError:
        return []
    symbols = []
    for node in ast.walk(module):
        if isinstance(node, ast.ClassDef):
            symbols.append(_QuerySymbol(node.name, "class", node.lineno, node.end_lineno))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append(_QuerySymbol(node.name, "function", node.lineno, node.end_lineno))
    return sorted(symbols, key=lambda item: (item.line, item.name))


def _shell_query_symbols(source: str) -> list[_QuerySymbol]:
    symbols = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        function = _SHELL_FUNCTION.match(line)
        if function:
            symbols.append(_QuerySymbol(function.group(1) or function.group(2), "function", lineno))
            continue
        assignment = _SHELL_ASSIGNMENT.match(line)
        if assignment:
            symbols.append(_QuerySymbol(assignment.group(1), "variable", lineno))
    return symbols


def _default_query_cache(root: Path) -> Path:
    repository_id = hashlib.sha256(str(root).encode()).hexdigest()[:16]
    return Path.home() / ".cache" / "safeyolo" / "repo-map" / f"{repository_id}.json"


def _load_query_cache(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": _QUERY_CACHE_VERSION, "files": {}}
    if value.get("version") != _QUERY_CACHE_VERSION or not isinstance(value.get("files"), dict):
        return {"version": _QUERY_CACHE_VERSION, "files": {}}
    return value


def _save_query_cache(path: Path, records: dict[str, tuple[str, _QueryRecord]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = {
        "version": _QUERY_CACHE_VERSION,
        "files": {
            name: {
                "digest": digest,
                "terms": dict(record.terms),
            }
            for name, (digest, record) in sorted(records.items())
        },
    }
    temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, path)


def _query_records(root: Path, cache_path: Path) -> tuple[list[_QueryRecord], int, int]:
    cache = _load_query_cache(cache_path)
    cached_values = cache.get("files", {})
    current: dict[str, tuple[str, _QueryRecord]] = {}
    cached_files = 0
    indexed_files = 0
    for relative in _query_files(root):
        if (root / relative).resolve() == cache_path.resolve():
            continue
        try:
            raw = (root / relative).read_bytes()
        except OSError:
            continue
        digest = hashlib.sha256(raw).hexdigest()
        name = relative.as_posix()
        cached = cached_values.get(name) if isinstance(cached_values, dict) else None
        if isinstance(cached, dict) and cached.get("digest") == digest:
            try:
                record = _QueryRecord(
                    path=name,
                    terms=Counter(cached["terms"]),
                )
            except (KeyError, TypeError):
                record = None
            if record is not None:
                current[name] = (digest, record)
                cached_files += 1
                continue
        source = raw.decode("utf-8", errors="ignore")
        record = _QueryRecord(
            path=name,
            terms=_query_terms(source),
        )
        current[name] = (digest, record)
        indexed_files += 1
    if indexed_files or set(current) != set(cached_values):
        _save_query_cache(cache_path, current)
    return [record for _, record in current.values()], indexed_files, cached_files


def _load_query_hints(root: Path, requested: Path | None) -> list[_QueryHint]:
    path = requested or root / "repo-map.toml"
    if not path.exists():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RepoMapError(f"cannot read repository hints: {path}: {exc}") from exc
    if data.get("version") != 1:
        raise RepoMapError(f"unsupported repository hint version: {path}")
    hints = []
    try:
        for value in data.get("hints", []):
            hints.append(
                _QueryHint(
                    identifier=value["id"],
                    triggers=tuple(value["triggers"]),
                    advice=value["advice"],
                    paths=tuple(value.get("paths", [])),
                    source=value["source"],
                )
            )
    except (KeyError, TypeError) as exc:
        raise RepoMapError(f"invalid repository hint in {path}: {exc}") from exc
    return hints


def _match_query_hints(query_terms: set[str], hints: list[_QueryHint]) -> list[dict[str, object]]:
    matched = []
    for hint in hints:
        triggers = []
        for trigger in hint.triggers:
            required = set(_query_terms(trigger))
            if required and required <= query_terms:
                triggers.append(trigger)
        if triggers:
            matched.append(
                {
                    "id": hint.identifier,
                    "matched_triggers": triggers,
                    "advice": hint.advice,
                    "paths": list(hint.paths),
                    "source": hint.source,
                    "strength": sum(len(set(_query_terms(value))) for value in triggers),
                }
            )
    return sorted(
        matched,
        key=lambda value: (-int(value["strength"]), str(value["id"])),
    )[:3]


def _query_category(path: str) -> str:
    parts = Path(path).parts
    if "tests" in parts or Path(path).name.startswith("test_"):
        return "test"
    if path.endswith(".md"):
        return "documentation"
    return "implementation"


def _rank_query_records(
    task: str,
    records: list[_QueryRecord],
    hints: list[_QueryHint],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    query_counts = _task_query_terms(task)
    query_set = set(query_counts)
    matched_hints = _match_query_hints(query_set, hints)
    total = max(len(records), 1)
    document_frequency = {term: sum(1 for record in records if term in record.terms) for term in query_set}
    document_lengths = {record.path: sum(record.terms.values()) for record in records}
    average_length = sum(document_lengths.values()) / total
    early_terms = set(_task_query_terms(task[:800]))
    weighted_terms = []
    for term in query_set:
        frequency = document_frequency[term]
        if not frequency:
            continue
        inverse = math.log(1 + (total - frequency + 0.5) / (frequency + 0.5))
        query_weight = 1 + math.log1p(min(query_counts[term], 5))
        if term in early_terms:
            query_weight *= 1.35
        weighted_terms.append((inverse * query_weight, term))
    weighted_terms.sort(reverse=True)
    selected_terms = weighted_terms[:_QUERY_TERM_LIMIT]
    selected_weights = {term: weight for weight, term in selected_terms}

    ranked = []
    for record in records:
        path_terms = set(_query_terms(record.path))
        score = 0.0
        reasons = []
        lexical_matches = []
        length = document_lengths[record.path]
        for query_weight, term in selected_terms:
            frequency = record.terms.get(term, 0)
            if not frequency:
                continue
            normalized = 1.2 * (0.25 + 0.75 * length / max(average_length, 1))
            contribution = query_weight * (frequency * 2.2) / (frequency + normalized)
            score += contribution
            lexical_matches.append((contribution, term))
        path_matches = sorted(query_set & path_terms & selected_weights.keys())
        if path_matches:
            score += sum(2.5 * selected_weights[term] for term in path_matches)
            reasons.append("path=" + ",".join(path_matches[:4]))
        hint_matches = []
        for hint in matched_hints:
            for index, hinted_path in enumerate(hint["paths"]):
                directory = str(hinted_path).endswith("/")
                applies = record.path == hinted_path or (directory and record.path.startswith(str(hinted_path)))
                if applies:
                    if directory:
                        score += 4 + min(int(hint["strength"]), 4)
                    else:
                        # Exact paths are repository-authored inspection priorities.
                        # Earlier paths are deliberately stronger than later ones.
                        priority = len(hint["paths"]) - index
                        score += 42 + priority * 5 + min(int(hint["strength"]) * 2, 18)
                    hint_matches.append(str(hint["id"]))
                    break
        if hint_matches:
            reasons.append("guidance=" + ",".join(hint_matches))
        if score <= 0:
            continue
        if lexical_matches:
            lexical_matches.sort(reverse=True)
            reasons.append("text=" + ",".join(term for _, term in lexical_matches[:4]))
        ranked.append(
            {
                "path": record.path,
                "score": round(score, 2),
                "category": _query_category(record.path),
                "reasons": reasons,
                "symbols": [],
            }
        )
    ranked.sort(key=lambda value: (-float(value["score"]), str(value["path"])))
    return ranked, matched_hints


def _select_query_locations(ranked: list[dict[str, object]], limit: int) -> list[dict[str, object]]:
    implementation = [value for value in ranked if value["category"] == "implementation"]
    support = [value for value in ranked if value["category"] != "implementation"]
    support_limit = min(3, max(1, limit // 3)) if support else 0
    implementation_limit = max(0, limit - support_limit)

    diverse_implementation = []
    parent_counts: Counter[str] = Counter()
    for value in implementation:
        parent = str(Path(str(value["path"])).parent)
        if parent_counts[parent] >= 3:
            continue
        diverse_implementation.append(value)
        parent_counts[parent] += 1
        if len(diverse_implementation) == implementation_limit:
            break
    return [*diverse_implementation, *support[:support_limit]][:limit]


def _query_symbols_for_path(root: Path, relative: str) -> list[_QuerySymbol]:
    path = root / relative
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    first_line = source.partition("\n")[0]
    if path.suffix == ".py" or (not path.suffix and "python" in first_line):
        return _python_query_symbols(source)
    if path.suffix == ".sh" or path.name == "Makefile" or (not path.suffix and first_line.startswith("#!")):
        return _shell_query_symbols(source)
    return []


def _enrich_query_locations(root: Path, task: str, locations: list[dict[str, object]]) -> None:
    query_terms = set(_task_query_terms(task))
    for location in locations:
        symbols = _query_symbols_for_path(root, str(location["path"]))
        relevant = [symbol for symbol in symbols if set(_query_terms(symbol.name)) & query_terms]
        location["symbols"] = (relevant or symbols[:3])[:5]


def _render_repo_query(locations: list[dict[str, object]], guidance: list[dict[str, object]]) -> str:
    lines = []
    if guidance:
        lines.append("GUIDANCE (repository-authored, not syntax-derived)")
        for hint in guidance:
            triggers = ", ".join(hint["matched_triggers"])
            related = ", ".join(hint["paths"][:4])
            lines.append(f"- [{hint['id']}] {hint['advice']}")
            lines.append(f"  matched: {triggers}; source: {hint['source']}")
            if related:
                lines.append(f"  related: {related}")
    for category, heading in (
        ("implementation", "LIKELY IMPLEMENTATION"),
        ("test", "RELATED TESTS"),
        ("documentation", "RELATED DOCUMENTATION"),
    ):
        selected = [location for location in locations if location["category"] == category]
        if not selected:
            continue
        if lines:
            lines.append("")
        lines.append(f"{heading} (lexical + repository guidance; returned-file symbols)")
        for location in selected:
            reasons = "; ".join(location["reasons"])
            lines.append(f"- {location['path']} [{reasons}]")
            for symbol in location["symbols"]:
                lines.append(f"  {symbol.kind} {symbol.name} {_line_range(symbol.line, symbol.end_line)}")
    return "\n".join(lines)


def build_repo_query(
    path: Path | str,
    task: str,
    *,
    hints_path: Path | None = None,
    cache_path: Path | None = None,
    limit: int = _QUERY_FILE_LIMIT,
) -> RepoQuery:
    """Return task-conditioned locations and optional repository guidance."""

    started = time.perf_counter()
    requested = Path(path)
    if not requested.exists():
        raise RepoMapError(f"path does not exist: {requested}")
    root = _repository_root(requested)
    records, indexed_files, cached_files = _query_records(root, cache_path or _default_query_cache(root))
    ranked, guidance = _rank_query_records(task, records, _load_query_hints(root, hints_path))
    locations = _select_query_locations(ranked, limit)
    _enrich_query_locations(root, task, locations)
    return RepoQuery(
        root=root,
        head=_head_identity(root),
        text=_render_repo_query(locations, guidance),
        files=len(records),
        indexed_files=indexed_files,
        cached_files=cached_files,
        elapsed_ms=round((time.perf_counter() - started) * 1000),
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
        if not any(scope != other_scope and scope in other_scope.parents for _, _, other_scope in resolved)
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
        help=("repository file or directory to map; multiple paths are allowed (default: current directory)"),
    )
    parser.add_argument(
        "--query",
        metavar="TEXT",
        help=("rank likely implementation locations for a task and include matching repository guidance"),
    )
    parser.add_argument(
        "--hints",
        type=Path,
        metavar="FILE",
        help="use an explicit repository-hints TOML file",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=_QUERY_FILE_LIMIT,
        metavar="N",
        help=f"maximum files returned by --query (default: {_QUERY_FILE_LIMIT})",
    )
    args = parser.parse_args(argv)
    try:
        if args.query is not None:
            if len(args.paths) > 1:
                raise RepoMapError("--query accepts at most one repository path")
            if args.limit < 1:
                raise RepoMapError("--limit must be at least 1")
            result = build_repo_query(
                args.paths[0] if args.paths else Path("."),
                args.query,
                hints_path=args.hints,
                limit=args.limit,
            )
            print(
                f"# repo-map mode=query head={result.head[:12]} "
                f"files={result.files} indexed={result.indexed_files} "
                f"cached={result.cached_files} elapsed_ms={result.elapsed_ms}"
            )
            if result.text:
                print(result.text)
            return 0
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
