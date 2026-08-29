#!/usr/bin/env python3
"""Reject Agent API curl examples that put bearer tokens in process argv.

The check binds a finding to three facts: an established Agent API token
source, a curl header argument, and the Agent API virtual host. This keeps the
rule focused on the shipped risk without rejecting admin/service credentials
or in-process header fixtures.
"""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_TEXT_SUFFIXES = frozenset({".md", ".mmd", ".py", ".sh", ".yaml", ".yml"})
_SCAN_DIRS = ("cli", "contrib", "docs", "guest", "scripts", "tests", "vm")
_EXCLUDED = frozenset({
    "scripts/check_agent_token_argv.py",
    "tests/test_check_agent_token_argv.py",
})

_AGENT_HOST = "_safeyolo.proxy.internal"
_AUTH_RE = re.compile(r"authorization\s*:\s*bearer", re.IGNORECASE)
_AGENT_TOKEN_PATH_RE = re.compile(
    r"(?:^|[/])agent_token(?:$|[\s\"'])",
    re.IGNORECASE,
)
_VARIABLE_RE = re.compile(r"\$\{?([a-z_][a-z0-9_]*)\}?", re.IGNORECASE)
_SUBSTITUTION_RE = re.compile(
    r"\$\((?P<dollar>(?:(?!\)).){0,500})\)"
    r"|`(?P<backtick>(?:(?!`).){0,500})`",
    re.DOTALL,
)
_ASSIGNMENT_RE = re.compile(
    r"(?im)(?:^|[;(])\s*(?:(?:local|readonly|export)\s+)?"
    r"(?P<name>[a-z_][a-z0-9_]*)\s*=\s*(?P<value>[^;\n]+)",
)
_HEADER_FLAG_RE = re.compile(r"(?:-H\s*|--header(?:\s+|=))", re.IGNORECASE)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _contains_agent_token_path(value: str) -> bool:
    return _AGENT_TOKEN_PATH_RE.search(value.strip()) is not None


def _referenced_names(value: str) -> set[str]:
    return {match.group(1).lower() for match in _VARIABLE_RE.finditer(value)}


def _read_uses_agent_source(body: str, path_aliases: set[str]) -> bool:
    if _contains_agent_token_path(body):
        return True
    return bool(_referenced_names(body) & path_aliases)


def _shell_aliases(text: str) -> tuple[set[str], set[str]]:
    """Return (token-path aliases, token-value aliases) for shell-like text."""
    assignments = [
        (match.group("name").lower(), match.group("value").strip())
        for match in _ASSIGNMENT_RE.finditer(text)
    ]

    path_aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, value in assignments:
            if _SUBSTITUTION_RE.search(value):
                continue
            refs = _referenced_names(value)
            if _contains_agent_token_path(value) or refs & path_aliases:
                if name not in path_aliases:
                    path_aliases.add(name)
                    changed = True

    token_aliases: set[str] = set()
    for name, value in assignments:
        for substitution in _SUBSTITUTION_RE.finditer(value):
            body = substitution.group("dollar") or substitution.group("backtick")
            if _read_uses_agent_source(body, path_aliases):
                token_aliases.add(name)
                break
    return path_aliases, token_aliases


def _logical_shell(text: str) -> str:
    """Join backslash continuations without changing source offsets."""
    return re.sub(r"\\\r?\n", lambda match: " " * len(match.group()), text)


def _shell_findings(text: str) -> list[tuple[int, str]]:
    path_aliases, token_aliases = _shell_aliases(text)
    logical = _logical_shell(text)
    findings: list[tuple[int, str]] = []

    for curl in re.finditer(r"\bcurl\b", logical, re.IGNORECASE):
        line_end = logical.find("\n", curl.start())
        command = logical[curl.start():line_end if line_end >= 0 else len(logical)]
        if _AGENT_HOST not in command.lower():
            continue

        for header_flag in _HEADER_FLAG_RE.finditer(command):
            header_tail = command[header_flag.end():]
            auth = _AUTH_RE.search(header_tail)
            if auth is None:
                continue
            bearer_tail = header_tail[auth.end():]

            unsafe = False
            for substitution in _SUBSTITUTION_RE.finditer(bearer_tail):
                body = substitution.group("dollar") or substitution.group("backtick")
                if _read_uses_agent_source(body, path_aliases):
                    unsafe = True
                    break
            if not unsafe and _referenced_names(bearer_tail) & token_aliases:
                unsafe = True
            if unsafe:
                findings.append((
                    _line_number(logical, curl.start()),
                    "Agent API token is interpolated into a curl header argument",
                ))
                break

    return findings


def _scope_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Walk one Python scope without leaking assignments from nested scopes."""
    stack = list(reversed(list(ast.iter_child_nodes(scope))))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _string_parts(expr: ast.AST) -> str:
    return "".join(
        node.value
        for node in ast.walk(expr)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    )


def _expr_names(expr: ast.AST) -> set[str]:
    return {node.id.lower() for node in ast.walk(expr) if isinstance(node, ast.Name)}


def _expr_has_agent_path(expr: ast.AST, path_vars: set[str]) -> bool:
    if _contains_agent_token_path(_string_parts(expr)):
        return True
    return bool(_expr_names(expr) & path_vars)


def _expr_is_token_read(
    expr: ast.AST,
    path_vars: set[str],
    token_vars: set[str],
    source_functions: set[str],
) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id.lower() in token_vars
    if not isinstance(expr, ast.Call):
        return False
    if isinstance(expr.func, ast.Name) and expr.func.id.lower() in source_functions:
        return True
    if isinstance(expr.func, ast.Attribute):
        method = expr.func.attr.lower()
        receiver = expr.func.value
        if method in {"strip", "rstrip", "decode"}:
            return _expr_is_token_read(
                receiver, path_vars, token_vars, source_functions,
            )
        if method in {"read_text", "read_bytes"}:
            return _expr_has_agent_path(receiver, path_vars)
        if method == "read" and isinstance(receiver, ast.Call):
            if isinstance(receiver.func, ast.Name) and receiver.func.id == "open":
                return bool(receiver.args) and _expr_has_agent_path(
                    receiver.args[0], path_vars,
                )
    return False


def _assigned_name(node: ast.AST) -> str | None:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) == 1 and isinstance(targets[0], ast.Name):
            return targets[0].id.lower()
    return None


def _assigned_value(node: ast.AST) -> ast.AST | None:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return node.value
    return None


def _python_scopes(tree: ast.Module) -> list[ast.AST]:
    return [tree, *[
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]]


def _python_token_sources(
    tree: ast.Module,
) -> tuple[dict[ast.AST, set[str]], set[str], dict[str, ast.AST]]:
    scopes = _python_scopes(tree)
    functions = {
        node.name.lower(): node
        for node in scopes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    source_functions = {
        name for name, node in functions.items()
        if _contains_agent_token_path(_string_parts(node))
        and any(isinstance(child, ast.Return) for child in ast.walk(node))
    }

    path_vars: dict[ast.AST, set[str]] = {scope: set() for scope in scopes}
    token_vars: dict[ast.AST, set[str]] = {scope: set() for scope in scopes}
    for scope in scopes:
        nodes = list(_scope_nodes(scope))
        changed = True
        while changed:
            changed = False
            for node in nodes:
                name = _assigned_name(node)
                value = _assigned_value(node)
                if name is None or value is None:
                    continue
                if _expr_has_agent_path(value, path_vars[scope]):
                    if name not in path_vars[scope]:
                        path_vars[scope].add(name)
                        changed = True
                if _expr_is_token_read(
                    value,
                    path_vars[scope],
                    token_vars[scope],
                    source_functions,
                ) and name not in token_vars[scope]:
                    token_vars[scope].add(name)
                    changed = True

    # Propagate established token arguments into helper parameters, e.g.
    # ``_curl_agent_api(token=_agent_token())``.
    changed = True
    while changed:
        changed = False
        for scope in scopes:
            for call in (node for node in _scope_nodes(scope) if isinstance(node, ast.Call)):
                if not isinstance(call.func, ast.Name):
                    continue
                callee = functions.get(call.func.id.lower())
                if not isinstance(callee, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                params = [arg.arg.lower() for arg in callee.args.args]
                bindings: list[tuple[str, ast.AST]] = list(zip(params, call.args))
                bindings.extend(
                    (keyword.arg.lower(), keyword.value)
                    for keyword in call.keywords
                    if keyword.arg is not None
                )
                for parameter, value in bindings:
                    if _expr_is_token_read(
                        value,
                        path_vars[scope],
                        token_vars[scope],
                        source_functions,
                    ) and parameter not in token_vars[callee]:
                        token_vars[callee].add(parameter)
                        changed = True
    return token_vars, source_functions, functions


def _container_elements(expr: ast.AST) -> list[ast.AST] | None:
    if isinstance(expr, (ast.List, ast.Tuple)):
        return list(expr.elts)
    return None


def _subprocess_command_expr(call: ast.Call) -> ast.AST | None:
    if not isinstance(call.func, ast.Attribute):
        return None
    if call.func.attr.lower() not in {"run", "popen", "call", "check_call"}:
        return None
    if not isinstance(call.func.value, ast.Name) or call.func.value.id != "subprocess":
        return None
    if call.args:
        return call.args[0]
    return next((kw.value for kw in call.keywords if kw.arg == "args"), None)


def _python_findings(text: str) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    token_vars, source_functions, _functions = _python_token_sources(tree)
    findings: list[tuple[int, str]] = []

    for scope in _python_scopes(tree):
        commands: dict[str, list[ast.AST]] = {}
        nodes = sorted(_scope_nodes(scope), key=lambda node: getattr(node, "lineno", 0))
        for node in nodes:
            name = _assigned_name(node)
            value = _assigned_value(node)
            elements = _container_elements(value) if value is not None else None
            if name is not None and elements is not None:
                commands[name] = elements
                continue
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if not isinstance(node.func.value, ast.Name):
                continue
            command = commands.get(node.func.value.id.lower())
            if command is None or not node.args:
                continue
            if node.func.attr == "extend":
                extension = _container_elements(node.args[0])
                if extension is not None:
                    command.extend(extension)
            elif node.func.attr == "append":
                command.append(node.args[0])

        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            command_expr = _subprocess_command_expr(node)
            if command_expr is None:
                continue
            if isinstance(command_expr, ast.Name):
                elements = commands.get(command_expr.id.lower())
            else:
                elements = _container_elements(command_expr)
            if not elements:
                continue

            strings = [_string_parts(element) for element in elements]
            if not any(value.strip().lower() == "curl" for value in strings):
                continue
            if not any(_AGENT_HOST in value.lower() for value in strings):
                continue
            if not any(
                value.strip() in {"-H", "--header"}
                or value.strip().lower().startswith(("-hauthorization", "--header="))
                for value in strings
            ):
                continue

            unsafe_header = any(
                _AUTH_RE.search(_string_parts(element))
                and (
                    bool(_expr_names(element) & token_vars[scope])
                    or _expr_is_token_read(
                        element,
                        set(),
                        token_vars[scope],
                        source_functions,
                    )
                )
                for element in elements
            )
            if unsafe_header:
                findings.append((
                    node.lineno,
                    "Agent API token is constructed inside a curl argv container",
                ))

    # Python tests sometimes embed a complete shell command in one string
    # argument. Python's AST has already joined adjacent string literals, so
    # scan those values as shell without confusing surrounding Python syntax.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if "curl" not in node.value.lower() or _AGENT_HOST not in node.value.lower():
            continue
        for _line, reason in _shell_findings(node.value):
            findings.append((node.lineno, reason))

    return findings


def find_unsafe_token_argv(text: str) -> list[tuple[int, str]]:
    """Return ``(line, reason)`` findings for one text file."""
    return sorted({*_shell_findings(text), *_python_findings(text)})


def _scan_files(root: Path) -> list[Path]:
    files: set[Path] = {
        path for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES
    }
    for directory in _SCAN_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        files.update(
            path for path in base.rglob("*")
            if path.is_file() and path.suffix.lower() in _TEXT_SUFFIXES
        )
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
