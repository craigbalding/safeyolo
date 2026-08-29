#!/usr/bin/env python3
"""Reject Agent API curl examples that put bearer tokens in process argv.

A finding requires all three parts of the risk: a value read from the Agent API
token file, a curl header argument, and the Agent API endpoint. The ordered
shell pass and small Python AST pass track simple aliases so unrelated
admin/service credentials and in-process header fixtures remain valid.
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
_PATH = "path"
_TOKEN = "token"
_ENDPOINT = "endpoint"
_FILE = "file"

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
_FENCE_RE = re.compile(r"(?m)^\s*```[^\n]*\n?")

_Provenance = set[str]
_Arg = tuple[str, frozenset[str]]


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _contains_agent_token_path(value: str) -> bool:
    return _AGENT_TOKEN_PATH_RE.search(value.strip()) is not None


def _shell_names(value: str) -> set[str]:
    return {match.group(1).lower() for match in _VARIABLE_RE.finditer(value)}


def _substitution_uses_path(body: str, state: dict[str, _Provenance]) -> bool:
    if _contains_agent_token_path(body):
        return True
    return any(_PATH in state.get(name, set()) for name in _shell_names(body))


def _shell_value_provenance(
    value: str,
    state: dict[str, _Provenance],
) -> _Provenance:
    provenance: _Provenance = set()
    references = _shell_names(value)
    for name in references:
        provenance.update(state.get(name, set()) & {_PATH, _TOKEN, _ENDPOINT})
    if _contains_agent_token_path(value) and not _SUBSTITUTION_RE.search(value):
        provenance.add(_PATH)
    if _AGENT_HOST in value.lower():
        provenance.add(_ENDPOINT)
    for substitution in _SUBSTITUTION_RE.finditer(value):
        body = substitution.group("dollar") or substitution.group("backtick")
        if _substitution_uses_path(body, state):
            provenance.add(_TOKEN)
    return provenance


def _logical_shell(text: str) -> str:
    """Join backslash continuations without changing source offsets."""
    return re.sub(r"\\\r?\n", lambda match: " " * len(match.group()), text)


def _shell_segments(text: str) -> Iterator[tuple[str, int]]:
    """Split Markdown fences so aliases cannot leak between examples."""
    start = 0
    for fence in _FENCE_RE.finditer(text):
        if fence.start() > start:
            yield text[start:fence.start()], _line_number(text, start) - 1
        start = fence.end()
    if start < len(text):
        yield text[start:], _line_number(text, start) - 1


def _shell_findings(text: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    for segment, base_line in _shell_segments(text):
        logical = _logical_shell(segment)
        state: dict[str, _Provenance] = {}
        events: list[tuple[int, str, re.Match[str]]] = [
            (match.start(), "assign", match)
            for match in _ASSIGNMENT_RE.finditer(logical)
        ]
        events.extend(
            (match.start(), "curl", match)
            for match in re.finditer(r"\bcurl\b", logical, re.IGNORECASE)
        )

        for _offset, kind, match in sorted(events, key=lambda event: event[0]):
            if kind == "assign":
                name = match.group("name").lower()
                state[name] = _shell_value_provenance(match.group("value"), state)
                continue

            line_end = logical.find("\n", match.start())
            command = logical[match.start():line_end if line_end >= 0 else len(logical)]
            command_names = _shell_names(command)
            is_agent_endpoint = (
                _AGENT_HOST in command.lower()
                or any(_ENDPOINT in state.get(name, set()) for name in command_names)
            )
            if not is_agent_endpoint:
                continue

            for header_flag in _HEADER_FLAG_RE.finditer(command):
                header_tail = command[header_flag.end():]
                auth = _AUTH_RE.search(header_tail)
                if auth is None:
                    continue
                bearer_tail = header_tail[auth.end():]
                unsafe = any(
                    _TOKEN in state.get(name, set())
                    for name in _shell_names(bearer_tail)
                )
                if not unsafe:
                    for substitution in _SUBSTITUTION_RE.finditer(bearer_tail):
                        body = substitution.group("dollar") or substitution.group("backtick")
                        if _substitution_uses_path(body, state):
                            unsafe = True
                            break
                if unsafe:
                    findings.append((
                        base_line + _line_number(logical, match.start()),
                        "Agent API token is interpolated into a curl header argument",
                    ))
                    break
    return findings


def _string_parts(expr: ast.AST) -> str:
    return "".join(
        node.value
        for node in ast.walk(expr)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    )


def _python_names(expr: ast.AST) -> set[str]:
    return {node.id.lower() for node in ast.walk(expr) if isinstance(node, ast.Name)}


def _expr_provenance(
    expr: ast.AST,
    state: dict[str, _Provenance],
    function_returns: dict[str, _Provenance],
) -> _Provenance:
    if isinstance(expr, ast.Name):
        return set(state.get(expr.id.lower(), set()))
    if isinstance(expr, ast.Constant):
        if isinstance(expr.value, str):
            provenance: _Provenance = set()
            if _contains_agent_token_path(expr.value):
                provenance.add(_PATH)
            if _AGENT_HOST in expr.value.lower():
                provenance.add(_ENDPOINT)
            return provenance
        return set()
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name):
            name = expr.func.id.lower()
            if name in function_returns:
                return set(function_returns[name])
            if name == "open" and expr.args:
                if _PATH in _expr_provenance(expr.args[0], state, function_returns):
                    return {_FILE}
        if isinstance(expr.func, ast.Attribute):
            method = expr.func.attr.lower()
            receiver = _expr_provenance(expr.func.value, state, function_returns)
            if method in {"strip", "rstrip", "decode"}:
                return receiver
            if method in {"read_text", "read_bytes"} and _PATH in receiver:
                return {_TOKEN}
            if method == "read" and _FILE in receiver:
                return {_TOKEN}
        provenance: _Provenance = set()
        for argument in [*expr.args, *(keyword.value for keyword in expr.keywords)]:
            provenance.update(_expr_provenance(argument, state, function_returns))
        return provenance

    provenance: _Provenance = set()
    for child in ast.iter_child_nodes(expr):
        provenance.update(_expr_provenance(child, state, function_returns))
    static = _string_parts(expr)
    if _AGENT_HOST in static.lower():
        provenance.add(_ENDPOINT)
    return provenance


def _arg(expr: ast.AST, state: dict[str, _Provenance], returns: dict[str, _Provenance]) -> _Arg:
    return _string_parts(expr), frozenset(_expr_provenance(expr, state, returns))


def _container(
    expr: ast.AST,
    state: dict[str, _Provenance],
    containers: dict[str, list[_Arg]],
    returns: dict[str, _Provenance],
) -> list[_Arg] | None:
    if isinstance(expr, ast.Name):
        value = containers.get(expr.id.lower())
        return list(value) if value is not None else None
    if isinstance(expr, (ast.List, ast.Tuple)):
        return [_arg(element, state, returns) for element in expr.elts]
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _container(expr.left, state, containers, returns)
        right = _container(expr.right, state, containers, returns)
        if left is not None and right is not None:
            return [*left, *right]
    return None


def _assigned_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Assign):
        return [target.id.lower() for target in node.targets if isinstance(target, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id.lower()]
    return []


def _statements(scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.stmt]:
    def walk(statement: ast.stmt) -> Iterator[ast.stmt]:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        yield statement
        for field in ("body", "orelse", "finalbody"):
            for child in getattr(statement, field, []):
                yield from walk(child)
        for handler in getattr(statement, "handlers", []):
            for child in handler.body:
                yield from walk(child)

    for statement in scope.body:
        yield from walk(statement)


def _calls_in_statement(statement: ast.stmt) -> Iterator[ast.Call]:
    stack = list(ast.iter_child_nodes(statement))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.stmt):
            continue
        if isinstance(node, ast.Call):
            yield node
        stack.extend(ast.iter_child_nodes(node))


def _subprocess_command(call: ast.Call) -> ast.AST | None:
    if not isinstance(call.func, ast.Attribute):
        return None
    if call.func.attr.lower() not in {"run", "popen", "call", "check_call"}:
        return None
    if not isinstance(call.func.value, ast.Name) or call.func.value.id != "subprocess":
        return None
    if call.args:
        return call.args[0]
    return next((keyword.value for keyword in call.keywords if keyword.arg == "args"), None)


def _command_is_unsafe(elements: list[_Arg]) -> bool:
    if not any(text.strip().lower() == "curl" for text, _prov in elements):
        return False
    if not any(
        _ENDPOINT in provenance or _AGENT_HOST in text.lower()
        for text, provenance in elements
    ):
        return False
    if not any(
        text.strip() in {"-H", "--header"}
        or text.strip().lower().startswith(("-hauthorization", "--header="))
        for text, _provenance in elements
    ):
        return False
    return any(
        _AUTH_RE.search(text) and _TOKEN in provenance
        for text, provenance in elements
    )


def _function_parameters(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[str]:
    return [argument.arg.lower() for argument in function.args.args]


def _analyze_scope(
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
    initial_state: dict[str, _Provenance],
    initial_containers: dict[str, list[_Arg]],
    function_returns: dict[str, _Provenance],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    parameter_provenance: dict[ast.AST, dict[str, _Provenance]],
    *,
    collect_findings: bool,
) -> tuple[dict[str, _Provenance], dict[str, list[_Arg]], _Provenance, list[tuple[int, str]], bool]:
    state = {name: set(value) for name, value in initial_state.items()}
    containers = {name: list(value) for name, value in initial_containers.items()}
    returned: _Provenance = set()
    findings: list[tuple[int, str]] = []
    parameter_changed = False

    for statement in _statements(scope):
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            if value is not None:
                container = _container(value, state, containers, function_returns)
                provenance = _expr_provenance(value, state, function_returns)
                for name in _assigned_names(statement):
                    state[name] = set(provenance)
                    if container is None:
                        containers.pop(name, None)
                    else:
                        containers[name] = list(container)
        elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
            name = statement.target.id.lower()
            if isinstance(statement.op, ast.Add):
                extension = _container(statement.value, state, containers, function_returns)
                if extension is not None and name in containers:
                    containers[name].extend(extension)
                else:
                    state[name] = _expr_provenance(statement.value, state, function_returns)
                    containers.pop(name, None)
        elif isinstance(statement, ast.With):
            for item in statement.items:
                if isinstance(item.optional_vars, ast.Name):
                    state[item.optional_vars.id.lower()] = _expr_provenance(
                        item.context_expr, state, function_returns,
                    )
        elif isinstance(statement, ast.Return) and statement.value is not None:
            returned.update(_expr_provenance(statement.value, state, function_returns))

        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            call = statement.value
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                name = call.func.value.id.lower()
                if name in containers and call.args:
                    if call.func.attr == "append":
                        containers[name].append(_arg(call.args[0], state, function_returns))
                    elif call.func.attr == "extend":
                        extension = _container(
                            call.args[0], state, containers, function_returns,
                        )
                        if extension is not None:
                            containers[name].extend(extension)

        for call in _calls_in_statement(statement):
            command_expr = _subprocess_command(call)
            if command_expr is not None:
                elements = _container(command_expr, state, containers, function_returns)
                if collect_findings and elements and _command_is_unsafe(elements):
                    findings.append((
                        call.lineno,
                        "Agent API token is constructed inside a curl argv container",
                    ))

            if not isinstance(call.func, ast.Name):
                continue
            callee = functions.get(call.func.id.lower())
            if callee is None:
                continue
            params = _function_parameters(callee)
            bindings: list[tuple[str, ast.AST]] = list(zip(params, call.args))
            bindings.extend(
                (keyword.arg.lower(), keyword.value)
                for keyword in call.keywords
                if keyword.arg is not None
            )
            for parameter, value in bindings:
                provenance = _expr_provenance(value, state, function_returns)
                current = parameter_provenance[callee].setdefault(parameter, set())
                before = len(current)
                current.update(provenance)
                parameter_changed |= len(current) != before

    return state, containers, returned, findings, parameter_changed


def _python_findings(text: str) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    function_nodes = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    functions = {node.name.lower(): node for node in function_nodes}
    parameter_provenance: dict[ast.AST, dict[str, _Provenance]] = {
        node: {name: set() for name in _function_parameters(node)}
        for node in function_nodes
    }
    function_returns: dict[str, _Provenance] = {name: set() for name in functions}

    empty_params: dict[ast.AST, dict[str, _Provenance]] = {
        node: {} for node in function_nodes
    }
    global_state, global_containers, _returned, _findings, _changed = _analyze_scope(
        tree, {}, {}, function_returns, functions, empty_params, collect_findings=False,
    )

    # Resolve return provenance from actual return expressions. Returning the
    # token-file Path remains PATH; only read_text/read_bytes/open(...).read()
    # becomes TOKEN.
    changed = True
    while changed:
        changed = False
        for name, function in functions.items():
            initial = {
                **global_state,
                **parameter_provenance[function],
            }
            _state, _containers, returned, _findings, _param_changed = _analyze_scope(
                function,
                initial,
                global_containers,
                function_returns,
                functions,
                parameter_provenance,
                collect_findings=False,
            )
            before = len(function_returns[name])
            function_returns[name].update(returned)
            changed |= len(function_returns[name]) != before

    # Propagate token/path/endpoint arguments into helper parameters.
    changed = True
    while changed:
        changed = False
        _state, _containers, _returned, _findings, param_changed = _analyze_scope(
            tree,
            {},
            {},
            function_returns,
            functions,
            parameter_provenance,
            collect_findings=False,
        )
        changed |= param_changed
        for function in function_nodes:
            initial = {**global_state, **parameter_provenance[function]}
            _state, _containers, _returned, _findings, param_changed = _analyze_scope(
                function,
                initial,
                global_containers,
                function_returns,
                functions,
                parameter_provenance,
                collect_findings=False,
            )
            changed |= param_changed

    findings: list[tuple[int, str]] = []
    _state, _containers, _returned, module_findings, _changed = _analyze_scope(
        tree,
        {},
        {},
        function_returns,
        functions,
        parameter_provenance,
        collect_findings=True,
    )
    findings.extend(module_findings)
    for function in function_nodes:
        initial = {**global_state, **parameter_provenance[function]}
        _state, _containers, _returned, scoped_findings, _changed = _analyze_scope(
            function,
            initial,
            global_containers,
            function_returns,
            functions,
            parameter_provenance,
            collect_findings=True,
        )
        findings.extend(scoped_findings)

    # Python tests can embed a complete shell command in one string argument;
    # AST constants join adjacent literals before this scan.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if "curl" not in node.value.lower():
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
