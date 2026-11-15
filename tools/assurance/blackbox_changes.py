#!/usr/bin/env python3
"""Compare blackbox assurance definitions. Git objects are data, never programs."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import tomllib
from difflib import SequenceMatcher
from pathlib import Path, PurePosixPath

import yaml

CATALOGUE = "tests/blackbox/controls.toml"
MAP = "docs/assurance-map.toml"
SELF = "tools/assurance/blackbox_changes.py"
PUBLISHER = "tools/assurance/notify_blackbox.py"
WORKFLOW = ".github/workflows/blackbox-changes.yml"
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 20000
MAX_DELTAS = 500
EVIDENCE_DIRS = ("tests/blackbox/", "tests/proxy_contracts/", "proxy/tests/")
CONTEXT_NAMES = {"uv.lock", "pyproject.toml", "Cargo.lock", "Cargo.toml", "rust-toolchain.toml",
                 "Package.resolved", "Package.swift"}
FIXTURE_SUFFIXES = {".json", ".toml", ".yaml", ".yml", ".txt", ".pem", ".crt", ".conf"}
CATALOGUE_CODE = {"tests/blackbox/catalogue.py", "tests/blackbox/gen_docs.py", "tests/blackbox/_docstring_lint.py",
                  "tests/blackbox/selections.py", "tests/blackbox/execution_receipt.py"}


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Revision:
    """Read bounded regular blobs without checking out candidate files or links."""

    def __init__(self, root: Path, revision: str):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("expected a full Git commit SHA")
        self.root, self.sha = root, revision
        self.total = 0
        self.cache: dict[str, str] = {}
        rows = self.git("ls-tree", "-rz", "--full-tree", revision).split(b"\0")
        if len(rows) > MAX_FILES:
            raise ValueError("analysis tree exceeds file bound")
        self.files = {}
        for row in filter(None, rows):
            metadata, path = row.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            self.files[path.decode("utf-8")] = (mode, kind, oid)

    def git(self, *args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(self.root), *args], timeout=60)

    def read(self, name: str) -> str:
        if name not in self.files:
            return ""
        if name not in self.cache:
            mode, kind, oid = self.files[name]
            if mode not in {"100644", "100755"} or kind != "blob":
                raise ValueError(f"non-regular analysis input: {name}")
            size = int(self.git("cat-file", "-s", oid))
            self.total += size
            if size > MAX_FILE or self.total > MAX_TOTAL:
                raise ValueError("analysis input exceeds byte bound")
            self.cache[name] = self.git("cat-file", "blob", oid).decode("utf-8")
        return self.cache[name]


class PythonDefinition(ast.NodeTransformer):
    """Discard prose and empty statements, retaining executable AST fields."""

    def visit_Pass(self, node):
        return None

    def generic_visit(self, node):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                node.body = node.body[1:]
        return super().generic_visit(node)


def python_definition(source: str) -> dict:
    tree = PythonDefinition().visit(ast.parse(source, type_comments=True))
    units, order = {}, []
    python_scope(tree.body, "", units, order)
    units["<order>"] = order
    if source.startswith("#!"):
        units["<interpreter>"] = source.splitlines()[0]
    return units


def publisher_definition(source: str) -> dict:
    """Retain reachable notification code except one inspected diagnostic pair.

    Follow static names through local functions, including the API adapter and
    its helpers. Only the complete inspected adapter definitions and their
    order at 2ec26866/690549f1 qualify for the diagnostic-only exception.
    """
    tree = ast.parse(source, type_comments=True)
    functions = {}
    statements = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append(node)
        else:
            statements.append(node)
    pending = [node.id for statement in statements for node in ast.walk(statement) if isinstance(node, ast.Name)]
    # Decorators and defaults execute at definition time even for an otherwise
    # unused function. Do not hide their code behind static call discovery.
    pending.extend(name for name, definitions in functions.items()
                   if any(function.decorator_list or function.args.defaults or any(function.args.kw_defaults)
                          or any(is_python_assertion(node) for node in ast.walk(function))
                          for function in definitions))
    selected = set()
    while pending:
        name = pending.pop()
        if name in selected or name not in functions:
            continue
        selected.add(name)
        for function in functions[name]:
            pending.extend(node.id for node in ast.walk(function) if isinstance(node, ast.Name))
    tree.body = [node for node in tree.body
                 if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name in selected]
    interpreter = source.splitlines()[0] + "\n" if source.startswith("#!") else ""
    definitions = python_definition(interpreter + ast.unparse(tree))
    adapter = {name: value for name, value in definitions.items()
               if name.startswith(("api#", "api_failure#")) or name == "<order>"}
    diagnostic_pair = {"70a8ef5846f05f98aa980d5b2ad7465c5f34b5660db2c12ff1261a31019b7e17",
                       "9816ef4967142c5ba0577af5aaa417e6535b298e19d4148c4a43abdfd74fec08"}
    if digest(adapter) in diagnostic_pair:
        definitions["api#0"] = "<inspected raw/included-header GitHub API diagnostic adaptation>"
        definitions.pop("api_failure#0", None)
        definitions["<order>"] = [name for name in definitions["<order>"] if name != "api_failure#0"]
    return definitions


def is_python_assertion(node: ast.AST) -> bool:
    if isinstance(node, ast.Assert):
        return True
    if not isinstance(node, ast.Call):
        return False
    name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
    return name.startswith("assert") or name in {"raises", "fail", "skip", "skipif", "xfail", "check_call", "check_output"}


def regression_definition(source: str) -> dict:
    """Retain full test setup except one inspected diagnostic-only adaptation.

    These are the complete normalized recurring CLI fixture definitions at
    2ec26866 and 690549f1, before/after included response headers. Fingerprints
    include all setup, assertions and selection; no other definition is exempt.
    """
    definitions = python_definition(source)
    framing_pair = {"ca09afda8b825e687a7559c7df2d280b674eae3260164af341913761dce94190",
                    "730db5a13ffaddd9abdb44fbb0c0aa3cb9a269376c568c892799b4fccb9a25f0"}
    for name, value in definitions.items():
        if isinstance(value, str) and digest(value) in framing_pair:
            definitions[name] = "<inspected raw/included-header GitHub CLI fixture>"
    return definitions


def python_scope(nodes: list, prefix: str, units: dict, order: list) -> None:
    remainder = []
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Duplicate definitions and definition order can affect collection.
            name = prefix + node.name
            key = f"{name}#{sum(key.startswith(name + '#') for key in units)}"
            order.append(key)
            if isinstance(node, ast.ClassDef):
                children, node.body = node.body, []
                units[key] = ast.dump(node, include_attributes=False, indent=2)
                python_scope(children, key + ".", units, order)
            else:
                units[key] = ast.dump(node, include_attributes=False, indent=2)
        else:
            remainder.append(node)
            order.append(prefix + "<statement:" + digest(ast.dump(node, include_attributes=False)) + ">")
    if remainder:
        units[prefix + "<module>"] = ast.dump(ast.Module(body=remainder, type_ignores=[]), include_attributes=False, indent=2)


RUST_TOKEN = re.compile(
    r'(?:b|c)?"(?:\\.|[^"\\])*"[A-Za-z_0-9]*|'
    r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^'\\])'[A-Za-z_0-9]*|"
    r"r#[A-Za-z_][A-Za-z_0-9]*|'[A-Za-z_][A-Za-z_0-9]*|[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9.]*|"
    r"::|->|=>|\.\.=|\.\.|&&|\|\||==|!=|<=|>=|<<=?|>>=?|[+*/%&|^!-]=|[^\s]",
    re.DOTALL,
)


def rust_tokens(source: str) -> list[str]:
    """Lex strings and nested comments before discarding comment/space trivia."""
    tokens, offset, previous_end = [], 0, -1
    while offset < len(source):
        if source[offset].isspace():
            offset += 1
        elif source.startswith("//", offset):
            end = source.find("\n", offset)
            offset = len(source) if end < 0 else end + 1
        elif source.startswith("/*", offset):
            offset = rust_comment_end(source, offset)
        elif match := re.match(r'(?:br|cr|r)(#{0,255})"', source[offset:]):
            delimiter = '"' + match[1]
            end = source.find(delimiter, offset + match.end())
            if end < 0:
                raise ValueError("unterminated Rust raw string")
            end += len(delimiter)
            if suffix := re.match(r"[A-Za-z_][A-Za-z_0-9]*", source[end:]):
                end += suffix.end()
            tokens.append(source[offset:end])
            offset, previous_end = end, end
        else:
            match = RUST_TOKEN.match(source, offset)
            if match is None:
                raise ValueError("unrecognized Rust token")
            if match[0] == '"':
                raise ValueError("unterminated Rust string")
            punctuation = r"[^A-Za-z_0-9\s\"'()\[\]{}]+"
            if tokens and previous_end == offset and re.fullmatch(punctuation, tokens[-1]) and re.fullmatch(punctuation, match[0]):
                tokens.append("<joint punctuation>")
            tokens.append(match[0])
            offset, previous_end = match.end(), match.end()
    return tokens


def rust_comment_end(source: str, offset: int) -> int:
    depth, offset = 1, offset + 2
    while depth and offset < len(source):
        if source.startswith("/*", offset):
            depth, offset = depth + 1, offset + 2
        elif source.startswith("*/", offset):
            depth, offset = depth - 1, offset + 2
        else:
            offset += 1
    if depth:
        raise ValueError("unterminated Rust comment")
    return offset


def rust_definition(source: str, *, inline: bool) -> list[str]:
    tokens = rust_tokens(source)
    if not inline:
        return tokens
    # Inline test modules: include helpers, attributes, imports and all oracles.
    # Production code outside these modules is product context, not a test edit.
    selected, offset = [], 0
    while offset < len(tokens):
        if tokens[offset:offset + 6] == ["#", "[", "cfg", "(", "test", ")"]:
            start = offset
            while offset < len(tokens) and tokens[offset] != "{":
                offset += 1
            depth = 1
            offset += 1
            while depth and offset < len(tokens):
                depth += (tokens[offset] == "{") - (tokens[offset] == "}")
                offset += 1
            if depth:
                raise ValueError("unbalanced inline Rust test module")
            selected.extend(tokens[start:offset])
        else:
            offset += 1
    return selected


def cadence(expression: str) -> object:
    parts = expression.split()
    if (len(parts) == 5 and all(re.fullmatch(r"\d+", item) for item in parts[:2])
            and int(parts[0]) < 60 and int(parts[1]) < 24
            and parts[2:4] == ["*", "*"] and re.fullmatch(r"\*|[0-6]", parts[4])):
        return "daily" if parts[4] == "*" else "weekly"
    # Unsupported expressions remain exact; no guessed equivalence suppresses them.
    return expression


def bounded_yaml(source: str) -> object:
    data = yaml.load(source, Loader=yaml.BaseLoader) or {}
    queue = [(data, 0)]
    count = 0
    while queue:
        value, depth = queue.pop()
        count += 1
        if count > 50000 or depth > 80:
            raise ValueError("YAML structure exceeds analysis bound")
        children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
        queue.extend((child, depth + 1) for child in children)
    return data


def shell_definition(source: str) -> list[str]:
    if re.search(r"<<-?\s*['\"]?\w+", source):
        # Heredoc contents can be an oracle in another language. Do not strip
        # comments or indentation inside it as if they were shell trivia.
        return source.splitlines()
    # Keep word boundaries and literal quote/escape bytes. shlex's non-POSIX
    # mode loses the distinction between 'a'b and 'a' b; POSIX mode loses the
    # distinction between "$word" and $word. Neither can suppress these edits.
    pattern = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"|\\[\s\S]|[ \t\r]+|\n|[^ \t\r\n'\"\\]+")
    pieces, offset = [], 0
    if source.startswith("#!"):
        interpreter, _, source = source.partition("\n")
        pieces = [interpreter, "\n"]
    while offset < len(source):
        match = pattern.match(source, offset)
        if match is None:
            raise ValueError("unterminated shell quote or escape")
        token, offset = match[0], match.end()
        if token.startswith("#") and (not pieces or pieces[-1] in {" ", "\n"}):
            end = source.find("\n", offset)
            offset = len(source) if end < 0 else end
        elif token == "\\\n":
            continue  # A continuation outside a quoted literal is removed by shell.
        elif token == "\n":
            if pieces and pieces[-1] == " ":
                pieces.pop()
            if pieces and pieces[-1] != "\n":
                pieces.append("\n")
        elif token.isspace():
            if pieces and pieces[-1] not in {" ", "\n"}:
                pieces.append(" ")
        else:
            pieces.append(token)
    while pieces and pieces[-1] in {" ", "\n"}:
        pieces.pop()
    return pieces


def workflow_definition(source: str, *, guard: bool) -> object:
    data = bounded_yaml(source)
    if not isinstance(data, dict):
        raise ValueError("workflow is not a mapping")
    data.pop("name", None)
    triggers = data.get("on", {})
    for schedule in triggers.get("schedule", []) if isinstance(triggers, dict) else []:
        schedule["cron"] = cadence(schedule["cron"])
    data["jobs"] = assurance_jobs(data.get("jobs", {}), guard=guard)
    if not data["jobs"]:
        return None
    for job in data["jobs"].values():
        normalize_job(job)
    return data


def normalize_job(job: dict) -> None:
    job.pop("name", None)
    if isinstance(job.get("runs-on"), str):
        job["runs-on"] = re.sub(r"^(ubuntu|macos|windows)-(?:latest|[0-9.]+)(.*)$", r"\1-<image>\2", job["runs-on"])
    for owner in [job, *job.get("steps", [])]:
        owner.pop("name", None)
        if isinstance(owner.get("env"), dict):
            for key in {"HOST_RUN", "GUEST_INDEX"} & owner["env"].keys():
                owner["env"][key] = "<artifact input>"
    for step in job.get("steps", []):
        if "run" in step:
            step["run"] = shell_definition(step["run"])
        # Action revisions alone are dependency context; action identity remains.
        if "uses" in step:
            step["uses"] = step["uses"].split("@", 1)[0]
            if "version" in step.get("with", {}):
                step["with"]["version"] = "<dependency version>"


def assurance_jobs(jobs: dict, *, guard: bool) -> dict:
    relevant = {name for name, job in jobs.items() if guard or re.search(
        r"\bpytest\b|\bcargo[^\n]*\btest\b|tests/blackbox/|tools/assurance/|check_blackbox|check_test_assurance",
        canonical(job))}
    for _ in range(len(jobs)):
        for name in list(relevant):
            needs = jobs[name].get("needs", [])
            relevant.update([needs] if isinstance(needs, str) else needs)
    return {name: job for name, job in jobs.items() if name in relevant}


def catalogue_scope(base: Revision) -> dict[str, set[str]]:
    metadata = tomllib.loads(base.read(CATALOGUE))
    controls = {row["id"]: row for row in metadata["controls"]}
    if set(controls) != {f"BB-{number:02}" for number in range(1, 38)}:
        raise ValueError("trusted catalogue must identify BB-01 through BB-37")
    scope: dict[str, set[str]] = {}
    for witness in metadata["witnesses"]:
        for reference in [*witness["paths"], *([witness["owner"]] if "owner" in witness else [])]:
            scope.setdefault(reference.split("::", 1)[0], set()).update(witness["controls"])
    decisions = tomllib.loads(base.read(MAP))["decisions"]
    for decision in decisions:
        ids = {row["id"] for row in controls.values() if decision["id"] in row["decisions"]}
        for reference in decision["tests"]:
            scope.setdefault(reference.split("::", 1)[0], set()).update(ids)
    return scope


def imports(source: str, name: str) -> set[str]:
    """Resolve static local Python imports without importing their targets."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            parent = PurePosixPath(name).parent
            for _ in range(max(node.level - 1, 0)):
                parent = parent.parent
            prefix = str(parent).replace("/", ".") + "." if node.level else ""
            module = prefix + (node.module or "")
            modules = [module, *(module + "." + alias.name for alias in node.names)]
        else:
            continue
        for module in modules:
            path = module.replace(".", "/")
            found.update((path + ".py", path + "/__init__.py"))
            # Several executable test drivers support a direct script invocation.
            sibling = PurePosixPath(name).parent / path
            found.update((str(sibling) + ".py", str(sibling / "__init__.py")))
    return found


def evidence_scope(base: Revision, head: Revision, trusted: Revision) -> dict[str, set[str]]:
    scope = catalogue_scope(trusted)
    for name in (SELF, PUBLISHER, WORKFLOW, CATALOGUE, MAP, "tests/assurance.toml"):
        scope.setdefault(name, set())
    # The trusted paths and broad discovery remain authoritative during map edits.
    for name in base.files.keys() | head.files.keys():
        if discovered_input(name, base):
            scope.setdefault(name, set())
    queue = list(scope)
    seen = {}
    while queue:
        name = queue.pop()
        ids = frozenset(scope[name])
        if seen.get(name) == ids:
            continue
        seen[name] = ids
        for revision in (base, head):
            for reference in referenced_helpers(revision.read(name), name):
                if reference not in base.files and reference not in head.files:
                    continue
                if not reference.startswith(("tests/", "cli/tests/", "scripts/", "tools/")):
                    continue  # Imported product implementations remain context.
                if reference not in scope:
                    scope[reference] = set(scope[name])
                    queue.append(reference)
                else:
                    previous = set(scope[reference])
                    scope[reference].update(scope[name])
                    if scope[reference] != previous:
                        queue.append(reference)
    return scope


def discovered_input(name: str, base: Revision) -> bool:
    path = PurePosixPath(name)
    return (name in CATALOGUE_CODE
            or name.startswith(EVIDENCE_DIRS) and name.endswith(".py") and (path.name.startswith("test_") or path.name == "conftest.py")
            or name.startswith(EVIDENCE_DIRS) and name.endswith((".rs", ".sh")) and name in base.files
            # Cargo discovers both tests/name.rs and tests/name/main.rs, even
            # when the trusted catalogue predates the new integration target.
            or name.endswith(".rs") and (path.parent == PurePosixPath("proxy/tests")
                                        or path.name == "main.rs" and path.parent.parent == PurePosixPath("proxy/tests"))
            or name.startswith("proxy/src/") and name.endswith(".rs") and "test" in path.stem
            or name.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")))


def referenced_helpers(source: str, name: str) -> set[str]:
    if name.startswith(".github/workflows/"):
        source = canonical(workflow_definition(source, guard=name == WORKFLOW))
    references = imports(source, name) if name.endswith(".py") else set()
    references.update(re.findall(r"(?:tests|cli/tests|scripts|tools)/[A-Za-z0-9_./-]+\.(?:py|sh|rs|json|toml|yaml|yml|txt|pem|crt|conf)", source))
    references.update(str(PurePosixPath(name).parent / reference)
                      for reference in re.findall(r"\bfixtures/[A-Za-z0-9_./-]+\.(?:json|toml|yaml|yml|txt|pem|crt|conf)", source))
    if name.endswith(".py"):
        references.update(str(parent / "conftest.py") for parent in PurePosixPath(name).parents)
    return references


def definition(name: str, source: str) -> object:
    if name.endswith(".py"):
        return publisher_definition(source) if name == PUBLISHER else python_definition(source)
    if name.endswith(".toml"):
        return toml_definition(name, source)
    if not source:
        return None
    if name.endswith(".rs"):
        inline = name.startswith("proxy/src/") and "test" not in PurePosixPath(name).stem
        return rust_definition(source, inline=inline)
    if name.startswith(".github/workflows/"):
        return workflow_definition(source, guard=name == WORKFLOW)
    if name.endswith(".json"):
        return json.loads(source)
    if name.endswith((".yml", ".yaml")):
        return bounded_yaml(source)
    return shell_definition(source)


def toml_definition(name: str, source: str) -> object:
    data = tomllib.loads(source)
    if name == CATALOGUE:
        witnesses = [{key: sorted(row[key]) if key in {"paths", "controls"} else row[key]
                      for key in ("paths", "controls", "kind", "target", "module", "owner") if key in row}
                     for row in data.get("witnesses", [])]
        return {"witnesses": sorted(witnesses, key=canonical),
                "controls": sorted([{"id": row["id"], "decisions": sorted(row["decisions"])} for row in data.get("controls", [])], key=canonical)}
    if name == MAP:
        return sorted([{"id": row["id"], "tests": sorted(row["tests"])} for row in data.get("decisions", [])], key=canonical)
    if PurePosixPath(name).name == "pyproject.toml":
        return data.get("tool", {}).get("pytest")
    if PurePosixPath(name).name == "Cargo.toml":
        package = data.get("package", {})
        workspace = data.get("workspace", {})
        # Cargo 2015 disables inference for an explicitly listed target kind;
        # later editions default to discovery. Keep the edition/inheritance and
        # workspace inputs too: member defaults can depend on another manifest.
        automatic = {option: package.get(option,
                     kind == "lib" or kind not in data or package.get("edition", "2015") != "2015")
                     for kind, option in (("lib", "autolib"), ("bin", "autobins"), ("example", "autoexamples"),
                                          ("test", "autotests"), ("bench", "autobenches"))}
        profiles = {profile: {key: settings[key] for key in ("debug-assertions", "panic") if key in settings}
                    for profile, settings in data.get("profile", {}).items()}
        return {key: data[key] for key in ("lib", "bin", "example", "test", "bench", "features") if key in data} | {
            "automatic-targets": automatic,
            "edition": package.get("edition", "2015"),
            "package-workspace": package.get("workspace"),
            "workspace": ({key: sorted(workspace[key]) for key in ("members", "exclude", "default-members") if key in workspace}
                          | {"edition": workspace.get("package", {}).get("edition")}) if "workspace" in data else None,
            "profile": {profile: settings for profile, settings in profiles.items() if settings}}
    return data


def category(name: str, scope: dict) -> tuple[str, str]:
    if name in {SELF, PUBLISHER, WORKFLOW, CATALOGUE, MAP} or name.startswith("tools/assurance/"):
        return "material", "notification, catalogue or trusted analysis definition changed"
    if PurePosixPath(name).name in {"Cargo.toml", "pyproject.toml"}:
        return "material", "effective test configuration changed (dependencies are excluded)"
    if PurePosixPath(name).name in CONTEXT_NAMES or name.startswith(("proxy/vendor/", "proxy/data/", "tests/blackbox/artifacts/")):
        return "context", "dependency/build/artifact input; no assurance effect established"
    if name in scope:
        return "material", "executable witness, helper, oracle or required selection changed"
    if name.startswith(("docs/", "tests/", "cli/tests/", "scripts/", ".github/")):
        return "unclassified", "inspected input; material assurance effect not established"
    return "context", "product or other input; no assurance definition change established"


def mechanical_moves(base: Revision, head: Revision, scope: dict) -> dict[str, str]:
    """Recognize same-directory moves with unchanged code and updated references.

    Do not infer location independence for contextual introspection, package
    boundaries or dynamic discovery. Unproved executable moves remain material.
    """
    moves = {}
    removed = sorted(base.files.keys() - head.files.keys())
    added = sorted(head.files.keys() - base.files.keys())
    for old in removed:
        path = PurePosixPath(old)
        if old not in scope or path.suffix != ".py" or path.name in {"conftest.py", "__init__.py"}:
            continue
        matches = [new for new in added if base.files[old] == head.files[new]
                   and PurePosixPath(new).parent == path.parent and new.endswith(".py")
                   and PurePosixPath(new).name.startswith("test_") == path.name.startswith("test_")]
        if len(matches) != 1:
            continue
        source = base.read(old)
        if re.search(r"\b(?:__file__|__name__|__spec__|__module__|__package__|__loader__|inspect|importlib|pytest_plugins|eval|exec|globals|locals|_getframe|f_code)\b", source):
            continue
        referenced = False
        for name in scope:
            if name == old or name not in head.files:
                continue
            current = head.read(name)
            if name.endswith(".py") and old in imports(current, name):
                referenced = True
                break
            effective = canonical(definition(name, current))
            if old in effective:
                referenced = True
                break
        if not referenced:
            moves[matches[0]] = old
    return moves


def moved_references(source: str, moves: dict[str, str]) -> str:
    for new, old in moves.items():
        source = source.replace(new, old)
        source = source.replace(new[:-3].replace("/", "."), old[:-3].replace("/", "."))
    return source


def definition_delta(name: str, before: object, after: object) -> tuple[list, list]:
    if name.endswith(".py"):
        old_order, new_order = before.pop("<order>"), after.pop("<order>")
        common = set(old_order) & set(new_order)
        if [key for key in old_order if key in common] != [key for key in new_order if key in common]:
            before["<order>"], after["<order>"] = old_order, new_order
        units = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
        edits = [{"unit": key, "change": "added" if key not in before else "removed" if key not in after else "changed"} for key in units]
        delta = []
        for key in units:
            old, new = before.get(key, ""), after.get(key, "")
            old = old if isinstance(old, str) else json.dumps(old, indent=2)
            new = new if isinstance(new, str) else json.dumps(new, indent=2)
            delta.extend(sequence_changes(key, old.splitlines(), new.splitlines()))
        return delta, edits
    if name.endswith(".rs"):
        return sequence_changes("<Rust definition>", before or [], after or [], rust=True), []
    return sequence_changes("<definition>", json.dumps(before, sort_keys=True, indent=2).splitlines(),
                            json.dumps(after, sort_keys=True, indent=2).splitlines()), []


def sequence_changes(subject: str, before: list[str], after: list[str], *, rust: bool = False) -> list:
    """Fingerprint changed chunks and local definition context, excluding offsets.

    Equal source around a change is not part of its identity. A rebase that
    changes an unrelated definition therefore does not create another notice.
    Local anchors distinguish separate edits with the same replacement text.
    """
    result = []
    for kind, start, end, new_start, new_end in SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes():
        if kind == "equal":
            continue
        context = [before[max(0, start - 4):start], after[new_end:new_end + 4]]
        if rust:
            functions = [before[index + 1] for index in range(min(start, len(before) - 1))
                         if before[index] == "fn" and re.fullmatch(r"[A-Za-z_]\w*", before[index + 1])]
            context.append(functions[-1:])
        result.append((subject, digest(context), digest(before[start:end]), digest(after[new_start:new_end])))
    return result


def report_python_context(row: dict, before: str, after: str) -> None:
    """Keep inspected diagnostics and unselected helpers visible in the report."""
    delta, edits = definition_delta(row["path"], python_definition(before), python_definition(after))
    if delta:
        reason = ("inspected GitHub API diagnostics or unused helper changed; material assurance effect not established" if row["path"] == PUBLISHER
                  else "GitHub CLI fixture response framing changed; remaining test definition is unchanged")
        row.update(status="unclassified", edits=edits, reason=reason)


def compare(base: Revision, head: Revision, *, trusted: Revision | None = None) -> dict:
    scope = evidence_scope(base, head, trusted or base)
    declared = catalogue_scope(trusted or base)
    metadata = tomllib.loads((trusted or base).read(CATALOGUE))
    excluded = {path for group in metadata.get("out_of_scope", []) for path in group["paths"]}
    moves = mechanical_moves(base, head, scope)
    moved_paths = moves.keys() | moves.values()
    changes, deltas = [], []
    for name in sorted(base.files.keys() | head.files.keys()):
        if base.files.get(name) == head.files.get(name):
            continue
        status, reason = category(name, scope)
        if name in excluded and not scope.get(name):
            status, reason = "unclassified", "trusted catalogue identifies this witness as outside BB control assurance"
        if status == "unclassified" and "/fixtures/" in name and PurePosixPath(name).suffix in FIXTURE_SUFFIXES:
            # Inspect other data fixtures without equating path membership with
            # an established effect on a required oracle.
            if definition(name, base.read(name)) == definition(name, head.read(name)):
                status, reason = "mechanical", "same parsed fixture data"
        row = {"path": name, "status": status, "reason": reason, "controls": sorted(scope.get(name, set()))}
        if name in moved_paths:
            row.update(status="mechanical", reason="same-directory code move with preserved discovery and updated static references")
            changes.append(row)
            continue
        if status == "material":
            ancillary_test = (name in scope and name not in declared and not scope[name]
                              and not name.startswith(EVIDENCE_DIRS) and name.endswith(".py")
                              and PurePosixPath(name).name.startswith("test_"))
            before = regression_definition(base.read(name)) if ancillary_test else definition(name, base.read(name))
            source = moved_references(head.read(name), moves)
            after = regression_definition(source) if ancillary_test else definition(name, source)
            delta, edits = definition_delta(name, before, after)
            old_mode = base.files.get(name, (None,))[0]
            new_mode = head.files.get(name, (None,))[0]
            if old_mode and new_mode and old_mode != new_mode:
                delta.append(("<file mode>", digest(old_mode), digest(new_mode)))
                edits.append({"unit": "<file mode>", "change": "changed"})
            if not delta:
                row.update(status="mechanical", reason="same executable definition after bounded normalization")
                if name == PUBLISHER or ancillary_test:
                    report_python_context(row, base.read(name), head.read(name))
            else:
                row["edits"] = edits
                # Keep the affected subject and changed definition chunks, not
                # commit IDs, offsets or unrelated definitions on a rebased base.
                deltas.append({"path": name, "controls": row["controls"], "delta": delta})
        changes.append(row)
    if len(changes) > MAX_DELTAS or len(deltas) > MAX_DELTAS:
        raise ValueError("change report exceeds row bound")
    return {"schema": 1, "status": "complete", "trusted_base": (trusted or base).sha, "base": base.sha, "head": head.sha,
            "inspected_inputs": len(scope),
            "delta_id": digest(sorted(deltas, key=canonical)) if deltas else None, "changes": changes}


def markdown(report: dict) -> str:
    lines = ["## Blackbox assurance changes", "",
             f"Analysis: **{report['status']}**. Material changes: {sum(row['status'] == 'material' for row in report.get('changes', []))}.", ""]
    if report.get("error"):
        lines += ["Analysis failed; assurance impact is unknown. No change notice was sent.", "", f"`{report['error']}`", ""]
    for row in report.get("changes", []):
        # JSON quoting prevents candidate paths from creating mentions or markup.
        lines.append(f"- {row['status']}: `{json.dumps(row['path'], ensure_ascii=True).replace('`', '')}` — {row['reason']}.")
    lines += ["", "Repository-level protection remains with #838. A completed report does not prove delivery.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--merge-base", action="store_true", help="compare a PR from its common ancestor, using current base rules")
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": 1, "status": "failed", "trusted_base": args.base, "base": args.base, "head": args.head, "delta_id": None, "changes": []}
    try:
        trusted = Revision(args.repository, args.base)
        base_sha = trusted.git("merge-base", args.base, args.head).decode().strip() if args.merge_base else args.base
        report = compare(Revision(args.repository, base_sha), Revision(args.repository, args.head), trusted=trusted)
    except (ValueError, KeyError, SyntaxError, OSError, subprocess.SubprocessError, yaml.YAMLError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)[:500]
    args.json.write_text(canonical(report) + "\n")
    args.markdown.write_text(markdown(report))
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
