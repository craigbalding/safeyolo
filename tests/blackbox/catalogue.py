"""Resolve authored BB control metadata against maintained source and selectors.

Discovery establishes names, locations and selection only. It does not judge
assertion semantics, control sufficiency or whether a deployment passed.
"""

from __future__ import annotations

import ast
import fnmatch
import re
import shlex
import tomllib
from pathlib import Path

import yaml

if __package__:
    from .execution_receipt import phase_functions, python_tests
    from .selections import (
        HOST_EXCLUSIONS,
        NATIVE_PHASES,
        OPTIONAL_CASES,
        OPTIONAL_SECTIONS,
        PROCEDURES,
        PYTEST_PHASES,
        SECTIONS,
    )
else:
    from execution_receipt import phase_functions, python_tests
    from selections import (
        HOST_EXCLUSIONS,
        NATIVE_PHASES,
        OPTIONAL_CASES,
        OPTIONAL_SECTIONS,
        PROCEDURES,
        PYTEST_PHASES,
        SECTIONS,
    )

ROOT = Path(__file__).resolve().parents[2]
METADATA = "tests/blackbox/controls.toml"
WATCHED = ("tests/blackbox/host", "tests/blackbox/isolation", "tests/proxy_contracts")
EXTERNAL_FAMILIES = ("tests/test_guest_*.py", "tests/test_hyperlight_*.py", "tests/test_job_*.py",
                     "proxy/tests/native_coord/**/*.rs", "proxy/tests/credential_http/*.rs")
RUST_TEST = re.compile(
    r"(?P<attrs>(?:\s*#\[[^\]]+\]\s*)+)\s*(?:async\s+)?fn\s+(?P<name>\w+)\s*\(", re.MULTILINE)


def workflows(root: Path) -> list[dict]:
    """Read executable YAML run steps, with their actual job conditions."""
    commands = []
    for path in sorted((root / ".github/workflows").glob("*.yml")):
        data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        triggers = data.get("on", {})
        scheduled = isinstance(triggers, dict) and bool(triggers.get("schedule"))
        for name, job in data.get("jobs", {}).items():
            condition = job.get("if", "")
            recurring = scheduled and (not condition or "github.event_name == 'schedule'" in condition
                                        or condition == "github.event_name != 'workflow_run'")
            for step in job.get("steps", []):
                for line in step.get("run", "").replace("\\\n", " ").splitlines():
                    # Ignore prose comments and preserve quoted shell operands.
                    try:
                        tokens = shlex.split(line, comments=True)
                    except ValueError:
                        continue  # An embedded script line is not a shell selector.
                    if ("pytest" in tokens or any(token.endswith("cargo_with_space.sh") for token in tokens)
                            or any(token.endswith("retained_inputs.py") for token in tokens)):
                        commands.append({"path": path.relative_to(root).as_posix(), "job": name,
                                         "tokens": tokens, "condition": condition,
                                         "cadence": "scheduled/manual" if recurring and not step.get("if") else "conditional CI"})
    return commands


def shell_commands(root: Path) -> list[dict]:
    """Resolve literal pytest selectors in the maintained shell runners."""
    commands = []
    for path in sorted((root / "tests/blackbox").rglob("*.sh")):
        for line in path.read_text().replace("\\\n", " ").splitlines():
            try:
                tokens = shlex.split(line, comments=True)
            except ValueError:
                continue
            if "pytest" in tokens:
                tokens = [token.replace("$REPO_ROOT/", "") for token in tokens]
                commands.append({"path": path.relative_to(root).as_posix(), "job": "shell runner",
                                 "tokens": tokens, "condition": "explicit invocation", "cadence": "manual"})
    return commands


def pytest_path_options(command: dict) -> dict[str, list[str]]:
    """Separate maintained collection exclusions from positive path operands."""
    options = {name: [] for name in ("selectors", "--ignore", "--ignore-glob", "--deselect")}
    tokens = command["tokens"]
    if "pytest" not in tokens:
        return options
    arguments = iter(tokens[tokens.index("pytest") + 1:])
    for token in arguments:
        name, separator, value = token.partition("=")
        if name in options and name != "selectors":
            options[name].append(value if separator else next(arguments, ""))
        elif token.startswith(("tests/", "cli/tests/")):
            options["selectors"].append(token)
    return options


def selects(selector: str, node: str) -> bool:
    path = node.split("::", 1)[0]
    return node == selector or node.startswith(selector + "::") or path.startswith(selector.rstrip("/") + "/")


def pytest_selected(command: dict, node: str) -> bool:
    """Apply collection exclusions and deselection to a source test identity."""
    options = pytest_path_options(command)
    paths = [Path(selector.split("::", 1)[0]) for selector in options["selectors"] if selects(selector, node)]
    if not paths or any(node.startswith(prefix) for prefix in options["--deselect"]):
        return False
    # Pytest applies ignores while traversing directories, not to a sole
    # explicit starting file. A broader starting directory still applies them.
    start = min(paths, key=lambda path: len(path.parts))
    path = Path(node.split("::", 1)[0])
    traversed = [entry for entry in (path, *path.parents) if start in entry.parents]
    return not any(entry == Path(ignored) for entry in traversed for ignored in options["--ignore"]) and not any(
        fnmatch.fnmatchcase(entry.as_posix(), pattern) for entry in traversed for pattern in options["--ignore-glob"])


def resolve(witness: dict, reference: str, root: Path) -> list[dict]:
    relative, _, suffix = reference.partition("::")
    path = root / relative
    if not path.is_file():
        raise ValueError(f"unresolved witness file: {relative}")
    kind = witness["kind"]
    if kind == "pytest":
        nodes = python_tests(path, root)
        result = [{"node": node, "line": line, "ignored": False} for node, line in nodes.items()
                  if not suffix or selects(reference, node)]
    elif kind == "procedure":
        tree = ast.parse(path.read_text())
        result = [{"node": reference, "line": node.lineno, "ignored": False}
                  for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == suffix]
    elif kind == "cargo":
        source = path.read_text()
        start, end = 0, len(source)
        if relative == witness["owner"]:
            # An owner file can contain several sibling inline test modules.
            # Keep each module's identities separate; native execution must
            # still confirm every discovered name against the compiled tests.
            leaf = witness["module"].split("::")[-1]
            inline = re.search(r"(?m)^(?P<indent>[ \t]*)mod\s+" + re.escape(leaf) + r"\s*\{", source)
            if inline:
                start = inline.end()
                closing = re.search(r"(?m)^" + inline["indent"] + r"\}", source[start:])
                if closing:
                    end = start + closing.start()
        constraint_sources = [source, (root / witness["owner"]).read_text()]
        if witness["target"] != "lib":
            target = root / "proxy/tests" / (witness["target"] + ".rs")
            constraint_sources.append(target.read_text())
        file_constraints = "\n".join(dict.fromkeys(
            constraint for content in constraint_sources for constraint in re.findall(r"#!\[cfg[^\]]*\]", content)))
        result = [{"node": "::".join(filter(None, (witness["module"], match["name"]))),
                   "line": source[:match.start()].count("\n") + 1,
                   "ignored": "#[ignore" in match["attrs"], "cfg": file_constraints + "\n" + match["attrs"].strip()}
                  for match in RUST_TEST.finditer(source, start, end) if re.search(r"#\[(?:tokio::)?test\b", match["attrs"])]
    else:
        raise ValueError(f"unknown witness kind: {kind}")
    if not result:
        raise ValueError(f"unresolved witness identity: {reference}")
    return result


def cargo_selected(witness: dict, node: dict, command: dict) -> bool:
    tokens = command["tokens"]
    if "test" not in tokens or "--no-run" in tokens:
        return False
    if not any(token.endswith("cargo_with_space.sh") for token in tokens):
        return False
    if "--manifest-path" in tokens and tokens[tokens.index("--manifest-path") + 1] != "proxy/Cargo.toml":
        return False
    if "--lib" in tokens and witness["target"] != "lib":
        return False
    targets = [tokens[index + 1] for index, value in enumerate(tokens[:-1]) if value == "--test"]
    if targets and witness["target"] not in targets:
        return False
    if node["ignored"] and not ({"--ignored", "--include-ignored"} & set(tokens)):
        return False
    if "--ignored" in tokens and not node["ignored"]:
        return False
    # Maintained filtered Cargo commands place the filter after --lib or the
    # target. Flags and their arguments are not test names.
    options = tokens[tokens.index("test") + 1:]
    positional = []
    skip = False
    for token in options:
        if skip:
            skip = False
        elif token in {"--manifest-path", "--test", "--bin", "--package", "-p"}:
            skip = True
        elif token == "--":
            break
        elif not token.startswith("-"):
            positional.append(token)
    return not positional or any((node["node"] == value if "--exact" in tokens else value in node["node"])
                                 for value in positional)


def selection(witness: dict, reference: str, node: dict, commands: list[dict], phases: dict) -> list[str]:
    selected = []
    if witness["kind"] == "pytest":
        for optional_node, variable, value, reason in OPTIONAL_CASES:
            if node["node"] == optional_node:
                selected.append(f"optional: select `{variable}`" + (f" = `{value}`" if value else " explicitly") + f" ({reason})")
        for phase, functions in phases.items():
            if any(selects(function, node["node"]) for function in functions):
                selected.append(f"phase `{phase}` ({PYTEST_PHASES[phase][0]})")
        matches = [command for command in commands if pytest_selected(command, node["node"])]
    elif witness["kind"] == "cargo":
        matches = [command for command in commands if cargo_selected(witness, node, command)]
        for phase, groups in NATIVE_PHASES.items():
            if any(witness["target"] == target and (not prefix or node["node"].startswith(prefix + "::"))
                   for target, prefix in groups):
                selected.append(f"manual native phase `{phase}` (named execution receipt; ignored cases remain incomplete)")
        if node["ignored"]:
            selected.append("ignored by default")
    else:
        matches = []
        filename = reference.split("::", 1)[0].removeprefix("tests/blackbox/")
        for phase, (driver, _checkpoints) in PROCEDURES.items():
            if filename != driver:
                continue
            section = "ingress" if phase == "ingress-pair" else phase
            for lane, sections in SECTIONS.items():
                if section in sections and not (section == "ingress" and phase == "ingress-pair"):
                    selected.append(f"default `{lane}` section `{section}`")
                elif section in OPTIONAL_SECTIONS[lane]:
                    selected.append(f"optional `{lane}` section `{section}`")
    selected += [f"[{command['job']}]({link(command['path'])}) ({command['cadence']}; condition `{command['condition'] or 'none'}`)"
                 for command in matches]
    return list(dict.fromkeys(selected)) or ["manual; no recurring selector resolved"]


def selector_problems(root: Path = ROOT) -> list[str]:
    """Reject unwired shared phases, renamed YAML tests and procedure steps."""
    problems = []
    shell = (root / "tests/blackbox/run-tests.sh").read_text()
    wired = set(re.findall(r"(?:run_pytest_phase|--pytest-phase|--phase)\s+([a-z][a-z-]+)", shell))
    required = {"native", "security", "identity", "guest-agent", "guest-root", "host-lifecycle", "listener-restart", "proxy"}
    if not required <= wired:
        problems.append(f"unwired pytest phases: {sorted(required - wired)}")
    commands = [*workflows(root), *shell_commands(root)]
    commands += [{"path": f"shared phase {phase}", "tokens": ["pytest", *operands]}
                 for phase, (_identity, operands) in PYTEST_PHASES.items()]
    for command in commands:
        options = pytest_path_options(command)
        for selector in [*options["selectors"], *options["--ignore"], *options["--deselect"]]:
            relative, _, _suffix = selector.partition("::")
            path = root / relative
            if not path.exists():
                problems.append(f"{command['path']}: unresolved pytest selector {selector}")
            elif "::" in selector and (not path.is_file() or not any(selects(selector, node) for node in python_tests(path, root))):
                problems.append(f"{command['path']}: unresolved pytest identity {selector}")
    for section, (filename, checkpoints) in PROCEDURES.items():
        path = root / "tests/blackbox" / filename
        tree = ast.parse(path.read_text())
        actual = [node.args[0].value for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "checkpoint" and node.args and isinstance(node.args[0], ast.Constant)]
        if sorted(actual) != sorted(checkpoints):
            problems.append(f"{filename}: stale/missing procedure checkpoints for {section}")
        drivers = shell + (root / "tests/blackbox/installed_sections.py").read_text()
        focused = root / "tests/blackbox/run-controls.sh"
        if focused.is_file():
            drivers += focused.read_text()
        if filename not in drivers:
            problems.append(f"unwired installed procedure: {filename}")
    explicit = [node for node, _variable, _value, _reason in OPTIONAL_CASES]
    explicit += [node for _system, node, _reason in HOST_EXCLUSIONS if "*" not in node]
    for node in explicit:
        path = root / node.split("::", 1)[0]
        if path.is_file() and node not in python_tests(path, root):
            problems.append(f"stale optional/platform reference: {node}")
    return problems


def validate_controls(controls: list[dict], root: Path) -> set[str]:
    ids = [control["id"] for control in controls]
    expected = [f"BB-{number:02}" for number in range(1, 38)]
    if sorted(ids) != expected:
        raise ValueError("control IDs must contain BB-01–BB-37 exactly once")
    fields = {"id", "control", "source", "what", "existing", "conformance", "effort", "comments", "owner", "decisions"}
    decisions = {item["id"] for item in tomllib.loads((root / "docs/assurance-map.toml").read_text())["decisions"]}
    for control in controls:
        if set(control) != fields or any(not control[key] for key in fields - {"decisions"}):
            raise ValueError(f"{control['id']}: incomplete control metadata")
        if set(control["decisions"]) - decisions:
            raise ValueError(f"{control['id']}: unresolved assurance decision")
    return set(ids)


def validate_cargo_source(witness: dict, root: Path) -> None:
    owner = root / witness["owner"]
    if not witness["module"] and witness["target"] != "lib":
        expected = root / "proxy/tests" / (witness["target"] + ".rs")
        if owner != expected or any(root / path != expected for path in witness["paths"]):
            raise ValueError(f"unwired Cargo root target: {witness['paths']}")
        return
    leaf = witness["module"].split("::")[-1]
    if witness["target"] == "lib":
        prefix = owner.relative_to(root / "proxy/src").with_suffix("").parts
    else:
        owner_parts = owner.relative_to(root / "proxy/tests").with_suffix("").parts
        if owner_parts[0] != witness["target"]:
            raise ValueError(f"unresolved Cargo target: {witness['target']}")
        prefix = owner_parts[1:]
    if witness["module"] != "::".join((*prefix, leaf)):
        raise ValueError(f"unresolved Cargo module identity: {witness['module']}")
    source = owner.read_text()
    module = re.search(r"\bmod\s+" + re.escape(leaf) + r"\s*([;{])", source)
    if not module:
        raise ValueError(f"unwired Cargo module: {witness['paths']}")
    if module[1] == "{":
        resolved = owner
    else:
        explicit = re.search(r'#\[path\s*=\s*"([^\"]+)"\]\s*mod\s+' + re.escape(leaf) + r"\s*;", source)
        resolved = owner.parent / (explicit[1] if explicit else owner.stem + "/" + leaf + ".rs")
    if any(resolved.resolve() != (root / path).resolve() for path in witness["paths"]):
        raise ValueError(f"unwired Cargo source: {witness['paths']}")


def load(root: Path = ROOT) -> tuple[list[dict], list[dict], list[dict]]:
    metadata = tomllib.loads((root / METADATA).read_text())
    controls, witnesses = metadata["controls"], metadata["witnesses"]
    ids = validate_controls(controls, root)
    classified = set()
    for witness in witnesses:
        if not witness["controls"] or set(witness["controls"]) - set(ids) or not witness["scope"] or not witness["adapter"]:
            raise ValueError("incomplete witness classification")
        witness["resolved"] = []
        for reference in witness["paths"]:
            nodes = resolve(witness, reference, root)
            witness["resolved"].append((reference, nodes))
            classified.add(reference.split("::", 1)[0])
        if witness["kind"] == "cargo":
            validate_cargo_source(witness, root)
    for group in metadata.get("out_of_scope", []):
        if not group["reason"]:
            raise ValueError("out-of-scope classification needs a reason")
        for path in group["paths"]:
            if not (root / path).is_file():
                raise ValueError(f"stale out-of-scope reference: {path}")
            classified.add(path)
    discovered = {path.relative_to(root).as_posix() for directory in WATCHED
                  for path in (root / directory).rglob("test_*.py")}
    discovered.update(path.relative_to(root).as_posix() for pattern in EXTERNAL_FAMILIES for path in root.glob(pattern))
    if discovered - classified:
        raise ValueError(f"assurance tests need control mapping or out-of-scope classification: {sorted(discovered - classified)}")
    problems = selector_problems(root)
    if problems:
        raise ValueError("; ".join(problems))
    return controls, witnesses, metadata.get("out_of_scope", [])


def link(path: str, line: int | None = None) -> str:
    return "../" + path + (f"#L{line}" if line else "")


def render_control_rows(controls: list[dict], witnesses: list[dict], commands: list[dict], phases: dict) -> list[str]:
    lines = []
    for control in controls:
        matching = [witness for witness in witnesses if control["id"] in witness["controls"]]
        lines += [f"### {control['id']} — {control['control']}", "",
                  f"**What and why:** {control['what']}", "",
                  f"**Audit coverage:** {control['existing']}", "",
                  f"**Conformance / action:** {control['conformance']}", "",
                  f"**Effort:** {control['effort']}. **Comments:** {control['comments']}", "",
                  f"**Owner / remaining work:** [{control['owner']}](https://github.com/craigbalding/safeyolo/issues/{control['owner'][1:]}). "
                  f"[Audit source / evidence context]({control['source']}).", ""]
        if control["decisions"]:
            lines += ["**Assurance decisions:** " + ", ".join(f"`{name}`" for name in control["decisions"]) + ".", ""]
        lines += ["**Current existence:** " + ("resolved witnesses listed below; no current run inferred." if matching else
                  "no maintained witness resolved. The owner above retains the missing control."), ""]
        for witness in matching:
            for reference, nodes in witness["resolved"]:
                lines += [f"- [{reference}]({link(reference.split('::', 1)[0], nodes[0]['line'])}) — "
                          f"{witness['scope']}. Evidence: {witness['adapter']}."]
                if witness["kind"] == "procedure":
                    lines += ["  Selection: " + "; ".join(selection(witness, reference, nodes[0], commands, phases)) + "."]
                else:
                    lines += [f"  Exact identities: [source inventory](#{witness_anchor(witness, reference)})."]
        lines.append("")
    return lines


def render_witness_identities(witnesses: list[dict], commands: list[dict], phases: dict) -> list[str]:
    lines = []
    for witness in witnesses:
        for reference, nodes in witness["resolved"]:
            if witness["kind"] == "procedure":
                continue
            lines += [f'<a id="{witness_anchor(witness, reference)}"></a>', f"### [`{reference}`]({link(reference)})", ""]
            last_selection = None
            for node in nodes:
                selected = selection(witness, reference, node, commands, phases)
                if selected != last_selection:
                    lines += ["Selection: " + "; ".join(selected) + ".", ""]
                    last_selection = selected
                identity = node["node"]
                if witness["kind"] == "cargo":
                    target = "--lib" if witness["target"] == "lib" else "--test " + witness["target"]
                    identity = f"cargo test --manifest-path proxy/Cargo.toml {target} {identity} -- --exact" + (" --ignored" if node["ignored"] else "")
                lines += [f"- [`{identity}`]({link(reference.split('::', 1)[0], node['line'])})"]
                if witness["kind"] == "cargo":
                    constraints = re.findall(r"#!?\[(?:ignore|cfg)[^\]]*\]", node["cfg"])
                    if constraints:
                        lines[-1] += " — " + "; ".join(f"`{constraint}`" for constraint in constraints)
            lines.append("")
    return lines


def render(root: Path = ROOT) -> str:
    controls, witnesses, outside = load(root)
    commands = [*workflows(root), *shell_commands(root)]
    phases = {phase: phase_functions(phase, root) for phase in PYTEST_PHASES}
    lines = ["## Complete control catalogue", "",
             "The authored meaning and dispositions preserve [all 37 agreed controls](https://github.com/craigbalding/safeyolo/issues/1557). "
             "The audit baseline is 13 November 2026. Current existence and exact identities below come from source. "
             "Conformance is an authored boundary judgment, not a fresh passing result. Planned repairs remain with their named owners.", "",
             "Metadata lives in [`controls.toml`](../tests/blackbox/controls.toml). "
             "The [assurance map](assurance-map.toml) retains the implementation decision IDs. "
             "Controlled adapters, host-only tests and real-guest procedures have different evidence levels. "
             "AST/attribute discovery does not prove assertion semantics.", ""]
    lines += render_control_rows(controls, witnesses, commands, phases)
    lines += ["## Exact witness identities and maintained selection", "",
              "Python identities name pytest functions/methods; a phase receipt expands parameter IDs and records each case. "
              "Cargo identities name the target and exact Rust test name. Ignore and cfg attributes remain source constraints. "
              "CI selectors describe maintained execution, not a passing receipt on every host. "
              "No hardware deployment or installed result is inferred from these files.", ""]
    recurring_lanes = sorted({command["tokens"][command["tokens"].index("--lane") + 1]
                             for command in commands if command["path"] == ".github/workflows/blackbox.yml"
                             and command["cadence"] == "scheduled/manual" and "--lane" in command["tokens"]})
    lines += ["**Scheduled installed lanes resolved from automation:** " + ", ".join(f"`{lane}`" for lane in recurring_lanes) + ". "
              "Unlisted KVM/VZ venues remain with [#889](https://github.com/craigbalding/safeyolo/issues/889). "
              "A workflow selector describes intended cadence; it is not proof that a host deployment ran.", ""]
    lines += render_witness_identities(witnesses, commands, phases)
    lines += ["## Explicitly outside this control catalogue", ""]
    for group in outside:
        lines += [group["reason"], "", *(f"- [`{path}`]({link(path)})" for path in group["paths"]), ""]
    return "\n".join(lines)


def anchor(reference: str) -> str:
    return "witness-" + re.sub(r"[^a-z0-9]+", "-", reference.lower()).strip("-")


def witness_anchor(witness: dict, reference: str) -> str:
    # Sibling inline Rust modules share a file but have distinct inventories.
    suffix = "::" + witness["module"] if witness["kind"] == "cargo" and reference == witness["owner"] else ""
    return anchor(reference + suffix)
