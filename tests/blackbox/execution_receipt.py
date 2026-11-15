"""Record named pytest cases and installed procedure checkpoints.

Collection is an inventory, not execution. A complete phase needs every required
function, every collected parameter case and successful setup/call/teardown.
Only maintained platform exclusions may excuse a skipped or unselected case.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

if __package__:
    from .selections import (
        BOUNDARY_SECTIONS,
        HOST_EXCLUSIONS,
        NATIVE_PHASES,
        OPTIONAL_CASES,
        PLATFORM_EXCLUSIONS,
        PROCEDURES,
        PYTEST_PHASES,
        SECTION_DRIVERS,
    )
else:
    from selections import (
        BOUNDARY_SECTIONS,
        HOST_EXCLUSIONS,
        NATIVE_PHASES,
        OPTIONAL_CASES,
        PLATFORM_EXCLUSIONS,
        PROCEDURES,
        PYTEST_PHASES,
        SECTION_DRIVERS,
    )

ROOT = Path(__file__).resolve().parents[2]
MAX_REPORT_BYTES = 8 * 1024 * 1024


def read_json(path: Path) -> dict:
    """Read bounded regular reports without following candidate symlinks."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ValueError("report must be a bounded regular file")
        data = stream.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("report grew beyond the read bound")
    document = json.loads(data)
    if not isinstance(document, dict):
        raise ValueError("report must contain a JSON mapping")
    return document


def python_tests(path: Path, root: Path) -> dict[str, int]:
    """Resolve pytest functions and methods without importing candidate code."""
    found = {}

    def walk(body, parents=()):
        for node in body:
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                walk(node.body, (*parents, node.name))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                found["::".join((path.relative_to(root).as_posix(), *parents, node.name))] = node.lineno

    walk(ast.parse(path.read_text(), filename=str(path)).body)
    return found


def phase_functions(phase: str, root: Path = ROOT) -> list[str]:
    selectors = PYTEST_PHASES[phase][1]
    ignored = {value.removeprefix("--ignore=") for value in selectors if value.startswith("--ignore=")}
    found = set()
    for selector in selectors:
        if selector.startswith("-"):
            continue
        relative, _, suffix = selector.partition("::")
        path = root / relative
        paths = sorted(path.rglob("test_*.py")) if path.is_dir() else [path]
        for candidate in paths:
            if candidate.relative_to(root).as_posix() in ignored:
                continue
            for node in python_tests(candidate, root):
                if not suffix or node == selector or node.startswith(selector + "::"):
                    found.add(node)
    return sorted(found)


def exclusion(lane: str, phase: str, node: str, enabled_optional=(), system: str | None = None) -> str | None:
    platform = next((reason for backend, selected_phase, pattern, reason in PLATFORM_EXCLUSIONS
                     if backend == lane and selected_phase == phase and fnmatch.fnmatchcase(node, pattern)), None)
    if platform or phase not in {"proxy", "policy-recipe"}:
        return platform
    host = next((reason for selected_system, pattern, reason in HOST_EXCLUSIONS
                 if selected_system == system and fnmatch.fnmatchcase(node, pattern)), None)
    if host:
        return host
    return next((reason for pattern, _variable, _value, reason in OPTIONAL_CASES
                 if pattern not in enabled_optional and node.split("[", 1)[0] == pattern), None)


def pytest_problems(report: dict, phase: str, lane: str, *, root: Path = ROOT) -> list[str]:
    """Recompute completeness; never trust a report's own complete flag."""
    problems = []
    identity = PYTEST_PHASES[phase][0]
    if (report.get("phase"), report.get("lane"), report.get("identity")) != (phase, lane, identity):
        return ["phase/backend/identity mismatch"]
    uid = report.get("uid")
    if identity == "guest-root" and uid != 0 or identity == "guest-agent" and uid != 1000:
        problems.append("wrong guest uid")
    if report.get("finished") is not True or type(report.get("exit")) is not int or report["exit"] != 0:
        problems.append("pytest did not finish successfully")
    collected = report.get("collected", [])
    selected = report.get("selected", [])
    outcomes = report.get("tests", {})
    if (not isinstance(collected, list) or not all(isinstance(node, str) for node in collected)
            or not isinstance(selected, list) or not all(isinstance(node, str) for node in selected)
            or not isinstance(outcomes, dict) or not all(isinstance(steps, dict) for steps in outcomes.values())):
        return [*problems, "invalid pytest outcome fields"]
    if not collected or len(collected) != len(set(collected)):
        problems.append("empty or duplicate collection")
    functions = {node.split("[", 1)[0] for node in collected}
    enabled_optional = report.get("enabled_optional", [])
    for node in phase_functions(phase, root):
        if node not in functions and not exclusion(lane, phase, node, enabled_optional, report.get("system")):
            problems.append(f"uncollected required function: {node}")
    for node in collected:
        steps = outcomes.get(node, {})
        reason = exclusion(lane, phase, node, enabled_optional, report.get("system"))
        if reason and (node not in selected or "skipped" in steps.values()):
            continue
        if node not in selected:
            problems.append(f"deselected required case: {node}")
        elif steps != dict.fromkeys(("setup", "call", "teardown"), "passed"):
            problems.append(f"required case did not pass all stages: {node}")
    if set(outcomes) - set(collected) or set(selected) - set(collected):
        problems.append("outcomes/selection differ from collection")
    return problems


def save(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n")
    temporary.replace(path)


def guest_context(platform: dict) -> dict:
    """Reuse the observed backend birth identity from assert-platform.py."""
    return {key: platform[key] for key in ("platform", "agent", "pid", "start_token")}


class ProcedureReceipt:
    """Retain reached checkpoints, including when a later operation fails."""

    def __init__(self, section: str, output: Path):
        self.path = output.with_name("procedure.json")
        self.document = {"section": section, "run_id": os.environ.get("SAFEYOLO_BLACKBOX_RUN_ID"),
                         "lane": os.environ.get("SAFEYOLO_BLACKBOX_LANE"),
                         "agent": os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest"),
                         "expected_checkpoints": list(PROCEDURES[section][1]),
                         "checkpoints": [], "finished": False, "complete": False}
        self.document["guest"] = json.loads(os.environ.get("SAFEYOLO_BLACKBOX_GUEST_IDENTITY", "null"))
        save(self.path, self.document)

    def checkpoint(self, name: str, **observations) -> None:
        expected = PROCEDURES[self.document["section"]][1]
        if name not in expected or name in self.document["checkpoints"]:
            raise ValueError(f"unexpected or repeated procedure checkpoint: {name}")
        self.document["checkpoints"].append(name)
        if observations:
            self.document.setdefault("observations", {})[name] = observations
        self.document["finished"] = name == "finished"
        self.document["complete"] = self.document["checkpoints"] == list(expected)
        save(self.path, self.document)


def section_execution(artifacts: Path, section: str, lane: str, run_id: str,
                      *, root: Path = ROOT, listener_restart: bool = False) -> dict:
    """Read each required report and retain explicit missing/partial outcomes."""
    phases = ("listener-restart",) if listener_restart else SECTION_DRIVERS[section]
    if section == "ingress" and lane == "systrap":
        phases = ("ingress-pair",)
    rows = []
    context = None
    context_problem = None
    if section not in ("continuity", *BOUNDARY_SECTIONS):
        try:
            context = guest_context(read_json(artifacts / "platform.json"))
            if context["platform"] != lane:
                context_problem = "observed backend differs from selected lane"
        except (OSError, ValueError, KeyError):
            context_problem = "missing observed guest/backend identity"
    for phase in phases:
        path = artifacts / (f"pytest-{phase}.json" if phase in PYTEST_PHASES else "procedure.json")
        try:
            report = read_json(path)
        except (OSError, ValueError) as exc:
            rows.append({"phase": phase, "complete": False, "problems": [f"missing/unreadable report: {type(exc).__name__}"]})
            continue
        problems = []
        if context_problem:
            problems.append(context_problem)
        elif context is not None and report.get("guest") != context:
            problems.append("report belongs to another guest/backend lifetime")
        if report.get("run_id") != run_id:
            problems.append("report belongs to another run")
        if section in BOUNDARY_SECTIONS and report.get("lane") != lane:
            problems.append("procedure belongs to another backend")
        if section in BOUNDARY_SECTIONS:
            identities = report.get("identities")
            if not isinstance(identities, dict) or not all(
                    isinstance(identities.get(key), dict) and identities[key]
                    for key in ("product", "controller", "guest_selection")):
                problems.append("missing product/controller/guest identities")
            elif identities["controller"].get("controller_dirty") is not False or not identities["controller"].get("controller_revision"):
                problems.append("controller source is not a clean recorded revision")
        if phase in PYTEST_PHASES:
            problems += pytest_problems(report, phase, lane, root=root)
            valid_fields = "invalid pytest outcome fields" not in problems
            cases = report.get("collected", []) if valid_fields else []
            outcomes = report.get("tests", {}) if valid_fields else {}
            excluded = {node: reason for node in cases
                        if (reason := exclusion(lane, phase, node, report.get("enabled_optional", []), report.get("system"))) and
                        (node not in report.get("selected", []) or "skipped" in report.get("tests", {}).get(node, {}).values())}
            failed_stages = sorted({stage for steps in outcomes.values()
                                    for stage, outcome in steps.items() if outcome == "failed" and stage in {"setup", "call", "teardown"}})
        else:
            if (report.get("section") != phase or report.get("finished") is not True
                    or report.get("checkpoints") != list(PROCEDURES[phase][1])):
                problems.append("missing/partial procedure checkpoints")
            excluded = {}
            failed_stages = []
        rows.append({"phase": phase, "complete": not problems, "problems": problems,
                     "exclusions": excluded, "failed_stages": failed_stages,
                     **({"expected_checkpoints": list(PROCEDURES[phase][1]),
                         "checkpoints": report.get("checkpoints", [])} if phase in PROCEDURES else {})})
    return {"complete": bool(rows) and all(row["complete"] for row in rows), "phases": rows}


class PytestReceipt:
    def __init__(self, path: Path, phase: str, lane: str, run_id: str, root: Path):
        self.path, self.root = path, root
        self.nodes = {}
        self.document = {"phase": phase, "lane": lane, "identity": PYTEST_PHASES[phase][0],
                         "run_id": run_id, "uid": os.getuid(), "gid": os.getgid(), "system": sys.platform,
                         "collected": [], "selected": [], "deselected": [], "tests": {}, "finished": False}
        self.document["enabled_optional"] = [node for node, variable, value, _reason in OPTIONAL_CASES
                                             if (os.environ.get(variable) == value if value else bool(os.environ.get(variable)))]
        self.document["guest"] = json.loads(os.environ.get("SAFEYOLO_BLACKBOX_GUEST_IDENTITY", "null"))
        if phase in {"policy-recipe", "sudo-disclosure"}:
            self.document.update(focused_inputs(root, phase))
        save(self.path, self.document)

    def node(self, item):
        path = Path(item.path).resolve().relative_to(self.root).as_posix()
        value = path + "::" + item.nodeid.partition("::")[2]
        self.nodes[item.nodeid] = value
        return value

    def pytest_collection_modifyitems(self, items):
        self.document["collected"] = [self.node(item) for item in items]
        yield
        self.document["selected"] = [self.node(item) for item in items]
        save(self.path, self.document)

    def pytest_deselected(self, items):
        self.document["deselected"].extend(self.node(item) for item in items)

    def pytest_runtest_logreport(self, report):
        node = self.nodes[report.nodeid]
        self.document["tests"].setdefault(node, {})[report.when] = report.outcome
        save(self.path, self.document)

    def pytest_sessionfinish(self, exitstatus):
        self.document.update(finished=True, exit=int(exitstatus))
        save(self.path, self.document)


def focused_inputs(root: Path, phase: str) -> dict:
    """Identify the actual native inputs used by the existing Python fixtures."""
    layout = os.environ.get("SAFEYOLO_AUTHORING_LAYOUT", "installed")
    boundary = "host-disclosure/controlled-authentication" if phase == "sudo-disclosure" else f"native-process/{layout}-layout"
    result = {"boundary": boundary,
              "authoring_layout": os.environ.get("SAFEYOLO_AUTHORING_LAYOUT", "installed"),
              "controller_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
              "working_tree_changed": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root)),
              "product_binaries": {}}
    if phase == "sudo-disclosure":
        binaries = [Path(os.environ.get("SAFEYOLO_NATIVE_CLI", root / "proxy/target/release/safeyolo"))]
    else:
        from tests.proxy_contracts.test_native_policy_cli import native_inputs

        host, _guest, _profile = native_inputs()
        binaries = [host / name for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord")]
    for binary in binaries:
        if binary.is_file():
            with binary.open("rb") as stream:
                result["product_binaries"][str(binary.resolve())] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def native_cases(phase: str, root: Path) -> list[tuple[str, str, list[str]]]:
    """Use the catalogue's source identities for the selected native modules."""
    if __package__:
        from .catalogue import resolve
    else:
        from catalogue import resolve

    witnesses = tomllib.loads((root / "tests/blackbox/controls.toml").read_text())["witnesses"]
    groups = []
    for target, module in NATIVE_PHASES[phase]:
        names = []
        for witness in witnesses:
            if witness["kind"] == "cargo" and (witness["target"], witness["module"]) == (target, module):
                for reference in witness["paths"]:
                    names += [node["node"] for node in resolve(witness, reference, root)]
        if not names or len(names) != len(set(names)):
            raise ValueError(f"missing or duplicate native identities: {target}/{module}")
        groups.append((target, module, sorted(names)))
    return groups


def native_problems(report: dict, expected: list[tuple[str, str, list[str]]]) -> list[str]:
    """Require observed named results, including every ignored or missing case."""
    problems = []
    groups = report.get("groups", [])
    if report.get("finished") is not True or len(groups) != len(expected):
        problems.append("native phase did not finish every selected group")
    for group, (target, module, names) in zip(groups, expected):
        if (group.get("target"), group.get("module"), group.get("selected")) != (target, module, names):
            problems.append(f"native selection mismatch: {target}/{module}")
        if (type(group.get("exit")) is not int or group["exit"] != 0
                or group.get("tests") != dict.fromkeys(names, "ok")):
            problems.append(f"missing, ignored or failed native cases: {target}/{module}")
    return problems


def run_native(args, root: Path) -> int:
    """Build and run the bounded policy/feed/transition process selections."""
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {"phase": args.native_phase, "lane": args.lane, "identity": "host",
              "boundary": "native-process", "run_id": args.run_id, "uid": os.getuid(), "gid": os.getgid(),
              "system": sys.platform, "architecture": platform.machine(), "profile": args.cargo_profile,
              "controller_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
              "working_tree_changed": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root)),
              "include_ignored": args.include_ignored, "groups": [], "finished": False, "complete": False}
    save(output, report)
    expected = native_cases(args.native_phase, root)
    environment = dict(os.environ, CARGO_BUILD_JOBS="1",
                       CARGO_TARGET_DIR=os.environ.get("CARGO_TARGET_DIR", str(root / "proxy/target")))
    executables = {}
    for index, (target, module, names) in enumerate(expected):
        group = {"target": target, "module": module, "selected": names, "tests": {}}
        report["groups"].append(group)
        save(output, report)
        if target not in executables:
            command = [str(root / "scripts/cargo_with_space.sh"), "test", "--manifest-path", "proxy/Cargo.toml",
                       "--locked", "--no-run", "--message-format=json"]
            command += ["--lib"] if target == "lib" else ["--test", target]
            if args.cargo_profile == "release":
                command.append("--release")
            build = output.with_name(f"{output.stem}-{target}-build.jsonl")
            with build.open("w") as stdout, build.with_suffix(".log").open("w") as stderr:
                result = subprocess.run(command, cwd=root, env=environment, stdout=stdout, stderr=stderr, check=False)
            group.update(build_command=command, build_exit=result.returncode, build_log=str(build),
                         build_stderr=str(build.with_suffix(".log")))
            save(output, report)
            if result.returncode:
                break
            artifacts = [json.loads(line) for line in build.read_text().splitlines()]
            kind = "lib" if target == "lib" else "test"
            binaries = [row["executable"] for row in artifacts if row.get("reason") == "compiler-artifact"
                        and row.get("profile", {}).get("test") and kind in row["target"]["kind"]
                        and row.get("executable") and (target == "lib" or row["target"]["name"] == target)]
            if len(binaries) != 1:
                raise ValueError(f"expected one native {target} test executable, found {binaries}")
            executables[target] = Path(binaries[0])
        binary = executables[target]
        with binary.open("rb") as stream:
            group.update(executable=str(binary), executable_sha256=hashlib.file_digest(stream, "sha256").hexdigest())
        command = [str(binary), *([module] if module else []), "--format", "pretty", "--test-threads=1"]
        if args.include_ignored:
            command.append("--include-ignored")
        log = output.with_name(f"{output.stem}-{index}.log")
        group.update(command=command, log=str(log))
        save(output, report)
        with log.open("w") as stdout:
            result = subprocess.run(command, cwd=root, env=environment, stdout=stdout, stderr=subprocess.STDOUT, check=False)
        group.update(exit=result.returncode,
                     tests=dict(re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b", log.read_text(), re.MULTILINE)))
        save(output, report)
    report["finished"] = True
    report["problems"] = native_problems(report, expected)
    report["complete"] = not report["problems"]
    save(output, report)
    print(f"{'Complete' if report['complete'] else 'Incomplete'} native phase {args.native_phase}: {output}")
    return 0 if report["complete"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--phase", choices=PYTEST_PHASES)
    selection.add_argument("--native-phase", choices=NATIVE_PHASES)
    parser.add_argument("--cargo-profile", choices=("debug", "release"), default="debug")
    parser.add_argument("--include-ignored", action="store_true", help="run required native cases that need an explicitly prepared host")
    parser.add_argument("--lane", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.native_phase:
        if args.arguments:
            parser.error("native phases have fixed selectors and accept no extra test arguments")
        try:
            return run_native(args, root)
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            if args.output.is_file():
                report = read_json(args.output)
                if report.get("run_id") == args.run_id:
                    report.update(complete=False, observer_error=f"{type(exc).__name__}: {exc}")
                    save(args.output, report)
            print(f"Incomplete native phase {args.native_phase}: {exc}; report: {args.output}", file=sys.stderr)
            return 2
    try:
        import pytest
    except ModuleNotFoundError as exc:
        if exc.name != "pytest":
            raise
        print("Blackbox preparation failed: the selected Python needs pytest", file=sys.stderr)
        return 2

    os.chdir(root)
    plugin = PytestReceipt(args.output.resolve(), args.phase, args.lane, args.run_id, root)
    # Keep the report reader usable in the stdlib-only installation bootstrap.
    PytestReceipt.pytest_collection_modifyitems = pytest.hookimpl(hookwrapper=True, tryfirst=True)(
        PytestReceipt.pytest_collection_modifyitems)
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    result = int(pytest.main([*PYTEST_PHASES[args.phase][1], *arguments], plugins=[plugin]))
    problems = pytest_problems(plugin.document, args.phase, args.lane, root=root)
    plugin.document.update(complete=not problems, problems=problems)
    save(plugin.path, plugin.document)
    if problems and result == 0:
        print(f"Incomplete blackbox phase {args.phase}: " + "; ".join(problems), file=sys.stderr)
        return 2
    return result


if __name__ == "__main__":
    raise SystemExit(main())
