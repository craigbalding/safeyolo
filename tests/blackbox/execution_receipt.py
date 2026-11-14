"""Record named pytest cases and installed procedure checkpoints.

Collection is an inventory, not execution. A complete phase needs every required
function, every collected parameter case and successful setup/call/teardown.
Only maintained platform exclusions may excuse a skipped or unselected case.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import stat
import sys
from pathlib import Path

if __package__:
    from .selections import (
        HOST_EXCLUSIONS,
        OPTIONAL_CASES,
        PLATFORM_EXCLUSIONS,
        PROCEDURES,
        PYTEST_PHASES,
        SECTION_DRIVERS,
    )
else:
    from selections import (
        HOST_EXCLUSIONS,
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
    if platform or phase != "proxy":
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
                         "checkpoints": [], "finished": False}
        self.document["guest"] = json.loads(os.environ.get("SAFEYOLO_BLACKBOX_GUEST_IDENTITY", "null"))
        save(self.path, self.document)

    def checkpoint(self, name: str) -> None:
        expected = PROCEDURES[self.document["section"]][1]
        if name not in expected or name in self.document["checkpoints"]:
            raise ValueError(f"unexpected or repeated procedure checkpoint: {name}")
        self.document["checkpoints"].append(name)
        self.document["finished"] = name == "finished"
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
    if section != "continuity":
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
                     "exclusions": excluded, "failed_stages": failed_stages})
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


def main() -> int:
    try:
        import pytest
    except ModuleNotFoundError as exc:
        if exc.name != "pytest":
            raise
        print("Blackbox preparation failed: the selected Python needs pytest", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=PYTEST_PHASES, required=True)
    parser.add_argument("--lane", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = args.root.resolve()
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
