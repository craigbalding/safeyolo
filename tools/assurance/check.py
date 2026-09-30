#!/usr/bin/env python3
"""Compare a candidate's parsed proxy sources with a trusted accepted snapshot."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from pathlib import Path

SCHEMA = 1
CHECKER_VERSION = "2"
SEMGREP_VERSION = "1.176.0"
ROOT = Path(__file__).resolve().parents[2]
FUNCTION_RULES = {"rust-function", "python-function"}
NAME_RE = re.compile(r"\b(?:async\s+)?(?:fn|def)\s+([A-Za-z_][A-Za-z_0-9]*)\b")
IMPL_NAME_RE = re.compile(r"^impl\s+(?:<[^{}]*>\s+)?([A-Za-z_][A-Za-z_0-9]*)(?:<[^{}]*>)?\s*\{")
MAP = "docs/assurance-map.toml"
ACCEPTED = "tools/assurance/accepted.json"
RULES = "tools/assurance/rules.yml"
CONTROL_FILES = {
    MAP,
    "docs/assurance.md",
    ".github/CODEOWNERS",
    ".semgrepignore",
    "tools/acceptance/pyproject.toml",
    "tools/acceptance/uv.lock",
}
CONTROL_DIRS = ("tools/assurance", ".github/workflows")
INPUT_FILES = (
    "proxy/Cargo.toml",
    "proxy/Cargo.lock",
    "proxy/build.rs",
    "proxy/rust-toolchain.toml",
    "pyproject.toml",
    "uv.lock",
    "vm/Package.swift",
    "vm/Package.resolved",
    "install.sh",
    "guest/build-rootfs.sh",
    "cli/src/safeyolo/guest-proxy-forwarder.sh",
)
INPUT_DIRS = ("proxy/vendor", "proxy/data", "proxy/.cargo", "vm/Sources")
SOURCE_DIRS = ("proxy/src", "cli/src/safeyolo", "pdp")


class AnalysisError(Exception):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_revision(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    result = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=root,
                            capture_output=True, text=True, check=False)
    revision = result.stdout.strip()
    return revision if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", revision) else None


def files_under(root: Path, names: tuple[str, ...]) -> set[str]:
    found: set[str] = set()
    for name in names:
        directory = root / name
        if directory.is_symlink():
            raise AnalysisError(f"symlink in analysis scope: {name}")
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise AnalysisError(f"symlink in analysis scope: {path.relative_to(root)}")
            if path.is_file() and not any(part in {"__pycache__", ".pytest_cache", ".ruff_cache"} for part in path.parts):
                found.add(path.relative_to(root).as_posix())
    return found


def source_paths(root: Path) -> set[str]:
    paths = files_under(root, SOURCE_DIRS)
    selected = set()
    for path in paths:
        parts = Path(path).parts
        if path.startswith("proxy/src/"):
            if (not path.endswith(".rs") or any(part == "tests" or part.endswith("_tests") for part in parts)
                    or path.endswith(("tests.rs", "_tests.rs", "test_owned_endpoint.rs"))):
                continue
        elif not path.endswith(".py") or Path(path).name.startswith("test_"):
            continue
        selected.add(path)
    if not any(path.startswith("proxy/src/") for path in selected):
        raise AnalysisError("Rust proxy source scope is empty")
    if not any(path.startswith("cli/src/safeyolo/") for path in selected):
        raise AnalysisError("Python CLI source scope is empty")
    return selected


def file_hashes(root: Path, paths: set[str]) -> dict[str, str]:
    result = {}
    for name in sorted(paths):
        path = root / name
        if path.is_symlink():
            raise AnalysisError(f"symlink in analysis scope: {name}")
        result[name] = digest(path.read_bytes())
    return result


def input_paths(root: Path) -> set[str]:
    return {name for name in INPUT_FILES if (root / name).is_file()} | files_under(root, INPUT_DIRS)


def control_paths(root: Path) -> set[str]:
    return {name for name in CONTROL_FILES if (root / name).is_file()} | files_under(root, CONTROL_DIRS)


def load_map(root: Path) -> tuple[list[dict], set[str]]:
    path = root / MAP
    if not path.is_file():
        raise AnalysisError(f"missing trusted map: {MAP}")
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    decisions = document.get("decisions")
    if not isinstance(decisions, list) or not decisions:
        raise AnalysisError("trusted source map has no decisions")
    symbols: set[str] = set()
    ids: set[str] = set()
    for item in decisions:
        if not isinstance(item, dict) or not all(item.get(key) for key in ("id", "inputs", "authority", "checks", "effects", "failure", "tests", "symbols")):
            raise AnalysisError("incomplete source-map decision")
        if item["id"] in ids:
            raise AnalysisError(f"duplicate decision id: {item['id']}")
        ids.add(item["id"])
        for symbol in item["symbols"]:
            if not isinstance(symbol, str) or "::" not in symbol or symbol in symbols:
                raise AnalysisError(f"invalid or duplicate mapped symbol: {symbol}")
            symbols.add(symbol)
    return decisions, symbols


def semgrep_binary(trusted_root: Path) -> Path:
    path = Path(os.environ.get("SAFEYOLO_ASSURANCE_SEMGREP", trusted_root / "tools/acceptance/.venv/bin/semgrep"))
    if not path.is_file():
        raise AnalysisError(f"missing Semgrep executable: {path}")
    version = subprocess.run([str(path), "--version"], capture_output=True, text=True, check=False)
    if version.returncode or version.stdout.strip().splitlines()[-1:] != [SEMGREP_VERSION]:
        raise AnalysisError(f"Semgrep {SEMGREP_VERSION} required; got {version.stdout.strip()!r}")
    return path


def parse_source(trusted_root: Path, candidate_root: Path, paths: set[str]) -> dict:
    semgrep = semgrep_binary(trusted_root)
    scratch_parent = Path(os.environ.get("RUNNER_TEMP", Path.home() / ".cache"))
    scratch_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="safeyolo-assurance-", dir=scratch_parent) as tmp:
        stage = Path(tmp)
        for name in paths:
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate_root / name, destination)
        command = [
            str(semgrep), "scan", "--config", str(trusted_root / RULES),
            "--json", "--strict", "--disable-nosem", "--no-git-ignore",
            "--metrics=off", "--disable-version-check", "--max-target-bytes=10000000",
            "--timeout=120", "--jobs=1", ".",
        ]
        completed = subprocess.run(command, cwd=stage, capture_output=True, text=True, check=False)
        if completed.returncode:
            raise AnalysisError(f"Semgrep failed ({completed.returncode}): {completed.stderr[-1800:]}")
        try:
            scan = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise AnalysisError(f"Semgrep did not return JSON: {error}") from error
        if scan.get("errors"):
            raise AnalysisError(f"Semgrep reported {len(scan['errors'])} analysis errors: {scan['errors'][:2]}")
        scanned = {str(Path(name)) for name in scan.get("paths", {}).get("scanned", [])}
        if scanned != paths:
            raise AnalysisError(f"Semgrep scope mismatch: missing={sorted(paths - scanned)[:8]}, extra={sorted(scanned - paths)[:8]}")
        return scan


def mapped_function_bodies(
    sources: dict[str, bytes],
    functions: dict[str, list[tuple[int, int, str]]],
    implementations: dict[str, list[tuple[int, int, str]]],
) -> dict[str, list[str]]:
    mapped: dict[str, list[str]] = {}
    for name, spans in functions.items():
        for start, end, symbol in spans:
            body_digest = digest(sources[name][start:end])
            mapped.setdefault(f"{name}::{symbol}", []).append(body_digest)
            owners = [span for span in implementations[name] if span[0] <= start and end <= span[1]]
            if owners:
                owner = min(owners, key=lambda span: span[1] - span[0])[2]
                mapped.setdefault(f"{name}::{owner}::{symbol}", []).append(body_digest)
    return mapped


def extracted_source(root: Path, paths: set[str], scan: dict) -> tuple[dict, list[dict], int]:
    sources = {name: (root / name).read_bytes() for name in paths}
    functions: dict[str, list[tuple[int, int, str]]] = {name: [] for name in paths}
    implementations: dict[str, list[tuple[int, int, str]]] = {name: [] for name in paths}
    operations: list[dict] = []
    for finding in scan["results"]:
        name = finding["path"].removeprefix("./")
        if name not in sources:
            raise AnalysisError(f"finding outside source scope: {name}")
        start, end = finding["start"]["offset"], finding["end"]["offset"]
        if not 0 <= start < end <= len(sources[name]):
            raise AnalysisError(f"invalid source span: {name}:{start}-{end}")
        rule = finding["check_id"].rsplit(".", 1)[-1]
        body = sources[name][start:end]
        if rule in FUNCTION_RULES:
            match = NAME_RE.search(body.decode("utf-8"))
            if not match:
                raise AnalysisError(f"function name missing from AST span: {name}:{start}")
            functions[name].append((start, end, match.group(1)))
        elif rule == "rust-impl":
            match = IMPL_NAME_RE.match(body.decode("utf-8"))
            if match:
                implementations[name].append((start, end, match.group(1)))
        else:
            operations.append({"rule": rule, "path": name, "offset": start, "end": end,
                               "digest": digest(body), "text": body.decode("utf-8").strip()[:160]})
    mapped = mapped_function_bodies(sources, functions, implementations)
    for operation in operations:
        spans = [span for span in functions[operation["path"]]
                 if span[0] <= operation["offset"] < span[1]]
        operation["symbol"] = min(spans, key=lambda span: span[1] - span[0])[2] if spans else "<module>"
        del operation["offset"], operation["end"]
    operations.sort(key=lambda item: (item["rule"], item["path"], item["symbol"], item["digest"]))
    return mapped, operations, sum(map(len, functions.values()))


def analyze(trusted_root: Path, candidate_root: Path) -> dict:
    _, symbols = load_map(trusted_root)
    paths = source_paths(candidate_root)
    scan = parse_source(trusted_root, candidate_root, paths)
    functions, operations, count = extracted_source(candidate_root, paths, scan)
    return {
        "schema": SCHEMA,
        "checker_version": CHECKER_VERSION,
        "semgrep_version": SEMGREP_VERSION,
        "rules_sha256": digest((trusted_root / RULES).read_bytes()),
        "map_sha256": digest((trusted_root / MAP).read_bytes()),
        "checker_sha256": digest((trusted_root / "tools/assurance/check.py").read_bytes()),
        "workflow_sha256": digest((trusted_root / ".github/workflows/proxy-assurance.yml").read_bytes()),
        "codeowners_sha256": digest((trusted_root / ".github/CODEOWNERS").read_bytes()),
        "tool_lock_sha256": digest((trusted_root / "tools/acceptance/uv.lock").read_bytes()),
        "mapped_functions": {symbol: values[0] for symbol in sorted(symbols)
                             if len(values := functions.get(symbol, [])) == 1},
        "stale_symbols": sorted(symbol for symbol in symbols if len(functions.get(symbol, [])) != 1),
        "operations": operations,
        "function_count": count,
        "source_files": sorted(paths),
        "source_revision": git_revision(candidate_root),
        "inputs": file_hashes(candidate_root, input_paths(candidate_root)),
    }


def operation_key(item: dict) -> tuple[str, str, str, str]:
    return item["rule"], item["path"], item["symbol"], item["digest"]


def compare(accepted: dict, current: dict, controls: list[str]) -> dict:
    failures = []
    for key in ("schema", "checker_version", "semgrep_version", "rules_sha256", "map_sha256",
                "checker_sha256", "workflow_sha256", "codeowners_sha256", "tool_lock_sha256"):
        if accepted.get(key) != current[key]:
            failures.append(f"accepted {key} does not match the trusted checker")
    if accepted.get("stale_symbols"):
        failures.append("accepted snapshot contains stale symbols")
    old_ops = Counter(operation_key(item) for item in accepted["operations"])
    new_ops = Counter(operation_key(item) for item in current["operations"])
    old_items = {operation_key(item): item for item in accepted["operations"]}
    new_items = {operation_key(item): item for item in current["operations"]}
    removed_keys = list((old_ops - new_ops).elements())
    added_keys = list((new_ops - old_ops).elements())
    moved = []
    for old in removed_keys[:]:
        match = next((new for new in added_keys if (new[0], new[3]) == (old[0], old[3]) and new[1:3] != old[1:3]), None)
        if match is not None:
            moved.append({"from": old_items[old], "to": new_items[match]})
            removed_keys.remove(old)
            added_keys.remove(match)
    old_sources = set(accepted["source_files"])
    new_sources = set(current["source_files"])
    old_inputs = accepted["inputs"]
    new_inputs = current["inputs"]
    report = {
        "schema": SCHEMA,
        "status": "error" if failures else "drift",
        "accepted_revision": accepted.get("source_revision"),
        "candidate_revision": current.get("source_revision"),
        "errors": failures,
        "control_changes": controls,
        "mapped_decisions_changed": sorted(symbol for symbol in set(accepted["mapped_functions"]) | set(current["mapped_functions"])
                                             if accepted["mapped_functions"].get(symbol) != current["mapped_functions"].get(symbol)),
        "stale_symbols": current["stale_symbols"],
        "operations_added": [new_items[key] for key in added_keys],
        "operations_removed": [old_items[key] for key in removed_keys],
        "operations_moved": moved,
        "source_files_added": sorted(new_sources - old_sources),
        "source_files_removed": sorted(old_sources - new_sources),
        "function_count": {"accepted": accepted["function_count"], "candidate": current["function_count"]},
        "input_changes": sorted(name for name in set(old_inputs) | set(new_inputs) if old_inputs.get(name) != new_inputs.get(name)),
    }
    if not failures and not any(report[key] for key in report if key not in (
            "schema", "status", "accepted_revision", "candidate_revision", "errors", "function_count"
    )) and current["function_count"] >= accepted["function_count"]:
        report["status"] = "clean"
    return report


def changed_controls(trusted_root: Path, candidate_root: Path) -> list[str]:
    trusted = file_hashes(trusted_root, control_paths(trusted_root))
    candidate = file_hashes(candidate_root, control_paths(candidate_root))
    return sorted(name for name in trusted.keys() | candidate.keys() if trusted.get(name) != candidate.get(name))


def markdown(report: dict) -> str:
    lines = [f"# Proxy assurance drift: {report['status']}", "", "A finding needs review; it does not establish a vulnerability.", ""]
    if report.get("candidate_revision"):
        lines.extend([f"Candidate revision: `{report['candidate_revision']}`. Accepted source revision: `{report.get('accepted_revision') or 'unknown'}`.", ""])
    for title, key in (
        ("Analysis errors", "errors"), ("Proposed control changes", "control_changes"),
        ("Changed mapped decisions", "mapped_decisions_changed"), ("Stale mapped symbols", "stale_symbols"),
        ("Added operations", "operations_added"), ("Removed operations", "operations_removed"),
        ("Moved operations", "operations_moved"), ("Added source files", "source_files_added"),
        ("Removed source files", "source_files_removed"), ("Changed dependency or build inputs", "input_changes"),
    ):
        items = report.get(key, [])
        if not items:
            continue
        lines.extend([f"## {title} ({len(items)})", ""])
        for item in items[:30]:
            if key == "operations_moved":
                label = f"{item['from']['rule']} {item['from']['path']}::{item['from']['symbol']} → {item['to']['path']}::{item['to']['symbol']}"
            elif key.startswith("operations_"):
                label = f"{item['rule']} {item['path']}::{item['symbol']}: {item['text']}"
            else:
                label = str(item)
            lines.append(f"- {html.escape(' '.join(label.split()), quote=False).replace('`', '')}")
        if len(items) > 30:
            lines.append(f"- {len(items) - 30} more in the JSON report")
        lines.append("")
    counts = report.get("function_count")
    if counts and counts["candidate"] < counts["accepted"]:
        lines.extend(["## Reduced extraction scope", "", f"Parsed function count: {counts['accepted']} → {counts['candidate']}.", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "snapshot"))
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--trusted-root", type=Path, default=ROOT)
    parser.add_argument("--json", type=Path, required=True, help="machine-readable output path")
    parser.add_argument("--markdown", type=Path, help="human-readable output path for check")
    args = parser.parse_args()
    try:
        trusted = args.trusted_root.resolve(strict=True)
        candidate = args.candidate.resolve(strict=True)
        if args.command == "snapshot" and args.json.resolve() == (trusted / ACCEPTED).resolve():
            raise AnalysisError("write a proposed snapshot outside the accepted path; promote it only after review")
        current = analyze(trusted, candidate)
        if args.command == "snapshot":
            if current["stale_symbols"]:
                raise AnalysisError(f"cannot accept stale symbols: {current['stale_symbols']}")
            result = current
            status = 0
        else:
            accepted = json.loads((trusted / ACCEPTED).read_text(encoding="utf-8"))
            result = compare(accepted, current, changed_controls(trusted, candidate))
            status = 0 if result["status"] == "clean" else 1
    except (AnalysisError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        if args.command == "snapshot":
            print(f"proxy assurance: snapshot failed: {error}", file=sys.stderr)
            return 2
        result = {"schema": SCHEMA, "status": "error", "errors": [str(error)]}
        status = 2
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown(result), encoding="utf-8")
    print(f"proxy assurance: {result.get('status', 'snapshot')} ({args.json})")
    if status:
        for error in result.get("errors", []):
            print(error, file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
