"""Validate a selected black-box proxy backend and record its identity.

The runner invokes this module before a selected process is started.  It is
deliberately stdlib-only so a missing test environment cannot turn into a
different backend or a silently skipped run.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


class SelectionError(ValueError):
    """Raised when a requested backend cannot be identified or launched."""


def _path(value: str | os.PathLike[str], label: str) -> Path:
    candidate = Path(value).expanduser()
    try:
        return candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise SelectionError(f"{label} does not exist: {candidate}") from exc
    except OSError as exc:
        raise SelectionError(f"{label} cannot be inspected: {candidate}") from exc


def validate_python_source(value: str | os.PathLike[str]) -> Path:
    """Validate a Python checkout without importing its package."""
    source = _path(value, "Python source")
    package = source / "cli" / "src" / "safeyolo"
    if not package.is_dir() or not (package / "__init__.py").is_file():
        raise SelectionError(
            f"Python source must contain cli/src/safeyolo: {source}"
        )
    return source


def validate_rust_binary(value: str | os.PathLike[str]) -> tuple[Path, str]:
    """Validate an executable Rust proxy and obtain its own version string."""
    binary = _path(value, "Rust proxy executable")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SelectionError(f"Rust proxy executable is not executable: {binary}")
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SelectionError(f"Rust proxy version check failed: {binary}") from exc
    output = (result.stdout or result.stderr).strip()
    if result.returncode != 0 or not output:
        raise SelectionError(
            f"Rust proxy version check failed ({result.returncode}): {binary}"
        )
    if output.split(maxsplit=1)[0] != "safeyolo-proxy":
        raise SelectionError(
            f"Rust proxy executable has an unexpected identity: {binary}"
        )
    return binary, output[:256]


def _git_identity(source: Path) -> dict[str, object]:
    """Return revision and dirty state without requiring a GitPython install."""
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=source,
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=source,
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=10,
            ).strip()
        )
    except (OSError, subprocess.SubprocessError):
        revision = None
        dirty = None
    return {"revision": revision, "dirty": dirty}


def _python_identity(source: Path | None) -> dict[str, object]:
    package = None
    if source is None:
        spec = importlib.util.find_spec("safeyolo")
        if spec is not None:
            package = spec.origin or (
                str(next(iter(spec.submodule_search_locations), ""))
                if spec.submodule_search_locations
                else None
            )
    else:
        package = str(source / "cli" / "src" / "safeyolo")
    interpreter = Path(sys.executable).resolve()
    launcher = shutil.which("pytest")
    if launcher:
        try:
            first_line = Path(launcher).read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            first_line = ""
        if first_line.startswith("#!"):
            parts = first_line[2:].split()
            if parts and parts[0].endswith("env") and len(parts) > 1:
                candidate = shutil.which(parts[1])
            else:
                candidate = parts[0] if parts else None
            if candidate:
                interpreter = Path(candidate).resolve()
    try:
        version = subprocess.run(
            [str(interpreter), "-c", "import sys; print(sys.version)"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        version = sys.version
    return {
        "interpreter": str(interpreter),
        "interpreter_version": version or sys.version,
        "pytest_launcher": launcher,
        "package_location": package,
    }


def _nearest_git_root(path: Path) -> Path | None:
    """Find the checkout that owns a selected executable, when available."""
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def identity(
    backend: str,
    *,
    python_source: str | os.PathLike[str] | None = None,
    rust_bin: str | os.PathLike[str] | None = None,
    test_suite_root: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Validate and describe one selected backend without starting it."""
    if backend not in {"python", "rust"}:
        raise SelectionError(f"unsupported proxy backend: {backend}")
    source = validate_python_source(python_source) if python_source else None
    suite = (
        _path(test_suite_root, "test suite")
        if test_suite_root
        else Path(__file__).resolve().parents[2]
    )
    binary = version = None
    binary_source = None
    if backend == "rust":
        selected = rust_bin or os.environ.get("SAFEYOLO_RUST_PROXY")
        if not selected:
            selected = suite / "proxy/target/debug/safeyolo-proxy"
        binary, version = validate_rust_binary(selected)
        binary_source = _nearest_git_root(binary.parent)
    python_source_for_identity = source or suite
    result: dict[str, object] = {
        "schema": 1,
        "backend": backend,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": _python_identity(python_source_for_identity),
        "source": _git_identity(binary_source or source or suite),
        "test_suite": {
            "root": str(suite),
            **_git_identity(suite),
        },
    }
    if source:
        result["python_source"] = str(source)
    if binary:
        result["executable"] = str(binary)
        result["executable_version"] = version
        result["executable_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        if binary_source:
            result["executable_source_root"] = str(binary_source)
    return result


def _write_failure_evidence(output: Path, backend: str, error: str) -> None:
    """Leave an explicit artifact when a selected backend cannot be run."""
    result = {
        "schema": 1,
        "backend": backend,
        "status": "infrastructure_failure",
        "error": error,
        "platform": platform.platform(),
        "machine": platform.machine(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("python", "rust"), required=True)
    parser.add_argument("--python-source")
    parser.add_argument("--rust-bin")
    parser.add_argument("--test-suite-root")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = identity(
            args.backend,
            python_source=args.python_source,
            rust_bin=args.rust_bin,
            test_suite_root=args.test_suite_root,
        )
    except SelectionError as exc:
        try:
            _write_failure_evidence(args.output, args.backend, str(exc))
        except OSError as write_error:
            print(
                f"ERROR: {exc} (unable to record infrastructure evidence: {write_error})",
                file=sys.stderr,
            )
        else:
            print(
                f"ERROR: {exc}; infrastructure evidence: {args.output}",
                file=sys.stderr,
            )
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"backend": args.backend, "evidence": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
