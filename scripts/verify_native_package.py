#!/usr/bin/env python3
"""Verify the native proxy contents and import boundary of a built wheel.

This is intentionally a small post-build check.  It does not decide which
Python dependencies are retained or removed; it proves that the wheel being
examined carries the executable selected by the native default and that CLI
registration does not need the retained Python proxy runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED_MEMBERS = {
    "pdp/__init__.py": "retained Python policy package",
    "safeyolo/bin/safeyolo-proxy": "native proxy executable",
    "safeyolo/proxy.py": "retained CLI proxy facade",
    "safeyolo/rust_proxy.py": "native launch path",
}
BLOCKED_RUNTIME = ("mitmproxy", "safeyolo.mitm_addons", "safeyolo.traffic_master")


def _safe_member(name: str) -> None:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"wheel contains an unsafe member path: {name!r}")


def inspect_wheel(wheel: Path, *, expected_binary_sha256: str | None = None) -> dict:
    """Return the package facts needed by the post-cutover audit."""
    if wheel.suffix != ".whl" or not wheel.is_file():
        raise ValueError(f"wheel does not exist or is not a .whl file: {wheel}")

    with zipfile.ZipFile(wheel) as archive:
        members = {info.filename: info for info in archive.infolist()}
        for name in members:
            _safe_member(name)
        missing = sorted(set(REQUIRED_MEMBERS) - set(members))
        if missing:
            raise ValueError("wheel is missing required members: " + ", ".join(missing))

        binary_info = members["safeyolo/bin/safeyolo-proxy"]
        if binary_info.is_dir():
            raise ValueError("native proxy member is a directory")
        binary = archive.read(binary_info)
        if not binary:
            raise ValueError("native proxy member is empty")
        mode = (binary_info.external_attr >> 16) & 0o777
        if mode and not mode & 0o111:
            raise ValueError(f"native proxy member is not executable (mode {mode:o})")

        binary_sha256 = hashlib.sha256(binary).hexdigest()
        if expected_binary_sha256 and binary_sha256 != expected_binary_sha256:
            raise ValueError(
                "native proxy hash mismatch: "
                f"expected {expected_binary_sha256}, got {binary_sha256}"
            )

        dist_info = sorted(
            name for name in members if name.endswith(".dist-info/METADATA")
        )
        if not dist_info:
            raise ValueError("wheel has no dist-info/METADATA member")

        return {
            "wheel": str(wheel.resolve()),
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "members": len(members),
            "required_members": sorted(REQUIRED_MEMBERS),
            "native_binary": "safeyolo/bin/safeyolo-proxy",
            "native_binary_size": len(binary),
            "native_binary_sha256": binary_sha256,
            "native_binary_mode": f"{mode:04o}" if mode else "unspecified",
            "policy_package": "pdp/__init__.py",
            "dist_info_metadata": dist_info,
        }


def _run_import_probe(extracted: Path) -> dict:
    script = r'''
import importlib.abc
import json
import sys

blocked = ("mitmproxy", "safeyolo.mitm_addons", "safeyolo.traffic_master")

class BlockPythonProxyRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == name or fullname.startswith(name + ".") for name in blocked):
            raise AssertionError(f"native wheel import required retained Python runtime: {fullname}")
        return None

sys.meta_path.insert(0, BlockPythonProxyRuntime())
import safeyolo.cli  # noqa: E402
from safeyolo.proxy import selected_backend  # noqa: E402

assert selected_backend({"proxy": {}}) == "rust"
loaded = sorted(
    module for module in sys.modules
    if any(module == name or module.startswith(name + ".") for name in blocked)
)
assert not loaded, loaded
print(json.dumps({"backend": "rust", "blocked_runtime_modules": loaded}, sort_keys=True))
'''
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(extracted)
    environment["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=extracted,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"native wheel import probe failed: {detail}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("native wheel import probe returned non-JSON output") from exc
    if result != {"backend": "rust", "blocked_runtime_modules": []}:
        raise RuntimeError(f"unexpected native wheel import result: {result!r}")
    return result


def inspect_import_boundary(wheel: Path) -> dict:
    """Extract a wheel and prove native registration has no old-runtime import."""
    with tempfile.TemporaryDirectory(prefix="safeyolo-wheel-audit-") as temporary:
        extracted = Path(temporary)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(extracted)
        return _run_import_probe(extracted)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--expected-binary-sha256")
    args = parser.parse_args(argv)
    try:
        result = inspect_wheel(
            args.wheel,
            expected_binary_sha256=args.expected_binary_sha256,
        )
        result["import_probe"] = inspect_import_boundary(args.wheel)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
