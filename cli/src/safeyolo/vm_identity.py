"""Read the installed macOS VM helper's build and signing identity."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .vm import VMError, find_vm_helper


@dataclass(frozen=True)
class VMHelperIdentity:
    version: str
    helper_version: str
    git_sha: str
    build_profile: str
    architecture: str
    swift_compiler: str
    optimization: str
    symbols: str
    git_dirty: bool | None
    get_task_allow: bool | None
    hardened_runtime: bool | None

    @property
    def summary(self) -> str:
        debug = {True: "yes", False: "no", None: "unknown"}[self.get_task_allow]
        tree = {True: "dirty", False: "clean", None: "unknown"}[self.git_dirty]
        return (
            f"{self.build_profile}, helper={self.helper_version}, SafeYolo={self.version}, "
            f"git={self.git_sha}, tree={tree}, arch={self.architecture}, debuggable={debug}"
        )

    @property
    def warning(self) -> str:
        warnings = []
        if self.get_task_allow is True:
            warnings.append(
                "com.apple.security.get-task-allow is enabled: authorised local debuggers "
                "may inspect or modify VM-helper memory and execution"
            )
        if self.get_task_allow is None or self.hardened_runtime is None:
            warnings.append("the helper could not determine its running signing posture")
        elif not self.hardened_runtime:
            warnings.append("hardened runtime is disabled")
        if self.build_profile not in {"production", "development"} or self.git_sha == "unknown":
            warnings.append("source/build identity is incomplete; rebuild with make -C vm build")
        return "; ".join(warnings)


def read_vm_helper_identity(
    helper: Path | None = None, *, timeout: float = 3.0,
) -> VMHelperIdentity:
    """Query a helper with a deadline; old/malformed helpers remain unknown."""
    binary = helper or find_vm_helper()
    try:
        result = subprocess.run(
            [str(binary), "--version", "--json"], capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VMError(f"VM helper identity unavailable: {error}") from error
    if result.returncode or len(result.stdout) > 16 * 1024:
        raise VMError("VM helper identity unavailable; rebuild with make -C vm build")
    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VMError("VM helper does not provide JSON build identity; rebuild with make -C vm build") from error
    if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        raise VMError("VM helper returned an unsupported identity schema")
    strings = (
        "version", "helper_version", "git_sha", "build_profile", "architecture",
        "swift_compiler", "optimization", "symbols",
    )
    values = {}
    for field in strings:
        value = raw.get(field)
        if not isinstance(value, str) or not value or len(value) > 512 or not value.isprintable():
            raise VMError(f"VM helper returned an invalid identity field: {field}")
        values[field] = value
    for field in ("git_dirty", "get_task_allow", "hardened_runtime"):
        value = raw.get(field)
        if field not in raw or (value is not None and type(value) is not bool):
            raise VMError(f"VM helper returned an invalid signing/source state: {field}")
        values[field] = value
    return VMHelperIdentity(**values)
