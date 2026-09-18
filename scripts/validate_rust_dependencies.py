#!/usr/bin/env python3
"""Run focused validation for SafeYolo's locally patched Rust dependencies.

The proxy's locked product resolution and each vendored package's own
resolution are reported separately.  A package test command is successful only
when it executes at least one test and reports no failed tests.  The controlled
missing-oracle run proves that a selected regression cannot silently pass when
its required Python oracle is unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = ROOT / "proxy" / "vendor"
CRATES = {
    "fancy-regex": {"version": "0.19.2"},
    "hyper": {"version": "1.11.1"},
    "h2": {"version": "0.4.19"},
}
LICENSE_SHA256 = {
    "fancy-regex": "3bc70e239e91272782006c638fc0452a714d384224f11f0923036b7be07cf9b5",
    "hyper": "2d01890414494742ba4a509fcec8efa40f6d8be22cbd72be7cff08d6fda4ec89",
    "h2": "b21623012e6c453d944b0342c515b631cfcbf30704c2621b291526b69c10724d",
}
FANCY_PYTHON_TEST = "every_valid_scalar_lowercase_matches_actual_python_312"
TEST_RESULT_RE = re.compile(
    r"test result: (?P<status>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out;"
)
RUNNING_RE = re.compile(r"running (?P<count>\d+) tests?\b")
# The wrapper's interrupt-to-kill grace is five seconds; allow ten here so its
# trap can finish the group reap before the validator escalates its own group.
VALIDATOR_TERM_GRACE_SECONDS = 10
# The order is meaningful: a vendored/current hash supersedes an intermediate
# post-patch hash when a checkpoint records more than one value.
HASH_KEYS = ("vendored_sha256", "after_sha256", "candidate_sha256")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LICENSE_RE = re.compile(r"^license\s*=\s*\"([^\"]+)\"\s*$", re.MULTILINE)

FANCY_DEFAULT_FEATURES = {"unicode", "perf", "std", "variable-lookbehinds"}
PRODUCT_FEATURES = {
    "fancy-regex": FANCY_DEFAULT_FEATURES,
    "hyper": {"client", "server", "http1", "http2"},
    "h2": set(),
}
STANDALONE_FEATURES = {
    "fancy-regex": FANCY_DEFAULT_FEATURES,
    "hyper": {"client", "http2"},
}


class ValidationError(RuntimeError):
    """A required validation step or provenance check failed."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cargo_license(path: Path) -> str | None:
    """Read the package license without adding a TOML parser dependency."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = LICENSE_RE.search(text)
    return match.group(1) if match else None


def _git_value(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _git_branch() -> str:
    result = subprocess.run(
        ["git", "symbolic-ref", "--short", "-q", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "(detached)"


def _rust_host() -> str:
    output = subprocess.run(
        ["rustc", "-vV"], check=True, capture_output=True, text=True
    ).stdout
    for line in output.splitlines():
        if line.startswith("host:"):
            return line.partition(":")[2].strip()
    raise ValidationError("rustc -vV did not report a host target")


def _parse_test_counts(output: str) -> dict[str, int]:
    summaries = list(TEST_RESULT_RE.finditer(output))
    running = sum(int(match.group("count")) for match in RUNNING_RE.finditer(output))
    return {
        "suites": len(summaries),
        "started": running,
        "passed": sum(int(match.group("passed")) for match in summaries),
        "failed": sum(int(match.group("failed")) for match in summaries),
        "ignored": sum(int(match.group("ignored")) for match in summaries),
        "measured": sum(int(match.group("measured")) for match in summaries),
        "filtered": sum(int(match.group("filtered")) for match in summaries),
    }


def _command_text(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _stop_process_group(process: subprocess.Popen[str], signal_number: int) -> None:
    """Stop a timed-out command and its descendants where POSIX permits it."""
    if hasattr(os, "killpg"):
        try:
            os.killpg(process.pid, signal_number)
            return
        except ProcessLookupError:
            return
    process.send_signal(signal_number)


class Runner:
    """Execute commands and retain concise machine-readable evidence."""

    def __init__(
        self,
        report: dict[str, Any],
        *,
        offline: bool,
        report_path: Path,
        target_dir: Path,
    ):
        self.report = report
        self.offline = offline
        self.report_path = report_path
        self.target_dir = target_dir
        self.command_index = 0

    def _environment(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CARGO_PROFILE_DEV_DEBUG": "0",
                "CARGO_PROFILE_TEST_DEBUG": "0",
                "CARGO_INCREMENTAL": "0",
                "CARGO_TARGET_DIR": str(self.target_dir),
            }
        )
        if extra:
            for key, value in extra.items():
                if value == "__UNSET__":
                    environment.pop(key, None)
                else:
                    environment[key] = value
        return environment

    def command(
        self,
        name: str,
        command: list[str],
        *,
        kind: str,
        environment: dict[str, str] | None = None,
        expect_failure: bool = False,
        require_tests: bool = False,
        timeout: int = 900,
        print_output: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, int]]:
        display_environment = {
            "CARGO_PROFILE_DEV_DEBUG": "0",
            "CARGO_PROFILE_TEST_DEBUG": "0",
            "CARGO_INCREMENTAL": "0",
            "CARGO_TARGET_DIR": str(self.target_dir),
        }
        display_environment.update(environment or {})
        display = dict(display_environment)
        for key, value in display.items():
            if value == "__UNSET__":
                display[key] = "<unset>"

        full_environment = self._environment(environment)
        guarded_command = command
        if command and command[0] == "cargo":
            guarded_command = [
                str(ROOT / "scripts" / "cargo_with_space.sh"), *command[1:]
            ]
        print(f"\n[{name}] ")
        print(f"$ {_command_text(guarded_command)}")
        started = time.monotonic()
        timed_out = False
        process = subprocess.Popen(
            guarded_command,
            cwd=ROOT,
            env=full_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            result = subprocess.CompletedProcess(
                guarded_command, process.returncode, stdout, stderr
            )
        except subprocess.TimeoutExpired as error:
            timed_out = True
            _stop_process_group(process, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(
                    timeout=VALIDATOR_TERM_GRACE_SECONDS
                )
            except subprocess.TimeoutExpired:
                _stop_process_group(process, signal.SIGKILL)
                stdout, stderr = process.communicate()
            stdout = stdout or error.stdout or ""
            stderr = stderr or error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            result = subprocess.CompletedProcess(guarded_command, 124, stdout, stderr)
        elapsed = time.monotonic() - started
        output = (result.stdout or "") + (result.stderr or "")
        if print_output:
            print(output, end="")
        counts = _parse_test_counts(output)
        entry: dict[str, Any] = {
            "index": self.command_index,
            "name": name,
            "kind": kind,
            "command": _command_text(guarded_command),
            "cwd": str(ROOT),
            "environment": display,
            "exit_code": result.returncode,
            "elapsed_seconds": round(elapsed, 3),
            "output_bytes": len(output.encode()),
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "output_tail": output[-8192:],
        }
        if guarded_command != command:
            entry["requested_command"] = _command_text(command)
        if counts["suites"]:
            entry["tests"] = counts
        if timed_out:
            entry["timed_out"] = True
        self.report["commands"].append(entry)
        self.command_index += 1

        succeeded = result.returncode == 0
        if expect_failure:
            if succeeded:
                raise ValidationError(
                    f"{name}: controlled failure unexpectedly exited zero"
                )
        elif not succeeded:
            raise ValidationError(
                f"{name}: command exited {result.returncode}; see report {self.report_path}"
            )
        if require_tests:
            if counts["started"] <= 0 or counts["suites"] <= 0:
                raise ValidationError(
                    f"{name}: no tests were collected; this is not a passing validation"
                )
            if not expect_failure and (counts["failed"] or counts["passed"] <= 0):
                raise ValidationError(
                    f"{name}: test summary is not a clean pass: {counts}"
                )
            if expect_failure and counts["failed"] <= 0:
                raise ValidationError(
                    f"{name}: expected failure did not report a failed selected test"
                )
        return result, counts

    def cargo(
        self,
        name: str,
        args: list[str],
        *,
        kind: str,
        environment: dict[str, str] | None = None,
        expect_failure: bool = False,
        require_tests: bool = False,
        locked: bool = False,
        timeout: int = 900,
        print_output: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, int]]:
        command = ["cargo", *args]
        if locked:
            command.insert(1, "--locked")
        if self.offline:
            command.insert(1, "--offline")
        return self.command(
            name,
            command,
            kind=kind,
            environment=environment,
            expect_failure=expect_failure,
            require_tests=require_tests,
            timeout=timeout,
            print_output=print_output,
        )


def _normalise_vendor_path(name: str, version: str, path: str) -> str:
    for prefix in (f"proxy/vendor/{name}/", f"{name}-{version}/"):
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def _safe_vendor_path(directory: Path, relative: str) -> bool:
    """Keep metadata checkpoints confined to their package directory."""
    if not relative or Path(relative).is_absolute():
        return False
    try:
        (directory / relative).resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _record_checkpoint(
    name: str,
    directory: Path,
    relative: Any,
    detail: Any,
    context: str,
    current_expected: dict[str, str],
    failures: list[str],
) -> bool:
    if not isinstance(relative, str) or not relative:
        failures.append(f"{name}: {context} has no file path")
        return False
    if not _safe_vendor_path(directory, relative):
        failures.append(
            f"{name}: {context} escapes the vendor directory: {relative!r}"
        )
        return False
    if not isinstance(detail, dict):
        failures.append(f"{name}: {context} must be an object")
        return False
    present = [key for key in HASH_KEYS if key in detail]
    if not present:
        failures.append(f"{name}: {context} has no cumulative hash")
        return False
    expected_hash: str | None = None
    for key in HASH_KEYS:
        if key not in detail:
            continue
        expected = detail[key]
        if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
            failures.append(f"{name}: {context} has invalid {key}")
            continue
        if expected_hash is None:
            expected_hash = expected
    if expected_hash is None:
        return False
    current_expected[relative] = expected_hash
    return True


def _collect_checkpoints(
    name: str,
    version: str,
    directory: Path,
    value: Any,
    current_expected: dict[str, str],
    failures: list[str],
    context: str,
) -> int:
    checkpoints = 0
    if isinstance(value, dict):
        path_value = value.get("path")
        if isinstance(path_value, str):
            relative = _normalise_vendor_path(name, version, path_value)
            checkpoints += _record_checkpoint(
                name,
                directory,
                relative,
                value,
                f"{context} path {path_value!r}",
                current_expected,
                failures,
            )
        for key, child in value.items():
            checkpoints += _collect_checkpoints(
                name,
                version,
                directory,
                child,
                current_expected,
                failures,
                f"{context}.{key}",
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            checkpoints += _collect_checkpoints(
                name,
                version,
                directory,
                child,
                current_expected,
                failures,
                f"{context}[{index}]",
            )
    return checkpoints


def _provenance(report: dict[str, Any]) -> None:
    """Verify current source hashes against cumulative UPSTREAM checkpoints."""
    provenance: dict[str, Any] = {}
    failures: list[str] = []
    for name, spec in CRATES.items():
        directory = VENDOR_ROOT / name
        upstream_path = directory / "UPSTREAM.json"
        try:
            metadata = json.loads(upstream_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            failures.append(f"{name}: cannot read UPSTREAM.json: {error}")
            continue
        if not isinstance(metadata, dict):
            failures.append(f"{name}: UPSTREAM.json must contain an object")
            continue
        if metadata.get("version") != spec["version"]:
            failures.append(
                f"{name}: UPSTREAM version {metadata.get('version')!r} "
                f"does not match {spec['version']}"
            )
        recorded_source = metadata.get("source") or metadata.get("repository")
        recorded_archive = metadata.get("archive_sha256") or metadata.get(
            "crates_io_package_sha256"
        )
        if not isinstance(recorded_source, str) or not recorded_source:
            failures.append(f"{name}: UPSTREAM source is missing")
        if not isinstance(recorded_archive, str) or not SHA256_RE.fullmatch(
            recorded_archive
        ):
            failures.append(f"{name}: UPSTREAM archive checksum is missing or invalid")
        if name != "fancy-regex":
            patch_source = metadata.get("patch_source_sha256")
            if not isinstance(patch_source, str) or not SHA256_RE.fullmatch(
                patch_source
            ):
                failures.append(
                    f"{name}: UPSTREAM patch source checksum is missing or invalid"
                )
        if not (directory / "LICENSE").is_file():
            failures.append(f"{name}: retained LICENSE is missing")
        license_path = directory / "LICENSE"
        license_actual = _sha256(license_path) if license_path.is_file() else "MISSING"
        license_expected = LICENSE_SHA256[name]
        if license_actual != license_expected:
            failures.append(
                f"{name}: LICENSE hash {license_actual} != expected {license_expected}"
            )
        recorded_license = metadata.get("license") or metadata.get("vendored_license")
        if not isinstance(recorded_license, str) or not recorded_license:
            failures.append(f"{name}: UPSTREAM license is missing")
        recorded_license_hash = metadata.get("license_sha256")
        if recorded_license_hash != license_expected:
            failures.append(
                f"{name}: UPSTREAM license checksum {recorded_license_hash!r} "
                f"!= expected {license_expected}"
            )

        current_expected: dict[str, str] = {}
        checkpoints = 0
        if name == "fancy-regex":
            file_map = metadata.get("files", {})
            if not isinstance(file_map, dict):
                failures.append(f"{name}: UPSTREAM files must be an object")
            else:
                for relative, detail in file_map.items():
                    if not isinstance(detail, dict):
                        failures.append(
                            f"{name}: UPSTREAM files entry {relative!r} must be an "
                            "object"
                        )
                        continue
                    checkpoints += _record_checkpoint(
                        name,
                        directory,
                        relative,
                        detail,
                        f"files[{relative!r}]",
                        current_expected,
                        failures,
                    )
            components = metadata.get("additional_components", [])
            if not isinstance(components, list):
                failures.append(f"{name}: additional_components must be an array")
                components = []
            for component in components:
                if not isinstance(component, dict):
                    continue
                source_metadata = component.get("source_metadata")
                source_license = component.get("source_license")
                expected_metadata = component.get("vendored_sha256")
                if source_metadata and not isinstance(source_metadata, str):
                    failures.append(
                        f"{name}: additional component metadata path must be a string"
                    )
                if source_metadata and isinstance(expected_metadata, str):
                    if not _safe_vendor_path(directory, source_metadata):
                        failures.append(
                            f"{name}: additional component metadata escapes the vendor "
                            f"directory: {source_metadata!r}"
                        )
                        continue
                    path = directory / source_metadata
                    actual = _sha256(path) if path.is_file() else "MISSING"
                    if actual != expected_metadata:
                        failures.append(
                            f"{name}: {source_metadata} hash {actual} != "
                            f"{expected_metadata}"
                        )
                if source_license:
                    if not isinstance(source_license, str):
                        failures.append(
                            f"{name}: additional component license path must be "
                            "a string"
                        )
                        continue
                    expected_license = component.get("source_license_sha256")
                    if not _safe_vendor_path(directory, source_license):
                        failures.append(
                            f"{name}: additional component license escapes the vendor "
                            f"directory: {source_license!r}"
                        )
                        continue
                    path = directory / source_license
                    actual = _sha256(path) if path.is_file() else "MISSING"
                    if not isinstance(expected_license, str) or not SHA256_RE.fullmatch(
                        expected_license
                    ):
                        failures.append(
                            f"{name}: {source_license} has missing or invalid "
                            "license checksum"
                        )
                    elif actual != expected_license:
                        failures.append(
                            f"{name}: {source_license} hash {actual} != "
                            f"{expected_license}"
                        )
            if not (directory / "PATCH.diff").is_file():
                failures.append(f"{name}: PATCH.diff is missing")
        else:
            checkpoints += _collect_checkpoints(
                name,
                spec["version"],
                directory,
                metadata.get("files", []),
                current_expected,
                failures,
                "files",
            )
            for key, value in metadata.items():
                if key != "files":
                    checkpoints += _collect_checkpoints(
                        name,
                        spec["version"],
                        directory,
                        value,
                        current_expected,
                        failures,
                        key,
                    )

        if checkpoints == 0:
            failures.append(
                f"{name}: UPSTREAM contains no usable source hash checkpoints"
            )

        mismatches: list[dict[str, str]] = []
        for relative, expected in sorted(current_expected.items()):
            path = directory / relative
            actual = _sha256(path) if path.is_file() else "MISSING"
            if actual != expected:
                mismatches.append(
                    {"path": relative, "expected": expected, "actual": actual}
                )
                failures.append(
                    f"{name}: {relative} hash {actual} != cumulative {expected}"
                )
        if name == "fancy-regex":
            lowercase = directory / "PYTHON_LOWERCASE.json"
            license_path = directory / "LICENSE-CPYTHON"
            if not lowercase.is_file() or not license_path.is_file():
                failures.append(
                    f"{name}: generated lowercase data or its license is missing"
                )
        provenance[name] = {
            "upstream_json_sha256": _sha256(upstream_path),
            "version": metadata.get("version"),
            "license": metadata.get("license")
            or metadata.get("vendored_license")
            or _cargo_license(directory / "Cargo.toml"),
            "retained_license_file": "LICENSE"
            if (directory / "LICENSE").is_file()
            else None,
            "recorded_source": recorded_source,
            "recorded_archive_or_crates_io_sha256": recorded_archive,
            "recorded_patch_source_sha256": metadata.get("patch_source_sha256"),
            "recorded_upstream_commit": metadata.get("git_commit"),
            "license_sha256": license_actual,
            "expected_license_sha256": license_expected,
            "hash_checkpoints": checkpoints,
            "current_hashes_checked": len(current_expected),
            "current_hash_mismatches": mismatches,
        }
        if name == "fancy-regex":
            provenance[name]["generated_components"] = {
                "PYTHON_LOWERCASE.json": {
                    "sha256": _sha256(directory / "PYTHON_LOWERCASE.json"),
                    "license_file": "LICENSE-CPYTHON",
                    "license_sha256": _sha256(directory / "LICENSE-CPYTHON"),
                }
            }
    report["provenance"] = provenance
    if failures:
        raise ValidationError("provenance checks failed: " + "; ".join(failures))


def _metadata_summary(
    raw: dict[str, Any], names: set[str], *, manifest: Path
) -> dict[str, Any]:
    package_by_id = {
        package.get("id"): package
        for package in raw.get("packages", [])
        if isinstance(package, dict) and isinstance(package.get("id"), str)
    }

    def dependency_id(value: Any) -> str | None:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            package_id = value.get("pkg") or value.get("id")
            return package_id if isinstance(package_id, str) else None
        return None

    resolve = raw.get("resolve") or {}
    nodes = {
        node.get("id"): node
        for node in resolve.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    root_ids = []
    root_id = resolve.get("root")
    if isinstance(root_id, str) and root_id in package_by_id:
        root_ids.append(root_id)
    else:
        root_ids.extend(
            member
            for member in resolve.get("workspace_members", [])
            if isinstance(member, str) and member in package_by_id
        )

    # Cargo's resolve graph identifies the package actually used by each root
    # dependency.  Selecting the last package with a matching name is unsafe
    # when a registry copy and a path-patched copy coexist in metadata.
    selected_by_name: dict[str, list[str]] = {name: [] for name in names}
    for current_root in root_ids:
        root_package = package_by_id.get(current_root, {})
        root_name = root_package.get("name")
        if root_name in selected_by_name:
            selected_by_name[root_name].append(current_root)
        node = nodes.get(current_root, {})
        dependency_ids: list[str] = []
        for dependency in node.get("deps", []):
            package_id = dependency_id(dependency)
            if package_id:
                dependency_ids.append(package_id)
        for dependency in node.get("dependencies", []):
            package_id = dependency_id(dependency)
            if package_id:
                dependency_ids.append(package_id)
        for package_id in dependency_ids:
            package = package_by_id.get(package_id, {})
            package_name = package.get("name")
            if package_name in selected_by_name:
                selected_by_name[package_name].append(package_id)

    # Keep summaries useful for older Cargo metadata fixtures that omit the
    # resolve root or dependency edges, while making ambiguity visible to the
    # product-resolution check below.
    if not root_ids:
        for package_id, package in package_by_id.items():
            package_name = package.get("name")
            if package_name in selected_by_name:
                selected_by_name[package_name].append(package_id)
    selected_by_name = {
        name: list(dict.fromkeys(package_ids))
        for name, package_ids in selected_by_name.items()
    }

    packages: list[dict[str, Any]] = []
    for package in raw.get("packages", []):
        if package.get("name") not in names:
            continue
        package_id = package.get("id", "")
        packages.append(
            {
                "id": package_id,
                "name": package.get("name"),
                "version": package.get("version"),
                "source": package.get("source"),
                "manifest_path": package.get("manifest_path"),
                "selected": package_id in selected_by_name.get(package.get("name"), []),
                "targets": [
                    {
                        "name": target.get("name"),
                        "kind": target.get("kind", []),
                    }
                    for target in package.get("targets", [])
                ],
            }
        )
    features: dict[str, list[str]] = {}
    resolved_package_features: dict[str, list[dict[str, Any]]] = {}
    for name, package_ids in selected_by_name.items():
        records: list[dict[str, Any]] = []
        for package_id in package_ids:
            node = nodes.get(package_id)
            if node is None:
                continue
            package_features = sorted(
                feature
                for feature in node.get("features", [])
                if isinstance(feature, str)
            )
            records.append({"id": package_id, "features": package_features})
        if records:
            resolved_package_features[name] = records
            features[name] = sorted(
                {feature for record in records for feature in record["features"]}
            )
    lock_path = manifest.parent / "Cargo.lock"
    return {
        "manifest": str(manifest),
        "lock_sha256": _sha256(lock_path) if lock_path.is_file() else None,
        "packages": packages,
        "selected_package_ids": selected_by_name,
        "enabled_features": features,
        "resolved_features": features,
        "resolved_package_features": resolved_package_features,
    }


def _read_metadata(
    runner: Runner,
    name: str,
    manifest: Path,
    *,
    locked: bool,
    no_deps: bool = False,
    no_default_features: bool = False,
    features: str | None = None,
    filter_platform: str | None = None,
) -> dict[str, Any]:
    metadata_args = [
        "metadata",
        "--format-version=1",
        "--manifest-path",
        str(manifest.relative_to(ROOT)),
    ]
    if no_deps:
        metadata_args.append("--no-deps")
    if no_default_features:
        metadata_args.append("--no-default-features")
    if features:
        metadata_args.extend(["--features", features])
    if filter_platform:
        metadata_args.extend(["--filter-platform", filter_platform])
    result, _ = runner.cargo(
        f"{name}-metadata",
        metadata_args,
        kind="metadata",
        locked=locked,
        print_output=False,
    )
    return json.loads(result.stdout)


def _validate_product_resolution(
    report: dict[str, Any], metadata: dict[str, Any]
) -> None:
    packages_by_id = {
        package.get("id"): package
        for package in metadata.get("packages", [])
        if isinstance(package, dict) and isinstance(package.get("id"), str)
    }
    failures: list[str] = []
    for name, spec in CRATES.items():
        selected_map = metadata.get("selected_package_ids")
        if isinstance(selected_map, dict):
            selected_ids = selected_map.get(name, [])
        else:
            selected_ids = [
                package.get("id")
                for package in metadata.get("packages", [])
                if package.get("name") == name and isinstance(package.get("id"), str)
            ]
        if not isinstance(selected_ids, list):
            selected_ids = [selected_ids]
        if len(selected_ids) != 1:
            failures.append(
                f"product did not resolve exactly one direct {name} package: "
                f"{selected_ids!r}"
            )
            continue
        package = packages_by_id.get(selected_ids[0])
        expected_manifest = (VENDOR_ROOT / name / "Cargo.toml").resolve()
        if package is None:
            failures.append(
                f"product metadata omitted selected {name} package "
                f"{selected_ids[0]!r}"
            )
            continue
        if package.get("version") != spec["version"]:
            failures.append(
                f"product selected {name} {package.get('version')} instead of "
                f"{spec['version']}"
            )
        if package.get("source") is not None:
            failures.append(
                f"product selected registry {name}; local patch is not active"
            )
        if Path(package.get("manifest_path", "")).resolve() != expected_manifest:
            failures.append(
                f"product selected {name} manifest {package.get('manifest_path')} "
                f"instead of {expected_manifest}"
            )
    report["product_resolution"] = metadata
    if failures:
        raise ValidationError(
            "product resolution checks failed: " + "; ".join(failures)
        )


def _validate_feature_resolution(
    summary: dict[str, Any],
    expected: dict[str, set[str]],
    *,
    scope: str,
    forbidden: dict[str, set[str]] | None = None,
    exact: bool = False,
) -> None:
    """Check enabled features, including forbidden features for isolated lanes."""
    resolved = summary.get("resolved_features", {})
    forbidden = forbidden or {}
    failures: list[str] = []
    for name, required in expected.items():
        actual = resolved.get(name)
        if not isinstance(actual, list):
            failures.append(f"{scope}: resolved features omitted {name}")
            continue
        actual_set = set(actual)
        missing = sorted(required - actual_set)
        unexpected = sorted(actual_set - required) if exact else []
        forbidden_enabled = sorted(actual_set & forbidden.get(name, set()))
        if unexpected:
            failures.append(
                f"{scope}: {name} has unexpected resolved features {unexpected}; "
                f"expected exactly {sorted(required)}"
            )
        if forbidden_enabled:
            failures.append(
                f"{scope}: {name} has forbidden resolved features "
                f"{forbidden_enabled}; actual={sorted(actual_set)}"
            )
        if missing:
            failures.append(
                f"{scope}: {name} is missing resolved features {missing}; "
                f"actual={sorted(actual)}"
            )
    if failures:
        raise ValidationError(
            "feature resolution checks failed: " + "; ".join(failures)
        )


def _cargo_test_args(
    manifest: Path,
    *,
    target: str | None = None,
    features: str | None = None,
    no_default_features: bool = False,
    lib: bool = False,
    extra: list[str] | None = None,
) -> list[str]:
    args = ["test", "--manifest-path", str(manifest.relative_to(ROOT))]
    if no_default_features:
        args.append("--no-default-features")
    if features:
        args.extend(["--features", features])
    if lib:
        args.append("--lib")
    if target:
        args.extend(["--test", target])
    if extra:
        args.extend(extra)
    return args


def _cargo_check_args(
    manifest: Path,
    *,
    features: str | None = None,
    no_default_features: bool = False,
    all_targets: bool = False,
) -> list[str]:
    args = ["check", "--manifest-path", str(manifest.relative_to(ROOT))]
    if no_default_features:
        args.append("--no-default-features")
    if features:
        args.extend(["--features", features])
    if all_targets:
        args.append("--all-targets")
    return args


def _cargo_build_args(manifest: Path, *, all_targets: bool = False) -> list[str]:
    args = ["build", "--manifest-path", str(manifest.relative_to(ROOT))]
    if all_targets:
        args.append("--all-targets")
    return args


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        type=Path,
        help="write JSON evidence here (default: a file outside the checkout)",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="allow Cargo to resolve/download missing packages; offline is the default",
    )
    options = parser.parse_args(argv)
    if options.report is None:
        handle, temporary_report = tempfile.mkstemp(
            prefix="safeyolo-rust-dependency-validation-", suffix=".json"
        )
        os.close(handle)
        report_path = Path(temporary_report)
    else:
        report_path = options.report.expanduser().resolve()
    offline = not options.online
    report: dict[str, Any] = {
        "schema": 1,
        "status": "running",
        "repository": {},
        "mode": "offline" if offline else "online",
        "commands": [],
        "limitations": [
            "This lane validates selected local regressions and product integration; it does not claim whole-library conformance.",
            "The vendored h2 package excludes its upstream fixture corpus; that inherited fixture suite is not run here.",
            "The Hyper client/http2 inherited unit suite is not a patch regression target; the independent feature build and product parser tests are selected instead.",
            "Ignored product inspection oracles that import checkout Python dependencies are reported as unexecuted; run them separately when that environment is available.",
            "This command does not start a proxy or claim Linux/macOS black-box acceptance; those scopes belong to shared #621 acceptance.",
        ],
    }
    target_context = None
    try:
        rust_host = _rust_host()
        report["repository"] = {
            "revision": _git_value("rev-parse", "HEAD"),
            "branch": _git_branch(),
            "rust_host": rust_host,
            "rustc": subprocess.run(
                ["rustc", "--version"], check=True, capture_output=True, text=True
            ).stdout.strip(),
            "cargo": subprocess.run(
                ["cargo", "--version"], check=True, capture_output=True, text=True
            ).stdout.strip(),
        }
        print("SafeYolo Rust dependency validation")
        print(json.dumps(report["repository"], sort_keys=True))
        print(f"mode={report['mode']}")
        print(f"report={report_path}")
        _provenance(report)
        target_context = tempfile.TemporaryDirectory(
            prefix="safeyolo-rust-dependency-target-"
        )
        runner = Runner(
            report,
            offline=offline,
            report_path=report_path,
            target_dir=Path(target_context.name),
        )

        product_manifest = ROOT / "proxy" / "Cargo.toml"
        product_raw = _read_metadata(
            runner, "product", product_manifest, locked=True
        )
        product = _metadata_summary(
            product_raw,
            {"fancy-regex", "hyper", "h2", "safeyolo-proxy"},
            manifest=product_manifest,
        )
        _validate_product_resolution(report, product)
        _validate_feature_resolution(product, PRODUCT_FEATURES, scope="product")

        standalone: dict[str, Any] = {}
        standalone_specs = {
            "fancy-regex": (None, False),
            "hyper": ("client,http2", True),
        }
        for name, (features, no_default_features) in standalone_specs.items():
            manifest = VENDOR_ROOT / name / "Cargo.toml"
            raw = _read_metadata(
                runner,
                name,
                manifest,
                locked=True,
                features=features or "default",
                no_default_features=no_default_features,
                filter_platform=rust_host,
            )
            summary = _metadata_summary(raw, {name}, manifest=manifest)
            summary["requested_features"] = (
                features.split(",") if features else ["default"]
            )
            summary["no_default_features"] = no_default_features
            _validate_feature_resolution(
                summary,
                {name: STANDALONE_FEATURES[name]},
                scope=f"standalone {name}",
                forbidden={"hyper": {"http1"}}
                if name == "hyper"
                else None,
            )
            standalone[name] = summary

        h2 = VENDOR_ROOT / "h2" / "Cargo.toml"
        h2_feature_resolutions: dict[str, Any] = {}
        for resolution_name, features, no_default_features, expected_features, forbidden_features in (
            ("none", None, True, set(), {"stream", "unstable"}),
            ("stream", "stream", False, {"stream"}, {"unstable"}),
            ("unstable", "unstable", False, {"unstable"}, {"stream"}),
            ("all", "stream,unstable", False, {"stream", "unstable"}, set()),
        ):
            raw = _read_metadata(
                runner,
                "h2-" + resolution_name,
                h2,
                locked=True,
                features=features,
                no_default_features=no_default_features,
                filter_platform=rust_host,
            )
            summary = _metadata_summary(raw, {"h2"}, manifest=h2)
            summary["requested_features"] = (
                features.split(",") if features else []
            )
            summary["no_default_features"] = no_default_features
            _validate_feature_resolution(
                summary,
                {"h2": expected_features},
                scope=f"standalone h2 {resolution_name}",
                forbidden={"h2": forbidden_features},
                exact=True,
            )
            h2_feature_resolutions[resolution_name] = summary
        standalone["h2"] = {"feature_resolutions": h2_feature_resolutions}
        report["standalone_resolution"] = standalone

        fancy = VENDOR_ROOT / "fancy-regex" / "Cargo.toml"
        hyper = VENDOR_ROOT / "hyper" / "Cargo.toml"
        product_python = os.environ.get("SAFEYOLO_POLICY_PYTHON") or shutil.which("python3")
        if not product_python:
            raise ValidationError(
                "CPython 3.12 is required for the actual fancy-regex Python oracle; set SAFEYOLO_POLICY_PYTHON"
            )
        python_path = str(Path(product_python).expanduser().resolve())
        if not Path(python_path).is_file() or not os.access(python_path, os.X_OK):
            raise ValidationError(f"SAFEYOLO_POLICY_PYTHON is not executable: {python_path}")

        common_env = {"SAFEYOLO_POLICY_PYTHON": python_path}
        runner.cargo(
            "fancy-regex-inherited-unit-tests",
            _cargo_test_args(fancy, lib=True, extra=["--", "--test-threads=1"]),
            kind="inherited-upstream-tests",
            environment=common_env,
            require_tests=True,
            locked=True,
        )
        runner.cargo(
            "fancy-regex-runtime-allocation",
            _cargo_test_args(
                fancy,
                target="runtime_allocation",
                extra=["--", "--test-threads=1", "--nocapture"],
            ),
            kind="patch-regression",
            environment=common_env,
            require_tests=True,
            locked=True,
        )
        runner.cargo(
            "fancy-regex-runtime-cancellation",
            _cargo_test_args(
                fancy,
                target="runtime_cancellation",
                extra=["--", "--include-ignored", "--test-threads=1", "--nocapture"],
            ),
            kind="patch-regression",
            environment=common_env,
            require_tests=True,
            locked=True,
        )
        runner.cargo(
            "fancy-regex-ascii-backrefs",
            _cargo_test_args(
                fancy,
                target="ascii_backrefs",
                extra=["--", "--test-threads=1", "--nocapture"],
            ),
            kind="patch-regression",
            environment=common_env,
            require_tests=True,
            locked=True,
        )
        runner.cargo(
            "fancy-regex-python-backrefs-missing-oracle",
            _cargo_test_args(
                fancy,
                target="python_backrefs",
                extra=["--", "--include-ignored", "--exact", FANCY_PYTHON_TEST],
            ),
            kind="controlled-failure",
            environment={"SAFEYOLO_POLICY_PYTHON": "__UNSET__"},
            expect_failure=True,
            require_tests=True,
            locked=True,
        )
        runner.cargo(
            "fancy-regex-python-backrefs",
            _cargo_test_args(
                fancy,
                target="python_backrefs",
                extra=["--", "--include-ignored", "--test-threads=1", "--nocapture"],
            ),
            kind="patch-regression-python-oracle",
            environment=common_env,
            require_tests=True,
            locked=True,
        )

        runner.cargo(
            "hyper-inherited-unit-smoke",
            _cargo_test_args(
                hyper,
                no_default_features=True,
                lib=True,
                extra=["--", "--test-threads=1"],
            ),
            kind="inherited-upstream-tests",
            require_tests=True,
            locked=True,
        )
        runner.cargo(
            "h2-inherited-unit-smoke",
            _cargo_test_args(
                h2,
                no_default_features=True,
                lib=True,
                extra=[
                    "--",
                    "hpack::huffman::test::decode_single_byte",
                    "--exact",
                    "--test-threads=1",
                ],
            ),
            kind="inherited-upstream-tests",
            require_tests=True,
            locked=True,
        )

        for name, features, no_default in (
            ("h2-feature-none", None, True),
            ("h2-feature-stream", "stream", False),
            ("h2-feature-unstable", "unstable", False),
            ("h2-feature-all", "stream,unstable", False),
        ):
            runner.cargo(
                name,
                _cargo_check_args(h2, features=features, no_default_features=no_default),
                kind="independent-feature-build",
                locked=True,
            )
        runner.cargo(
            "hyper-client-http2-without-http1",
            _cargo_check_args(
                hyper,
                features="client,http2",
                no_default_features=True,
            ),
            kind="independent-feature-build",
            locked=True,
        )
        runner.cargo(
            "product-locked-build-all-targets",
            _cargo_build_args(product_manifest, all_targets=True),
            kind="product-locked-build",
            locked=True,
        )
        runner.cargo(
            "product-inspection-focused",
            _cargo_test_args(
                product_manifest,
                target="inspection",
                extra=["--", "--test-threads=1"],
            ),
            kind="product-focused-tests",
            require_tests=True,
            locked=True,
        )
        runner.cargo(
            "product-parser-completion",
            _cargo_test_args(
                product_manifest,
                extra=[
                    "--test",
                    "request_completion_h1",
                    "--test",
                    "request_completion_h2",
                    "--test",
                    "response_completion_h1",
                    "--test",
                    "response_completion_h2",
                    "--test",
                    "response_head_capture",
                    "--",
                    "--test-threads=1",
                    "--nocapture",
                ],
            ),
            kind="product-parser-completion-tests",
            require_tests=True,
            locked=True,
        )
        report["status"] = "passed"
        _write_report(report_path, report)
        print(f"\nPASS: report written to {report_path}")
        return 0
    except (ValidationError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        _write_report(report_path, report)
        print(f"\nFAIL: {error}", file=sys.stderr)
        print(f"report={report_path}", file=sys.stderr)
        return 1
    finally:
        if target_context is not None:
            target_context.cleanup()


if __name__ == "__main__":
    sys.exit(main())
