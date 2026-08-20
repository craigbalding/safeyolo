#!/usr/bin/env python3
"""Run the same Python CodeQL quality suite locally before pushing.

The first run downloads the checksum-pinned bundle used by the CodeQL action
SHA in ``.github/workflows/codeql.yml``. The extracted bundle is cached under
the user cache directory; databases and SARIF output live in a temporary
directory and are removed after each run.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLE_MANIFEST = REPO_ROOT / ".github" / "codeql" / "local-bundle.json"
QUERY_SUITE = "codeql/python-queries:codeql-suites/python-security-and-quality.qls"
SUPPRESSION_QUERY = "codeql/python-queries:AlertSuppression.ql"
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
RELEASE_API = "https://api.github.com/repos/github/codeql-action/releases/tags"
ASSET_LAYOUT = {
    "linux-x86_64": (
        ("codeql-bundle-linux64.tar.zst", "zstd"),
        ("codeql-bundle-linux64.tar.gz", None),
    ),
    "macos-x86_64": (
        ("codeql-bundle-osx64.tar.zst", "zstd"),
        ("codeql-bundle-osx64.tar.gz", None),
    ),
}


class CodeQLCheckError(RuntimeError):
    """A local CodeQL setup or execution failure."""


def _read_manifest() -> dict[str, Any]:
    try:
        manifest = json.loads(BUNDLE_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CodeQLCheckError(f"cannot read {BUNDLE_MANIFEST}: {error}") from error
    if not isinstance(manifest.get("assets"), dict):
        raise CodeQLCheckError(f"invalid asset map in {BUNDLE_MANIFEST}")
    return manifest


def _workflow_action_sha() -> str:
    workflow = REPO_ROOT / ".github" / "workflows" / "codeql.yml"
    try:
        workflow_text = workflow.read_text(encoding="utf-8")
    except OSError as error:
        raise CodeQLCheckError(f"cannot read {workflow}: {error}") from error
    init = re.search(r"github/codeql-action/init@([0-9a-f]{40})", workflow_text)
    analyze = re.search(r"github/codeql-action/analyze@([0-9a-f]{40})", workflow_text)
    if init is None or analyze is None or init.group(1) != analyze.group(1):
        raise CodeQLCheckError("CodeQL workflow action SHAs are missing or inconsistent")
    return init.group(1)


def _load_manifest() -> dict[str, Any]:
    manifest = _read_manifest()
    if manifest.get("action_sha") != _workflow_action_sha():
        raise CodeQLCheckError(
            "local CodeQL bundle manifest is out of sync with the workflow action SHA"
        )
    return manifest


def _update_manifest(version: str) -> None:
    """Refresh platform asset hashes from an official CodeQL bundle release."""
    if re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
        raise CodeQLCheckError(f"invalid CodeQL bundle version: {version!r}")
    _read_manifest()  # Validate the existing JSON shape before replacing it.
    tag = f"codeql-bundle-v{version}"
    request = urllib.request.Request(
        f"{RELEASE_API}/{tag}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "SafeYolo-CodeQL-bundle-updater",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            release = json.load(response)
    except (OSError, json.JSONDecodeError) as error:
        raise CodeQLCheckError(f"cannot read official CodeQL release {tag}: {error}") from error

    release_assets = {
        str(asset.get("name")): str(asset.get("digest", ""))
        for asset in release.get("assets", [])
        if isinstance(asset, dict)
    }
    assets: dict[str, list[dict[str, str]]] = {}
    for platform_key, specifications in ASSET_LAYOUT.items():
        candidates = []
        for archive, requirement in specifications:
            digest = release_assets.get(archive, "")
            if not digest.startswith("sha256:") or re.fullmatch(
                r"[0-9a-f]{64}", digest.removeprefix("sha256:")
            ) is None:
                raise CodeQLCheckError(f"official release has no SHA256 digest for {archive}")
            candidate = {
                "archive": archive,
                "sha256": digest.removeprefix("sha256:"),
            }
            if requirement is not None:
                candidate["requires"] = requirement
            candidates.append(candidate)
        assets[platform_key] = candidates

    updated = {
        "action_sha": _workflow_action_sha(),
        "bundle_version": version,
        "assets": assets,
    }
    BUNDLE_MANIFEST.write_text(
        json.dumps(updated, indent=2) + "\n",
        encoding="utf-8",
    )


def _platform_key() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Linux" and machine in {"amd64", "x86_64"}:
        return "linux-x86_64"
    if system == "Darwin" and machine in {"amd64", "x86_64", "arm64", "aarch64"}:
        # GitHub publishes an x86_64 macOS bundle. It runs on Apple Silicon
        # through Rosetta 2, matching GitHub's documented CodeQL requirement.
        return "macos-x86_64"
    raise CodeQLCheckError(
        f"no pinned CodeQL bundle for {system} {platform.machine()}"
    )


def _cache_root() -> Path:
    override = os.environ.get("SAFEYOLO_CODEQL_CACHE")
    if override:
        return Path(override).expanduser().resolve()
    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg_cache).expanduser() if xdg_cache else Path.home() / ".cache"
    return base / "safeyolo" / "codeql"


def _download(url: str, destination: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256()
    downloaded = 0
    next_progress = 10
    try:
        with urllib.request.urlopen(url, timeout=60) as response, destination.open("wb") as output:
            total = int(response.headers.get("Content-Length", "0"))
            while chunk := response.read(DOWNLOAD_CHUNK_BYTES):
                output.write(chunk)
                digest.update(chunk)
                downloaded += len(chunk)
                if total:
                    progress = downloaded * 100 // total
                    if progress >= next_progress:
                        print(f"  download: {progress}%", file=sys.stderr)
                        next_progress = progress + 10
    except OSError as error:
        destination.unlink(missing_ok=True)
        raise CodeQLCheckError(f"CodeQL bundle download failed: {error}") from error

    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        destination.unlink(missing_ok=True)
        raise CodeQLCheckError(
            "CodeQL bundle checksum mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )


def _extract(archive: Path, destination: Path) -> None:
    tar = shutil.which("tar")
    if tar is None:
        raise CodeQLCheckError("tar is required to extract the CodeQL bundle")
    command = [tar, "--extract", "--file", str(archive), "--directory", str(destination)]
    if archive.name.endswith(".tar.zst"):
        command.append("--zstd")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown tar error"
        raise CodeQLCheckError(f"CodeQL bundle extraction failed: {detail}")


def _ensure_codeql() -> Path:
    configured = os.environ.get("SAFEYOLO_CODEQL_BIN")
    if configured:
        binary = Path(configured).expanduser().resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise CodeQLCheckError(f"SAFEYOLO_CODEQL_BIN is not executable: {binary}")
        return binary

    manifest = _load_manifest()
    platform_key = _platform_key()
    candidates = manifest["assets"].get(platform_key)
    if not isinstance(candidates, list):
        raise CodeQLCheckError(f"missing {platform_key} asset in {BUNDLE_MANIFEST}")
    asset = next(
        (
            candidate
            for candidate in candidates
            if isinstance(candidate, dict)
            and (
                not candidate.get("requires")
                or shutil.which(str(candidate["requires"])) is not None
            )
        ),
        None,
    )
    if asset is None:
        raise CodeQLCheckError(f"no usable {platform_key} asset in {BUNDLE_MANIFEST}")

    version = str(manifest["bundle_version"])
    archive_name = str(asset["archive"])
    expected_sha256 = str(asset["sha256"])
    install_dir = _cache_root() / version / platform_key
    binary = install_dir / "codeql" / "codeql"
    if binary.is_file() and os.access(binary, os.X_OK):
        return binary

    cache_root = _cache_root()
    cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = cache_root / ".install.lock"
    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        if binary.is_file() and os.access(binary, os.X_OK):
            return binary

        release = f"codeql-bundle-v{version}"
        url = (
            "https://github.com/github/codeql-action/releases/download/"
            f"{release}/{archive_name}"
        )
        install_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if install_dir.exists():
            # Exact version/platform target under the private cache. A prior
            # interrupted extraction is unusable and safe to replace.
            shutil.rmtree(install_dir)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{platform_key}-", dir=install_dir.parent)
        )
        archive = temporary / archive_name
        print(
            f"Installing CodeQL {version} for {platform_key} (one-time download)...",
            file=sys.stderr,
        )
        try:
            _download(url, archive, expected_sha256)
            _extract(archive, temporary)
            archive.unlink()
            extracted_binary = temporary / "codeql" / "codeql"
            if not extracted_binary.is_file():
                raise CodeQLCheckError(
                    f"bundle did not contain expected executable: {extracted_binary}"
                )
            os.replace(temporary, install_dir)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    return binary


def _tracked_snapshot(destination: Path) -> None:
    """Copy tracked files with current worktree contents into ``destination``."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    )
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(os.fsdecode(raw_path))
        source = REPO_ROOT / relative
        if not source.exists() and not source.is_symlink():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.is_file():
            shutil.copy2(source, target)


def _run_codeql(command: list[str], *, cwd: Path) -> None:
    """Run CodeQL quietly and retain useful diagnostics for failures."""
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return
    detail = (result.stderr.strip() or result.stdout.strip() or "no diagnostics")[-8000:]
    raise CodeQLCheckError(f"CodeQL exited with status {result.returncode}:\n{detail}")


def _run_analysis(codeql: Path) -> tuple[list[dict[str, Any]], int]:
    with tempfile.TemporaryDirectory(prefix="safeyolo-codeql-") as temporary_name:
        temporary = Path(temporary_name)
        source = temporary / "source"
        database = temporary / "database"
        sarif = temporary / "results.sarif"
        source.mkdir()
        _tracked_snapshot(source)

        print("Creating local Python CodeQL database...", file=sys.stderr)
        _run_codeql(
            [
                str(codeql),
                "database",
                "create",
                str(database),
                "--language=python",
                f"--source-root={source}",
                f"--codescanning-config={source / '.github/codeql/codeql-config.yml'}",
                "--threads=0",
                "--quiet",
            ],
            cwd=source,
        )
        print("Running Python security-and-quality queries...", file=sys.stderr)
        _run_codeql(
            [
                str(codeql),
                "database",
                "analyze",
                str(database),
                QUERY_SUITE,
                SUPPRESSION_QUERY,
                "--no-download",
                "--format=sarif-latest",
                f"--output={sarif}",
                "--threads=0",
                "--quiet",
            ],
            cwd=source,
        )
        payload = json.loads(sarif.read_text(encoding="utf-8"))
        results = [
            result
            for run in payload.get("runs", [])
            for result in run.get("results", [])
        ]
        findings = [result for result in results if not result.get("suppressions")]
        return findings, len(results) - len(findings)


def _render_findings(findings: list[dict[str, Any]]) -> None:
    for finding in findings:
        location = {}
        locations = finding.get("locations", [])
        if locations:
            location = locations[0].get("physicalLocation", {})
        artifact = location.get("artifactLocation", {}).get("uri", "?")
        line = location.get("region", {}).get("startLine", "?")
        message = finding.get("message", {}).get("text", "CodeQL finding")
        print(f"{artifact}:{line}: {finding.get('ruleId', '?')}: {message}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--install-only",
        action="store_true",
        help="Install and verify the pinned bundle without analyzing",
    )
    mode.add_argument(
        "--verify-version",
        metavar="VERSION",
        help="Verify CI's selected CodeQL version against the local manifest",
    )
    mode.add_argument(
        "--update-bundle",
        metavar="VERSION",
        help="Update bundle hashes from the official GitHub release",
    )
    arguments = parser.parse_args()
    try:
        if arguments.update_bundle:
            _update_manifest(arguments.update_bundle)
            print(f"Updated {BUNDLE_MANIFEST} to CodeQL {arguments.update_bundle}.")
            return 0
        if arguments.verify_version:
            expected = str(_load_manifest()["bundle_version"])
            if arguments.verify_version != expected:
                raise CodeQLCheckError(
                    "CI/local CodeQL version drift: "
                    f"CI selected {arguments.verify_version}, local manifest pins {expected}. "
                    f"Run scripts/check_codeql.py --update-bundle {arguments.verify_version}."
                )
            print(f"CI and local CodeQL versions match ({expected}).")
            return 0
        codeql = _ensure_codeql()
        version = subprocess.run(
            [str(codeql), "version", "--format=terse"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        print(f"CodeQL {version}: {codeql}", file=sys.stderr)
        if arguments.install_only:
            return 0
        findings, suppressed_count = _run_analysis(codeql)
    except (CodeQLCheckError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"local CodeQL check failed: {error}", file=sys.stderr)
        return 2

    if findings:
        _render_findings(findings)
        print(f"Local CodeQL found {len(findings)} issue(s).", file=sys.stderr)
        return 1
    suppression_note = (
        f" ({suppressed_count} intentional source suppression(s))"
        if suppressed_count
        else ""
    )
    print(f"Local CodeQL found no issues{suppression_note}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
