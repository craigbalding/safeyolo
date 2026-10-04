#!/usr/bin/env python3
"""Gate postmerge packages and publish complete releases without stale promotion."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

try:
    from scripts.verify_host_package import sha256
except ModuleNotFoundError:
    from verify_host_package import sha256

WORKFLOWS = ("ci.yml", "proxy-rust.yml", "codeql.yml")
PLATFORMS = ("darwin-arm64", "linux-amd64", "linux-arm64")
ASSETS = {f"safeyolo-{platform}-{profile}.tar.gz" for platform in PLATFORMS for profile in ("production", "debug")}


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True, timeout=120).strip()


def api(repository: str, path: str) -> dict:
    return json.loads(gh("api", f"repos/{repository}/{path}"))


def successful_checks(repository: str, commit: str) -> dict | None:
    """Use current push-run conclusions, never PR or historical-head conclusions."""
    comparison = api(repository, f"compare/{commit}...master")
    if comparison["status"] not in {"ahead", "identical"}:
        raise ValueError("package source is not in current master history")
    checks = {}
    for workflow in WORKFLOWS:
        runs = api(repository, f"actions/workflows/{workflow}/runs?event=push&branch=master&head_sha={commit}&per_page=100")
        matching = [
            run for run in runs["workflow_runs"]
            if run["head_sha"] == commit and run["event"] == "push" and run["head_branch"] == "master"
            and run["head_repository"]["full_name"] == repository
        ]
        if not matching:
            print(f"No master push check for {workflow} at {commit}")
            return None
        run = max(matching, key=lambda item: (item["id"], item["run_attempt"]))
        if run["status"] != "completed" or run["conclusion"] != "success":
            print(f"Source check {workflow}: {run['status']}/{run['conclusion']} at {run['html_url']}")
            return None
        checks[workflow] = {"id": run["id"], "attempt": run["run_attempt"], "url": run["html_url"]}
    return checks


def release(repository: str, tag: str) -> dict | None:
    path = f"releases/tags/{tag}" if tag else "releases/latest"
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/{path}"], capture_output=True, text=True, timeout=60,
    )
    data = json.loads(result.stdout)
    if result.returncode:
        if data.get("status") == "404":
            # A first release or an absent commit tag is expected. Other failures propagate.
            return None
        raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
    return data


def select(repository: str, commit: str) -> None:
    checks = successful_checks(repository, commit)
    existing = release(repository, f"host-{commit}")
    if existing and not existing["draft"]:
        print(f"Host package release already exists: {existing['html_url']}")
        ready = False
    else:
        ready = checks is not None
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"ready={'true' if ready else 'false'}\n")
        if ready:
            stream.write(f"native_run={checks['proxy-rust.yml']['id']}\n")


def download_debug(repository: str, commit: str, run_id: int, platform: str, directory: Path) -> None:
    run = api(repository, f"actions/runs/{run_id}")
    if (run["head_sha"] != commit or run["event"] != "push" or run["head_branch"] != "master"
            or run["head_repository"]["full_name"] != repository or run["conclusion"] != "success"):
        raise ValueError("debug artifact run is not a successful push of the selected master commit")
    artifacts = api(repository, f"actions/runs/{run_id}/artifacts?per_page=100")["artifacts"]
    name = f"host-debug-{platform}"
    if not any(item["name"] == name and not item["expired"] for item in artifacts):
        print(f"No saved {platform} debug runtimes; using the missing-output fallback")
        return
    subprocess.run(
        ["gh", "run", "download", str(run_id), "--repo", repository, "--name", name, "--dir", str(directory)],
        check=True, timeout=180,
    )


def stage(repository: str, commit: str, directory: Path) -> None:
    checks = successful_checks(repository, commit)
    if checks is None:
        raise ValueError("current checks for the package source have not all succeeded")
    paths = {path.name: path for path in directory.glob("*.tar.gz")}
    if set(paths) != ASSETS:
        raise ValueError(f"host package set is incomplete or unexpected: {sorted(paths)}")
    for name, path in paths.items():
        root = name.removesuffix(".tar.gz")
        with tarfile.open(path) as archive:
            stream = archive.extractfile(f"{root}/manifest.json")
            native = json.load(stream)["native"]
        if (native["commit"] != commit or
                root != f"safeyolo-{native['platform']}-{native['profile']}"):
            raise ValueError(f"archive source/platform/profile mismatch: {name}")
    tag = f"host-{commit}"
    existing = release(repository, tag)
    if existing and not existing["draft"]:
        raise ValueError("refusing to change an already published host package release")
    checksums = directory / "SHA256SUMS"
    checksums.write_text("".join(f"{sha256(paths[name])}  {name}\n" for name in sorted(paths)))
    with tempfile.TemporaryDirectory(prefix="host-release-notes-") as temporary:
        notes = Path(temporary) / "notes.md"
        notes.write_text(
            f"Host packages from master commit `{commit}`.\n\n"
            "Production packages use the release proxy and production macOS helper. "
            "Debug packages use the dev proxy and development macOS helper with debug symbols.\n\n"
            "Verify SHA256SUMS before extracting a download, then run its install.sh with uv on the target host. "
            "Each archive records source, platform, profile, compiler settings, compatibility and file checksums. "
            "Guest images and host runtime setup are separate.\n\n"
            "Source checks:\n" + "".join(f"- [{name}]({check['url']}), attempt {check['attempt']}\n" for name, check in checks.items())
        )
        if existing is None:
            gh("release", "create", tag, "--repo", repository, "--target", commit, "--draft", "--latest=false",
               "--title", f"Host packages {commit[:12]}", "--notes-file", str(notes))
        else:
            gh("release", "edit", tag, "--repo", repository, "--notes-file", str(notes))
    gh("release", "upload", tag, "--repo", repository, "--clobber", *map(str, paths.values()), str(checksums))
    staged = release(repository, tag)
    if {asset["name"] for asset in staged["assets"]} != ASSETS | {"SHA256SUMS"}:
        raise ValueError("uploaded host package set differs from the complete local set")
    # A prerelease is downloadable but cannot become GitHub's implicit first latest.
    # Only the later consumer pass makes this a latest-eligible release.
    gh("api", "--method", "PATCH", f"repos/{repository}/releases/{staged['id']}",
       "-F", "draft=false", "-F", "prerelease=true", "-f", "make_latest=false")


def promote(repository: str, commit: str) -> None:
    """The workflow serializes this operation across commits; compare source ancestry."""
    if successful_checks(repository, commit) is None:
        raise ValueError("source checks changed before latest promotion")
    candidate = release(repository, f"host-{commit}")
    if candidate is None or candidate["draft"] or {a["name"] for a in candidate["assets"]} != ASSETS | {"SHA256SUMS"}:
        raise ValueError("only a complete downloadable host package release can become latest")
    latest = release(repository, "")
    if latest:
        latest_commit = api(repository, f"commits/{latest['tag_name']}")["sha"]
        comparison = api(repository, f"compare/{latest_commit}...{commit}")
        if comparison["status"] not in {"ahead", "identical"}:
            print(f"Preserving newer latest release {latest['tag_name']}; {candidate['tag_name']} remains downloadable")
            return
    gh("api", "--method", "PATCH", f"repos/{repository}/releases/{candidate['id']}",
       "-F", "prerelease=false", "-f", "make_latest=true")
    print(f"Latest successful host packages: {candidate['html_url']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("select", "download-debug", "stage", "promote"))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"), required=False)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--directory", type=Path, default=Path("packages"))
    parser.add_argument("--native-run", type=int)
    parser.add_argument("--platform", choices=PLATFORMS)
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("repository and full source commit are required")
    if args.operation == "select":
        select(args.repository, args.commit)
    elif args.operation == "download-debug":
        if args.native_run is None or args.platform is None:
            parser.error("download-debug requires native-run and platform")
        download_debug(args.repository, args.commit, args.native_run, args.platform, args.directory)
    elif args.operation == "stage":
        stage(args.repository, args.commit, args.directory)
    else:
        promote(args.repository, args.commit)


if __name__ == "__main__":
    main()
