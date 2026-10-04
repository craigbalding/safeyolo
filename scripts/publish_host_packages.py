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
import zipfile
from datetime import UTC, datetime
from pathlib import Path

try:
    from scripts.verify_host_package import sha256
except ModuleNotFoundError:
    from verify_host_package import sha256

# These are the existing required CI/security checks and master native producer.
# Optional platform fixtures do not add a package-publication prerequisite.
WORKFLOWS = {
    "ci.yml": ("Test CLI", "Lint", "Test Addons (Python 3.12)"),
    "proxy-rust.yml": ("Quick native checks (Ubuntu)",),
    "codeql.yml": ("Analyze",),
}
DEBUG_JOBS = {"linux-amd64": "Quick native checks (Ubuntu)", "darwin-arm64": "Relevant macOS platform checks"}
PLATFORMS = ("darwin-arm64", "linux-amd64", "linux-arm64")
ASSETS = {f"safeyolo-{platform}-{profile}.tar.gz" for platform in PLATFORMS for profile in ("production", "debug")}


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True, timeout=120).strip()


def api(repository: str, path: str) -> dict:
    return json.loads(gh("api", f"repos/{repository}/{path}"))


def run_jobs(repository: str, run: dict) -> list[dict]:
    # A failed-job rerun can leave successful producers at an earlier attempt.
    # GitHub's latest filter returns each job's newest result, including those.
    return api(repository, f"actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]


def successful_job(job: dict, run: dict) -> bool:
    return (job["run_id"] == run["id"] and 1 <= job["run_attempt"] <= run["run_attempt"]
            and job["head_sha"] == run["head_sha"] and job["status"] == "completed"
            and job["conclusion"] == "success")


def successful_checks(repository: str, commit: str) -> dict | None:
    """Require current same-source jobs; retain unrelated workflow failures."""
    comparison = api(repository, f"compare/{commit}...master")
    if comparison["status"] not in {"ahead", "identical"}:
        raise ValueError("package source is not in current master history")
    checks = {}
    for workflow, required_jobs in WORKFLOWS.items():
        runs = api(repository, f"actions/workflows/{workflow}/runs?event=push&branch=master&head_sha={commit}&per_page=100")
        matching = [
            run for run in runs["workflow_runs"]
            if run["head_sha"] == commit and run["event"] == "push" and run["head_branch"] == "master"
            and run["head_repository"]["full_name"] == repository
            and run["path"] == f".github/workflows/{workflow}"
        ]
        if not matching:
            print(f"No master push check for {workflow} at {commit}")
            return None
        run = max(matching, key=lambda item: (item["id"], item["run_attempt"]))
        if run["status"] != "completed":
            print(f"Source check {workflow}: {run['status']}/{run['conclusion']} at {run['html_url']}")
            return None
        jobs = run_jobs(repository, run)
        passed = {}
        for name in required_jobs:
            matching_jobs = [job for job in jobs if job["name"] == name]
            if len(matching_jobs) != 1 or not successful_job(matching_jobs[0], run):
                print(f"Source check {name} has not succeeded in {run['html_url']}, attempt {run['run_attempt']}")
                return None
            passed[name] = {"url": matching_jobs[0]["html_url"], "attempt": matching_jobs[0]["run_attempt"]}
        checks[workflow] = {
            "id": run["id"], "attempt": run["run_attempt"], "url": run["html_url"],
            "conclusion": run["conclusion"], "jobs": passed,
        }
    return checks


def release(repository: str, tag: str) -> dict | None:
    path = f"releases/tags/{tag}" if tag else "releases/latest"
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/{path}"], capture_output=True, text=True, timeout=60,
    )
    data = json.loads(result.stdout)
    if result.returncode:
        if data.get("status") == "404":
            # Tag lookup can omit drafts. List all pages before declaring a tag absent.
            if tag:
                pages = json.loads(gh("api", "--paginate", "--slurp", f"repos/{repository}/releases?per_page=100"))
                for page in pages:
                    for candidate in page:
                        if candidate["tag_name"] == tag:
                            return candidate
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
            stream.write(f"native_attempt={checks['proxy-rust.yml']['attempt']}\n")


def download_debug(repository: str, commit: str, run_id: int, platform: str, directory: Path, *, attempt: int) -> None:
    run = api(repository, f"actions/runs/{run_id}")
    if (run["id"] != run_id or run["run_attempt"] != attempt or run["status"] != "completed"
            or run["path"] != ".github/workflows/proxy-rust.yml" or run["head_sha"] != commit
            or run["event"] != "push" or run["head_branch"] != "master"
            or run["head_repository"]["full_name"] != repository):
        raise ValueError("debug artifact run differs from the selected master push and attempt")
    artifacts = api(repository, f"actions/runs/{run_id}/artifacts?per_page=100")["artifacts"]
    name = f"host-debug-{platform}"
    matching = [item for item in artifacts if item["name"] == name and not item["expired"]]
    if not matching:
        print(f"No saved {platform} debug runtimes; using the missing-output fallback")
        return
    if len(matching) != 1:
        raise ValueError("debug artifact name does not identify one output")
    artifact = matching[0]
    source = artifact["workflow_run"]
    if source["id"] != run_id or source["head_sha"] != commit or source["head_branch"] != "master":
        raise ValueError("debug artifact source differs from the selected master push")
    jobs = [job for job in run_jobs(repository, run) if job["name"] == DEBUG_JOBS.get(platform)]
    if len(jobs) != 1 or not successful_job(jobs[0], run):
        print(f"No successful {platform} debug producer; using the missing-output fallback")
        return
    steps = jobs[0]["steps"]
    saved = [step for step in steps if step["name"] == "Save actual master CI debug runtimes"]
    uploads = [step for step in steps if step["name"].startswith("Run actions/upload-artifact@")]
    if (len(saved) != 1 or saved[0]["conclusion"] != "success" or len(uploads) != 1
            or uploads[0]["conclusion"] != "success"):
        print(f"No successful {platform} runtime save/upload; using the missing-output fallback")
        return
    # The artifact API omits attempt/job identity. Its creation must fall inside
    # this producer's successful upload, excluding retained earlier-attempt ZIPs.
    created = datetime.fromisoformat(artifact["created_at"])
    upload = uploads[0]
    if not datetime.fromisoformat(upload["started_at"]) <= created <= datetime.fromisoformat(upload["completed_at"]):
        print(f"No {platform} debug artifact from the selected producer attempt; using the missing-output fallback")
        return
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="host-debug-download-", dir=directory.parent) as temporary:
        archive_path = Path(temporary) / "runtime.zip"
        with archive_path.open("wb") as stream:
            subprocess.run(
                ["gh", "api", f"repos/{repository}/actions/artifacts/{artifact['id']}/zip"],
                stdout=stream, check=True, timeout=180,
            )
        if artifact["digest"] != f"sha256:{sha256(archive_path)}":
            raise ValueError("debug artifact ZIP checksum differs from GitHub's recorded bytes")
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(directory)


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
    if existing and existing["target_commitish"] != commit:
        raise ValueError("existing host package draft targets a different source commit")
    checksums = directory / "SHA256SUMS"
    checksums.write_text("".join(f"{sha256(paths[name])}  {name}\n" for name in sorted(paths)))
    published_at = datetime.now(UTC)
    month = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[published_at.month - 1]
    title = f"SafeYolo — master build, {published_at.day} {month} {published_at.year} ({commit[:7]})"
    with tempfile.TemporaryDirectory(prefix="host-release-notes-") as temporary:
        notes = Path(temporary) / "notes.md"
        notes.write_text(
            f"Host packages from master commit `{commit}`.\n\n"
            "Production packages use the release proxy and production macOS helper. "
            "Debug packages use the dev proxy and development macOS helper with debug symbols.\n\n"
            "Verify SHA256SUMS before extracting a download, then run its install.sh with uv on the target host. "
            "Each archive records source, platform, profile, compiler settings, compatibility and file checksums. "
            "Guest images and host runtime setup are separate.\n\n"
            "Source checks:\n" + "".join(
                f"- [{name}]({check['url']}), attempt {check['attempt']}, workflow conclusion {check['conclusion']}; "
                "successful jobs: " + ", ".join(
                    f"[{job}]({result['url']}) (attempt {result['attempt']})" for job, result in check["jobs"].items()
                ) + "\n"
                for name, check in checks.items()
            )
        )
        if existing is None:
            gh("release", "create", tag, "--repo", repository, "--target", commit, "--draft", "--latest=false",
               "--title", title, "--notes-file", str(notes))
        else:
            gh("release", "edit", tag, "--repo", repository, "--title", title, "--notes-file", str(notes))
    gh("release", "upload", tag, "--repo", repository, "--clobber", *map(str, paths.values()), str(checksums))
    staged = release(repository, tag)
    if staged is None or staged["target_commitish"] != commit:
        raise ValueError("uploaded host package release is missing or targets a different source commit")
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
    parser.add_argument("--native-attempt", type=int)
    parser.add_argument("--platform", choices=PLATFORMS)
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("repository and full source commit are required")
    if args.operation == "select":
        select(args.repository, args.commit)
    elif args.operation == "download-debug":
        if args.native_run is None or args.native_attempt is None or args.platform is None:
            parser.error("download-debug requires native-run, native-attempt and platform")
        download_debug(args.repository, args.commit, args.native_run, args.platform, args.directory, attempt=args.native_attempt)
    elif args.operation == "stage":
        stage(args.repository, args.commit, args.directory)
    else:
        promote(args.repository, args.commit)


if __name__ == "__main__":
    main()
