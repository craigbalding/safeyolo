#!/usr/bin/env python3
"""Open an issue when the pinned gVisor release needs attention.

The bundled runsc is built from one upstream gVisor release, pinned in
scripts/build_runsc.sh. No dependency scanner reads that pin. This check
reports two conditions and is otherwise silent:

- a published gVisor security advisory whose fix is newer than the pin;
- a pin that is more than STALE_DAYS older than the newest upstream release.

Each condition opens at most one issue. An issue that was closed is not
opened again. Run with --dry-run to print the findings without opening issues.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "https://github.com/google/gvisor.git"
ADVISORIES = "repos/google/gvisor/security-advisories?state=published&per_page=100"
LABEL = "gvisor-pin"
STALE_DAYS = 30
RELEASE = re.compile(r"release-(\d{4})(\d{2})(\d{2})\.(\d+)")
# gVisor names fixes by release tag, bare release version or Go pseudo-version.
FIXED_VERSION = re.compile(r"(20\d{2}\d{2}\d{2})(?:\.(\d+))?")


def release_order(tag: str) -> tuple[datetime.date, int]:
    """Return the date and sequence number that a release tag encodes."""
    match = RELEASE.fullmatch(tag)
    if match is None:
        raise ValueError(f"not a gVisor release tag: {tag}")
    year, month, day, sequence = (int(group) for group in match.groups())
    return datetime.date(year, month, day), sequence


def pinned_release(build_script: str) -> str:
    """Return the upstream release tag that scripts/build_runsc.sh builds."""
    match = re.search(r"^version=(release-\d{8}\.\d+)-safeyolo\.\d+$", build_script, re.MULTILINE)
    if match is None:
        raise ValueError("scripts/build_runsc.sh has no version=release-YYYYMMDD.N-safeyolo.N line")
    return match.group(1)


def newest_release(tags: list[str]) -> str:
    releases = [tag for tag in tags if RELEASE.fullmatch(tag)]
    if not releases:
        raise ValueError("upstream lists no release tags")
    return max(releases, key=release_order)


def fixed_releases(advisory: dict) -> list[str]:
    """Return fixed releases, retaining any named release sequence."""
    releases = []
    for vulnerability in advisory.get("vulnerabilities") or []:
        for match in FIXED_VERSION.finditer(vulnerability.get("patched_versions") or ""):
            date, sequence = match.groups()
            # Date-only and Go pseudo-versions do not name a release sequence.
            releases.append(f"release-{date}.{sequence or '0'}")
    return releases


def advisory_findings(advisories: list[dict], pin: str) -> list[dict]:
    """Return the advisories that the pinned release may not include a fix for."""
    pin_order = release_order(pin)
    findings = []
    for advisory in advisories:
        releases = fixed_releases(advisory)
        if releases:
            latest_fix = max(releases, key=release_order)
            # The pin has the fix when it is at least as new as every fixed release.
            if release_order(latest_fix) <= pin_order:
                continue
            reason = f"The advisory names a fix in {latest_fix}, after the pin."
        else:
            # Without a fixed release, an advisory published before the pin was
            # cut is taken as fixed in it. A later one needs a person to check.
            published = datetime.date.fromisoformat(advisory["published_at"][:10])
            if published < pin_order[0]:
                continue
            reason = "The advisory names no fixed release and was published after the pin was cut."
        findings.append({
            "key": f"advisory {advisory['ghsa_id']}",
            "title": f"gVisor advisory {advisory['ghsa_id']} may affect the bundled runtime ({pin})",
            "lines": [
                f"Advisory: {advisory['html_url']}",
                f"CVE: {advisory.get('cve_id') or 'none assigned'}",
                f"Severity: {advisory.get('severity') or 'not stated'}",
                f"Summary: {advisory.get('summary') or 'not stated'}",
                reason,
            ],
        })
    return findings


def stale_finding(pin: str, newest: str) -> dict | None:
    """Return a finding when the pin is too far behind the newest release."""
    gap = (release_order(newest)[0] - release_order(pin)[0]).days
    if gap <= STALE_DAYS:
        return None
    return {
        "key": f"stale {pin}",
        "title": f"Bundled gVisor {pin} is more than {STALE_DAYS} days behind upstream",
        "lines": [
            f"The pin is {gap} days older than the newest upstream release, {newest}.",
            "Not every upstream security fix gets an advisory, so an old pin can lack fixes that this check cannot see.",
        ],
    }


def run(*command: str, cwd: Path | None = None) -> str:
    return subprocess.run(command, cwd=cwd, check=True, stdout=subprocess.PIPE, text=True).stdout


def upstream_tags() -> list[str]:
    listing = run("git", "ls-remote", "--tags", "--refs", UPSTREAM, "release-*")
    return [line.split("refs/tags/", 1)[1] for line in listing.splitlines()]


def published_advisories() -> list[dict]:
    pages = json.loads(run("gh", "api", "--paginate", "--slurp", ADVISORIES))
    return [advisory for page in pages for advisory in page]


def patch_report(release: str) -> list[str]:
    """Say whether each carried patch still applies to an upstream release."""
    lines = [f"Carried patches against {release} (`git apply --check`):"]
    with tempfile.TemporaryDirectory() as directory:
        run("git", "clone", "--quiet", "--depth", "1", "--branch", release, UPSTREAM, directory)
        for patch in sorted((ROOT / "scripts/gvisor").glob("*.patch")):
            applied = subprocess.run(
                ["git", "apply", "--check", str(patch)], cwd=directory, capture_output=True, text=True
            )
            state = "applies" if applied.returncode == 0 else "does not apply; upstream may contain it, or it needs a rebase"
            lines.append(f"- `{patch.name}`: {state}")
    return lines


def issue_body(finding: dict, pin: str, newest: str) -> str:
    lines = [*finding["lines"], "", f"Pinned release: {pin}", f"Newest upstream release: {newest}", ""]
    lines += patch_report(newest)
    lines += ["", "The pin and its version marker are in `scripts/build_runsc.sh`.", "", f"Check key: {finding['key']}"]
    return "\n".join(lines)


def reported_keys() -> set[str]:
    """Return the check keys of every issue this check opened, open or closed."""
    endpoint = f"repos/{{owner}}/{{repo}}/issues?state=all&labels={LABEL}&per_page=100"
    pages = json.loads(run("gh", "api", "--paginate", "--slurp", endpoint))
    return {line.removeprefix("Check key: ") for page in pages for issue in page
            for line in (issue.get("body") or "").splitlines()
            if line.startswith("Check key: ")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="print the findings and open no issue")
    arguments = parser.parse_args()

    pin = pinned_release((ROOT / "scripts/build_runsc.sh").read_text())
    newest = newest_release(upstream_tags())
    findings = advisory_findings(published_advisories(), pin)
    stale = stale_finding(pin, newest)
    if stale is not None:
        findings.append(stale)
    print(f"pinned {pin}; newest upstream {newest}; {len(findings)} finding(s)")

    known = set() if arguments.dry_run else reported_keys()
    for finding in findings:
        if finding["key"] in known:
            print(f"already reported: {finding['key']}")
            continue
        body = issue_body(finding, pin, newest)
        if arguments.dry_run:
            print(f"\n## {finding['title']}\n{body}")
        else:
            print(run("gh", "issue", "create", "--title", finding["title"], "--label", LABEL, "--body", body).strip())
            known.add(finding["key"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
