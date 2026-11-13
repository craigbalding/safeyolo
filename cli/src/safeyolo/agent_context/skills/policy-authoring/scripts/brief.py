#!/usr/bin/env python3
"""Write a bounded cyber brief from CISA's public Known Exploited Vulnerabilities feed.

Run as the research workload through its ordinary proxy, without host policy
credentials. Embedded URLs are cited; they are never fetched. The script uses
no model or paid API. It does not install or change a schedule.
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import urlopen

SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 8 * 1024 * 1024


def write_brief(output: Path, focus: str, limit: int) -> None:
    """Read one authorized reporting source and write references, not verdicts."""
    with urlopen(SOURCE, timeout=20) as response:
        content = response.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError("CISA feed exceeded the 8 MiB read bound")
    output.write_text(format_brief(json.loads(content), focus, limit))


def format_brief(feed: dict, focus: str, limit: int) -> str:
    """Summarize a retrieved catalogue without fetching embedded references."""
    entries = [entry for entry in feed["vulnerabilities"] if focus.lower() in (
        f"{entry['cveID']} {entry['vendorProject']} {entry['product']} {entry['shortDescription']}"
    ).lower()]
    entries.sort(key=lambda entry: (entry["dateAdded"], entry["cveID"]), reverse=True)
    collected = datetime.now(UTC).isoformat()
    lines = ["# Cyber research brief", "", f"Collected: {collected}",
             f"Focus: {focus or 'latest catalogue additions'}", f"Source: [CISA KEV catalogue]({SOURCE})",
             f"Provider catalogue version: {feed.get('catalogVersion', 'not supplied')}", "",
             "Catalogue addition date is not vulnerability discovery, exploitation or publication time.", ""]
    for entry in entries[:limit]:
        lines.extend([f"- **{entry['cveID']} — {entry['vendorProject']} {entry['product']}** "
                      f"(CISA added {entry['dateAdded']}): {entry['shortDescription']}",
                      f"  Required action: {entry['requiredAction']}",
                      f"  Reference: https://www.cve.org/CVERecord?id={entry['cveID']}"])
    if not entries:
        lines.append("No matching entries in the successfully retrieved catalogue.")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--focus", default="")
    parser.add_argument("--limit", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_brief(args.output, args.focus, args.limit)


if __name__ == "__main__":
    main()
