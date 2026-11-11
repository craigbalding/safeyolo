#!/usr/bin/env python3
"""Report bounded, nonsecret runner inputs at CI's apt setup boundary."""

import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

URL = re.compile(r"https?://[^\s\"'<>]+")


def public_url(match: re.Match[str]) -> str:
    """Remove URL credentials and query strings before logging or probing."""
    parsed = urlsplit(match.group())
    return urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", ""))


def report_config(path: Path) -> list[str]:
    """Read only resolver/source inputs, never apt authentication files."""
    print(f"=== {path} (resolved: {path.resolve()}) ===", flush=True)
    try:
        with path.open() as config:
            content = config.read(8193)
    except OSError as error:
        print(f"unavailable: {error.strerror}", flush=True)
        return []
    truncated = len(content) > 8192
    content = URL.sub(public_url, content[:8192])
    print(content, flush=True)
    if truncated:
        print("[truncated at 8192 characters]", flush=True)
    # Comments are useful context in the report, but are not configured mirrors.
    configured = "\n".join(line.split("#", 1)[0] for line in content.splitlines())
    return URL.findall(configured)


def report_command(command: list[str], timeout: int) -> None:
    """Keep a failed lookup/request visible without stopping other mirror probes."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        print(f"{command[0]}: timed out after {timeout}s", flush=True)
    except OSError as error:
        print(f"{command[0]}: unavailable: {error.strerror}", flush=True)
    else:
        print(f"{command[0]}: exit {result.returncode}\n{result.stdout[:2048]}{result.stderr[:2048]}", flush=True)


def main() -> None:
    paths = [Path("/etc/resolv.conf"), Path("/etc/apt/sources.list"),
             Path("/etc/apt/sources.list.d/ubuntu.sources"), Path("/etc/apt/apt-mirrors.txt")]
    paths += sorted(Path("/etc/apt/sources.list.d").glob("*.list"))
    paths += sorted(Path("/etc/apt/sources.list.d").glob("*.sources"))
    paths = list(dict.fromkeys(paths))
    if len(paths) > 16:
        print("[report limited to 16 source/resolver files]", flush=True)
    mirrors = []
    for path in paths[:16]:
        mirrors.extend(report_config(path))
    mirrors = list(dict.fromkeys(mirrors))
    if len(mirrors) > 6:
        print("[probes limited to 6 configured mirror URLs]", flush=True)
    for mirror in mirrors[:6]:
        print(f"=== configured mirror: {mirror} ===", flush=True)
        report_command(["getent", "ahosts", urlsplit(mirror).hostname or ""], timeout=5)
        report_command([
            "curl", "--disable", "--silent", "--show-error", "--head", "--output", "/dev/null",
            "--connect-timeout", "3", "--max-time", "5", "--write-out",
            "http_code=%{http_code} remote_ip=%{remote_ip} time_total=%{time_total}\n", mirror,
        ], timeout=6)


if __name__ == "__main__":
    main()
