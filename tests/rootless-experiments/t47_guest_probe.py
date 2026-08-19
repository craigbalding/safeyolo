#!/usr/bin/env python3
"""Guest half of T47: prove namespace-root remains host-contained."""

from __future__ import annotations

import argparse
import os
import socket
from pathlib import Path
from urllib.parse import urlparse


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canary-token", required=True)
    parser.add_argument("--host-canary", required=True)
    parser.add_argument("--listener-port", required=True, type=int)
    parser.add_argument("--root-marker", required=True)
    args = parser.parse_args()

    failures: list[str] = []

    if os.getuid() != 0 or os.getgid() != 0:
        failures.append(f"expected sandbox uid/gid 0, got {os.getuid()}:{os.getgid()}")

    config_canary = Path("/safeyolo/t47-canary")
    try:
        original = config_canary.read_text()
    except OSError as exc:
        failures.append(f"could not read config canary: {exc}")
    else:
        if original != args.canary_token:
            failures.append("config canary content did not match host")
        try:
            config_canary.write_text("sandbox-root-overwrite")
        except OSError:
            pass
        else:
            failures.append("sandbox root wrote to /safeyolo")

    if Path(args.host_canary).exists():
        failures.append(f"unmounted host canary visible inside sandbox: {args.host_canary}")

    for device in ("/dev/kvm", "/dev/mem", "/dev/kmem"):
        if Path(device).exists():
            failures.append(f"host device exposed: {device}")

    try:
        pid1 = Path("/proc/1/cmdline").read_bytes().decode(errors="replace")
    except OSError:
        pid1 = ""
    if any(host_init in pid1 for host_init in ("systemd", "launchd")):
        failures.append(f"host PID 1 exposed: {pid1!r}")

    proxy_host = urlparse(os.environ.get("HTTP_PROXY", "")).hostname
    if not proxy_host:
        failures.append("HTTP_PROXY did not contain a host endpoint")
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((proxy_host, args.listener_port))
        except OSError:
            pass
        else:
            failures.append(
                f"sandbox root connected to host listener {proxy_host}:{args.listener_port}"
            )
        finally:
            sock.close()

    try:
        Path(args.root_marker).write_text("sandbox-root-overlay-write")
    except OSError as exc:
        failures.append(f"sandbox root could not write its rootfs overlay: {exc}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print("PASS: sandbox root is usable and host-contained")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
