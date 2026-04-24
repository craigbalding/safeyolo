#!/usr/bin/env python3
"""SafeYolo guest-side egress chain diagnostic.

Run from inside an agent shell (`safeyolo agent shell <name>`) to walk
every hop from the agent's perspective out to mitmproxy on the host.

Chain (macOS / VZ microVM):
  curl → 127.0.0.1:8080 (guest-proxy-forwarder)
       → vsock:1080 (safeyolo-vm VSockProxyRelay)
       → host per-agent UDS (mitmproxy UnixInstance)

Chain (Linux / gVisor):
  curl → 127.0.0.1:8080 (guest-proxy-forwarder)
       → /safeyolo/proxy.sock UDS (bind-mounted, gVisor --host-uds=open)
       → host per-agent UDS (mitmproxy UnixInstance)

Usage:
    python3 /safeyolo/guest-diag
    # or, if staged into config share:
    /safeyolo/guest-diag
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time

PROXY_PORT = 8080
UDS_PATH = "/safeyolo/proxy.sock"
VSOCK_HOST_CID = 2
VSOCK_PROXY_PORT = 1080
VSOCK_SHELL_PORT = 2220

# --- output helpers -------------------------------------------------------

_COLOURS = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m",
            "INFO": "\033[36m", "SKIP": "\033[90m"}
_RESET = "\033[0m"
_results: list[tuple[str, str, str]] = []


def _print(status: str, name: str, msg: str, hint: str = "") -> None:
    _results.append((status, name, msg))
    c = _COLOURS.get(status, "")
    print(f"  {c}{status:4s}{_RESET}  {name}: {msg}")
    if hint:
        print(f"         → {hint}")


# --- checks ---------------------------------------------------------------

def check_identity() -> None:
    agent = "unknown"
    try:
        with open("/safeyolo/agent-name") as f:
            agent = f.read().strip()
    except OSError:
        pass  # agent-name file absent — use default
    uid = os.getuid()
    user = os.environ.get("USER", f"uid={uid}")
    _print("INFO", "Agent identity", f"name={agent} user={user} uid={uid}")


def check_loopback() -> None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.close()
        _print("PASS", "Loopback", "127.0.0.1 is up")
    except OSError as e:
        _print("FAIL", "Loopback", f"bind(127.0.0.1) failed: {e}",
               "loopback interface may be down — check `ip link show lo`")


def check_forwarder_process() -> None:
    try:
        out = subprocess.run(
            ["pgrep", "-af", "guest-proxy-forwarder"],
            capture_output=True, text=True, timeout=3,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        out = ""

    if not out:
        # fallback: check /proc
        found = False
        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid_dir}/cmdline") as f:
                        cmdline = f.read()
                    if "guest-proxy-forwarder" in cmdline:
                        out = f"pid={pid_dir}"
                        found = True
                        break
                except OSError:
                    continue
        except OSError:
            pass  # /proc not available on this platform
        if not found:
            _print("FAIL", "Forwarder process", "guest-proxy-forwarder not running",
                   "check console log: dmesg | grep -i proxy")
            return

    _print("PASS", "Forwarder process", out.splitlines()[0] if out else "running")


def check_forwarder_listener() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", PROXY_PORT))
        s.close()
        _print("PASS", "Forwarder listener", f"127.0.0.1:{PROXY_PORT} accepting connections")
    except OSError as e:
        _print("FAIL", "Forwarder listener", f"127.0.0.1:{PROXY_PORT} — {e}",
               "forwarder may have crashed or port conflict")


def check_transport_uds() -> bool:
    if os.path.exists(UDS_PATH):
        _print("PASS", "Transport: UDS", f"{UDS_PATH} exists")
        # Try connecting
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect(UDS_PATH)
            s.close()
            _print("PASS", "UDS connect", f"{UDS_PATH} accepts connections")
        except OSError as e:
            _print("FAIL", "UDS connect", f"{UDS_PATH} — {e}",
                   "socket file exists but connect failed — stale socket or bridge down")
        return True
    _print("INFO", "Transport: UDS", f"{UDS_PATH} not present (expected on Linux/gVisor)")
    return False


def check_transport_vsock() -> bool:
    if not hasattr(socket, "AF_VSOCK"):
        _print("FAIL", "Transport: vsock", "AF_VSOCK not available in this kernel/python",
               "kernel may lack CONFIG_VSOCKETS; or python built without it")
        return False

    _print("PASS", "Transport: vsock", "AF_VSOCK available")

    # Check /dev/vsock
    if os.path.exists("/dev/vsock"):
        _print("PASS", "vsock device", "/dev/vsock present")
    else:
        _print("WARN", "vsock device", "/dev/vsock missing",
               "vsock module may not be loaded")

    # Try connecting to the proxy relay port
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((VSOCK_HOST_CID, VSOCK_PROXY_PORT))
        _print("PASS", "vsock proxy relay", f"vsock CID={VSOCK_HOST_CID} port={VSOCK_PROXY_PORT} connected")
        s.close()
        return True
    except OSError as e:
        _print("FAIL", "vsock proxy relay", f"vsock:{VSOCK_PROXY_PORT} — {e}",
               "safeyolo-vm may not have VSockProxyRelay enabled "
               "(check --proxy-socket was passed)")
        s.close()

    # Also probe the shell bridge port for context
    s2 = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s2.settimeout(3)
    try:
        s2.connect((VSOCK_HOST_CID, VSOCK_SHELL_PORT))
        _print("INFO", "vsock shell bridge", f"vsock:{VSOCK_SHELL_PORT} connected (shell bridge works)")
    except OSError as e:
        _print("INFO", "vsock shell bridge", f"vsock:{VSOCK_SHELL_PORT} — {e}")
    finally:
        s2.close()

    return False


def check_proxy_env() -> None:
    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
    ssl_cert = os.environ.get("SSL_CERT_FILE")
    node_ca = os.environ.get("NODE_EXTRA_CA_CERTS")

    if http_proxy:
        _print("PASS", "HTTP_PROXY", http_proxy)
    else:
        _print("WARN", "HTTP_PROXY", "not set",
               "agent traffic won't route through SafeYolo")

    if https_proxy:
        _print("PASS", "HTTPS_PROXY", https_proxy)
    else:
        _print("WARN", "HTTPS_PROXY", "not set")

    if no_proxy:
        _print("PASS", "NO_PROXY", no_proxy)

    if ssl_cert:
        exists = os.path.exists(ssl_cert)
        if exists:
            _print("PASS", "SSL_CERT_FILE", f"{ssl_cert} (exists)")
        else:
            _print("FAIL", "SSL_CERT_FILE", f"{ssl_cert} (FILE MISSING)",
                   "CA trust will fail — check guest-init-static CA copy")
    else:
        _print("WARN", "SSL_CERT_FILE", "not set — HTTPS through proxy will fail")

    if node_ca:
        exists = os.path.exists(node_ca)
        status = "PASS" if exists else "FAIL"
        _print(status, "NODE_EXTRA_CA_CERTS", f"{node_ca} ({'exists' if exists else 'MISSING'})")


def check_end_to_end() -> None:
    """Send a minimal HTTP request through the forwarder to mitmproxy."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(("127.0.0.1", PROXY_PORT))
    except OSError as e:
        _print("FAIL", "End-to-end", f"connect to forwarder failed: {e}")
        return

    # Send a proxy-style HTTP request — mitmproxy should answer even
    # if the destination is unreachable. A 502/503 from mitmproxy still
    # proves the full chain works.
    req = (
        b"GET http://httpbin.org/status/200 HTTP/1.1\r\n"
        b"Host: httpbin.org\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    try:
        s.sendall(req)
    except OSError as e:
        _print("FAIL", "End-to-end", f"send failed: {e}")
        s.close()
        return

    buf = b""
    started = time.monotonic()
    while time.monotonic() - started < 5:
        try:
            chunk = s.recv(4096)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    s.close()

    if not buf:
        _print("FAIL", "End-to-end", "empty reply from forwarder",
               "forwarder accepted but upstream hop failed — "
               "check transport (UDS or vsock relay)")
        return

    first_line = buf.split(b"\n", 1)[0].decode(errors="replace").strip()
    if first_line.startswith("HTTP/"):
        # Any HTTP response (200, 400, 403, 502, 503) proves the chain works.
        size = len(buf)
        _print("PASS", "End-to-end", f"got HTTP response ({size}B): {first_line}")
    else:
        _print("FAIL", "End-to-end", f"non-HTTP response: {first_line[:80]!r}")


def check_safeyolo_files() -> None:
    """Inventory key files in /safeyolo/ config share."""
    expected = [
        "guest-init", "guest-init-static", "guest-init-per-run",
        "guest-proxy-forwarder", "guest-shell-bridge",
        "proxy.env", "agent.env", "agent-name",
        "mitmproxy-ca-cert.pem",
    ]
    missing = [f for f in expected if not os.path.exists(f"/safeyolo/{f}")]

    if not missing:
        _print("PASS", "Config share", f"all {len(expected)} expected files present")
    else:
        _print("WARN", "Config share", f"missing: {', '.join(missing)}")

    # Check executable bits on scripts
    scripts = ["guest-init", "guest-init-static", "guest-init-per-run",
               "guest-proxy-forwarder", "guest-shell-bridge"]
    non_exec = [s for s in scripts if os.path.exists(f"/safeyolo/{s}")
                and not os.access(f"/safeyolo/{s}", os.X_OK)]
    if non_exec:
        _print("WARN", "Script permissions", f"not executable: {', '.join(non_exec)}")


# --- main -----------------------------------------------------------------

def main() -> int:
    print("\nSafeYolo Guest Diagnostic\n")

    # Timeout the whole script so it doesn't hang forever on a broken
    # transport probe.
    def _alarm(signum, frame):
        print("\n  FAIL  Diagnostic timed out after 30s")
        sys.exit(1)
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(30)

    check_identity()
    check_safeyolo_files()
    check_proxy_env()
    check_loopback()
    check_forwarder_process()
    check_forwarder_listener()

    # Transport — try UDS first, then vsock
    print()
    has_uds = check_transport_uds()
    if not has_uds:
        check_transport_vsock()

    # End-to-end
    print()
    check_end_to_end()

    # Summary
    n_pass = sum(1 for s, _, _ in _results if s == "PASS")
    n_fail = sum(1 for s, _, _ in _results if s == "FAIL")
    n_warn = sum(1 for s, _, _ in _results if s == "WARN")
    print(f"\n  Summary: {n_pass} pass, {n_fail} fail, {n_warn} warn\n")

    if n_fail:
        print("  Tip: fix failures top-to-bottom — later checks depend on earlier ones.")
        print("  For host-side diagnostics run: safeyolo agent diag <name>\n")

    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
