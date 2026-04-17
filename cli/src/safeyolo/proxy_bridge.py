"""Host-side UDS -> TCP bridge for SafeYolo on Linux.

mitmproxy listens on TCP (127.0.0.1:<proxy_port>). Agent containers
can't reach host TCP directly — with the new networking architecture
they have no external network interface at all.

This bridge accepts connections on a Unix domain socket
(~/.safeyolo/data/proxy.sock) and forwards each one bidirectionally
to mitmproxy's TCP listener. The agent container gets the UDS via
gVisor --host-uds=open + a bind-mount, and runs guest-proxy-forwarder
to expose it as localhost:8080 (the agent's HTTP_PROXY target).

Lifecycle:
  - start_proxy_bridge() — spawn as a detached subprocess, write PID file
  - stop_proxy_bridge() — read PID, SIGTERM, cleanup socket + PID file
Called from proxy.py's start_proxy / stop_proxy so the bridge's
lifetime matches mitmproxy's.

The daemon itself is in __main__: when executed as a script it opens
the UDS, listens forever, and forwards connections. No CLI flags,
config from argv[1] (socket path) and argv[2] (upstream host:port).
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

log = logging.getLogger("safeyolo.proxy_bridge")


def _get_data_dir() -> Path:
    """Lazy import so the daemon mode (run as a standalone script) doesn't
    need the safeyolo package on sys.path — the daemon only uses argv."""
    from .config import get_data_dir as _impl  # noqa: PLC0415
    return _impl()

# ---------------------------------------------------------------------------
# Lifecycle helpers (called from proxy.py)
# ---------------------------------------------------------------------------


def socket_path() -> Path:
    """Path of the UDS agents connect to."""
    return _get_data_dir() / "proxy.sock"


def _pid_file() -> Path:
    return _get_data_dir() / "proxy-bridge.pid"


def start_proxy_bridge(proxy_port: int = 8080) -> None:
    """Spawn the UDS -> TCP bridge as a detached subprocess.

    Idempotent: re-running is a no-op if the bridge is already live.
    """
    if is_bridge_running():
        log.info("proxy bridge already running")
        return

    data_dir = _get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    sock = socket_path()
    # Clean up any stale socket from a previous run that didn't shut down.
    # We own this path — the PID file check above is the authoritative
    # liveness signal.
    try:
        sock.unlink()
    except FileNotFoundError:
        pass

    log_file = data_dir.parent / "logs" / "proxy-bridge.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Run this very module as a script — no separate binary needed.
    cmd = [
        sys.executable, "-m", "safeyolo.proxy_bridge",
        str(sock), f"127.0.0.1:{proxy_port}",
    ]
    with open(log_file, "a") as lf:
        proc = subprocess.Popen(
            cmd, stdout=lf, stderr=lf,
            start_new_session=True,
        )

    _pid_file().write_text(str(proc.pid))
    log.info("proxy bridge started (PID %d) on %s", proc.pid, sock)


def stop_proxy_bridge() -> None:
    """SIGTERM the bridge, clean up its socket + PID file."""
    pid_file = _pid_file()
    if not pid_file.exists():
        # May still have a stale socket if the bridge died ungracefully.
        _cleanup_socket()
        return

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
        _cleanup_socket()
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        _cleanup_socket()
        return

    # Wait up to 5s for graceful exit
    for _ in range(50):
        try:
            os.kill(pid, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            break
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    pid_file.unlink(missing_ok=True)
    _cleanup_socket()
    log.info("proxy bridge stopped")


def is_bridge_running() -> bool:
    """Check whether the bridge process is alive (and clean up stale PID)."""
    pid_file = _pid_file()
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, OSError, ProcessLookupError):
        pid_file.unlink(missing_ok=True)
        return False


def _cleanup_socket() -> None:
    try:
        socket_path().unlink()
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Daemon — runs when this module is executed as a script
# ---------------------------------------------------------------------------


def _forward(src: socket.socket, dst: socket.socket) -> None:
    """Copy src -> dst until EOF, then half-close dst's write side."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle_client(uds_conn: socket.socket, upstream: tuple[str, int]) -> None:
    try:
        tcp = socket.create_connection(upstream, timeout=5)
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "upstream %s:%d connect failed: %s: %s",
            upstream[0], upstream[1], type(exc).__name__, exc,
        )
        uds_conn.close()
        return

    t1 = threading.Thread(target=_forward, args=(uds_conn, tcp), daemon=True)
    t2 = threading.Thread(target=_forward, args=(tcp, uds_conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    uds_conn.close()
    tcp.close()


def _daemon_main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write(
            f"Usage: {sys.argv[0]} <socket_path> <upstream_host:port>\n"
        )
        return 2

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    sock_path = sys.argv[1]
    host_port = sys.argv[2]
    host, _, port_str = host_port.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        sys.stderr.write(f"Invalid upstream port: {port_str!r}\n")
        return 2
    upstream = (host or "127.0.0.1", port)

    # Clean up any stale socket (caller does this too, but be defensive).
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(sock_path)
    except OSError as exc:
        sys.stderr.write(f"bind {sock_path} failed: {exc}\n")
        return 1
    # 0660 so the owner (SafeYolo operator) and group can access.
    # The gVisor sandbox runs the gofer as root which already has
    # DAC_OVERRIDE, so this doesn't block the container connecting.
    os.chmod(sock_path, 0o660)
    server.listen(32)

    log = logging.getLogger(__name__)
    log.info("listening on %s -> %s:%d", sock_path, *upstream)

    stop = threading.Event()

    def _on_signal(signum, frame):  # noqa: ARG001
        log.info("signal %d received, shutting down", signum)
        stop.set()
        # Unblock accept() by closing the server socket.
        try:
            server.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    try:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                if stop.is_set():
                    break
                raise
            threading.Thread(
                target=_handle_client, args=(conn, upstream), daemon=True,
            ).start()
    finally:
        try:
            server.close()
        except OSError:
            pass
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass
        log.info("shut down")
    return 0


if __name__ == "__main__":
    sys.exit(_daemon_main())
