"""Host-side UDS -> TCP bridge for SafeYolo on Linux.

mitmproxy listens on TCP (127.0.0.1:<proxy_port>). Agent containers
can't reach host TCP directly — with the UDS-only architecture they
have no external network interface at all.

Multi-tenant design: each agent gets its OWN per-agent socket at
<data>/sockets/<name>.sock, bind-mounted into its container as
/safeyolo/proxy.sock. The bridge listens on every registered agent's
socket and stamps agent identity by the listener fd that accept()'d
the connection — no identity claims ever come from the guest.

Identity flows to mitmproxy via the upstream TCP *source* address:
each agent is allocated a synthetic loopback IP (127.0.0.<idx+2>),
and the bridge binds its upstream socket to that IP before connecting
to mitmproxy on 127.0.0.1:<proxy_port>. The existing service_discovery
addon maps src_ip -> agent_name, so attribution works unchanged.

Lifecycle:
  - start_proxy_bridge() — spawn as a detached subprocess, write PID file
  - stop_proxy_bridge() — SIGTERM, cleanup all per-agent sockets
Called from proxy.py's start_proxy and lifecycle.py's stop_all.

The daemon watches ~/.safeyolo/data/agent_map.json for add/remove
events (poll every 1s) and brings listeners up/down in lockstep.
"""
from __future__ import annotations

import itertools
import json
import logging
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

log = logging.getLogger("safeyolo.proxy_bridge")

# SAFEYOLO_VM_DEBUG gates high-frequency per-flow accept lines.
# `done` + error lines are always logged — they carry byte counts,
# duration, and error context that are load-bearing for debugging.
_DEBUG_ENABLED = os.environ.get("SAFEYOLO_VM_DEBUG", "").lower() in ("1", "true")

# Monotonic flow counter — stamps each accept/done pair so cross-hop
# logs grep together.
_flow_counter = itertools.count(1)


def _get_data_dir() -> Path:
    """Lazy import so daemon mode doesn't need the safeyolo package."""
    from .config import get_data_dir as _impl  # noqa: PLC0415
    return _impl()


def _get_agent_map_path() -> Path:
    from .config import get_agent_map_path as _impl  # noqa: PLC0415
    return _impl()


def _get_sockets_dir() -> Path:
    from .config import get_bridge_sockets_dir as _impl  # noqa: PLC0415
    return _impl()


# ---------------------------------------------------------------------------
# Lifecycle helpers (called from proxy.py / lifecycle.py)
# ---------------------------------------------------------------------------


def sockets_dir() -> Path:
    """Directory containing per-agent listener sockets."""
    return _get_sockets_dir()


def _pid_file() -> Path:
    return _get_data_dir() / "proxy-bridge.pid"


def socket_path_for(name: str) -> Path:
    """Host-side bridge socket for an agent. Bind-mounted into the
    container as /safeyolo/proxy.sock."""
    return sockets_dir() / f"{name}.sock"


def start_proxy_bridge(proxy_port: int = 8080) -> None:
    """Spawn the UDS -> TCP bridge as a detached subprocess.

    Idempotent: re-running is a no-op if the bridge is already live.
    """
    if is_bridge_running():
        log.info("proxy bridge already running")
        return

    data_dir = _get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    socks = sockets_dir()
    socks.mkdir(parents=True, exist_ok=True)
    # 0700: only the operator needs to list/traverse the sockets dir.
    # The gVisor gofer runs as root with DAC_OVERRIDE and reaches the
    # per-socket paths directly via the bind-mount source path, so it
    # does not need directory-read rights here.
    os.chmod(socks, 0o700)

    # Clean up any stale per-agent sockets from a previous run.
    # PID file check above is the authoritative liveness signal.
    for f in socks.glob("*.sock"):
        try:
            f.unlink()
        except OSError:
            # Socket already gone, or permissions changed out from under us;
            # we tried, move on — bind() below will surface any real problem.
            pass

    log_file = data_dir.parent / "logs" / "proxy-bridge.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "safeyolo.proxy_bridge",
        str(socks),
        str(_get_agent_map_path()),
        f"127.0.0.1:{proxy_port}",
    ]
    with open(log_file, "a") as lf:
        proc = subprocess.Popen(
            cmd, stdout=lf, stderr=lf,
            start_new_session=True,
        )

    _pid_file().write_text(str(proc.pid))
    log.info("proxy bridge started (PID %d), sockets dir %s", proc.pid, socks)


def stop_proxy_bridge() -> None:
    """SIGTERM the bridge, clean up its sockets + PID file."""
    pid_file = _pid_file()
    if not pid_file.exists():
        _cleanup_sockets()
        return

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
        _cleanup_sockets()
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        _cleanup_sockets()
        return

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
            # Process exited between our liveness poll and SIGKILL —
            # exactly the state we wanted, nothing to do.
            pass

    pid_file.unlink(missing_ok=True)
    _cleanup_sockets()
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


def _cleanup_sockets() -> None:
    try:
        socks = sockets_dir()
    except Exception:
        # Config lookup failed (missing env, torn-down home dir). Nothing
        # to clean if we can't even find the directory.
        return
    if not socks.exists():
        return
    for f in socks.glob("*.sock"):
        try:
            f.unlink()
        except OSError:
            # Best-effort cleanup — perms or concurrent removal shouldn't
            # fail the overall stop. Any leftover file will be unlinked
            # by the next bridge start (which clears stale sockets).
            pass


# ---------------------------------------------------------------------------
# Daemon — runs when this module is executed as a script
# ---------------------------------------------------------------------------


def _forward(src: socket.socket, dst: socket.socket, counter: list[int]) -> None:
    """Copy src -> dst until EOF, then half-close dst's write side.

    `counter` is a single-element list used as an out-param for the
    byte count — threading makes returning a value awkward, and a
    list lets the caller read it after .join().
    """
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            counter[0] += len(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        # Either end hung up mid-stream. Normal during client disconnects
        # (agent CLI ^C, mitmproxy restart). Let the finally block half-close
        # the other side so its pump thread exits cleanly.
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            # Peer socket may already be closed — the shutdown is just a
            # signal for the opposite-direction thread to notice EOF.
            pass


def _handle_client(
    uds_conn: socket.socket,
    upstream: tuple[str, int],
    attribution_ip: str,
    agent: str,
) -> None:
    """Pump one agent->mitmproxy TCP flow.

    Binds the upstream TCP socket's source to the agent's synthetic
    loopback address before connecting. mitmproxy sees src=attribution_ip
    and service_discovery maps that back to the agent name.
    """
    flow = next(_flow_counter)
    started = time.monotonic()
    log_ = logging.getLogger(__name__)

    if _DEBUG_ENABLED:
        log_.info("accept flow=%d agent=%s src=uds upstream=%s:%d",
                  flow, agent, upstream[0], upstream[1])

    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((attribution_ip, 0))
        tcp.settimeout(5)
        tcp.connect(upstream)
        tcp.settimeout(None)
    except OSError as exc:
        log_.warning(
            "flow=%d agent=%s upstream %s:%d from %s connect failed: %s: %s",
            flow, agent, upstream[0], upstream[1], attribution_ip,
            type(exc).__name__, exc,
        )
        uds_conn.close()
        return

    # Single-element lists as out-params so _forward can report bytes
    # without a threading.Queue/Event on the hot path.
    bytes_in: list[int] = [0]   # uds → tcp (agent request)
    bytes_out: list[int] = [0]  # tcp → uds (proxy response)

    t1 = threading.Thread(target=_forward, args=(uds_conn, tcp, bytes_in), daemon=True)
    t2 = threading.Thread(target=_forward, args=(tcp, uds_conn, bytes_out), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    uds_conn.close()
    tcp.close()

    duration_ms = int((time.monotonic() - started) * 1000)
    log_.info("done flow=%d agent=%s bytes_in=%d bytes_out=%d duration_ms=%d",
              flow, agent, bytes_in[0], bytes_out[0], duration_ms)


class _Listener:
    """Bound listening socket for one agent."""
    def __init__(self, name: str, path: Path, ip: str, server: socket.socket):
        self.name = name
        self.path = path
        self.ip = ip
        self.server = server


def _make_listener(name: str, path: Path, ip: str) -> _Listener | None:
    log_ = logging.getLogger(__name__)
    # Stale file from a crashed bridge instance
    try:
        path.unlink()
    except FileNotFoundError:
        # Already absent — exactly what we want before bind().
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
    except OSError as exc:
        log_.error("bind %s failed: %s: %s", path, type(exc).__name__, exc)
        server.close()
        return None

    # 0600: only the operator may connect() here from the host side.
    # The gVisor gofer runs as root with DAC_OVERRIDE so it can still
    # relay connect() calls across the sandbox boundary regardless of
    # mode; the operator is the only non-root principal that should
    # reach this socket directly.
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Mode setting is best-effort; the bind() above already succeeded
        # with the umask-derived default. Don't tear the listener down.
        pass
    server.listen(32)
    server.setblocking(False)
    log_.info("listen agent=%s ip=%s path=%s", name, ip, path)
    return _Listener(name, path, ip, server)


def _read_agent_map(map_path: Path) -> dict[str, dict]:
    """Read agent_map.json, returning empty dict on any failure."""
    try:
        return json.loads(map_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _daemon_main() -> int:
    if len(sys.argv) != 4:
        sys.stderr.write(
            f"Usage: {sys.argv[0]} <sockets_dir> <agent_map_path> "
            "<upstream_host:port>\n"
        )
        return 2

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    log_ = logging.getLogger(__name__)

    socks_dir = Path(sys.argv[1])
    map_path = Path(sys.argv[2])
    host_port = sys.argv[3]
    host, _, port_str = host_port.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        sys.stderr.write(f"Invalid upstream port: {port_str!r}\n")
        return 2
    upstream = (host or "127.0.0.1", port)

    socks_dir.mkdir(parents=True, exist_ok=True)

    sel = selectors.DefaultSelector()
    listeners: dict[str, _Listener] = {}
    stop = threading.Event()

    def _on_signal(signum, frame):  # noqa: ARG001
        log_.info("signal %d received, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    def _sync_listeners() -> None:
        """Reconcile the live listener set against agent_map.json."""
        desired = _read_agent_map(map_path)
        desired_names = set(desired.keys())
        current_names = set(listeners.keys())

        # Remove listeners for agents no longer in the map
        for name in current_names - desired_names:
            lst = listeners.pop(name)
            try:
                sel.unregister(lst.server)
            except KeyError:
                # Selector already forgot about it (double-close race);
                # continue with socket + file cleanup.
                pass
            try:
                lst.server.close()
            except OSError:
                # Already closed elsewhere; the goal is a closed fd.
                pass
            try:
                lst.path.unlink()
            except FileNotFoundError:
                # File is gone (manual cleanup, fs reset); matches our goal.
                pass
            log_.info("closed listener agent=%s", name)

        # Add listeners for new agents
        for name in desired_names - current_names:
            info = desired[name]
            ip = info.get("ip")
            sock_raw = info.get("socket")
            if not ip or not sock_raw:
                continue
            lst = _make_listener(name, Path(sock_raw), ip)
            if lst is None:
                continue
            listeners[name] = lst
            sel.register(lst.server, selectors.EVENT_READ, lst)

        # Handle IP or path change: simpler to rebuild the listener
        for name in desired_names & current_names:
            info = desired[name]
            cur = listeners[name]
            new_ip = info.get("ip")
            new_path = info.get("socket")
            if new_ip == cur.ip and new_path == str(cur.path):
                continue
            # changed — drop and re-add on next tick
            sel.unregister(cur.server)
            try:
                cur.server.close()
            except OSError:
                # Socket already closed; proceed to file cleanup.
                pass
            try:
                cur.path.unlink()
            except FileNotFoundError:
                # Stale path; nothing to remove.
                pass
            listeners.pop(name)

    _sync_listeners()
    log_.info("daemon ready, upstream %s:%d", *upstream)

    last_sync = 0.0
    SYNC_INTERVAL = 1.0

    try:
        while not stop.is_set():
            # Poll selectors with a short timeout so we can periodically
            # reconcile with the map file.
            events = sel.select(timeout=0.5)
            for key, _ in events:
                lst: _Listener = key.data
                try:
                    conn, _ = lst.server.accept()
                except OSError:
                    continue
                # Darwin inherits the listener's O_NONBLOCK flag across
                # accept() — the pump threads' recv() then returns EAGAIN
                # immediately and tears down the flow after the request is
                # sent but before the response arrives. Force blocking on
                # the accepted socket so recv() waits as intended. Harmless
                # on Linux (which doesn't inherit the flag there).
                conn.setblocking(True)
                threading.Thread(
                    target=_handle_client,
                    args=(conn, upstream, lst.ip, lst.name),
                    daemon=True,
                ).start()

            now = time.time()
            if now - last_sync >= SYNC_INTERVAL:
                _sync_listeners()
                last_sync = now
    finally:
        # Daemon shutdown: tear down every live listener. Each cleanup
        # step is best-effort because we're already on the exit path.
        for lst in list(listeners.values()):
            try:
                sel.unregister(lst.server)
            except KeyError:
                # Already unregistered (signal arrived mid-sync).
                pass
            try:
                lst.server.close()
            except OSError:
                # Already closed; fd is released.
                pass
            try:
                lst.path.unlink()
            except FileNotFoundError:
                # File already gone; exactly the desired end state.
                pass
        sel.close()
        log_.info("shut down")
    return 0


if __name__ == "__main__":
    sys.exit(_daemon_main())
