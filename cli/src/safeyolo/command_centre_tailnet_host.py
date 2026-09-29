"""Own Command Centre's two explicit Tailnet Serve mappings for one proxy life."""

from __future__ import annotations

import json
import select
import sys
from pathlib import Path

from .tailnet import start_tailnet_serve, write_tailnet_state


def publish(admin_local: int, events_local: int, admin_https: int, events_https: int, state_path: Path) -> int:
    """Publish both routes, report readiness, and close them when the parent exits."""
    admin = None
    events = None
    ready = False
    failed = False
    try:
        admin = start_tailnet_serve(admin_local, admin_https)
        # Keep the WebSocket upgrade on one HTTP/1.1 connection. Tailscale's
        # HTTPS reverse proxy can fail that upgrade while ordinary GET works.
        events = start_tailnet_serve(events_local, events_https, tls_terminated_tcp=True)
        admin_url = admin.url("/")
        events_url = events.url("/admin/events").replace("https://", "wss://", 1)
        write_tailnet_state(state_path, {
            "state": "healthy", "enabled": True,
            "admin_port": admin_https, "events_port": events_https,
            "admin_url": admin_url, "events_url": events_url,
            "admin_pid": admin.process.pid, "events_pid": events.process.pid,
        })
        print(json.dumps({"state": "healthy", "admin_url": admin_url, "events_url": events_url}), flush=True)
        ready = True
        while True:
            if admin.process.poll() is not None or events.process.poll() is not None:
                raise RuntimeError("a Command Centre Tailnet Serve mapping exited")
            readable, _, _ = select.select([sys.stdin], [], [], 0.5)
            if readable and not sys.stdin.buffer.read(1):
                return 0
    except Exception as exc:
        failed = True
        detail = f"{type(exc).__name__}: {exc}"
        try:
            write_tailnet_state(state_path, {"state": "error", "enabled": True, "detail": detail})
        except OSError:
            # The readiness channel still reports the startup failure when
            # the status file itself cannot be written.
            pass
        print(json.dumps({"state": "error", "detail": detail}),
              file=sys.stderr if ready else sys.stdout, flush=True)
        return 1
    finally:
        if events is not None:
            events.close()
        if admin is not None:
            admin.close()
        if not failed:
            state_path.unlink(missing_ok=True)


def main() -> int:
    if len(sys.argv) != 6:
        print(json.dumps({"state": "error", "detail": "invalid publication arguments"}), flush=True)
        return 2
    try:
        admin_local, events_local, admin_https, events_https = map(int, sys.argv[1:5])
    except ValueError:
        print(json.dumps({"state": "error", "detail": "invalid publication ports"}), flush=True)
        return 2
    return publish(admin_local, events_local, admin_https, events_https, Path(sys.argv[5]))


if __name__ == "__main__":
    raise SystemExit(main())
