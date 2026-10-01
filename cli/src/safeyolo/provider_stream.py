"""Pipe one Rust proxy connection through the existing platform port forward."""

import subprocess
import sys
import threading

from .agent_configuration import HOSTNAME_PATTERN
from .platform import get_platform


def _copy_available_bytes(source, target) -> None:
    read = getattr(source, "read1", source.read)
    while chunk := read(64 * 1024):
        remaining = memoryview(chunk)
        while remaining:
            written = target.write(remaining)
            if written is None or written <= 0:
                raise OSError("provider stream stopped accepting bytes")
            remaining = remaining[written:]
        target.flush()


def _close_relay(relay) -> None:
    try:
        relay.wait(timeout=1)
    except subprocess.TimeoutExpired:
        relay.terminate()
        try:
            relay.wait(timeout=2)
        except subprocess.TimeoutExpired:
            relay.kill()
            relay.wait(timeout=2)


def main() -> int:
    try:
        if len(sys.argv) != 3:
            raise ValueError("provider name and port required")
        name = sys.argv[1]
        if len(name) > 63 or not HOSTNAME_PATTERN.fullmatch(name):
            raise ValueError("invalid provider name")
        port = int(sys.argv[2])
        if not 1 <= port <= 65535:
            raise ValueError("invalid guest port")
        platform = get_platform()
        if not platform.is_sandbox_running(name):
            raise RuntimeError("provider sandbox is stopped")
        relay = platform.popen_port_forward(name, port)
        if relay.stdin is None or relay.stdout is None:
            _close_relay(relay)
            raise RuntimeError("provider stream has no byte pipes")
    except (OSError, RuntimeError, ValueError):
        sys.stdout.buffer.write(b"\x00")
        sys.stdout.buffer.flush()
        return 1

    sys.stdout.buffer.write(b"\x01")
    sys.stdout.buffer.flush()

    def upload() -> None:
        try:
            _copy_available_bytes(sys.stdin.buffer, relay.stdin)
        except OSError:
            pass
        finally:
            relay.stdin.close()

    threading.Thread(target=upload, daemon=True).start()
    try:
        _copy_available_bytes(relay.stdout, sys.stdout.buffer)
    except (BrokenPipeError, OSError):
        pass
    finally:
        _close_relay(relay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
