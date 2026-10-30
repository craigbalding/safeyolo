"""Provision current native Coord state for the Rust shutdown tests.

The native CLI owns bootstrap, the pinned NATS runtime, room creation, grants
and verified shutdown. The fixture stays alive until its caller requests teardown.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path

SHUTDOWN_ROOM = "coord-shutdown-room"
SHUTDOWN_AGENT = "ag-alice"
FIXTURE_STOP_TIMEOUT_S = 15.0


def fixture_root() -> Path:
    """Require an isolated native instance root and dynamic test endpoints."""
    configured_root = os.environ.get("SAFEYOLO_COORD_FIXTURE_ROOT")
    if not configured_root:
        raise RuntimeError("SAFEYOLO_COORD_FIXTURE_ROOT must name an isolated fixture directory")
    root = Path(configured_root)
    if not root.is_absolute():
        raise RuntimeError("SAFEYOLO_COORD_FIXTURE_ROOT must be an absolute path")
    if not os.environ.get("SAFEYOLO_NATS_TEST_INSTANCE"):
        raise RuntimeError("SAFEYOLO_NATS_TEST_INSTANCE must name the test-owned NATS server")
    root = root.resolve(strict=False)
    operator_root = (Path.home() / ".safeyolo").resolve(strict=False)
    if root == operator_root or operator_root in root.parents:
        raise RuntimeError("Coord tests cannot use state under the operator's ~/.safeyolo")
    return root


def fixture_path(root: Path, name: str) -> Path:
    """Return a fixture control path without permitting writes outside root."""
    path = (root / name).resolve(strict=False)
    if root not in path.parents:
        raise RuntimeError(f"fixture control path must remain under {root}")
    return path


def native(root: Path, *arguments: str) -> str:
    """Run the maintained CLI and retain useful diagnostics on failure."""
    default = Path(__file__).resolve().parents[1] / "target/release/safeyolo"
    binary = os.environ.get("SAFEYOLO_NATIVE_CLI", str(default))
    result = subprocess.run(
        [binary, "--root", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    if result.returncode:
        raise RuntimeError(f"native {' '.join(arguments)} exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def drain_setup_audits(root: Path) -> None:
    """Deliver native membership audits before the two shutdown owners start."""
    default = Path(__file__).resolve().parents[1] / "target/release/safeyolo-proxy"
    binary = os.environ.get("SAFEYOLO_RUST_PROXY", str(default))
    log_path = root / "setup-proxy.log"
    with log_path.open("w", encoding="utf-8") as log:
        proxy = subprocess.Popen([binary, "--config", str(root / "config.toml")], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            with sqlite3.connect(root / "data/coord/v0.db") as connection:
                while connection.execute(
                    "SELECT COUNT(*) FROM coord_outbox WHERE destination='audit-jsonl' AND delivered_at IS NULL"
                ).fetchone()[0]:
                    if proxy.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(f"setup audit delivery failed; inspect {log_path}")
                    time.sleep(0.05)
        finally:
            if proxy.poll() is None:
                proxy.terminate()
            try:
                status = proxy.wait(timeout=15)
            except subprocess.TimeoutExpired:
                # This is our Popen child, not a PID recovered from disk.
                proxy.kill()
                proxy.wait(timeout=5)
                raise
        if status:
            raise RuntimeError(f"setup proxy exited {status}; inspect {log_path}")


def prepare_fixture(root: Path, ready_path: Path) -> None:
    """Create the current native store and one receive-only shutdown room."""
    if root.exists() and any(root.iterdir()):
        raise RuntimeError(f"fixture directory must be empty before setup: {root}")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    coord = root / "data/coord"
    try:
        native(root, "init")
        (root / "config.toml").write_text("admin_port=0\nflow_store_enabled=false\n", encoding="utf-8")
        (root / "policy.toml").write_text(f"[agents.alice]\nagent_id='{SHUTDOWN_AGENT}'\n", encoding="utf-8")
        start = ["coord", "start"]
        if selected_binary := os.environ.get("SAFEYOLO_COORD_NATS_BINARY"):
            start.extend(["--binary", selected_binary])
        owner = json.loads(native(root, *start))
        room = json.loads(native(root, "coord", "room", "create", SHUTDOWN_ROOM))
        native(root, "coord", "grant", SHUTDOWN_ROOM, "alice", "receive",
               "--operation-id", "proxy-rust-fixture-shutdown-grant")
        drain_setup_audits(root)
        binary = coord / "nats/bin/2.14.5/nats-server"
        fixture = {
            "instance_id": (coord / "instance_id").read_text(encoding="utf-8").strip(),
            "nats_binary": str(binary),
            "nats_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "nats_pid": owner["pid"],
            "nats_version": "2.14.5",
            "room_id": room["room_id"],
            "shutdown_agent_id": SHUTDOWN_AGENT,
            "shutdown_room_name": SHUTDOWN_ROOM,
        }
        (coord / "fixture.json").write_text(json.dumps(fixture, sort_keys=True) + "\n", encoding="utf-8")
        ready_path.touch()
        print(json.dumps({"fixture": "ready", "nats_pid": owner["pid"], "room_id": room["room_id"]}), flush=True)
        stop_path = fixture_path(root, "fixture.stop")
        while not stop_path.exists():
            time.sleep(0.05)
    finally:
        if coord.exists():
            native(root, "coord", "stop")
        fixture_path(root, "fixture.stopped").touch()


def stop_fixture(root: Path) -> None:
    """Ask the fixture owner to stop NATS and wait for its stop receipt."""
    if not root.exists():
        return
    stopped_path = fixture_path(root, "fixture.stopped")
    if stopped_path.is_file():
        return
    fixture_path(root, "fixture.stop").touch()
    deadline = time.monotonic() + FIXTURE_STOP_TIMEOUT_S
    while not stopped_path.is_file():
        if time.monotonic() >= deadline:
            # An absent owner cannot confirm cleanup. Try the native runtime's
            # ownership-verified stop, but still report the missing receipt.
            native(root, "coord", "stop")
            raise TimeoutError(f"fixture owner did not confirm NATS shutdown: {stopped_path}")
        time.sleep(0.05)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision the test-owned native Coord fixture for Rust tests.")
    parser.add_argument("--ready-file", type=Path, help="write this file below SAFEYOLO_COORD_FIXTURE_ROOT after setup")
    parser.add_argument("--teardown", action="store_true", help="request verified shutdown and wait for the owner receipt")
    return parser.parse_args()


def main() -> None:
    """Run fixture setup or explicit teardown from the selected environment."""
    arguments = parse_arguments()
    root = fixture_root()
    if arguments.teardown:
        if arguments.ready_file is not None:
            raise RuntimeError("--ready-file cannot be combined with --teardown")
        stop_fixture(root)
        return
    ready_path = fixture_path(root, "fixture.ready")
    if arguments.ready_file is not None:
        ready_path = fixture_path(root, str(arguments.ready_file))
    prepare_fixture(root, ready_path)


if __name__ == "__main__":
    main()
