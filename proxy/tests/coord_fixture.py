"""Provision the Python-owned Coord fixture for Rust integration tests.

The fixture uses the same pinned NATS runtime and SQLite store as the Stage-0
Coord acceptance lane. It remains alive until its caller requests teardown so
the ordinary Rust suite can exercise both cross-version state and wait cleanup.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

ROLLBACK_ROOM = "coord-rollback-room"
ROLLBACK_AGENT = "ag-11111111111111111111111111111111"
SHUTDOWN_ROOM = "coord-shutdown-room"
SHUTDOWN_AGENT = "ag-alice"
INITIAL_CAPABILITIES = ["python:initial", "python:shared"]
FINAL_CAPABILITIES = ["python:final", "python:shared"]
NATIVE_CAPABILITIES = ["rust:native", "rust:shared"]
FIXTURE_STOP_TIMEOUT_S = 15.0


def fixture_root() -> Path:
    """Return the isolated Coord directory required by the pinned runtime."""
    configured_root = os.environ.get("SAFEYOLO_COORD_DATA_DIR")
    if not configured_root:
        raise RuntimeError("SAFEYOLO_COORD_DATA_DIR must name an isolated fixture directory")
    root = Path(configured_root)
    if not root.is_absolute():
        raise RuntimeError("SAFEYOLO_COORD_DATA_DIR must be an absolute path")
    if not os.environ.get("SAFEYOLO_NATS_TEST_INSTANCE"):
        raise RuntimeError("SAFEYOLO_NATS_TEST_INSTANCE must name the test-owned NATS server")
    return root.resolve(strict=False)


def fixture_path(root: Path, name: str) -> Path:
    """Return a fixture control path without permitting writes outside root."""
    path = (root / name).resolve(strict=False)
    if root not in path.parents:
        raise RuntimeError(f"fixture control path must remain under {root}")
    return path


def coord_modules() -> tuple[Any, Any, Any]:
    """Load Coord from this checkout after selecting the isolated environment."""
    repository_root = Path(__file__).resolve().parents[2]
    # The fixture is a standalone workflow helper, so import the candidate's
    # source tree only after the caller has selected its test-owned state path.
    sys.path.insert(0, str(repository_root / "cli" / "src"))
    from safeyolo.coord import api, nats_client, nats_runtime

    return api, nats_client, nats_runtime


def sha256(path: Path) -> str:
    """Return the content identity recorded in the synthetic fixture manifest."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


async def create_rooms(api: Any) -> tuple[str, str]:
    """Create the retained declaration and shutdown rooms on one NATS loop."""
    rollback_room_id = await api.create_room(ROLLBACK_ROOM)
    shutdown_room_id = await api.create_room(SHUTDOWN_ROOM)
    return rollback_room_id, shutdown_room_id


def prepare_fixture(root: Path, ready_path: Path) -> None:
    """Start pinned NATS and write the durable inputs consumed by Rust tests."""
    api, nats_client, nats_runtime = coord_modules()
    # nats_root validates the instance token and rejects an operator-home path
    # before the fixture can inspect or create any selected state.
    nats_runtime.nats_root()
    if root.exists() and any(root.iterdir()):
        raise RuntimeError(f"fixture directory must be empty before setup: {root}")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)

    try:
        nats_pid = nats_runtime.start_server(ready_timeout=8.0)
        nats_client.reset_for_tests()
        instance_id = api.bootstrap()
        rollback_room_id, shutdown_room_id = asyncio.run(create_rooms(api))
        api.grant(
            ROLLBACK_ROOM,
            "agent",
            ROLLBACK_AGENT,
            ["receive"],
            operation_id="proxy-rust-fixture-rollback-grant",
        )
        api.declare_capabilities(
            ROLLBACK_ROOM,
            ROLLBACK_AGENT,
            INITIAL_CAPABILITIES,
            ttl_seconds=900,
        )
        api.grant(
            SHUTDOWN_ROOM,
            "agent",
            SHUTDOWN_AGENT,
            ["receive"],
            operation_id="proxy-rust-fixture-shutdown-grant",
        )
        fixture_json = fixture_path(root, "fixture.json")
        write_json(
            fixture_json,
            {
                "agent_id": ROLLBACK_AGENT,
                "db_sha256_initial": sha256(root / "v0.db"),
                "initial_capabilities": INITIAL_CAPABILITIES,
                "instance_id": instance_id,
                "nats_binary_sha256": sha256(nats_runtime.nats_binary_path()),
                "nats_pid": nats_pid,
                "nats_url": nats_runtime.client_url(),
                "nats_version": nats_runtime.NATS_VERSION,
                "rollback_room_id": rollback_room_id,
                "room_id": shutdown_room_id,
                "room_name": ROLLBACK_ROOM,
                "shutdown_agent_id": SHUTDOWN_AGENT,
                "shutdown_room_name": SHUTDOWN_ROOM,
            },
        )
        ready_path.touch()
        print(
            json.dumps(
                {
                    "fixture": "ready",
                    "nats_pid": nats_pid,
                    "room_id": shutdown_room_id,
                }
            ),
            flush=True,
        )
        wait_for_native_generation(root, nats_runtime, api)
    finally:
        try:
            nats_client.reset_for_tests()
        finally:
            nats_runtime.stop_server()
        fixture_path(root, "fixture.stopped").touch()


def native_generation(path: Path) -> dict[str, Any] | None:
    """Read a complete native handoff, tolerating only its truncate/write race."""
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # Rust writes this small handoff directly; retry only the observable
        # truncate/write race instead of accepting malformed state.
        return None
    if not isinstance(value, dict):
        raise RuntimeError("native fixture generation must be a JSON object")
    if value.get("capabilities") != NATIVE_CAPABILITIES:
        raise RuntimeError("native fixture generation has unexpected capabilities")
    return value


def pause_before_deadline(deadline: float, message: str) -> None:
    """Sleep for the bounded polling interval or report the caller's timeout."""
    if time.monotonic() >= deadline:
        raise TimeoutError(message)
    time.sleep(0.05)


def wait_for_stop(stop_path: Path) -> None:
    """Keep the fixture alive until its workflow owner requests teardown."""
    while not stop_path.exists():
        time.sleep(0.05)


def wait_for_native_generation(root: Path, nats_runtime: Any, api: Any) -> None:
    """Publish the retained Python response, then wait for explicit teardown."""
    stop_path = fixture_path(root, "fixture.stop")
    native_written = fixture_path(root, "native-written.json")
    deadline = time.monotonic() + 900
    while not stop_path.exists():
        value = native_generation(native_written)
        if value is not None:
            break
        pause_before_deadline(deadline, "native cross-version witness did not write its generation")
    else:
        return

    api.declare_capabilities(
        ROLLBACK_ROOM,
        ROLLBACK_AGENT,
        FINAL_CAPABILITIES,
        ttl_seconds=900,
    )
    write_json(
        fixture_path(root, "python-updated.json"),
        {
            "capabilities": FINAL_CAPABILITIES,
            "db_sha256": sha256(root / "v0.db"),
            "native_generation": value,
            "nats_version": nats_runtime.NATS_VERSION,
        },
    )
    print(json.dumps({"fixture": "updated"}), flush=True)
    wait_for_stop(stop_path)


def stop_fixture(root: Path) -> None:
    """Ask the fixture owner to stop NATS and wait for its stop receipt."""
    _, _, nats_runtime = coord_modules()
    nats_runtime.nats_root()
    if not root.exists():
        return

    stopped_path = fixture_path(root, "fixture.stopped")
    if stopped_path.is_file():
        return
    fixture_path(root, "fixture.stop").touch()
    deadline = time.monotonic() + FIXTURE_STOP_TIMEOUT_S
    while not stopped_path.is_file():
        if time.monotonic() >= deadline:
            # If the owner died, attempt the runtime's ownership-verified
            # cleanup. Never report a missing receipt as a clean stop.
            nats_runtime.stop_server()
            raise TimeoutError(f"fixture owner did not confirm NATS shutdown: {stopped_path}")
        time.sleep(0.05)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision the test-owned Python Coord fixture for Rust tests.")
    parser.add_argument(
        "--ready-file",
        type=Path,
        help="write this file below SAFEYOLO_COORD_DATA_DIR after fixture setup",
    )
    parser.add_argument(
        "--teardown",
        action="store_true",
        help="request owner-verified fixture shutdown and wait for its stop receipt",
    )
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
        requested_ready_path = arguments.ready_file.resolve(strict=False)
        if root not in requested_ready_path.parents:
            raise RuntimeError("--ready-file must remain below SAFEYOLO_COORD_DATA_DIR")
        ready_path = requested_ready_path
    prepare_fixture(root, ready_path)


if __name__ == "__main__":
    main()
