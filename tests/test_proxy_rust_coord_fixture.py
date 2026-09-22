"""Regression coverage for the Python-owned Rust Coord workflow fixture."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import subprocess
import sys
import time
from hashlib import sha256
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPOSITORY_ROOT / "proxy" / "tests" / "coord_fixture.py"
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "proxy-rust.yml"


def wait_for_path(path: Path, process: subprocess.Popen[str]) -> None:
    """Wait for fixture output while surfacing a failed child immediately."""
    deadline = time.monotonic() + 15
    while not path.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise AssertionError(f"fixture exited before writing {path}:\nstdout:\n{stdout}\nstderr:\n{stderr}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"fixture did not write {path} within 15 seconds")
        time.sleep(0.05)


@pytest.fixture
def running_coord_fixture(tmp_path: Path):
    """Start the one fixture that the ordinary Rust workflow starts."""
    root = tmp_path / "coord-fixture"
    ready_path = root / "fixture.ready"
    environment = os.environ.copy()
    environment.update(
        {
            "SAFEYOLO_COORD_DATA_DIR": str(root),
            "SAFEYOLO_NATS_TEST_INSTANCE": f"proxy-rust-{secrets.token_hex(8)}",
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            str(FIXTURE),
            "--ready-file",
            str(ready_path),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for_path(ready_path, process)
    try:
        yield root, environment, process
    finally:
        teardown = subprocess.run(
            [sys.executable, str(FIXTURE), "--teardown"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)
            pytest.fail("fixture process did not stop after teardown")
        stdout, stderr = process.communicate(timeout=1)
        assert teardown.returncode == 0, teardown.stderr
        assert process.returncode == 0, stdout + stderr
        assert (root / "fixture.stopped").is_file()
        assert not (root / "nats" / "nats.pid.json").exists()


def test_fixture_creates_the_shared_nats_and_python_state(running_coord_fixture) -> None:
    """One fixture supplies the retained inputs for both Rust Coord targets."""
    root, environment, process = running_coord_fixture
    fixture = json.loads((root / "fixture.json").read_text(encoding="utf-8"))
    assert fixture["room_name"] == "coord-rollback-room"
    assert fixture["agent_id"] == "ag-11111111111111111111111111111111"
    assert fixture["shutdown_room_name"] == "coord-shutdown-room"
    assert fixture["shutdown_agent_id"] == "ag-alice"
    assert fixture["room_id"].startswith("rm-")
    assert fixture["nats_version"] == "2.14.5"
    assert len(fixture["nats_binary_sha256"]) == 64
    assert (root / "nats" / "creds").is_file()
    endpoints = json.loads((root / "nats" / "test-endpoints.json").read_text(encoding="utf-8"))
    assert endpoints["test_instance"] == environment["SAFEYOLO_NATS_TEST_INSTANCE"]
    assert endpoints["client_port"] != 4222
    assert endpoints["monitor_port"] != 8222

    with sqlite3.connect(root / "v0.db") as connection:
        rollback = connection.execute("SELECT room_id FROM rooms WHERE name = ?", (fixture["room_name"],)).fetchone()
        shutdown = connection.execute(
            """SELECT r.room_id, m.permissions
               FROM rooms AS r
               JOIN memberships AS m ON m.room_id = r.room_id
               WHERE r.name = ? AND m.principal_kind = 'agent'
                 AND m.principal_id = ? AND m.revoked_at IS NULL""",
            (fixture["shutdown_room_name"], fixture["shutdown_agent_id"]),
        ).fetchone()
    assert rollback is not None
    assert shutdown == (fixture["room_id"], "receive")

    # Use a second Python process with the fixture environment. The real Rust
    # test performs this intermediate mutation through its native route.
    native_declaration = subprocess.run(
        [
            sys.executable,
            "-c",
            "from safeyolo.coord import api; "
            "api.declare_capabilities("
            "'coord-rollback-room', 'ag-11111111111111111111111111111111', "
            "['rust:native', 'rust:shared'], ttl_seconds=900)",
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert native_declaration.returncode == 0, native_declaration.stderr
    native_hash = sha256((root / "v0.db").read_bytes()).hexdigest()
    (root / "native-written.json").write_text(
        json.dumps(
            {
                "capabilities": ["rust:native", "rust:shared"],
                "db_sha256": native_hash,
            }
        ),
        encoding="utf-8",
    )
    update_path = root / "python-updated.json"
    wait_for_path(update_path, process)
    update = json.loads(update_path.read_text(encoding="utf-8"))
    assert update["capabilities"] == ["python:final", "python:shared"]
    assert update["native_generation"]["capabilities"] == [
        "rust:native",
        "rust:shared",
    ]
    assert update["native_generation"]["db_sha256"] == native_hash
    assert len(update["db_sha256"]) == 64


def test_fixture_rejects_an_unowned_nats_environment(tmp_path: Path) -> None:
    """The helper must fail before it can touch a default Coord directory."""
    root = tmp_path / "unowned-coord-fixture"
    environment = os.environ.copy()
    environment["SAFEYOLO_COORD_DATA_DIR"] = str(root)
    environment.pop("SAFEYOLO_NATS_TEST_INSTANCE", None)
    result = subprocess.run(
        [sys.executable, str(FIXTURE)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode != 0
    assert "SAFEYOLO_NATS_TEST_INSTANCE" in result.stderr
    assert not root.exists()


def test_fixture_rejects_stale_fixture_state(tmp_path: Path) -> None:
    """A prior fixture's state cannot be mistaken for a fresh NATS owner."""
    root = tmp_path / "stale-coord-fixture"
    root.mkdir()
    stale_marker = root / "fixture.ready"
    stale_marker.write_text("stale\n", encoding="utf-8")
    environment = os.environ.copy()
    environment.update(
        {
            "SAFEYOLO_COORD_DATA_DIR": str(root),
            "SAFEYOLO_NATS_TEST_INSTANCE": "proxy-rust-fixture",
        }
    )
    result = subprocess.run(
        [sys.executable, str(FIXTURE)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode != 0
    assert "fixture directory must be empty before setup" in result.stderr
    assert stale_marker.read_text(encoding="utf-8") == "stale\n"
    assert not (root / "nats" / "nats.pid.json").exists()


def test_fixture_refuses_an_operator_home_coord_directory(tmp_path: Path) -> None:
    """The helper validates the runtime boundary before touching the root."""
    home = tmp_path / "operator-home"
    root = home / ".safeyolo"
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "SAFEYOLO_COORD_DATA_DIR": str(root),
            "SAFEYOLO_NATS_TEST_INSTANCE": "proxy-rust-fixture",
        }
    )
    result = subprocess.run(
        [sys.executable, str(FIXTURE)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode != 0
    assert "operator's ~/.safeyolo" in result.stderr
    assert not root.exists()


def test_fixture_rejects_a_mismatched_native_generation(tmp_path: Path) -> None:
    """A malformed cross-version handoff fails rather than weakening the witness."""
    root = tmp_path / "mismatched-coord-fixture"
    ready_path = root / "fixture.ready"
    environment = os.environ.copy()
    environment.update(
        {
            "SAFEYOLO_COORD_DATA_DIR": str(root),
            "SAFEYOLO_NATS_TEST_INSTANCE": f"proxy-rust-{secrets.token_hex(8)}",
        }
    )
    process = subprocess.Popen(
        [sys.executable, str(FIXTURE), "--ready-file", str(ready_path)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for_path(ready_path, process)
    (root / "native-written.json").write_text(json.dumps({"capabilities": ["wrong:fixture"]}), encoding="utf-8")
    process.wait(timeout=15)
    stdout, stderr = process.communicate(timeout=1)
    assert process.returncode != 0, stdout + stderr
    assert "unexpected capabilities" in stderr
    assert (root / "fixture.stopped").is_file()
    assert not (root / "nats" / "nats.pid.json").exists()


def test_rust_workflow_orders_fixture_setup_and_teardown() -> None:
    """The ordinary Rust test step must run between fixture ownership steps."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    setup = workflow.index("- name: Start the Python-owned Coord fixture")
    test = workflow.index("- name: Test and build the Rust proxy")
    teardown = workflow.index("- name: Stop the Python-owned Coord fixture")
    assert setup < test < teardown
    setup_block = workflow[setup:test]
    assert "if: matrix.os == 'ubuntu-latest'" in setup_block
    assert "coord_fixture.py" in setup_block
    assert "SAFEYOLO_NATS_TEST_INSTANCE" in setup_block
    assert workflow.count("SAFEYOLO_NATS_TEST_INSTANCE: proxy-rust-fixture") == 2
    assert "teardown failed after startup failure" in setup_block
    test_block = workflow[test:teardown]
    assert 'if [ "$RUNNER_OS" = Linux ]; then' in test_block
    assert "export SAFEYOLO_NATS_TEST_INSTANCE=proxy-rust-fixture" in test_block
    teardown_block = workflow[teardown:]
    assert "if: always() && matrix.os == 'ubuntu-latest'" in teardown_block
    assert "coord_fixture.py --teardown" in teardown_block
