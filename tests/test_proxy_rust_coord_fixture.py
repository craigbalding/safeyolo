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

from proxy.tests import coord_fixture

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPOSITORY_ROOT / "proxy" / "tests" / "coord_fixture.py"
RUNNER = REPOSITORY_ROOT / "proxy" / "tests" / "coord_test_runner.sh"
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
            "from proxy.tests.coord_fixture import coord_modules; "
            "api, _, _ = coord_modules(); "
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


def test_teardown_waits_for_the_fixture_owner(running_coord_fixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second process requests shutdown without stopping the owner's child."""
    from safeyolo.coord import nats_runtime

    root, environment, process = running_coord_fixture
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(root))
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", environment["SAFEYOLO_NATS_TEST_INSTANCE"])

    def reject_cross_process_stop() -> None:
        pytest.fail("teardown stopped the fixture owner's NATS child")

    monkeypatch.setattr(nats_runtime, "stop_server", reject_cross_process_stop)
    coord_fixture.stop_fixture(root)
    assert process.wait(timeout=15) == 0
    assert (root / "fixture.stopped").is_file()
    assert not (root / "nats" / "nats.pid.json").exists()


def test_teardown_reports_a_missing_owner_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing owner receipt triggers bounded verified cleanup, not success."""
    from safeyolo.coord import nats_runtime

    root = tmp_path / "owner-exited"
    root.mkdir()
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(root))
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", f"proxy-rust-{secrets.token_hex(8)}")
    monkeypatch.setattr(coord_fixture, "FIXTURE_STOP_TIMEOUT_S", 0.0)
    cleanup_calls: list[bool] = []
    monkeypatch.setattr(nats_runtime, "stop_server", lambda: cleanup_calls.append(True))

    with pytest.raises(TimeoutError, match="fixture owner did not confirm NATS shutdown"):
        coord_fixture.stop_fixture(root)
    assert cleanup_calls == [True]
    assert (root / "fixture.stop").is_file()
    assert not (root / "fixture.stopped").exists()


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


def test_runner_exposes_the_fixture_only_to_coord_test_binaries(tmp_path: Path) -> None:
    """The ordinary suite keeps its own Coord state outside the two witnesses."""
    probe = tmp_path / "probe"
    probe.write_text(
        '#!/bin/sh\nprintf \'%s\\n%s\\n\' "${SAFEYOLO_COORD_DATA_DIR-}" "${SAFEYOLO_NATS_TEST_INSTANCE-}"\n',
        encoding="utf-8",
    )
    probe.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "SAFEYOLO_COORD_DATA_DIR": "must-not-reach-unrelated-tests",
            "SAFEYOLO_NATS_TEST_INSTANCE": "must-not-reach-unrelated-tests",
            "SAFEYOLO_PROXY_COORD_DATA_DIR": "/workflow-coord-fixture",
            "SAFEYOLO_PROXY_NATS_TEST_INSTANCE": "workflow-fixture",
        }
    )

    coord_probe = tmp_path / "coord_state_cross_version-probe"
    probe.rename(coord_probe)
    coord_result = subprocess.run(
        [str(RUNNER), str(coord_probe)],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=15,
    )
    assert coord_result.returncode == 0, coord_result.stderr
    assert coord_result.stdout == "/workflow-coord-fixture\nworkflow-fixture\n"

    unrelated_probe = tmp_path / "gateway_workflow-probe"
    coord_probe.rename(unrelated_probe)
    unrelated_result = subprocess.run(
        [str(RUNNER), str(unrelated_probe)],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=15,
    )
    assert unrelated_result.returncode == 0, unrelated_result.stderr
    assert unrelated_result.stdout == "\n\n"

    missing_probe = tmp_path / "coord_wait_shutdown-missing-fixture"
    unrelated_probe.rename(missing_probe)
    missing_environment = environment.copy()
    missing_environment.pop("SAFEYOLO_PROXY_COORD_DATA_DIR")
    missing_environment.pop("SAFEYOLO_PROXY_NATS_TEST_INSTANCE")
    missing_result = subprocess.run(
        [str(RUNNER), str(missing_probe)],
        capture_output=True,
        check=False,
        env=missing_environment,
        text=True,
        timeout=15,
    )
    assert missing_result.returncode != 0
    assert "missing workflow Coord fixture directory" in missing_result.stderr


def test_rust_workflow_orders_fixture_setup_and_teardown() -> None:
    """Both matrix platforms run Rust tests between owned fixture steps."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    setup = workflow.index("- name: Start the Python-owned Coord fixture")
    test = workflow.index("- name: Test the Rust proxy")
    teardown = workflow.index("- name: Stop the Python-owned Coord fixture")
    assert setup < test < teardown
    setup_block = workflow[setup:test]
    assert "if: matrix.os == 'ubuntu-latest'" not in setup_block
    assert "coord_fixture.py" in setup_block
    assert "SAFEYOLO_NATS_TEST_INSTANCE" in setup_block
    assert workflow.count("SAFEYOLO_NATS_TEST_INSTANCE: proxy-rust-fixture") == 2
    assert "teardown failed after startup failure" in setup_block
    test_block = workflow[test:teardown]
    assert "export SAFEYOLO_PROXY_COORD_DATA_DIR" in test_block
    assert "export SAFEYOLO_PROXY_NATS_TEST_INSTANCE=proxy-rust-fixture" in test_block
    lint = workflow[workflow.index("      - name: Check Rust formatting and lint", workflow.index("  contracts:")):setup]
    assert 'host_target="$(rustc -vV' in lint
    assert "tr '[:lower:]-' '[:upper:]_'" in lint
    assert "CARGO_TARGET_%s_RUNNER" in lint
    assert "coord_test_runner.sh" in lint
    assert "CARGO_BUILD_TARGET" not in lint + test_block
    assert 'if [ "$RUNNER_OS" = Linux ]; then' not in test_block
    assert "export SAFEYOLO_COORD_DATA_DIR" not in test_block
    assert "export SAFEYOLO_NATS_TEST_INSTANCE" not in test_block
    teardown_block = workflow[teardown:]
    assert "if: always()" in teardown_block
    assert "if: always() && matrix.os == 'ubuntu-latest'" not in teardown_block
    assert "coord_fixture.py --teardown" in teardown_block


def test_rust_workflow_exposes_production_inputs_and_restores_their_dependency_features() -> None:
    """All production and test outputs use the producers' implicit host target."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    compile_production = workflow.index("- name: Compile production native executables")
    compile_tests = workflow.index("- name: Compile Rust contract executables")
    setup = workflow.index("- name: Start the Python-owned Coord fixture")
    test = workflow.index("- name: Test the Rust proxy")
    teardown = workflow.index("- name: Stop the Python-owned Coord fixture")
    assert compile_production < compile_tests < setup < test < teardown
    assert "build --release --locked --bins" in workflow[compile_production:compile_tests]
    assert "test --release --locked --no-run" in workflow[compile_tests:setup]
    test_block = workflow[test:teardown]
    assert test_block.index("cargo_with_space.sh test --release --locked") < test_block.index("cargo_with_space.sh build --release --locked --bins")
    production_block = workflow[compile_production:compile_tests]
    binary = production_block.index('rust_proxy="$GITHUB_WORKSPACE/proxy/target/release/safeyolo-proxy"')
    export = production_block.index('printf \'SAFEYOLO_RUST_PROXY=%s\\n\' "$rust_proxy" >> "$GITHUB_ENV"')
    assert binary < export
    assert 'test -x "$rust_proxy"' in production_block[binary:export]
    assert 'verify_native_artifacts "$SAFEYOLO_NATIVE_ARTIFACTS" guest/command/target/release production' in production_block


def test_cargo_uses_coord_runner_with_the_producers_implicit_host_target(tmp_path):
    """Observe actual Cargo test outputs and runner isolation without --target."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="coord-runner-probe"\nversion="0.1.0"\nedition="2024"\n',
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="coord-runner-probe"\nversion="0.1.0"\n',
    )
    (tmp_path / "tests/coord_state_cross_version.rs").write_text(
        '#[test]\nfn fixture_reaches_coord() {\n'
        'assert_eq!(std::env::var("SAFEYOLO_COORD_DATA_DIR").unwrap(), "owned-fixture");\n'
        'assert_eq!(std::env::var("SAFEYOLO_NATS_TEST_INSTANCE").unwrap(), "owned-instance");\n}\n',
    )
    (tmp_path / "tests/regular.rs").write_text(
        '#[test]\nfn regular_test_stays_isolated() {\n'
        'assert!(std::env::var_os("SAFEYOLO_COORD_DATA_DIR").is_none());\n'
        'assert!(std::env::var_os("SAFEYOLO_NATS_TEST_INSTANCE").is_none());\n}\n',
    )
    version = subprocess.check_output(["rustc", "-vV"], text=True)
    target = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    environment = {**os.environ, "CARGO_TARGET_DIR": str(tmp_path / "target"),
                   "SAFEYOLO_PROXY_COORD_DATA_DIR": "owned-fixture",
                   "SAFEYOLO_PROXY_NATS_TEST_INSTANCE": "owned-instance",
                   f"CARGO_TARGET_{target.upper().replace('-', '_')}_RUNNER": str(RUNNER)}
    environment.pop("CARGO_BUILD_TARGET", None)
    command = [str(REPOSITORY_ROOT / "scripts/cargo_with_space.sh"), "test", "--release", "--locked", "--offline",
               "--manifest-path", str(tmp_path / "Cargo.toml"), "--message-format=json"]
    compiled = subprocess.run([*command, "--no-run"], env=environment, capture_output=True, text=True, timeout=30)
    assert compiled.returncode == 0, compiled.stderr
    outputs = [json.loads(line) for line in compiled.stdout.splitlines()]
    executables = {row["executable"] for row in outputs if row["reason"] == "compiler-artifact" and row["executable"]}
    assert len(executables) == 2
    assert all(Path(path).parent == tmp_path / "target/release/deps" for path in executables)
    executed = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
    assert executed.returncode == 0, executed.stderr + executed.stdout
    assert executed.stdout.count("1 passed; 0 failed") == 2
    artifacts = [json.loads(line) for line in executed.stdout.splitlines() if line.startswith('{"reason":')]
    assert {row["executable"] for row in artifacts if row["reason"] == "compiler-artifact"} == executables
    assert all(row["fresh"] for row in artifacts if row["reason"] == "compiler-artifact")
