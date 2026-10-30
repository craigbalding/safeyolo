"""Regression coverage for the native Rust Coord workflow fixture."""

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
def running_coord_fixture(tmp_path: Path, _binary_cache: Path):
    """Start the one fixture that the ordinary Rust workflow starts."""
    root = tmp_path / "coord-fixture"
    ready_path = root / "fixture.ready"
    environment = os.environ.copy()
    environment.update(
        {
            "SAFEYOLO_COORD_FIXTURE_ROOT": str(root),
            "SAFEYOLO_NATS_TEST_INSTANCE": f"proxy-rust-{secrets.token_hex(8)}",
            "SAFEYOLO_COORD_NATS_BINARY": str(_binary_cache),
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
    try:
        wait_for_path(ready_path, process)
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
        assert not (root / "data/coord/nats/process.json").exists()


def test_fixture_creates_current_native_state(running_coord_fixture, _binary_cache: Path) -> None:
    """The shared shutdown fixture uses native bootstrap, create and grant."""
    root, environment, process = running_coord_fixture
    coord = root / "data/coord"
    fixture = json.loads((coord / "fixture.json").read_text(encoding="utf-8"))
    assert fixture["shutdown_room_name"] == "coord-shutdown-room"
    assert fixture["shutdown_agent_id"] == "ag-alice"
    assert fixture["room_id"].startswith("rm-")
    assert fixture["nats_version"] == "2.14.5"
    assert fixture["nats_binary_sha256"] == sha256(_binary_cache.read_bytes()).hexdigest()
    assert Path(fixture["nats_binary"]).read_bytes() == _binary_cache.read_bytes()
    assert (coord / "nats/creds").is_file()
    endpoints = json.loads((coord / "nats/test-endpoints.json").read_text(encoding="utf-8"))
    assert endpoints["pid"] == fixture["nats_pid"]
    assert endpoints["client_port"] != 4222
    assert endpoints["monitor_port"] != 8222

    with sqlite3.connect(coord / "v0.db") as connection:
        shutdown = connection.execute(
            """SELECT r.room_id, m.permissions
               FROM rooms AS r
               JOIN memberships AS m ON m.room_id = r.room_id
               WHERE r.name = ? AND m.principal_kind = 'agent'
                 AND m.principal_id = ? AND m.revoked_at IS NULL""",
            (fixture["shutdown_room_name"], fixture["shutdown_agent_id"]),
        ).fetchone()
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        instance = connection.execute("SELECT id FROM instance").fetchone()
        pending = connection.execute(
            "SELECT COUNT(*) FROM coord_outbox WHERE destination='audit-jsonl' AND delivered_at IS NULL"
        ).fetchone()[0]
    assert shutdown == (fixture["room_id"], "receive")
    assert instance == (fixture["instance_id"],)
    assert {"coord_signals", "coord_signal_revisions", "coord_work"} <= tables
    assert pending == 0
    audit = [json.loads(line) for line in (root / "logs/audit.jsonl").read_text().splitlines()]
    grants = [row for row in audit if row["event"] == "coord.membership_granted"]
    assert len(grants) == 2
    assert grants[1]["details"]["operation_id"] == "proxy-rust-fixture-shutdown-grant"
    assert not (root / "data/ready.json").exists()
    assert process.poll() is None
    assert not (root / "native-written.json").exists()


def test_teardown_waits_for_the_fixture_owner(running_coord_fixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second process requests shutdown without stopping the owner's child."""
    root, environment, process = running_coord_fixture
    monkeypatch.setenv("SAFEYOLO_COORD_FIXTURE_ROOT", str(root))
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", environment["SAFEYOLO_NATS_TEST_INSTANCE"])

    def reject_cross_process_stop(*_arguments) -> None:
        pytest.fail("teardown stopped the fixture owner's NATS child")

    monkeypatch.setattr(coord_fixture, "native", reject_cross_process_stop)
    coord_fixture.stop_fixture(root)
    assert process.wait(timeout=15) == 0
    assert (root / "fixture.stopped").is_file()
    assert not (root / "data/coord/nats/process.json").exists()


def test_teardown_reports_a_missing_owner_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing owner receipt triggers bounded verified cleanup, not success."""
    root = tmp_path / "owner-exited"
    root.mkdir()
    monkeypatch.setenv("SAFEYOLO_COORD_FIXTURE_ROOT", str(root))
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", f"proxy-rust-{secrets.token_hex(8)}")
    monkeypatch.setattr(coord_fixture, "FIXTURE_STOP_TIMEOUT_S", 0.0)
    cleanup_calls: list[bool] = []
    monkeypatch.setattr(coord_fixture, "native", lambda *_arguments: cleanup_calls.append(True))

    with pytest.raises(TimeoutError, match="fixture owner did not confirm NATS shutdown"):
        coord_fixture.stop_fixture(root)
    assert cleanup_calls == [True]
    assert (root / "fixture.stop").is_file()
    assert not (root / "fixture.stopped").exists()


def test_fixture_rejects_an_unowned_nats_environment(tmp_path: Path) -> None:
    """The helper must fail before it can touch a default Coord directory."""
    root = tmp_path / "unowned-coord-fixture"
    environment = os.environ.copy()
    environment["SAFEYOLO_COORD_FIXTURE_ROOT"] = str(root)
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
            "SAFEYOLO_COORD_FIXTURE_ROOT": str(root),
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
    assert not (root / "data/coord/nats/process.json").exists()


def test_fixture_refuses_an_operator_home_coord_directory(tmp_path: Path) -> None:
    """The helper validates the runtime boundary before touching the root."""
    home = tmp_path / "operator-home"
    root = home / ".safeyolo"
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "SAFEYOLO_COORD_FIXTURE_ROOT": str(root),
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


def test_fixture_rejects_a_tampered_shared_binary(tmp_path: Path) -> None:
    """The shared executable must pass the runtime's pinned checksum check."""
    root = tmp_path / "tampered-coord-fixture"
    marker = tmp_path / "executed"
    binary = tmp_path / "nats-server"
    binary.write_text('#!/bin/sh\ntouch "$SAFEYOLO_TEST_BINARY_MARKER"\n', encoding="utf-8")
    binary.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "SAFEYOLO_COORD_FIXTURE_ROOT": str(root),
            "SAFEYOLO_NATS_TEST_INSTANCE": f"proxy-rust-{secrets.token_hex(8)}",
            "SAFEYOLO_COORD_NATS_BINARY": str(binary),
            "SAFEYOLO_TEST_BINARY_MARKER": str(marker),
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
    assert "reviewed platform pin" in result.stderr
    assert not marker.exists()
    assert not (root / "fixture.ready").exists()
    assert (root / "fixture.stopped").is_file()
    assert not (root / "data/coord/nats/process.json").exists()



def test_fixture_reports_setup_proxy_failure_and_cleans_nats(tmp_path: Path, _binary_cache: Path) -> None:
    """A failed audit-delivery owner leaves its diagnostics and stops NATS."""
    root = tmp_path / "failed-setup-proxy"
    proxy = tmp_path / "failed-proxy"
    proxy.write_text("#!/bin/sh\nprintf 'setup proxy refused\\n' >&2\nexit 7\n", encoding="utf-8")
    proxy.chmod(0o755)
    result = subprocess.run(
        [sys.executable, str(FIXTURE)], cwd=REPOSITORY_ROOT,
        env={**os.environ, "SAFEYOLO_COORD_FIXTURE_ROOT": str(root),
             "SAFEYOLO_NATS_TEST_INSTANCE": "failed-setup-proxy",
             "SAFEYOLO_COORD_NATS_BINARY": str(_binary_cache), "SAFEYOLO_RUST_PROXY": str(proxy)},
        capture_output=True, text=True, check=False, timeout=15,
    )
    assert result.returncode != 0
    assert "setup audit delivery failed" in result.stderr
    assert (root / "setup-proxy.log").read_text() == "setup proxy refused\n"
    assert (root / "fixture.stopped").is_file()
    assert not (root / "fixture.ready").exists()
    assert not (root / "data/coord/nats/process.json").exists()


def test_runner_exposes_the_fixture_only_to_coord_test_binaries(tmp_path: Path) -> None:
    """The ordinary suite keeps its own Coord state outside the shutdown tests."""
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

    coord_probe = tmp_path / "coord_wait_shutdown-probe"
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
    setup = workflow.index("- name: Start the native Coord fixture")
    test = workflow.index("- name: Test the Rust proxy")
    teardown = workflow.index("- name: Stop the native Coord fixture")
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
    setup = workflow.index("- name: Start the native Coord fixture")
    test = workflow.index("- name: Test the Rust proxy")
    teardown = workflow.index("- name: Stop the native Coord fixture")
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


def test_cargo_uses_coord_runner_with_the_producers_implicit_host_target(tmp_path, monkeypatch):
    """Observe actual Cargo test outputs and runner isolation without --target."""
    monkeypatch.setenv("SAFEYOLO_CARGO_RESERVE_GIB", "1024")
    (tmp_path / "tests").mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="coord-runner-probe"\nversion="0.1.0"\nedition="2024"\n',
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="coord-runner-probe"\nversion="0.1.0"\n',
    )
    (tmp_path / "tests/coord_wait_shutdown.rs").write_text(
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
                   # This tiny dependency-free crate must not inherit a product build's reserve.
                   "SAFEYOLO_CARGO_RESERVE_GIB": "1",
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
