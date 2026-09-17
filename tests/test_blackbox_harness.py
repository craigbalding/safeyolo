"""Regression tests for blackbox harness isolation and backend selection."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.blackbox.proxy_backend import SelectionError, identity, validate_python_source
from tests.proxy_migration.harness import REPO, python_proxy_command, python_proxy_environment


def test_harness_assigns_distinct_proxy_admin_and_web_ports():
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "TEST_PROXY_PORT=8180" in harness
    assert "TEST_ADMIN_PORT=9190" in harness
    assert "TEST_WEB_PORT=8181" in harness
    assert "config['proxy']['port'] = $TEST_PROXY_PORT" in harness
    assert "config['proxy']['admin_port'] = $TEST_ADMIN_PORT" in harness
    assert "config['proxy']['web_port'] = $TEST_WEB_PORT" in harness


def test_runner_cleanup_only_reclaims_owned_sinkhole_processes():
    """The compatibility lane must not kill unrelated process names."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "pkill" not in runner
    assert 'SINKHOLE_PID_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.pid"' in runner
    assert (
        'stop_owned_pid_file "$SINKHOLE_PID_FILE" "$SCRIPT_DIR/sinkhole/server.py"'
        in runner
    )
    assert 'printf \'%s\\n\' "$SINKHOLE_PID" > "$SINKHOLE_PID_FILE"' in runner
    assert 'kill "$HOST_LISTENER_PID"' in runner
    assert "printf -v quoted_arg '%q' \"$forwarded_arg\"" in runner
    assert 'pytest${PYTEST_FORWARD_SHELL}' in runner


def test_python_proxy_cross_checkout_keeps_suite_fixture_and_selected_packages(tmp_path):
    """A source checkout cannot shadow the suite fixture launched by the harness."""
    selected = tmp_path / "selected-checkout"
    safeyolo = selected / "cli" / "src" / "safeyolo"
    pdp = selected / "pdp"
    selected_old_proxy = selected / "tests" / "proxy_migration"
    safeyolo.mkdir(parents=True)
    pdp.mkdir(parents=True)
    selected_old_proxy.mkdir(parents=True)
    (safeyolo / "__init__.py").write_text("ORIGIN = 'selected-safeyolo'\n")
    (pdp / "__init__.py").write_text("ORIGIN = 'selected-pdp'\n")
    (selected_old_proxy / "__init__.py").write_text("")
    (selected_old_proxy / "old_proxy.py").write_text("ORIGIN = 'selected-old-proxy'\n")

    env = python_proxy_environment(python_source=selected)
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, safeyolo, pdp; print(json.dumps({'safeyolo': safeyolo.__file__, 'pdp': pdp.__file__}))",
        ],
        env=env,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=True,
    )
    origins = json.loads(probe.stdout)
    assert str(selected / "cli" / "src") in origins["safeyolo"]
    assert str(selected / "pdp") in origins["pdp"]

    command = python_proxy_command()
    assert Path(command[1]).resolve() == REPO / "tests" / "proxy_migration" / "old_proxy.py"
    assert Path(command[1]).resolve() != selected_old_proxy / "old_proxy.py"


def test_kvm_lane_prepares_operator_access_before_product_bootstrap():
    lane = (Path(__file__).parent / "blackbox" / "run-lane.sh").read_text()

    operator_acl = 'sudo -n setfacl -m "u:${OPERATOR_UID}:rw" /dev/kvm'
    assert 'if [ "$LANE" = "kvm" ]; then' in lane
    assert 'OPERATOR_UID="$(id -u)"' in lane
    assert operator_acl in lane
    assert lane.index(operator_acl) < lane.index("    safeyolo bootstrap\n")
    # The harness supplies only its operator prerequisite. Product setup owns
    # the separate persistent uid 100000 ACL and udev rule.
    assert 'setfacl -m "u:100000:rw"' not in lane


def test_backend_selector_requires_a_real_python_checkout(tmp_path):
    """A selected Python source must contain the package that will be loaded."""
    with_source = tmp_path / "source"
    package = with_source / "cli" / "src" / "safeyolo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    assert validate_python_source(with_source) == with_source.resolve()

    try:
        validate_python_source(tmp_path / "missing")
    except SelectionError as exc:
        assert "Python source" in str(exc)
    else:
        raise AssertionError("missing source was accepted")


def test_backend_selector_records_actual_rust_binary_identity(tmp_path):
    """Rust evidence comes from the executable's version and bytes."""
    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("#!/bin/sh\nprintf 'safeyolo-proxy 0.1.0 (fixture)\\n'\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)

    result = identity("rust", rust_bin=binary, test_suite_root=Path(__file__).parents[1])

    assert result["executable"] == str(binary.resolve())
    assert result["executable_version"].startswith("safeyolo-proxy 0.1.0")
    assert result["policy_mode"] == "native"
    assert len(result["executable_sha256"]) == 64
    assert result["test_suite"]["root"] == str(Path(__file__).parents[1].resolve())

    wrong = tmp_path / "wrong-program"
    wrong.write_text("#!/bin/sh\nprintf 'something-else\\n'\n")
    wrong.chmod(wrong.stat().st_mode | stat.S_IXUSR)
    try:
        identity("rust", rust_bin=wrong)
    except SelectionError as exc:
        assert "unexpected identity" in str(exc)
    else:
        raise AssertionError("an unrelated executable was accepted as Rust")


def test_selected_runner_rejects_bad_selector_and_missing_binary(tmp_path):
    """Invalid selections fail before setup can touch a live instance."""
    runner = Path(__file__).parent / "blackbox" / "run-tests.sh"
    invalid = subprocess.run(
        [str(runner), "--proxy", "--proxy-impl", "wasm"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert invalid.returncode == 2
    assert "unsupported proxy implementation" in invalid.stderr

    missing = subprocess.run(
        [str(runner), "--proxy", "--proxy-impl", "rust", "--rust-bin", str(tmp_path / "gone")],
        text=True,
        capture_output=True,
        check=False,
    )
    assert missing.returncode == 2
    assert "Rust proxy executable" in missing.stderr


def test_both_backend_runner_forwards_args_and_runs_second_after_failure(tmp_path):
    """Both mode keeps the second independent run after a first failure."""
    binary = tmp_path / "safeyolo-proxy"
    binary.write_text(
        "#!/bin/sh\n[ \"$1\" = --version ] && printf 'safeyolo-proxy fixture\\n'\n"
    )
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "pytest-args"
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" >> \"$BLACKBOX_ARGS_LOG\"\n"
        "for arg in \"$@\"; do\n"
        "  [ \"$arg\" = rust ] && exit 0\n"
        "done\n"
        "exit 1\n"
    )
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "BLACKBOX_ARGS_LOG": str(log)}

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "both",
            "--rust-bin",
            str(binary),
            "--",
            "--sentinel",
            "value with spaces",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    forwarded = log.read_text().splitlines()
    assert forwarded.count("--sentinel") == 2
    assert forwarded.count("value with spaces") == 2
    assert forwarded.count("--proxy-backend") == 2
    assert forwarded.count("rust") >= 1
    assert "Selected proxy backend: rust" in result.stdout


def test_both_backend_runner_records_missing_rust_after_python_and_continues(tmp_path):
    """Each backend is selected at its own run boundary."""
    log = tmp_path / "pytest-args"
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" >> \"$BLACKBOX_ARGS_LOG\"\n"
        "exit 0\n"
    )
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    artifacts = tmp_path / "artifacts"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "BLACKBOX_ARGS_LOG": str(log),
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(artifacts),
    }

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "both",
            "--rust-bin",
            str(tmp_path / "missing-rust"),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    forwarded = log.read_text().splitlines()
    assert forwarded.count("--proxy-backend") == 1
    assert forwarded.count("python") == 1
    assert "rust" not in forwarded
    assert "Infrastructure failure selecting proxy backend 'rust'; continuing" in result.stderr
    rust_evidence = json.loads((artifacts / "proxy-rust-runtime.json").read_text())
    assert rust_evidence["backend"] == "rust"
    assert rust_evidence["status"] == "infrastructure_failure"


def test_both_backend_runner_infrastructure_dominates_earlier_test_failure(tmp_path):
    """A later selection failure cannot be hidden by an earlier pytest 1."""
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text("#!/bin/sh\nexit 1\n")
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    artifacts = tmp_path / "artifacts"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(artifacts),
    }

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "both",
            "--rust-bin",
            str(tmp_path / "missing-rust"),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    rust_evidence = json.loads((artifacts / "proxy-rust-runtime.json").read_text())
    assert rust_evidence["status"] == "infrastructure_failure"


@pytest.mark.parametrize(
    "pytest_exit,expected",
    [(1, 1), (2, 2), (3, 2), (4, 2), (5, 2)],
    ids=["test-failure", "interrupted", "internal", "usage", "no-collection"],
)
def test_selected_runner_classifies_pytest_exit_codes(tmp_path, pytest_exit, expected):
    """Only pytest's ordinary test-failure code remains a test failure."""
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(f"#!/bin/sh\nexit {pytest_exit}\n")
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "python",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == expected


def test_selected_runner_classifies_readiness_failure_as_infrastructure(tmp_path):
    """A legacy pytest plugin's code-1 readiness report is still infrastructure."""
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in --junitxml=*) junit=\"${arg#*=}\";; esac\n"
        "done\n"
        "printf '%s\\n' '<testsuite><testcase><failure>ReadinessError: timed out</failure></testcase></testsuite>' > \"$junit\"\n"
        "exit 1\n"
    )
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    artifacts = tmp_path / "artifacts"
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(artifacts),
    }

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "python",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2


def test_selected_rust_runner_requires_native_policy_provenance():
    """Release Rust selection opts out of the temporary Python policy adapter."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()
    harness = (Path(__file__).parent / "proxy_migration" / "harness.py").read_text()
    assert 'export SAFEYOLO_RUST_NATIVE_ONLY=1' in runner
    assert 'os.environ.get("SAFEYOLO_RUST_NATIVE_ONLY") == "1"' in harness
    assert '"policy_mode": "native" if use_native_policy else "temporary_adapter"' in harness
