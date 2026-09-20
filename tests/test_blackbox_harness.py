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


def test_compatibility_isolation_lane_selects_python_before_test_start():
    """The retained VM/Python lane must opt out of the native default."""
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    selector = "config['proxy']['backend'] = 'python'"
    start = "safeyolo start --test --no-wait"
    assert selector in harness
    assert harness.index(selector) < harness.index(start)


def test_runner_cleanup_only_reclaims_owned_sinkhole_processes():
    """The compatibility lane must not kill unrelated process names."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "pkill" not in runner
    assert "killall" not in runner
    assert 'SINKHOLE_PID_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.pid"' in runner
    assert (
        'stop_owned_pid_file "$SINKHOLE_PID_FILE" "$SCRIPT_DIR/sinkhole/server.py" "$SINKHOLE_ARGV_FILE"'
        in runner
    )
    assert 'SINKHOLE_ARGV_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.argv"' in runner
    assert 'printf \'%s\\n%s\\n\' "$SINKHOLE_PID" "$SINKHOLE_START_ID" > "$SINKHOLE_PID_FILE"' in runner
    assert 'kill "$HOST_LISTENER_PID"' in runner
    assert "printf -v quoted_arg '%q' \"$forwarded_arg\"" in runner
    assert 'pytest${PYTEST_FORWARD_SHELL}' in runner


def _runner_cleanup_helpers():
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()
    start = runner.index("canonical_path() {")
    end = runner.index("\ncleanup() {", start)
    return runner[start:end]


def _run_cleanup_probe(tmp_path, mode):
    target = tmp_path / "owned-process.py"
    target.write_text(
        "import signal\n"
        "import sys\n"
        "import time\n"
        "if '--ignore-term' in sys.argv:\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(60)\n"
    )
    probe = tmp_path / f"cleanup-{mode}.sh"
    probe.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        + _runner_cleanup_helpers()
        + """
expected="$1"
mode="$2"
pid_file="$3"
argv_file="$4"
target_pid=""

cleanup_probe() {
    if [ -n "$target_pid" ]; then
        kill "$target_pid" 2>/dev/null || true
        wait "$target_pid" 2>/dev/null || true
    fi
}
trap cleanup_probe EXIT

record_process() {
    local pid="$1"
    local output="$2"
    local start
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        start="$(process_start_identity "$pid" 2>/dev/null || true)"
        if [ -n "$start" ] && capture_process_argv "$pid" "$output" && [ -s "$output" ]; then
            printf '%s\n' "$start"
            return 0
        fi
        sleep 0.05
    done
    return 1
}

case "$mode" in
    owned)
        python3 "$expected" &
        target_pid=$!
        start="$(record_process "$target_pid" "$argv_file")"
        printf '%s\n%s\n' "$target_pid" "$start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=owned_survived'
            exit 1
        fi
        echo 'result=owned_stopped'
        ;;
    ignore)
        python3 "$expected" --ignore-term &
        target_pid=$!
        start="$(record_process "$target_pid" "$argv_file")"
        printf '%s\n%s\n' "$target_pid" "$start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=ignore_survived'
            exit 1
        fi
        echo 'result=ignore_stopped'
        ;;
    unrelated)
        python3 -c 'import time; time.sleep(60)' "$expected" &
        target_pid=$!
        start="$(record_process "$target_pid" "$argv_file")"
        printf '%s\n%s\n' "$target_pid" "$start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if ! kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=unrelated_killed'
            exit 1
        fi
        echo 'result=unrelated_survived'
        ;;
    stale)
        python3 "$expected" &
        stale_pid=$!
        stale_start="$(record_process "$stale_pid" "$argv_file")"
        kill "$stale_pid"
        wait "$stale_pid" 2>/dev/null || true
        printf '%s\n%s\n' "$stale_pid" "$stale_start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        echo 'result=stale_safe'
        ;;
    reused)
        python3 "$expected" &
        stale_pid=$!
        stale_start="$(record_process "$stale_pid" "$argv_file")"
        kill "$stale_pid"
        wait "$stale_pid" 2>/dev/null || true
        python3 -c 'import time; time.sleep(60)' "$expected" &
        target_pid=$!
        printf '%s\n%s\n' "$target_pid" "$stale_start" > "$pid_file"
        stop_owned_pid_file "$pid_file" "$expected" "$argv_file"
        if ! kill -0 "$target_pid" 2>/dev/null; then
            echo 'result=reused_killed'
            exit 1
        fi
        echo 'result=reused_survived'
        ;;
    *)
        echo "unknown mode: $mode" >&2
        exit 2
        ;;
esac
"""
    )
    probe.chmod(0o755)
    result = subprocess.run(
        [str(probe), str(target), mode, str(tmp_path / "owned.pid"), str(tmp_path / "owned.argv")],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    return result.stdout


@pytest.mark.parametrize("mode", ["owned", "unrelated", "stale", "reused", "ignore"])
def test_runner_cleanup_process_identity_behaves_as_owned_only(tmp_path, mode):
    output = _run_cleanup_probe(tmp_path, mode)

    assert f"result={mode}_" in output
    if mode == "ignore":
        assert "Escalating owned process" in output
    else:
        assert "Escalating owned process" not in output


def test_runner_vm_forwarding_preserves_arguments_without_shell_execution(tmp_path):
    """Forwarded VM arguments survive shell embedding byte-for-byte."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()
    start = runner.index('PYTEST_FORWARD_SHELL=""')
    end = runner.index("\n\n# The focused", start)
    quoting = runner[start:end]
    output = tmp_path / "forwarded.json"
    sentinel = tmp_path / "injected"
    probe = tmp_path / "forwarding.sh"
    probe.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "output=\"$1\"\n"
        "shift\n"
        "PYTEST_FORWARD_ARGS=(\"$@\")\n"
        + quoting
        + "\n"
        "printf -v code '%q' 'import json,sys; print(json.dumps(sys.argv[1:]))'\n"
        "bash -lc \"python3 -c $code${PYTEST_FORWARD_SHELL}\" > \"$output\"\n"
    )
    probe.chmod(0o755)
    arguments = [
        "--marker",
        "value with spaces",
        f"$(touch {sentinel})",
        f"semi;touch {sentinel}",
        "*",
        "quote\"single'",
        "line1\nline2",
    ]
    result = subprocess.run(
        [str(probe), str(output), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text()) == arguments
    assert not sentinel.exists()


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


def test_selected_runner_rejects_wrong_rust_executable_before_pytest(tmp_path):
    """A wrong program is infrastructure failure, without a fallback run."""
    binary = tmp_path / "wrong-program"
    binary.write_text("#!/bin/sh\nprintf 'unrelated-program 1.0\\n'\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    pytest_log = tmp_path / "pytest-ran"
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(f"#!/bin/sh\ntouch {pytest_log}\nexit 0\n")
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
            "rust",
            "--rust-bin",
            str(binary),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "unexpected identity" in result.stderr
    assert not pytest_log.exists()
    evidence = json.loads((artifacts / "proxy-rust-runtime.json").read_text())
    assert evidence["backend"] == "rust"
    assert evidence["status"] == "infrastructure_failure"


def test_both_backend_runner_continues_after_readiness_failure(tmp_path):
    """A failed first readiness report cannot suppress the second backend."""
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
        "junit=''\n"
        "for arg in \"$@\"; do case \"$arg\" in --junitxml=*) junit=\"${arg#*=}\";; esac; done\n"
        "case \" $* \" in\n"
        "  *'--proxy-backend python'*) printf '%s\\n' '<testsuite><testcase><failure>ReadinessError: stale listener</failure></testcase></testsuite>' > \"$junit\"; exit 1;;\n"
        "  *'--proxy-backend rust'*) printf '%s\\n' '<testsuite></testsuite>' > \"$junit\"; exit 0;;\n"
        "esac\n"
        "exit 3\n"
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
            str(binary),
            "--",
            "tests/proxy_migration/test_readiness.py",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    forwarded = log.read_text().splitlines()
    assert forwarded.count("--proxy-backend") == 2
    assert forwarded.count("python") == 1
    assert forwarded.count("rust") == 1
    assert (artifacts / "proxy-python-junit.xml").is_file()
    assert (artifacts / "proxy-rust-junit.xml").is_file()
    assert json.loads((artifacts / "proxy-python-runtime.json").read_text())["backend"] == "python"
    assert json.loads((artifacts / "proxy-rust-runtime.json").read_text())["backend"] == "rust"


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
