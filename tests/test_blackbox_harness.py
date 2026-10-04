"""Regression tests for blackbox harness isolation and backend selection."""

import copy
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import tomllib
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from hypothesis import example, given, settings
from hypothesis import strategies as st

from tests.blackbox import installed_lifecycle as lifecycle
from tests.blackbox import installed_sections
from tests.blackbox import installed_state_transition as continuity
from tests.blackbox.harness.vz_fixture import P2Fixture, Parent, VZRequest
from tests.blackbox.installed_ingress import installed_identity
from tests.blackbox.isolation import installed_access as guest
from tests.blackbox.isolation import installed_lifecycle as guest_lifecycle
from tests.blackbox.isolation import installed_workloads as guest_workloads
from tests.blackbox.proxy_backend import SelectionError, identity
from tests.proxy_contracts import harness as proxy_harness
from tests.proxy_contracts.websocket_peer import read_head


@pytest.fixture
def native_binary(tmp_path):
    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("#!/bin/sh\nprintf 'safeyolo-proxy 0.1.0 (fixture)\\n'\n")
    binary.chmod(0o755)
    return binary


def test_harness_assigns_distinct_proxy_admin_and_web_ports():
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "TEST_PROXY_PORT=8180" in harness
    assert "TEST_ADMIN_PORT=9190" in harness
    assert "TEST_WEB_PORT=8181" in harness
    assert "config['proxy']['port'] = $TEST_PROXY_PORT" in harness
    assert "config['proxy']['admin_port'] = $TEST_ADMIN_PORT" in harness
    assert "config['proxy']['web_port'] = $TEST_WEB_PORT" in harness


def test_native_isolation_lane_selects_rust_before_test_start():
    """Ordinary installed guest runs select the production native runtime."""
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    selector = "config['proxy']['backend'] = '$PROXY_IMPL'"
    start = "safeyolo start --no-wait"
    assert 'PROXY_IMPL="rust"' in harness
    assert selector in harness
    assert harness.index(selector) < harness.index(start)


def test_installed_native_vm_lane_fails_before_instance_setup_without_packaged_binary(tmp_path):
    """A native guest label cannot fall back to a checkout binary or Python."""
    cli = tmp_path / "safeyolo"
    cli.write_text("#!/bin/sh\nprintf 'safeyolo fixture\\n'\n")
    cli.chmod(0o755)
    config_dir = tmp_path / "test-instance"
    result = subprocess.run(
        [str(Path(__file__).parent / "blackbox" / "run-tests.sh"), "--isolation", "--proxy-impl", "rust"],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "SAFEYOLO_TEST_CONFIG_DIR": str(config_dir),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "installed CLI has no usable packaged Rust proxy" in result.stderr
    assert not config_dir.exists()


@pytest.mark.parametrize("options", [
    ["--expect-platform", "vz", "--proxy-impl", "rust", "--workloads"],
    ["--expect-platform", "kvm", "--proxy-impl", "python", "--workloads"],
    ["--expect-platform", "kvm", "--proxy-impl", "rust", "--workloads", "--ingress"],
])
def test_workloads_reject_a_different_lane_before_setup(tmp_path, options):
    config_dir = tmp_path / "test-instance"
    result = subprocess.run(
        [str(Path(__file__).parent / "blackbox" / "run-tests.sh"), *options],
        env={**os.environ, "SAFEYOLO_TEST_CONFIG_DIR": str(config_dir)},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    if "python" in options:
        assert "unsupported proxy implementation" in result.stderr
    else:
        assert "--workloads requires --expect-platform kvm|systrap --proxy-impl rust" in result.stderr
    assert not config_dir.exists()


def test_runner_cleanup_only_reclaims_owned_sinkhole_processes():
    """The compatibility lane must not kill unrelated process names."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "pkill" not in runner
    assert "killall" not in runner
    assert 'SINKHOLE_PID_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.pid"' in runner
    assert (
        'stop_owned_pid_file "$SINKHOLE_PID_FILE" "$SINKHOLE_SCRIPT" "$SINKHOLE_ARGV_FILE"'
        in runner
    )
    assert 'SINKHOLE_ARGV_FILE="$SAFEYOLO_CONFIG_DIR/sinkhole.argv"' in runner
    assert 'printf \'%s\\n%s\\n\' "$SINKHOLE_PID" "$SINKHOLE_START_ID" > "$SINKHOLE_PID_FILE"' in runner
    assert 'kill "$HOST_LISTENER_PID"' in runner
    assert "printf -v quoted_arg '%q' \"$forwarded_arg\"" in runner
    assert 'pytest${PYTEST_FORWARD_SHELL}' in runner


def test_vz_fixture_shares_http_origin_parent_and_control_without_losing_capture(tmp_path):
    """The fixed HTTP listener serves each path and rejects an unknown direct host."""
    from server import clear_requests, get_requests

    with Parent(None, None, host="127.0.0.1", request_handler=VZRequest) as server:
        server.https_port = 1
        server.p2_fixture = P2Fixture(tmp_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            clear_requests()

            def get(target, host, **headers):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    connection.request("GET", target, headers={"Host": host, **headers})
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            assert get("/health", "127.0.0.1")[0] == 200
            assert get("/p2/health", "127.0.0.1")[0] == 200
            assert get("/p4/echo/p4-" + "a" * 32, "failing.test") == (
                200, b"echo:p4-" + b"a" * 32
            )
            assert get("/p4/echo/invalid", "failing.test")[0] == 400
            assert get("/direct", "httpbin.org")[0] == 200
            assert get("http://httpbin.org/absolute?x=1", "httpbin.org",
                       **{"Proxy-Authorization": "Basic fixture"})[0] == 200
            assert get("/unknown", "unknown.test")[0] == 400
            assert get(f"http://127.0.0.1:{server.server_port}/health", "127.0.0.1")[0] == 502
            assert get("http://httpbin.org:bad/path", "httpbin.org")[0] == 400
            assert get("/requests", "127.0.0.1")[0] == 200
            captured = get_requests(host="httpbin.org")
            assert [(item.path, item.raw_target) for item in captured] == [
                ("/direct", "/direct"),
                ("/absolute", "/absolute?x=1"),
            ]
            assert "Proxy-Authorization" not in captured[1].headers
        finally:
            server.shutdown()
            thread.join(timeout=5)
            clear_requests()


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
        env={**os.environ, "SCRIPT_DIR": str(Path(__file__).parent / "blackbox")},
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


@pytest.mark.parametrize("forwarded", [False, True])
def test_runner_vm_forwarding_preserves_arguments_without_shell_execution(tmp_path, forwarded):
    """Empty and supplied VM arguments work with the host's /bin/bash."""
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
    ] if forwarded else []
    result = subprocess.run(
        ["/bin/bash", str(probe), str(output), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text()) == arguments
    assert not sentinel.exists()


def test_kvm_lane_prepares_operator_access_before_product_bootstrap():
    lane = (Path(__file__).parent / "blackbox" / "run-lane.sh").read_text()

    operator_acl = 'sudo -n setfacl -m "u:${OPERATOR_UID}:rw" /dev/kvm'
    assert 'if [ "$LANE" = "kvm" ]; then' in lane
    assert 'OPERATOR_UID="$(id -u)"' in lane
    assert operator_acl in lane
    assert lane.index(operator_acl) < lane.index(
        '    safeyolo bootstrap --source-checkout "$INSTALL_ROOT"\n'
    )
    # The harness supplies only its operator prerequisite. Product setup owns
    # the separate persistent uid 100000 ACL and udev rule.
    assert 'setfacl -m "u:100000:rw"' not in lane


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


def test_backend_selector_reports_unknown_interpreter_for_pytest_wrapper(tmp_path, monkeypatch, native_binary):
    """A shell wrapper must not be reported as a Python interpreter."""
    launcher = tmp_path / "pytest"
    launcher.write_text('#!/bin/sh\nexec python3 -m pytest "$@"\n')
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")

    python = identity("rust", rust_bin=native_binary, test_suite_root=Path(__file__).parents[1])["python"]
    assert python["pytest_launcher"] == str(launcher)
    assert python["interpreter"] is None
    assert python["interpreter_version"] is None

    launcher.write_text(f"#!{sys.executable}\n")
    python = identity("rust", rust_bin=native_binary, test_suite_root=Path(__file__).parents[1])["python"]
    assert Path(python["interpreter"]).resolve() == Path(sys.executable).resolve()
    assert python["interpreter_version"] == sys.version


@pytest.mark.parametrize("selector", ["wasm", "python", "both"])
def test_selected_runner_rejects_bad_selector_and_missing_binary(tmp_path, selector):
    """Invalid selections fail before setup can touch a live instance."""
    runner = Path(__file__).parent / "blackbox" / "run-tests.sh"
    invalid = subprocess.run(
        [str(runner), "--proxy", "--proxy-impl", selector],
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


@pytest.mark.parametrize(
    "pytest_exit,expected",
    [(1, 1), (2, 2), (3, 2), (4, 2), (5, 2)],
    ids=["test-failure", "interrupted", "internal", "usage", "no-collection"],
)
def test_selected_runner_classifies_pytest_exit_codes(tmp_path, pytest_exit, expected, native_binary):
    """Only pytest's ordinary test-failure code remains a test failure."""
    fake_pytest = tmp_path / "pytest"
    fake_pytest.write_text(f"#!/bin/sh\nexit {pytest_exit}\n")
    fake_pytest.chmod(fake_pytest.stat().st_mode | stat.S_IXUSR)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR": str(tmp_path / "artifacts"),
    }

    result = subprocess.run(
        [
            str(Path(__file__).parent / "blackbox" / "run-tests.sh"),
            "--proxy",
            "--proxy-impl",
            "rust",
            "--rust-bin",
            str(native_binary),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == expected


INSTALLED_PYTEST_SLOTS = (
    "PROXY", "FIREWALL", "IDENTITY", "ISOLATION", "ROOT_ISOLATION", "LIFECYCLE",
)


@pytest.fixture
def installed_pytest_runner(tmp_path):
    """Run the installed suite commands and summary with controlled command exits."""
    directory = tmp_path / "pytest-runner"
    (directory / "host").mkdir(parents=True)
    runner = (Path(__file__).parent / "blackbox/run-tests.sh").read_text()
    script = directory / "run-tests.sh"
    script.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        + r'''
SCRIPT_DIR="$(dirname "$0")"
RUN_PROXY=true
RUN_ISOLATION=true
AGENT_NAME=bbtest
VERBOSE=
PYTEST_FORWARD_ARGS=()
PYTEST_FORWARD_SHELL=

fixture_suite_exit() {
    printf '%s\n' "$1" >> "$SCRIPT_DIR/suites.log"
    local variable="FIXTURE_${1}_EXIT"
    return "${!variable:-0}"
}

pytest() {
    case "$*" in
        *native/) fixture_suite_exit PROXY ;;
        *security/) fixture_suite_exit FIREWALL ;;
        *identity/) fixture_suite_exit IDENTITY ;;
        *lifecycle/) fixture_suite_exit LIFECYCLE ;;
        *) return 99 ;;
    esac
}

safeyolo() {
    case "$*" in
        *--root*) fixture_suite_exit ROOT_ISOLATION ;;
        *) fixture_suite_exit ISOLATION ;;
    esac
}
'''
        + runner[runner.index("# --- Phase 2: Run tests ---"):]
    )
    script.chmod(0o755)
    return script


@pytest.mark.parametrize("slot", INSTALLED_PYTEST_SLOTS)
@pytest.mark.parametrize("suite_exit,expected", [(1, 1), (2, 2), (3, 2), (4, 2), (5, 2), (127, 2)])
def test_installed_runner_classifies_each_suite_exit(installed_pytest_runner, slot, suite_exit, expected):
    env = {**os.environ, **{f"FIXTURE_{name}_EXIT": "0" for name in INSTALLED_PYTEST_SLOTS}}
    env[f"FIXTURE_{slot}_EXIT"] = str(suite_exit)
    result = subprocess.run(
        [str(installed_pytest_runner)], env=env, capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    assert installed_pytest_runner.with_name("suites.log").read_text().splitlines() == list(INSTALLED_PYTEST_SLOTS)


@pytest.mark.parametrize("suite_exits,expected", [
    ((0, 0, 0, 0, 0, 0), 0),
    ((3, 0, 0, 0, 0, 1), 2),
    ((1, 0, 0, 0, 0, 3), 2),
], ids=["all-success", "infrastructure-before-assertion", "infrastructure-after-assertion"])
def test_installed_runner_failure_precedence(installed_pytest_runner, suite_exits, expected):
    env = {**os.environ, **{
        f"FIXTURE_{slot}_EXIT": str(code) for slot, code in zip(INSTALLED_PYTEST_SLOTS, suite_exits, strict=True)
    }}
    result = subprocess.run(
        [str(installed_pytest_runner)], env=env, capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    assert installed_pytest_runner.with_name("suites.log").read_text().splitlines() == list(INSTALLED_PYTEST_SLOTS)


def test_selected_runner_classifies_readiness_failure_as_infrastructure(tmp_path, native_binary):
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
            "rust",
            "--rust-bin",
            str(native_binary),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2


@pytest.mark.parametrize("native_policy", [False, True])
def test_selected_rust_runner_requires_native_policy_provenance(tmp_path, monkeypatch, native_policy):
    """Every Rust fixture supplies its policy file and records native ownership."""
    runner = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()
    selector = (Path(__file__).parent / "proxy_contracts" / "run.py").read_text()
    assert "SAFEYOLO_RUST_NATIVE_ONLY" not in runner + selector

    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("fixture binary")
    monkeypatch.setenv("SAFEYOLO_RUST_PROXY", str(binary))

    @contextmanager
    def fake_child_process(command, directory, env):
        assert command[0] == str(binary)
        yield object()

    monkeypatch.setattr(proxy_harness, "child_process", fake_child_process)
    monkeypatch.setattr(proxy_harness, "wait_ready", lambda *args, **kwargs: None)
    directory = tmp_path / "fixture"
    with proxy_harness.launch_proxy(
        "rust", directory, '[hosts]\n"*" = { egress = "deny" }\n',
        native_policy=native_policy,
    ):
        config = json.loads((directory / "proxy.json").read_text())
        provenance = json.loads((directory / "native-policy-provenance.json").read_text())

    assert config["policy_file"] == str(directory / "policy.toml")
    assert "temporary_policy_socket" not in config
    assert provenance == {
        "backend": "rust",
        "policy_mode": "native",
        "policy_file": config["policy_file"],
        "temporary_policy_socket": None,
        "temporary_policy_adapter": False,
    }


ROOT = Path(__file__).resolve().parents[1]
REQUEST_ID = "req-" + "a" * 32
MARKER = "p3-" + "b" * 32
OTHER_REVISION = "b" * 40
SELECTED_REVISION = "a" * 40


def test_access_launcher_targets_match_selected_guest_requests(tmp_path, monkeypatch):
    """Run the launcher's final addon rewrite and capture the guest's calls."""
    source = tmp_path / "source-instance"
    instance = tmp_path / "test-instance"
    environment = os.environ.copy()
    environment.update(
        SAFEYOLO_CONFIG_DIR=str(source),
        SAFEYOLO_TEST_CONFIG_DIR=str(instance),
        PATH=f"{Path(sys.executable).parent}:{environment['PATH']}",
        PYTHONPATH=f"{ROOT / 'cli/src'}:{ROOT}",
    )
    command = [
        str(ROOT / "tests/blackbox/run-tests.sh"),
        "--expect-platform",
        "systrap",
        "--proxy-impl",
        "rust",
        "--access-config-only",
    ]
    prepared = subprocess.run(command, env=environment, cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert prepared.returncode == 0, prepared.stdout[-1000:] + prepared.stderr[-1000:]
    assert "no proxy or guest started" in prepared.stdout
    targets = yaml.safe_load((instance / "addons.yaml").read_text())["addons"]["test_context"]["target_hosts"]
    policy = tomllib.loads((instance / "policy.toml").read_text())
    assert policy["hosts"][guest.BASIC_HOST]["service"] == "p3_basic"
    assert policy["hosts"][guest.CONTRACT_HOST]["service"] == "p3_contract"
    assert policy["hosts"]["failing.test"]["egress"] == "allow"

    calls: list[tuple[str, str, bool]] = []

    def exchange(method, target, *, headers=None, **_kwargs):
        calls.append((method, urlsplit(target).hostname, bool(headers and "X-SafeYolo-Test-Context" in headers)))
        status = 428 if method == "POST" else 200
        return status, {"x-safeyolo-request-id": REQUEST_ID}, b'{"received":true}'

    declared = None

    def api(method, path, *, payload=None):
        nonlocal declared
        if method == "POST" and path == "/api/test-context/current":
            declared = {"run": "installed-p3", "agent": "bbtest", "test": MARKER}
            return 200, {}, {"context": declared}
        if method == "GET" and path == "/api/test-context/current":
            return 200, {}, {"context": declared}
        if method == "GET" and path.startswith("/trace?"):
            return 200, {}, {"agent_id": "bbtest"}
        if method == "POST" and path == "/api/flows/search":
            return 200, {}, {"flows": [{"id": "owned-flow", "request_id": REQUEST_ID, "agent_id": "bbtest"}]}
        if method == "GET" and path == "/api/flows/owned-flow":
            return 200, {}, {"request_id": REQUEST_ID}
        if method == "DELETE" and path == "/api/test-context/current":
            declared = None
            return 200, {}, {"status": "cleared"}
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(guest, "service_token", lambda _service: "sgw_fixture")
    monkeypatch.setattr(guest, "exchange", exchange)
    monkeypatch.setattr(guest, "api", api)
    guest.basic_read(MARKER)
    guest.contract_prompt()
    guest.context_and_evidence("bbtest", MARKER)

    assert calls == [
        ("GET", guest.BASIC_HOST, False),
        ("POST", guest.CONTRACT_HOST, False),
        ("GET", guest.BASIC_HOST, True),
    ]
    assert targets == ["failing.test"], (
        "access needs an owned activation target without mandatory context on ordinary hosts"
    )
    assert all(host not in targets or has_context for _, host, has_context in calls)
    assert guest.BASIC_HOST not in targets, "the explicit header must exercise a non-target host"

    # The operator's execution-970 configuration would block both ordinary calls.
    old_targets = ["httpbin.org", "failing.test", "legitimate-api.com", "httpbin.org"]
    assert [host for _, host, has_context in calls if host in old_targets and not has_context] == [
        guest.BASIC_HOST,
        guest.CONTRACT_HOST,
    ]


def test_installed_setup_command_failure_is_infrastructure(tmp_path):
    cli = tmp_path / "safeyolo"
    cli.write_text("#!/bin/sh\necho 'deliberate init failure' >&2\nexit 1\n")
    cli.chmod(0o755)
    environment = {**os.environ,
                   "PATH": f"{tmp_path}:{Path(sys.executable).parent}:{os.environ['PATH']}",
                   "SAFEYOLO_CONFIG_DIR": str(tmp_path / "prepared"),
                   "SAFEYOLO_TEST_CONFIG_DIR": str(tmp_path / "section")}
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), "--expect-platform", "systrap",
         "--access-config-only"],
        env=environment, capture_output=True, text=True, check=False, timeout=20,
    )
    assert "deliberate init failure" in result.stderr
    assert result.returncode == 2
    assert "Starting sinkhole" not in result.stdout


def test_held_guest_keeps_preamble_and_observation(monkeypatch):
    observation = {
        "phase": "drain",
        "agent": "bbtest",
        "forwarder": {"pid": 42},
        "result": {"http": "completed", "connect_closed": True},
    }
    script = (
        "print('shell preamble'); "
        "print('P4_READY=drain', flush=True); "
        f"print('P4_OBSERVATION=' + {json.dumps(json.dumps(observation))}, flush=True)"
    )
    monkeypatch.setattr(lifecycle, "guest_command", lambda *_args: [sys.executable, "-u", "-c", script])

    process, first = lifecycle.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)
    assert lifecycle.finish_guest(process, first, "drain", "bbtest") == observation["result"]


def test_held_guest_reports_exit_before_ready(monkeypatch):
    monkeypatch.setattr(
        lifecycle,
        "guest_command",
        lambda *_args: [sys.executable, "-u", "-c", "print('shell preamble', flush=True); raise SystemExit(4)"],
    )

    with pytest.raises(AssertionError, match="exited before its admitted-work boundary"):
        lifecycle.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)


@pytest.mark.parametrize("client", [guest_workloads, guest_lifecycle], ids=["workloads", "lifecycle"])
@pytest.mark.parametrize("chunked", [False, True], ids=["close-delimited", "chunked"])
def test_guest_sse_decodes_http_before_reporting_admitted_event(monkeypatch, client, chunked):
    marker = "p2-" + "a" * 32
    first, last = (f"data: {position}:{marker}\n\n".encode() for position in ("first", "last"))
    admitted = threading.Event()
    errors = []

    def report(*_args, **_kwargs):
        admitted.set()

    def serve(listener):
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                _, headers = read_head(connection)
                assert headers["host"] == ["failing.test"]
                framing = b"Transfer-Encoding: chunked\r\n" if chunked else b""
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                                   + framing + b"Connection: close\r\n\r\n")

                def send_event(payload):
                    for part in (payload[:7], payload[7:-1], payload[-1:]):
                        connection.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n" if chunked else part)

                send_event(first)
                assert admitted.wait(3), "guest did not admit the first event before origin release"
                send_event(last)
                if chunked:
                    connection.sendall(b"0\r\n\r\n")
        except (OSError, AssertionError) as exc:
            errors.append(exc)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(3)
        monkeypatch.setattr(client, "PROXY", listener.getsockname())
        monkeypatch.setattr(client, "print", report, raising=False)
        server = threading.Thread(target=serve, args=(listener,))
        server.start()
        try:
            result = client.sse(marker, "bbtest") if client is guest_workloads else client.sse(marker)
            assert result == {"first": first.decode(), "last": last.decode()}
        finally:
            admitted.set()
            server.join(timeout=5)
        assert not server.is_alive()
        assert errors == []


@pytest.mark.parametrize("body,message", [(b"data: truncated", "ended before"), (b"x" * 8192, "exceeded")],
                         ids=["incomplete", "oversized"])
def test_guest_sse_rejects_incomplete_or_oversized_events(body, message):
    reader, writer = socket.socketpair()
    errors = []

    def send():
        try:
            writer.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body)
            writer.shutdown(socket.SHUT_WR)
        except OSError as exc:
            errors.append(exc)

    with reader, writer:
        reader.settimeout(3)
        writer.settimeout(3)
        writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        # macOS's socketpair buffer cannot hold this whole response before a read.
        # A small buffer also exercises producer backpressure on Linux.
        sender = threading.Thread(target=send, name="SSE fixture sender")
        sender.start()
        try:
            with http.client.HTTPResponse(reader) as response:
                response.begin()
                with pytest.raises(AssertionError, match=message):
                    guest_workloads._event(response)
        finally:
            reader.close()
            sender.join(timeout=5)
            assert not sender.is_alive(), "SSE fixture sender did not stop after socket cleanup"
        assert errors == []


def test_retained_python_timeout_reports_blocked_sse_and_cleans_sockets(tmp_path):
    """The retained job's signal timeout reports the blocked read and runs finally."""
    cleanup = tmp_path / "cleanup.json"
    control = tmp_path / "test_blocked_sse.py"
    control.write_text(f'''import http.client
import json
import socket
from pathlib import Path
from tests.blackbox.isolation.installed_workloads import _event

def test_blocked_sse_input():
    reader, writer = socket.socketpair()
    response = http.client.HTTPResponse(reader)
    try:
        writer.sendall(b"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\n\\r\\ndata: unfinished")
        response.begin()
        _event(response)
    finally:
        response.close()
        reader.close()
        writer.close()
        Path({str(cleanup)!r}).write_text(json.dumps([reader.fileno(), writer.fileno()]))
''')
    environment = {**os.environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--noconftest", "-v", "--tb=short",
         "--timeout=1", "--timeout-method=signal", str(control)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10, check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1, output
    assert "Timeout (>1.0s)" in output, output
    assert "test_blocked_sse_input" in output and "installed_workloads.py" in output, output
    assert json.loads(cleanup.read_text()) == [-1, -1]


def test_selected_installed_identity_requires_exact_wheel_stamp_and_binary(tmp_path):
    revision = SELECTED_REVISION
    checkout = tmp_path / "source"
    built = checkout / "proxy/target/release/safeyolo-proxy"
    built.parent.mkdir(parents=True)
    built.write_bytes(b"selected-native-binary")

    package = tmp_path / "tool/safeyolo"
    packaged = package / "bin/safeyolo-proxy"
    packaged.parent.mkdir(parents=True)
    packaged.write_bytes(built.read_bytes())
    (package / "_build_identity.json").write_text(json.dumps({"source_revision": revision, "state": "known"}))
    cli = tmp_path / "tool/bin/safeyolo"
    cli.parent.mkdir(parents=True)
    diagnostic = {
        "checks": [
            {
                "name": "Runtime identity",
                "status": "pass",
                "message": f"Running {packaged.resolve()}",
                "detail": "PID 4242",
            }
        ],
    }
    cli.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'doctor': print({json.dumps(json.dumps(diagnostic))})\n"
        "else: print('native running 4242')\n"
    )
    cli.chmod(0o755)
    runtime = {
        "status": "attached_ready",
        "cli": {"path": str(cli), "package_location": str(package / "__init__.py")},
        "candidate": {"path": str(packaged), "sha256": hashlib.sha256(built.read_bytes()).hexdigest()},
        "runtime": {
            "status": "ready",
            "pid": 4242,
            "actual_executable": str(packaged),
            "authenticated_runtime_identity": {"status": "authenticated"},
        },
        "native": {},
    }

    selected = installed_identity(runtime, checkout, expected_revision=revision)
    assert selected["build_identity"]["source_revision"] == revision
    assert selected["cli_diagnostics"]["detail"] == "PID 4242"
    with pytest.raises(AssertionError, match="selected source build identity"):
        installed_identity(runtime, checkout, expected_revision=OTHER_REVISION)
    wrong_diagnostic = {"checks": [{**diagnostic["checks"][0], "message": "Running /wrong/proxy"}]}
    cli.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'doctor': print({json.dumps(json.dumps(wrong_diagnostic))})\n"
        "else: print('native running 4242')\n"
    )
    with pytest.raises(AssertionError):
        installed_identity(runtime, checkout, expected_revision=revision)


def test_install_commit_option_needs_an_installed_selection(tmp_path):
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), "--install-commit", SELECTED_REVISION],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "SAFEYOLO_TEST_CONFIG_DIR": str(tmp_path / "test-instance"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "requires an installed ingress, workloads, access, or lifecycle selection" in result.stderr
    assert not (tmp_path / "test-instance").exists()


@pytest.mark.parametrize("selection", ["default", "matching", "mismatched", "missing_checkout"])
def test_direct_installed_selection_resolves_current_source_before_setup(tmp_path, selection):
    checkout = tmp_path / "source"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    (checkout / "source.txt").write_text("selected source\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
         "commit", "-qm", "Selected source"], check=True,
    )
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    instance = tmp_path / "test-instance"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "SAFEYOLO_TEST_CONFIG_DIR": str(instance)}
    if selection != "missing_checkout":
        env["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"] = str(checkout)
    options = ["--expect-platform", "systrap", "--workloads"]
    if selection != "default":
        options += ["--install-commit", OTHER_REVISION if selection == "mismatched" else revision]
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), *options], env=env,
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 2
    if selection in {"default", "matching"}:
        assert f"Installed source: {revision}" in result.stdout
        assert "installed safeyolo CLI is required" in result.stderr
    elif selection == "mismatched":
        assert "install checkout must contain the exact full selected commit" in result.stderr
        assert "Installed source:" not in result.stdout
    else:
        assert "installed sections need SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT" in result.stderr
    assert not instance.exists()


@pytest.fixture
def installed_section_commands(tmp_path, monkeypatch):
    """Owned subprocesses exercise preparation reuse and section cleanup."""
    repository = tmp_path / "repository"
    scripts = repository / "tests/blackbox"
    scripts.mkdir(parents=True)
    built = repository / "proxy/target/release/safeyolo-proxy"
    built.parent.mkdir(parents=True)
    built.write_bytes(b"selected native fixture")
    prepare = scripts / "run-lane.sh"
    stop_script = f"#!{sys.executable}\n" + "\n".join([
        "import os, pathlib, sys",
        "root = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])",
        "if os.environ.get('FAIL_CLEANUP') and root.name == 'isolation': sys.exit(7)",
        "for marker in root.glob('agents/*/container.pid'): marker.unlink()",
        "for marker in root.glob('data/proxy*.json'): marker.unlink()",
        "",
    ])
    prepare.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "root = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])\n"
        "root.mkdir(parents=True)\n"
        "(root / 'prepared-once').write_text('one installation')\n"
        "assert sys.argv[-1] == '--prepare-only'\n"
        "if os.environ.get('FAIL_PREPARATION'): sys.exit(9)\n"
        "(root / 'share').mkdir()\n"
        "(root / 'share/kernel').write_bytes(b'compatible immutable boot input')\n"
        "binary_dir = pathlib.Path(os.environ['UV_TOOL_BIN_DIR'])\n"
        "binary_dir.mkdir(parents=True)\n"
        f"(binary_dir / 'safeyolo').write_text({stop_script!r})\n"
        "(binary_dir / 'safeyolo').chmod(0o755)\n"
    )
    section = scripts / "run-tests.sh"
    section.write_text(
        f"#!{sys.executable}\n"
        "import datetime, hashlib, json, os, pathlib, platform, sys, uuid\n"
        "root = pathlib.Path(os.environ['SAFEYOLO_TEST_CONFIG_DIR'])\n"
        "source = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])\n"
        "assert '--proxy-impl' in sys.argv and 'rust' in sys.argv\n"
        "assert os.environ['SAFEYOLO_COORD_DATA_DIR'] == str(root / 'data/coord')\n"
        "assert os.environ['SAFEYOLO_BLACKBOX_ARTIFACTS_DIR'].endswith('/' + root.name)\n"
        "assert not root.exists(), 'a section received another section writable state'\n"
        "root.mkdir(parents=True)\n"
        "(root / 'share').symlink_to(source / 'share')\n"
        "(root / 'config.yaml').write_text('owned section configuration')\n"
        "(root / 'agents/bbtest').mkdir(parents=True)\n"
        "(root / 'agents/bbtest/container.pid').write_text(str(os.getpid()))\n"
        "(root / 'data').mkdir()\n"
        "(root / 'data/proxy-rust.json').write_text(json.dumps({'pid': os.getpid()}))\n"
        "for name in ('token', 'certificate', 'capture', 'approval', 'overlay'):\n"
        "    (root / name).write_text(uuid.uuid4().hex)\n"
        "(root / 'selection.json').write_text(json.dumps(sys.argv[1:]))\n"
        "(root / 'nats-instance').write_text(os.environ['SAFEYOLO_NATS_TEST_INSTANCE'])\n"
        "artifacts = pathlib.Path(os.environ['SAFEYOLO_BLACKBOX_ARTIFACTS_DIR'])\n"
        "lane = sys.argv[sys.argv.index('--expect-platform') + 1]\n"
        "revision = os.environ['SAFEYOLO_BLACKBOX_INSTALL_REVISION']\n"
        "pid = os.getpid()\n"
        "binary = source / 'package/bin/safeyolo-proxy'\n"
        "now = datetime.datetime.now(datetime.timezone.utc).isoformat()\n"
        "runtime = {'status': 'attached_ready', 'captured_at': now, 'run_id': os.environ['SAFEYOLO_BLACKBOX_RUN_ID'],\n"
        "    'source_revision': revision, 'build_identity': {'state': 'known', 'source_revision': revision},\n"
        "    'host': {'system': 'Darwin' if lane == 'vz' else platform.system(), 'machine': 'arm64' if lane == 'vz' else platform.machine()},\n"
        "    'cli': {'package_location': str(source / 'package/__init__.py')},\n"
        "    'candidate': {'path': str(binary), 'sha256': hashlib.sha256((pathlib.Path(os.environ['SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT']) / 'proxy/target/release/safeyolo-proxy').read_bytes()).hexdigest()},\n"
        "    'runtime': {'status': 'ready', 'pid': pid, 'actual_executable': str(binary),\n"
        "        'receipt': {'pid': pid, 'start_token': f'darwin:{pid}:123:456' if lane == 'vz' else f'linux:00000000-0000-0000-0000-000000000000:{pid}:123'},\n"
        "        'readiness': {'ready': True, 'pid': pid, 'backend': 'rust-m2', 'instance_id': 'f'*32, 'listeners': 1},\n"
        "        'authenticated_runtime_identity': {'status': 'authenticated', 'schema_version': 1, 'instance_id': 'f'*32}}}\n"
        "(artifacts / 'installed-rust-runtime.json').write_text(json.dumps(runtime))\n"
        "prefix = {'systrap': 'systrap ', 'kvm': 'KVM ', 'vz': 'Apple Virtualization.framework '}[lane]\n"
        "(artifacts / 'doctor.json').write_text(json.dumps({'checks': [{'name': 'Isolation platform', 'message': prefix + 'fixture'}]}))\n"
        "if root.name == 'isolation' and not os.environ.get('OMIT_OBSERVATIONS'):\n"
        "    for suite in ('native', 'security', 'identity', 'isolation', 'root-isolation', 'lifecycle'):\n"
        "        now = datetime.datetime.now(datetime.timezone.utc).isoformat()\n"
        "        (artifacts / ('pytest-' + suite + '.json')).write_text(json.dumps({\n"
        "            'schema_version': 1, 'started_at': now, 'finished_at': now, 'exit': 0, 'deselected': 0,\n"
        "            'suite': suite, 'run_id': os.environ['SAFEYOLO_BLACKBOX_RUN_ID'],\n"
        "            'source_revision': os.environ['SAFEYOLO_BLACKBOX_INSTALL_REVISION'],\n"
        "            'collected': 1, 'collection_errors': 0, 'omitted_cases': 0, 'counts': {'passed': 1},\n"
        "            'cases': [{'test': 'test_fixture.py::test_case', 'case_sha256': 'f'*64, 'outcome': 'passed', 'phase': 'call'}]}))\n"
        "if root.name == 'isolation': sys.exit(int(os.environ.get('FAIL_SECTION', '0')))\n"
    )
    prepare.chmod(0o755)
    section.chmod(0o755)
    monkeypatch.setattr(installed_sections, "REPOSITORY", repository)
    return repository


@pytest.mark.parametrize("failure,expected", [(0, 0), (1, 1), (2, 2)])
def test_installed_sections_reuse_preparation_and_separate_live_state(
    tmp_path, monkeypatch, installed_section_commands, failure, expected
):
    monkeypatch.setenv("FAIL_SECTION", str(failure))
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    result = installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, directory, artifacts
    )
    assert result == expected
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["preparation"]["exit"] == 0
    assert [row["section"] for row in report["sections"]] == ["isolation", "access"]
    assert all(row["cleanup"] == "stopped" for row in report["sections"])
    assert report["sections"][0]["result"] == {
        0: "passed", 1: "assertion_failure", 2: "preparation_failure"
    }[failure]
    first, second = directory / "isolation", directory / "access"
    assert (first / "share/kernel").stat().st_ino == (second / "share/kernel").stat().st_ino
    for name in ("token", "certificate", "capture", "approval", "overlay", "nats-instance"):
        assert (first / name).read_text() != (second / name).read_text()
    assert not list(directory.glob("*/agents/*/container.pid"))
    assert not list(directory.glob("*/data/proxy-rust.json"))
    selected = json.loads((second / "selection.json").read_text())
    assert "--access" in selected and selected[-2:] == ["--install-commit", "a" * 40]


def test_installed_sections_do_not_continue_across_unclean_boundary(
    tmp_path, monkeypatch, installed_section_commands
):
    monkeypatch.setenv("FAIL_CLEANUP", "1")
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, directory, artifacts
    ) == 2
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert len(report["sections"]) == 1
    assert report["sections"][0]["cleanup"] == "failed"
    assert any("agent stop bbtest exited 7" in error for error in report["sections"][0]["cleanup_failures"])
    assert (directory / "isolation/agents/bbtest/container.pid").exists()
    assert not (directory / "access").exists()


@pytest.mark.parametrize("leave_process_live,section_exit,aggregate", [
    (True, 1, False), (False, 1, False), (False, 3, False),
    (False, 3, True), (True, 3, True),
], ids=["survivor", "clean-assertion-failure", "clean-pytest-internal-error",
        "clean-aggregated-pytest-internal-error", "survivor-with-aggregated-infrastructure"])
@pytest.mark.parametrize("owner", [False, True], ids=["subject", "lifecycle-owner"])
def test_installed_sections_preserve_inner_cleanup_outcome(
    tmp_path, monkeypatch, installed_section_commands, installed_pytest_runner,
    leave_process_live, section_exit, aggregate, owner
):
    """Run the real inner trap and outer loop when stop removes a PID marker."""
    repository = installed_section_commands
    scripts = repository / "tests/blackbox"
    stop_script = f"#!{sys.executable}\n" + f"""
import json, os, pathlib, signal, sys, time
sys.path.insert(0, {str(ROOT)!r})
from tests.blackbox.installed_host_smoke import _pid_alive
root = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])
if root.name == 'lifecycle-owner':
    identity = json.loads((root / 'expected-nats-identity.json').read_text())
    assert os.environ['SAFEYOLO_NATS_TEST_INSTANCE'] == identity['owner'] != identity['primary']
    assert os.environ.get('SAFEYOLO_NATS_TEST_PORTS') == identity['ports']
    assert os.environ['SAFEYOLO_COORD_DATA_DIR'] == str(root / 'data/coord')
    assert os.environ['SAFEYOLO_LOG_PATH'] == str(root / 'logs/safeyolo.jsonl')
marker = root / 'data/proxy-rust.json'
if marker.exists():
    pid = json.loads(marker.read_text())['pid']
    marker.unlink()
    if os.environ['LEAVE_PROCESS_LIVE'] == '0':
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while _pid_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not _pid_alive(pid)
"""
    prepare = scripts / "run-lane.sh"
    prepare.write_text(prepare.read_text()
                       + f"(binary_dir / 'safeyolo').write_text({stop_script!r})\n")
    runner = (ROOT / "tests/blackbox/run-tests.sh").read_text()
    trap_start = runner.index("cleanup() {")
    trap_end = runner.index("\n# --- Clean stale state", trap_start)
    section = scripts / "run-tests.sh"
    first_section = "lifecycle" if owner else "isolation"
    owned_root = '"${SAFEYOLO_CONFIG_DIR%/*}/lifecycle-owner"' if owner else '"$SAFEYOLO_CONFIG_DIR"'
    section.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        "export SAFEYOLO_CONFIG_DIR=\"$SAFEYOLO_TEST_CONFIG_DIR\"\n"
        "mkdir -p \"$SAFEYOLO_CONFIG_DIR/data\"\n"
        "touch \"$SAFEYOLO_CONFIG_DIR/config.yaml\"\n"
        "if [ \"${SAFEYOLO_CONFIG_DIR##*/}\" = access ]; then\n"
        "    touch \"$SAFEYOLO_CONFIG_DIR/access-started\"\n"
        "    exit 0\n"
        "fi\n"
        f"SCRIPT_DIR={str(ROOT / 'tests/blackbox')!r}\n"
        f"STARTED_VM=false\nSTARTED_PROXY={'false' if owner else 'true'}\n"
        "STARTED_PARENT=false\nSTARTED_SINKHOLE=false\n"
        "PARENT_PID=\nSINKHOLE_PID=\nHOST_LISTENER_PID=\nPROXY_IMPL=rust\nAGENT_NAME=bbtest\n"
        f"LIFECYCLE={'true' if owner else 'false'}\n"
        + _runner_cleanup_helpers()
        + runner[trap_start:trap_end]
        + f"\nowned_root={owned_root}\n"
        + 'mkdir -p "$owned_root/data"\ntouch "$owned_root/config.yaml"\n'
        + ("python3 - \"$owned_root\" <<'PY_IDENTITY'\n"
           "import json, os, pathlib, sys\n"
           "(pathlib.Path(sys.argv[1]) / 'expected-nats-identity.json').write_text(json.dumps({\n"
           "    'owner': os.environ['SAFEYOLO_LIFECYCLE_OWNER_NATS_TEST_INSTANCE'],\n"
           "    'primary': os.environ['SAFEYOLO_NATS_TEST_INSTANCE'],\n"
           "    'ports': os.environ.get('SAFEYOLO_LIFECYCLE_OWNER_NATS_TEST_PORTS')}))\n"
           "PY_IDENTITY\n" if owner else "")
        + "printf '{\"pid\":%s}\\n' \"$OWNED_TEST_PID\" > \"$owned_root/data/proxy-rust.json\"\n"
        + ('set +e\n"$FIXTURE_INSTALLED_RUNNER"\nexit $?\n' if aggregate else f"exit {section_exit}\n")
    )
    section.chmod(0o755)
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    monkeypatch.setenv("OWNED_TEST_PID", str(process.pid))
    monkeypatch.setenv("LEAVE_PROCESS_LIVE", "1" if leave_process_live else "0")
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}:{os.environ['PATH']}")
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_PORTS", "46370,46372")
    monkeypatch.setenv("FIXTURE_INSTALLED_RUNNER", str(installed_pytest_runner))
    for slot in INSTALLED_PYTEST_SLOTS:
        monkeypatch.setenv(f"FIXTURE_{slot}_EXIT", str(section_exit if slot == "ISOLATION" else 0))
    # pytest owns this child. Darwin keeps a terminated child observable until
    # that parent waits; the stop subprocess cannot reap it on pytest's behalf.
    reaped = threading.Event()
    reap_errors = []
    def reap_owned_child():
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired as exc:
            reap_errors.append(exc)
        finally:
            reaped.set()
    reaper = threading.Thread(target=reap_owned_child)
    reaper.start()
    try:
        result = installed_sections.run_sections(
            "vz" if sys.platform == "darwin" else "systrap",
            (first_section, "access"), repository, "a" * 40, directory, artifacts
        )
        report = json.loads((artifacts / "installed-sections.json").read_text())
        first = report["sections"][0]
        if aggregate:
            assert installed_pytest_runner.with_name("suites.log").read_text().splitlines() == list(INSTALLED_PYTEST_SLOTS)
        assert not (directory / ("lifecycle-owner" if owner else "isolation") / "data/proxy-rust.json").exists()
        if leave_process_live:
            assert process.poll() is None, "the injected stop must leave the owned lifetime live"
            assert result == 2
            assert first["result"] == "cleanup_failure" and first["cleanup"] == "failed"
            assert len(report["sections"]) == 1
            assert not (directory / "access/access-started").exists()
        else:
            assert reaped.wait(timeout=5), "the owning pytest parent must reap the stopped child"
            assert not reap_errors
            expected = 1 if section_exit == 1 else 2
            # The trap-only access fixture has no retained runtime observation.
            # Preserve the first assertion result and the later evidence failure.
            assert result == 2
            assert first["exit"] == expected
            assert first["result"] == ("assertion_failure" if expected == 1 else "preparation_failure")
            assert first["cleanup"] == "stopped"
            assert len(report["sections"]) == 2
            assert (directory / "access/access-started").is_file()
            assert report["sections"][1]["result"] == "evidence_failure"
    finally:
        if process.poll() is None:
            process.terminate()
        reaper.join(timeout=5)
        assert not reaper.is_alive(), "owned fixture child reaping must finish"


def test_installed_sections_attribute_preparation_failure_without_starting_section(
    tmp_path, monkeypatch, installed_section_commands
):
    monkeypatch.setenv("FAIL_PREPARATION", "1")
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, directory, artifacts
    ) == 2
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["preparation"]["exit"] == 9
    assert report["sections"] == []
    assert not (directory / "isolation").exists()
    summary = json.loads((artifacts / "installed-summary.json").read_text())
    assert summary["exit"] == 2 and summary["finished_at"]
    assert summary["preparation"] == {"exit": 9}
    assert summary["unexecuted_sections"] == ["isolation", "access"]


@pytest.mark.parametrize("stage", ["preparation", "section"])
def test_installed_summary_write_failure_stops_before_independent_continuation(
    tmp_path, installed_section_commands, stage
):
    """A real filesystem failure cannot leave a successful or continued run."""
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    artifacts.mkdir()
    if stage == "preparation":
        # A directory cannot be written as the atomic summary's temporary file.
        (artifacts / "installed-summary.json.tmp").mkdir()
    else:
        command = installed_section_commands / "tests/blackbox/run-tests.sh"
        command.write_text(command.read_text().replace(
            "if root.name == 'isolation': sys.exit",
            "(pathlib.Path(os.environ['SAFEYOLO_BLACKBOX_ARTIFACTS_DIR']).parent / "
            "'installed-summary.json.tmp').mkdir()\nif root.name == 'isolation': sys.exit",
        ))
    assert installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, directory, artifacts
    ) == 2
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert not (directory / "access").exists()
    if stage == "preparation":
        assert report["sections"] == []
        assert not (directory / "prepared").exists()
    else:
        assert report["sections"][0]["cleanup"] == "stopped"
        assert not (directory / "isolation/data/proxy-rust.json").exists()
        prior_summary = json.loads((artifacts / "installed-summary.json").read_text())
        assert prior_summary["exit"] is None and prior_summary["finished_at"] is None


@pytest.mark.parametrize("private_report_missing", [False, True])
def test_installed_retry_preserves_the_original_failed_attempt(
    tmp_path, monkeypatch, installed_section_commands, private_report_missing
):
    artifacts = tmp_path / "artifacts"
    monkeypatch.setenv("FAIL_SECTION", "1")
    assert installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40,
        tmp_path / "first-attempt", artifacts,
    ) == 1
    original = {name: (artifacts / name).read_bytes() for name in (
        "installed-sections.json", "installed-summary.json",
    )}
    if private_report_missing:
        (artifacts / "installed-sections.json").unlink()
        del original["installed-sections.json"]
    monkeypatch.delenv("FAIL_SECTION")
    retry = tmp_path / "retry"
    assert installed_sections.run_sections(
        "systrap", ("isolation", "access"), installed_section_commands, "a" * 40, retry, artifacts,
    ) == 2
    assert not retry.exists(), "a colliding retry must not prepare or execute"
    assert {name: (artifacts / name).read_bytes() for name in original} == original


def test_generated_nested_private_annotations_do_not_enter_written_summary(
    tmp_path, monkeypatch, installed_section_commands
):
    """Exercise the real writer with additional fields at every report level."""
    project = installed_sections.publication_summary
    values = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=40),
                          lambda children: st.lists(children, max_size=3)
                          | st.dictionaries(st.text(max_size=20), children, max_size=3), max_leaves=8)
    attempt_number = 0

    @settings(max_examples=20, deadline=None)
    @given(value=values)
    def omit_private_fields(value):
        nonlocal attempt_number
        attempt_number += 1
        marker = "fixture-publication-secret"
        annotation = {"admin_token": marker, "nested": value}

        def annotate_before_projection(report):
            report = copy.deepcopy(report)
            report["private_instance"] = annotation
            report["preparation"]["private_instance"] = annotation
            for row in report["sections"]:
                row["private_instance"] = annotation
                runtime = row.get("installed_runtime")
                if runtime is not None:
                    runtime["private_instance"] = annotation
                    runtime["host"]["private_instance"] = annotation
                    runtime["process"]["private_instance"] = annotation
                for observation in row.get("pytest", []):
                    observation["raw_inspector_export"] = annotation
                    observation["counts"]["private_instance"] = annotation
                    for case in observation["cases"]:
                        case["captured_output"] = annotation
            return project(report)

        monkeypatch.setattr(installed_sections, "publication_summary", annotate_before_projection)
        attempt = tmp_path / str(attempt_number)
        artifacts = attempt / "artifacts"
        assert installed_sections.run_sections(
            "kvm", installed_sections.SECTIONS["kvm"], installed_section_commands, "a" * 40,
            attempt / "installed", artifacts,
        ) == 0
        summary_text = (artifacts / "installed-summary.json").read_text()
        summary = json.loads(summary_text)
        private = json.loads((artifacts / "installed-sections.json").read_text())
        assert marker not in summary_text and str(tmp_path) not in summary_text
        assert summary["full_section_selection"] is True and summary["unexecuted_sections"] == []
        assert summary["run_id"] == private["run_id"] and summary["finished_at"]
        assert all(observation["counts"] == {"passed": 1}
                   for observation in summary["sections"][0]["pytest"])
        assert summary["sections"][0]["pytest"][0]["cases"][0]["test"] == "test_fixture.py::test_case"
        assert all(row["installed_runtime"]["wheel_source_revision"] == "a" * 40
                   and row["installed_runtime"]["native_sha256"] == hashlib.sha256(b"selected native fixture").hexdigest()
                   and row["installed_runtime"]["isolation_platform"] == "kvm" for row in summary["sections"])

    omit_private_fields()


def test_installed_sections_treat_missing_pytest_reports_as_evidence_failure(
    tmp_path, monkeypatch, installed_section_commands
):
    monkeypatch.setenv("OMIT_OBSERVATIONS", "1")
    artifacts = tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "vz" if sys.platform == "darwin" else "systrap", ("isolation", "access"), installed_section_commands, "a" * 40,
        tmp_path / "installed", artifacts,
    ) == 2
    report = json.loads((artifacts / "installed-sections.json").read_text())
    isolation, access = report["sections"]
    assert isolation["result"] == "evidence_failure" and isolation["exit"] == 2
    assert isolation["cleanup"] == "stopped"
    assert len(isolation["evidence_failures"]) == 6
    assert access["result"] == "passed", "clean failure must retain independent continuation"
    summary = json.loads((artifacts / "installed-summary.json").read_text())
    assert summary["exit"] == 2
    assert summary["sections"][0]["evidence_failure_count"] == 6
    assert "evidence_failures" not in summary["sections"][0]


@pytest.mark.parametrize("section_exit", [0, 1, 2])
def test_real_pytest_failure_cannot_be_cleared_by_a_successful_section(
    tmp_path, monkeypatch, installed_section_commands, section_exit
):
    """Retain real guest pytest failures through local config and section precedence."""
    run = installed_sections.subprocess.run
    blackbox = tmp_path / "guest-workspace/tests/blackbox"
    isolation = blackbox / "isolation"
    isolation.mkdir(parents=True)
    source = ROOT / "tests/blackbox"
    for name in ("_docstring_lint.py", "pytest_observations.py"):
        shutil.copy2(source / name, blackbox / name)
    for name in ("conftest.py", "pytest.ini"):
        shutil.copy2(source / "isolation" / name, isolation / name)
    suite = isolation / "test_failed_observation.py"
    suite.write_text('''def test_failed_observation():
    """Retain a failed guest assertion.

    What: Fail one disposable assertion under the real guest conftest.
    Why: A successful section cannot erase a failed pytest outcome.
    """
    assert False, 'fixture-private-diagnostic'
''')
    monkeypatch.setenv("FAIL_SECTION", str(section_exit))

    def retain_failed_pytest(command, **options):
        result = run(command, **options)
        if Path(command[0]).name == "run-tests.sh" and Path(options["env"]["SAFEYOLO_TEST_CONFIG_DIR"]).name == "isolation":
            env = {key: value for key, value in options["env"].items()
                   if key not in ("PYTHONPATH", "SAFEYOLO_BLACKBOX_OBSERVATIONS_DIR")}
            env.update(PYTEST_ADDOPTS="", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
                       SAFEYOLO_BLACKBOX_ISOLATION="1")
            for pytest_suite in ("isolation", "root-isolation"):
                retained = Path(options["env"]["SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"]) / f"pytest-{pytest_suite}.json"
                retained.unlink()  # The fake section's report must not hide missing guest output.
                output = tmp_path / "guest-home" / f"bb-{pytest_suite}.json"
                env.update(SAFEYOLO_BLACKBOX_PYTEST_SUITE=pytest_suite,
                           SAFEYOLO_BLACKBOX_OBSERVATIONS_PATH=str(output))
                pytest_result = run(
                    [sys.executable, "-m", "pytest", "-q", suite.name],
                    cwd=isolation, env=env, capture_output=True, text=True, timeout=30, check=False,
                )
                assert pytest_result.returncode == 1, pytest_result.stdout + pytest_result.stderr
                shutil.copy2(output, retained)
        return result

    monkeypatch.setattr(installed_sections.subprocess, "run", retain_failed_pytest)
    artifacts = tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "vz" if sys.platform == "darwin" else "systrap", ("isolation", "access"), installed_section_commands, "a" * 40,
        tmp_path / "installed", artifacts,
    ) == (section_exit or 2)
    summary_text = (artifacts / "installed-summary.json").read_text()
    summary = json.loads(summary_text)
    isolation, access = summary["sections"]
    assert isolation["result"] == {0: "evidence_failure", 1: "assertion_failure", 2: "preparation_failure"}[section_exit]
    assert isolation["evidence_failure_count"] == (2 if section_exit == 0 else 0)
    observed = [data for data in isolation["pytest"] if data["suite"] in ("isolation", "root-isolation")]
    assert len(observed) == 2
    assert all(data["exit"] == 1 and data["counts"] == {"failed": 1} for data in observed)
    assert isolation["cleanup"] == access["cleanup"] == "stopped"
    assert access["result"] == "passed" and summary["unexecuted_sections"] == []
    assert "fixture-private-diagnostic" not in summary_text and str(tmp_path) not in summary_text
    assert not list((tmp_path / "installed").glob("*/agents/*/container.pid"))


def test_generated_pytest_results_are_consistent_with_successful_sections(
    tmp_path, monkeypatch, installed_section_commands
):
    """Retain failed and skipped outcomes through actual section reports."""
    run = installed_sections.subprocess.run
    attempt_number = 0

    @settings(max_examples=30, deadline=None)
    @given(suite=st.sampled_from(installed_sections.PYTEST_SUITES), exit_code=st.integers(min_value=0, max_value=5),
           outcome=st.sampled_from(("passed", "failed", "skipped")))
    @example(suite="isolation", exit_code=0, outcome="failed")
    @example(suite="native", exit_code=2, outcome="passed")
    @example(suite="isolation", exit_code=0, outcome="passed")
    @example(suite="isolation", exit_code=0, outcome="skipped")
    def check_result(suite, exit_code, outcome):
        nonlocal attempt_number
        attempt_number += 1

        def alter_pytest_result(command, **options):
            result = run(command, **options)
            if Path(command[0]).name == "run-tests.sh" and Path(options["env"]["SAFEYOLO_TEST_CONFIG_DIR"]).name == "isolation":
                path = Path(options["env"]["SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"]) / f"pytest-{suite}.json"
                data = json.loads(path.read_text())
                data.update(exit=exit_code, counts={outcome: 1})
                data["cases"][0].update(outcome=outcome, phase="setup" if outcome == "skipped" else "call")
                path.write_text(json.dumps(data))
            return result

        monkeypatch.setattr(installed_sections.subprocess, "run", alter_pytest_result)
        attempt = tmp_path / str(attempt_number)
        artifacts = attempt / "artifacts"
        failed = exit_code != 0 or outcome == "failed"
        assert installed_sections.run_sections(
            "kvm", ("isolation", "workloads"), installed_section_commands, "a" * 40,
            attempt / "installed", artifacts,
        ) == (2 if failed else 0)
        summary = json.loads((artifacts / "installed-summary.json").read_text())
        isolation, continuation = summary["sections"]
        assert isolation["result"] == ("evidence_failure" if failed else "passed")
        assert isolation["evidence_failure_count"] == int(failed)
        assert isolation["cleanup"] == continuation["cleanup"] == "stopped"
        assert continuation["result"] == "passed"
        observed = next(data for data in isolation["pytest"] if data["suite"] == suite)
        assert observed["exit"] == exit_code and observed["counts"] == {outcome: 1}

    check_result()


@pytest.mark.parametrize("failure", (
    "missing", "symlink", "fifo", "runtime-scalar", "runtime-list", "doctor-missing", "doctor-scalar", "doctor-checks",
    "platform", "run", "source", "wheel", "wheel-state", "native", "executable", "captured", "past", "future", "timezone", "host", "machine",
    "process", "pid-bool", "receipt-pid", "readiness", "backend", "start-token", "auth", "auth-schema", "auth-instance",
))
@pytest.mark.timeout(15)
def test_installed_runtime_evidence_failure_is_saved_without_hiding_clean_continuation(
    tmp_path, monkeypatch, installed_section_commands, failure
):
    run = installed_sections.subprocess.run
    marker = "fixture-runtime-private-secret"

    def alter_saved_observation(command, **options):
        result = run(command, **options)
        if Path(command[0]).name != "run-tests.sh" or "--access" not in command:
            return result
        artifacts = Path(options["env"]["SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"])
        path = artifacts / "installed-rust-runtime.json"
        data = json.loads(path.read_text())
        data["private_instance"] = {"admin_token": marker}
        if failure in {"missing", "symlink", "fifo"}:
            path.unlink()
            if failure == "symlink":
                private = artifacts / "private-token.json"
                private.write_text(json.dumps({"private_token": marker}))
                path.symlink_to(private)
            elif failure == "fifo":
                os.mkfifo(path)
            return result
        if failure == "doctor-missing":
            (artifacts / "doctor.json").unlink()
        elif failure.startswith("doctor-") or failure == "platform":
            doctor = {"checks": [{"name": "Isolation platform", "message": "KVM fixture"}]}
            if failure == "doctor-scalar":
                doctor = marker
            elif failure == "doctor-checks":
                doctor["checks"] = [marker]
            (artifacts / "doctor.json").write_text(json.dumps(doctor))
        elif failure in {"runtime-scalar", "runtime-list"}:
            data = marker if failure == "runtime-scalar" else [marker]
        elif failure in {"run", "source", "captured"}:
            data[{"run": "run_id", "source": "source_revision", "captured": "captured_at"}[failure]] = {
                "run": "b" * 32, "source": "b" * 40, "captured": marker,
            }[failure]
        elif failure in {"past", "future"}:
            data["captured_at"] = "2020-01-01T00:00:00+00:00" if failure == "past" else "9999-01-01T00:00:00+00:00"
        elif failure == "timezone":
            data["captured_at"] = "2020-01-01T00:00:00"
        elif failure.startswith("wheel"):
            data["build_identity"]["state" if failure == "wheel-state" else "source_revision"] = marker
        elif failure == "native":
            data["candidate"]["sha256"] = "e" * 64
        elif failure == "executable":
            data["runtime"]["actual_executable"] = "/unrelated/" + marker
        elif failure in {"host", "machine"}:
            data["host"]["system" if failure == "host" else "machine"] = {} if failure == "machine" else "Darwin"
        elif failure == "process":
            data["runtime"] = marker
        elif failure == "pid-bool":
            data["runtime"]["pid"] = True
        elif failure.startswith("receipt") or failure == "start-token":
            data["runtime"]["receipt"]["pid" if failure == "receipt-pid" else "start_token"] = marker
        elif failure in {"readiness", "backend"}:
            data["runtime"]["readiness"]["ready" if failure == "readiness" else "backend"] = marker
        else:
            data["runtime"]["authenticated_runtime_identity"][{
                "auth": "status", "auth-schema": "schema_version", "auth-instance": "instance_id",
            }[failure]] = True if failure == "auth-schema" else marker
        path.write_text(json.dumps(data))
        return result

    monkeypatch.setattr(installed_sections.subprocess, "run", alter_saved_observation)
    artifacts = tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "systrap", ("access", "workloads"), installed_section_commands, "a" * 40,
        tmp_path / "installed", artifacts,
    ) == 2
    private = json.loads((artifacts / "installed-sections.json").read_text())
    summary_text = (artifacts / "installed-summary.json").read_text()
    summary = json.loads(summary_text)
    first, continuation = summary["sections"]
    assert first["exit"] == 2 and first["result"] == "evidence_failure" and first["cleanup"] == "stopped"
    assert first["evidence_failure_count"] == 1 and "installed_runtime" not in first
    assert continuation["exit"] == 0 and continuation["result"] == "passed" and continuation["cleanup"] == "stopped"
    assert continuation["installed_runtime"]["run_id"] == private["run_id"]
    assert summary["exit"] == 2 and summary["finished_at"] and summary["unexecuted_sections"] == []
    assert marker not in summary_text and str(tmp_path) not in summary_text
    assert marker not in private["sections"][0]["evidence_failures"][0]


def test_generated_runtime_annotations_do_not_enter_installed_publication(tmp_path, monkeypatch, installed_section_commands):
    run = installed_sections.subprocess.run
    values = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=30),
                          lambda children: st.lists(children, max_size=3)
                          | st.dictionaries(st.text(max_size=20), children, max_size=3), max_leaves=8)
    attempts = 0

    @settings(max_examples=20, deadline=None)
    @given(annotation=values)
    def project(annotation):
        nonlocal attempts
        attempts += 1
        marker = "fixture-runtime-private-secret"

        def annotate_report(command, **options):
            result = run(command, **options)
            if Path(command[0]).name == "run-tests.sh":
                path = Path(options["env"]["SAFEYOLO_BLACKBOX_ARTIFACTS_DIR"]) / "installed-rust-runtime.json"
                data = json.loads(path.read_text())
                for fields in (data, data["host"], data["candidate"], data["build_identity"], data["runtime"],
                               data["runtime"]["receipt"], data["runtime"]["authenticated_runtime_identity"]):
                    fields["private_instance"] = {"admin_token": marker, "annotation": annotation}
                path.write_text(json.dumps(data))
            return result

        monkeypatch.setattr(installed_sections.subprocess, "run", annotate_report)
        attempt = tmp_path / str(attempts)
        artifacts = attempt / "artifacts"
        assert installed_sections.run_sections(
            "kvm", installed_sections.SECTIONS["kvm"], installed_section_commands, "a" * 40,
            attempt / "installed", artifacts,
        ) == 0
        text = (artifacts / "installed-summary.json").read_text()
        summary = json.loads(text)
        assert marker not in text and str(tmp_path) not in text
        assert summary["preparation"]["native_sha256"] == hashlib.sha256(b"selected native fixture").hexdigest()
        for row in summary["sections"]:
            observed = row["installed_runtime"]
            assert observed["wheel_source_revision"] == "a" * 40 and observed["run_id"] == summary["run_id"]
            assert observed["isolation_platform"] == "kvm" and observed["process"]["pid"] > 1
            assert set(observed["process"]) == {"pid", "start_token", "instance_id"}

    project()


def test_generated_invalid_runtime_fields_fail_at_the_retained_report_boundary(tmp_path, installed_section_commands):
    artifacts = tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "kvm", ("ingress",), installed_section_commands, "a" * 40, tmp_path / "installed", artifacts,
    ) == 0
    report = json.loads((artifacts / "installed-sections.json").read_text())
    row = report["sections"][0]
    path = artifacts / "ingress/installed-rust-runtime.json"
    original = json.loads(path.read_text())
    fields = st.sampled_from((
        ("status",), ("run_id",), ("source_revision",), ("captured_at",),
        ("build_identity",), ("build_identity", "source_revision"), ("build_identity", "state"),
        ("candidate",), ("candidate", "sha256"), ("candidate", "path"), ("cli", "package_location"),
        ("host",), ("host", "system"), ("host", "machine"), ("runtime",), ("runtime", "status"), ("runtime", "pid"),
        ("runtime", "receipt"), ("runtime", "receipt", "start_token"), ("runtime", "readiness"),
        ("runtime", "authenticated_runtime_identity"), ("runtime", "authenticated_runtime_identity", "schema_version"),
    ))
    nested = st.recursive(st.none() | st.booleans() | st.integers(max_value=0),
                          lambda children: st.lists(children, max_size=3)
                          | st.dictionaries(st.text(max_size=15), children, max_size=3), max_leaves=8)
    marker = "fixture-runtime-private-secret"

    @settings(max_examples=80, deadline=None)
    @given(field=fields, value=nested | st.text(max_size=30).map(lambda text: marker + text))
    def reject(field, value):
        data = copy.deepcopy(original)
        parent = data
        for name in field[:-1]:
            parent = parent[name]
        parent[field[-1]] = value
        path.write_text(json.dumps(data))
        observed, failures = installed_sections.installed_runtime_observation(
            path.parent, report, row["started_at"], row["finished_at"],
        )
        assert observed is None and len(failures) == 1
        assert marker not in failures[0]

    reject()


def test_vz_runtime_projection_uses_darwin_identity_in_a_controlled_host_context(
    tmp_path, monkeypatch, installed_section_commands
):
    """A Linux fixture substitutes host discovery; this does not boot a VZ guest."""
    monkeypatch.setattr(installed_sections.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(installed_sections.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(installed_sections, "check_vz_ports", lambda **_kwargs: [])
    artifacts = tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "vz", ("access", "lifecycle"), installed_section_commands, "a" * 40, tmp_path / "installed", artifacts,
    ) == 0
    summary = json.loads((artifacts / "installed-summary.json").read_text())
    for row in summary["sections"]:
        observed = row["installed_runtime"]
        assert observed["host"] == {"system": "Darwin", "machine": "arm64"}
        assert observed["isolation_platform"] == "vz"
        assert observed["process"]["start_token"].startswith(f"darwin:{observed['process']['pid']}:")


@pytest.mark.parametrize("explicit", [False, True])
def test_installed_attached_invocation_receives_selected_source_before_guest_tests(tmp_path, explicit):
    """Execute the maintained Bash invocation with a bounded argument spy."""
    source = (ROOT / "tests/blackbox/run-tests.sh").read_text()
    selection = source[source.index("INSTALL_COMMIT_ARGS=()"):
                       source.index("# The physical VZ test account")]
    start = source.index('if [ "$PROXY_IMPL" = "rust" ] && [ "$RUN_ISOLATION" = true ]; then\n    ARTIFACTS_DIR=')
    attached = source[start:source.index("\ntrap - ERR", start)]
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    recorded = tmp_path / "args.json"
    (scripts / "installed_host_smoke.py").write_text(
        "import json, os, pathlib, sys\npathlib.Path(os.environ['FIXTURE_ARGS']).write_text(json.dumps(sys.argv[1:]))\n"
    )
    env = dict(os.environ, INSTALL_COMMIT="a" * 40 if explicit else "",
               SAFEYOLO_BLACKBOX_INSTALL_REVISION="b" * 40, PROXY_IMPL="rust", RUN_ISOLATION="true",
               SCRIPT_DIR=str(scripts), INSTALLED_CLI="/installed cli", INSTALLED_RUST_BIN="/packaged native",
               SAFEYOLO_CONFIG_DIR="/private instance", AGENT_NAME="bbtest", FIXTURE_ARGS=str(recorded))
    result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + selection + attached], env=env,
                            capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    args = json.loads(recorded.read_text())
    assert args[args.index("--install-commit") + 1] == ("a" * 40 if explicit else "b" * 40)
    assert args[args.index("--cli") + 1] == "/installed cli"
    assert args[args.index("--rust-bin") + 1] == "/packaged native"


def test_installed_staged_preparation_failure_retains_every_unexecuted_section(
    tmp_path, monkeypatch, installed_section_commands
):
    from tests.blackbox import installed_staging

    def reject(*args):
        raise ValueError("input index does not match trusted digest")

    monkeypatch.setattr(installed_staging, "prepare_inputs", reject)
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "vz", installed_sections.SECTIONS["vz"], installed_section_commands, "a" * 40,
        directory, artifacts, staged_inputs=tmp_path / "payload", staged_sha256="b" * 64,
    ) == 2
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["preparation"]["exit"] == 2
    assert report["unexecuted_sections"] == list(installed_sections.SECTIONS["vz"])
    assert not (directory / "prepared").exists(), "staged rejection must not fall back to source preparation"


def test_vz_continuity_forwards_the_allocated_parent_ports_and_private_state(
    tmp_path, installed_section_commands, monkeypatch
):
    repository = installed_section_commands
    test_bin = repository / ".venv/bin"
    test_bin.mkdir(parents=True)
    (test_bin / "python").symlink_to(sys.executable)
    procedure = repository / "tests/blackbox/installed_state_transition.py"
    procedure.write_text("""
import json, os, pathlib, sys
output = pathlib.Path(sys.argv[sys.argv.index('--output')+1])
root = pathlib.Path(sys.argv[sys.argv.index('--config-dir')+1])
assert not root.exists()
root.mkdir()
output.write_text(json.dumps({'args': sys.argv[1:], 'nats_ports': os.environ['SAFEYOLO_NATS_TEST_PORTS']}))
""")
    # This is an invocation control on Linux, not a physical Mac port witness.
    monkeypatch.setattr(installed_sections, "check_vz_ports", lambda **_kwargs: [])
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "vz", ("continuity",), repository, "a" * 40, directory, artifacts,
    ) == 0
    document = json.loads((artifacts / "continuity/installed-continuity.json").read_text())
    arguments = document["args"]
    for flag, value in installed_sections.VZ_CONTINUITY_DEFAULTS.items():
        assert arguments[arguments.index(f"--{flag}") + 1] == str(value)
    assert arguments[arguments.index("--state-parent") + 1] == str(directory)
    assert arguments[arguments.index("--prepared-config") + 1] == str(directory / "prepared")
    assert document["nats_ports"] == "46370,46372"


def test_vz_port_preflight_preserves_a_foreign_live_listener(tmp_path, installed_section_commands):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as foreign:
        foreign.bind(("127.0.0.1", 46373))
        foreign.listen()
        directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
        assert installed_sections.run_sections(
            "vz", ("continuity",), installed_section_commands, "a" * 40, directory, artifacts,
        ) == 2
        report = json.loads((artifacts / "installed-sections.json").read_text())
        assert report["unexecuted_sections"] == ["continuity"]
        assert report["sections"][0]["executed"] is False
        assert "46373" in report["sections"][0]["error"]
        assert not (directory / "continuity").exists()
        with socket.create_connection(foreign.getsockname(), timeout=1):
            accepted, _ = foreign.accept()
            accepted.close()


def test_vz_sections_forward_deadline_supervision_to_installed_commands(
    tmp_path, installed_section_commands, monkeypatch
):
    repository = installed_section_commands
    test_bin = repository / ".venv/bin"
    test_bin.mkdir(parents=True)
    (test_bin / "python").symlink_to(sys.executable)
    procedure = repository / "tests/blackbox/installed_state_transition.py"
    procedure.write_text("""
import json, os, pathlib, sys
output = pathlib.Path(sys.argv[sys.argv.index('--output')+1])
root = pathlib.Path(sys.argv[sys.argv.index('--config-dir')+1])
root.mkdir()
output.write_text(json.dumps({name: os.environ.get(name) for name in
    ('SAFEYOLO_VZ_TEST_RUNNER', 'SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS')}))
""")
    monkeypatch.setattr(installed_sections, "check_vz_ports", lambda **_kwargs: [])
    runner = tmp_path / "trusted-runner"
    runner.write_text("#!/bin/sh\nexit 0\n")
    runner.chmod(0o755)
    artifacts = tmp_path / "artifacts"
    assert installed_sections.run_sections(
        "vz", ("continuity",), repository, "a" * 40, tmp_path / "installed", artifacts,
        vz_test_runner=(runner, 900),
    ) == 0
    report = json.loads((artifacts / "continuity/installed-continuity.json").read_text())
    assert report == {"SAFEYOLO_VZ_TEST_RUNNER": str(runner), "SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS": "900"}


@pytest.mark.parametrize("stale", (False, True))
def test_section_cleanup_observes_owned_supervisor_and_helper_only(tmp_path, stale):
    root = tmp_path / "instance"
    agent = root / "agents/bbtest"
    agent.mkdir(parents=True)
    (root / "config.yaml").write_text("owned fixture")
    cli = tmp_path / "cli"
    cli.write_text(f"#!{sys.executable}\n" + """
import os, pathlib
for path in pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR']).glob('agents/*/vm*'):
    path.unlink()
""")
    cli.chmod(0o755)
    processes = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]) for _ in range(2)]
    try:
        from safeyolo.runtime_identity import process_start_token

        (agent / "vm.pid").write_text(str(processes[1].pid))
        (agent / "vm-supervisor.json").write_text(json.dumps({
            "pid": processes[0].pid,
            "start_token": "older-runner" if stale else process_start_token(processes[0].pid),
            "helper_pid": processes[1].pid,
            "helper_start_token": "older-helper" if stale else process_start_token(processes[1].pid),
        }))
        failures = installed_sections.cleanup_instance(cli, root)
        assert not (agent / "vm-supervisor.json").exists()
        if stale:
            assert failures == [], "reused foreign PIDs in the receipt and vm.pid are not owned"
        else:
            assert all(f"owned process {process.pid} is still live" in failures for process in processes)
        assert all(process.poll() is None for process in processes)
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=5)


@pytest.mark.parametrize("failure,expected,results", [
    ({}, 0, ["passed", "passed"]),
    ({"FAIL_SECTION": "1"}, 1, ["assertion_failure", "passed"]),
    ({"FAIL_SECTION": "2"}, 2, ["preparation_failure", "passed"]),
    ({"FAIL_PREPARATION": "1"}, 2, []),
    ({"FAIL_CLEANUP": "1"}, 2, ["cleanup_failure"]),
])
def test_installed_sections_start_and_clean_up_without_an_installed_python_package(
    tmp_path, installed_section_commands, failure, expected, results
):
    """A clean-shell parent must inspect cleanup and save each section result."""
    repository = installed_section_commands
    scripts = repository / "tests/blackbox"
    for name in ("run-installed.sh", "installed_sections.py", "installed_host_smoke.py", "assert-platform.py"):
        shutil.copy2(ROOT / "tests/blackbox" / name, scripts / name)
    package = repository / "cli/src/safeyolo"
    package.mkdir(parents=True)
    for name in ("__init__.py", "runtime_identity.py"):
        shutil.copy2(ROOT / "cli/src/safeyolo" / name, package / name)
    for command in (
        ["git", "init", "--quiet"],
        ["git", "add", "."],
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
         "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "clean host fixture"],
    ):
        subprocess.run(command, cwd=repository, check=True, capture_output=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    clean_env = tmp_path / "clean-python"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(clean_env)], check=True)
    env = {key: value for key, value in os.environ.items()
           if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
           and not key.startswith("FAIL_")}
    home = tmp_path / "bare-home"
    home.mkdir()
    env.update(PATH=f"{clean_env / 'bin'}:/usr/bin:/bin", HOME=str(home),
               PYTHONNOUSERSITE="1", **failure)
    # This interpreter has neither the checkout package nor development
    # dependencies. A later preparation child cannot add imports to its parent.
    subprocess.run([str(clean_env / "bin/python3"), "-c",
                    "import importlib.util; assert importlib.util.find_spec('safeyolo') is None"],
                   cwd=repository, env=env, check=True)
    assert not (repository / ".venv").exists()
    artifacts = tmp_path / "literal artifacts $(unused) ; [space]"
    lane = "vz" if sys.platform == "darwin" else "systrap"
    result = subprocess.run(
        [str(scripts / "run-installed.sh"), lane, "--section", "isolation",
         "--section", "access", "--install-checkout", str(repository),
         "--install-commit", revision, "--artifacts", str(artifacts)],
        cwd=repository, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["source_revision"] == revision
    assert report["preparation"]["exit"] == (9 if "FAIL_PREPARATION" in failure else 0)
    assert [row["result"] for row in report["sections"]] == results
    summary_text = (artifacts / "installed-summary.json").read_text()
    summary = json.loads(summary_text)
    assert summary["run_id"] == report["run_id"] and summary["source_revision"] == revision
    assert summary["exit"] == expected and summary["finished_at"]
    assert summary["full_section_selection"] is False
    assert [row["result"] for row in summary["sections"]] == results
    assert str(tmp_path) not in summary_text
    assert "config_dir" not in summary_text and "cleanup_failures" not in summary_text
    for row in report["sections"]:
        root = Path(row["config_dir"])
        if row["result"] == "cleanup_failure":
            assert row["cleanup"] == "failed" and row["cleanup_failures"]
            assert (root / "data/proxy-rust.json").exists()
            assert not (root.parent / "access").exists()
        else:
            assert row["cleanup"] == "stopped" and row["cleanup_failures"] == []
            assert not (root / "data/proxy-rust.json").exists()
            assert not (root / "agents/bbtest/container.pid").exists()
        if row["section"] == "access":
            selected = json.loads((root / "selection.json").read_text())
            assert selected[-2:] == ["--install-commit", revision]


def test_installed_source_rejects_ambiguous_commit_before_preparation(tmp_path):
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-installed.sh"), "systrap", "--install-commit", "abcd1234"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 2
    assert "exact full selected commit" in result.stderr
    assert "Prepared product and section state:" not in result.stdout


def test_cleanup_cannot_hide_a_live_owned_process_by_removing_its_pid_file(tmp_path, monkeypatch):
    # The hardware wrapper can leave tmux in the C locale. Observe all exact
    # identities there without relying on an ambient UTF-8 LC_CTYPE.
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.delenv("LC_CTYPE", raising=False)
    # Darwin's temporary pytest paths can exceed the Unix socket limit.
    console_directory = tempfile.TemporaryDirectory(prefix="t889-", dir="/tmp")
    root = Path(console_directory.name).resolve() / "instance space"
    (root / "data").mkdir(parents=True)
    (root / "config.yaml").write_text("owned fixture")
    cli = tmp_path / "cli"
    cli.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib\n"
        "(pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR']) / 'data/proxy-rust.json').unlink()\n"
    )
    cli.chmod(0o755)
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    tmux = shutil.which("tmux")
    socket_path = root / "data/traffic-tmux.sock"
    base = [tmux, "-S", str(socket_path), "-f", "/dev/null"]
    try:
        # Where the maintained tmux prerequisite is installed, dispose a dead
        # console even when another owned process survives. The original
        # marker-removal control runs on hosts without that prerequisite too.
        if tmux is not None:
            (root / "bin").mkdir()
            private_tmux = root / "bin/safeyolo-tmux"
            shutil.copy2(tmux, private_tmux)
            subprocess.run([*base, "new-session", "-d", "-s", "safeyolo-traffic", "sleep 30"], check=True)
            subprocess.run([*base, "set-option", "-t", "safeyolo-traffic", "remain-on-exit", "on"], check=True)
            console = installed_sections.console_process(root)
            subprocess.run([*base, "send-keys", "-t", "safeyolo-traffic:0.0", "C-c"], check=True)
        (root / "data/proxy-rust.json").write_text(json.dumps({"pid": process.pid}))
        failures = installed_sections.cleanup_instance(cli, root)
        assert not (root / "data/proxy-rust.json").exists()
        assert any(f"owned process {process.pid} is still live" == error for error in failures)
        assert process.poll() is None
        if tmux is None:
            return
        assert installed_sections.surviving_processes([console]) == []
        assert installed_sections.console_process(root) is None
        # A new instance at this socket is not the old snapshot's server.
        subprocess.run([*base, "new-session", "-d", "-s", "safeyolo-traffic", "sleep 30"], check=True)
        replacement = installed_sections.console_process(root)
        assert installed_sections.stop_owned_console([console])
        assert installed_sections.console_process(root) == replacement
        assert installed_sections.surviving_processes([replacement])
        # Removing the private runtime makes observation fail visibly.
        private_tmux.write_text("not executable")
        private_tmux.chmod(0o644)
        (root / "data/proxy-rust.json").write_text(json.dumps({"pid": process.pid}))
        failures = installed_sections.cleanup_instance(cli, root)
        assert any("owned process inspection" in error for error in failures)
        assert installed_sections.surviving_processes([replacement])
    finally:
        if tmux is not None:
            subprocess.run([*base, "kill-session", "-t", "safeyolo-traffic"], capture_output=True, check=False)
        process.terminate()
        process.wait(timeout=5)
        console_directory.cleanup()


def test_continuity_keeps_nats_in_its_state_directory_with_a_valid_instance(tmp_path, monkeypatch):
    from safeyolo.coord import nats_runtime

    root = tmp_path / ("installed-native-continuity-" + "x" * 80)
    env = continuity.env_for(root)
    for key in ("SAFEYOLO_NATS_TEST_INSTANCE", "SAFEYOLO_COORD_DATA_DIR"):
        monkeypatch.setenv(key, env[key])
    assert nats_runtime.nats_root() == root / "data/coord/nats"
    assert env["SAFEYOLO_NATS_TEST_INSTANCE"] != continuity.env_for(root.with_name("peer"))["SAFEYOLO_NATS_TEST_INSTANCE"]


@pytest.mark.parametrize("host,bind_host", [
    ("127.0.0.1", "127.0.0.1"),
    # Use Darwin's configured IPv6 loopback as the second bind address.
    ("::1", "::1") if sys.platform == "darwin" else ("127.0.0.2", "127.0.0.2"),
    ("127.0.0.2", "127.0.0.1"),
])
def test_continuity_tls_origin_uses_selected_bind_address_and_certificate(tmp_path, host, bind_host):
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    with socket.socket(family) as reserve:
        reserve.bind((bind_host, 0))
        port = reserve.getsockname()[1]
    origin, root_cert = continuity.https_origin(tmp_path, host, port, bind_host)
    assert origin.server_address[:2] == (bind_host, port)
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    context = ssl.create_default_context(cafile=root_cert)
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    try:
        with socket.create_connection((bind_host, port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secured:
                connection = http.client.HTTPConnection(host, port, timeout=3)
                connection.sock = secured
                try:
                    connection.request("GET", "/selected-host")
                    response = connection.getresponse()
                    assert response.status == 200 and response.read() == continuity.BODY
                finally:
                    connection.close()
        wrong_host = "127.0.0.2" if host == "127.0.0.1" else "127.0.0.1"
        with socket.create_connection((bind_host, port), timeout=3) as raw:
            with pytest.raises(ssl.SSLCertVerificationError):
                context.wrap_socket(raw, server_hostname=wrong_host)
        with socket.create_connection((bind_host, port), timeout=3) as raw:
            with pytest.raises(ssl.SSLCertVerificationError):
                ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        assert [row["path"] for row in origin.seen] == ["/selected-host"]
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def test_continuity_owned_parent_routes_only_its_tls_origin(tmp_path):
    tls_origin, root_cert = continuity.https_origin(tmp_path, "127.0.0.2", bind_host="127.0.0.1")
    origin = continuity.Origin(("127.0.0.1", 0))
    origin.tls_target = ("127.0.0.2", tls_origin.server_port)
    origin.tls_address = tls_origin.server_address
    threads = [threading.Thread(target=server.serve_forever) for server in (origin, tls_origin)]
    for thread in threads:
        thread.start()
    try:
        connection = http.client.HTTPSConnection(*origin.server_address, timeout=3,
                                                context=ssl.create_default_context(cafile=root_cert))
        connection.set_tunnel(*origin.tls_target)
        try:
            connection.request("GET", "/selected-tunnel")
            response = connection.getresponse()
            assert response.status == 200 and response.read() == continuity.BODY
        finally:
            connection.close()
        invalid = http.client.HTTPConnection(*origin.server_address, timeout=3)
        try:
            invalid.request("CONNECT", f"127.0.0.2:{tls_origin.server_port+1}")
            response = invalid.getresponse()
            assert response.status == 400
            response.read()
        finally:
            invalid.close()
        assert not origin.seen
        assert [row["path"] for row in tls_origin.seen] == ["/selected-tunnel"]
    finally:
        for server in (origin, tls_origin):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
            assert not thread.is_alive()


def test_continuity_owned_parent_keeps_oauth_provider_separate():
    origin = continuity.Origin(("127.0.0.1", 0))
    oauth = continuity.Origin(("127.0.0.1", 0), oauth=True)
    origin.oauth_address = oauth.server_address
    threads = [threading.Thread(target=server.serve_forever) for server in (origin, oauth)]
    for thread in threads:
        thread.start()
    connection = http.client.HTTPConnection(*origin.server_address, timeout=3)
    try:
        connection.request("POST", f"http://127.0.0.1:{oauth.server_port}/oauth/token",
                           body=b"grant_type=refresh_token&refresh_token=synthetic-test")
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 200 and payload["access_token"] == "synthetic-r638-access-v1"
        assert len(oauth.seen) == 1 and oauth.seen[0]["path"] == "/oauth/token"
        assert oauth.seen[0]["body"] == b"grant_type=refresh_token&refresh_token=synthetic-test"
        assert not origin.seen
        connection.request("POST", f"http://127.0.0.2:{origin.server_port}/ordinary?item=one",
                           body=b"separate-origin-body")
        response = connection.getresponse()
        assert response.status == 200 and response.read() == continuity.BODY
        assert origin.seen == [{"method": "POST", "path": "/ordinary?item=one",
                                "body": b"separate-origin-body", "authorization": ""}]
        assert len(oauth.seen) == 1
    finally:
        connection.close()
        for server in (origin, oauth):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
            assert not thread.is_alive()
