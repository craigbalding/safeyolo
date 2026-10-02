"""Regression tests for blackbox harness isolation and backend selection."""

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
import threading
import tomllib
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

from tests.blackbox import installed_lifecycle as pilot
from tests.blackbox import installed_sections
from tests.blackbox import installed_state_transition as continuity
from tests.blackbox.harness.vz_fixture import P2Fixture, Parent, VZRequest
from tests.blackbox.installed_ingress import installed_identity
from tests.blackbox.isolation import installed_access as guest
from tests.blackbox.proxy_backend import SelectionError, identity
from tests.proxy_contracts import harness as proxy_harness


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
    ["--expect-platform", "vz", "--proxy-impl", "rust", "--p2"],
    ["--expect-platform", "kvm", "--proxy-impl", "python", "--p2"],
    ["--expect-platform", "kvm", "--proxy-impl", "rust", "--p2", "--kvm-p1"],
])
def test_linux_p2_rejects_a_different_lane_before_setup(tmp_path, options):
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
        assert "--p2 requires --expect-platform kvm|systrap --proxy-impl rust" in result.stderr
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
FROZEN_R = "2faba3306de7c099e2913e0eebc8907ff3eba148"
POST_DELETION = "d680ef82e4cdd9f1b725a421bccf8496123fd55a"


def test_p3_launcher_targets_match_selected_guest_requests(tmp_path, monkeypatch):
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
        "P3 needs an owned activation target without mandatory context on ordinary hosts"
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
    monkeypatch.setattr(pilot, "guest_command", lambda *_args: [sys.executable, "-u", "-c", script])

    process, first = pilot.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)
    assert pilot.finish_guest(process, first, "drain", "bbtest") == observation["result"]


def test_held_guest_reports_exit_before_ready(monkeypatch):
    monkeypatch.setattr(
        pilot,
        "guest_command",
        lambda *_args: [sys.executable, "-u", "-c", "print('shell preamble', flush=True); raise SystemExit(4)"],
    )

    with pytest.raises(AssertionError, match="exited before its admitted-work boundary"):
        pilot.held_guest("unused", "bbtest", "drain", "p4-" + "a" * 32)


def test_selected_installed_identity_requires_exact_wheel_stamp_and_binary(tmp_path):
    revision = POST_DELETION
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
        installed_identity(runtime, checkout, expected_revision=FROZEN_R)
    wrong_diagnostic = {"checks": [{**diagnostic["checks"][0], "message": "Running /wrong/proxy"}]}
    cli.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if sys.argv[1] == 'doctor': print({json.dumps(json.dumps(wrong_diagnostic))})\n"
        "else: print('native running 4242')\n"
    )
    with pytest.raises(AssertionError):
        installed_identity(runtime, checkout, expected_revision=revision)


def test_install_commit_option_needs_an_installed_pilot(tmp_path):
    result = subprocess.run(
        [str(ROOT / "tests/blackbox/run-tests.sh"), "--install-commit", POST_DELETION],
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


@pytest.fixture
def installed_section_commands(tmp_path, monkeypatch):
    """Owned subprocesses exercise preparation reuse and section cleanup."""
    repository = tmp_path / "repository"
    scripts = repository / "tests/blackbox"
    scripts.mkdir(parents=True)
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
        "import json, os, pathlib, sys, uuid\n"
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


@pytest.mark.parametrize("leave_process_live,section_exit", [(True, 1), (False, 1), (False, 3)],
                         ids=["survivor", "clean-assertion-failure", "clean-pytest-internal-error"])
def test_installed_sections_preserve_inner_cleanup_outcome(
    tmp_path, monkeypatch, installed_section_commands, leave_process_live, section_exit
):
    """Run the real inner trap and outer loop when stop removes a PID marker."""
    repository = installed_section_commands
    scripts = repository / "tests/blackbox"
    stop_script = f"#!{sys.executable}\n" + f"""
import json, os, pathlib, signal, sys, time
sys.path.insert(0, {str(ROOT)!r})
from tests.blackbox.installed_host_smoke import _pid_alive
root = pathlib.Path(os.environ['SAFEYOLO_CONFIG_DIR'])
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
        "STARTED_VM=false\nSTARTED_PROXY=true\nSTARTED_PARENT=false\nSTARTED_SINKHOLE=false\n"
        "PARENT_PID=\nSINKHOLE_PID=\nHOST_LISTENER_PID=\nPROXY_IMPL=rust\nAGENT_NAME=bbtest\n"
        + _runner_cleanup_helpers()
        + runner[trap_start:trap_end]
        + "\nprintf '{\"pid\":%s}\\n' \"$OWNED_TEST_PID\" > \"$SAFEYOLO_CONFIG_DIR/data/proxy-rust.json\"\n"
        f"exit {section_exit}\n"
    )
    section.chmod(0o755)
    directory, artifacts = tmp_path / "installed", tmp_path / "artifacts"
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    monkeypatch.setenv("OWNED_TEST_PID", str(process.pid))
    monkeypatch.setenv("LEAVE_PROCESS_LIVE", "1" if leave_process_live else "0")
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}:{os.environ['PATH']}")
    try:
        result = installed_sections.run_sections(
            "systrap", ("isolation", "access"), repository, "a" * 40, directory, artifacts
        )
        report = json.loads((artifacts / "installed-sections.json").read_text())
        first = report["sections"][0]
        assert not (directory / "isolation/data/proxy-rust.json").exists()
        if leave_process_live:
            assert process.poll() is None, "the injected stop must leave the owned lifetime live"
            assert result == 2
            assert first["result"] == "cleanup_failure" and first["cleanup"] == "failed"
            assert len(report["sections"]) == 1
            assert not (directory / "access/access-started").exists()
        else:
            process.wait(timeout=5)
            expected = 1 if section_exit == 1 else 2
            assert result == expected
            assert first["exit"] == expected
            assert first["result"] == ("assertion_failure" if expected == 1 else "preparation_failure")
            assert first["cleanup"] == "stopped"
            assert len(report["sections"]) == 2
            assert (directory / "access/access-started").is_file()
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


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
    for name in ("run-installed.sh", "installed_sections.py", "installed_host_smoke.py"):
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
    result = subprocess.run(
        [str(scripts / "run-installed.sh"), "systrap", "--section", "isolation",
         "--section", "access", "--install-checkout", str(repository),
         "--install-commit", revision, "--artifacts", str(artifacts)],
        cwd=repository, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    report = json.loads((artifacts / "installed-sections.json").read_text())
    assert report["source_revision"] == revision
    assert report["preparation"]["exit"] == (9 if "FAIL_PREPARATION" in failure else 0)
    assert [row["result"] for row in report["sections"]] == results
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


def test_cleanup_cannot_hide_a_live_owned_process_by_removing_its_pid_file(tmp_path):
    root = tmp_path / "instance"
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
    try:
        (root / "data/proxy-rust.json").write_text(json.dumps({"pid": process.pid}))
        failures = installed_sections.cleanup_instance(cli, root)
        assert not (root / "data/proxy-rust.json").exists()
        assert any(f"owned process {process.pid} is still live" == error for error in failures)
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_continuity_keeps_nats_in_its_state_directory_with_a_valid_instance(tmp_path, monkeypatch):
    from safeyolo.coord import nats_runtime

    root = tmp_path / ("installed-native-continuity-" + "x" * 80)
    env = continuity.env_for(root)
    for key in ("SAFEYOLO_NATS_TEST_INSTANCE", "SAFEYOLO_COORD_DATA_DIR"):
        monkeypatch.setenv(key, env[key])
    assert nats_runtime.nats_root() == root / "data/coord/nats"
    assert env["SAFEYOLO_NATS_TEST_INSTANCE"] != continuity.env_for(root.with_name("peer"))["SAFEYOLO_NATS_TEST_INSTANCE"]


@pytest.mark.parametrize("host,bind_host", [("127.0.0.1", "127.0.0.1"), ("127.0.0.2", "127.0.0.2"),
                                          ("127.0.0.2", "127.0.0.1")])
def test_continuity_tls_origin_uses_selected_bind_address_and_certificate(tmp_path, host, bind_host):
    with socket.socket() as reserve:
        reserve.bind((bind_host, 0))
        port = reserve.getsockname()[1]
    origin, root_cert = continuity.https_origin(tmp_path, host, port, bind_host)
    assert origin.server_address == (bind_host, port)
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    context = ssl.create_default_context(cafile=root_cert)
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
