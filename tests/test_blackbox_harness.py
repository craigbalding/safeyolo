"""Regression tests for blackbox harness isolation and backend selection."""

import os
import stat
import subprocess
from pathlib import Path

from tests.blackbox.proxy_backend import SelectionError, identity, validate_python_source


def test_harness_assigns_distinct_proxy_admin_and_web_ports():
    harness = (Path(__file__).parent / "blackbox" / "run-tests.sh").read_text()

    assert "TEST_PROXY_PORT=8180" in harness
    assert "TEST_ADMIN_PORT=9190" in harness
    assert "TEST_WEB_PORT=8181" in harness
    assert "config['proxy']['port'] = $TEST_PROXY_PORT" in harness
    assert "config['proxy']['admin_port'] = $TEST_ADMIN_PORT" in harness
    assert "config['proxy']['web_port'] = $TEST_WEB_PORT" in harness


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
