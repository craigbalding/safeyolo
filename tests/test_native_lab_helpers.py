"""Real tmux and native evidence controls; the controller is a deterministic shell fixture."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "cli/src/safeyolo/agent_context/skills/safeyolo-lab-controller"


@pytest.fixture
def guest_binary() -> Path:
    selected = os.environ.get("SAFEYOLO_TEST_GUEST_BINARY")
    binary = Path(selected) if selected else ROOT / "proxy/target/debug/safeyolo-guest"
    if selected:
        assert binary.is_file(), f"Selected native helper is missing: {binary}"
    elif not binary.is_file():
        pytest.skip("Build the native guest helper first")
    return binary.resolve()


@pytest.fixture
def lab(tmp_path: Path, guest_binary: Path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".safeyolo").mkdir(mode=0o700)
    (home / ".safeyolo/AGENTS.md").write_text("Fixture base instructions\n")
    command = home / ".safeyolo-command"
    command.write_text(
        '#!/bin/bash\n'
        'printf "started\\n" >> "$HOME/starts"\n'
        'printf "public-marker\\nAuthorization: Bearer fake-only-secret\\n"\n'
        'while :; do sleep 1; done\n'
    )
    command.chmod(0o755)
    tools = tmp_path / "tools"
    tools.mkdir()
    tmux = shutil.which("tmux")
    assert tmux
    wrapper = tools / "tmux"
    # Keep fixture shells out of the operator's login startup and home. Only
    # terminal viewing is omitted; sessions, panes, processes and capture are real.
    wrapper.write_text(
        '#!/bin/bash\n'
        'shell=0\n'
        'for arg in "$@"; do if [ "$arg" = attach-session ]; then exit 0; fi; done\n'
        'for arg in "$@"; do\n'
        '  case "$arg" in new-session|new-window|respawn-pane) shell=1 ;; esac\n'
        'done\n'
        f'if [ "$shell" = 1 ]; then exec "{tmux}" "$@" "/bin/bash --noprofile --norc"; fi\n'
        f'exec "{tmux}" "$@"\n'
    )
    wrapper.chmod(0o755)
    python_calls = tmp_path / "python-calls"
    for name in ["python", "python3", "uv"]:
        interpreter = tools / name
        interpreter.write_text(f'#!/bin/sh\nprintf "unexpected Python execution\\n" >> "{python_calls}"\nexit 91\n')
        interpreter.chmod(0o755)
    env = {
        "HOME": str(home), "PATH": f"{tools}:/usr/bin:/bin", "TERM": "xterm-256color",
        "SAFEYOLO_AGENT_NAME": "lab-fixture", "SAFEYOLO_GUEST_EXECUTABLE": str(guest_binary),
    }
    socket = home / ".safeyolo/lab-tmux.sock"

    def command_tmux(*args: str) -> str:
        result = subprocess.run([str(wrapper), "-S", str(socket), *args], env=env, capture_output=True, text=True, timeout=10, check=True)
        return result.stdout.strip()

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(SKILL / "scripts/safeyolo-lab"), *args], env=env, capture_output=True, text=True, timeout=15, check=False)

    try:
        yield home, env, command_tmux, run
    finally:
        subprocess.run([tmux, "-S", str(socket), "kill-server"], env=env, capture_output=True, timeout=10, check=False)
    assert not python_calls.exists(), "Reached Lab helpers executed Python"


def test_concurrent_entry_reattach_recovery_intervention_and_teardown(lab):
    home, env, tmux, run = lab
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run("--objective", "compare the same request"), range(2)))
    assert all(result.returncode == 0 for result in results), [(r.stdout, r.stderr) for r in results]
    for _ in range(50):
        if (home / "starts").exists():
            break
        time.sleep(0.05)
    else:
        pytest.fail(tmux("capture-pane", "-p", "-t", "lab", "-S", "-"))
    assert (home / "starts").read_text().splitlines() == ["started"]
    status = json.loads(run("--status", "--json").stdout)
    assert status["owned"] is True and status["controller_alive"] is True
    controller = status["controller_pane"]
    identity = tmux("show-options", "-pqv", "-t", controller, "@safeyolo_lab_controller_run")
    evidence = home / ".safeyolo/lab-evidence"
    evidence.mkdir(mode=0o700)
    (evidence / "experiment-marker").write_text("retained")
    assert run().returncode == 0
    assert tmux("show-options", "-pqv", "-t", controller, "@safeyolo_lab_controller_run") == identity
    assert (home / "starts").read_text().splitlines() == ["started"]
    assert (evidence / "experiment-marker").read_text() == "retained"
    # Direct intervention has an observable effect in an ordinary persistent pane.
    pane = tmux("new-window", "-d", "-P", "-F", "#{pane_id}", "-t", "lab", "-n", "experiment")
    tmux("send-keys", "-t", pane, "-l", "printf 'operator-marker\\n'")
    tmux("send-keys", "-t", pane, "Enter")
    for _ in range(50):
        if "operator-marker\n" in tmux("capture-pane", "-p", "-t", pane):
            break
        time.sleep(0.05)
    else:
        pytest.fail("Operator intervention produced no observed marker")
    peer = tmux("new-session", "-d", "-P", "-F", "#{pane_id}", "-s", "peer")
    peer_pid = tmux("display-message", "-p", "-t", peer, "#{pane_pid}")
    # Kill only the verified owned controller runner; its shell and evidence stay.
    pid = int(identity.split(":", 1)[0])
    os.kill(pid, 15)
    for _ in range(50):
        dead = run("--status", "--json")
        if not json.loads(dead.stdout)["controller_alive"]:
            break
        time.sleep(0.05)
    else:
        pytest.fail("Controller exit was not observed")
    assert run().returncode == 4
    assert run("--recover").returncode == 0
    recovered = json.loads(run("--status", "--json").stdout)
    assert recovered["controller_pane"] == controller and recovered["controller_alive"]
    for _ in range(50):
        if (home / "starts").read_text().splitlines() == ["started", "started"]:
            break
        time.sleep(0.05)
    assert (home / "starts").read_text().splitlines() == ["started", "started"]
    # A failed native export must leave the owned session intact.
    failed_env = dict(env, SAFEYOLO_GUEST_EXECUTABLE="/nonexistent/native-helper")
    failed = subprocess.run([str(SKILL / "scripts/safeyolo-lab"), "--teardown"], env=failed_env, capture_output=True, text=True, timeout=15, check=False)
    assert failed.returncode == 4
    assert json.loads(run("--status", "--json").stdout)["session_exists"]
    result = run("--teardown")
    assert result.returncode == 0, result.stderr
    capture = Path(result.stdout.strip().removeprefix("Lab session removed after redacted evidence capture: "))
    manifest = [json.loads(line) for line in (capture / "manifest.jsonl").read_text().splitlines()]
    assert len(manifest) == 2  # controller and second-window experiment, never peer
    captured = "\n".join((capture / row["captured_path"]).read_text() for row in manifest)
    assert "public-marker" in captured and "operator-marker" in captured
    assert "fake-only-secret" not in captured
    assert all((capture / row["captured_path"]).stat().st_mode & 0o777 == 0o600 for row in manifest)
    assert (capture / "capture-status.txt").read_text() == "status=complete\n"
    assert tmux("display-message", "-p", "-t", peer, "#{pane_pid}") == peer_pid
    assert not json.loads(run("--status", "--json").stdout)["session_exists"]


def test_unowned_session_is_never_adopted_or_removed(lab):
    home, _env, tmux, run = lab
    pane = tmux("new-session", "-d", "-P", "-F", "#{pane_id}", "-s", "lab")
    pid = tmux("display-message", "-p", "-t", pane, "#{pane_pid}")
    for args in [(), ("--recover",), ("--relaunch",), ("--teardown",)]:
        result = run(*args)
        assert result.returncode == 3
        assert tmux("display-message", "-p", "-t", pane, "#{pane_pid}") == pid
    assert not (home / "starts").exists()


def test_native_capture_refuses_credential_and_nontext_files(tmp_path: Path, guest_binary: Path):
    source = tmp_path / "auth.json"
    source.write_text('{"access_token":"fake-only-secret"}')
    output = tmp_path / "evidence"
    for candidate in [source, tmp_path / "binary", tmp_path / "fifo"]:
        if candidate.name == "binary":
            candidate.write_bytes(b"\x00\xff")
        if candidate.name == "fifo":
            os.mkfifo(candidate)
        result = subprocess.run([str(guest_binary), "lab-evidence", "capture", "--output", str(output), "--file", str(candidate)], capture_output=True, timeout=5, check=False)
        assert result.returncode != 0
        assert not output.exists()
    public = tmp_path / "results.txt"
    public.write_text('marker=retained\nAuthorization: Bearer fake-only-secret\n')
    result = subprocess.run([str(guest_binary), "lab-evidence", "capture", "--output", str(output), "--file", str(public)], capture_output=True, text=True, timeout=5, check=True)
    capture = Path(result.stdout.strip())
    row = json.loads((capture / "manifest.jsonl").read_text())
    assert row["source_path"] == str(public)
    text = (capture / row["captured_path"]).read_text()
    assert "marker=retained" in text and "fake-only-secret" not in text
    assert "[REDACTED_CREDENTIAL]" in text


@pytest.mark.parametrize(
    ("field", "header", "token"),
    [
        ("password", "Authorization: Bearer ", "0"),
        ("access_token", "Proxy-Authorization=Basic ", "YWJj"),
        ("client_secret", "aUtHoRiZaTiOn : bearer ", "sk-proj-FakeValue0123456789ABCDE"),
        ("authorization", "Proxy-Authorization: BASIC ", "token\\with-backslash"),
    ],
)
def test_native_capture_redacts_json_credentials_before_header_tokens(
    tmp_path: Path, guest_binary: Path, field: str, header: str, token: str,
):
    source = tmp_path / "results.json"
    source.write_text(json.dumps(
        {field: f'{header}{token}"FAKE_SUFFIX_MARKER', "marker": "PUBLIC_MARKER"},
        separators=(",", ":"),
    ))
    result = subprocess.run(
        [str(guest_binary), "lab-evidence", "capture", "--output", str(tmp_path / "evidence"), "--file", str(source)],
        capture_output=True, text=True, timeout=5, check=True,
    )
    capture = Path(result.stdout.strip())
    row = json.loads((capture / "manifest.jsonl").read_text())
    exported = (capture / row["captured_path"]).read_text()
    assert "FAKE_SUFFIX_MARKER" not in exported
    assert json.loads(exported) == {field: "[REDACTED_CREDENTIAL]", "marker": "PUBLIC_MARKER"}
    assert (capture / "capture-status.txt").read_text() == "status=complete\n"


def test_nested_preparation_uses_native_configuration_and_preserves_retained_state(tmp_path: Path):
    binaries = ROOT / "proxy/target/debug"
    for name in ["safeyolo", "safeyolo-proxy"]:
        if not (binaries / name).is_file():
            pytest.skip("Build the native CLI and proxy first")
    inputs = tmp_path / "inputs"
    (inputs / "bin").mkdir(parents=True)
    for name in ["safeyolo", "safeyolo-proxy"]:
        (inputs / "bin" / name).symlink_to(binaries / name)
    # Only relocate the installed read-only asset path; all preparation and
    # configuration checks execute the real helper and native CLI.
    script = tmp_path / "prepare-nested.sh"
    script.write_text((SKILL / "scripts/prepare-nested.sh").read_text().replace("inputs=/safeyolo/lab-native", f'inputs="{inputs}"'))
    script.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    ca = tmp_path / "outer-ca.pem"
    ca.write_text("readability preflight fixture")
    env = {
        "HOME": str(home), "PATH": "/usr/bin:/bin", "HTTP_PROXY": "http://127.0.0.1:8080",
        "SSL_CERT_FILE": str(ca),
    }
    instance = home / ".safeyolo/lab-inner"
    missing_ca = dict(env, SSL_CERT_FILE=str(tmp_path / "missing-ca"))
    result = subprocess.run([str(script)], env=missing_ca, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode != 0 and not instance.exists()
    result = subprocess.run([str(script)], env=env, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    config = tomllib.loads((instance / "config.toml").read_text())
    assert config["parent_proxy"] == "http://127.0.0.1:8080"
    assert config["listeners"] == [{"agent_id": "lab-client", "socket_path": "data/lab-client.sock", "source_id": "10.80.0.10"}]
    original = (instance / "policy-original.toml").read_bytes()
    assert (instance / "policy.toml").read_bytes() == original
    identity = (instance / "data/instance_id").read_bytes()
    result = subprocess.run([str(script)], env=env, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode != 0 and "already exists" in result.stderr
    assert (instance / "data/instance_id").read_bytes() == identity
    assert (instance / "policy.toml").read_bytes() == original
    assert not (instance / "data/proxy.pid").exists()  # preparation never starts it
