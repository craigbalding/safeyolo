"""Check guest startup environment and shell-bridge diagnostics."""

import json
import os
import shlex
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("setsid") is None, reason="guest launch requires setsid")
@pytest.mark.parametrize("bridge_state", ["alive", "exited", "absent"])
def test_boot_does_not_wait_for_shell_bridge_diagnostics(tmp_path, bridge_state):
    source = (ROOT / "cli/src/safeyolo/guest-init-per-run.sh").read_text()
    block = source[source.index("if [ -x /safeyolo/guest-shell-bridge ]; then") :]
    block = block[:block.index("# 2. Agent API token")]
    bridge = tmp_path / "bridge"
    bridge_pid = tmp_path / "bridge.pid"
    if bridge_state != "absent":
        bridge.write_text(
            f"#!/bin/sh\necho $$ > {shlex.quote(str(bridge_pid))}\n"
            + ("exec sleep 30\n" if bridge_state == "alive" else "echo deliberate-exit >&2\nexit 17\n")
        )
        bridge.chmod(0o755)
    console = tmp_path / "console"
    # A regular file must append to model writes to the console device.
    block = block.replace("> /dev/console", ">> /dev/console")
    for old, new in (
        ("/safeyolo/guest-shell-bridge", bridge),
        ("/var/log/shell-bridge.log", tmp_path / "bridge.log"),
        ("/dev/console", console),
    ):
        block = block.replace(old, shlex.quote(str(new)))
    # SSH reachability is independent of the diagnostic wait under test.
    block = block.replace("(echo > /dev/tcp/127.0.0.1/22)", "true")
    ready = tmp_path / "boot-continued"
    script = f"""set -e
sleep() {{
    # Hold the diagnostic until boot continues. An inline wait deadlocks.
    while [ ! -f {shlex.quote(str(ready))} ]; do command sleep 0.01; done
    command sleep "$@"
}}
{block}
echo ready > {shlex.quote(str(ready))}
if [ -n "${{SB_PID:-}}" ]; then wait "$!"; fi
"""
    with (tmp_path / "boot.log").open("w") as log:
        process = subprocess.Popen(
            ["bash", "-c", script], stdout=log, stderr=log, start_new_session=True,
        )
        try:
            assert process.wait(timeout=5) == 0
            assert ready.read_text() == "ready\n"
            if bridge_state == "absent":
                assert not console.exists()
            else:
                assert bridge_pid.exists(), "the shell bridge was not launched"
                diagnostic = console.read_text()
                if bridge_state == "alive":
                    assert "guest-shell-bridge alive" in diagnostic
                else:
                    assert "guest-shell-bridge EXITED; log:" in diagnostic
                    assert "deliberate-exit" in diagnostic
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            if bridge_state == "alive" and bridge_pid.exists():
                os.kill(int(bridge_pid.read_text()), signal.SIGTERM)


@pytest.mark.parametrize("boot", ["static", "per-run"])
def test_boot_preserves_literal_proxy_and_ca_values(tmp_path, boot):
    # Read the actual producer literal. /etc/environment readers do not expand
    # shell aliases, even though sourcing the same file in a shell does.
    producer = (ROOT / "proxy/src/host_boot.rs").read_text()
    literal = producer.split('share.join("proxy.env"),', 1)[1].lstrip()
    proxy, _ = json.JSONDecoder().raw_decode(literal)
    share = tmp_path / "share with spaces"
    share.mkdir()
    (share / "proxy.env").write_text(proxy)
    (share / "agent.env").write_text("export SAFEYOLO_YOLO_MODE=1\n")
    mise = tmp_path / "mise-environment"
    mise.write_text("export MISE_DATA_DIR=/home/agent/.mise\n")
    environment, profile = tmp_path / "environment", tmp_path / "profile"
    source = (ROOT / f"cli/src/safeyolo/guest-init-{boot}.sh").read_text()
    block = source[source.index("if [ -f /safeyolo/proxy.env ]; then"):]
    end = "# Start the proxy forwarder." if boot == "static" else "# 1b. Guest-side proxy forwarder"
    block = block[:block.index(end)]
    for old, new in (
        ("/safeyolo/proxy.env", share / "proxy.env"),
        ("/safeyolo/agent.env", share / "agent.env"),
        ("/etc/environment", environment),
        ("/etc/profile.d/safeyolo-proxy.sh", profile),
        ("/etc/safeyolo-mise-environment", mise),
    ):
        block = block.replace(old, shlex.quote(str(new)))
    # Caller values must not affect the fixed guest proxy, bypass list or CA.
    poison = "caller value with spaces, 'quotes', $HOME and `false`"
    incoming = os.environ | dict.fromkeys(
        ("HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE"), poison,
    )
    result = subprocess.run(["sh", "-ec", block], env=incoming,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    expected = dict.fromkeys(
        ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"),
        "http://127.0.0.1:8080",
    ) | dict.fromkeys(("NO_PROXY", "no_proxy"), "localhost,127.0.0.1") | dict.fromkeys(
        ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"),
        "/usr/local/share/ca-certificates/safeyolo.crt",
    ) | {"HOME": "/home/agent", "SAFEYOLO_YOLO_MODE": "1", "MISE_DATA_DIR": "/home/agent/.mise"}
    observed = dict(line.removeprefix("export ").split("=", 1)
                    for line in environment.read_text().splitlines())
    assert observed == expected
    for path in (environment, profile) if boot == "per-run" else (environment,):
        result = subprocess.run(
            ["sh", "-ec", 'set -a; . "$1"; env -0', "environment", str(path)],
            env=incoming, capture_output=True, timeout=10,
        )
        assert result.returncode == 0, result.stderr
        values = dict(entry.split(b"=", 1) for entry in result.stdout.split(b"\0") if entry)
        for key, value in expected.items():
            if path == profile and key == "MISE_DATA_DIR":
                continue  # The rootfs mise profile supplies this value separately.
            assert values[key.encode()] == value.encode()
