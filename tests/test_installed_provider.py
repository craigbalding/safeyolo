"""Controls for the native-provider recipe's shell workload and observations."""

import hashlib
import http.client
import os
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import tomlkit

from tests.blackbox.installed_provider import (
    ParentObserver,
    capture_guest_command,
    client_observation,
    origin_observation,
    prepare,
)
from tests.blackbox.native_credentials import native_cli

SCRIPTS = Path(__file__).parent / "blackbox/isolation"


@pytest.mark.parametrize("exit_code", [0, 7])
def test_guest_output_uses_pipes_and_keeps_private_log_ownership(tmp_path, exit_code):
    program = '''
import os, stat, sys
assert stat.S_ISFIFO(os.fstat(1).st_mode)
assert stat.S_ISFIFO(os.fstat(2).st_mode)
sys.stdout.buffer.write(b'o' * 131072)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(b'e' * 131072)
sys.stderr.buffer.flush()
sys.exit(int(sys.argv[1]))
'''
    log = tmp_path / "guest.log"
    failures = []
    child, reader, finished = capture_guest_command(
        [sys.executable, "-c", program, str(exit_code)], os.environ, log, failures)
    try:
        # Waiting before capture finishes exercises output beyond pipe capacity.
        assert child.wait(timeout=10) == exit_code
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        finished.set()
        reader.join(timeout=5)
    assert not reader.is_alive() and failures == []
    assert child.returncode == exit_code
    assert log.read_bytes() == b'o' * 131072 + b'e' * 131072
    assert log.stat().st_uid == os.getuid() and log.stat().st_gid == os.getgid()
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_producer_records_accept_before_parsing_and_never_records_authorization(tmp_path):
    result = subprocess.run(["bash", str(SCRIPTS / "provider-origin.sh"), str(tmp_path)],
        input="GET /api/v1/value HTTP/1.1\r\nHost: proofspot.safeyolo.internal:8088\r\n"
              "Authorization: Bearer fixture-secret\r\nX-SafeYolo-Agent: forged\r\n"
              "X-SafeYolo-Agent-ID: ag-caller\r\nX-SafeYolo-Agent-ID: forged-id\r\n"
              "X-SafeYolo-Agent-Name: caller\r\n\r\n", capture_output=True, text=True, check=True)
    assert result.stdout.endswith("native-http-service\n")
    assert origin_observation(tmp_path) == {"accepts": 1, "requests": [[
        "GET /api/v1/value HTTP/1.1", "forged-id", "caller", "proofspot.safeyolo.internal:8088",
        "1", "1", "2", "1"]]}
    assert "fixture-secret" not in (tmp_path / "requests.tsv").read_text()
    incomplete = subprocess.run(["bash", str(SCRIPTS / "provider-origin.sh"), str(tmp_path)],
                                input="", capture_output=True, text=True)
    assert incomplete.returncode != 0
    assert origin_observation(tmp_path)["accepts"] == 2
    assert len(origin_observation(tmp_path)["requests"]) == 1


def test_caller_runs_all_phases_with_token_only_on_stdin(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    cat = tools / "cat"
    cat.write_text("#!/bin/bash\n[[ $1 == /app/agent_token ]] || exit 2\nprintf 'fixture-agent-token'\n")
    cat.chmod(0o755)
    curl = tools / "curl"
    curl.write_text(f"#!{sys.executable}\n" + r'''
import pathlib, sys
args = sys.argv[1:]
header = sys.stdin.read()
if args[-1].endswith('/gateway/services'):
    assert header == 'Authorization: Bearer fixture-agent-token\n'
    print('{"authorized":{"proofspot":{"token":"sgw_fixture-proof"}}}')
else:
    assert header == 'Authorization: Bearer sgw_fixture-proof\n'
    counter = pathlib.Path('counter')
    index = int(counter.read_text()) if counter.exists() else 0
    statuses = [403, 403, 403, 403, 200, 403, 200, 503, 503]
    expected = [('DELETE', '/api/v1/value'), ('GET', '/outside'), ('GET', '/api/v1/value'),
                ('GET', '/api/v1/value'),
                ('GET', '/api/v1/value'), ('GET', '/api/v1/value'), ('GET', '/api/v1/value'),
                ('GET', '/api/v1/value'), ('GET', '/api/v1/value')]
    assert args[args.index('--request') + 1] == expected[index][0]
    assert args[-1].endswith(expected[index][1])
    if index == 2:
        assert 'unrelated.safeyolo.internal' in args[-1]
    if index == 3:
        assert ':8089/' in args[-1]
    counter.write_text(str(index + 1))
    status = statuses[index]
    pathlib.Path(args[args.index('--output') + 1]).write_bytes(
        b'native-http-service\n' if status == 200 else b'refused')
    pathlib.Path(args[args.index('--dump-header') + 1]).write_text('HTTP/1.1\n')
    print(status, end='')
''')
    curl.chmod(0o755)
    for phase in ("allowed", "revoked", "recovered", "closed", "stopped"):
        (tmp_path / f"{phase}.go").touch()
    result = subprocess.run(["bash", str(SCRIPTS / "provider-caller.sh"), str(tmp_path)],
        env=os.environ | {"PATH": str(tools) + os.pathsep + os.environ["PATH"]},
        capture_output=True, text=True, timeout=15, check=True)
    observations = client_observation(tmp_path)
    assert {label: row["status"] for label, row in observations.items()} == {
        "method": 403, "path": 403, "destination": 403, "port": 403, "allowed": 200,
        "revoked": 403, "recovered": 200, "closed": 503, "stopped": 503}
    assert observations["allowed"]["body_sha256"] == hashlib.sha256(b"native-http-service\n").hexdigest()
    assert "sgw_" not in result.stdout + result.stderr + (tmp_path / "results.tsv").read_text()
    assert not (tmp_path / "response").exists() and not (tmp_path / "headers").exists()


def test_parent_observer_counts_connections_before_http(tmp_path):
    with ParentObserver() as parent:
        thread = threading.Thread(target=parent.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", parent.server_port, timeout=3)
            try:
                connection.request("GET", "/control")
                response = connection.getresponse()
                assert response.status == 200 and response.read() == b"fallback"
            finally:
                connection.close()
            assert parent.accepts == 1
        finally:
            parent.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


@pytest.mark.skipif(sys.platform != "linux" or not os.environ.get("SAFEYOLO_NATIVE_CLI"),
                    reason="Requires the selected native Linux CLI")
def test_prepared_configuration_is_readable_by_native_cli(tmp_path):
    """Use the real config reader without starting a proxy, broker or sandbox."""
    cli = native_cli()
    base, root = tmp_path / "base", tmp_path / "instance"
    subprocess.run([str(cli), "--root", str(base), "init"], check=True, capture_output=True)
    (base / "bin").mkdir()
    (base / "bin/safeyolo").symlink_to(cli)
    (base / "data/coord/nats/bin").mkdir(parents=True)
    config = tomlkit.parse((base / "config.toml").read_text())
    config["linux"] = {"host_uid": os.getuid(), "host_gid": os.getgid(), "uid_base": 100000,
                       "gid_base": 100000, "runsc": shutil.which("true"), "runsc_origin": "system"}
    (base / "config.toml").write_text(tomlkit.dumps(config))
    prepare(base, root, 19437, 19438)
    subprocess.run([str(cli), "--root", str(root), "status"], check=True, capture_output=True)
