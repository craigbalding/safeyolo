"""Rust gateway admission and provider stream boundary, including fail-closed routes."""

import json
import os
import socket
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.proxy_contracts.harness import launch_proxy, request
from tests.proxy_contracts.test_gateway_redirect import AGENT_API, _origin, _wire

SERVICE = """\
schema_version: 1
name: proofspot
default_host: proofspot.safeyolo.internal
capabilities:
  assessment:
    routes:
      - methods: [GET, POST]
        path: /api/v1/**
"""


def _policy() -> str:
    return '''[hosts."proofspot.safeyolo.internal"]
service = "proofspot"
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.alice]
agent_id = "ag-trusted-alice"
[agents.alice.services.proofspot]
capability = "assessment"
[agents.bob]
agent_id = "ag-trusted-bob"
[agents.proofspot]
agent_id = "ag-provider"
'''


def _header_values(wire: bytes, name: bytes) -> list[bytes]:
    return [line.split(b":", 1)[1].strip() for line in wire.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
            if line.split(b":", 1)[0].lower() == name.lower()]


@contextmanager
def _provider_run(directory, monkeypatch):
    # Match the owned namespace/process fixture in proxy/tests/support/owned_run.rs.
    # The fake runsc still connects to the existing host-side provider observer.
    agent = directory / "agents/proofspot"
    (agent / "config-share").mkdir(parents=True)
    generation = "0123456789abcdef0123456789abcdef"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(directory))
    monkeypatch.setenv("SAFEYOLO_RUNSC_ROOT", str(directory / "run"))
    monkeypatch.setenv("FAKE_RUN_ID", f"safeyolo-{generation}")
    # Production validates the owned namespaces before invoking nsenter. Keep
    # only the controlled runsc command in the host observer's network here.
    entry = directory / "bin/nsenter"
    entry.write_text('#!/bin/sh\nshift 5\nexec "$@"\n')
    entry.chmod(0o755)
    backend = subprocess.Popen(
        ["/usr/bin/unshare", "--user", "--net", "/bin/bash", "-c",
         'exec -a runsc-sandbox /bin/sh -c \'read -r finish\' "$@"', "fixture",
         f"--root={directory / 'run'}", "boot", f"safeyolo-{generation}"],
        stdin=subprocess.PIPE,
    )
    try:
        proc = Path(f"/proc/{backend.pid}")
        deadline = time.monotonic() + 3
        while any((proc / f"ns/{kind}").stat().st_ino == Path(f"/proc/self/ns/{kind}").stat().st_ino
                  for kind in ("user", "net")):
            assert backend.poll() is None, "owned provider namespace exited"
            assert time.monotonic() < deadline, "owned provider namespace did not start"
            time.sleep(0.01)
        for kind, identity in (("uid", os.getuid()), ("gid", os.getgid())):
            if kind == "gid":
                (proc / "setgroups").write_text("deny")
            try:
                (proc / f"{kind}_map").write_text(f"0 100000 1000\n1000 {identity} 1\n1001 101001 64534\n")
            except PermissionError:
                # Rootless hosts use the same subordinate-ID helpers as the
                # maintained native fixture and production sandbox startup.
                subprocess.run(
                    [f"/usr/bin/new{kind}map", str(backend.pid),
                     "0", "100000", "1000", "1000", str(identity), "1", "1001", "101001", "64534"],
                    check=True, timeout=5,
                )
        ticks = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        token = f"linux:{boot}:{backend.pid}:{ticks}"
        (agent / "config-share/host-launch-context.json").write_text(json.dumps({"generation": generation}))
        (agent / "runtime.json").write_text(json.dumps({
            "run_id": generation, "holder_pid": backend.pid, "holder_token": token,
            "backend_pid": backend.pid, "backend_token": token,
        }))
        (agent / "userns.pid").write_text(str(backend.pid))
        yield
    finally:
        if backend.poll() is None:
            backend.terminate()
        backend.communicate(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="Fake runsc provider fixture requires Linux")
@pytest.mark.parametrize("parent_enabled", [False, True], ids=["direct", "parent"])
def test_gateway_routes_only_authorized_calls_to_provider_stream(tmp_path, monkeypatch, parent_enabled):
    directory = tmp_path / "provider"
    directory.mkdir()
    (directory / "builtin").mkdir()
    (directory / "services").mkdir()
    (directory / "services/proofspot.yaml").write_text(SERVICE)
    api_data = directory / "api-data"
    api_data.mkdir()
    (api_data / "agent_token").write_text("fixture-provider-agent-api-token")

    runsc_dir = directory / "bin"
    runsc_dir.mkdir()
    runsc = runsc_dir / "runsc"
    runsc.write_text('''#!/bin/sh
case "$3" in
  state)
    [ ! -e "$PROVIDER_STOP_MARKER" ] || exit 1
    [ "$4" = "$FAKE_RUN_ID" ] || exit 2
    printf '{"id":"%s","status":"running"}\\n' "$FAKE_RUN_ID"
    ;;
  port-forward)
    [ ! -e "$PROVIDER_STOP_MARKER" ] || exit 1
    if [ -e "$PROVIDER_CLOSE_MARKER" ]; then
        echo 'connection was refused' >&2
        exit 1
    fi
    /usr/bin/socat "UNIX-CONNECT:$5" "TCP:127.0.0.1:$PROVIDER_FIXTURE_PORT" </dev/null >/dev/null 2>/dev/null &
    ;;
  *) exit 2 ;;
esac
''')
    runsc.chmod(runsc.stat().st_mode | stat.S_IXUSR)
    stopped = directory / "provider-stopped"
    closed = directory / "provider-port-closed"
    with _origin("127.0.0.1") as origin, _origin("127.0.0.1") as parent, _provider_run(directory, monkeypatch):
        monkeypatch.setenv("PATH", f"{runsc_dir}:{os.environ['PATH']}")
        monkeypatch.setenv("PROVIDER_FIXTURE_PORT", str(origin.server_address[1]))
        monkeypatch.setenv("PROVIDER_STOP_MARKER", str(stopped))
        monkeypatch.setenv("PROVIDER_CLOSE_MARKER", str(closed))
        with launch_proxy(
            "rust", directory, _policy(), native_policy=True, agent_api=True,
            agent_api_token=b"fixture-provider-agent-api-token",
            gateway_services_dir=directory / "services",
            gateway_builtin_services_dir=directory / "builtin",
            agents=("alice", "bob"), network_guard_enabled=True,
            network_guard_block=True,
            parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}" if parent_enabled else None,
        ) as proxy:
            status, _, body = request(
                proxy.paths["alice"], AGENT_API + "/gateway/services",
                headers={"Authorization": "Bearer fixture-provider-agent-api-token"},
            )
            assert status == 200, body
            token = json.loads(body)["authorized"]["proofspot"]["token"]
            assert token.startswith("sgw_")
            url = "http://proofspot.safeyolo.internal:8088/api/v1/allowed?sig=%252F&tag=a&tag=b"

            for agent, headers, target in [
                ("alice", {}, url),
                ("alice", {"Authorization": "Bearer sgw_invalid"}, url),
                ("bob", {"Authorization": f"Bearer {token}"}, url),
                ("alice", {"Authorization": f"Bearer {token}"},
                 "http://proofspot.safeyolo.internal:8088/outside"),
            ]:
                status, _, _ = request(proxy.paths[agent], target, headers=headers)
                assert status == 403
                assert origin.accepts == 0
            assert not proxy.events("proxy.egress")

            status, _, _ = request(
                proxy.paths["alice"], "proofspot.safeyolo.internal:8088",
                method="CONNECT",
            )
            assert status == 403
            assert origin.accepts == 0
            assert not proxy.events("proxy.egress")

            status, _, body = request(
                proxy.paths["alice"], url,
                headers={"Authorization": f"Bearer {token}",
                         "X-SafeYolo-Agent": "forged-legacy",
                         "X-SafeYolo-Agent-ID": "forged-id",
                         "X-SafeYolo-Agent-Name": "forged-name"},
                method="POST", body=b"provider-request-body",
            )
            assert status == 200, body
            assert origin.accepts == 1
            wire = _wire(origin.requests[0])
            assert wire.split(b"\r\n", 1)[0] == (
                b"POST /api/v1/allowed?sig=%252F&tag=a&tag=b HTTP/1.1"
            )
            assert _header_values(wire, b"host") == [b"proofspot.safeyolo.internal:8088"]
            assert _header_values(wire, b"authorization") == []
            assert _header_values(wire, b"x-safeyolo-agent") == []
            assert _header_values(wire, b"x-safeyolo-agent-id") == [b"ag-trusted-alice"]
            assert _header_values(wire, b"x-safeyolo-agent-name") == [b"alice"]
            assert token.encode() not in wire
            assert wire.split(b"\r\n\r\n", 1)[1] == b"provider-request-body"
            assert not proxy.events("proxy.egress")

            closed.touch()
            status, _, _ = request(
                proxy.paths["alice"], url,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert status in {502, 503}
            assert origin.accepts == 1
            assert not proxy.events("proxy.egress")

            closed.unlink()

            stopped.touch()
            status, _, _ = request(
                proxy.paths["alice"], url,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert status in {502, 503}
            assert origin.accepts == 1
            assert not proxy.events("proxy.egress")

        assert parent.accepts == 0
        assert parent.requests == []
        # The live observer counts TCP accepts even before HTTP parsing. Check
        # its response as a positive control after the zero-contact assertions.
        with socket.create_connection(parent.server_address, timeout=5) as control:
            control.sendall(
                b"GET /parent-observer-control HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"
            )
            assert control.recv(4096).startswith(b"HTTP/1.1 200 OK\r\n")
        assert parent.accepts == 1
        assert len(parent.requests) == 1
