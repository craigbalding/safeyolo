"""Rust gateway admission and provider stream boundary, including fail-closed routes."""

import json
import os
import stat
import sys

import pytest

from tests.proxy_migration.harness import launch_proxy, request
from tests.proxy_migration.test_gateway_redirect import AGENT_API, _origin, _wire

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


@pytest.mark.skipif(sys.platform != "linux", reason="Fake runsc provider fixture requires Linux")
def test_gateway_routes_only_authorized_calls_to_provider_stream(tmp_path, monkeypatch):
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
    printf '{"status":"running"}\\n'
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
    with _origin("127.0.0.1") as origin:
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
        ) as proxy:
            status, _, body = request(
                proxy.paths["alice"], AGENT_API + "/gateway/services",
                headers={"Authorization": "Bearer fixture-provider-agent-api-token"},
            )
            assert status == 200, body
            token = json.loads(body)["authorized"]["proofspot"]["token"]
            assert token.startswith("sgw_")
            url = "http://proofspot.safeyolo.internal:8088/api/v1/allowed"

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
            assert _header_values(wire, b"authorization") == []
            assert _header_values(wire, b"x-safeyolo-agent") == []
            assert _header_values(wire, b"x-safeyolo-agent-id") == [b"ag-trusted-alice"]
            assert _header_values(wire, b"x-safeyolo-agent-name") == [b"alice"]
            assert token.encode() not in wire
            assert wire.endswith(b"provider-request-body")
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
