"""Installed event consumers use real native approvals and authenticated APIs.

Controlled backend records bind the native current-run ingress. No guest or
model is booted by this focused host test.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect

from tests.blackbox import installed_access as access
from tests.blackbox.installed_host_smoke import _process_start_token
from tests.proxy_contracts.harness import request
from tests.proxy_contracts.test_native_coord_operator import instance  # noqa: F401
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN


def test_approval_event_allows_intervening_frames_and_still_matches_key():
    class Stream:
        def __init__(self):
            self.frames = iter([
                *[{"type": "operator_state", "revision": revision} for revision in range(6)],
                {"approval": {"key": "other", "approval_type": "coord_room"}},
                {"event": "coord.access_requested", "approval": {"key": "wanted", "approval_type": "coord_room"}},
            ])

        def recv(self, timeout):
            assert 0 < timeout <= 1
            return json.dumps(next(self.frames))

    assert access.wait_for_approval_event(Stream(), "wanted", timeout=1)["approval"]["key"] == "wanted"


def test_unrelated_event_traffic_cannot_extend_approval_deadline(monkeypatch):
    clock = iter([0, 0.1, 0.2, 0.3])
    monkeypatch.setattr(access.time, "monotonic", lambda: next(clock))

    class Stream:
        def recv(self, timeout):
            return json.dumps({"type": "operator_state", "revision": 3})

    with pytest.raises(AssertionError, match="missed collaboration approval wanted.*revision.*3"):
        access.wait_for_approval_event(Stream(), "wanted", timeout=0.25)


def test_installed_collaboration_matches_event_resolves_and_revokes(instance, monkeypatch):  # noqa: F811
    for token in (None, "synthetic-wrong-token"):
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidStatus) as failure:
            connect(f"ws://127.0.0.1:{instance.port}/admin/events", additional_headers=headers, proxy=None)
        assert failure.value.response.status_code == 401

    generation = "0123456789abcdef0123456789abcdef"
    backend = subprocess.Popen([
        "runsc-sandbox", "-c", "import time; time.sleep(300)", "boot", "safeyolo-" + generation,
        "--root", str(instance.root / "run"),
    ], executable=sys.executable)
    try:
        for name, identity in (("alice", "ag-" + "a" * 32), ("bob", "ag-" + "b" * 32)):
            directory = instance.root / "agents" / name
            (directory / "config-share").mkdir(parents=True)
            (directory / "runtime.json").write_text(json.dumps({
                "name": name, "agent_id": identity, "run_id": generation, "state": "running",
                "backend_pid": backend.pid, "backend_token": _process_start_token(backend.pid),
            }))
            (directory / "config-share/host-launch-context.json").write_text(json.dumps({
                "agent_id": identity, "generation": generation,
            }))

        def native_guest(cli, agent, platform, marker, phase, **options):
            # Substitute only guest exec. Each collaboration action reaches the
            # installed product's real authenticated per-agent UDS boundary.
            if phase == "collaboration-request":
                return instance.agent_api(agent, "/api/coord/request-collaboration", method="POST", body={
                    "participants": [options["peer"]], "topic": "installed access", "ttl_seconds": 120,
                    "operation_id": marker,
                })
            room = options["room"]
            path = f"/api/coord/rooms/{room}"
            if phase == "collaboration-send":
                sent = instance.agent_api(agent, path + "/send", method="POST", body={
                    "body": "p3-message:" + marker, "notify": "room", "declared_content_type": "text/plain",
                })
                return {"message_id": sent["envelope"]["msg_id"]}
            if phase == "collaboration-read":
                page = instance.agent_api(agent, path + "/messages")
                assert [row["body"] for row in page["messages"]] == ["p3-message:" + marker]
                return {"message_count": len(page["messages"])}
            assert phase == "collaboration-revoked"
            status, _, _ = request(instance.paths[agent], "http://_safeyolo.proxy.internal" + path + "/messages",
                                   headers={"Authorization": f"Bearer {AGENT_TOKEN}"})
            assert status in (403, 404)
            return {"revoked_read_status": status}

        monkeypatch.setattr(access, "guest", native_guest)
        monkeypatch.setattr(access, "PEER", "bob")
        result = access.run_collaboration_and_event(
            access.AdminAPI(f"http://127.0.0.1:{instance.port}", token=instance.token),
            str(instance.root / "bin/safeyolo"), instance.root, "alice", "systrap", "installed-event", instance.token,
        )
        assert result["operator_event"] == "coord.access_requested"
        assert result["revoked_read_status"] in (403, 404)
        assert result["peer_message_id"]
    finally:
        backend.terminate()
        backend.wait(timeout=5)
        (instance.root / "agents").rename(instance.root / "controlled-runs")
