"""Real operator-client workflow against a standalone Rust proxy child.

The source HTTP comparator is a separate frozen fixture. This scenario only
runs when Rust is selected; its operator listener, token and upstream are owned
by the fixture. Normal proxy/CA environment and loopback exclusions are retained.
"""

import json

import pytest

from safeyolo.api import AdminAPI, APIError
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import ALLOW, policy_proxy, replace_policy

TOKEN = "synthetic-operator-workflow-original"
NEXT_TOKEN = "synthetic-operator-workflow-replacement"
RAW_CANARY = "synthetic-raw-task-confidential-value"
SHIELD_BODY = {"error": "Forbidden", "message": "Admin API not accessible through proxy"}


def test_operator_client_registers_raw_tasks_without_activating_them(pytestconfig, tmp_path, monkeypatch):
    if "rust" not in pytestconfig.getoption("--proxy-backend"):
        pytest.skip("Rust-only operator workflow; select --proxy-backend rust")

    def no_operator_defaults():
        raise AssertionError("The fixture must supply its owned base URL and synthetic token")

    # The real client remains intact; fail if it tries to consult operator state.
    monkeypatch.setattr("safeyolo.api.get_admin_token", no_operator_defaults)
    monkeypatch.setattr("safeyolo.api.load_config", no_operator_defaults)
    token_file = tmp_path / "operator-token"
    token_file.touch(mode=0o600)
    token_file.write_text(TOKEN + "\n")
    directory = tmp_path / "rust"
    raw = {
        "metadata": {"task_id": "authored-other"},
        "unknown": {"keep": [3, 1], "synthetic_secret": RAW_CANARY},
        "permissions": [{"action": "network:request", "resource": "*", "effect": "deny"}],
    }
    replacement = {"unknown": ["replacement"], "permissions": []}

    with origin_server() as origin:
        with policy_proxy("rust", directory, ALLOW, admin_port=0, admin_api_token_file=token_file) as proxy:
            marker = json.loads(proxy.readiness_file.read_text())
            port = marker["admin_port"]
            assert 0 < port <= 65535 and marker["pid"] == proxy.process.pid
            base_url = f"http://127.0.0.1:{port}"
            client = AdminAPI(base_url=base_url, token=TOKEN, timeout=5)
            wrong = AdminAPI(base_url=base_url, token=NEXT_TOKEN, timeout=5)
            assert wrong.health() == {"status": "ok"}
            with pytest.raises(APIError) as failure:
                wrong.get_policy("task/alpha")
            assert failure.value.status_code == 401

            assert client.set_policy("task/alpha", raw) == {
                "status": "updated",
                "task_id": "alpha",
                "permission_count": 1,
                "message": "Task policy updated",
            }
            assert client.get_policy("task/alpha") == {"task_id": "alpha", "policy": raw}
            # A registered blanket deny does not become an active overlay. Both
            # trusted agents still reach the owned origin under the same policy.
            for agent in ("alice", "bob"):
                result = send_request(
                    proxy.paths[agent], f"http://127.0.0.1:{origin.server_address[1]}/registered-task"
                )
                assert result[0] == 200 and result[2] == b"hello"
            assert origin.accepts == 2 and len(origin.requests) == 2

            assert client.set_policy("task/alpha", replacement) == {
                "status": "updated",
                "task_id": "alpha",
                "permission_count": 0,
                "message": "Task policy updated",
            }
            with pytest.raises(APIError) as failure:
                client.set_policy("task/alpha", {"permissions": False})
            assert failure.value.status_code == 400
            assert client.get_policy("task/alpha") == {"task_id": "alpha", "policy": replacement}

            # Startup token ownership and the actual process-local registry both
            # survive a real binary SIGHUP reload; no facade-only call substitutes.
            token_file.write_text(NEXT_TOKEN + "\n")
            replace_policy(proxy, "rust", directory, ALLOW)
            assert json.loads(proxy.readiness_file.read_text())["admin_port"] == port
            with pytest.raises(APIError) as failure:
                wrong.get_policy("task/alpha")
            assert failure.value.status_code == 401
            assert client.get_policy("task/alpha") == {"task_id": "alpha", "policy": replacement}

            before = len(proxy.events("proxy.egress")), origin.accepts
            for agent, method, target in (
                ("alice", "GET", base_url + "/admin/policy/task/alpha"),
                ("bob", "CONNECT", f"127.0.0.1:{port}"),
            ):
                status, headers, body = send_request(
                    proxy.paths[agent], target, method=method, headers={"Authorization": f"Bearer {TOKEN}"}
                )
                assert status == 403 and json.loads(body) == SHIELD_BODY
                assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "admin-shield"
            assert (len(proxy.events("proxy.egress")), origin.accepts) == before
            assert client.health() == {"status": "ok"}

            events = proxy.events("proxy.admin_api")
            updates = [event for event in events if event["audit_intent"] == "admin.task_policy_update"]
            assert [(event["task_id"], event["permission_count"]) for event in updates] == [("alpha", 1), ("alpha", 0)]
            assert sum(event["audit_intent"] == "admin.auth_failure" for event in events) == 2
            for path in (proxy.event_log, directory / "process.log", proxy.readiness_file):
                contents = path.read_text()
                for private in (TOKEN, NEXT_TOKEN, RAW_CANARY):
                    assert private not in contents and private.encode().hex() not in contents
