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
from tests.proxy_migration.test_agent_api_contract import api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import ALLOW, policy_proxy, replace_policy

TOKEN = "synthetic-operator-workflow-original"
NEXT_TOKEN = "synthetic-operator-workflow-replacement"
RAW_CANARY = "synthetic-raw-task-confidential-value"
SHIELD_BODY = {"error": "Forbidden", "message": "Admin API not accessible through proxy"}


def test_operator_client_registers_activates_and_clears_task_policy(pytestconfig, tmp_path, monkeypatch):
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
        with policy_proxy(
            "rust", directory, ALLOW, admin_port=0, admin_api_token_file=token_file, agent_api=True
        ) as proxy:
            marker = json.loads(proxy.readiness_file.read_text())
            port = marker["admin_port"]
            assert 0 < port <= 65535 and marker["pid"] == proxy.process.pid
            base_url = f"http://127.0.0.1:{port}"
            client = AdminAPI(base_url=base_url, token=TOKEN, timeout=5)
            wrong = AdminAPI(base_url=base_url, token=NEXT_TOKEN, timeout=5)
            initial = assert_api_response(api_request(proxy, "/status"), 200)

            def check_task_state(count, evaluations, policy_hash, task_permissions):
                report = assert_api_response(api_request(proxy, "/status", agent="bob"), 200)
                assert report["task_policies"] == count
                assert report["policy_hash"] == policy_hash
                assert report["engine_stats"]["task_permissions"] == task_permissions
                assert report["engine_stats"]["task_policy_path"] is None
                assert report["engine_stats"]["evaluations"] == evaluations

            initial_config = assert_api_response(api_request(proxy, "/config"), 200)
            assert initial_config["policy_hash"] == initial["policy_hash"]
            check_task_state(0, 0, initial["policy_hash"], 0)
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
            check_task_state(1, 0, initial["policy_hash"], 0)
            # A registered blanket deny does not become an active overlay. Both
            # trusted agents still reach the owned origin under the same policy.
            for agent in ("alice", "bob"):
                result = send_request(
                    proxy.paths[agent], f"http://127.0.0.1:{origin.server_address[1]}/registered-task"
                )
                assert result[0] == 200 and result[2] == b"hello"
            assert origin.accepts == 2 and len(origin.requests) == 2

            assert client.activate_task_policy("alpha") == {
                "status": "activated",
                "task_id": "alpha",
                "permission_count": 1,
                "message": "Task policy activated",
            }
            activated_config = assert_api_response(api_request(proxy, "/config"), 200)
            activated_hash = activated_config["policy_hash"]
            assert activated_hash != initial["policy_hash"]
            check_task_state(1, 2, activated_hash, 1)
            status, headers, body = send_request(
                proxy.paths["alice"], f"http://127.0.0.1:{origin.server_address[1]}/activated-task"
            )
            assert status == 403 and json.loads(body)["domain"] == "127.0.0.1"
            assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
            assert origin.accepts == 2 and len(origin.requests) == 2
            check_task_state(1, 3, activated_hash, 1)

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
            check_task_state(1, 3, activated_hash, 1)

            assert client.clear_task_policy("alpha") == {
                "status": "cleared",
                "task_id": "alpha",
                "message": "Task policy cleared",
            }
            cleared_config = assert_api_response(api_request(proxy, "/config"), 200)
            assert cleared_config["policy_hash"] == initial["policy_hash"]
            check_task_state(0, 3, initial["policy_hash"], 0)
            with pytest.raises(APIError) as failure:
                client.get_policy("task/alpha")
            assert failure.value.status_code == 404
            status, _, body = send_request(
                proxy.paths["alice"], f"http://127.0.0.1:{origin.server_address[1]}/cleared-task"
            )
            assert status == 200 and body == b"hello"
            assert origin.accepts == 3 and len(origin.requests) == 3
            check_task_state(0, 4, initial["policy_hash"], 0)

            assert client.set_policy("task/beta", {})["permission_count"] == 0
            check_task_state(1, 4, initial["policy_hash"], 0)

            # Startup token ownership and the actual process-local registry both
            # survive a real binary SIGHUP reload; no facade-only call substitutes.
            token_file.write_text(NEXT_TOKEN + "\n")
            replace_policy(proxy, "rust", directory, ALLOW)
            assert json.loads(proxy.readiness_file.read_text())["admin_port"] == port
            with pytest.raises(APIError) as failure:
                wrong.get_policy("task/alpha")
            assert failure.value.status_code == 401
            with pytest.raises(APIError) as failure:
                client.get_policy("task/alpha")
            assert failure.value.status_code == 404
            assert client.get_policy("task/beta") == {"task_id": "beta", "policy": {}}
            check_task_state(1, 4, initial["policy_hash"], 0)

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
            assert [(event["task_id"], event["permission_count"]) for event in updates] == [
                ("alpha", 1),
                ("alpha", 1),
                ("alpha", 0),
                ("beta", 0),
            ]
            clears = [event for event in events if event["audit_intent"] == "admin.task_policy_clear"]
            assert [event["task_id"] for event in clears] == ["alpha"]
            assert sum(event["audit_intent"] == "admin.auth_failure" for event in events) == 2
            for path in (proxy.event_log, directory / "process.log", proxy.readiness_file):
                contents = path.read_text()
                for private in (TOKEN, NEXT_TOKEN, RAW_CANARY):
                    assert private not in contents and private.encode().hex() not in contents
