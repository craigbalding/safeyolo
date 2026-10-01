"""Cumulative status through actual policy traffic and accepted reloads.

The expected initial report comes from the authenticated source-handler golden.
Only its owned file path varies. Real proxy requests supply subsequent counter
and budget transitions; status reads must remain local and leave them unchanged.
"""

import copy
import json
import time
from pathlib import Path

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_agent_api_budgets import assert_no_refill
from tests.proxy_migration.test_agent_api_contract import AUTH_REQUIRED, api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import assert_rejection, policy_proxy, replace_policy

SOURCE = json.loads((Path(__file__).resolve().parents[2] / "proxy/tests/agent_status_source.json").read_text())
INITIAL = json.loads(bytes.fromhex(SOURCE["rows"][0]["response"]["body_hex"]))


def read_status(proxy, parent, expected):
    """Both identities see the same ordered report, without any upstream work."""
    before = parent.accepts, len(proxy.events("proxy.egress"))
    for agent, path in (("alice", "/status"), ("bob", "/status///?agent=alice&task_id=forged&ignored=%ff")):
        result = api_request(proxy, path, agent=agent, headers={"X-SafeYolo-Agent": "forged"})
        assert_api_response(result, 200, expected)
        assert result[2] == json.dumps(expected).encode()
    assert (parent.accepts, len(proxy.events("proxy.egress"))) == before


def test_agent_api_status_counts_real_requests_and_preserves_state_on_reload(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    expected = copy.deepcopy(INITIAL)
    expected["engine_stats"]["baseline_path"] = str(directory / "policy.json")
    with origin_server() as parent:
        options = {
            "policy_format": "json",
            "agent_api": True,
            "parent_proxy": f"http://127.0.0.1:{parent.server_address[1]}",
        }
        with policy_proxy(proxy_backend, directory, json.dumps(SOURCE["baseline"]), **options) as proxy:
            read_status(proxy, parent, expected)
            assert_api_response(api_request(proxy, "/status", auth=None), 401, AUTH_REQUIRED)
            assert_api_response(
                api_request(proxy, "/status", method="POST", auth=None),
                405,
                {"error": "Method Not Allowed", "allowed": ["GET"]},
            )
            read_status(proxy, parent, expected)
            for agent in ("alice", "bob"):
                lookup = assert_api_response(api_request(proxy, "/lookup?host=allowed.invalid", agent=agent), 200)
                assert lookup["effect"] == "allow"
                expected["engine_stats"]["evaluations"] += 1
                read_status(proxy, parent, expected)
            for path in ("/config", "/policy", "/budgets", "/health"):
                assert_api_response(api_request(proxy, path), 200)
            read_status(proxy, parent, expected)
            assert parent.accepts == 0 and proxy.events("proxy.egress") == []

            started = time.monotonic()
            for agent, status in (("alice", 200), ("bob", 200), ("alice", 429)):
                result = send_request(proxy.paths[agent], "http://allowed.invalid/status-counter")
                if status == 200:
                    assert result[0] == 200 and result[2] == b"hello"
                else:
                    assert_rejection(*result, status, "allowed.invalid")
                expected["engine_stats"]["evaluations"] += 1
                expected["engine_stats"]["budget_stats"] = {
                    "tracked_keys": 1,
                    "keys": ["network:request:allowed.invalid"],
                }
                read_status(proxy, parent, expected)
            assert_no_refill(started)
            assert parent.accepts == 2 and len(proxy.events("proxy.egress")) == 2

            replace_policy(proxy, proxy_backend, directory, "{}")
            expected["policy_hash"] = "sha256:917ea0d8c9828d33"
            expected["engine_stats"]["baseline_permissions"] = 0
            read_status(proxy, parent, expected)
            assert_rejection(
                *send_request(proxy.paths["alice"], "http://allowed.invalid/after-reload"), 403, "allowed.invalid"
            )
            expected["engine_stats"]["evaluations"] += 1
            replace_policy(proxy, proxy_backend, directory, '{"permissions":false}', valid=False)
            read_status(proxy, parent, expected)
            assert parent.accepts == 2 and len(parent.requests) == 2

        # A fresh process has no cumulative evaluations or retained budget keys.
        expected["engine_stats"]["evaluations"] = 0
        expected["engine_stats"]["budget_stats"] = {"tracked_keys": 0, "keys": []}
        restarted = tmp_path / f"{proxy_backend}-restarted"
        expected["engine_stats"]["baseline_path"] = str(restarted / "policy.json")
        with policy_proxy(proxy_backend, restarted, "{}", **options) as proxy:
            read_status(proxy, parent, expected)
            assert parent.accepts == 2 and len(parent.requests) == 2
