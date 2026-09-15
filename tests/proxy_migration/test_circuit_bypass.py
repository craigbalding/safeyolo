"""Circuit policy bypass affects request checks, not completed response recording.

Canonical domain/client/required forms come from the policy enablement oracle.
Every case uses the actual source or native HTTP path, an owned origin, and
authenticated live state reads. Global circuit disable has separate controls.
"""

import json

import pytest

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.test_circuit_completion import wait_failure_count
from tests.proxy_migration.test_circuit_reload import assert_stopped, observe, reload_origin
from tests.proxy_migration.test_native_network_policy import policy_proxy
from tests.proxy_migration.test_operator_circuits import HOST, CircuitOriginHandler, hit


def circuit_policy(**scopes):
    return json.dumps(
        {
            "permissions": [{"action": "network:request", "resource": "*", "effect": "allow"}],
            "addons": {
                "circuit_breaker": {
                    "failure_threshold": 2,
                    "timeout_seconds": 120,
                    "use_exponential_backoff": False,
                    "jitter_factor": 0,
                }
            },
            **scopes,
        }
    )


def check_state(proxy, stage, *, checks, failures):
    observe(
        proxy,
        stage,
        checks=checks,
        opens=int(failures >= 2),
        half_opens=0,
        recoveries=0,
        threshold=2,
        timeout=120,
        failures=failures,
        state="open" if failures >= 2 else "closed",
    )


@pytest.mark.parametrize("scope", ["domain-bypass", "client-disable"])
def test_policy_bypass_skips_request_checks_but_records_completed_failure(proxy_backend, tmp_path, scope):
    scopes = (
        {"domains": {HOST: {"bypass": ["circuit_breaker"]}}}
        if scope == "domain-bypass"
        else {"clients": {"alice": {"addons": {"circuit_breaker": {"enabled": False}}}}}
    )
    directory = tmp_path / proxy_backend
    with reload_origin() as origin:
        with policy_proxy(
            proxy_backend,
            directory,
            circuit_policy(**scopes),
            policy_format="json",
            agent_api=True,
            circuit_breaker_enabled=True,
        ) as proxy:
            for failures in (1, 2):
                hit(proxy, origin, "alice", "/failure", 500)
                wait_failure_count(proxy, failures)
                check_state(proxy, f"bypassed-request-failure-{failures}", checks=0, failures=failures)
            # The open circuit still does not stop the policy-bypassed request.
            bypassed_agent = "bob" if scope == "domain-bypass" else "alice"
            hit(proxy, origin, bypassed_agent, "/failure", 500)
            wait_failure_count(proxy, 3)
            check_state(proxy, "bypassed-open-circuit-still-records-response", checks=0, failures=3)
            if scope == "client-disable":
                _, headers, _ = hit(proxy, origin, "bob", "/retry", 503)
                assert {key.lower(): value for key, value in headers.items()}["x-circuit-state"] == "open"
                check_state(proxy, "other-trusted-agent-still-enforced", checks=1, failures=3)
        assert_stopped(proxy, origin.server_address, 3)
        assert origin.accepts == len(origin.requests) == 3


def test_required_circuit_overrides_domain_and_client_bypass(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    source = circuit_policy(
        required=["circuit_breaker"],
        domains={HOST: {"bypass": ["circuit_breaker"]}},
        clients={"alice": {"addons": {"circuit_breaker": {"enabled": False}}}},
    )
    with reload_origin() as origin:
        with policy_proxy(
            proxy_backend, directory, source, policy_format="json", agent_api=True, circuit_breaker_enabled=True
        ) as proxy:
            for failures in (1, 2):
                hit(proxy, origin, "alice", "/failure", 500)
                wait_failure_count(proxy, failures)
                check_state(proxy, f"required-failure-{failures}", checks=failures, failures=failures)
            _, headers, _ = hit(proxy, origin, "alice", "/retry", 503)
            assert {key.lower(): value for key, value in headers.items()}["x-circuit-state"] == "open"
            check_state(proxy, "required-overrides-both-bypasses", checks=3, failures=2)
        assert_stopped(proxy, origin.server_address, 2)
        assert origin.accepts == len(origin.requests) == 2


class ClassificationHandler(CircuitOriginHandler):
    """Only the existing owned HTTP origin's response status differs."""

    def do_GET(self):
        self.server.requests.append({"method": self.command, "target": self.path})
        self.send_response({"/500": 500, "/404": 404, "/429": 429}[self.path])
        self.send_header("Content-Length", "5")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"hello")


def test_complete_429_counts_but_ordinary_4xx_does_not(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with reload_origin() as origin:
        # This instance has no requests until after the proxy becomes ready.
        origin.RequestHandlerClass = ClassificationHandler
        with policy_proxy(
            proxy_backend,
            directory,
            circuit_policy(),
            policy_format="json",
            agent_api=True,
            circuit_breaker_enabled=True,
        ) as proxy:
            for checks, (expected, failures, agent) in enumerate(
                [(500, 1, "alice"), (404, 1, "bob"), (429, 2, "alice")], start=1
            ):
                before = origin.accepts, len(proxy.events("proxy.egress"))
                status, headers, body = send_request(
                    proxy.paths[agent], f"http://{HOST}:{origin.server_address[1]}/{expected}"
                )
                assert status == expected and body == b"hello"
                assert "x-blocked-by" not in {key.lower() for key in headers}
                assert (origin.accepts, len(proxy.events("proxy.egress"))) == (before[0] + 1, before[1] + 1)
                wait_failure_count(proxy, failures)
                check_state(proxy, f"completed-upstream-{expected}", checks=checks, failures=failures)
            _, headers, _ = hit(proxy, origin, "bob", "/blocked", 503)
            assert {key.lower(): value for key, value in headers.items()}["x-circuit-state"] == "open"
            check_state(proxy, "local-block-does-not-count-as-upstream-failure", checks=4, failures=2)
        assert_stopped(proxy, origin.server_address, 3)
        assert origin.accepts == len(origin.requests) == 3
