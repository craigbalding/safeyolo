"""Current native missing-route challenge, operator decision and explicit retry.

Only the local fixture is mutated. Its example execution/delete paths are not
verified Rundeck endpoints. Backend process observations supply real run identity;
no model claim grants authority.
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.blackbox.installed_host_smoke import _process_start_token
from tests.blackbox.native_credentials import store_credential
from tests.proxy_contracts.harness import REPO, child_process, launch_proxy, read_events, request, wait_ready
from tests.proxy_contracts.test_gateway_risk_approval import (
    AGENT_TOKEN,
    VAULT_NAME,
    VAULT_VALUE,
    _origin,
)
from tests.proxy_contracts.test_native_network_policy import replace_policy

SERVICE = "route-challenge-fixture"
EXECUTE = "/api/59/executions/"
DELETE = "/api/delete"
RUN = "0123456789abcdef0123456789abcdef"
IDS = {"alice": "ag-" + "a" * 32, "bob": "ag-" + "b" * 32}
FIXTURE = REPO / "tests/blackbox/fixtures/service-route-challenge.yaml"


def _policy(port, ttl=30, extra=""):
    return f'''budget = 12000
[hosts."127.0.0.1"]
service = "{SERVICE}"
[hosts."127.0.0.1:{port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[gateway]
grant_ttl_seconds = {ttl}
[controls.credentials]
standard_auth_headers = []
[agents.alice]
agent_id = "{IDS['alice']}"
[agents.alice.services."{SERVICE}"]
capability = "operator"
token = "{VAULT_NAME}"
account = "agent"
[agents.bob]
agent_id = "{IDS['bob']}"
[agents.bob.services."{SERVICE}"]
capability = "operator"
token = "{VAULT_NAME}"
account = "agent"
[[risk]]
account = "agent"
tactics = ["impact"]
decision = "require_approval"
{extra}
'''


def _admin(fixture, method, path, body=None, status=200):
    port = json.loads(fixture.proxy.readiness_file.read_text())["admin_port"]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=json.dumps(body) if body is not None else None,
                           headers={"Authorization": "Bearer fixture-route-operator", "Content-Type": "application/json"})
        reply = connection.getresponse()
        raw = reply.read()
        assert reply.status == status, (reply.status, raw)
        return json.loads(raw)
    finally:
        connection.close()


def _api(fixture, path, *, agent="alice", method="GET", body=None, status=200):
    result, _, raw = request(fixture.proxy.paths[agent], "http://_safeyolo.proxy.internal" + path, method=method,
                            headers={"Authorization": f"Bearer {AGENT_TOKEN}"}, body=json.dumps(body).encode() if body is not None else None)
    assert result == status, (result, raw)
    assert VAULT_VALUE.encode() not in raw
    return json.loads(raw)


def _traffic(fixture, path=EXECUTE, *, method="POST", agent="alice", token=None, body=b"job=unrestricted", port=None):
    token = token or fixture.tokens[agent]
    status, headers, raw = request(fixture.proxy.paths[agent], f"http://127.0.0.1:{port or fixture.port}{path}", method=method,
                                  headers={"Authorization": f"Bearer {token}"}, body=body if method == "POST" else None)
    assert VAULT_VALUE.encode() not in raw and token.encode() not in raw
    return status, headers, raw


def _challenge(fixture, path=EXECUTE):
    status, _, raw = _traffic(fixture, path)
    assert status == 403, raw
    result = json.loads(raw)
    assert result["error"] == "GATEWAY_ROUTE_CHALLENGE", result
    return result


def _escalate(fixture, challenge, reason="The operator requested this synthetic execution.", **overrides):
    body = {"source": "directly_requested", "context": {"task": "Exercise the approved local operation", "reason": reason,
            "fallback": "Status confirms readiness but cannot perform the requested operation."}}
    body.update(overrides)
    return _api(fixture, challenge["escalate"], method="POST", body=body, status=202)


def _decide(fixture, challenge, decision="approve", *, status=200):
    return _admin(fixture, "POST", "/admin/approvals/" + challenge["challenge_id"], {"decision": decision, "option": "run"}, status=status)


@contextmanager
def route_fixture(directory, *, ttl=30, extra=""):
    if sys.platform != "linux":
        pytest.skip("current-run fixture observes a Linux backend birth and argv")
    directory.mkdir(parents=True)
    services, builtin = directory / "services", directory / "builtin"
    services.mkdir()
    builtin.mkdir()
    (services / "fixture.yaml").write_text(FIXTURE.read_text())
    token_file = directory / "operator-token"
    token_file.write_text("fixture-route-operator")
    data = directory / "data"
    data.mkdir()
    store_credential(data, VAULT_NAME, VAULT_VALUE)
    (directory / "run").mkdir()
    backend = subprocess.Popen(["runsc-sandbox", "-c", "import time; time.sleep(300)", "boot", "safeyolo-" + RUN,
                                "--root", str(directory / "run")], executable=sys.executable)
    try:
        for agent, identity in IDS.items():
            owned = directory / "agents" / agent
            (owned / "config-share").mkdir(parents=True)
            (owned / "runtime.json").write_text(json.dumps({"name": agent, "agent_id": identity, "run_id": RUN,
                "state": "running", "backend_pid": backend.pid, "backend_token": _process_start_token(backend.pid)}))
            (owned / "config-share/host-launch-context.json").write_text(json.dumps({"agent_id": identity, "generation": RUN}))
        with _origin() as sink:
            sink.release_post.set()
            port = sink.server_address[1]
            source = _policy(port, ttl=ttl, extra=extra)
            with launch_proxy("rust", directory, source, native_product=True, agent_api=True,
                              agent_api_token=AGENT_TOKEN.encode(), admin_port=0, admin_api_token_file=token_file,
                              gateway_services_dir=services, gateway_builtin_services_dir=builtin) as proxy:
                fixture = SimpleNamespace(directory=directory, proxy=proxy, port=port, sink=sink, tokens={}, source=source)
                for agent in IDS:
                    fixture.tokens[agent] = _api(fixture, "/gateway/services", agent=agent)["authorized"][SERVICE]["token"]
                yield fixture
    finally:
        backend.terminate()
        backend.wait(timeout=5)


def test_challenge_abandon_alternative_and_explicit_retry(tmp_path):
    with route_fixture(tmp_path / "route") as fixture:
        challenge = _challenge(fixture)
        assert fixture.sink.deliveries == []
        assert _admin(fixture, "GET", "/admin/approvals")["approvals"] == []
        assert not any(row.get("approval", {}).get("required") for row in read_events(fixture.proxy.audit_log))
        assert challenge["guidance"]["assessment"]["risk_policy"]["effect"] == "prompt"
        assert challenge["guidance"]["reviewed_risk"]["description"].startswith("Synthetic execution")
        alternatives = challenge["guidance"]["alternatives"]
        assert next(row for row in alternatives if row["path"] == "/status")["gateway_permission"] == "allowed"
        assert next(row for row in alternatives if row["path"] == "/diagnostics")["gateway_permission"] == "requires_access"
        assert "not been verified" in alternatives[0]["prerequisites"]
        assert _traffic(fixture, "/status", method="GET")[0] == 200
        scope = challenge["scope"]["action"]
        assert scope["run"]["run_id"] == RUN and scope["credential"] == VAULT_NAME
        assert scope["method"] == "POST" and scope["path"] == EXECUTE and scope["port"] == fixture.port
        pending = _escalate(fixture, challenge)
        context_path = "/admin/approvals/" + challenge["challenge_id"] + "/context"
        question = _admin(fixture,"POST",context_path,{},status=202)
        _api(fixture,"/approvals/" + challenge["challenge_id"] + "/context",method="POST",
             body={"context_id":question["context"]["context_id"],"context":{"task":"local fixture","reason":"Additional operator-requested context.","fallback":"Status is insufficient."}})
        assert _admin(fixture,"GET",context_path)["context"]["status"] == "answered"
        assert pending["status"] == "pending" and pending["options"][0]["parameters"]["ttl_seconds"] == 30
        # Explanation wording and query/body values do not change authority.
        assert _escalate(fixture, challenge, "A differently worded explanation.")["approval_id"] == pending["approval_id"]
        assert _challenge(fixture, EXECUTE + "?job=other")["challenge_id"] == challenge["challenge_id"]
        result = _decide(fixture, challenge)
        assert result["status"] == "approved"
        assert len(fixture.sink.deliveries) == 1  # Only the explicit diagnostic, no replay.
        assert _traffic(fixture, EXECUTE + "?job=another", body=b"job=another")[0] == 200
        delivery = fixture.sink.deliveries[-1]
        assert delivery["authorization_is_vaulted"] and delivery["gateway_token_absent"]
        assert _traffic(fixture, DELETE)[0] == 403
        assert _traffic(fixture, EXECUTE.rstrip("/"))[0] == 403
        assert _traffic(fixture, "/status/", method="GET")[0] == 403
        for path in ("/api/../delete", "/api/%2Fdelete", "/api//delete"):
            assert _traffic(fixture,path)[0] == 403
        assert VAULT_VALUE not in fixture.proxy.audit_log.read_text()
        assert _traffic(fixture, EXECUTE, method="GET")[0] == 403
        assert _traffic(fixture, EXECUTE, method="post")[0] == 403
        assert _traffic(fixture, EXECUTE, agent="bob")[0] == 403
        assert _traffic(fixture, EXECUTE, agent="bob", token=fixture.tokens["alice"])[0] == 403
        events = read_events(fixture.proxy.audit_log)
        assert any(row["event"] == "gateway.route_challenged" for row in events)
        assert any(row["event"] == "gateway.route_escalated" for row in events)
        assert any(row["event"] == "gateway.route_exception_used" for row in events)


def test_forged_scope_and_refusal_do_not_create_more_operator_work(tmp_path):
    with route_fixture(tmp_path / "refusal") as fixture:
        challenge = _challenge(fixture)
        _api(fixture, challenge["escalate"], method="POST", body={"source":"inferred", "context":{"task":"task", "reason":"reason", "fallback":"none"}, "path":DELETE}, status=400)
        _api(fixture, challenge["escalate"], agent="bob", method="POST", body={"source":"inferred", "context":{"task":"task", "reason":"reason", "fallback":"none"}}, status=404)
        assert not _admin(fixture,"POST","/admin/approvals/" + challenge["challenge_id"] + "/attention", {})["notify"]
        _escalate(fixture, challenge)
        assert _admin(fixture,"POST","/admin/approvals/" + challenge["challenge_id"] + "/attention", {})["notify"]
        assert not _admin(fixture,"POST","/admin/approvals/" + challenge["challenge_id"] + "/attention", {})["notify"]
        _decide(fixture, challenge, "reject")
        again = _challenge(fixture)
        assert again["status"] == "challenged"
        assert _admin(fixture,"GET","/admin/approvals")["approvals"] == []
        refused = _api(fixture, again["escalate"], method="POST", body={"source":"untrusted_content", "context":{"task":"task", "reason":"new wording", "fallback":"none"}}, status=202)
        assert refused["status"] == "pending" and refused["request_history"]["last_refusal"]
        assert len(_admin(fixture,"GET","/admin/approvals")["approvals"]) == 1
        assert not _admin(fixture,"POST","/admin/approvals/" + again["challenge_id"] + "/attention", {})["notify"]
        assert fixture.sink.deliveries == []


@pytest.mark.parametrize("change", ["explicit_deny", "risk_deny", "definition", "binding", "host_mapping", "credential", "run", "revocation", "expiry"])
@pytest.mark.parametrize("phase", ["pending", "approved"])
def test_route_exception_rechecks_current_authority(tmp_path, change, phase):
    with route_fixture(tmp_path / change, ttl=2 if change == "expiry" else 30) as fixture:
        challenge = _challenge(fixture)
        _escalate(fixture, challenge)
        if phase == "approved":
            _decide(fixture, challenge)
        document = tomlkit.parse((fixture.directory / "policy.toml").read_text())
        if change == "explicit_deny":
            document["hosts"]["127.0.0.1"]["rules"] = [{"action":"gateway:request", "resource":f"{SERVICE}:{EXECUTE}", "effect":"deny"}]
        elif change == "risk_deny":
            document["risk"][0]["decision"] = "deny"
        elif change == "definition":
            path = fixture.directory / "services/fixture.yaml"
            path.write_text(path.read_text().replace("irreversible: true", "irreversible: false"))
        elif change == "binding":
            document["agents"]["alice"]["services"][SERVICE]["account"] = "changed"
        elif change == "host_mapping":
            document["hosts"]["127.0.0.1"]["service"] = "unbound-service"
        elif change == "credential":
            store_credential(fixture.directory / "data", VAULT_NAME, "changed-synthetic-value")
        elif change == "run":
            path = fixture.directory / "agents/alice/runtime.json"
            run = json.loads(path.read_text())
            run["run_id"] = "f" * 32
            path.write_text(json.dumps(run))
        elif change == "revocation":
            if phase == "pending":
                _decide(fixture, challenge, "reject")
            else:
                grant = _admin(fixture,"GET","/admin/gateway/grants")["grants"][0]
                _admin(fixture,"DELETE","/admin/gateway/grants/" + grant["grant_id"])
        elif change == "expiry":
            time.sleep(2.1)
        if change not in {"credential", "run", "expiry", "revocation"}:
            (fixture.directory / "policy.toml").write_text(tomlkit.dumps(document))
            replace_policy(fixture.proxy, "rust", fixture.directory, tomlkit.dumps(document))
        if phase == "pending" and change not in {"expiry", "revocation"}:
            assert _decide(fixture, challenge, status=409)["status"] == "superseded"
        fixture.tokens["alice"] = _api(fixture,"/gateway/services")["authorized"][SERVICE]["token"]
        result, _, raw = _traffic(fixture)
        assert result in ({403, 503} if change == "host_mapping" else {403}), raw
        if change == "explicit_deny":
            assert json.loads(raw)["error"] == "ROUTE_DENIED"
        if change == "risk_deny":
            assert json.loads(raw)["error"] == "GATEWAY_RISKY_ROUTE"
        assert fixture.sink.deliveries == []


@pytest.mark.parametrize("before_approval", [True, False])
def test_restart_preserves_pending_scope_and_grant_expiry(tmp_path, before_approval):
    with route_fixture(tmp_path / "restart", ttl=5) as fixture:
        challenge = _challenge(fixture)
        _escalate(fixture, challenge)
        if not before_approval:
            _decide(fixture, challenge)
            original = _admin(fixture,"GET","/admin/gateway/grants")["grants"][0]["expires"]
        fixture.proxy.process.terminate()
        fixture.proxy.process.wait(timeout=10)
        command = [os.environ.get("SAFEYOLO_RUST_PROXY", str(REPO / "proxy/target/release/safeyolo-proxy")),
                   "--config", str(fixture.directory / "config.toml")]
        with child_process(command, fixture.directory, dict(os.environ)) as restarted:
            wait_ready(restarted,[fixture.proxy.readiness_file,*map(Path,fixture.proxy.paths.values())],fixture.directory / "process.log",
                       readiness_file=fixture.proxy.readiness_file,expected_backend="rust-m2")
            fixture.tokens["alice"] = _api(fixture,"/gateway/services")["authorized"][SERVICE]["token"]
            assert fixture.sink.deliveries == []
            if before_approval:
                assert _api(fixture,"/gateway/challenges/" + challenge["challenge_id"])["status"] == "pending"
                _decide(fixture,challenge)
                original = _admin(fixture,"GET","/admin/gateway/grants")["grants"][0]["expires"]
            assert _traffic(fixture)[0] == 200
            assert _admin(fixture,"GET","/admin/gateway/grants")["grants"][0]["expires"] == original
            remaining = (datetime.fromisoformat(original) - datetime.now(UTC)).total_seconds()
            time.sleep(max(0,remaining) + 0.05)
            assert _traffic(fixture)[0] == 403
            assert len(fixture.sink.deliveries) == 1


def test_destination_and_literal_metacharacter_scope(tmp_path):
    with _origin() as other:
        other.release_post.set()
        port = other.server_address[1]
        with route_fixture(tmp_path / "literal", extra=f'[hosts."127.0.0.1:{port}"]\negress="allow"') as fixture:
            challenge = _challenge(fixture,"/literal*name")
            assert challenge["guidance"]["reviewed_risk"] is None
            assert not challenge["guidance"]["assessment"]["risk_guidance_available"]
            _escalate(fixture,challenge)
            _decide(fixture,challenge)
            assert _traffic(fixture,"/literal*name")[0] == 200
            assert _traffic(fixture,"/literalXname")[0] == 403
            assert _traffic(fixture,"/literal*name",port=port)[0] == 403
            assert other.deliveries == []
            assert _traffic(fixture,"/status",method="GET")[0] == 200


def test_risk_grant_alone_cannot_admit_missing_route(tmp_path):
    with route_fixture(tmp_path / "risk-grant") as fixture:
        _admin(fixture,"POST","/admin/gateway/grant",{"agent":"alice","service":SERVICE,"method":"POST","path":EXECUTE,"lifetime":"remembered"})
        fixture.tokens["alice"] = _api(fixture,"/gateway/services")["authorized"][SERVICE]["token"]
        challenge = _challenge(fixture)
        assert challenge["status"] == "challenged" and fixture.sink.deliveries == []
        assert _admin(fixture,"GET","/admin/approvals")["approvals"] == []


@pytest.mark.parametrize("control", ["network", "credential", "contract"])
def test_exception_preserves_other_enforcement(tmp_path, control):
    with route_fixture(tmp_path / control) as fixture:
        challenge = _challenge(fixture)
        _escalate(fixture,challenge)
        _decide(fixture,challenge)
        source = (fixture.directory / "policy.toml").read_text()
        document = tomlkit.parse(source)
        if control == "network":
            document["hosts"][f"127.0.0.1:{fixture.port}"]["egress"] = "deny"
        elif control == "credential":
            document["hosts"]["127.0.0.1"]["rules"] = [{"action":"credential:use","resource":"127.0.0.1/*","effect":"deny"}]
            document["controls"]["credentials"]["standard_auth_headers"] = ["authorization"]
        else:
            service = fixture.directory / "services/fixture.yaml"
            service.write_text(service.read_text().replace("  operator:\n", """  operator:
    contract:
      template: fixture.route.v1
      bindings:
        project: {type: string}
      operations:
        - name: execute
          request:
            method: POST
            path: /contract/{project}
            path_params:
              project: {equals_var: project}
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_enforcement: declared
"""))
        replace_policy(fixture.proxy,"rust",fixture.directory,tomlkit.dumps(document))
        fixture.tokens["alice"] = _api(fixture,"/gateway/services")["authorized"][SERVICE]["token"]
        status, _, raw = _traffic(fixture)
        assert status == 403, raw
        assert json.loads(raw).get("error") != "GATEWAY_ROUTE_CHALLENGE"
        assert _admin(fixture,"GET","/admin/approvals")["approvals"] == []
        assert fixture.sink.deliveries == []
