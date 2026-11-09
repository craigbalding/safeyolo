"""Adopted job semantics cross real challenge, approval and request boundaries.

The upstream is a controlled sink. The maintained model defines the illustrative
job semantics; these tests do not infer behavior from live Rundeck or run jobs.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from tests.proxy_contracts.harness import REPO, request
from tests.proxy_contracts.test_native_coord_operator import terminal, wait_terminal_exit
from tests.proxy_contracts.test_native_network_policy import replace_policy
from tests.proxy_contracts.test_native_policy_cli import native_inputs
from tests.proxy_contracts.test_service_route_challenge import (
    SERVICE,
    VAULT_VALUE,
    _admin,
    _api,
    _decide,
    _escalate,
    route_fixture,
)

DEFINITION = "/projects/demo/jobs/alpha/definition"
EXECUTION = "/projects/demo/jobs/alpha/run"
MODEL = REPO / "proxy/tests/fixtures/service-authoring/job.generated.yaml"


@contextmanager
def job_fixture(directory, *, extra="", modify=None, ttl=30):
    source = json.loads(MODEL.read_text())
    source.update(name=SERVICE, default_host="127.0.0.1")
    source["auth"]["allow_http"] = True
    source["capabilities"]["operator"] = {"routes": [
        {"methods": ["POST"], "path": EXECUTION},
        {"methods": ["GET"], "path": DEFINITION},
    ]}
    if modify is not None:
        modify(source)
    with route_fixture(directory, service_source=json.dumps(source), extra=extra, ttl=ttl) as fixture:
        yield fixture


def traffic(fixture, path=DEFINITION, method="PATCH", payload=None):
    status, _, raw = request(fixture.proxy.paths["alice"], f"http://127.0.0.1:{fixture.port}{path}",
                            method=method, headers={"Authorization": "Bearer " + fixture.tokens["alice"], "Content-Type": "application/json"},
                            body=json.dumps(payload or {"description": "A cosmetic observation"}).encode() if method in {"PATCH", "PUT"} else None)
    assert VAULT_VALUE.encode() not in raw
    return status, raw


def challenge(fixture, **kwargs):
    status, raw = traffic(fixture, **kwargs)
    assert status == 403, raw
    value = json.loads(raw)
    assert value["error"] == "GATEWAY_ROUTE_CHALLENGE", value
    return value


def test_normal_approval_interfaces_retain_canonical_effects_guidance_and_outcome(tmp_path):
    with job_fixture(tmp_path / "presentation", ttl=120) as fixture:
        value = challenge(fixture)
        _escalate(fixture, value, "The operator requested a stored-definition edit.")
        identifier = value["challenge_id"]
        record = _admin(fixture, "GET", "/admin/approvals/" + identifier)
        # The same nonsecret canonical input is consumed by the native Mac view.
        (tmp_path / "canonical-approval.json").write_text(json.dumps(record))
        binary = native_inputs()[0] / "safeyolo"
        command = [str(binary), "--root", str(fixture.directory)]
        for action in ("show", "explain"):
            result = subprocess.run([*command, "approvals", action, identifier, "--agent", "alice"],
                                    capture_output=True, text=True, timeout=15)
            assert result.returncode == 0, result.stderr
            output = result.stdout
            assert "SafeYolo assessment" in output and "Policy and reviewed guidance" in output
            assert "executable_changed" in output and "alternatives" in output
            assert "unverified" in output.lower() and "uncertainty" in output
            assert identifier in output and "run" in output and "expires" in output.lower()
            assert VAULT_VALUE not in output
            (tmp_path / f"normal-{action}.txt").write_text(output)
        instance = SimpleNamespace(root=fixture.directory, environment=dict(os.environ))
        with terminal(instance, command=[*command, "approvals", "review", "--agent", "alice"]) as (process, master, until):
            until(b"Request number")
            os.write(master, b"1\n")
            output = until(b"approve / reject")
            assert b"SafeYolo assessment" in output and b"executable_changed" in output
            assert b"Policy and reviewed guidance" in output and b"untrusted" in output.lower()
            os.write(master, b"reject\n")
            output += until(b"No pending requests")
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
            (tmp_path / "normal-review.txt").write_bytes(output)
        result = subprocess.run([*command, "approvals", "show", identifier], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0 and "rejected" in result.stdout
        assert "Recorded outcome" in result.stdout and fixture.sink.deliveries == []


def test_combined_authority_is_prepared_before_operator_work_and_shared_by_approval(tmp_path):
    with job_fixture(tmp_path / "combined") as fixture:
        assert traffic(fixture, path=EXECUTION, method="POST")[0] == 200
        value = challenge(fixture)
        assessed = value["guidance"]["assessment"]
        rule = assessed["model"]["rules"]["changed_job_execution"]
        assert rule["status"] == "match"
        assert "job runner" in rule["consequence"]
        assert len(rule["combinations"][0]["contributing_permissions"]) == 2
        assert rule["combinations"][0]["scope"]["job"] == {"kind": "known", "value": "alpha"}
        assert rule["unverified_prerequisites"]
        edit = next(row for row in assessed["model"]["direct"] if row["permission"]["proposed"])
        assert "executable_changed" in edit["possible_effects"]
        assert "executable_changed" in edit["persistent_effects"]
        assert _admin(fixture, "GET", "/admin/approvals")["approvals"] == []
        assert len(fixture.sink.deliveries) == 1  # Abandonment needs no operator action.
        recipe = assessed["alternatives"][0]
        assert recipe["required_access"][0]["access"] == "available"
        assert recipe["unverified_prerequisites"]
        assert "Unverified" in recipe["goal_suitability"]
        pending = _escalate(fixture, value, "The operator requested a stored-definition edit.")
        assert pending["assessment"] == assessed
        repeated = _escalate(fixture, value, "Different agent wording cannot change the grant.")
        assert repeated["assessment"] == assessed
        operator = _admin(fixture, "GET", "/admin/approvals/" + value["challenge_id"])
        assert operator["assessment"] == assessed
        result = _decide(fixture, value)
        assert result["status"] == "approved"
        assert len(fixture.sink.deliveries) == 1
        assert traffic(fixture, payload={"steps": ["controlled-fixture"]})[0] == 200
        assert fixture.sink.deliveries[-1]["authorization_is_vaulted"]
        assert fixture.sink.deliveries[-1]["method"] == "PATCH"
        assert traffic(fixture, path=DEFINITION.replace("alpha", "beta"))[0] == 403
        assert traffic(fixture, method="PUT")[0] == 403


@pytest.mark.parametrize("phase", ["escalation", "approval"])
def test_policy_changes_expose_recomputed_assessment_and_supersede_old_consent(tmp_path, phase):
    with job_fixture(tmp_path / phase) as fixture:
        value = challenge(fixture)
        if phase == "approval":
            _escalate(fixture, value)
        replacement = fixture.source + '\n[[risk]]\nenables = ["changed_job_execution"]\ndecision = "deny"\n'
        replace_policy(fixture.proxy, "rust", fixture.directory, replacement)
        if phase == "escalation":
            result = _api(fixture, value["escalate"], method="POST", body={"source": "direct_request", "context": {
                "task": "fixture", "reason": "Try the retained request", "fallback": "Diagnostics do not edit"}})
        else:
            result = _decide(fixture, value, status=409)
        assert result["status"] == "superseded"
        assert result["assessment_changed"]
        assert result["assessment"]["risk_policy"]["effect"] == "deny"
        assert fixture.sink.deliveries == []
        fixture.tokens["alice"] = _api(fixture, "/gateway/services")["authorized"][SERVICE]["token"]
        assert json.loads(traffic(fixture)[1])["error"] == "GATEWAY_RISKY_ROUTE"


def test_alternative_recipe_needs_access_and_effect_denial_applies_to_other_endpoint(tmp_path):
    def modify(source):
        alternative = source["effect_model"]["alternatives"]["inspect_stored_definition"]
        alternative["steps"][0]["arguments"]["path.job"] = "beta"
        # Replacement and PATCH share the authored executable-change effect.
        source["effect_model"]["alternatives"]["replace_instead"] = {
            **alternative,
            "steps": [{"operation": "replace_definition", "enforcement": "replace_scoped",
                       "arguments": {"path.project": "demo", "path.job": "alpha"},
                       "expected_effects": ["executable_changed", "description_changed"]}],
            "prerequisites": ["Approved replacement access for the specified job."],
            "limitations": ["Replacement can leave persistent executable edits; it does not verify runner connectivity."],
        }
    with job_fixture(tmp_path / "recipes", modify=modify,
                     extra='\n[[risk]]\nenables = ["executable_changed"]\ndecision = "deny"\n') as fixture:
        # Inspection has no executable-change authority, so it can be challenged
        # without imposing a blanket denial on other modeled operations.
        value = challenge(fixture, path=DEFINITION.replace("alpha", "gamma"), method="GET")
        recipes = {row["id"]: row for row in value["guidance"]["assessment"]["alternatives"]}
        assert recipes["inspect_stored_definition"]["required_access"][0]["access"] == "requires_access"
        assert recipes["inspect_stored_definition"]["risk_policy"][0]["effect"] == "allow"
        assert recipes["replace_instead"]["risk_policy"][0]["effect"] == "deny"
        assert json.loads(traffic(fixture, method="PUT")[1])["error"] == "GATEWAY_RISKY_ROUTE"
        assert json.loads(traffic(fixture, method="PATCH")[1])["error"] == "GATEWAY_RISKY_ROUTE"
        assert fixture.sink.deliveries == []


@pytest.mark.parametrize("denied_effect", ["executable_changed", "changed_job_execution"])
def test_prohibited_edit_does_not_deny_independent_inspection_or_recipe(tmp_path, denied_effect):
    def modify(source):
        source["capabilities"]["operator"]["routes"].append({"methods": ["PATCH"], "path": DEFINITION})
    with job_fixture(tmp_path / denied_effect, modify=modify,
                     extra=f'\n[[risk]]\nenables = ["{denied_effect}"]\ndecision = "deny"\n') as fixture:
        status, raw = traffic(fixture)
        assert status == 403
        denied = json.loads(raw)
        assert denied["error"] == "GATEWAY_RISKY_ROUTE"
        assert denied_effect in denied["assessment"]["enables"]
        assert traffic(fixture, method="GET")[0] == 200
        assert fixture.sink.deliveries[-1]["authorization_is_vaulted"]
        assert fixture.sink.deliveries[-1]["method"] == "GET"

        # A missing inspection route and its permitted diagnostic recipe must
        # also remain usable when another admitted route is risk-denied.
        value = challenge(fixture, path=DEFINITION.replace("alpha", "beta"), method="GET")
        assessed = value["guidance"]["assessment"]
        assert assessed["risk_policy"]["effect"] == "allow"
        assert assessed["enables"] == ["inspected"]
        recipe = assessed["alternatives"][0]
        assert recipe["required_access"][0]["access"] == "available"
        assert recipe["risk_policy"][0]["effect"] == "allow"
        if denied_effect == "executable_changed":
            assert not any(row["method"] == "PATCH" for row in assessed["model"]["direct"])
            assert traffic(fixture, path=EXECUTION, method="POST")[0] == 200
        assert len(fixture.sink.deliveries) == (2 if denied_effect == "executable_changed" else 1)
        assert _admin(fixture, "GET", "/admin/approvals")["approvals"] == []


def test_new_temporary_route_authority_invalidates_a_pending_assessment(tmp_path):
    with job_fixture(tmp_path / "grant-change") as fixture:
        original = challenge(fixture)
        _escalate(fixture, original)
        another = challenge(fixture, path=DEFINITION.replace("alpha", "beta"))
        _escalate(fixture, another)
        assert _decide(fixture, another)["status"] == "approved"
        changed = _decide(fixture, original, status=409)
        assert changed["status"] == "superseded"
        assert changed["assessment_changed"]
        assert any(row["permission"]["id"].startswith("grt_") for row in changed["assessment"]["model"]["direct"])
        assert fixture.sink.deliveries == []


@pytest.mark.parametrize("change", ["revocation", "expiry"])
def test_removed_temporary_execution_access_is_reassessed_without_asserting_upstream_state(tmp_path, change):
    with job_fixture(tmp_path / change, ttl=2 if change == "expiry" else 30) as fixture:
        execute = challenge(fixture, path=EXECUTION.replace("alpha", "beta"), method="POST")
        _escalate(fixture, execute)
        assert _decide(fixture, execute)["status"] == "approved"
        edit = challenge(fixture, path=DEFINITION.replace("alpha", "beta"))
        assert edit["guidance"]["assessment"]["model"]["rules"]["changed_job_execution"]["status"] == "match"
        _escalate(fixture, edit)
        if change == "revocation":
            grant = _admin(fixture, "GET", "/admin/gateway/grants")["grants"][0]
            _admin(fixture, "DELETE", "/admin/gateway/grants/" + grant["grant_id"])
        else:
            time.sleep(2.1)
        result = _decide(fixture, edit, status=409)
        assert result["status"] == "superseded"
        assert result["assessment_changed"]
        assert result["assessment"]["model"]["rules"]["changed_job_execution"]["status"] == "non_match"
        assert any("prior edits were undone" in line for line in result["assessment"]["model"]["limitations"])
        assert fixture.sink.deliveries == []


def test_definition_changes_are_recomputed_before_approval(tmp_path):
    with job_fixture(tmp_path / "definition-change") as fixture:
        value = challenge(fixture)
        _escalate(fixture, value)
        path = fixture.directory / "services/fixture.yaml"
        definition = json.loads(path.read_text())
        definition["effect_model"]["rules"]["changed_job_execution"]["consequence"] = "Updated operator-adopted consequence."
        path.write_text(json.dumps(definition))
        replace_policy(fixture.proxy, "rust", fixture.directory, fixture.source)
        result = _decide(fixture, value, status=409)
        assert result["status"] == "superseded"
        assert result["assessment_changed"]
        assert result["assessment"]["model"]["rules"]["changed_job_execution"]["consequence"] == "Updated operator-adopted consequence."


@pytest.mark.parametrize("denied", [False, True])
def test_unbounded_execution_scope_includes_the_job_except_where_policy_denies_it(tmp_path, denied):
    def modify(source):
        source["capabilities"]["operator"]["routes"][0]["path"] = "/projects/*/jobs/*/run"
    extra = f'\n[[hosts."127.0.0.1".rules]]\naction = "gateway:request"\nresource = "{SERVICE}:{EXECUTION}"\neffect = "deny"\ncondition = {{agent = "alice"}}\n' if denied else ""
    with job_fixture(tmp_path / str(denied), modify=modify, extra=extra) as fixture:
        value = challenge(fixture)
        assert value["guidance"]["assessment"]["model"]["rules"]["changed_job_execution"]["status"] == ("non_match" if denied else "match")


@pytest.mark.parametrize("selector", ["/projects/*/alpha/run", "/projects/demo/jobs/a*/run"])
def test_known_candidate_scope_establishes_overlap_through_native_selectors(tmp_path, selector):
    def modify(source):
        source["capabilities"]["operator"]["routes"][0]["path"] = selector
    with job_fixture(tmp_path / "selector", modify=modify) as fixture:
        value = challenge(fixture)
        assert value["guidance"]["assessment"]["model"]["rules"]["changed_job_execution"]["status"] == "match"


def test_unresolved_alias_overlap_does_not_invent_an_effect_prohibition(tmp_path):
    def modify(source):
        source["capabilities"]["operator"]["routes"][0]["path"] = "/projects/demo/aliases/nightly/run"
    with job_fixture(tmp_path / "unknown", modify=modify,
                     extra='\n[[risk]]\nenables = ["changed_job_execution"]\ndecision = "deny"\n') as fixture:
        value = challenge(fixture)
        assessed = value["guidance"]["assessment"]
        assert assessed["model"]["rules"]["changed_job_execution"]["status"] == "unresolved"
        assert assessed["risk_policy"]["effect"] == "allow"
        assert _admin(fixture, "GET", "/admin/approvals")["approvals"] == []


def test_risk_only_grant_does_not_add_modeled_route_admission_authority(tmp_path):
    with job_fixture(tmp_path / "risk-only") as fixture:
        _admin(fixture, "POST", "/admin/gateway/grant", {"agent": "alice", "service": SERVICE,
               "method": "POST", "path": EXECUTION.replace("alpha", "beta"), "lifetime": "remembered"})
        fixture.tokens["alice"] = _api(fixture, "/gateway/services")["authorized"][SERVICE]["token"]
        value = challenge(fixture, path=DEFINITION.replace("alpha", "beta"))
        assert value["guidance"]["assessment"]["model"]["rules"]["changed_job_execution"]["status"] == "non_match"
        assert not any(row["permission"]["id"].startswith("grt_") for row in value["guidance"]["assessment"]["model"]["direct"])
        assert challenge(fixture, path=EXECUTION.replace("alpha", "beta"), method="POST")["error"] == "GATEWAY_ROUTE_CHALLENGE"


@pytest.mark.parametrize("capability,excluded", [("describe_job", True), ("edit_job", False)])
def test_actual_contract_binding_projects_enforced_cosmetic_constraints(tmp_path, capability, excluded):
    def modify(source):
        source["capabilities"]["operator"] = source["capabilities"][capability]
        for mapping in source["effect_model"]["enforcement"].values():
            if mapping["capability"] == capability:
                mapping["capability"] = "operator"
    bindings = f'''\n[[agents.alice.contract_bindings]]
service = "{SERVICE}"
capability = "operator"
template = "job-fixture.v1.edit_definition"
bound_values = {{project = "demo", job = "alpha"}}
grantable_operations = ["edit_definition"]
[[risk]]
enables = ["description_changed"]
decision = "deny"
'''
    with job_fixture(tmp_path / capability, modify=modify, extra=bindings) as fixture:
        status, raw = traffic(fixture)
        assert status == 403
        value = json.loads(raw)
        assert value["error"] == "GATEWAY_RISKY_ROUTE", value
        direct = value["assessment"]["model"]["direct"]
        assert len(direct) == 1
        assert direct[0]["permission"]["enforcement"] == ("description_only" if excluded else "edit_scoped")
        assert ("executable_changed" in direct[0]["excluded_effects"]) == excluded
        assert ("executable_changed" in direct[0]["possible_effects"]) != excluded
        assert direct[0]["scopes"]["job"] == {"project": {"kind": "known", "value": "demo"}, "job": {"kind": "known", "value": "alpha"}}
        assert fixture.sink.deliveries == []


def test_recipe_with_unspecified_binding_reports_the_prerequisite_and_full_effects(tmp_path):
    def modify(source):
        source["effect_model"]["alternatives"]["inspect_stored_definition"]["steps"] = [{
            "operation": "execute_job", "enforcement": "execute_scoped",
            "arguments": {"path.project": "demo", "path.job": "alpha"},
            "expected_effects": ["executed", "previewed"],
        }]
        source["effect_model"]["alternatives"]["inspect_stored_definition"]["limitations"] = ["Running stored steps does not prove that they meet the operator's goal."]
    with job_fixture(tmp_path / "missing-binding", modify=modify) as fixture:
        value = challenge(fixture)
        required = value["guidance"]["assessment"]["alternatives"][0]["required_access"][0]
        assert any("mode" in condition for condition in required["unverified_binding_conditions"])
        assert required["access"] == "available"
        assert "executed" in required["modeled_effects"]["direct"][0]["possible_effects"]


def test_existing_risk_approval_consumes_the_same_temporary_combined_authority(tmp_path):
    with job_fixture(tmp_path / "ordinary-risk", extra='\n[[risk]]\nenables = ["changed_job_execution"]\ndecision = "require_approval"\n') as fixture:
        value = challenge(fixture)
        _escalate(fixture, value)
        assert _decide(fixture, value)["status"] == "approved"
        status, headers, raw = request(fixture.proxy.paths["alice"], f"http://127.0.0.1:{fixture.port}{EXECUTION}",
                                       method="POST", headers={"Authorization": "Bearer " + fixture.tokens["alice"]})
        assert status == 428, raw
        approval_id = next(value for name, value in headers.items() if name.lower() == "x-safeyolo-approval-id")
        pending = _admin(fixture, "GET", "/admin/approvals/" + approval_id)
        assert pending["assessment"]["model"]["rules"]["changed_job_execution"]["status"] == "match"
        assert pending["assessment"]["risk_policy"]["effect"] == "prompt"
        assert _admin(fixture, "POST", "/admin/approvals/" + approval_id, {"decision": "approve", "option": "run"})["status"] == "approved"
        assert traffic(fixture, path=EXECUTION, method="POST")[0] == 200
