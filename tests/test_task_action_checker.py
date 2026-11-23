"""Task/action model protocol controls; these stubs do not measure model accuracy."""
import base64
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("task_action_checker", ROOT / "jobs/task_action_checker.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def request(case):
    trusted = {"task": {"id": "synthetic-task", "revision": "task-1", "objective": case["objective"]},
               "requester": {"agent_id": "synthetic-agent", "run_id": "synthetic-run"},
               "action": case["action"], "prepared": case["prepared"],
               "constraints": case["constraints"], "history": case["history"]}
    return {"subject": {"kind": "value", "value": json.dumps({"schema": "task_action.v1",
                "bindings": {"task": "task-1", "action": case["id"], "input_revision": "fixtures-1"},
                "trusted": trusted, "untrusted": case["untrusted"]})},
            "inputs": {"prompt_revision": "task-action-2", "model": "claude-haiku-4-5-20251001",
                       "model_revision": "claude-haiku-4-5-20251001", "input_revision": "fixtures-1",
                       "service": "claude", "endpoint": "https://api.anthropic.com/v1/messages"}}


CASES = json.loads((ROOT / "tests/fixtures/task-action-cases.json").read_text())


def result(concern=False):
    return {"relevance": "irrelevant" if concern else "relevant", "proportionality": "excessive" if concern else "proportionate",
            "evidence_refs": ["task", "action"], "clarification": None, "uncertainty": []}


def evaluate(value, finding=None, patch=None, raw=None):
    output = {"model": value["inputs"]["model"], "stop_reason": "end_turn",
              "content": [{"type": "text", "text": json.dumps(finding or result())}]}
    output.update(patch or {})
    capture = raw if raw is not None else json.dumps(output).encode()
    calls = []

    def call(operation):
        if operation["kind"] == "service":
            calls.append(operation)
            return {"id": "host-capture", "bytes": len(capture), "status": 200}
        start = operation["offset"]
        return {"total_bytes": len(capture),
                "data_base64": base64.b64encode(capture[start:start + operation["length"]]).decode()}

    return CHECKER.assess(value, call), calls


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_same_adapter_uses_both_structured_actions_and_fixed_provider(case):
    value = request(case)
    output, calls = evaluate(value, result(case["expected_concern"]))
    assert output["finding"]["kind"] == "task_action"
    assert len(calls) == 1
    assert calls[0]["service"] == "claude"
    assert calls[0]["url"] == "https://api.anthropic.com/v1/messages"
    body = json.loads(base64.b64decode(calls[0]["body_base64"]))
    assert body["model"] == value["inputs"]["model"]
    assert body["system"] == CHECKER.SYSTEM
    assert "host_operation" not in body["system"]
    assert json.loads(body["messages"][0]["content"])["trusted"]["action"] == case["action"]


def test_provider_schema_uses_only_disclosed_top_level_evidence_references():
    value = request(CASES[-1])
    _, calls = evaluate(value)
    body = json.loads(base64.b64decode(calls[0]["body_base64"]))
    response_format = body["output_config"]["format"]
    assert response_format["type"] == "json_schema"
    schema = response_format["schema"]
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    assert set(schema["required"]) == set(result()) == set(schema["properties"])
    properties = schema["properties"]
    assert properties["evidence_refs"] == {
        "type": "array", "minItems": 1,
        "items": {"type": "string", "enum": ["action", "constraints", "history", "prepared", "requester", "task"]}}
    assert properties["relevance"]["enum"] == ["relevant", "irrelevant", "uncertain"]
    assert properties["proportionality"]["enum"] == ["proportionate", "excessive", "uncertain"]


@pytest.mark.parametrize("text", [
    '```json\n' + json.dumps(result()) + '\n```',
    json.dumps(result()) + '\nAdditional rationale',
    json.dumps(dict(result(), evidence_refs=["task.objective"])),
])
def test_observed_model_format_failures_remain_unavailable(text):
    with pytest.raises(ValueError):
        evaluate(request(CASES[0]), patch={"content": [{"type": "text", "text": text}]})


@pytest.mark.parametrize("patch", [{"model": "substituted"}, {"stop_reason": "max_tokens"},
    {"stop_reason": "refusal"}, {"content": []}, {"content": [{"type": "tool_use"}]}])
def test_model_identity_partial_and_non_text_results_remain_unavailable(patch):
    with pytest.raises(ValueError):
        evaluate(request(CASES[0]), patch=patch)


@pytest.mark.parametrize("raw", [b'{', b'PASS', b'{"model":"a","model":"b"}', b'NaN'])
def test_malformed_complete_capture_is_not_a_finding(raw):
    with pytest.raises(ValueError):
        evaluate(request(CASES[0]), raw=raw)


@pytest.mark.parametrize("change", [lambda v: v.update(score=0.99), lambda v: v.update(evidence_refs=["invented"]),
    lambda v: v.update(uncertainty="none"), lambda v: v.update(relevance="certainly_safe"),
    lambda v: v.update(relevance="uncertain"), lambda v: v.update(clarification=""),
    lambda v: v.pop("proportionality")])
def test_typed_result_rejects_invented_references_and_undefined_meaning(change):
    finding = result()
    change(finding)
    with pytest.raises(ValueError):
        evaluate(request(CASES[0]), finding=finding)


def test_timeout_and_denied_service_propagate_without_retry():
    for error in (TimeoutError("adopted deadline"), PermissionError("service denied")):
        calls = []

        def call(operation):
            calls.append(operation)
            raise error

        with pytest.raises(type(error)):
            CHECKER.assess(request(CASES[0]), call)
        assert len(calls) == 1


def test_complete_chunked_capture_and_input_bounds():
    finding = result()
    finding["uncertainty"] = ["unknown " * 200] * 16
    assert evaluate(request(CASES[0]), finding=finding)[0]["finding"]["assessment"] == finding
    value = request(CASES[0])
    subject = json.loads(value["subject"]["value"])
    subject["untrusted"] = {"rationale": "oversized evidence" * 3000}
    value["subject"]["value"] = json.dumps(subject)
    with pytest.raises(ValueError, match="input exceeds"):
        evaluate(value)
