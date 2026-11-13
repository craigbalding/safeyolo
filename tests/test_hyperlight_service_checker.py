"""Both guests' predicate uses the existing authoritative GitHub capture."""

import base64
import copy
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("service_checker", REPO / "jobs/service_checker.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
CAPTURE = json.loads((REPO / "proxy/tests/fixtures/policy-check-github-issue.json").read_bytes())


def request():
    return {"subject": {"kind": "value", "value": "1544"}, "inputs": {
        "repository": "craigbalding/safeyolo", "expected_author_id": str(CAPTURE["user"]["id"])}}


def bridge(data):
    offset = 0

    def call(value):
        nonlocal offset
        if value["kind"] == "service":
            assert value == {"kind": "service", "service": "github", "method": "GET",
                             "url": "https://api.github.com/repos/craigbalding/safeyolo/issues/1544"}
            return {"id": "host-capture", "status": 200, "bytes": len(data)}
        assert value == {"kind": "read", "id": "host-capture", "offset": offset, "length": checker.CHUNK}
        chunk = data[offset:offset + checker.CHUNK]
        offset += len(chunk)
        return {"total_bytes": len(data), "data_base64": base64.b64encode(chunk).decode()}

    return call


def test_complete_chunked_capture_and_identity_mismatch():
    capture = {**CAPTURE, "body": "large authenticated issue body " * 2000}
    data = json.dumps(capture).encode()
    assert len(data) > checker.CHUNK * 3
    assert checker.service_check(request(), bridge(data)) == {"finding": {"kind": "finding", "positive": True}}
    other = request()
    other["inputs"]["expected_author_id"] = "0"
    assert checker.service_check(other, bridge(data))["finding"]["positive"] is False
    with pytest.raises(ValueError):
        checker.service_check(request(), bridge(data[:-1]))


@pytest.mark.parametrize("field", ["url", "number", "id", "title", "updated_at", "user"])
def test_missing_evidence_is_unavailable(field):
    capture = copy.deepcopy(CAPTURE)
    del capture[field]
    with pytest.raises((ValueError, KeyError)):
        checker.service_check(request(), bridge(json.dumps(capture).encode()))


@pytest.mark.parametrize("field,value", [("url", "https://api.github.com/repos/other/repo/issues/1544"),
                                       ("number", 1545), ("number", True), ("user", {"id": True})])
def test_mismatched_subject_and_wrong_types_are_unavailable(field, value):
    with pytest.raises(ValueError):
        checker.service_check(request(), bridge(json.dumps({**CAPTURE, field: value}).encode()))


@pytest.mark.parametrize("chunk", [{"total_bytes": 2, "data_base64": ""},
                                  {"total_bytes": 3, "data_base64": "e30="},
                                  {"total_bytes": 2, "data_base64": "invalid base64"}])
def test_incomplete_capture_is_unavailable(chunk):
    def call(value):
        return {"id": "capture", "status": 200, "bytes": 2} if value["kind"] == "service" else chunk
    with pytest.raises(ValueError):
        checker.service_check(request(), call)


def test_provider_denial_and_limit_are_unavailable():
    def denied(_value):
        raise RuntimeError("policy_denied")
    with pytest.raises(RuntimeError, match="policy_denied"):
        checker.service_check(request(), denied)
    for response in [{"status": 200, "bytes": checker.MAX_CAPTURE + 1}, {"status": 403, "bytes": 0}]:
        with pytest.raises(ValueError):
            checker.service_check(request(), lambda _: response)


def test_bundle_pins_both_service_checkers_without_changing_offline_examples(tmp_path):
    import hashlib

    spec = importlib.util.spec_from_file_location("builder", REPO / "scripts/build_hyperlight_jobs.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    for name in ("core.elf", "checker.py", "service_checker.py", "runtime.json"):
        (tmp_path / name).write_text(name)
    builder.write_job_definitions(tmp_path)
    for kind in ("hyperlight", "hyperlight-unikraft"):
        offline = json.loads((tmp_path / f"{kind}.json").read_text())
        service = json.loads((tmp_path / f"{kind}-service.json").read_text())
        assert "mediated_services" not in offline
        assert service["network"] is False
        assert service["mediated_services"]["services"] == ["github"]
        assert service["gate_id"] == "hyperlight-service-check"
        selected = service["engine"]["guest" if kind == "hyperlight" else "checker"]
        assert selected["sha256"] == hashlib.sha256((tmp_path / selected["path"]).read_bytes()).hexdigest()
        if kind == "hyperlight":
            assert offline["engine"]["function"] == "Check"
            assert service["engine"]["function"] == "ServiceCheck"
        else:
            assert offline["engine"]["checker"]["path"] == "checker.py"
            assert selected["path"] == "service_checker.py"
