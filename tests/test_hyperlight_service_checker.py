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


@pytest.fixture
def host_driver(monkeypatch):
    directory = REPO / "tests/blackbox/host"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("hyperlight_services", directory / "hyperlight_services.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver


@pytest.fixture
def host_capture():
    # Execution 17663 reached these two distinct host identity formats. No
    # guest result or source-only control establishes real-engine acceptance.
    return {"observation_error": None, "outcome": {"kind": "exit", "code": 0},
            "gate_principal": "gate:hyperlight-service-check",
            "authorization_principal": "gate:hyperlight-service-check",
            "runtime_report": {"error": None},
            "rootfs": {"service_access": "mediated", "runtime_manifest_sha256": "a" * 64,
                       "artifact_sha256": "b" * 64},
            "input_sha256": "c" * 64, "gate_definition_sha256": "d" * 64,
            "started_unix_ms": 1, "ended_unix_ms": 4,
            "service_evidence": [{"started_at_ms": 2, "ended_at_ms": 3,
                "configuration_sha256": "d24ad902fecfe5456559a18228fc10c8819c5044e431d4bc5986aada459ec63d",
                "policy_hash": "sha256:3936e5b89eae7b38", "retained_base64": None}]}


def test_host_capture_retains_the_current_policy_and_configuration_identities(host_driver, host_capture):
    assert host_driver.captured(host_capture) == host_capture["service_evidence"]
    host_capture["service_evidence"].append(copy.deepcopy(host_capture["service_evidence"][0]))
    assert len(host_driver.captured(host_capture)) == 2
    host_capture["service_evidence"][1]["policy_hash"] = "sha256:" + "a" * 16
    with pytest.raises(AssertionError, match="one delegated configuration and policy"):
        host_driver.captured(host_capture)


@pytest.mark.parametrize("field,value", [
    ("policy_hash", "a" * 64), ("policy_hash", "sha256:" + "a" * 64),
    ("policy_hash", "sha256:" + "a" * 15), ("policy_hash", "sha256:" + "g" * 16),
    ("configuration_sha256", "a" * 63), ("configuration_sha256", "g" * 64),
    ("configuration_sha256", "sha256:" + "a" * 64), ("started_at_ms", 0),
    ("ended_at_ms", 5),
])
def test_host_capture_rejects_invalid_identity_or_time_binding(host_driver, host_capture, field, value):
    host_capture["service_evidence"][0][field] = value
    with pytest.raises(AssertionError):
        host_driver.captured(host_capture)


def test_named_evidence_binds_the_raw_adopted_definition_digest(host_driver, tmp_path):
    path = tmp_path / "adopted.json"
    path.write_text('{ "timeout_seconds": 30, "gate_id": "hyperlight-service-check" }\n')
    subject = {"kind": "value", "value": "1550"}
    first = {"run_id": "job-first", "gate_principal": "gate:hyperlight-service-check"}
    named = {"evidence": {
        "result": {"finding": {"positive": True}, "subject": subject},
        "execution": {"run_id": "job-named", "gate_principal": first["gate_principal"],
                      "definition_digest": host_driver.digest(path), "service_evidence": [{}]}}}
    host_driver.check_named_evidence(first, named, path, subject)

    rewritten = tmp_path / "rewritten.json"
    rewritten.write_text(json.dumps(json.loads(path.read_bytes()), sort_keys=True))
    assert host_driver.digest(rewritten) != host_driver.digest(path)
    for value in ("sha256:" + host_driver.digest(path), "0" * 64, host_driver.digest(rewritten)):
        named["evidence"]["execution"]["definition_digest"] = value
        with pytest.raises(AssertionError):
            host_driver.check_named_evidence(first, named, path, subject)
