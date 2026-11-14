"""Both guests' predicate uses the existing authoritative GitHub capture."""

import base64
import contextlib
import copy
import importlib.util
import json
import signal
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

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


@pytest.mark.parametrize("entrypoint", ["job_result", "run_job"])
def test_driver_preserves_job33_failure_before_decoding_stdout(host_driver, tmp_path, monkeypatch, entrypoint):
    prefix = tmp_path / "job-33"
    stderr = ("safeyolo: job cleanup failed: delegated listener cleanup acknowledgment is unavailable; "
              "runtime preserved at /home/agent/hl1550-a706de61/data/job-hyperlight-sP769u\n")
    assert len(stderr.encode()) == 164
    prefix.with_suffix(".stdout").write_bytes(b"")
    prefix.with_suffix(".stderr").write_text(stderr)
    prefix.with_suffix(".status.json").write_text('{"returncode": 1}\n')
    diagnostic = tmp_path / "job-hyperlight-sP769u" / "service-evidence.json"
    diagnostic.parent.mkdir()
    diagnostic.write_text("retained diagnostic\n")

    @contextlib.contextmanager
    def completed_job(_engine, _request, **_options):
        yield SimpleNamespace(wait=lambda timeout: 1), prefix

    instance = host_driver.Instance(SimpleNamespace(root=tmp_path, scratch=tmp_path))
    monkeypatch.setattr(instance, "job", completed_job)
    with pytest.raises(RuntimeError) as failed:
        if entrypoint == "job_result":
            host_driver.job_result(prefix, "hyperlight", "shutdown")
        else:
            instance.run_job("hyperlight", {})
    message = str(failed.value)
    mode = "shutdown" if entrypoint == "job_result" else "run_job"
    assert f"hyperlight/{mode}" in message and "command exit 1" in message
    assert stderr in message
    for suffix in (".status.json", ".stdout", ".stderr"):
        assert str(prefix.with_suffix(suffix)) in message
    assert diagnostic.read_text() == "retained diagnostic\n"
    assert prefix.with_suffix(".stdout").read_bytes() == b""
    assert json.loads(prefix.with_suffix(".status.json").read_bytes()) == {"returncode": 1}


def test_driver_cannot_accept_json_from_a_failed_command(host_driver, tmp_path):
    prefix = tmp_path / "job"
    prefix.with_suffix(".stdout").write_text('{"outcome": {"kind": "exit", "code": 0}, "observation_error": null}')
    prefix.with_suffix(".stderr").write_text("cleanup failed")
    prefix.with_suffix(".status.json").write_text('{"returncode": 1}')
    with pytest.raises(RuntimeError, match="command exit 1.*cleanup failed"):
        host_driver.job_result(prefix, "hyperlight-unikraft", "shutdown")
    prefix.with_suffix(".status.json").write_text('{"returncode": 0}')
    assert host_driver.job_result(prefix, "hyperlight-unikraft", "run_job") == {
        "outcome": {"kind": "exit", "code": 0}, "observation_error": None}
    for malformed in (b"malformed", b"\xff"):
        prefix.with_suffix(".stdout").write_bytes(malformed)
        with pytest.raises(RuntimeError, match="invalid job result JSON"):
            host_driver.job_result(prefix, "hyperlight-unikraft", "run_job")


@pytest.fixture
def driver_command(host_driver, tmp_path):
    """Run the real driver subprocess boundary without starting a VM."""
    cli = tmp_path / "fixture-cli"
    cli.write_text(f"#!{sys.executable}\nimport json, sys\nfrom pathlib import Path\n"
                   "value = json.loads(Path(__file__).with_suffix('.json').read_bytes())\n"
                   "sys.stdout.write(value['stdout'])\nsys.stderr.write(value['stderr'])\n"
                   "sys.exit(value['returncode'])\n")
    cli.chmod(0o700)
    (tmp_path / "hyperlight-adopted.json").write_text('{"engine": {}}')
    instance = host_driver.Instance(SimpleNamespace(root=tmp_path, scratch=tmp_path, cli=cli))

    def run(stdout, returncode, *, expected=None, stderr=""):
        cli.with_suffix(".json").write_text(json.dumps({"stdout": stdout, "returncode": returncode, "stderr": stderr}))
        return instance.run_job("hyperlight", {}, expected_outcome=expected)

    return run


def test_driver_accepts_only_the_explicit_retained_grant_denial(driver_command):
    # Exact nonsecret execution17804/job8 operands supplied in backlog15950.
    # CLI/proxy3dc, protocol3; a reached negative, not complete engine proof.
    retained = json.loads((REPO / "proxy/tests/fixtures/hyperlight-denied-job.json").read_bytes())
    result, status = retained["denied_job_result"], retained["denied_command_status"]["returncode"]
    assert result["outcome"] == {"kind": "exit", "code": 1} and status == 1
    assert result["stdout"]["bytes"] == result["stderr"]["bytes"] == 0
    with pytest.raises(RuntimeError, match="command exit 1"):
        driver_command(json.dumps(result), status)
    assert driver_command(json.dumps(result), status, expected={"kind": "exit", "code": 1}) == result


@pytest.mark.parametrize("control,outcome,status", [
    ("scope probe with a typed denial", {"kind": "exit", "code": 0}, 0),
    ("oversize request", {"kind": "exit", "code": 1}, 1),
    ("deadline", {"kind": "timeout"}, 124),
    ("cancel", {"kind": "interrupted", "signal": int(signal.SIGINT)}, 1),
    ("revoke", {"kind": "interrupted", "signal": int(signal.SIGTERM)}, 1),
    ("shutdown", {"kind": "interrupted", "signal": int(signal.SIGTERM)}, 1),
])
def test_driver_matches_sibling_job_outcomes_and_cli_status(driver_command, control, outcome, status):
    # Synthetic siblings follow jobs::command_status and hyperlight::run;
    # they establish result classification, not a protected execution result.
    result = {"outcome": outcome, "observation_error": None}
    assert driver_command(json.dumps(result), status, expected=outcome) == result, control
    with pytest.raises(RuntimeError, match="command exit"):
        driver_command(json.dumps(result), 0 if status else 1, expected=outcome)


@pytest.mark.parametrize("stdout,status", [
    ("", 1), ("malformed", 1), ('{"outcome":', 1), ("[]", 1), ("{}", 1),
    ('{"outcome":{"kind":"exit","code":0},"observation_error":null}', 1),
    ('{"outcome":{"kind":"exit","code":2},"observation_error":null}', 1),
    ('{"outcome":{"kind":"signal","number":11},"observation_error":null}', 1),
    ('{"outcome":{"kind":"exit","code":1},"observation_error":"incomplete report"}', 1),
    ('{"outcome":{"kind":"exit","code":1}}', 1),
    ('{"outcome":{"kind":"exit","code":1},"observation_error":null}', 0),
    ('{"outcome":{"kind":"exit","code":1},"observation_error":null}', 2),
])
def test_expected_negative_still_rejects_command_and_observation_failures(driver_command, stdout, status):
    with pytest.raises(RuntimeError) as failed:
        driver_command(stdout, status, expected={"kind": "exit", "code": 1}, stderr="retained diagnostic")
    message = str(failed.value)
    assert f"command exit {status}" in message and "retained diagnostic" in message
    assert all(suffix in message for suffix in (".status.json", ".stdout", ".stderr"))


def test_expected_negative_requires_a_retained_json_file(host_driver, tmp_path):
    prefix = tmp_path / "missing"
    prefix.with_suffix(".status.json").write_text('{"returncode": 1}')
    prefix.with_suffix(".stderr").write_text("retained diagnostic")
    with pytest.raises(RuntimeError, match="command exit 1.*retained diagnostic.*job result JSON"):
        host_driver.job_result(prefix, "hyperlight", "revoke", expected_outcome={"kind": "exit", "code": 1})


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


@pytest.mark.parametrize("engine", ["hyperlight", "hyperlight-unikraft"])
def test_held_controls_keep_entry_triggers_late_release_and_fresh_runs(host_driver, tmp_path, monkeypatch, engine):
    """Exercise the observer's four modes; these local controls are not VM proof."""
    origin = SimpleNamespace(entered=threading.Event(), release=threading.Event())
    services = {"held": {"token": "held-secret"}}
    instance = SimpleNamespace(root=tmp_path, policy={"agents": {
        "gate:hyperlight-service-check": {"services": services}}}, proxy=object())
    controls, triggers, fresh = [], [], []
    modes = ("deadline", "cancel", "revoke", "shutdown")

    def trigger(value):
        assert origin.entered.is_set() and not origin.release.is_set()
        triggers.append(value)

    @contextlib.contextmanager
    def job(selected, request, *, probe, timeout):
        mode = modes[len(controls)]
        controls.append(mode)
        assert selected == engine and probe and request["call"]["url"].endswith("/hold")
        # Retained17813 Unikraft totals reached8243ms; entry can take up to20s.
        assert timeout == (5 if engine == "hyperlight" and mode == "deadline" else 30)
        if engine == "hyperlight-unikraft":
            assert timeout * 1000 > 8243 and timeout > 20
        assert not origin.entered.is_set() and not origin.release.is_set()
        origin.entered.set()
        prefix = tmp_path / mode

        def wait(*, timeout):
            assert timeout == 45 and not origin.release.is_set()
            if mode != "deadline":
                assert triggers[-1] == mode

        child = SimpleNamespace(poll=lambda: None, wait=wait,
            send_signal=lambda sig: trigger("cancel") if sig == signal.SIGINT else pytest.fail("wrong signal"))
        yield child, prefix
        assert origin.release.is_set(), "late success must be released after the child stops"
        outcome = ({"kind": "timeout"} if mode == "deadline" else {
            "kind": "interrupted", "signal": int(signal.SIGINT if mode == "cancel" else signal.SIGTERM)})
        prefix.with_suffix(".stdout").write_text(json.dumps({
            "outcome": outcome, "observation_error": None, "service_evidence": [{"response_sha256": None}]}))
        prefix.with_suffix(".stderr").write_text("")
        prefix.with_suffix(".status.json").write_text(json.dumps({"returncode": 124 if mode == "deadline" else 1}))

    def apply():
        if "held" not in services:
            trigger("revoke")
        else:
            assert origin.release.is_set(), "restore standing authority after the interrupted run"

    def run_job(selected, request, *, probe):
        assert selected == engine and probe and request["call"]["url"].endswith("/value")
        assert "held" in services and origin.release.is_set()
        fresh.append(controls[-1])
        payload = b'[{"ok": true}]'
        return {"stdout": {"retained_base64": base64.b64encode(payload).decode(), "bytes": len(payload),
                           "sha256": host_driver.hashlib.sha256(payload).hexdigest()}}

    instance.job, instance.apply, instance.run_job = job, apply, run_job
    monkeypatch.setattr(host_driver, "stop", lambda proxy: trigger("shutdown"))
    host_driver.held_lifetimes(instance, engine, origin, 18451)
    assert controls == list(modes) and triggers == ["cancel", "revoke", "shutdown"]
    assert fresh == ["deadline", "cancel", "revoke"] and "held" in services


@pytest.mark.parametrize("entered,alive", [(False, True), (True, False)])
def test_held_controls_reject_an_unreached_or_finished_call(host_driver, tmp_path, entered, alive):
    triggered = []
    origin = SimpleNamespace(entered=SimpleNamespace(clear=lambda: None, wait=lambda timeout: entered),
                             release=threading.Event())

    @contextlib.contextmanager
    def job(*_args, **_options):
        yield SimpleNamespace(poll=lambda: None if alive else 124,
                              send_signal=lambda sig: triggered.append(sig)), tmp_path / "job"

    with pytest.raises(AssertionError, match="never reached|terminated before"):
        host_driver.held_lifetimes(SimpleNamespace(job=job), "hyperlight-unikraft", origin, 18451)
    assert triggered == [] and not origin.release.is_set()


def test_remaining_window_skips_completed_phases_and_reports_its_actual_scope(host_driver, tmp_path, monkeypatch, capsys):
    args = SimpleNamespace(root=tmp_path / "root", scratch=tmp_path, admin_port=18450,
                           bundle=tmp_path, cli=tmp_path / "cli", proxy=tmp_path / "proxy",
                           unikraft_lifetimes_only=True)
    for name in ("runtime.json", "cli", "proxy"):
        (tmp_path / name).write_text(name)
    calls = []
    instance = SimpleNamespace(prepare=lambda port: calls.append("prepare"))
    monkeypatch.setattr(host_driver, "Instance", lambda actual: instance)
    monkeypatch.setattr(host_driver.subprocess, "Popen", lambda *_args, **_options: object())
    monkeypatch.setattr(host_driver, "wait_ready", lambda *_args: calls.append("ready"))
    monkeypatch.setattr(host_driver, "stop", lambda *_args: calls.append("stop"))

    def held(actual, engine, origin, port):
        assert actual is instance and engine == "hyperlight-unikraft"
        calls.append("held")

    monkeypatch.setattr(host_driver, "held_lifetimes", held)
    host_driver.exercise(args)
    assert calls == ["prepare", "ready", "held", "stop"]
    result = json.loads((tmp_path / "result.json").read_bytes())
    assert result["engines"] == ["hyperlight-unikraft"]
    assert result["checks"] == "held deadline/cancel/revoke/shutdown lifetimes"
    report = capsys.readouterr().out
    assert "hyperlight-unikraft" in report and "live GitHub" not in report and "both" not in report
