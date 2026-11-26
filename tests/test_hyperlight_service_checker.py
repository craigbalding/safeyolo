"""Both guests' predicate uses the existing authoritative GitHub capture."""

import base64
import contextlib
import copy
import errno
import importlib.util
import json
import random
import runpy
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


@pytest.mark.parametrize("constant", ["Infinity", "-Infinity", "NaN"])
def test_non_json_constants_in_capture_are_unavailable(constant):
    data = json.dumps(CAPTURE)[:-1] + ',"value":' + constant + '}'
    with pytest.raises(ValueError, match="invalid JSON constant"):
        checker.service_check(request(), bridge(data.encode()))


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


def test_bundle_keeps_patched_dependency_licenses(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("builder", REPO / "scripts/build_hyperlight_jobs.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    upstream = tmp_path / "registry-dependency"
    upstream.mkdir()
    (upstream / "LICENSE").write_text("registry license")
    patched = REPO / "jobs/hyperlight-host/vendor/hyperlight-host"
    metadata = {"workspace_members": ["root"], "packages": [
        {"id": "root", "source": None},
        {"id": "patched", "source": None, "name": "hyperlight-host", "version": "0.19.0",
         "license": "Apache-2.0", "license_file": None, "manifest_path": str(patched / "Cargo.toml")},
        {"id": "registry", "source": "registry+https://github.com/rust-lang/crates.io-index",
         "name": "other", "version": "1.0.0", "license": "MIT", "license_file": None,
         "manifest_path": str(upstream / "Cargo.toml")},
    ]}
    monkeypatch.setattr(builder.subprocess, "check_output", lambda *args, **kwargs: json.dumps(metadata))
    output = tmp_path / "bundle"
    output.mkdir()
    builder.copy_licenses(REPO, output)
    licenses = output / "licenses"
    for name in ("LICENSE", "NOTICE"):
        assert (licenses / "hyperlight-host-0.19.0" / name).read_bytes() == (patched / name).read_bytes()
    assert (licenses / "other-1.0.0/LICENSE").read_text() == "registry license"
    inventory = json.loads((licenses / "dependencies.json").read_text())
    assert sorted(inventory) == ["hyperlight-host-0.19.0", "other-1.0.0"]
    assert inventory["hyperlight-host-0.19.0"]["license"] == "Apache-2.0"
    assert inventory["hyperlight-host-0.19.0"]["source"] is None


def test_bundle_pins_both_service_checkers_without_changing_offline_examples(tmp_path):
    import hashlib

    spec = importlib.util.spec_from_file_location("builder", REPO / "scripts/build_hyperlight_jobs.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    for name in ("core.elf", "checker.py", "service_checker.py", "artifact_checker.py", "network_checker.py", "task_action_checker.py", "runtime.json"):
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
        artifact = json.loads((tmp_path / f"{kind}-artifact.json").read_text())
        for definition in (offline, service, artifact):
            assert definition["timeout_seconds"] == (5 if kind == "hyperlight" else 15)
            assert definition["max_input_bytes"] == definition["retain_bytes"] == 16384
            assert definition["max_input_entries"] == 16
            assert definition["memory_mb"] == (16 if kind == "hyperlight" else 256)
        assert service["mediated_services"] == {
            "services": ["github"], "max_calls": 4,
            "max_request_bytes": 49152, "max_response_bytes": 1048576,
        }
        assert "mediated_services" not in artifact
        assert artifact["gate_id"] == "hyperlight-artifact-check"
        if kind == "hyperlight":
            assert artifact["engine"]["function"] == "ArtifactCheck"
        else:
            assert artifact["engine"]["checker"]["sha256"] == hashlib.sha256((tmp_path / "artifact_checker.py").read_bytes()).hexdigest()
    task = json.loads((tmp_path / "task-action-check.json").read_text())
    assert task["engine"]["kind"] == "hyperlight-unikraft"
    assert task["engine"]["checker"] == {
        "path": "task_action_checker.py",
        "sha256": hashlib.sha256((tmp_path / "task_action_checker.py").read_bytes()).hexdigest(),
    }
    assert task["network"] is False
    assert task["mediated_services"]["services"] == ["claude"]
    assert task["mediated_services"]["max_calls"] == 1


@pytest.mark.parametrize("case", json.loads((REPO / "proxy/tests/fixtures/hyperlight-author-cases.json").read_bytes()), ids=lambda case: case["name"])
def test_shared_author_and_autonomy_cases(case):
    capture = {**CAPTURE, **case["patch"]}
    value = request()
    if "expected_author_id" in case:
        value["inputs"]["expected_author_id"] = case["expected_author_id"]
    call = bridge(json.dumps(capture).encode())
    if case["outcome"] == "unavailable":
        with pytest.raises((ValueError, KeyError)):
            checker.service_check(value, call)
    else:
        assert checker.service_check(value, call)["finding"]["positive"] is (case["outcome"] == "pass")


@pytest.mark.parametrize("case", json.loads((REPO / "proxy/tests/fixtures/hyperlight-artifact-cases.json").read_bytes()), ids=lambda case: case["name"])
def test_shared_exact_artifact_cases(case):
    spec = importlib.util.spec_from_file_location("artifact_checker", REPO / "jobs/artifact_checker.py")
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    value = {"subject": {"kind": "value", "value": json.dumps({
        "artifact_base64": base64.b64encode(case["artifact"].encode()).decode()})}, "inputs": {"expected_status": "ready"}}
    if case["positive"] is None:
        with pytest.raises((ValueError, KeyError)):
            artifact.artifact_check(value)
    else:
        assert artifact.artifact_check(value)["finding"]["positive"] is case["positive"]


@pytest.mark.parametrize("constant", ["Infinity", "-Infinity", "NaN"])
def test_non_json_constants_in_artifact_subject_are_unavailable(constant):
    spec = importlib.util.spec_from_file_location("artifact_checker", REPO / "jobs/artifact_checker.py")
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    subject = json.dumps({"artifact_base64": base64.b64encode(b'{"status":"ready"}').decode()})
    value = {"subject": {"kind": "value", "value": subject[:-1] + ',"value":' + constant + '}'},
             "inputs": {"expected_status": "ready"}}
    with pytest.raises(ValueError, match="invalid JSON constant"):
        artifact.artifact_check(value)


@pytest.fixture
def host_driver(monkeypatch):
    directory = REPO / "tests/blackbox/host"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("hyperlight_services", directory / "hyperlight_services.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver


def test_resident_memory_reads_a_live_process_and_rejects_a_missing_one(host_driver):
    assert host_driver.resident_bytes(host_driver.os.getpid()) > 0
    with pytest.raises(OSError):
        host_driver.resident_bytes(2147483647)


def test_process_memory_includes_descendants_and_excludes_unrelated_processes(host_driver, monkeypatch):
    monkeypatch.setattr(host_driver.sys, "platform", "linux")
    monkeypatch.setattr(host_driver.subprocess, "check_output", lambda *_args, **_kwargs:
                        "10 1 8\n12 11 32\n11 10 16\n99 1 1024\n")
    sample = host_driver.process_memory([10])
    assert {row["pid"] for row in sample["processes"]} == {10, 11, 12}
    assert sample["rss_sum_bytes"] == (8 + 16 + 32) * 1024


@pytest.fixture
def darwin_observer(host_driver, monkeypatch):
    parents = {10: 1, 11: 10, 12: 11, 99: 1}
    children = {10: [11, 99], 11: [12]}
    capacities = []

    def pidinfo(pid, flavor, argument, destination, size):
        assert flavor == 3 and argument == 0 and size == 136
        if pid not in parents:
            host_driver.ctypes.set_errno(errno.ESRCH)
            return 0
        destination._obj.pid = pid
        destination._obj.parent_pid = parents[pid]
        return size

    def childpids(pid, buffer, size):
        assert size == host_driver.ctypes.sizeof(buffer)
        capacities.append(len(buffer))
        selected = children.get(pid, [])[:len(buffer)]
        for index, child in enumerate(selected):
            buffer[index] = child
        return len(selected)

    library = SimpleNamespace(proc_pidinfo=pidinfo, proc_listchildpids=childpids)
    monkeypatch.setattr(host_driver.sys, "platform", "darwin")
    monkeypatch.setattr(host_driver.ctypes, "CDLL", lambda *_args, **_kwargs: library)
    monkeypatch.setattr(host_driver, "resident_bytes", lambda pid: pid * 1024)
    return SimpleNamespace(driver=host_driver, library=library, parents=parents,
                           children=children, capacities=capacities)


def test_darwin_memory_aggregates_descendants_counts_pids_and_grows_full_buffers(darwin_observer):
    probe = darwin_observer
    probe.parents.update(dict.fromkeys(range(20, 60), 10))
    probe.children[10].extend(range(20, 60))
    # Overlapping roots count once; 99 was reparented before its metadata read.
    sample = probe.driver.process_memory([10, 11, 500])
    expected = {10, 11, 12, *range(20, 60)}
    assert {row["pid"] for row in sample["processes"]} == expected
    assert sample["rss_sum_bytes"] == sum(expected) * 1024
    assert 32 in probe.capacities and 64 in probe.capacities


@pytest.mark.parametrize("phase", ["metadata", "resident", "children"])
def test_darwin_memory_omits_processes_that_disappear_during_sampling(darwin_observer, monkeypatch, phase):
    probe = darwin_observer

    def missing(*_args):
        probe.driver.ctypes.set_errno(errno.ESRCH)
        return 0

    if phase == "metadata":
        monkeypatch.setattr(probe.library, "proc_pidinfo", missing)
    elif phase == "children":
        monkeypatch.setattr(probe.library, "proc_listchildpids", missing)
    else:
        def missing_rss(_pid):
            raise ProcessLookupError(errno.ESRCH, "exited during sampling")
        monkeypatch.setattr(probe.driver, "resident_bytes", missing_rss)
    sample = probe.driver.process_memory([10])
    assert sample["processes"] == [] and sample["rss_sum_bytes"] == 0


@pytest.mark.parametrize("phase", ["metadata", "short_metadata", "resident", "children"])
def test_darwin_memory_preserves_denied_or_incomplete_observations(darwin_observer, monkeypatch, phase):
    probe = darwin_observer

    def refused(*_args):
        probe.driver.ctypes.set_errno(0 if phase == "short_metadata" else errno.EPERM)
        return 135 if phase == "short_metadata" else 0

    if phase in {"metadata", "short_metadata"}:
        monkeypatch.setattr(probe.library, "proc_pidinfo", refused)
    elif phase == "children":
        monkeypatch.setattr(probe.library, "proc_listchildpids", refused)
    else:
        def refused_rss(_pid):
            raise PermissionError(errno.EPERM, "RSS denied")
        monkeypatch.setattr(probe.driver, "resident_bytes", refused_rss)
    with pytest.raises(OSError):
        probe.driver.process_memory([10])


def test_darwin_process_enumeration_keeps_the_existing_five_second_bound(darwin_observer, monkeypatch):
    probe = darwin_observer
    monkeypatch.setattr(probe.library, "proc_listchildpids", lambda _pid, buffer, _size: len(buffer))
    times = iter([0, 6])
    with monkeypatch.context() as context:
        context.setattr(probe.driver.time, "monotonic", lambda: next(times))
        with pytest.raises(TimeoutError):
            probe.driver.darwin_children(probe.library, 10, 5)


def test_job_memory_retains_live_processes_and_samples_idle_after_reaping(host_driver, tmp_path):
    # The same standalone command is runnable by the confined consumer without
    # installing pytest or starting the Hyperlight product.
    result = host_driver.subprocess.run(
        [sys.executable, str(REPO / "tests/blackbox/host/hyperlight_memory_probe.py"),
         "--output", str(tmp_path / "job")], capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["native_vm_executed"] is False
    assert observed["sample"]["sample_count"] > 0


def test_job_memory_preserves_failed_observation_without_claiming_zero_memory(host_driver, tmp_path, monkeypatch):
    def denied(_roots):
        raise PermissionError("process observation denied")
    monkeypatch.setattr(host_driver, "process_memory", denied)
    child = SimpleNamespace(pid=123, poll=lambda: None)
    with host_driver.sample_job_memory(child, child, tmp_path / "job"):
        pass
    sample = json.loads((tmp_path / "job.memory.json").read_bytes())
    assert sample["error"] == "process observation denied"
    assert sample["peak"] is sample["idle"] is None and sample["sample_count"] == 0


@pytest.mark.parametrize("console", ["missing", "other", "wrong", "exited"])
def test_spin_observer_rejects_missing_or_other_invocation_entry(host_driver, tmp_path, console):
    prefix = tmp_path / "current"
    if console == "other":
        (tmp_path / "previous.console").write_bytes(b"template-spin-entered\n")
    elif console == "wrong":
        prefix.with_suffix(".console").write_bytes(b"initializing\n")
    elif console == "exited":
        prefix.with_suffix(".console").write_bytes(b"template-spin-entered\n")
    child = host_driver.subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        if console == "exited":
            host_driver.stop(child)
        with pytest.raises(RuntimeError, match="spin entry"):
            host_driver.wait_spin_entry(child, prefix, timeout=0.05)
        if console != "exited":
            assert child.poll() is None
    finally:
        host_driver.stop(child)


def test_spin_observer_waits_for_the_current_live_marker(host_driver, tmp_path):
    prefix = tmp_path / "current"
    program = ("import pathlib, sys, time; "
               "p = pathlib.Path(sys.argv[1]); p.write_bytes(b'template-'); time.sleep(.05); "
               "p.write_bytes(b'template-spin-entered\\n'); time.sleep(10)")
    child = host_driver.subprocess.Popen([sys.executable, "-c", program, str(prefix.with_suffix(".console"))])
    try:
        host_driver.wait_spin_entry(child, prefix, timeout=2)
        assert child.poll() is None
    finally:
        host_driver.stop(child)


@pytest.mark.parametrize("inherited", [False, True])
def test_template_probe_compares_frozen_generator_state_before_drawing(
        tmp_path, monkeypatch, capsys, inherited):
    import builtins

    (tmp_path / "request.json").write_text("{}")
    monkeypatch.setattr(builtins, "_sy_initialized_ns", 123, raising=False)
    state = random.getstate() if inherited else random.Random().getstate()
    monkeypatch.setattr(builtins, "_sy_initialized_random_state", state, raising=False)
    monkeypatch.setattr(builtins, "_sy_probe_calls", 0, raising=False)
    monkeypatch.setenv("SY_INVOCATION_ID", "current-invocation")
    monkeypatch.setenv("SY_DEADLINE_MONOTONIC_MS", "1234")
    paths = {"/input/request.json": tmp_path / "request.json",
             "/work/prior-invocation": tmp_path / "prior-invocation"}
    with monkeypatch.context() as path_patch:
        path_patch.setattr("pathlib.Path", lambda path: paths[path])
        runpy.run_path(str(REPO / "jobs/template_probe.py"))
    value = json.loads(capsys.readouterr().out)
    assert value["initialized_random_state_inherited"] is inherited
    assert value["calls"] == 1 and not value["inherited_file"]
    assert value["context"]["invocation_id"] == "current-invocation"


@pytest.mark.parametrize("unavailable_memory", [False, True])
@pytest.mark.parametrize("replayed", ["runtime_random", "initialized_random_state"])
def test_warm_probe_rejects_replayed_runtime_randomness_and_preserves_samples(
        host_driver, tmp_path, monkeypatch, unavailable_memory, replayed):
    (tmp_path / "hyperlight-unikraft.json").write_text(json.dumps({"engine": {}}))
    (tmp_path / "template_probe.py").write_text("probe")
    instance = SimpleNamespace(args=SimpleNamespace(bundle=tmp_path), scratch=tmp_path,
                               proxy=SimpleNamespace(pid=host_driver.os.getpid()))
    results = []

    @contextlib.contextmanager
    def job(engine, request, **options):
        index = len(results)
        run_id = f"run-{index}"
        payload = json.dumps({"calls": 1, "input": list(request["value"].encode()), "initialized_at": 42,
                              "initialized_random_state_inherited": replayed == "initialized_random_state" and index > 0,
                              "context": {"invocation_id": run_id, "unix_ms": 100,
                                          "random": [index], "runtime_random": 0.25 if replayed == "runtime_random" else index}}).encode()
        result = {"outcome": {"kind": "exit", "code": 0}, "observation_error": None,
                  "run_id": run_id, "started_unix_ms": 99, "ended_unix_ms": 101,
                  "stdout": {"bytes": len(payload), "retained_base64": base64.b64encode(payload).decode(),
                             "sha256": host_driver.hashlib.sha256(payload).hexdigest()},
                  "runtime_report": {"initialization": {
                      "mode": "constructed" if index == 0 else "restored", "initialization_events": 1 - index,
                      "template_key": "same-template", "snapshot_digest": "sha256:" + "a" * 64}}}
        results.append(result)
        prefix = tmp_path / run_id
        yield SimpleNamespace(wait=lambda **_: None, returncode=0), prefix
        prefix.with_suffix(".stdout").write_text(json.dumps(result))
        prefix.with_suffix(".stderr").write_text("")
        prefix.with_suffix(".status.json").write_text(json.dumps({"returncode": 0, "command_wall_ms": 10}))

    instance.job = job
    if unavailable_memory:
        def refused(_pid):
            raise PermissionError("memory sample refused")
        monkeypatch.setattr(host_driver, "resident_bytes", refused)
    with pytest.raises(AssertionError):
        host_driver.warm_templates(instance, "hyperlight-unikraft")
    assert len(results) == 2
    retained = json.loads((tmp_path / "hyperlight-unikraft-templates.json").read_bytes())
    assert "idle_worker_bytes" not in retained
    samples = retained["observations"]
    assert len(samples) == 2
    for sample in samples:
        if unavailable_memory:
            assert sample["idle_proxy_rss_bytes"] is None
            assert sample["memory_observation_error"] == "memory sample refused"
        else:
            assert sample["idle_proxy_rss_bytes"] > 0
            assert sample["memory_observation_error"] is None


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
                   "import argparse\nparser = argparse.ArgumentParser()\n"
                   "parser.add_argument('--instance-dir', required=True)\n"
                   "parser.add_argument('--json', action='store_true')\n"
                   "options, arguments = parser.parse_known_args()\n"
                   "value = json.loads(Path(__file__).with_suffix('.json').read_bytes())\n"
                   "sys.stdout.write(value['stdout'] if options.json else 'Human job summary\\n')\n"
                   "sys.stderr.write(value['stderr'])\n"
                   "sys.exit(value['returncode'])\n")
    cli.chmod(0o700)
    (tmp_path / "hyperlight-adopted.json").write_text('{"engine": {}}')
    instance = host_driver.Instance(SimpleNamespace(root=tmp_path, scratch=tmp_path, cli=cli))

    def run(stdout, returncode, *, expected=None, stderr=""):
        cli.with_suffix(".json").write_text(json.dumps({"stdout": stdout, "returncode": returncode, "stderr": stderr}))
        return instance.run_job("hyperlight", {}, expected_outcome=expected)

    return run


def test_driver_policy_preview_selects_machine_output(host_driver, tmp_path):
    cli = tmp_path / "fixture-cli"
    cli.write_text(f"#!{sys.executable}\nimport argparse, json\n"
                   "parser = argparse.ArgumentParser()\n"
                   "parser.add_argument('--instance-dir', required=True)\n"
                   "parser.add_argument('--json', action='store_true')\n"
                   "options, arguments = parser.parse_known_args()\n"
                   "print(json.dumps({'status': 'preview'}) if options.json else 'Policy preview')\n")
    cli.chmod(0o700)
    instance = host_driver.Instance(SimpleNamespace(root=tmp_path, scratch=tmp_path, cli=cli))
    result = instance.command("policy", "evaluate", str(tmp_path / "policy.toml"), str(tmp_path / "scenario.json"))
    assert json.loads(result.stdout) == {"status": "preview"}


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


def test_capture_observer_requires_the_selected_current_principal(host_driver, host_capture):
    principal = "gate:hyperlight-template-other"
    with pytest.raises(AssertionError):
        host_driver.captured(host_capture, principal)
    host_capture["gate_principal"] = principal
    with pytest.raises(AssertionError):
        host_driver.captured(host_capture, principal)
    host_capture["authorization_principal"] = principal
    assert host_driver.captured(host_capture, principal) == host_capture["service_evidence"]


@pytest.mark.parametrize("engine", ["hyperlight", "hyperlight-unikraft"])
@pytest.mark.parametrize("defect", [None, "engine", "kind", "runtime_manifest_sha256", "artifact_sha256"])
def test_engine_observer_matches_selected_engine_and_artifact_pins(host_driver, host_capture, tmp_path, engine, defect):
    host_capture["engine"] = host_capture["rootfs"]["kind"] = engine
    selected = {"runtime": {"sha256": "a" * 64},
                "guest" if engine == "hyperlight" else "checker": {"sha256": "b" * 64}}
    path = tmp_path / "adopted.json"
    path.write_text(json.dumps({"engine": selected}))
    if defect:
        (host_capture if defect == "engine" else host_capture["rootfs"])[defect] = "wrong"
        with pytest.raises(AssertionError):
            host_driver.check_engine_identity(host_capture, engine, path)
    else:
        host_driver.check_engine_identity(host_capture, engine, path)


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

    for leak in ("retained_base64", "request_body_base64", "checked_input"):
        changed = copy.deepcopy(named)
        execution = changed["evidence"]["execution"]
        if leak == "checked_input":
            execution[leak] = {"content_base64": "private-snapshot"}
        else:
            # The old observer inspected only the first capture.
            execution["service_evidence"].append({leak: "private-provider-data"})
        with pytest.raises(AssertionError):
            host_driver.check_named_evidence(first, changed, path, subject)

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


@pytest.mark.parametrize("remaining_state,boundaries", [(False, False), (True, False), (False, True)])
def test_remaining_window_skips_completed_phases_and_reports_its_actual_scope(
        host_driver, tmp_path, monkeypatch, capsys, remaining_state, boundaries):
    args = SimpleNamespace(root=tmp_path / "root", scratch=tmp_path, admin_port=18450,
                           bundle=tmp_path, cli=tmp_path / "cli", proxy=tmp_path / "proxy",
                           unikraft_lifetimes_only=not remaining_state and not boundaries,
                           unikraft_remaining_only=remaining_state, template_boundaries_only=boundaries,
                           warm_templates_only=False, provider_port=0)
    for name in ("runtime.json", "cli", "proxy"):
        (tmp_path / name).write_text(name)
    calls = []
    instance = SimpleNamespace(prepare=lambda port: calls.append("prepare"))
    monkeypatch.setattr(host_driver, "Instance", lambda actual: instance)
    monkeypatch.setattr(host_driver.subprocess, "Popen", lambda *_args, **_options: object())
    monkeypatch.setattr(host_driver, "wait_ready", lambda *_args: calls.append("ready"))
    monkeypatch.setattr(host_driver, "stop", lambda *_args: calls.append("stop"))

    def warm(actual, engine, *, remaining_only):
        assert actual is instance and engine == "hyperlight-unikraft" and remaining_only
        calls.append("state")
        return []

    monkeypatch.setattr(host_driver, "warm_templates", warm)
    monkeypatch.setattr(host_driver, "template_comparison", lambda actual, engine: calls.append(engine + " comparison"))
    monkeypatch.setattr(host_driver, "template_authority", lambda actual, engine, origin, port: calls.append(engine + " authority"))
    monkeypatch.setattr(host_driver, "template_cache", lambda actual: {"entries": []})
    def held(actual, engine, origin, port):
        assert actual is instance and engine == "hyperlight-unikraft"
        calls.append("held")

    monkeypatch.setattr(host_driver, "held_lifetimes", held)
    host_driver.exercise(args)
    if boundaries:
        assert calls == ["prepare", "ready", "hyperlight comparison", "hyperlight authority", "stop",
                         "ready", "hyperlight-unikraft comparison", "hyperlight-unikraft authority", "stop"]
    else:
        assert calls == ["prepare", "ready", *(["state"] if remaining_state else []), "held", "stop"]
    result = json.loads((tmp_path / "result.json").read_bytes())
    assert result["engines"] == (["hyperlight", "hyperlight-unikraft"] if boundaries else ["hyperlight-unikraft"])
    assert result["checks"] == ("template authority, equivalent comparisons, capacity, expiry and shutdown" if boundaries else
                                "remaining Unikraft state and held-call lifetimes" if remaining_state
                                else "held deadline/cancel/revoke/shutdown lifetimes")
    report = capsys.readouterr().out
    assert "hyperlight-unikraft" in report and "live GitHub" not in report and "both" not in report
