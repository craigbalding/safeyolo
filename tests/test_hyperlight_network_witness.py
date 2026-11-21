"""The HTTP witness keeps typed denial separate from failed execution and reuse."""

import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import os
import runpy
import shlex
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import tomlkit

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def witness(monkeypatch):
    directory = REPO / "tests/blackbox/host"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("hyperlight_network", directory / "hyperlight_network.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def partial():
    # Exact nonsecret Bristol receipt supplied by canonical operator16385.
    # This records three completed Core calls and no Unikraft execution.
    return json.loads((REPO / "tests/fixtures/hyperlight-http-partial.json").read_bytes())


def test_witness_accepts_the_reached_core_findings(witness, partial):
    witness.check_direct(partial["direct_allowed"], True)
    witness.check_direct(partial["direct_after_permission_removal"], False)
    named = partial["named_allowed"]
    witness.check_named(named["status"], named["body"], True)


@pytest.mark.parametrize(("https", "deny", "wrong_host"), [
    (False, False, False), (False, True, False), (True, False, False),
    (True, True, False), (True, False, True)])
def test_platform_client_uses_only_selected_proxy_and_strict_guest_tls(witness, tmp_path, https, deny, wrong_host):
    from tests.test_hyperlight_proxy_client import ProxyBytes, certificates

    ca, context = certificates(tmp_path, host="wrong.test" if wrong_host else "example.test")
    (tmp_path / "ca.pem").write_text(ca)
    bridge = ProxyBytes(ca, context, https=https, deny=deny)
    url = f"{'https' if https else 'http'}://example.test/value?x=1#private"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(8)
        thread = threading.Thread(target=lambda: bridge.origin(listener.accept()[0]))
        thread.start()
        try:
            # Only the writable output mount path changes for this CPU control.
            program = witness.PLATFORM_CHECKER.replace('/work/response', shlex.quote(str(tmp_path / 'response')))
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", program, "network-check", url],
                capture_output=True, timeout=8,
                env={**os.environ, "HTTP_PROXY": f"http://127.0.0.1:{listener.getsockname()[1]}",
                     "SSL_CERT_FILE": str(tmp_path / "ca.pem")})
        finally:
            thread.join(9)
            assert not thread.is_alive()
    if https and (deny or wrong_host):
        assert result.returncode != 0 and not result.stdout, result
        assert not bridge.requests
        assert (b"403" if deny else b"SSL") in result.stderr
        # Feed the real guest exit through both observers instead of substituting
        # the CLI's status 1 for curl's own status. This is CPU/client proof.
        for engine in ("gvisor", "vz"):
            execution = {"engine": engine, "outcome": {"kind": "exit", "code": result.returncode},
                         "outcome_source": "guest_process", "rootfs": {"profile": "shared"},
                         "observation_error": None, "gate_principal": "gate:hyperlight-network-check",
                         "authorization_principal": "gate:hyperlight-network-check", "service_evidence": []}
            prefix = tmp_path / engine
            prefix.with_suffix(".status.json").write_text(json.dumps({"returncode": 1}))
            prefix.with_suffix(".stdout").write_text(json.dumps(execution))
            prefix.with_suffix(".stderr").write_text("")
            observed = witness.job_result(prefix, engine, "tls-refusal", expected_outcome={"kind": "exit", "code": 1})
            witness.check_failed_tls(observed)
    else:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"finding": {"kind": "finding", "positive": not deny}}
        assert len(bridge.requests) == 1
        expected = b"GET /value?x=1 " if https else b"GET http://example.test/value?x=1 "
        assert bridge.requests[0].startswith(expected)
        assert b"#private" not in bridge.requests[0]
        assert b"Authorization:" not in bridge.requests[0]


@pytest.mark.parametrize("client", ["platform", "unikraft"])
@pytest.mark.parametrize("allowed", [False, True])
def test_redirect_clients_actually_follow_one_location(witness, tmp_path, monkeypatch, capsys, client, allowed):
    from tests.test_hyperlight_proxy_client import ProxyBytes, head

    class RedirectProxy(ProxyBytes):
        def respond(self, stream):
            request = head(stream)
            self.requests.append(request)
            if request.startswith(b"GET http://example.test/start "):
                response = b"302 Found\r\nLocation: http://other.test/target"
            else:
                assert request.startswith(b"GET http://other.test/target "), request
                response = b"200 OK" if allowed else b"403 Forbidden"
            stream.sendall(b"HTTP/1.1 " + response + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

    bridge = RedirectProxy("", None, https=False)
    try:
        if client == "unikraft":
            module_spec = importlib.util.spec_from_file_location("redirect_client", REPO / "jobs/proxy_client.py")
            module = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(module)
            monkeypatch.setitem(sys.modules, "hyperlight", SimpleNamespace(call=lambda _name, value: bridge.reply(value)))
            monkeypatch.setitem(sys.modules, "safeyolo_proxy", module)
            request = tmp_path / "request.json"
            request.write_text(json.dumps({"subject": {"value": "http://example.test/start"}}))
            checker = tmp_path / "checker.py"
            checker.write_text(witness.UNIKRAFT_REDIRECT_CHECKER.replace("/input/request.json", str(request)))
            runpy.run_path(str(checker))
            result = json.loads(capsys.readouterr().out)
        else:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(5)

                def serve():
                    for _ in range(2):
                        bridge.origin(listener.accept()[0])

                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    program = witness.PLATFORM_REDIRECT_CHECKER.replace('/work/response', shlex.quote(str(tmp_path / 'response')))
                    completed = subprocess.run(["bash", "-euo", "pipefail", "-c", program,
                                                "redirect-check", "http://example.test/start"],
                        capture_output=True, timeout=8,
                        env={**os.environ, "HTTP_PROXY": f"http://127.0.0.1:{listener.getsockname()[1]}",
                             "SSL_CERT_FILE": str(tmp_path / "ca.pem")})
                    assert completed.returncode == 0, completed.stderr
                    result = json.loads(completed.stdout)
                finally:
                    thread.join(6)
                    assert not thread.is_alive()
        assert result == {"finding": {"kind": "finding", "positive": allowed}}
        assert len(bridge.requests) == 2 and not bridge.errors
        assert not bridge.streams
    finally:
        bridge.close()


def test_redirect_origin_serves_the_target_without_another_redirect(witness, tmp_path):
    with witness.ThreadingHTTPServer(("127.0.0.1", 0), witness.NetworkOrigin) as origin:
        origin.contacts, origin.contacts_path = [], tmp_path / "contacts.json"
        origin.redirect, origin.held, origin.redirect_target = True, None, "/redirected/engine"
        origin.redirect_location = f"http://localhost:{origin.server_port}{origin.redirect_target}"
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", origin.server_port, timeout=3)
            try:
                for path, status in (("/engine", 302), (origin.redirect_target, 200)):
                    connection.request("GET", path)
                    response = connection.getresponse()
                    assert response.status == status
                    if status == 302:
                        assert response.getheader("Location") == origin.redirect_location
                    response.read()
            finally:
                connection.close()
        finally:
            origin.shutdown()
            thread.join(5)
            assert not thread.is_alive()
    assert origin.contacts == [{"path": "/engine"}, {"path": "/redirected/engine"}]


@pytest.mark.parametrize("defect", [None, "no_second_request", "allowed_second_request", "wrong_run", "wrong_gate", "wrong_host"])
def test_redirect_refusal_requires_the_second_exact_run_proxy_observation(witness, defect):
    identity = {"trusted_transport_identity": "owned-run", "attribution_provenance": {
        "authorization_principal": "gate:hyperlight-network-check"}}
    rows = [{"event": "traffic.request_outcome", "details": {
        "host": host, "port": 12345, "status": status, "decision": decision, "attribution": copy.deepcopy(identity)}}
        for host, status, decision in (("127.0.0.1", 302, "allow"), ("localhost", 403, "deny"))]
    results = {"engine": {"destination": {"target_host": "localhost", "denied": {
        "direct": {"run_id": "owned-run"}, "named": {"evidence": {"execution": {"run_id": "owned-run"}}}}}}}
    if defect == "no_second_request":
        rows.pop()
    elif defect == "allowed_second_request":
        rows[1]["details"].update(status=200, decision="allow")
    elif defect == "wrong_run":
        rows[1]["details"]["attribution"]["trusted_transport_identity"] = "old-run"
    elif defect == "wrong_gate":
        rows[1]["details"]["attribution"]["attribution_provenance"]["authorization_principal"] = "gate:other"
    elif defect == "wrong_host":
        rows[1]["details"]["host"] = "another.test"
    if defect:
        with pytest.raises(AssertionError):
            witness.check_redirect_audit(rows, results, 12345)
    else:
        witness.check_redirect_audit(rows, results, 12345)


@pytest.mark.parametrize("defect", [None, "no_follow", "target_contact", "wrong_engine"])
def test_redirect_witness_pairs_permitted_follows_with_contact_free_target_refusal(witness, partial, tmp_path, defect):
    contacts = []
    origin = SimpleNamespace(redirect=False)
    original = {"hosts": {}, "agents": {}}

    class Instance:
        args = SimpleNamespace(upstream_port=12345)
        scratch = tmp_path

        def __init__(self):
            self.policy = copy.deepcopy(original)

        def command(self, *_args):
            pass  # Native validation is observed only in the installed procedure.

        def apply(self):
            pass  # This control selects the adapter's current policy below.

        def result(self):
            allowed = len(self.policy["permissions"]) == 3
            contacts.append({"path": "/hyperlight-unikraft"})
            if defect == "target_contact" or allowed and defect != "no_follow":
                contacts.append({"path": "/redirected/hyperlight-unikraft"})
            result = copy.deepcopy(partial["direct_allowed" if allowed else "direct_after_permission_removal"])
            result["engine"] = "wrong" if defect == "wrong_engine" else "hyperlight-unikraft"
            return result

        def run_job(self, *_args):
            return self.result()

        def invoke(self, *_args):
            direct = self.result()
            named = copy.deepcopy(partial["named_allowed"]["body"])
            named["evidence"]["result"]["finding"] = witness.output(direct)["finding"]
            named["evidence"]["execution"]["engine"] = direct["engine"]
            return 200, named

    instance = Instance()
    if defect:
        with pytest.raises(AssertionError):
            witness.redirect_cases(instance, "hyperlight-unikraft", contacts, origin)
    else:
        result = witness.redirect_cases(instance, "hyperlight-unikraft", contacts, origin)
        assert len(contacts) == 12 and set(result) == {"path", "destination"}
    assert instance.policy == original and not origin.redirect and not hasattr(origin, "redirect_location")


@pytest.mark.parametrize("defect", [None, "denied_contact", "path_positive", "other_engine"])
def test_scope_witness_requires_negative_findings_zero_denied_contacts_and_selected_engine(
        witness, partial, tmp_path, monkeypatch, defect):
    contacts = []
    origin = SimpleNamespace(redirect=False)
    original = {"hosts": {"*": {"egress": "deny"}}, "agents": {}, "checks": {}}
    (tmp_path / "hyperlight-adopted.json").write_text("{}")
    findings = iter([True, True, False, False, False, False, False, False, False, False])

    class Instance:
        args = SimpleNamespace(upstream_port=12345)
        scratch = tmp_path

        def __init__(self):
            self.policy = copy.deepcopy(original)
            self.calls = 0

        def command(self, *_args):
            pass  # This control tests witness assertions, not native validation.

        def apply(self):
            if "permissions" in self.policy:
                assert "hosts" not in self.policy and "agents" not in self.policy

        def finding(self, request):
            expected = next(findings)
            self.calls += 1
            url = request["subject"]["value"]
            if expected or origin.redirect or defect == "denied_contact":
                contacts.append({"path": urlsplit(url).path})
            if defect == "path_positive" and self.calls in (5, 6):
                return True
            return expected

        def run_job(self, engine, request):
            positive = self.finding(request)
            result = copy.deepcopy(partial["direct_allowed" if positive else "direct_after_permission_removal"])
            if defect == "other_engine":
                result["engine"] = "hyperlight-unikraft"
            return result

        def invoke(self, engine, request):
            value = copy.deepcopy(partial["named_allowed"]["body"])
            value["evidence"]["result"]["finding"]["positive"] = self.finding(request)
            return 200, value

    monkeypatch.setattr(witness, "cache_expiry_and_gate_separation", lambda *_args: {"separate_control": True})
    instance = Instance()
    if defect:
        with pytest.raises(AssertionError):
            witness.scope_cases(instance, "hyperlight", contacts, origin)
    else:
        result = witness.scope_cases(instance, "hyperlight", contacts, origin)
        assert len(contacts) == 4 and len(result) == 6
        redirected = result["http-302-no-follow"]
        assert redirected["named"]["evidence"]["result"]["finding"]["positive"] is False
        assert "No redirected second request was attempted" in redirected["evidence_scope"]
    assert instance.policy == original


@pytest.mark.parametrize("defect", [None, "expired_cached", "expired_run", "wrong_gate", "borrowed_positive", "denied_contact"])
def test_cache_witness_requires_expiry_and_separate_adopted_gate_evidence(
        witness, partial, tmp_path, monkeypatch, defect):
    contacts, calls, activations = [], [], []
    original = {"checks": {"hyperlight": {"source": {"spec": "owned.json", "limits": {}}}}}
    (tmp_path / "hyperlight-adopted.json").write_text('{"gate_id":"hyperlight-network-check"}')
    monkeypatch.setattr(witness.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(witness.time, "time", lambda: 100)

    class Instance:
        args = SimpleNamespace(upstream_port=12345)
        scratch = tmp_path

        def __init__(self):
            self.policy = copy.deepcopy(original)

        def apply(self):
            activations.append(copy.deepcopy(self.policy))

        def invoke(self, name, request):
            calls.append((name, request))
            index = len(calls)
            value = copy.deepcopy(partial["named_allowed"]["body"])
            evidence = value["evidence"]
            evidence["acquisition"] = "reused_live_evidence" if index == 2 else "live"
            evidence["execution"]["run_id"] = "owned-1" if index <= 2 else f"owned-{index}"
            evidence["result"]["collected_at_ms"] = 1000 if index <= 2 else 2100
            if index in (1, 3):
                contacts.append(request["subject"])
            if index == 3:
                if defect == "expired_cached":
                    evidence["acquisition"] = "reused_live_evidence"
                if defect == "expired_run":
                    evidence["execution"]["run_id"] = "owned-1"
            if index == 4:
                assert name == "hyperlight-other-gate"
                evidence["execution"].update(gate_principal="gate:network-other-gate",
                    authorization_principal="gate:network-other-gate")
                evidence["result"]["finding"]["positive"] = defect == "borrowed_positive"
                if defect == "wrong_gate":
                    evidence["execution"]["authorization_principal"] = "gate:hyperlight-network-check"
                if defect == "denied_contact":
                    contacts.append(request["subject"])
            return 200, value

    instance = Instance()
    if defect:
        with pytest.raises(AssertionError):
            witness.cache_expiry_and_gate_separation(instance, "hyperlight", contacts)
    else:
        result = witness.cache_expiry_and_gate_separation(instance, "hyperlight", contacts)
        assert len(calls) == 4 and len(contacts) == 2 and len(result) == 4
    assert instance.policy == original and len(activations) == 2
    spec = json.loads((tmp_path / "hyperlight-other-gate-adopted.json").read_bytes())
    assert spec["gate_id"] == "network-other-gate"


@pytest.mark.parametrize("engine", ["gvisor", "vz", "hyperlight", "hyperlight-unikraft"])
@pytest.mark.parametrize("mode", ["scope", "caller_only", "redirect"])
def test_shared_modes_do_not_replay_completed_cases(witness, monkeypatch, engine, mode):
    args = SimpleNamespace(scope=mode == "scope", caller_only=mode == "caller_only",
                           authority=False, lifetimes_only=False, redirect=mode == "redirect")
    calls = []

    def selected(_instance, selected_engine, *_args):
        calls.append(selected_engine)
        return {"selected": mode}

    def unselected(*_args):
        pytest.fail("a completed or unselected case was replayed")

    monkeypatch.setattr(witness, "scope_cases", selected if mode == "scope" else unselected)
    monkeypatch.setattr(witness, "redirect_cases", selected if mode == "redirect" else unselected)
    monkeypatch.setattr(witness, "authority_cases", selected if mode == "caller_only" else unselected)
    monkeypatch.setattr(witness, "exercise_lifetimes", unselected)
    result = witness.exercise_engine(SimpleNamespace(args=args), engine, [], False, None)
    assert calls == [engine]
    assert result == ({"authority": {"selected": mode}} if mode == "caller_only" else {"selected": mode})


@pytest.mark.parametrize("defect", ["exit", "observation", "missing", "malformed", "truncated", "hash", "integer", "positive"])
def test_direct_denial_requires_a_complete_typed_result(witness, partial, defect):
    result = partial["direct_after_permission_removal"]
    if defect == "exit":
        result["outcome"]["code"] = 1
    elif defect == "observation":
        result["observation_error"] = "cleanup failed"
    elif defect in {"missing", "malformed", "integer", "positive"}:
        data = {"missing": b"{}", "malformed": b"not JSON",
                "integer": b'{"finding":{"kind":"finding","positive":0}}',
                "positive": b'{"finding":{"kind":"finding","positive":true}}'}[defect]
        result["stdout"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                            "retained_base64": base64.b64encode(data).decode()}
    elif defect == "truncated":
        result["stdout"]["bytes"] += 1
    else:
        result["stdout"]["sha256"] = "0" * 64
    with pytest.raises((AssertionError, KeyError, json.JSONDecodeError)):
        witness.check_direct(result, False)


@pytest.mark.parametrize("defect", [None, "exit", "observation", "unavailable", "missing", "integer", "status", "positive"])
def test_named_denial_requires_a_negative_finding(witness, partial, defect):
    named = partial["named_allowed"]
    evidence = named["body"]["evidence"]
    evidence["result"]["finding"]["positive"] = False
    if defect == "exit":
        evidence["execution"]["outcome"]["code"] = 1
    elif defect == "observation":
        evidence["execution"]["observation_error"] = "incomplete result"
    elif defect == "unavailable":
        evidence["unavailable"] = "job execution failed or unavailable observation"
    elif defect == "missing":
        evidence["result"] = None
    elif defect == "integer":
        evidence["result"]["finding"]["positive"] = 0
    elif defect == "status":
        named["status"] = 500
    elif defect == "positive":
        evidence["result"]["finding"]["positive"] = True
    if defect is None:
        witness.check_named(named["status"], named["body"], False)
    else:
        with pytest.raises((AssertionError, TypeError)):
            witness.check_named(named["status"], named["body"], False)


@pytest.mark.parametrize("defect", [None, "outcome", "observation", "cause", "completion", "principal", "source"])
def test_tls_failure_requires_an_observed_guest_error(witness, partial, defect):
    execution = partial["direct_allowed"]
    execution.update(outcome={"kind": "exit", "code": 1}, outcome_source="host_helper",
                     runtime_report={"completion": None, "error": "the call failed in the guest with status 1 (see its output)"})
    if defect == "outcome":
        execution["outcome"] = {"kind": "timeout"}
    elif defect == "observation":
        execution["observation_error"] = "missing helper report"
    elif defect == "cause":
        execution["runtime_report"]["error"] = None
    elif defect == "completion":
        execution["runtime_report"]["completion"] = {"kind": "guest_function_returned"}
    elif defect == "principal":
        execution["authorization_principal"] = "gate:other"
    elif defect == "source":
        execution["outcome_source"] = "host_watchdog"
    if defect:
        with pytest.raises(AssertionError):
            witness.check_failed_tls(execution)
    else:
        witness.check_failed_tls(execution)


def connect_denial(run, port):
    # Current http.rs::request_outcome + lib.rs::audit_attribution producer.
    return {"event": "traffic.request_outcome", "details": {
        "status": 403, "decision": "deny", "host": "127.0.0.1", "port": port,
        "coverage": "native_network_guard_only", "attribution": {
            "trusted_transport_identity": run,
            "attribution_provenance": {"authorization_principal": "gate:hyperlight-network-check"}}}}


@pytest.mark.parametrize("defect", [None, "event", "status", "decision", "host", "port", "coverage", "run", "gate"])
def test_tls_denial_cause_requires_exact_proxy_audit(witness, defect):
    row = connect_denial("job-selected", 12345)
    if defect == "event":
        row["event"] = "security.network_guard.evaluated"
    elif defect in {"status", "decision", "host", "port", "coverage"}:
        row["details"][defect] = "other"
    elif defect == "run":
        row["details"]["attribution"]["trusted_transport_identity"] = "job-other"
    elif defect == "gate":
        row["details"]["attribution"]["attribution_provenance"]["authorization_principal"] = "gate:other"
    if defect:
        with pytest.raises(AssertionError):
            witness.check_connect_audit([row], ["job-selected"], 12345)
    else:
        witness.check_connect_audit([row], ["job-selected"], 12345)


@pytest.fixture
def selected_inputs(witness, partial, tmp_path, monkeypatch):
    bundle, scratch = tmp_path / "bundle", tmp_path / "scratch"
    bundle.mkdir()
    scratch.mkdir()
    for name in ("runtime.json", "core.elf", "safeyolo-hyperlight", "python.cpio"):
        (bundle / name).write_text(name)
    for observation in (partial["direct_allowed"], partial["direct_after_permission_removal"],
                        partial["named_allowed"]["body"]["evidence"]["execution"]):
        observation["rootfs"]["runtime_manifest_sha256"] = witness.digest(bundle / "runtime.json")
        observation["rootfs"]["artifact_sha256"] = witness.digest(bundle / "core.elf")
    for name in ("helper", "rootfs"):
        pin = partial["direct_allowed"]["rootfs"]["bundle"][name]
        pin["sha256"] = witness.digest(bundle / pin["file"])
    receipt = tmp_path / "partial.json"
    witness.save(receipt, partial)
    cli, proxy = tmp_path / "cli", tmp_path / "proxy"
    for path in (cli, proxy):
        path.write_text(path.name)
    real_run = witness.subprocess.run

    def run(arguments, **options):
        if str(arguments[0]) in {str(cli), str(proxy)}:
            return SimpleNamespace(stdout=f"safeyolo commit={partial['source']} profile=debug\n")
        return real_run(arguments, **options)

    monkeypatch.setattr(witness.subprocess, "run", run)
    return SimpleNamespace(bundle=bundle, scratch=scratch, root=tmp_path / "instance", cli=cli, proxy=proxy,
                           continue_from=receipt, engine=None, tls=False, admin_port=12345, upstream_port=0, issue=1584,
                           scope=False, caller_only=False, base_root=None, redirect=False)


@pytest.mark.parametrize("defect", [None, "guest", "runtime", "helper", "cpio", "source", "contacts", "policy"])
def test_continuation_checks_selected_artifacts_before_runtime(witness, selected_inputs, partial, monkeypatch, defect):
    args = selected_inputs
    if defect in {"guest", "runtime", "helper", "cpio"}:
        path = {"guest": "core.elf", "runtime": "runtime.json", "helper": "safeyolo-hyperlight",
                "cpio": "python.cpio"}[defect]
        (args.bundle / path).write_text("changed bytes")
    elif defect == "source":
        monkeypatch.setattr(witness.subprocess, "run", lambda *_a, **_k: SimpleNamespace(stdout="other source"))
    elif defect in {"contacts", "policy"}:
        prior = json.loads(args.continue_from.read_bytes())
        if defect == "contacts":
            prior["origin_contacts"].append({"path": "/hyperlight"})
        else:
            prior["policy_removal"]["active"] = "pending"
        witness.save(args.continue_from, prior)
    if defect:
        with pytest.raises(AssertionError):
            witness.completed_core(args)
    else:
        reused = witness.completed_core(args)
        assert reused["source"] == partial["source"] and len(reused["run_ids"]) == 3
        assert reused["sha256"] == witness.digest(args.continue_from)
        assert reused["contacts"] == [{"path": "/hyperlight"}] * 2


@pytest.mark.parametrize(("continuation", "selected_engine", "tls"), [
    (False, None, False), (True, None, False), (False, "hyperlight-unikraft", False),
    (False, None, True), (False, "hyperlight-unikraft", True),
    (False, "gvisor", False), (False, "vz", False), (False, "gvisor", True), (False, "vz", True)])
def test_complete_driver_runs_only_selected_calls_and_retains_separate_contacts(
        witness, selected_inputs, partial, monkeypatch, continuation, selected_engine, tls):
    args = selected_inputs
    args.engine, args.tls, args.authority, args.lifetimes_only = selected_engine, tls, False, False
    if not continuation:
        args.continue_from = None
    for engine in ("hyperlight", "hyperlight-unikraft"):
        witness.save(args.bundle / f"{engine}-network.json", {
            "engine": {"guest": {"path": "core.elf", "sha256": "a" * 64}}})
    platform = selected_engine in ("gvisor", "vz")
    if platform:
        args.base_root = args.bundle
        args.bundle = None
        (args.base_root / "share").mkdir()
        (args.base_root / "bin").mkdir()
        (args.base_root / "config.toml").write_text("[linux]\nplatform='systrap'\n")
    calls, validations, stopped = [], [], []
    gate = "gate:hyperlight-network-check"

    class Instance:
        proxy = None

        def __init__(self, _args):
            self.args, self.scratch = _args, _args.scratch
            self.policy = None
            self.audit = []

        def command(self, *arguments):
            if arguments == ("init",):
                args.root.mkdir()
                (args.root / "data").mkdir()
                if tls:
                    certs = args.root / "certs"
                    certs.mkdir()
                    # Disposable CA only; real origin signing and TLS remain unmocked.
                    ca_config = certs / "ca.cnf"
                    ca_config.write_text(
                        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
                        "[dn]\nCN=Disposable CA\n[extensions]\nbasicConstraints=critical,CA:TRUE\n"
                        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
                        "authorityKeyIdentifier=keyid:always\n")
                    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                                    "-config", str(ca_config), "-keyout", str(certs / "ca.key"),
                                    "-out", str(certs / "mitmproxy-ca-cert.pem")], check=True, capture_output=True)
                    (certs / "mitmproxy-ca.pem").write_bytes(
                        (certs / "mitmproxy-ca-cert.pem").read_bytes() + (certs / "ca.key").read_bytes())
            else:
                validations.append(arguments[:2])

        def apply(self, initial=False):
            pass  # The real activation contract has separate retained source/installed proof.

        def finding(self, engine, mode, request):
            allowed = bool(self.policy["agents"][gate]["hosts"])
            calls.append((engine, mode, allowed))
            assert request["subject"]["value"] == f"{'https' if tls else 'http'}://127.0.0.1:{args.upstream_port}/{engine}"
            if allowed:
                if tls:
                    context = ssl.create_default_context(cafile=str(args.root / "certs/mitmproxy-ca-cert.pem"))
                    connection = http.client.HTTPSConnection("127.0.0.1", args.upstream_port, timeout=5, context=context)
                else:
                    connection = http.client.HTTPConnection("127.0.0.1", args.upstream_port, timeout=5)
                try:
                    connection.request("GET", f"/{engine}")
                    assert connection.getresponse().status == 200
                finally:
                    connection.close()
            return allowed

        def run_job(self, engine, request, **_options):
            allowed = self.finding(engine, "direct", request)
            result = copy.deepcopy(partial["direct_allowed" if allowed else "direct_after_permission_removal"])
            result["engine"] = engine
            if platform:
                result.update(engine=engine, outcome_source="guest_process", rootfs={"profile": "shared"})
            if tls and not allowed:
                result.update(outcome={"kind": "exit", "code": 1}, outcome_source="guest_process" if platform else "host_helper",
                              runtime_report={"completion": None, "error": "the call failed in the guest with status 1 (see its output)"})
                self.refusal(result)
            return result

        def refusal(self, execution):
            self.audit.append(connect_denial(execution["run_id"], args.upstream_port))
            (args.root / "logs").mkdir(exist_ok=True)
            (args.root / "logs/audit.jsonl").write_text("".join(json.dumps(row) + "\n" for row in self.audit))

        def invoke(self, engine, request):
            allowed = self.finding(engine, "named", request)
            named = copy.deepcopy(partial["named_allowed"])
            named["body"]["evidence"]["execution"].update(engine=engine)
            named["body"]["evidence"]["result"]["finding"]["positive"] = allowed
            if platform:
                named["body"]["evidence"]["execution"].update(
                    engine=engine, outcome_source="guest_process", rootfs={"profile": "shared"})
            if tls and not allowed:
                evidence = named["body"]["evidence"]
                evidence.update(result=None, unavailable="job execution failed or unavailable observation")
                evidence["execution"].update(outcome={"kind": "exit", "code": 1}, outcome_source="guest_process" if platform else "host_helper",
                                             runtime_report={"completion": None, "error": "the call failed in the guest with status 1 (see its output)"})
                self.refusal(evidence["execution"])
            return named["status"], named["body"]

    real_server = witness.ThreadingHTTPServer

    def server(address, handler):
        result = real_server(address, handler)
        args.upstream_port = result.server_port
        return result

    monkeypatch.setattr(witness, "ThreadingHTTPServer", server)
    if tls:
        real_tls_server = witness.TlsOrigin

        def tls_server(address, handler):
            result = real_tls_server(address, handler)
            args.upstream_port = result.server_port
            return result

        monkeypatch.setattr(witness, "TlsOrigin", tls_server)
    monkeypatch.setattr(witness, "Instance", Instance)
    monkeypatch.setattr(witness, "wait_ready", lambda *_a: None)
    real_popen = witness.subprocess.Popen

    def popen(arguments, **options):
        return object() if arguments[0] == str(args.proxy) else real_popen(arguments, **options)

    monkeypatch.setattr(witness.subprocess, "Popen", popen)
    monkeypatch.setattr(witness, "stop", lambda child: stopped.append(child))
    witness.exercise(args)
    all_cases = [(engine, mode, allowed) for engine in ((selected_engine,) if selected_engine else ("hyperlight", "hyperlight-unikraft"))
                 for mode, allowed in (("direct", True), ("named", True), ("direct", False), ("named", False))]
    selected = all_cases[3:] if continuation else all_cases
    assert calls == selected
    assert validations.count(("job", "validate")) == (1 if continuation or selected_engine else 2)
    report = json.loads((args.scratch / "result.json").read_bytes())
    assert report["contacts"] == ([{"path": f"/{selected_engine or 'hyperlight-unikraft'}"}] * 2 if continuation or selected_engine else
                                  [{"path": "/hyperlight"}] * 2 + [{"path": "/hyperlight-unikraft"}] * 2)
    assert set(report["engines"]) == ({selected_engine} if selected_engine else {"hyperlight", "hyperlight-unikraft"})
    assert (report["reused_core"] is not None) is continuation
    if continuation:
        assert "direct" not in report["engines"]["hyperlight"]
        assert report["reused_core"]["contacts"] == [{"path": "/hyperlight"}] * 2
    assert len(stopped) == 1
    assert report["mode"] == ("https-inspected" if tls else "http")
    connections = json.loads((args.scratch / "origin-tls.json").read_bytes())
    assert len(connections) == (len(report["contacts"]) if tls else 0)
    assert all(row["phase"] == "tls" and row["version"].startswith("TLSv") for row in connections)
    if platform:
        adopted = json.loads((args.scratch / f"{selected_engine}-adopted.json").read_bytes())
        assert adopted["engine"] == {"kind": "platform"}
        assert adopted["argv"] == ["/bin/bash", "-euo", "pipefail", "-c", witness.PLATFORM_CHECKER,
                                   "network-check", f"{'https' if tls else 'http'}://127.0.0.1:{args.upstream_port}/{selected_engine}"]
        assert tomlkit.parse((args.root / "config.toml").read_text())["linux"] == {"platform": "systrap"}
    config = tomlkit.parse((args.root / "config.toml").read_text())
    assert config.get("upstream_ca_file") == ("certs/mitmproxy-ca-cert.pem" if tls else None)
    assert not config.get("ignore_hosts")


@pytest.mark.parametrize("selected_engine", ["hyperlight", "hyperlight-unikraft"])
def test_lifetime_continuation_skips_completed_authority_and_transport_cases(
        witness, selected_inputs, monkeypatch, selected_engine):
    args = selected_inputs
    args.engine, args.tls, args.authority, args.lifetimes_only = selected_engine, False, False, True
    args.continue_from = None
    witness.save(args.bundle / f"{selected_engine}-network.json", {
        "engine": {"guest": {"path": "core.elf", "sha256": "a" * 64}}})
    calls, stopped = [], []

    class Instance:
        def __init__(self, _args):
            self.args, self.scratch = _args, _args.scratch

        def command(self, *arguments):
            assert arguments == ("init",), arguments
            args.root.mkdir()
            (args.root / "logs").mkdir()
            (args.root / "logs/audit.jsonl").write_text("")

        def apply(self, initial=False):
            assert initial

    def lifetimes(_instance, engine, _origin, contacts):
        calls.append(engine)
        contacts.append({"path": "/held-and-fresh"})
        return {"selected": engine}

    monkeypatch.setattr(witness, "Instance", Instance)
    monkeypatch.setattr(witness, "authority_cases", lambda *_a: pytest.fail("authority replayed"))
    monkeypatch.setattr(witness, "exercise_lifetimes", lifetimes)
    monkeypatch.setattr(witness, "wait_ready", lambda *_a: None)
    monkeypatch.setattr(witness.subprocess, "Popen", lambda *_a, **_kw: object())
    monkeypatch.setattr(witness, "stop", stopped.append)
    # Use an unused kernel-selected loopback port for this controlled driver.
    args.upstream_port = 0
    witness.exercise(args)
    report = json.loads((args.scratch / "result.json").read_bytes())
    assert calls == [selected_engine] and len(stopped) == 1
    assert report["mode"] == "lifetimes"
    assert report["engines"] == {selected_engine: {"lifetimes": {"selected": selected_engine}}}
    assert report["contacts"] == [{"path": "/held-and-fresh"}]


def test_held_response_observes_eof_before_late_release(witness, tmp_path):
    held = witness.HeldResponse(tmp_path / "held.json")
    client, upstream = socket.socketpair()
    thread = threading.Thread(target=held.wait, args=(upstream,))
    thread.start()
    try:
        assert held.entered.wait(2)
        assert not held.closed.wait(0.05), "an idle open stream is not EOF"
        assert json.loads(held.path.read_bytes()) == {"entered": True}
        client.close()
        assert held.closed.wait(2)
        assert json.loads(held.path.read_bytes()) == {"entered": True, "peer_closed": True}
        assert thread.is_alive(), "late response must wait for explicit release"
    finally:
        held.release.set()
        thread.join(timeout=2)
        client.close()
        upstream.close()
    assert not thread.is_alive()


def test_http_origin_retains_disconnect_and_late_response_observations(witness, tmp_path):
    held = witness.HeldResponse(tmp_path / "held.json")
    with witness.ThreadingHTTPServer(("127.0.0.1", 0), witness.NetworkOrigin) as server:
        server.held, server.contacts, server.contacts_path = held, [], tmp_path / "contacts.json"
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            client.request("GET", "/hold/late")
            assert held.entered.wait(2)
            assert not held.closed.is_set()
            client.close()
            assert held.closed.wait(2)
            held.release.set()
            assert held.finished.wait(2)
            assert json.loads(server.contacts_path.read_bytes()) == [{"path": "/hold/late"}]
            observed = json.loads(held.path.read_bytes())
            assert observed["peer_closed"] is True
            assert observed.get("late_response_written") is True or observed.get("late_response_error") in {
                "BrokenPipeError", "ConnectionResetError"}
        finally:
            held.release.set()
            client.close()
            server.shutdown()
            thread.join(timeout=2)
    assert not thread.is_alive()


def test_teardown_probe_distinguishes_live_closed_and_missing_endpoint(witness, tmp_path):
    path = tmp_path / "delegate.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen(1)
        with pytest.raises(AssertionError, match="still accepts"):
            witness.check_closed_delegation(path)
    witness.check_closed_delegation(path)
    path.unlink()
    witness.check_closed_delegation(path)


def test_live_delegation_filters_stopped_and_foreign_generations_before_uniqueness(witness, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    old = data / "job-hyperlight-old"
    old.mkdir()
    witness.save(old / "invocation.json", {"parent_pid": 123, "service_bridge": "/retained/s.sock"})
    foreign = data / "job-hyperlight-foreign"
    foreign.mkdir()
    witness.save(foreign / "invocation.json", {"parent_pid": 456, "service_bridge": "/foreign/s.sock"})
    current = data / "job-hyperlight-current"
    current.mkdir()
    bridge = tmp_path / "s.sock"
    delegated = tmp_path / "p.sock"
    witness.save(current / "invocation.json", {"parent_pid": 123, "service_bridge": str(bridge)})
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(delegated))
        assert witness.live_delegation(tmp_path, {old}, 123) == (current, delegated)
        with pytest.raises(AssertionError):
            witness.live_delegation(tmp_path, set(), 123)
        with pytest.raises(AssertionError):
            witness.live_delegation(tmp_path, {old}, 789)


@pytest.mark.parametrize("mode", ["deadline", "revoke"])
@pytest.mark.parametrize("defect", [None, "positive", "cause", "status"])
def test_named_lifetime_refuses_a_positive_or_unrelated_failure(witness, mode, defect):
    status, value = ((409, {"error": "check authority changed while pending; late result discarded"})
                     if mode == "revoke" else
                     (422, {"error": "check execution deadline exceeded; late result discarded"}))
    if defect == "positive":
        value = {"evidence": {"result": {"finding": {"kind": "finding", "positive": True}}, "unavailable": None}}
    elif defect == "cause":
        value = {"error": "unrelated failure"}
    elif defect == "status":
        status = 503
    if defect:
        with pytest.raises((AssertionError, TypeError)):
            witness.check_unavailable_named(status, value, mode)
    else:
        witness.check_unavailable_named(status, value, mode)


@pytest.mark.parametrize("defect", [None, "event", "run", "gate", "action", "reason", "check"])
def test_cycle_credit_requires_exact_run_gate_and_dependency_reason(witness, defect):
    row = {"event": "security.network_guard.evaluated", "details": {
        "attribution": {"trusted_transport_identity": "job-cycle",
                        "attribution_provenance": {"authorization_principal": "gate:hyperlight-network-check"}},
        "named_checks": {"action": "unresolved", "evidence": {
            "hyperlight": {"unavailable": "recursive/cyclic check dependency"}}}}}
    if defect == "event":
        row["event"] = "other"
    elif defect == "run":
        row["details"]["attribution"]["trusted_transport_identity"] = "other"
    elif defect == "gate":
        row["details"]["attribution"]["attribution_provenance"]["authorization_principal"] = "gate:other"
    elif defect == "action":
        row["details"]["named_checks"]["action"] = "allow"
    elif defect == "reason":
        row["details"]["named_checks"]["evidence"]["hyperlight"]["unavailable"] = "job failed"
    elif defect == "check":
        row["details"]["named_checks"]["evidence"]["other"] = row["details"]["named_checks"]["evidence"].pop("hyperlight")
    results = {"hyperlight": {"authority": {"cycle": {"body": {"evidence": {"execution": {"run_id": "job-cycle"}}}}}}}
    if defect:
        with pytest.raises(AssertionError):
            witness.check_cycle_audit([row], results)
    else:
        witness.check_cycle_audit([row], results)


@pytest.mark.parametrize("defect", [None, "fresh_cached", "cached_other_run", "after_policy_cached"])
def test_lifetime_driver_requires_fresh_runs_and_current_policy_cache(witness, partial, tmp_path, monkeypatch, defect):
    contacts, held_calls = [], []

    class Instance:
        scratch = tmp_path
        args = SimpleNamespace(upstream_port=12345)
        policy = {"checks": {"hyperlight": {"source": {"limits": {}}}}}

        def __init__(self):
            self.cache, self.generation = {}, 0

        def apply(self):
            if not (defect == "after_policy_cached" and held_calls):
                self.cache.clear()

        def invoke(self, engine, request):
            subject = request["subject"]["value"]
            if subject in self.cache:
                body = copy.deepcopy(self.cache[subject])
                body["evidence"]["acquisition"] = "reused_live_evidence"
                if defect == "cached_other_run":
                    body["evidence"]["execution"]["run_id"] = "other"
            else:
                body = copy.deepcopy(partial["named_allowed"]["body"])
                self.generation += 1
                body["evidence"]["execution"]["run_id"] = f"fresh-{self.generation}"
                body["evidence"]["acquisition"] = "reused_live_evidence" if defect == "fresh_cached" else "live"
                contacts.append({"path": subject})
                self.cache[subject] = copy.deepcopy(body)
            return 200, body

    def held(instance, engine, origin, mode):
        held_calls.append((engine, mode))
        contacts.append({"path": "held"})
        return {"run_id": "retired"}

    monkeypatch.setattr(witness, "held_direct", held)
    monkeypatch.setattr(witness, "held_named", held)
    if defect:
        with pytest.raises(AssertionError):
            witness.exercise_lifetimes(Instance(), "hyperlight", None, contacts)
    else:
        results = witness.exercise_lifetimes(Instance(), "hyperlight", None, contacts)
        assert len(held_calls) == 5 and len(contacts) == 11
        assert results["policy-invalidated-cache"]["evidence"]["execution"]["run_id"] == "fresh-6"


@pytest.mark.parametrize("defect", [None, "caller_contact", "forged_accepted", "live_preview", "cycle_positive"])
def test_authority_driver_checks_refusal_offline_effects_and_restores_policy(witness, partial, tmp_path, monkeypatch, defect):
    contacts = []
    original = {"subject": "value", "source": {"effects": "passive"}}

    class Instance:
        args = SimpleNamespace(upstream_port=12345)
        scratch = tmp_path
        policy = {"checks": {"hyperlight": copy.deepcopy(original)}}

        def apply(self):
            pass  # This control checks the observer; installed activation is separate.

        def invoke(self, engine, request):
            if any(key != "subject" for key in request):
                return (200 if defect == "forged_accepted" else 400), {
                    "error": "supply only an adopted check name and typed subject"}
            body = copy.deepcopy(partial["named_allowed"]["body"])
            body["evidence"]["result"]["finding"]["positive"] = defect == "cycle_positive"
            return 200, body

        def command(self, *arguments):
            if arguments[:2] == ("policy", "evaluate"):
                effects = tomlkit.parse(Path(arguments[2]).read_text())["checks"]["hyperlight"]["source"]["effects"]
                return SimpleNamespace(stdout=json.dumps({"result": {
                    "evidence_mode": "live" if defect == "live_preview" else "recorded_offline",
                    "destination_contact": False, "dependency_calls": [], "stages": [{}, {
                        "evidence": {"hyperlight": {"execution": {"effects": effects, "invoked": False}}}}]}}))

    def caller(*_args):
        if defect == "caller_contact":
            contacts.append({"path": "forbidden"})
        return {"status": 403}

    monkeypatch.setattr(witness, "caller_request", caller)
    instance = Instance()
    if defect:
        with pytest.raises(AssertionError):
            witness.authority_cases(instance, "hyperlight", contacts)
    else:
        result = witness.authority_cases(instance, "hyperlight", contacts)
        assert set(result) == {"caller", "forged-headers", "gate_id", "run_id", "ancestry", "inputs", "spec",
                               "passive-preview", "active-preview", "cycle"}
    assert instance.policy == {"checks": {"hyperlight": original}}
