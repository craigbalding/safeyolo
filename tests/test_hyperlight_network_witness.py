"""The HTTP witness keeps typed denial separate from failed execution and reuse."""

import base64
import copy
import hashlib
import http.client
import importlib.util
import json
import ssl
import subprocess
from pathlib import Path
from types import SimpleNamespace

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
                           continue_from=receipt, engine=None, tls=False, admin_port=12345, upstream_port=0, issue=1584)


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
    (False, None, True), (False, "hyperlight-unikraft", True)])
def test_complete_driver_runs_only_selected_calls_and_retains_separate_contacts(
        witness, selected_inputs, partial, monkeypatch, continuation, selected_engine, tls):
    args = selected_inputs
    args.engine, args.tls = selected_engine, tls
    if not continuation:
        args.continue_from = None
    for engine in ("hyperlight", "hyperlight-unikraft"):
        witness.save(args.bundle / f"{engine}-network.json", {
            "engine": {"guest": {"path": "core.elf", "sha256": "a" * 64}}})
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
            if tls and not allowed:
                result.update(outcome={"kind": "exit", "code": 1}, outcome_source="host_helper",
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
            named["body"]["evidence"]["result"]["finding"]["positive"] = allowed
            if tls and not allowed:
                evidence = named["body"]["evidence"]
                evidence.update(result=None, unavailable="job execution failed or unavailable observation")
                evidence["execution"].update(outcome={"kind": "exit", "code": 1}, outcome_source="host_helper",
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
    all_cases = [(engine, mode, allowed) for engine in ("hyperlight", "hyperlight-unikraft")
                 for mode, allowed in (("direct", True), ("named", True), ("direct", False), ("named", False))]
    selected = all_cases[4:] if selected_engine else all_cases[3:] if continuation else all_cases
    assert calls == selected
    assert validations.count(("job", "validate")) == (1 if continuation or selected_engine else 2)
    report = json.loads((args.scratch / "result.json").read_bytes())
    assert report["contacts"] == ([{"path": "/hyperlight-unikraft"}] * 2 if continuation or selected_engine else
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
    config = tomlkit.parse((args.root / "config.toml").read_text())
    assert config.get("upstream_ca_file") == ("certs/mitmproxy-ca-cert.pem" if tls else None)
    assert not config.get("ignore_hosts")
