"""Exercise delegated public egress through both installed Hyperlight engines.

Run on an owning Linux KVM or physical Apple-silicon HVF host with matching
candidate CLI/proxy/bundle, Python and tomlkit. Supply a new short instance root,
empty private disk-backed scratch directory and two authorized loopback ports.
This witness needs no provider credential or Service Gateway grant. It covers
HTTP direct/named allow/removal and contact-free validation. Use --tls for
only the unrun HTTPS cases: guest TLS through the inspecting SY proxy to an
owned TLS origin, followed by CONNECT refusal after gate permission removal.
Use --authority for caller/gate separation, forged invocation fields, offline
preview, dependency-cycle refusal and generic HTTP stream lifetimes. The origin
withholds headers and observes upstream EOF before a late response. Fresh and
cached invocations follow direct cancellation/deadline/revocation and named
deadline/revocation. These modes do not establish the whole four-engine or
independent capture contract.
Use --lifetimes-only after a cleanup correction to run those lifetime cases
without repeating completed caller, offline or cycle observations.
TLS mode also requires the existing OpenSSL command.

Use --continue-from with the retained partial HTTP receipt to reuse completed
Core allow/direct-denial observations. The continuation runs Core named denial
and the Unikraft cases in a fresh instance, with separate contact counters.
Use --engine to select only an engine whose observations remain unrun. Earlier
receipts retain their own source, artifact identities and contact counters.
"""

import argparse
import copy
import http.client
import json
import select
import signal
import socket
import ssl
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomlkit
from hyperlight_services import Instance, digest, job_result, output, save, stop
from job_network import create_upstream_certificate, wait_ready


class TlsOrigin(ThreadingHTTPServer):
    """Retain TCP contacts as well as application requests across TLS refusal."""

    def get_request(self):
        stream, address = super().get_request()
        event = {"phase": "accepted"}
        self.connections.append(event)
        save(self.observation_path, self.connections)
        stream.settimeout(8)
        try:
            tls = self.context.wrap_socket(stream, server_side=True)
        except OSError as error:
            stream.close()
            event.update(phase="failed", error=str(error))
            save(self.observation_path, self.connections)
            raise
        event.update(phase="tls", version=tls.version(), cipher=tls.cipher()[0])
        save(self.observation_path, self.connections)
        return tls, address


class HeldResponse:
    """Observe upstream EOF before attempting a deliberately late response."""

    def __init__(self, path):
        self.path = path
        self.entered = threading.Event()
        self.closed = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.observation = {}

    def wait(self, stream):
        self.observation["entered"] = True
        save(self.path, self.observation)
        self.entered.set()
        while not self.release.wait(0.025):
            if not select.select([stream], [], [], 0)[0]:
                continue
            try:
                closed = stream.recv(1, socket.MSG_PEEK) == b""
            except ConnectionResetError:
                closed = True
                self.observation["close_reason"] = "reset"
            if closed:
                self.observation["peer_closed"] = True
                save(self.path, self.observation)
                self.closed.set()
                self.release.wait(60)
                return


class NetworkOrigin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.contacts.append({"path": self.path})
        save(self.server.contacts_path, self.server.contacts)
        held = self.server.held if self.path.startswith("/hold/") else None
        if held is not None:
            held.wait(self.connection)
        try:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError) as error:
            if held is None:
                raise
            held.observation["late_response_error"] = type(error).__name__
        else:
            if held is not None:
                held.observation["late_response_written"] = True
        finally:
            if held is not None:
                save(held.path, held.observation)
                held.finished.set()

    def log_message(self, *_args):
        pass  # Only the bounded contact observations are retained.


def live_delegation(root, before, parent_pid):
    """Select this invocation before checking uniqueness; ignore retained runs."""
    matches = []
    for directory in set((root / "data").glob("job-hyperlight-*")) - before:
        path = directory / "invocation.json"
        if not path.is_file():
            continue
        value = json.loads(path.read_bytes())
        if value["parent_pid"] == parent_pid:
            matches.append((directory, Path(value["service_bridge"]).with_name("p.sock")))
    assert len(matches) == 1, matches
    directory, delegated = matches[0]
    assert delegated.is_socket(), delegated
    return directory, delegated


def check_closed_delegation(path):
    with socket.socket(socket.AF_UNIX) as probe:
        probe.settimeout(2)
        try:
            probe.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            return
    raise AssertionError(f"ended invocation still accepts proxy connections: {path}")


def check_unavailable_named(status, value, mode):
    if mode == "revoke":
        assert status == 409, value
        assert value == {"error": "check authority changed while pending; late result discarded"}, value
    else:
        assert status == 422 and set(value) == {"error"}, value
        assert "check execution deadline exceeded" in value["error"], value


def caller_request(instance, url, headers):
    """Use the assessed caller's listener, without sending a token upstream."""
    connection = http.client.HTTPConnection("_safeyolo.proxy.internal", timeout=10)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(10)
    connection.sock.connect(str(instance.root / "driver.sock"))
    try:
        connection.request("GET", url, headers=headers)
        response = connection.getresponse()
        return {"status": response.status, "body": response.read().decode()}
    finally:
        connection.close()


def authority_cases(instance, engine, contacts):
    port = instance.args.upstream_port
    url = f"http://127.0.0.1:{port}/authority/{engine}"
    subject = {"kind": "value", "value": url}
    count = len(contacts)
    results = {}
    for label, headers in (("caller", {}), ("forged-headers", {
            "X-SafeYolo-Agent": "gate:hyperlight-network-check",
            "X-SafeYolo-Agent-ID": "gate:hyperlight-network-check", "X-SafeYolo-Agent-Name": "forged",
            "X-SafeYolo-Request-ID": "job-forged", "X-SafeYolo-Run": "job-forged",
            "X-SafeYolo-Policy-Checks": engine})):
        result = caller_request(instance, url, headers)
        results[label] = result
        save(instance.scratch / f"{engine}-authority.json", results)
        assert result["status"] == 403 and len(contacts) == count, results
    for field in ("gate_id", "run_id", "ancestry", "inputs", "spec"):
        status, body = instance.invoke(engine, {"subject": subject, field: "forged"})
        assert status == 400 and body == {"error": "supply only an adopted check name and typed subject"}, body
        assert len(contacts) == count, contacts
        results[field] = {"status": status, "body": body}
    original = copy.deepcopy(instance.policy["checks"][engine])
    check = instance.policy["checks"][engine]
    check.update(subject="http_path", inputs={"url": url})
    instance.policy["check_rules"] = [{
        "name": "dependency-cycle", "host": "127.0.0.1", "agent": "gate:hyperlight-network-check",
        "stage": "request", "influence": "hard_exclusion", "priority": 0, "required": True,
        "when": {"op": "finding", "check": engine}, "on_match": "deny", "on_unavailable": "unresolved"}]
    try:
        instance.apply()
        scenario = instance.scratch / f"{engine}-offline.json"
        save(scenario, {"agent": "gate:hyperlight-network-check", "host": "127.0.0.1", "port": port,
                        "scheme": "http", "method": "GET", "path": f"/authority/{engine}", "ip": "127.0.0.1"})
        for effects in ("passive", "active"):
            check["source"]["effects"] = effects
            candidate = instance.scratch / f"{engine}-{effects}-preview.toml"
            candidate.write_text(tomlkit.dumps(instance.policy))
            instance.command("policy", "check", str(candidate))
            preview = instance.command("policy", "evaluate", str(candidate), str(scenario))
            results[f"{effects}-preview"] = json.loads(preview.stdout)
            save(instance.scratch / f"{engine}-authority.json", results)
            assert len(contacts) == count, contacts
            value = results[f"{effects}-preview"]["result"]
            assert value["evidence_mode"] == "recorded_offline" and value["destination_contact"] is False, value
            assert value["dependency_calls"] == [], value
            assert value["stages"][1]["evidence"][engine]["execution"] == {"effects": effects, "invoked": False}, value
        # The active policy is still the passive definition. The real nested
        # request must reach cycle refusal, rather than exempting checker traffic.
        cycle_subject = {"kind": "http_path", "hostname": "127.0.0.1", "port": port,
                         "scheme": "http", "method": "GET", "path": f"/authority/{engine}"}
        status, cycle = instance.invoke(engine, {"subject": cycle_subject})
        results["cycle"] = {"status": status, "body": cycle}
        save(instance.scratch / f"{engine}-authority.json", results)
        check_named(status, cycle, False)
        assert len(contacts) == count, contacts
    finally:
        instance.policy["checks"][engine] = original
        instance.policy.pop("check_rules", None)
        instance.apply()
    return results


def held_direct(instance, engine, origin, mode):
    before = set((instance.root / "data").glob("job-hyperlight-*"))
    held = origin.held = HeldResponse(instance.scratch / f"{engine}-{mode}-origin.json")
    url = f"http://127.0.0.1:{instance.args.upstream_port}/hold/{engine}/{mode}"
    request = {"subject": {"kind": "value", "value": url}}
    permission = None
    try:
        with instance.job(engine, request, timeout=30) as (child, prefix):
            assert held.entered.wait(20), f"{engine}/{mode}: no held origin request"
            assert child.poll() is None, f"{engine}/{mode}: job already exited"
            directory, delegated = live_delegation(instance.root, before, child.pid)
            save(prefix.with_suffix(".held.json"), {"directory": str(directory), "delegate": str(delegated),
                                                    "parent_pid": child.pid, "mode": mode})
            if mode == "cancel":
                child.send_signal(signal.SIGINT)
            elif mode == "revoke":
                hosts = instance.policy["agents"]["gate:hyperlight-network-check"]["hosts"]
                permission = hosts.pop(f"127.0.0.1:{instance.args.upstream_port}")
                instance.apply()
            child.wait(timeout=45)
        expected = ({"kind": "timeout"} if mode == "deadline" else
                    {"kind": "interrupted", "signal": int(signal.SIGINT if mode == "cancel" else signal.SIGTERM)})
        result = job_result(prefix, engine, mode, expected_outcome=expected)
        save(prefix.with_suffix(".result.json"), result)
        assert result["stdout"]["bytes"] == 0 and result["service_evidence"] == [], result
        assert held.closed.wait(5), "terminated guest left its held upstream connection usable"
        check_closed_delegation(delegated)
        assert not directory.exists(), directory
        held.release.set()
        assert held.finished.wait(5), "late origin response was not observed"
        return result
    finally:
        held.release.set()
        if permission is not None:
            instance.policy["agents"]["gate:hyperlight-network-check"]["hosts"][
                f"127.0.0.1:{instance.args.upstream_port}"] = permission
            instance.apply()


def held_named(instance, engine, origin, mode):
    held = origin.held = HeldResponse(instance.scratch / f"{engine}-named-{mode}-origin.json")
    before = set((instance.root / "data").glob("job-hyperlight-*"))
    subject = {"kind": "value", "value": f"http://127.0.0.1:{instance.args.upstream_port}/hold/{engine}/named-{mode}"}
    permission = None
    try:
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(instance.invoke, engine, {"subject": subject})
            try:
                assert held.entered.wait(20), f"{engine}/named-{mode}: no held origin request"
                assert not pending.done(), "named invocation ended before trigger"
                directory, delegated = live_delegation(instance.root, before, instance.proxy.pid)
                save(instance.scratch / f"{engine}-named-{mode}-held.json",
                     {"directory": str(directory), "delegate": str(delegated), "parent_pid": instance.proxy.pid})
                if mode == "revoke":
                    hosts = instance.policy["agents"]["gate:hyperlight-network-check"]["hosts"]
                    permission = hosts.pop(f"127.0.0.1:{instance.args.upstream_port}")
                    instance.apply()
                status, value = pending.result(timeout=45)
            finally:
                # A failed assertion must release the origin before joining the
                # bounded invocation thread; preserve its reached observations.
                if not pending.done():
                    held.release.set()
        check_unavailable_named(status, value, mode)
        assert held.closed.wait(5), "named teardown left the held upstream connection usable"
        check_closed_delegation(delegated)
        assert not directory.exists(), directory
        held.release.set()
        assert held.finished.wait(5), "late named origin response was not observed"
        return {"status": status, "body": value}
    finally:
        held.release.set()
        if permission is not None:
            instance.policy["agents"]["gate:hyperlight-network-check"]["hosts"][
                f"127.0.0.1:{instance.args.upstream_port}"] = permission
            instance.apply()


def exercise_lifetimes(instance, engine, origin, contacts):
    """Use the same held-response cases for both guest client implementations."""
    results = {}
    check = instance.policy["checks"][engine]
    check["source"]["limits"]["timeout_ms"] = 20_000
    check["source"]["limits"]["max_cached"] = 2
    instance.apply()
    for entry, modes in (("direct", ("cancel", "deadline", "revoke")), ("named", ("deadline", "revoke"))):
        for mode in modes:
            count = len(contacts)
            result = (held_direct if entry == "direct" else held_named)(instance, engine, origin, mode)
            results[f"{entry}-{mode}"] = result
            save(instance.scratch / f"{engine}-lifetimes.json", results)
            assert len(contacts) == count + 1, contacts
            subject = {"kind": "value", "value": f"http://127.0.0.1:{instance.args.upstream_port}/fresh/{engine}/{entry}-{mode}"}
            status, fresh = instance.invoke(engine, {"subject": subject})
            check_named(status, fresh, True)
            assert fresh["evidence"]["acquisition"] == "live", fresh
            assert len(contacts) == count + 2, contacts
            if entry == "direct":
                assert fresh["evidence"]["execution"]["run_id"] != result["run_id"], fresh
            status, cached = instance.invoke(engine, {"subject": subject})
            check_named(status, cached, True)
            assert cached["evidence"]["acquisition"] == "reused_live_evidence", cached
            assert cached["evidence"]["execution"]["run_id"] == fresh["evidence"]["execution"]["run_id"], cached
            assert len(contacts) == count + 2, contacts
            results[f"{entry}-{mode}-fresh"] = fresh
            save(instance.scratch / f"{engine}-lifetimes.json", results)
    count = len(contacts)
    instance.apply()
    status, after_policy = instance.invoke(engine, {"subject": subject})
    check_named(status, after_policy, True)
    assert after_policy["evidence"]["acquisition"] == "live", after_policy
    assert after_policy["evidence"]["execution"]["run_id"] != fresh["evidence"]["execution"]["run_id"], after_policy
    assert len(contacts) == count + 1, contacts
    results["policy-invalidated-cache"] = after_policy
    save(instance.scratch / f"{engine}-lifetimes.json", results)
    return results


def check_direct(result, positive):
    assert result["outcome"] == {"kind": "exit", "code": 0}, result
    assert result["observation_error"] is None, result
    finding = output(result)["finding"]
    assert finding["kind"] == "finding" and finding["positive"] is positive, result
    assert result["gate_principal"] == result["authorization_principal"] == "gate:hyperlight-network-check"
    assert result["rootfs"]["network"] is True
    assert result["service_evidence"] == []


def check_named(status, value, positive):
    assert status == 200, value
    evidence = value["evidence"]
    assert evidence["unavailable"] is None, value
    finding = evidence["result"]["finding"]
    assert finding["kind"] == "finding" and finding["positive"] is positive, value
    execution = evidence["execution"]
    assert execution["outcome"] == {"kind": "exit", "code": 0}, value
    assert execution["observation_error"] is None, value
    assert execution["gate_principal"] == execution["authorization_principal"] == "gate:hyperlight-network-check"
    assert execution["service_evidence"] == [], value


def check_failed_tls(execution):
    """Check observed execution failure; the proxy audit establishes its cause."""
    assert execution["outcome"] == {"kind": "exit", "code": 1}, execution
    assert execution["observation_error"] is None, execution
    assert execution["outcome_source"] == "host_helper", execution
    report = execution["runtime_report"]
    assert report["completion"] is None and report["error"], execution
    assert execution["gate_principal"] == execution["authorization_principal"] == "gate:hyperlight-network-check"
    assert execution["rootfs"]["network"] is True and execution["service_evidence"] == [], execution


def check_connect_audit(rows, runs, port):
    """Require the proxy's exact-run CONNECT denial, not just a failed guest."""
    for run in runs:
        assert any(row["event"] == "traffic.request_outcome"
                   and row["details"].get("status") == 403
                   and row["details"].get("decision") == "deny"
                   and row["details"].get("host") == "127.0.0.1"
                   and row["details"].get("port") == port
                   and row["details"].get("coverage") == "native_network_guard_only"
                   and row["details"].get("attribution", {}).get("trusted_transport_identity") == run
                   and row["details"]["attribution"].get("attribution_provenance", {}).get(
                       "authorization_principal") == "gate:hyperlight-network-check"
                   for row in rows), f"missing proxy CONNECT 403 for {run}"


def check_cycle_audit(rows, results):
    for engine, result in results.items():
        run = result["authority"]["cycle"]["body"]["evidence"]["execution"]["run_id"]
        assert any(row["event"] == "security.network_guard.evaluated"
                   and row["details"].get("attribution", {}).get("trusted_transport_identity") == run
                   and row["details"]["attribution"].get("attribution_provenance", {}).get(
                       "authorization_principal") == "gate:hyperlight-network-check"
                   and row["details"].get("named_checks", {}).get("action") == "unresolved"
                   and row["details"]["named_checks"].get("evidence", {}).get(engine, {}).get(
                       "unavailable") == "recursive/cyclic check dependency"
                   for row in rows), f"missing exact-run dependency-cycle observation for {engine}/{run}"


def completed_core(args):
    """Validate the selected observation receipt before skipping completed work."""
    if args.continue_from is None:
        return None
    prior = json.loads(args.continue_from.read_bytes())
    check_direct(prior["direct_allowed"], True)
    check_named(prior["named_allowed"]["status"], prior["named_allowed"]["body"], True)
    check_direct(prior["direct_after_permission_removal"], False)
    assert prior["after_removal_cli_returncode"] == 0
    assert prior["policy_removal"] == {"http_status": 200, "hosts": {}, "active": "active"}
    assert prior["origin_contacts"] == [{"path": "/hyperlight"}, {"path": "/hyperlight"}]
    assert prior["ready_exists_after"] is False and prior["job_runtime_directories_after"] == []
    observations = [prior["direct_allowed"], prior["named_allowed"]["body"]["evidence"]["execution"],
                    prior["direct_after_permission_removal"]]
    assert len({item["run_id"] for item in observations}) == 3
    for item in observations:
        assert item["engine"] == item["rootfs"]["kind"] == "hyperlight"
        assert item["rootfs"]["runtime_manifest_sha256"] == digest(args.bundle / "runtime.json")
        assert item["rootfs"]["artifact_sha256"] == digest(args.bundle / "core.elf")
    bundle = prior["direct_allowed"]["rootfs"]["bundle"]
    for name in ("helper", "rootfs"):
        assert digest(args.bundle / bundle[name]["file"]) == bundle[name]["sha256"]
    versions = {}
    for name in ("cli", "proxy"):
        versions[name] = subprocess.run([str(getattr(args, name)), "--version"], check=True, timeout=10,
                                        capture_output=True, text=True).stdout.strip()
        assert f"commit={prior['source']} " in versions[name] + " ", versions[name]
    return {"receipt": str(args.continue_from), "sha256": digest(args.continue_from),
            "source": prior["source"], "case": prior["case"], "run_ids": [item["run_id"] for item in observations],
            "contacts": prior["origin_contacts"], "versions": versions}


def exercise_engine(instance, engine, contacts, continuing_core, origin):
    """Observe the selected calls and require denied calls to add no contact."""
    if instance.args.authority or instance.args.lifetimes_only:
        observed = {"authority": authority_cases(instance, engine, contacts)} if instance.args.authority else {}
        observed["lifetimes"] = exercise_lifetimes(instance, engine, origin, contacts)
        return observed
    connections = origin.connections
    destination = f"127.0.0.1:{instance.args.upstream_port}"
    gate = "gate:hyperlight-network-check"
    before = len(contacts)
    before_connections = len(connections)
    scheme = "https" if instance.args.tls else "http"
    subject = {"kind": "value", "value": f"{scheme}://{destination}/{engine}"}
    request = {"subject": subject, "inputs": {}}
    observed = {}
    if not continuing_core:
        instance.command("job", "validate", str(instance.scratch / f"{engine}-adopted.json"))
        instance.command("policy", "check", str(instance.scratch / "policy-candidate.toml"))
        assert len(contacts) == before and len(connections) == before_connections
        direct = instance.run_job(engine, request)
        check_direct(direct, True)
        assert len(contacts) == before + 1
        status, named = instance.invoke(engine, {"subject": subject})
        check_named(status, named, True)
        assert len(contacts) == before + 2
        observed.update(direct=direct["run_id"], named=named)
    expected_contacts = len(contacts)
    expected_connections = len(connections)
    permission = instance.policy["agents"][gate]["hosts"].pop(destination)
    instance.apply()
    if not continuing_core:
        if instance.args.tls:
            denied_direct = instance.run_job(engine, request, expected_outcome={"kind": "exit", "code": 1})
            check_failed_tls(denied_direct)
        else:
            denied_direct = instance.run_job(engine, request)
            check_direct(denied_direct, False)
        observed["denied_direct"] = denied_direct["run_id"]
    assert len(contacts) == expected_contacts
    status, denied = instance.invoke(engine, {"subject": subject})
    if instance.args.tls:
        assert status == 200 and denied["evidence"]["result"] is None, denied
        assert denied["evidence"]["unavailable"] == "job execution failed or unavailable observation", denied
        check_failed_tls(denied["evidence"]["execution"])
    else:
        check_named(status, denied, False)
    assert len(contacts) == expected_contacts
    assert len(connections) == expected_connections
    instance.policy["agents"][gate]["hosts"][destination] = permission
    instance.apply()
    return {**observed, "denied": denied}


def adopt_network_checks(instance, engines):
    """Use the same adopted network jobs for the direct and named entry points."""
    args = instance.args
    config = {"admin_port": args.admin_port, "flow_store_enabled": False,
              "agent_api_enabled": True, "tls_ca_file": "certs/mitmproxy-ca.pem",
              "listeners": [{"agent_id": "driver", "socket_path": str(args.root / "driver.sock")}]}
    if args.tls:
        config["upstream_ca_file"] = "certs/mitmproxy-ca-cert.pem"
    (args.root / "config.toml").write_text(tomlkit.dumps(config))
    destination = f"127.0.0.1:{args.upstream_port}"
    gate = "gate:hyperlight-network-check"
    instance.policy = {"hosts": {"*": {"egress": "deny"}},
                       "agents": {gate: {"hosts": {destination: {"egress": "allow"}}}},
                       "controls": {"test_context": {"action": "warn"}}, "checks": {}}
    for engine in engines:
        spec = json.loads((args.bundle / f"{engine}-network.json").read_bytes())
        for key in ("runtime", "guest", "checker"):
            if key in spec["engine"]:
                spec["engine"][key]["path"] = str(args.bundle / spec["engine"][key]["path"])
        spec["timeout_seconds"] = 30
        path = args.scratch / f"{engine}-adopted.json"
        save(path, spec)
        instance.policy["checks"][engine] = {
            "source_id": "public-http-status", "meaning": "Public endpoint returns HTTP 200",
            "subject": "value", "result_type": "finding", "influences": ["hard_exclusion"],
            "implementation_version": spec["engine"].get("guest", spec["engine"].get("checker"))["sha256"],
            "configuration_version": digest(path), "max_age_seconds": 60, "invokers": ["driver"],
            "source": {"kind": "job", "spec": str(path), "effects": "passive", "limits": {
                "timeout_ms": 40_000, "max_input_bytes": 16384, "max_output_bytes": 16384,
                "max_concurrent": 1, "max_pending": 1, "max_cached": 0}}}
    instance.apply(initial=True)


def check_shutdown(args, results):
    assert not (args.root / "data/ready.json").exists()
    assert not list((args.root / "data").glob("job-hyperlight-*"))
    if args.tls or args.authority or args.lifetimes_only:
        # Shutdown flushes the ordinary audit writer. Keep the complete private
        # audit and raw job streams even when the exact refusal assertion fails.
        rows = [json.loads(line) for line in (args.root / "logs/audit.jsonl").read_text().splitlines()]
    if args.authority:
        check_cycle_audit(rows, results)
    if args.tls:
        runs = [run for result in results.values() for run in
                (result["denied_direct"], result["denied"]["evidence"]["execution"]["run_id"])]
        check_connect_audit(rows, runs, args.upstream_port)


def exercise(args):
    engines = (args.engine,) if args.engine else ("hyperlight", "hyperlight-unikraft")
    reused = completed_core(args)
    instance = Instance(args)
    contacts, connections = [], []
    instance.command("init")
    context = None
    if args.tls:
        create_upstream_certificate(args.root)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.root / "certs/upstream.pem", args.root / "certs/upstream.key")

    server = TlsOrigin if args.tls else ThreadingHTTPServer
    with server(("127.0.0.1", args.upstream_port), NetworkOrigin) as origin:
        origin.context, origin.connections, origin.held = context, connections, None
        origin.observation_path = args.scratch / "origin-tls.json"
        origin.contacts, origin.contacts_path = contacts, args.scratch / "origin-contacts.json"
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            adopt_network_checks(instance, engines)
            results = {}
            report = {"engines": results, "contacts": contacts, "reused_core": reused,
                      "mode": ("lifetimes" if args.lifetimes_only else "authority" if args.authority
                               else "https-inspected" if args.tls else "http"),
                      "tls_connections": connections,
                      "runtime_manifest_sha256": digest(args.bundle / "runtime.json"),
                      "cli_sha256": digest(args.cli), "proxy_sha256": digest(args.proxy)}
            save(args.scratch / "result.json", report)
            with (args.scratch / "proxy.log").open("wb") as log:
                instance.proxy = subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml")],
                                                  stdout=log, stderr=log)
                try:
                    wait_ready(instance.proxy, args.root, args.admin_port)
                    for engine in engines:
                        results[engine] = exercise_engine(instance, engine, contacts,
                                                         reused is not None and engine == "hyperlight", origin)
                        if args.tls:
                            assert len(connections) == len(contacts), connections
                            assert all(row["phase"] == "tls" for row in connections), connections
                        save(args.scratch / "result.json", report)
                finally:
                    stop(instance.proxy)
        finally:
            origin.shutdown()
            thread.join(timeout=10)
            assert not thread.is_alive()
            save(args.scratch / "origin-contacts.json", contacts)
            save(args.scratch / "origin-tls.json", connections)
    check_shutdown(args, results)
    if args.authority or args.lifetimes_only:
        print("PASS: generic stream direct/named deadlines and revocation, cancellation, EOF/endpoint teardown and fresh/cached invocations")
    else:
        protocol = "HTTPS/CONNECT refusal" if args.tls else "HTTP"
        print(f"PASS: public {protocol} direct/named allow, permission removal and validation contact counters"
              + ("; completed Core observations reused from the selected receipt" if reused else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "proxy", "bundle", "root", "scratch"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("admin-port", "upstream-port"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--continue-from", type=Path, help="retained partial Core HTTP observation receipt")
    parser.add_argument("--engine", choices=("hyperlight", "hyperlight-unikraft"),
                        help="exercise only the selected engine (default: both)")
    parser.add_argument("--tls", action="store_true", help="run only HTTPS success and CONNECT-refusal cases")
    parser.add_argument("--authority", action="store_true", help="run only new generic HTTP authority, cycle/offline and lifetime cases")
    parser.add_argument("--lifetimes-only", action="store_true", help="run lifetime cases without caller, offline or cycle replays")
    args = parser.parse_args()
    for name in ("cli", "proxy", "bundle", "scratch"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.root = args.root.absolute()
    if args.authority and (args.tls or args.continue_from is not None):
        parser.error("--authority cannot be combined with --tls or --continue-from")
    if args.lifetimes_only and (args.authority or args.tls or args.continue_from is not None):
        parser.error("--lifetimes-only cannot be combined with --authority, --tls or --continue-from")
    if args.continue_from is not None:
        if args.engine is not None or args.tls:
            parser.error("--continue-from is HTTP-only and cannot be combined with --engine or --tls")
        args.continue_from = args.continue_from.resolve(strict=True)
    # Instance.invoke uses this only as a default subject; every call overrides it.
    args.issue = 1584
    if (args.root.exists() or any(args.scratch.iterdir()) or len(str(args.root / "driver.sock").encode()) >= 100
            or not all(1 <= port <= 65535 for port in (args.admin_port, args.upstream_port))
            or args.admin_port == args.upstream_port):
        parser.error("use a new short root, empty scratch and two distinct authorized nonzero ports")
    args.scratch.chmod(0o700)
    exercise(args)


if __name__ == "__main__":
    main()
