"""Exercise delegated public egress through both installed Hyperlight engines.

Run on an owning Linux KVM or physical Apple-silicon HVF host with matching
candidate CLI/proxy/bundle, Python and tomlkit. Supply a new short instance root,
empty private disk-backed scratch directory and two authorized loopback ports.
This witness needs no provider credential or Service Gateway grant. It covers
HTTP direct/named allow/removal and contact-free validation. Use --tls for
only the unrun HTTPS cases: guest TLS through the inspecting SY proxy to an
owned TLS origin, followed by CONNECT refusal after gate permission removal.
Neither mode establishes the whole four-engine, ancestry, capture or lifecycle
acceptance contract. TLS mode also requires the existing OpenSSL command.

Use --continue-from with the retained partial HTTP receipt to reuse completed
Core allow/direct-denial observations. The continuation runs Core named denial
and the Unikraft cases in a fresh instance, with separate contact counters.
Use --engine to select only an engine whose observations remain unrun. Earlier
receipts retain their own source, artifact identities and contact counters.
"""

import argparse
import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomlkit
from hyperlight_services import Instance, digest, output, save, stop
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


def exercise_engine(instance, engine, contacts, continuing_core, connections):
    """Observe the selected calls and require denied calls to add no contact."""
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

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            contacts.append({"path": self.path})
            save(args.scratch / "origin-contacts.json", contacts)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass  # Only the bounded contact observations are retained.

    server = TlsOrigin if args.tls else ThreadingHTTPServer
    with server(("127.0.0.1", args.upstream_port), Origin) as origin:
        origin.context, origin.connections = context, connections
        origin.observation_path = args.scratch / "origin-tls.json"
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            adopt_network_checks(instance, engines)
            results = {}
            report = {"engines": results, "contacts": contacts, "reused_core": reused,
                      "mode": "https-inspected" if args.tls else "http", "tls_connections": connections,
                      "runtime_manifest_sha256": digest(args.bundle / "runtime.json"),
                      "cli_sha256": digest(args.cli), "proxy_sha256": digest(args.proxy)}
            save(args.scratch / "result.json", report)
            with (args.scratch / "proxy.log").open("wb") as log:
                instance.proxy = subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml")],
                                                  stdout=log, stderr=log)
                try:
                    wait_ready(instance.proxy, args.root, args.admin_port)
                    for engine in engines:
                        before_connections = len(connections)
                        results[engine] = exercise_engine(instance, engine, contacts,
                                                         reused is not None and engine == "hyperlight", connections)
                        if args.tls:
                            assert len(connections) > before_connections, connections
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
    assert not (args.root / "data/ready.json").exists()
    assert not list((args.root / "data").glob("job-hyperlight-*"))
    if args.tls:
        # Shutdown flushes the ordinary audit writer. Keep the complete private
        # audit and raw job streams even when the exact refusal assertion fails.
        rows = [json.loads(line) for line in (args.root / "logs/audit.jsonl").read_text().splitlines()]
        runs = [run for result in results.values() for run in
                (result["denied_direct"], result["denied"]["evidence"]["execution"]["run_id"])]
        check_connect_audit(rows, runs, args.upstream_port)
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
    args = parser.parse_args()
    for name in ("cli", "proxy", "bundle", "scratch"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.root = args.root.absolute()
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
