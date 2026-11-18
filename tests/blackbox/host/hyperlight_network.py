"""Exercise delegated public egress through both installed Hyperlight engines.

Run on an owning Linux KVM or physical Apple-silicon HVF host with matching
candidate CLI/proxy/bundle, Python and tomlkit. Supply a new short instance root,
empty private disk-backed scratch directory and two authorized loopback ports.
This witness needs no provider credential or Service Gateway grant. It covers
HTTP direct/named allow/removal and contact-free validation, not the whole
four-engine, TLS, ancestry, capture or lifecycle acceptance contract.

Use --continue-from with the retained partial HTTP receipt to reuse completed
Core allow/direct-denial observations. The continuation runs Core named denial
and the Unikraft cases in a fresh instance, with separate contact counters.
"""

import argparse
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomlkit
from hyperlight_services import Instance, digest, output, save, stop
from job_network import wait_ready


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


def exercise_engine(instance, engine, contacts, continuing_core):
    """Observe the selected calls and require denied calls to add no contact."""
    destination = f"127.0.0.1:{instance.args.upstream_port}"
    gate = "gate:hyperlight-network-check"
    before = len(contacts)
    subject = {"kind": "value", "value": f"http://{destination}/{engine}"}
    request = {"subject": subject, "inputs": {}}
    observed = {}
    if not continuing_core:
        instance.command("job", "validate", str(instance.scratch / f"{engine}-adopted.json"))
        instance.command("policy", "check", str(instance.scratch / "policy-candidate.toml"))
        assert len(contacts) == before
        direct = instance.run_job(engine, request)
        check_direct(direct, True)
        assert len(contacts) == before + 1
        status, named = instance.invoke(engine, {"subject": subject})
        check_named(status, named, True)
        assert len(contacts) == before + 2
        observed.update(direct=direct["run_id"], named=named)
    expected_contacts = len(contacts)
    permission = instance.policy["agents"][gate]["hosts"].pop(destination)
    instance.apply()
    if not continuing_core:
        denied_direct = instance.run_job(engine, request)
        check_direct(denied_direct, False)
        observed["denied_direct"] = denied_direct["run_id"]
    assert len(contacts) == expected_contacts
    status, denied = instance.invoke(engine, {"subject": subject})
    check_named(status, denied, False)
    assert len(contacts) == expected_contacts
    instance.policy["agents"][gate]["hosts"][destination] = permission
    instance.apply()
    return {**observed, "denied": denied}


def exercise(args):
    reused = completed_core(args)
    instance = Instance(args)
    contacts = []

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            contacts.append({"path": self.path})
            save(args.scratch / "origin-contacts.json", contacts)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass  # Only the bounded contact observations are retained.

    with ThreadingHTTPServer(("127.0.0.1", args.upstream_port), Origin) as origin:
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            instance.command("init")
            config = {"admin_port": args.admin_port, "flow_store_enabled": False,
                      "agent_api_enabled": True, "tls_ca_file": "certs/mitmproxy-ca.pem",
                      "listeners": [{"agent_id": "driver", "socket_path": str(args.root / "driver.sock")}]}
            (args.root / "config.toml").write_text(tomlkit.dumps(config))
            destination = f"127.0.0.1:{args.upstream_port}"
            gate = "gate:hyperlight-network-check"
            instance.policy = {"hosts": {"*": {"egress": "deny"}},
                               "agents": {gate: {"hosts": {destination: {"egress": "allow"}}}},
                               "controls": {"test_context": {"action": "warn"}}, "checks": {}}
            for engine in ("hyperlight", "hyperlight-unikraft"):
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
            results = {}
            report = {"engines": results, "contacts": contacts, "reused_core": reused,
                      "runtime_manifest_sha256": digest(args.bundle / "runtime.json"),
                      "cli_sha256": digest(args.cli), "proxy_sha256": digest(args.proxy)}
            save(args.scratch / "result.json", report)
            with (args.scratch / "proxy.log").open("wb") as log:
                instance.proxy = subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml")],
                                                  stdout=log, stderr=log)
                try:
                    wait_ready(instance.proxy, args.root, args.admin_port)
                    for engine in ("hyperlight", "hyperlight-unikraft"):
                        results[engine] = exercise_engine(instance, engine, contacts,
                                                         reused is not None and engine == "hyperlight")
                        save(args.scratch / "result.json", report)
                finally:
                    stop(instance.proxy)
        finally:
            origin.shutdown()
            thread.join(timeout=10)
            assert not thread.is_alive()
            save(args.scratch / "origin-contacts.json", contacts)
    assert not (args.root / "data/ready.json").exists()
    assert not list((args.root / "data").glob("job-hyperlight-*"))
    print("PASS: public HTTP direct/named allow, permission removal and validation contact counters"
          + ("; completed Core observations reused from the selected receipt" if reused else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "proxy", "bundle", "root", "scratch"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("admin-port", "upstream-port"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--continue-from", type=Path, help="retained partial Core HTTP observation receipt")
    args = parser.parse_args()
    for name in ("cli", "proxy", "bundle", "scratch"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.root = args.root.absolute()
    if args.continue_from is not None:
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
