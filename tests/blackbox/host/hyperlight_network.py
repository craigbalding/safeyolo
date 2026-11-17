"""Exercise delegated public egress through both installed Hyperlight engines.

Run on an owning Linux KVM or physical Apple-silicon HVF host with matching
candidate CLI/proxy/bundle, Python and tomlkit. Supply a new short instance root,
empty private disk-backed scratch directory and two authorized loopback ports.
This witness needs no provider credential or Service Gateway grant. It covers
HTTP direct/named allow/removal and contact-free validation, not the whole
four-engine, TLS, ancestry, capture or lifecycle acceptance contract.
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


def exercise(args):
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
            paths = {}
            for engine in ("hyperlight", "hyperlight-unikraft"):
                spec = json.loads((args.bundle / f"{engine}-network.json").read_bytes())
                for key in ("runtime", "guest", "checker"):
                    if key in spec["engine"]:
                        spec["engine"][key]["path"] = str(args.bundle / spec["engine"][key]["path"])
                spec["timeout_seconds"] = 30
                path = args.scratch / f"{engine}-adopted.json"
                save(path, spec)
                paths[engine] = path
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
            with (args.scratch / "proxy.log").open("wb") as log:
                instance.proxy = subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml")],
                                                  stdout=log, stderr=log)
                try:
                    wait_ready(instance.proxy, args.root, args.admin_port)
                    for engine, spec_path in paths.items():
                        before = len(contacts)
                        instance.command("job", "validate", str(spec_path))
                        instance.command("policy", "check", str(args.scratch / "policy-candidate.toml"))
                        assert len(contacts) == before
                        subject = {"kind": "value", "value": f"http://{destination}/{engine}"}
                        request = {"subject": subject, "inputs": {}}
                        direct = instance.run_job(engine, request)
                        assert output(direct)["finding"]["positive"] is True
                        assert direct["gate_principal"] == direct["authorization_principal"] == gate
                        assert direct["rootfs"]["network"] is True
                        assert direct["service_evidence"] == []
                        assert len(contacts) == before + 1
                        status, named = instance.invoke(engine, {"subject": subject})
                        assert status == 200 and named["evidence"]["result"]["finding"]["positive"] is True, named
                        assert len(contacts) == before + 2
                        permission = instance.policy["agents"][gate]["hosts"].pop(destination)
                        instance.apply()
                        with instance.job(engine, request) as (child, prefix):
                            child.wait(timeout=60)
                        assert json.loads(prefix.with_suffix(".status.json").read_bytes())["returncode"] == 1
                        status, denied = instance.invoke(engine, {"subject": subject})
                        assert status == 200 and denied["evidence"].get("unavailable"), denied
                        assert len(contacts) == before + 2
                        instance.policy["agents"][gate]["hosts"][destination] = permission
                        instance.apply()
                        results[engine] = {"direct": direct["run_id"], "named": named, "denied": denied}
                        save(args.scratch / "result.json", {"engines": results, "contacts": contacts,
                             "runtime_manifest_sha256": digest(args.bundle / "runtime.json"),
                             "cli_sha256": digest(args.cli), "proxy_sha256": digest(args.proxy)})
                finally:
                    stop(instance.proxy)
        finally:
            origin.shutdown()
            thread.join(timeout=10)
            assert not thread.is_alive()
            save(args.scratch / "origin-contacts.json", contacts)
    assert not (args.root / "data/ready.json").exists()
    assert not list((args.root / "data").glob("job-hyperlight-*"))
    print("PASS: both-engine public HTTP direct/named allow, permission removal and validation contact counters")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "proxy", "bundle", "root", "scratch"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("admin-port", "upstream-port"):
        parser.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    for name in ("cli", "proxy", "bundle", "scratch"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.root = args.root.absolute()
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
