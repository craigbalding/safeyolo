"""Exercise both real Hyperlight engines in one owned, disposable instance.

Requires matching candidate CLI/proxy, a protocol-3 bundle built on this host's
architecture, Python with tomlkit, and accessible KVM or entitled Apple-silicon
HVF. The operator supplies an existing GitHub read credential in a private file.
Only the new instance's standing grant is changed. Artifacts, captures and
private logs stay in the supplied disk-backed scratch directory.
"""

import argparse
import base64
import contextlib
import copy
import hashlib
import http.client
import json
import os
import signal
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomlkit
from job_network import wait_ready


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def stop(child):
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=30)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
        raise


class Instance:
    def __init__(self, args):
        self.args = args
        self.root = args.root
        self.scratch = args.scratch
        self.policy = None
        self.proxy = None
        self.index = 0

    def command(self, *arguments, input=None):
        return subprocess.run([str(self.args.cli), "--root", str(self.root), *arguments],
                              input=input, check=True, capture_output=True)

    def prepare(self, port):
        self.command("init")
        # No platform guest, installer, vault export or original-instance edit.
        config = {"admin_port": self.args.admin_port, "flow_store_enabled": False, "agent_api_enabled": True,
                  "tls_ca_file": "certs/mitmproxy-ca.pem", "listeners": [
                      {"agent_id": "driver", "socket_path": str(self.root / "driver.sock")}]}
        if self.args.parent_proxy:
            config["parent_proxy"] = self.args.parent_proxy
        if os.environ.get("SSL_CERT_FILE"):
            config["upstream_ca_file"] = os.environ["SSL_CERT_FILE"]
        (self.root / "config.toml").write_text(tomlkit.dumps(config))
        github_path = f"/repos/{self.args.repository}/issues/{self.args.issue}"
        for name, host, paths, allow_http in [
            ("github", "api.github.com", [github_path], False),
            ("held", "127.0.0.1", ["/value", "/hold", "/large", "/redirect", "/failure"], True),
        ]:
            definition = {"schema_version": 1, "name": name, "default_host": host,
                          "auth": {"type": "bearer", "allow_http": allow_http}, "capabilities": {
                              "read_work": {"routes": [{"methods": ["GET"], "path": path} for path in paths]}}}
            save(self.root / "services" / f"{name}.yaml", definition)
        self.command("credentials", "add", "live-github", "--stdin", "--storage", "local",
                     input=self.args.github_token_file.read_bytes().strip() + b"\n")
        self.command("credentials", "add", "held-secret", "--stdin", "--storage", "local",
                     input=b"synthetic-hyperlight-provider-secret\n")
        self.policy = {"hosts": {"*": {"egress": "deny"},
                                 "api.github.com": {"egress": "allow", "service": "github"},
                                 "127.0.0.1": {"service": "held"},
                                 f"127.0.0.1:{port}": {"egress": "allow"}},
                       "agents": {"gate:hyperlight-service-check": {"services": {
                           "github": {"capability": "read_work", "token": "live-github"},
                           "held": {"capability": "read_work", "token": "held-secret"}}}},
                       "controls": {"test_context": {"action": "warn"}}, "checks": {}}
        for engine in ("hyperlight", "hyperlight-unikraft"):
            spec = json.loads((self.args.bundle / f"{engine}-service.json").read_bytes())
            for key in ("runtime", "guest", "checker"):
                if key in spec["engine"]:
                    spec["engine"][key]["path"] = str(self.args.bundle / spec["engine"][key]["path"])
            spec["timeout_seconds"] = 30
            spec["mediated_services"]["services"].append("held")
            path = self.scratch / f"{engine}-adopted.json"
            save(path, spec)
            definition = {"source_id": "github-issue-author", "meaning": "GitHub recorded issue author matches the adopted stable user ID",
                          "subject": "value", "result_type": "finding", "influences": ["hard_exclusion"],
                          "implementation_version": digest(self.args.bundle / ("core.elf" if engine == "hyperlight" else "service_checker.py")),
                          "configuration_version": digest(path), "max_age_seconds": 60, "invokers": ["driver"],
                          "inputs": {"repository": self.args.repository, "expected_author_id": self.args.expected_author_id},
                          "source": {"kind": "job", "spec": str(path), "effects": "passive", "limits": {
                              "timeout_ms": 40_000, "max_input_bytes": 16384, "max_output_bytes": 16384,
                              "max_concurrent": 1, "max_pending": 1, "max_cached": 0}}}
            self.policy["checks"][engine] = definition
        self.apply(initial=True)

    def apply(self, initial=False):
        candidate = self.scratch / "policy-candidate.toml"
        candidate.write_text(tomlkit.dumps(self.policy))
        if initial:
            (self.root / "policy.toml").write_bytes(candidate.read_bytes())
        else:
            self.command("policy", "check", str(candidate))
            # Revoking an accepted transport can consume the existing ten-second
            # teardown grace. Keep the observer alive through that real bound.
            connection = http.client.HTTPConnection("127.0.0.1", self.args.admin_port, timeout=30)
            try:
                connection.request("PUT", "/admin/policy/baseline", json.dumps({"source": candidate.read_text()}),
                                   {"Authorization": "Bearer " + (self.root / "data/admin_token").read_text().strip(),
                                    "Content-Type": "application/json"})
                response = connection.getresponse()
                status, result = response.status, json.load(response)
            finally:
                connection.close()
            self.index += 1
            save(self.scratch / f"policy-activation-{self.index}.json", {"status": status, "body": result})
            assert status == 200 and result["status"] == "active", result

    def invoke(self, name, extra=None):
        # HTTPConnection handles ordinary and chunked response framing.
        connection = http.client.HTTPConnection("_safeyolo.proxy.internal", timeout=60)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(60)
        connection.sock.connect(str(self.root / "driver.sock"))
        body = {"check": name, "subject": {"kind": "value", "value": str(self.args.issue)}}
        body.update(extra or {})
        try:
            connection.request("POST", "http://_safeyolo.proxy.internal/checks/invoke", json.dumps(body),
                               {"Authorization": "Bearer " + (self.root / "data/agent_token").read_text().strip(),
                                "Content-Type": "application/json"})
            response = connection.getresponse()
            status, value = response.status, json.load(response)
        finally:
            connection.close()
        self.index += 1
        save(self.scratch / f"named-{self.index}.json", {"status": status, "body": value})
        return status, value

    @contextlib.contextmanager
    def job(self, engine, request, *, probe=False, timeout=30, limits=None, retain=16384):
        self.index += 1
        prefix = self.scratch / f"job-{self.index}"
        inputs = prefix.with_suffix(".input")
        inputs.mkdir()
        save(inputs / "request.json", request)
        spec = json.loads((self.scratch / f"{engine}-adopted.json").read_bytes())
        spec.update(timeout_seconds=timeout, retain_bytes=retain, max_input_bytes=100_000)
        if limits:
            spec["mediated_services"].update(limits)
        if probe:
            if engine == "hyperlight":
                spec["engine"]["function"] = "ServiceProbe"
            else:
                spec["argv"].append("--isolation-probe" if probe == "isolation" else "--probe")
        path = prefix.with_suffix(".spec.json")
        save(path, spec)
        with prefix.with_suffix(".stdout").open("wb") as stdout, prefix.with_suffix(".stderr").open("wb") as stderr:
            child = subprocess.Popen([str(self.args.cli), "--root", str(self.root), "job", "run", str(path),
                                      "--input", str(inputs)], stdout=stdout, stderr=stderr)
            try:
                yield child, prefix
            finally:
                stop(child)
                save(prefix.with_suffix(".status.json"), {"returncode": child.returncode})

    def run_job(self, engine, request, **options):
        with self.job(engine, request, **options) as (child, prefix):
            child.wait(timeout=60)
        return json.loads(prefix.with_suffix(".stdout").read_bytes())


def output(result):
    stream = result["stdout"]
    data = base64.b64decode(stream["retained_base64"], validate=True)
    assert stream["bytes"] == len(data), "truncated output cannot be a finding"
    assert hashlib.sha256(data).hexdigest() == stream["sha256"]
    return json.loads(data)


def captured(result):
    assert result["observation_error"] is None, result
    assert result["outcome"] == {"kind": "exit", "code": 0}, result
    assert result["gate_principal"] == result["authorization_principal"] == "gate:hyperlight-service-check"
    assert result["runtime_report"]["error"] is None
    assert result["rootfs"]["service_access"] == "mediated"
    for key in ("runtime_manifest_sha256", "artifact_sha256"):
        assert len(result["rootfs"][key]) == 64
    assert len(result["input_sha256"]) == len(result["gate_definition_sha256"]) == 64
    records = result["service_evidence"]
    for record in records:
        assert result["started_unix_ms"] <= record["started_at_ms"] <= record["ended_at_ms"] <= result["ended_unix_ms"]
        assert len(record["configuration_sha256"]) == len(record["policy_hash"]) == 64
        if record["retained_base64"] is not None:
            data = base64.b64decode(record["retained_base64"], validate=True)
            assert len(data) == record["response_bytes"]
            assert hashlib.sha256(data).hexdigest() == record["response_sha256"]
    return records


def named_output_bound(instance, engine, path):
    original = path.read_bytes()
    spec = json.loads(original)
    spec["retain_bytes"] = 8
    try:
        save(path, spec)
        status, value = instance.invoke(engine)
        assert status == 200 and value["evidence"]["result"] is None, value
        assert "output limit" in value["evidence"]["unavailable"], value
    finally:
        path.write_bytes(original)


def scope_and_limits(instance, engine, port):
    github = f"https://api.github.com/repos/{instance.args.repository}/issues/{instance.args.issue}"
    for call in [
        {"service": "github", "method": "POST", "url": github},
        {"service": "github", "method": "GET", "url": github + "/comments"},
        {"service": "github", "method": "GET", "url": "https://api.github.com/repos/other/repo/issues/1"},
        {"service": "github", "method": "GET", "url": "https://denied.invalid/value"},
        {"service": "github", "method": "GET", "url": "http://127.0.0.2/value"},
        {"service": "github", "method": "GET", "url": "dns://api.github.com"},
        {"service": "github", "method": "CONNECT", "url": github},
        {"service": "held", "method": "GET", "url": f"http://127.0.0.1:{port}/redirect"},
        {"service": "held", "method": "GET", "url": f"http://127.0.0.1:{port}/failure"},
    ]:
        result = instance.run_job(engine, {"call": {"kind": "service", **call}}, probe=True)
        assert output(result)[0]["ok"] is False, result
    for kind in ("socket", "dns"):
        result = instance.run_job(engine, {"call": {"kind": kind, "destination": "api.github.com"}}, probe=True)
        assert output(result)[0]["ok"] is False, result
    if engine == "hyperlight-unikraft":
        result = output(instance.run_job(engine, {"port": port}, probe="isolation"))
        assert result["socket"]["unavailable"] and result["dns"]["unavailable"], result
        assert result["credentials_absent"] and result["host_tokens_absent"], result
    request = {"call": {"kind": "service", "service": "held", "method": "GET",
                        "url": f"http://127.0.0.1:{port}/value"}, "repeat": 2}
    result = instance.run_job(engine, request, probe=True, limits={"max_calls": 1})
    replies = output(result)
    assert replies[0]["ok"] is True and replies[1]["ok"] is False
    assert "call limit" in replies[1]["error"]
    request["repeat"] = 1
    request["call"]["url"] = f"http://127.0.0.1:{port}/large"
    result = instance.run_job(engine, request, probe=True, limits={"max_response_bytes": 32})
    assert output(result)[0]["ok"] is False
    record = result["service_evidence"][0]
    assert "limit exceeded" in record["error"] and record["retained_base64"] is None
    request["call"]["url"] = "https://api.github.com/" + "x" * 50_000
    result = instance.run_job(engine, request, probe=True)
    assert result["outcome"] != {"kind": "exit", "code": 0}, result


def held_lifetimes(instance, engine, origin, port):
    request = {"call": {"kind": "service", "service": "held", "method": "GET",
                        "url": f"http://127.0.0.1:{port}/hold"}}
    for mode in ("deadline", "cancel", "revoke", "shutdown"):
        origin.entered.clear()
        origin.release.clear()
        with instance.job(engine, request, probe=True, timeout=5 if mode == "deadline" else 30) as (child, prefix):
            assert origin.entered.wait(20), f"{engine}/{mode} never reached held provider"
            if mode == "cancel":
                child.send_signal(signal.SIGINT)
            elif mode == "revoke":
                grant = instance.policy["agents"]["gate:hyperlight-service-check"]["services"].pop("held")
                instance.apply()
            elif mode == "shutdown":
                stop(instance.proxy)
            child.wait(timeout=45)
            # Deliver late success only after the owning helper has terminated.
            origin.release.set()
        result = json.loads(prefix.with_suffix(".stdout").read_bytes())
        save(prefix.with_suffix(".result.json"), result)
        assert result["outcome"] != {"kind": "exit", "code": 0}, result
        assert not result["service_evidence"] or all(row["response_sha256"] is None
                                                    for row in result["service_evidence"]), result
        assert not list((instance.root / "data").glob("job-hyperlight-*")), "owned VM runtime remains"
        if mode == "revoke":
            instance.policy["agents"]["gate:hyperlight-service-check"]["services"]["held"] = grant
            instance.apply()
        if mode == "shutdown":
            return
        # A late completion must neither resurrect nor poison the next run.
        next_request = copy.deepcopy(request)
        next_request["call"]["url"] = f"http://127.0.0.1:{port}/value"
        assert output(instance.run_job(engine, next_request, probe=True))[0]["ok"] is True


def exercise(args):
    instance = Instance(args)
    observations = []

    class Provider(BaseHTTPRequestHandler):
        def do_GET(self):
            observations.append({"path": self.path, "credential_replaced":
                                 self.headers.get("Authorization") == "Bearer synthetic-hyperlight-provider-secret",
                                 "gateway_token_leaked": any("sgw_" in value for value in self.headers.values())})
            if self.path == "/hold":
                origin.entered.set()
                origin.release.wait(60)
            status = 302 if self.path == "/redirect" else 503 if self.path == "/failure" else 200
            body = json.dumps({"value": "a" * (100_000 if self.path == "/large" else 1)}).encode()
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "http://denied.invalid/escaped")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # Revocation deliberately closes the provider transport first.
                pass

        def log_message(self, *_args):
            pass  # Only sanitized, private observations are retained.

    with ThreadingHTTPServer(("127.0.0.1", 0), Provider) as origin:
        origin.entered, origin.release = threading.Event(), threading.Event()
        port = origin.server_address[1]
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            instance.prepare(port)
            for engine in ("hyperlight", "hyperlight-unikraft"):
                # Each engine gets a fresh proxy lifetime; grants stay standing.
                with (args.scratch / f"{engine}-proxy.log").open("wb") as log:
                    instance.proxy = subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml")],
                                                      stdout=log, stderr=log)
                    try:
                        wait_ready(instance.proxy, args.root, args.admin_port)
                        spec = args.scratch / f"{engine}-adopted.json"
                        instance.command("job", "validate", str(spec))
                        request = {"subject": {"kind": "value", "value": str(args.issue)}, "inputs": {
                            "repository": args.repository, "expected_author_id": args.expected_author_id}}
                        first = instance.run_job(engine, request)
                        records = captured(first)
                        assert len(records) == 1 and records[0]["service"] == "github"
                        assert records[0]["status"] == 200 and records[0]["error"] is None
                        evidence = json.loads(base64.b64decode(records[0]["retained_base64"], validate=True))
                        assert evidence["user"]["id"] == int(args.expected_author_id)
                        assert evidence["url"] == f"https://api.github.com/repos/{args.repository}/issues/{args.issue}"
                        assert output(first)["finding"]["positive"] is True
                        assert instance.invoke(engine, {"spec": "/arbitrary/path"})[0] == 400
                        status, named = instance.invoke(engine)
                        assert status == 200 and named["evidence"]["result"]["finding"]["positive"] is True, named
                        execution = named["evidence"]["execution"]
                        assert execution["run_id"] != first["run_id"]
                        assert execution["definition_digest"] == "sha256:" + digest(spec)
                        assert named["evidence"]["result"]["subject"] == {"kind": "value", "value": str(args.issue)}
                        assert "retained_base64" not in execution["service_evidence"][0]
                        assert execution["gate_principal"] == first["gate_principal"]
                        named_output_bound(instance, engine, spec)
                        instance.policy["checks"][engine]["inputs"]["expected_author_id"] = "0"
                        instance.apply()
                        status, mismatch = instance.invoke(engine)
                        assert status == 200 and mismatch["evidence"]["result"]["finding"]["positive"] is False
                        instance.policy["checks"][engine]["inputs"]["expected_author_id"] = args.expected_author_id
                        services = instance.policy["agents"]["gate:hyperlight-service-check"]["services"]
                        grant = services.pop("github")
                        instance.apply()
                        denied = instance.run_job(engine, request)
                        assert denied["outcome"] != {"kind": "exit", "code": 0}, denied
                        services["github"] = grant
                        instance.apply()
                        assert output(instance.run_job(engine, request))["finding"]["positive"] is True
                        scope_and_limits(instance, engine, port)
                        held_lifetimes(instance, engine, origin, port)
                    finally:
                        origin.release.set()
                        stop(instance.proxy)
                        save(args.scratch / "provider-observations.json", observations)
        finally:
            origin.release.set()
            origin.shutdown()
            thread.join(timeout=10)
            assert not thread.is_alive()
    assert all(row["credential_replaced"] and not row["gateway_token_leaked"] for row in observations), observations
    assert not (args.root / "data/ready.json").exists()
    assert not list((args.root / "data").glob("job-hyperlight-*"))
    save(args.scratch / "result.json", {"engines": ["hyperlight", "hyperlight-unikraft"],
                                      "checks": "live GitHub, standing grant/removal, named input/typed mismatch, scope/limits, held lifetimes",
                                      "bundle": digest(args.bundle / "runtime.json"),
                                      "cli": digest(args.cli), "proxy": digest(args.proxy)})
    print("PASS both real engines: mediated authority, typed evidence, limits and held-call lifetimes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("cli", "proxy", "bundle", "github-token-file", "scratch", "root"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--issue", type=int, required=True)
    parser.add_argument("--expected-author-id", required=True)
    parser.add_argument("--parent-proxy")
    parser.add_argument("--admin-port", type=int, required=True)
    args = parser.parse_args()
    for name in ("cli", "proxy", "bundle", "github_token_file", "scratch"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.root = args.root.absolute()
    if not 1 <= args.admin_port <= 65535:
        parser.error("--admin-port must be a nonzero authorized port")
    if args.root.exists() or any(args.scratch.iterdir()):
        parser.error("--root must be new and --scratch must be empty")
    args.scratch.chmod(0o700)
    if len(str(args.root / "driver.sock").encode()) >= 100:
        parser.error("choose a short root for the host's Unix socket limit")
    exercise(args)


if __name__ == "__main__":
    main()
