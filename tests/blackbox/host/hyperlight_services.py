"""Exercise both real Hyperlight engines in one owned, disposable instance.

Use --unikraft-lifetimes-only to run just the four Unikraft lifetime controls.
Use --unikraft-remaining-only for spin cancellation, recovery, overlap,
changed artifacts, corrupt templates and held calls, after two fresh setup runs.

Requires matching candidate CLI/proxy, a protocol-4 bundle built on this host's
architecture, Python with tomlkit, and accessible KVM or entitled Apple-silicon
HVF. The operator supplies an existing GitHub read credential in a private file.
Only the new instance's standing grant is changed. Artifacts, captures and
private logs stay in the supplied disk-backed scratch directory.
"""

import argparse
import base64
import contextlib
import copy
import ctypes
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomlkit
from job_network import wait_ready

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from execution_receipt import ProcedureReceipt


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


def resident_bytes(pid):
    """Read this process's current resident memory without invoking ps."""
    if sys.platform == "linux":
        pages = int(Path(f"/proc/{pid}/statm").read_text().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE")
    if sys.platform == "darwin":
        # sys/resource.h: rusage_info_v0 is a UUID followed by ten uint64_t
        # fields. ri_resident_size is the seventh field after that UUID.
        usage = (ctypes.c_uint64 * 12)()
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        if library.proc_pid_rusage(ctypes.c_int(pid), ctypes.c_int(0), ctypes.byref(usage)):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return usage[8]
    raise OSError(f"resident memory sampling unavailable on {sys.platform}")


def job_result(prefix, engine, mode, *, expected_outcome=None):
    """Match an explicit job outcome and the CLI status derived from it."""
    expected = {"kind": "exit", "code": 0} if expected_outcome is None else expected_outcome
    # jobs::command_status returns 124 for timeout, 0 for complete exit 0,
    # and 1 for every other outcome. A CLI failure without a result still fails.
    expected_status = 124 if expected == {"kind": "timeout"} else 0 if expected == {"kind": "exit", "code": 0} else 1
    status_path = prefix.with_suffix(".status.json")
    stdout_path = prefix.with_suffix(".stdout")
    stderr_path = prefix.with_suffix(".stderr")
    status = json.loads(status_path.read_bytes())
    stderr = stderr_path.read_text(errors="replace")
    context = (f"{engine}/{mode}: command exit {status['returncode']}; "
               f"status={status_path}; stdout={stdout_path}; stderr={stderr_path}; "
               f"diagnostic: {stderr}")
    if status["returncode"] != expected_status:
        raise RuntimeError(f"{context}; expected command exit {expected_status}")
    try:
        result = json.loads(stdout_path.read_bytes())
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError(f"{context}; unavailable or invalid job result JSON: {error}") from error
    if (not isinstance(result, dict) or result.get("outcome") != expected
            or result.get("observation_error", "missing") is not None):
        raise RuntimeError(f"{context}; expected observed outcome {expected}; job result: {result}")
    return result


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
                                 "api.github.com": {"egress": "allow", "service": "github", "allow": ["github:*"]},
                                 "127.0.0.1": {"service": "held", "allow": ["hyperlight-fixture:*"]},
                                 f"127.0.0.1:{port}": {"egress": "allow"}},
                       "credential": {"hyperlight-fixture": {"match": [r"\Asynthetic-hyperlight-provider-secret\Z"],
                                                             "headers": ["authorization"],
                                                             "allowed_hosts": ["127.0.0.1"]}},
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
    def job(self, engine, request, *, probe=False, timeout=30, limits=None, retain=16384, definition=None,
            console=False):
        self.index += 1
        prefix = self.scratch / f"job-{self.index}"
        inputs = prefix.with_suffix(".input")
        inputs.mkdir()
        save(inputs / "request.json", request)
        spec = (json.loads((self.scratch / f"{engine}-adopted.json").read_bytes())
                if definition is None else copy.deepcopy(definition))
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
        arguments = [str(self.args.cli), "--root", str(self.root), "job", "run", str(path),
                     "--input", str(inputs)]
        if console:
            console_path = prefix.with_suffix(".console")
            assert not console_path.exists(), f"console path already exists: {console_path}"
            arguments.extend(["--console-file", str(console_path)])
        with prefix.with_suffix(".stdout").open("wb") as stdout, prefix.with_suffix(".stderr").open("wb") as stderr:
            started = time.perf_counter_ns()
            child = subprocess.Popen(arguments, stdout=stdout, stderr=stderr)
            try:
                yield child, prefix
            finally:
                stop(child)
                save(prefix.with_suffix(".status.json"), {"returncode": child.returncode,
                     "command_wall_ms": (time.perf_counter_ns() - started) / 1_000_000})

    def run_job(self, engine, request, *, expected_outcome=None, **options):
        with self.job(engine, request, **options) as (child, prefix):
            child.wait(timeout=60)
        return job_result(prefix, engine, "run_job", expected_outcome=expected_outcome)


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
    identities = set()
    for record in records:
        assert result["started_unix_ms"] <= record["started_at_ms"] <= record["ended_at_ms"] <= result["ended_unix_ms"]
        assert re.fullmatch(r"[0-9a-f]{64}", record["configuration_sha256"]), record
        # Policy::policy_hash is the established short cache identity. The
        # runtime configuration has its separate, full SHA-256 digest.
        assert re.fullmatch(r"sha256:[0-9a-f]{16}", record["policy_hash"]), record
        identities.add((record["configuration_sha256"], record["policy_hash"]))
        if record["retained_base64"] is not None:
            data = base64.b64decode(record["retained_base64"], validate=True)
            assert len(data) == record["response_bytes"]
            assert hashlib.sha256(data).hexdigest() == record["response_sha256"]
    assert len(identities) <= 1, "one invocation must retain one delegated configuration and policy"
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


def check_named_evidence(first, named, path, subject):
    assert named["evidence"]["result"]["finding"]["positive"] is True, named
    execution = named["evidence"]["execution"]
    assert execution["run_id"] != first["run_id"], execution
    # The executor hashes the exact adopted file bytes, without a prefix.
    assert execution["definition_digest"] == digest(path), execution
    assert named["evidence"]["result"]["subject"] == subject, named
    assert "retained_base64" not in execution["service_evidence"][0], execution
    assert execution["gate_principal"] == first["gate_principal"], execution


def check_engine_identity(result, engine, path):
    """Match host observations to the exact selected engine and artifact pins."""
    selected = json.loads(path.read_bytes())["engine"]
    code = selected["guest" if engine == "hyperlight" else "checker"]
    assert result["engine"] == result["rootfs"]["kind"] == engine, result
    assert result["rootfs"]["runtime_manifest_sha256"] == selected["runtime"]["sha256"], result
    assert result["rootfs"]["artifact_sha256"] == code["sha256"], result


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
    instance.run_job(engine, request, probe=True, expected_outcome={"kind": "exit", "code": 1})


def held_lifetimes(instance, engine, origin, port):
    request = {"call": {"kind": "service", "service": "held", "method": "GET",
                        "url": f"http://127.0.0.1:{port}/hold"}}
    for mode in ("deadline", "cancel", "revoke", "shutdown"):
        origin.entered.clear()
        origin.release.clear()
        # Execution17813's completed Unikraft jobs took 7.2–8.2s in total;
        # its five-second deadline expired before any provider call. Keep a
        # finite whole-job budget that leaves a held-call window after entry.
        timeout = 5 if mode == "deadline" and engine == "hyperlight" else 30
        with instance.job(engine, request, probe=True, timeout=timeout) as (child, prefix):
            assert origin.entered.wait(20), f"{engine}/{mode} never reached held provider"
            assert child.poll() is None, f"{engine}/{mode} terminated before its held-call trigger"
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
        expected = ({"kind": "timeout"} if mode == "deadline" else
                    {"kind": "interrupted", "signal": int(signal.SIGINT if mode == "cancel" else signal.SIGTERM)})
        result = job_result(prefix, engine, mode, expected_outcome=expected)
        save(prefix.with_suffix(".result.json"), result)
        assert not result["service_evidence"] or all(row["response_sha256"] is None
                                                    for row in result["service_evidence"]), result
        assert not list((instance.root / "data").glob("job-hyperlight-*")), (
            "unexpected retained runtime after a successful command; inspect its diagnostics; "
            "directory presence alone does not establish a live VM")
        if mode == "revoke":
            instance.policy["agents"]["gate:hyperlight-service-check"]["services"]["held"] = grant
            instance.apply()
        if mode == "shutdown":
            return
        # A late completion must neither resurrect nor poison the next run.
        next_request = copy.deepcopy(request)
        next_request["call"]["url"] = f"http://127.0.0.1:{port}/value"
        assert output(instance.run_job(engine, next_request, probe=True))[0]["ok"] is True


def warm_templates(instance, engine, *, remaining_only=False):
    """Observe actual construction, restored state, fresh calls and cold costs."""
    spec = json.loads((instance.args.bundle / f"{engine}.json").read_bytes())
    for name in ("runtime", "guest", "checker"):
        if name in spec["engine"]:
            spec["engine"][name]["path"] = str(instance.args.bundle / spec["engine"][name]["path"])
    if engine == "hyperlight":
        spec["engine"]["function"] = "TemplateProbe"
    else:
        path = instance.args.bundle / "template_probe.py"
        spec["engine"]["checker"] = {"path": str(path), "sha256": digest(path)}
    observations = []

    def measured(request, definition, expected=None, timeout=30):
        with instance.job(engine, request, definition=definition, timeout=timeout) as (child, prefix):
            child.wait(timeout=60)
        result = job_result(prefix, engine, "warm-template", expected_outcome=expected)
        status = json.loads(prefix.with_suffix(".status.json").read_bytes())
        try:
            idle_proxy_bytes, memory_error = resident_bytes(instance.proxy.pid), None
        except OSError as error:
            idle_proxy_bytes, memory_error = None, str(error)
        observations.append({"full_invocation_ms": status["command_wall_ms"],
                             "result": result, "provider_latency_ms": 0,
                             "idle_proxy_rss_bytes": idle_proxy_bytes,
                             "memory_observation_error": memory_error})
        save(instance.scratch / f"{engine}-templates.json", {
            "observations": observations,
            "memory_limit": ("helper_max_rss_bytes is one helper's active peak; idle_proxy_rss_bytes is "
                             "the proxy after that command. Total process-tree and page-cache memory remain unmeasured"),
            "latency_limit": "offline workload, no provider; preparation and cache save/load remain included",
        })
        return result

    first = measured({"value": "first"}, spec)
    initialized = first["runtime_report"]["initialization"]
    assert initialized["mode"] == "constructed", first
    assert initialized["initialization_events"] == 1, first
    first_output = output(first)
    assert first_output["calls"] == 1
    runtime_random = ({first_output["context"]["runtime_random"]}
                      if engine == "hyperlight-unikraft" else set())
    spec["gate_id"] = "another-template-principal"
    second = measured({"value": "second"}, spec)
    restored = second["runtime_report"]["initialization"]
    assert restored["mode"] == "restored" and restored["initialization_events"] == 0, second
    assert initialized["template_key"] == restored["template_key"]
    assert initialized["snapshot_digest"] == restored["snapshot_digest"]

    def fresh(result):
        value = output(result)
        assert value["calls"] == 1 and not value.get("inherited_file", False), value
        assert value["context"]["invocation_id"] == result["run_id"], value
        assert result["started_unix_ms"] <= value["context"]["unix_ms"] <= result["ended_unix_ms"], value
        assert value["context"]["random"] != first_output["context"]["random"], value
        if engine == "hyperlight-unikraft":
            current_random = value["context"]["runtime_random"]
            assert current_random not in runtime_random, value
            runtime_random.add(current_random)
        if result["runtime_report"]["initialization"]["mode"] == "restored":
            assert value["initialized_at"] == first_output["initialized_at"], value
        return value

    assert fresh(second)["input"] != first_output["input"]
    assert second["run_id"] != first["run_id"] and second["gate_principal"] != first["gate_principal"]
    if not remaining_only:
        cold = copy.deepcopy(spec)
        cold["engine"]["reuse_initialization"] = False
        cold_result = measured({"value": "cold"}, cold)
        assert cold_result["runtime_report"]["initialization"]["mode"] == "cold", cold_result
        fresh(cold_result)
    template_predecessors(instance, engine, spec, measured, fresh, remaining_only=remaining_only)
    # All readers have exited. Alter an actual saved manifest, then require an
    # explicit cold run of this engine instead of stale or unchecked bytes.
    directory = instance.root / "data/hyperlight-templates"
    matches = [path for path in directory.glob("template-*")
               if json.loads((path / "receipt.json").read_bytes())["key"] == restored["template_key"]]
    assert len(matches) == 1, matches
    manifest = matches[0] / "blobs/sha256" / restored["snapshot_digest"].split(":")[1]
    manifest.write_bytes(manifest.read_bytes() + b"corrupt")
    invalid = measured({"value": "corrupt template"}, spec)
    diagnostic = invalid["runtime_report"]["initialization"]
    assert diagnostic["mode"] == "cold" and "invalid or incompatible" in diagnostic["cold_reason"], invalid
    fresh(invalid)
    assert invalid["engine"] == engine
    return observations


def wait_spin_entry(child, prefix, timeout=20):
    """Wait for this invocation's console marker while the job is still live."""
    path = prefix.with_suffix(".console")
    deadline = time.monotonic() + timeout
    while child.poll() is None:
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            # The CLI creates the file after validating its arguments.
            data = b""
        if b"template-spin-entered" in data:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"spin entry was not observed within {timeout}s: {path}")
        time.sleep(0.02)
    raise RuntimeError(f"job exited before live spin entry was observed: {path}")


def template_predecessors(instance, engine, spec, measured, fresh, *, remaining_only=False):
    """A failed, expired, cancelled or overlapping call cannot donate state."""
    if not remaining_only:
        measured({"mode": "fail"}, spec, {"kind": "exit", "code": 1})
        fresh(measured({"value": "after failure"}, spec))
        timed = measured({"mode": "spin"}, spec, {"kind": "timeout"}, timeout=5)
        assert b"template-spin-entered" in base64.b64decode(timed["stdout"]["retained_base64"], validate=True), timed
        fresh(measured({"value": "after deadline"}, spec))
    with instance.job(engine, {"mode": "spin"}, definition=spec, console=True) as (child, prefix):
        wait_spin_entry(child, prefix)
        assert child.poll() is None, "spin predecessor ended before cancellation"
        child.send_signal(signal.SIGINT)
        child.wait(timeout=10)
    cancelled = job_result(prefix, engine, "cancelled template", expected_outcome={"kind": "interrupted", "signal": int(signal.SIGINT)})
    assert b"template-spin-entered" in base64.b64decode(cancelled["stdout"]["retained_base64"], validate=True), cancelled
    fresh(measured({"value": "after cancellation"}, spec))
    # Two helper lifetimes share only immutable template files and reader leases.
    with instance.job(engine, {"mode": "hold", "value": "concurrent one"}, definition=spec) as (one, prefix_one):
        with instance.job(engine, {"mode": "hold", "value": "concurrent two"}, definition=spec) as (two, prefix_two):
            assert one.poll() is None and two.poll() is None
            one.wait(timeout=60)
            two.wait(timeout=60)
    overlapping = [fresh(job_result(prefix, engine, "concurrent template")) for prefix in (prefix_one, prefix_two)]
    assert max(row["context"]["unix_ms"] for row in overlapping) < min(row["completed_unix_ms"] for row in overlapping), overlapping
    # A usable template cannot bypass verification of the selected code. Alter
    # only an owned scratch copy, preserving the original artifact and pin.
    changed = copy.deepcopy(spec)
    code = changed["engine"]["guest" if engine == "hyperlight" else "checker"]
    path = instance.scratch / f"{engine}-changed-artifact"
    path.write_bytes(b"changed after adoption")
    code["path"] = str(path)
    with instance.job(engine, {"value": "changed artifact"}, definition=changed) as (child, prefix):
        child.wait(timeout=60)
    assert json.loads(prefix.with_suffix(".status.json").read_bytes())["returncode"] != 0
    assert "digest mismatch" in prefix.with_suffix(".stderr").read_text(), prefix
    fresh(measured({"value": "after rejected artifact"}, spec))


def exercise(args):
    instance = Instance(args)
    observations = []
    engines = (("hyperlight-unikraft",) if args.unikraft_lifetimes_only or args.unikraft_remaining_only
               else ("hyperlight", "hyperlight-unikraft"))
    receipt = ProcedureReceipt("hyperlight-services", args.scratch / "result.json")
    receipt.document.update(boundary="real-hyperlight-engines", selected_engines=engines, agent="driver", guest=None,
                            controller_sha256=digest(Path(__file__)),
                            system=sys.platform, architecture=os.uname().machine,
                            cli=digest(args.cli), proxy=digest(args.proxy), bundle=digest(args.bundle / "runtime.json"),
                            engine_cases={engine: [] for engine in engines})
    save(receipt.path, receipt.document)

    def engine_case(engine, name):
        receipt.document["engine_cases"][engine].append(name)
        save(receipt.path, receipt.document)

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

    with ThreadingHTTPServer(("127.0.0.1", args.provider_port), Provider) as origin:
        origin.entered, origin.release = threading.Event(), threading.Event()
        port = origin.server_address[1]
        thread = threading.Thread(target=origin.serve_forever)
        thread.start()
        try:
            instance.prepare(port)
            for engine in engines:
                # Each engine gets a fresh proxy lifetime; grants stay standing.
                with (args.scratch / f"{engine}-proxy.log").open("wb") as log:
                    instance.proxy = subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml")],
                                                      stdout=log, stderr=log)
                    try:
                        wait_ready(instance.proxy, args.root, args.admin_port)
                        if args.warm_templates_only or args.unikraft_remaining_only:
                            receipt.document.setdefault("warm_templates", {})[engine] = warm_templates(
                                instance, engine, remaining_only=args.unikraft_remaining_only)
                            save(receipt.path, receipt.document)
                            held_lifetimes(instance, engine, origin, port)
                            engine_case(engine, "remaining-state-and-lifetimes" if args.unikraft_remaining_only
                                        else "warm-templates-and-lifetimes")
                            continue
                        if args.unikraft_lifetimes_only:
                            held_lifetimes(instance, engine, origin, port)
                            engine_case(engine, "lifetimes")
                            continue
                        spec = args.scratch / f"{engine}-adopted.json"
                        instance.command("job", "validate", str(spec))
                        request = {"subject": {"kind": "value", "value": str(args.issue)}, "inputs": {
                            "repository": args.repository, "expected_author_id": args.expected_author_id}}
                        first = instance.run_job(engine, request)
                        check_engine_identity(first, engine, spec)
                        records = captured(first)
                        receipt.document.setdefault("invocations", {})[engine] = {
                            key: first[key] for key in ("run_id", "rootfs", "input_sha256", "gate_definition_sha256",
                                                       "gate_principal", "started_unix_ms", "ended_unix_ms")}
                        assert len(records) == 1 and records[0]["service"] == "github"
                        assert records[0]["status"] == 200 and records[0]["error"] is None
                        evidence = json.loads(base64.b64decode(records[0]["retained_base64"], validate=True))
                        assert evidence["user"]["id"] == int(args.expected_author_id)
                        assert evidence["url"] == f"https://api.github.com/repos/{args.repository}/issues/{args.issue}"
                        assert output(first)["finding"]["positive"] is True
                        assert instance.invoke(engine, {"spec": "/arbitrary/path"})[0] == 400
                        status, named = instance.invoke(engine)
                        assert status == 200, named
                        check_named_evidence(first, named, spec, request["subject"])
                        named_output_bound(instance, engine, spec)
                        instance.policy["checks"][engine]["inputs"]["expected_author_id"] = "0"
                        instance.apply()
                        status, mismatch = instance.invoke(engine)
                        assert status == 200 and mismatch["evidence"]["result"]["finding"]["positive"] is False
                        instance.policy["checks"][engine]["inputs"]["expected_author_id"] = args.expected_author_id
                        services = instance.policy["agents"]["gate:hyperlight-service-check"]["services"]
                        grant = services.pop("github")
                        instance.apply()
                        instance.run_job(engine, request, expected_outcome={"kind": "exit", "code": 1})
                        services["github"] = grant
                        instance.apply()
                        assert output(instance.run_job(engine, request))["finding"]["positive"] is True
                        engine_case(engine, "permitted")
                        scope_and_limits(instance, engine, port)
                        engine_case(engine, "scope-limits")
                        held_lifetimes(instance, engine, origin, port)
                        engine_case(engine, "lifetimes")
                        if engine == "hyperlight":
                            receipt.checkpoint("hyperlight")
                        else:
                            receipt.checkpoint("hyperlight-unikraft")
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
    receipt.checkpoint("provider")
    assert not (args.root / "data/ready.json").exists()
    assert not list((args.root / "data").glob("job-hyperlight-*"))
    receipt.checkpoint("cleanup")
    checks = ("remaining Unikraft state and held-call lifetimes" if args.unikraft_remaining_only else
              "initialized templates, cold comparison and held lifetimes" if args.warm_templates_only else
              "held deadline/cancel/revoke/shutdown lifetimes" if args.unikraft_lifetimes_only else
              "live GitHub, standing grant/removal, named input/typed mismatch, scope/limits, held lifetimes")
    save(args.scratch / "result.json", {"engines": engines, "checks": checks,
                                      "bundle": digest(args.bundle / "runtime.json"),
                                      "cli": digest(args.cli), "proxy": digest(args.proxy)})
    receipt.checkpoint("finished")
    print(f"PASS {', '.join(engines)}: {checks}")
    if not receipt.document["complete"]:
        print("Incomplete two-engine receipt: only the selected focused controls were exercised")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("cli", "proxy", "bundle", "github-token-file", "scratch", "root"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--issue", type=int, required=True)
    parser.add_argument("--expected-author-id", required=True)
    parser.add_argument("--parent-proxy")
    parser.add_argument("--admin-port", type=int, required=True)
    parser.add_argument("--provider-port", type=int, default=0,
                        help="select an authorized loopback provider port; zero asks the OS on unrestricted test hosts")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--unikraft-lifetimes-only", action="store_true",
                        help="run only the remaining Unikraft deadline/cancel/revoke/shutdown controls in a fresh instance")
    modes.add_argument("--warm-templates-only", action="store_true",
                        help="exercise initialized restores, fresh state, cold comparison and existing held lifetimes")
    modes.add_argument("--unikraft-remaining-only", action="store_true",
                       help="run remaining Unikraft state/lifetime windows; construct and restore one fresh setup template")
    args = parser.parse_args()
    for name in ("cli", "proxy", "bundle", "github_token_file", "scratch"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.root = args.root.absolute()
    if not 1 <= args.admin_port <= 65535:
        parser.error("--admin-port must be a nonzero authorized port")
    if not 0 <= args.provider_port <= 65535:
        parser.error("--provider-port must be zero or an authorized port")
    if args.root.exists() or any(args.scratch.iterdir()):
        parser.error("--root must be new and --scratch must be empty")
    args.scratch.chmod(0o700)
    if len(str(args.root / "driver.sock").encode()) >= 100:
        parser.error("choose a short root for the host's Unix socket limit")
    exercise(args)


if __name__ == "__main__":
    main()
