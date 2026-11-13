"""Exercise the shipped authoring workflow against installed policy boundaries.

Fixtures never visit live malicious infrastructure. The ordinary native
installer supplies the host layout; real UDS traffic observes feed/RDAP
composition, offline preview, activation and destination effects. Separate
operator execution owns real sandbox/research acceptance.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import tomlkit

from tests.proxy_contracts.harness import child_process, request, wait_ready
from tests.proxy_contracts.test_native_policy_cli import NativeInstance, native_inputs, native_instance

REPO = Path(__file__).resolve().parents[2]
SKILL = REPO / "cli/src/safeyolo/agent_context/skills/policy-authoring"
SPEC = importlib.util.spec_from_file_location("policy_author", SKILL / "scripts/author.py")
AUTHOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHOR)


def preferences():
    return json.loads((SKILL / "assets/preferences.json").read_text())


@contextmanager
def recipe_instance(directory, source, *, services, parent_proxy, service_sources):
    """Use installation by default; explicitly scoped source proof needs no runtime.

    The source mode exercises identical authoring/admission commands but does
    not establish package integrity, installer behavior or guest isolation.
    """
    if os.environ.get("SAFEYOLO_AUTHORING_LAYOUT") != "source":
        with native_instance(directory, source=source, services=services, parent_proxy=parent_proxy,
                             service_sources=service_sources,
                             extra_config='tls_ca_file="certs/mitmproxy-ca.pem"\n') as instance:
            # The shared fixture restricts PATH to installed binaries. Feed
            # acquisition also needs the documented host curl prerequisite,
            # including in the proxy's automatic refresh process.
            transport = instance.root / "bin/curl"
            transport.symlink_to(shutil.which("curl"))
            try:
                yield instance
            finally:
                transport.unlink()
        return
    root = directory / "source-layout"
    host = native_inputs()[0]
    initialized = subprocess.run([str(host / "safeyolo"), "--root", str(root), "init"], capture_output=True, text=True)
    assert initialized.returncode == 0, initialized.stderr
    (root / "bin").mkdir()
    for binary in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        (root / "bin" / binary).symlink_to(host / binary)
    shutil.copytree(SKILL, root / "assets/skills/policy-authoring", ignore=shutil.ignore_patterns("__pycache__"))
    (root / "policy.toml").write_text(source)
    for name, content in service_sources.items():
        (root / "services" / name).write_text(content)
    with tempfile.TemporaryDirectory(prefix="sy-cyber-") as sockets:
        paths = {"alice": str(Path(sockets) / "alice.sock")}
        (root / "config.toml").write_text(tomlkit.dumps({
            "admin_port": 0, "flow_store_enabled": False, "agent_api_enabled": True,
            "parent_proxy": parent_proxy, "gateway_services_dir": "services",
            "tls_ca_file": "certs/mitmproxy-ca.pem",
            "gateway_builtin_services_dir": "builtin-services",
            "listeners": [{"agent_id": "alice", "socket_path": paths["alice"]}],
        }))
        environment = dict(os.environ, SAFEYOLO_HOME=str(root), SAFEYOLO_CONFIG_DIR=str(root))
        with child_process([str(root / "bin/safeyolo-proxy"), "--config", str(root / "config.toml")], root, environment) as process:
            ready = root / "data/ready.json"
            wait_ready(process, [ready, Path(paths["alice"])], root / "process.log", readiness_file=ready,
                       expected_backend="rust-m2")
            yield NativeInstance(root, process, paths, environment)


def test_author_preserves_inline_identity_controls_and_rejects_changed_owned_blocks(tmp_path):
    choices = preferences()
    original = tomlkit.parse('''# selected controls
budget = 42
agents = {research = {id="retained", hosts={"kept.test"={egress="deny"}}}}
[hosts."*"]
egress="deny"
[controls.credentials]
action="block"
''')
    result = AUTHOR.compose(original, choices, None)
    assert result["agents"]["research"]["id"] == "retained"
    assert result["agents"]["research"]["hosts"]["kept.test"]["egress"] == "deny"
    assert result["hosts"]["*"]["egress"] == "deny"
    assert result["budget"] == 42 and result["controls"]["credentials"]["action"] == "block"
    updated = copy.deepcopy(choices)
    updated.update(threshold_days=7, unknown_action="unresolved")
    changed = AUTHOR.compose(tomlkit.parse(tomlkit.dumps(result)), updated, choices)
    assert changed["check_rules"][1]["when"]["seconds"] == 7 * 86400
    assert changed["check_rules"][1]["on_unavailable"] == "unresolved"
    assert changed["agents"]["research"]["id"] == "retained"
    changed["checks"][AUTHOR.REGISTERED]["max_age_seconds"] = 3
    with pytest.raises(ValueError, match="differs from the saved recipe"):
        AUTHOR.compose(changed, updated, updated)
    with pytest.raises(ValueError, match="differs from the saved recipe"):
        AUTHOR.compose(result, choices, None)


@pytest.mark.parametrize("linked", [False, True])
def test_generator_keeps_nondefault_policy_paths_and_sources_private(tmp_path, linked):
    root = tmp_path / "instance"
    root.mkdir()
    selected = root / "selected"
    selected.mkdir()
    (root / "config.toml").write_text('policy_file="selected/current.toml"\n')
    policy = selected / "current.toml"
    if linked:
        backing = root / "backing"
        backing.mkdir()
        policy.symlink_to(backing / "current.toml")
        (backing / "existing.txt").write_text("different.test\n")
    policy.write_text('''[hosts."*"]
egress="deny"
[lists]
local="existing.txt"
[checks.retained_recorded.source]
kind="recorded"
path="recorded.json"
[checks.retained_job.source]
kind="job"
spec="job.json"
''')
    (selected / "existing.txt").write_text("kept.test\n")
    (selected / "recorded.json").write_text("[]")
    (selected / "job.json").write_text("{}")
    (selected / "policy-feeds.toml").write_text('[sources.retained]\nendpoint="https://retained.test/list"\n')
    sources = tmp_path / "sources.toml"
    sources.write_text('[sources.hagezi]\nendpoint="https://selected.test/list"\n')
    choice_path = tmp_path / "preferences.json"
    choice_path.write_text(json.dumps(preferences()))
    command = [sys.executable, str(SKILL / "scripts/author.py"), "--root", str(root),
               "--choices", str(choice_path), "--sources", str(sources), "--output", str(tmp_path / "candidate")]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    candidate = tomllib.loads((tmp_path / "candidate/candidate.toml").read_text())
    assert candidate["lists"]["local"] == str(selected / "existing.txt")
    assert Path(candidate["lists"]["local"]).read_text() == "kept.test\n"
    assert candidate["checks"]["retained_recorded"]["source"]["path"] == str(selected / "recorded.json")
    assert candidate["checks"]["retained_job"]["source"]["spec"] == str(selected / "job.json")
    assert candidate["hosts"]["*"]["egress"] == "deny"
    assert set(tomllib.loads((tmp_path / "candidate/sources.toml").read_text())["sources"]) == {"retained", "hagezi"}
    for output in (tmp_path / "candidate").iterdir():
        assert output.stat().st_mode & 0o777 == 0o600
    assert "cyber_threats" not in (selected / "current.toml").read_text()
    assert (selected / "policy-feeds.toml").read_text().count("endpoint") == 1
    assert subprocess.run(command, capture_output=True).returncode != 0


@contextmanager
def research_origin(cases):
    by_host = {case["host"]: case for case in cases}
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            calls.append((url.hostname, url.path))
            status = 200
            headers = {}
            if url.hostname == "feeds.test":
                body = b"listed.test\nspare.test\n"
            elif url.hostname == "127.0.0.1":
                host = url.path.rsplit("/", 1)[-1]
                case = by_host.get(host, {"days": 90})
                if case.get("timeout"):
                    time.sleep(0.3)
                date = (datetime.now(UTC) - timedelta(days=case.get("days", 90))).isoformat()
                body = json.dumps({"objectClassName": "domain", "ldhName": case.get("record_domain", host),
                                   "events": [{"eventAction": case.get("event", "registration"), "eventDate": date},
                                              {"eventAction": "last changed", "eventDate": datetime.now(UTC).isoformat()}]}).encode()
            elif url.hostname == "redirect.test":
                status = 302
                headers["Location"] = "http://listed.test/report"
                body = b"redirect fixture"
            else:
                body = b"controlled reporting source"
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # A successful timeout/cancellation closes its own dependency.
                if not (url.hostname == "127.0.0.1" and by_host.get(host, {}).get("timeout")):
                    raise

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        yield server.server_port, calls
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def test_installed_authoring_feed_rdap_preview_activation_and_adverse_cases(tmp_path):
    cases = json.loads((SKILL / "assets/adverse-cases.json").read_text())["cases"]
    choices = preferences()
    choices.update(agent="alice", registration_timeout_ms=100, destinations=[])
    with research_origin(cases) as (port, calls):
        choices.update(registration_endpoint=f"http://127.0.0.1:{port}", registration_path="/rdap/{subject}")
        base = '[hosts."*"]\negress="allow"\n[controls.network]\nhomoglyph=false\n'
        service = {"schema_version": 1, "name": AUTHOR.SERVICE, "default_host": "127.0.0.1",
                   "capabilities": {"lookup": {"routes": [{"methods": ["GET"], "path": "/rdap/*"}]}}}
        with recipe_instance(tmp_path, source=base, services=True, parent_proxy=f"http://127.0.0.1:{port}",
                             service_sources={"cyber-rdap.yaml": json.dumps(service)}) as instance:
            installed_skill = instance.root / "assets/skills/policy-authoring"
            assert (installed_skill / "SKILL.md").is_file()
            operator_home = tmp_path / "operator-home"
            discovery = operator_home / ".agents/skills"
            discovery.mkdir(parents=True)
            (discovery / "policy-authoring").symlink_to(installed_skill)
            assert (discovery / "policy-authoring/SKILL.md").read_text().startswith("---\nname: policy-authoring\n")
            choice_path = tmp_path / "preferences.json"
            choice_path.write_text(json.dumps(choices))
            source_path = tmp_path / "sources.toml"
            source_path.write_text(tomlkit.dumps({"sources": {"hagezi": {
                "endpoint": "http://feeds.test/list", "format": "domains", "scope": "domain_suffix",
                "cadence_seconds": 3600, "max_age_seconds": 60, "timeout_seconds": 2, "max_bytes": 1024,
                "min_entries": 2, "max_entries": 20, "max_change_percent": 100,
                "retry_seconds": 60, "max_retry_seconds": 120, "on_unavailable": "deny", "on_stale": "deny",
            }}}))
            output = tmp_path / "authored"
            generated = subprocess.run([sys.executable, str(installed_skill / "scripts/author.py"), "--root", str(instance.root),
                                        "--choices", str(choice_path), "--sources", str(source_path), "--output", str(output)],
                                       capture_output=True, text=True)
            assert generated.returncode == 0, generated.stderr
            # Acquisition inherits the real host transport; this controlled proxy
            # owns every destination and records all contact.
            instance.environment.update(HTTP_PROXY=f"http://127.0.0.1:{port}", HTTPS_PROXY=f"http://127.0.0.1:{port}",
                                        http_proxy=f"http://127.0.0.1:{port}", https_proxy=f"http://127.0.0.1:{port}")
            configured = instance.cli("policy", "feeds", "configure", str(output / "sources.toml"))
            assert configured.returncode == 0, configured.stderr
            for command in [("services", "check", str(output / "cyber-rdap.yaml")),
                            ("policy", "check", str(output / "candidate.toml"))]:
                result = instance.cli(*command)
                assert result.returncode == 0, result.stderr
            before = len(calls)
            preview = instance.cli("policy", "evaluate", str(output / "candidate.toml"), str(output / "request.json"))
            assert preview.returncode == 0, preview.stderr
            evaluated = json.loads(preview.stdout)["result"]
            assert evaluated["evidence_mode"] == "recorded_offline" and evaluated["dependency_calls"] == []
            assert evaluated["destination_contact"] is False and len(calls) == before
            activated = instance.cli("policy", "apply", str(output / "candidate.toml"))
            assert activated.returncode == 0, activated.stderr
            assert instance.show()["saved_matches_active"] is True
            for case in cases:
                before = len(calls)
                status, headers, body = request(instance.paths["alice"], f"http://{case['host']}/report")
                assert status == case["expected"], (case, status, body)
                assert any(host == "127.0.0.1" and path == f"/rdap/{case['host']}" for host, path in calls[before:]), case
                if status == 403:
                    explanation = json.loads(body)["checks"]
                    assert explanation["evidence"][AUTHOR.REGISTERED]["result"]["finding"]["kind"] == "timestamp"
                    assert explanation["rules"][1]["truth"] == "true"
                    assert not any(host == case["host"] for host, _ in calls[before:])
                if status == 302:
                    target = next(value for name, value in headers.items() if name.lower() == "location")
                    assert target == "http://listed.test/report"
                    denied, _, _ = request(instance.paths["alice"], target)
                    assert denied == 403 and not any(host == "listed.test" for host, _ in calls)
            # Favorable dynamic finding cannot bypass a hard exclusion. With an
            # explicitly advisory list, higher-priority dynamic allow can win.
            for profile, expected in [("hard", 403), ("advisory", 200)]:
                selected = copy.deepcopy(choices)
                selected.update(profile=profile, threshold_days=300, new_domain_action="allow")
                policy = AUTHOR.compose(tomlkit.parse(base), selected, None)
                instance.apply(tomlkit.dumps(policy))
                status, _, body = request(instance.paths["alice"], "http://listed.test/report")
                assert status == expected, body
            # Explicit unknown behavior changes without losing existing controls.
            choices["unknown_action"] = "unresolved"
            policy = AUTHOR.compose(tomlkit.parse(base), choices, None)
            instance.apply(tomlkit.dumps(policy))
            for host in ("unknown.test", "timeout.test", "tenant.hosted.test", "127.0.0.2"):
                status, _, body = request(instance.paths["alice"], f"http://{host}/report")
                assert status == 503, (host, status, body)
                assert json.loads(body)["checks"]["rules"][1]["truth"] == "unavailable"
            feed = tomlkit.parse((output / "sources.toml").read_text())
            feed["sources"]["hagezi"]["max_age_seconds"] = 1
            short = tmp_path / "short-source.toml"
            short.write_text(tomlkit.dumps(feed))
            assert instance.cli("policy", "feeds", "configure", str(short)).returncode == 0
            deadline = time.monotonic() + 5
            while True:
                status, _, body = request(instance.paths["alice"], "http://clear.test/report")
                # A watcher replacement may first cancel an in-flight read.
                # Only the subsequent named stale-evidence result proves expiry.
                evidence = json.loads(body).get("checks", {}).get("evidence", {}) if status == 503 else {}
                if evidence.get(AUTHOR.THREATS, {}).get("unavailable"):
                    break
                assert time.monotonic() < deadline, body
                time.sleep(0.05)


@pytest.mark.skipif(os.environ.get("SAFEYOLO_REAL_RESEARCH") != "1", reason="explicit bounded real provider/research run")
def test_installed_real_provider_and_research_run(tmp_path):
    """Use adopted public sources through the selected installed proxy.

    This is an installed proxy/authoring witness. It reuses existing sandbox
    boundary proof; it does not establish a new guest platform or release path.
    """
    from tests.proxy_contracts.harness import connection, read_events

    choices = preferences()
    choices.update(agent="alice", destinations=[])
    base = '[hosts."*"]\negress="allow"\n'
    service = {"schema_version": 1, "name": AUTHOR.SERVICE, "default_host": "rdap.verisign.com",
               "capabilities": {"lookup": {"routes": [{"methods": ["GET"], "path": "/com/v1/domain/*"}]}}}
    parent = os.environ["HTTPS_PROXY"]
    with recipe_instance(tmp_path, source=base, services=True, parent_proxy=parent,
                         service_sources={"cyber-rdap.yaml": json.dumps(service)}) as instance:
        installed_skill = instance.root / "assets/skills/policy-authoring"
        operator_skills = tmp_path / "operator-home/.agents/skills"
        operator_skills.mkdir(parents=True)
        (operator_skills / "policy-authoring").symlink_to(installed_skill)
        loaded = (operator_skills / "policy-authoring/SKILL.md").read_text()
        assert "host that owns the selected instance" in loaded
        choice_path = tmp_path / "preferences.json"
        choice_path.write_text(json.dumps(choices))
        sources = instance.cli("policy", "feeds", "example", "hagezi")
        assert sources.returncode == 0, sources.stderr
        source_path = tmp_path / "sources.toml"
        source_path.write_text(sources.stdout)
        output = tmp_path / "authored"
        generated = subprocess.run([sys.executable, str(installed_skill / "scripts/author.py"), "--root", str(instance.root),
                                    "--choices", str(choice_path), "--sources", str(source_path), "--output", str(output)],
                                   capture_output=True, text=True)
        assert generated.returncode == 0, generated.stderr
        configured = instance.cli("policy", "feeds", "configure", str(output / "sources.toml"), timeout=75)
        assert configured.returncode == 0, configured.stderr
        status = instance.cli("policy", "feeds", "status")
        (tmp_path / "feed-status.json").write_text(status.stdout)
        assert json.loads(status.stdout)["sources"]["hagezi"]["snapshot"]["entries"] > 1000
        for arguments in [("policy", "check", str(output / "candidate.toml")),
                          ("policy", "evaluate", str(output / "candidate.toml"), str(output / "request.json")),
                          ("policy", "apply", str(output / "candidate.toml"))]:
            result = instance.cli(*arguments, timeout=30)
            assert result.returncode == 0, (arguments, result.stderr)
            (tmp_path / f"{arguments[1]}.txt").write_text(result.stdout)
        assert instance.show()["saved_matches_active"] is True

        def get(url):
            client = connection(instance.paths["alice"])
            client.sock.settimeout(30)
            try:
                client.request("GET", url)
                response = client.getresponse()
                data = response.read()
                assert response.status == 200, (url, response.status, data[:1000])
                return data
            finally:
                client.close()

        get("https://example.com/")
        feed_bytes = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        spec = importlib.util.spec_from_file_location("installed_brief", installed_skill / "scripts/brief.py")
        brief = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(brief)
        (tmp_path / "cyber-brief.md").write_text(brief.format_brief(json.loads(feed_bytes), "", 3))
        (tmp_path / "focused-brief.md").write_text(brief.format_brief(json.loads(feed_bytes), "Microsoft", 3))
        rows = read_events(instance.root / "logs/audit.jsonl")
        assessments = [row for row in rows if "named_checks" in row.get("details", {})]
        (tmp_path / "assessments.json").write_text(json.dumps(assessments, indent=2))
        assert any(row["details"]["named_checks"]["evidence"][AUTHOR.REGISTERED].get("result", {}).get("finding", {}).get("kind") == "timestamp"
                   for row in assessments), assessments
        assert "CVE-" in (tmp_path / "cyber-brief.md").read_text()
        assert "CISA KEV" in (tmp_path / "focused-brief.md").read_text()
