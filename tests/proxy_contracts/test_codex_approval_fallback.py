"""Exercise the documented manual fallback without real Codex credentials."""

from __future__ import annotations

import http.client
import json
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
import tomlkit

from tests.proxy_contracts.harness import request
from tests.proxy_contracts.test_authority_consistency import _connect, _peers
from tests.proxy_contracts.test_native_policy_cli import native_instance

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Uses the maintained installed Linux fixture")

ROUTING_PATH = "/backend-api/wham/accounts/check?workspace_id=fixture"
ROUTING_POLICY = '''budget=12000
[hosts]
"*"={egress="allow",unknown_creds="prompt"}
[credential.synthetic]
match=["routing-login-secret", "replacement-login-secret"]
headers=["authorization"]
[agents.alice]
agent_id="ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[agents.bob]
agent_id="ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
'''


@contextmanager
def _routing_run(instance):
    # This existing sentry-shaped process contract supplies a controlled run
    # identity. It does not claim a booted guest or namespace isolation.
    generation = "0123456789abcdef0123456789abcdef"
    agent = instance.root / "agents/alice"
    (agent / "config-share").mkdir(parents=True)
    backend = subprocess.Popen(
        ["runsc-sandbox", "-c", "read line", f"--root={instance.root / 'run'}", "boot", f"safeyolo-{generation}"],
        executable="/bin/sh", stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        birth = Path(f"/proc/{backend.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        (agent / "runtime.json").write_text(json.dumps({
            "agent_id": "ag-" + "a" * 32, "run_id": generation, "state": "running",
            "backend_pid": backend.pid, "backend_token": f"linux:{boot}:{backend.pid}:{birth}",
        }))
        (agent / "config-share/host-launch-context.json").write_text(json.dumps({
            "agent_id": "ag-" + "a" * 32, "generation": generation,
        }))
        yield agent
    finally:
        if backend.poll() is None:
            backend.terminate()
        backend.communicate(timeout=5)


@contextmanager
def _routing_client(instance, transport):
    scheme = "http" if transport == "http" else "https"
    curl = shutil.which("curl")
    assert curl, "the installed-proxy HTTP client is required"
    command = [
        curl, "--silent", "--show-error", "--location", "--max-redirs", "2", "--max-time", "40",
        "--http2" if transport == "h2" else "--http1.1",
        "--unix-socket", instance.paths["alice"], "--proxy", "http://proxy.invalid",
        "--cacert", str(instance.root / "certs/mitmproxy-ca-cert.pem"),
        "--header", "Authorization: Bearer routing-login-secret",
        "--write-out", "\n%{http_code} %{num_redirects} %{http_version}",
        f"{scheme}://allowed.invalid{ROUTING_PATH}",
    ]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as client:
        try:
            yield client
        finally:
            if client.poll() is None:
                client.terminate()
            client.communicate(timeout=5)


def _routing_pending(instance, client):
    deadline = time.monotonic() + 4
    while True:
        pending = instance.admin("GET", "/admin/approvals")["approvals"]
        if pending:
            assert len(pending) == 1 and pending[0]["status"] == "pending"
            assert pending[0]["action"]["run"]["run_id"] == "0123456789abcdef0123456789abcdef"
            assert client.poll() is None, "routing discovery returned before the operator decision"
            return pending[0]["approval_id"]
        assert client.poll() is None, client.communicate()
        assert time.monotonic() < deadline, "routing discovery did not create its canonical approval"
        time.sleep(0.02)


@pytest.mark.parametrize("transport", ["http", "https", "h2"])
@pytest.mark.parametrize("option", ["persistent", "run"])
def test_codex_routing_continues_after_explicit_approval(tmp_path, transport, option):
    with _peers(tmp_path / "peers") as (parent, origins, trust), native_instance(
        tmp_path, source=ROUTING_POLICY,
        parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        extra_config=f'upstream_ca_file={json.dumps(str(trust))}\ntls_ca_file="certs/mitmproxy-ca.pem"\n',
    ) as instance, _routing_run(instance), _routing_client(instance, transport) as client:
        identifier = _routing_pending(instance, client)
        assert not any(origin.requests for origin in origins)
        decided = instance.cli("approvals", "approve", identifier, "--option", option, "--json")
        assert decided.returncode == 0, decided.stderr
        stdout, stderr = client.communicate(timeout=5)
        assert client.returncode == 0, stderr
        assert stdout.splitlines()[-1] == f"200 1 {'2' if transport == 'h2' else '1.1'}"
        delivered = [row for origin in origins for row in origin.requests]
        assert len(delivered) == 1
        assert f"GET {ROUTING_PATH} HTTP/1.1".encode() in delivered[0]["head"]
        assert b"Authorization: Bearer routing-login-secret\r\n" in delivered[0]["head"]
        # A repeat needs no redirect. Current-run approval remains narrower
        # than the offered persistent instance-wide option.
        target = "http://allowed.invalid/backend-api/codex/responses"
        headers = {"Authorization": "Bearer routing-login-secret"}
        assert request(instance.paths["alice"], target, headers=headers)[0] == 200
        assert request(instance.paths["bob"], target, headers=headers)[0] == (200 if option == "persistent" else 428)
        assert request(instance.paths["alice"], target.replace("allowed", "forbidden"), headers=headers)[0] == 428
        assert request(instance.paths["alice"], target,
                       headers={"Authorization": "Bearer replacement-login-secret"})[0] == 428
        events = (instance.root / "logs/audit.jsonl").read_text()
        assert "routing-login-secret" not in events and "replacement-login-secret" not in events
        responses = [json.loads(line) for line in events.splitlines()]
        assert any(row["event"] == "traffic.response" and row["details"]["status"] == 307 for row in responses)


@pytest.mark.parametrize("transport", ["http", "h2"])
@pytest.mark.parametrize("outcome", ["reject", "network_deny", "run_changed", "cancel"])
def test_codex_routing_wait_keeps_refusal_and_cancellation(tmp_path, transport, outcome):
    with _peers(tmp_path / "peers") as (parent, origins, trust), native_instance(
        tmp_path, source=ROUTING_POLICY,
        parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        extra_config=f'upstream_ca_file={json.dumps(str(trust))}\ntls_ca_file="certs/mitmproxy-ca.pem"\n',
    ) as instance, _routing_run(instance) as agent, _routing_client(instance, transport) as client:
        identifier = _routing_pending(instance, client)
        assert not any(origin.requests for origin in origins)
        if outcome == "run_changed":
            state = json.loads((agent / "runtime.json").read_text())
            state["run_id"] = "1" * 32
            (agent / "runtime.json").write_text(json.dumps(state))
        else:
            if outcome == "network_deny":
                instance.apply(instance.policy.read_text().replace('egress="allow"', 'egress="deny"'))
            if outcome == "cancel":
                client.terminate()
                client.communicate(timeout=5)
            command = "reject" if outcome == "reject" else "approve"
            decided = instance.cli("approvals", command, identifier, "--option", "run", "--json")
            assert decided.returncode == 0, decided.stderr
        stdout, stderr = client.communicate(timeout=5)
        if outcome != "cancel":
            assert client.returncode == 0, stderr
            assert stdout.splitlines()[-1].split()[:2] == (["403", "1"] if outcome == "network_deny" else ["428", "0"])
        assert not any(origin.requests for origin in origins)


def test_codex_routing_wait_timeout_leaves_approval_pending_without_replay(tmp_path):
    with _peers(tmp_path / "peers") as (parent, origins, trust), native_instance(
        tmp_path, source=ROUTING_POLICY,
        parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        extra_config=f'upstream_ca_file={json.dumps(str(trust))}\ntls_ca_file="certs/mitmproxy-ca.pem"\n',
    ) as instance, _routing_run(instance), _routing_client(instance, "http") as client:
        identifier = _routing_pending(instance, client)
        stdout, stderr = client.communicate(timeout=35)
        assert client.returncode == 0, stderr
        assert stdout.splitlines()[-1].split()[:2] == ["428", "0"]
        view = instance.admin("GET", f"/admin/approvals/{identifier}")
        assert view["status"] == "pending"
        decided = instance.cli("approvals", "approve", identifier, "--option", "run", "--json")
        assert decided.returncode == 0, decided.stderr
        assert not any(origin.requests for origin in origins)


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_codex_fallback_approves_each_replacement_at_one_destination(tmp_path, scheme):
    # Controlled origins replace the documented subscription destination.
    # These opaque fixtures make no claim about a Codex token's actual format.
    tokens = ["synthetic-subscription-access-first", "synthetic-subscription-access-replacement"]
    arbitrary = "unapproved-arbitrary-bearer"
    other = "unapproved-other-credential-AbCdEf0123456789_-"
    secrets = [*tokens, arbitrary, other]
    source = '''budget = 12000
[hosts]
"*" = {egress="allow", unknown_creds="prompt"}
[hosts."allowed.invalid"]
unknown_creds = "prompt"
'''
    with _peers(tmp_path / "peers") as (parent, origins, trust), native_instance(
        tmp_path, source=source,
        parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
        extra_config=f'upstream_ca_file={json.dumps(str(trust))}\ntls_ca_file="certs/mitmproxy-ca.pem"\n',
    ) as instance:
        pid = instance.process.pid

        def send(token, expected, *, destination="allowed.invalid", extra=None):
            before = [len(origin.requests) for origin in origins]
            headers = {"Authorization": f"Bearer {token}", **(extra or {})}
            path = "/backend-api/codex/responses"
            if scheme == "http":
                status, response_headers, body = request(
                    instance.paths["alice"], f"http://{destination}{path}", headers=headers,
                )
            else:
                status, stream = _connect(
                    instance.paths["alice"], f"{destination}:443".encode(), destination,
                    instance.root / "certs/mitmproxy-ca-cert.pem",
                )
                assert status == 200
                with stream:
                    fields = "".join(f"{name}: {value}\r\n" for name, value in headers.items())
                    stream.sendall((f"GET {path} HTTP/1.1\r\nHost: {destination}\r\n"
                                    f"{fields}Connection: close\r\n\r\n").encode())
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    status, response_headers, body = response.status, dict(response.getheaders()), response.read()
            assert status == expected, (status, body)
            counts = before.copy()
            if expected == 200:
                index = (0 if destination == "allowed.invalid" else 1) + (2 if scheme == "https" else 0)
                counts[index] += 1
                assert f"Authorization: Bearer {token}\r\n".encode() in origins[index].requests[-1]["head"]
            assert [len(origin.requests) for origin in origins] == counts
            request_id = next(value for name, value in response_headers.items()
                              if name.lower() == "x-safeyolo-request-id")
            deadline = time.monotonic() + 4
            while True:
                logs = instance.cli("logs", "--agent", "alice", "--lines", "50", "--json")
                assert logs.returncode == 0, logs.stderr
                assert all(value not in logs.stdout + logs.stderr for value in secrets)
                events = json.loads(logs.stdout)["events"]
                rows = [row for row in events if row["event"] == "security.credential_guard"
                        and row.get("request_id") == request_id]
                if rows:
                    break
                assert time.monotonic() < deadline
                time.sleep(0.02)
            decision = {200: "allow", 428: "require_approval", 403: "deny"}[expected]
            event = next(row for row in rows if row["decision"] == decision)
            assert event["agent"] == "alice" and event["host"] == destination
            assert event["details"]["rule"] == "unknown_secret"
            assert all(value not in json.dumps(events) and value.encode() not in body for value in secrets)
            return event["details"]["fingerprint"]

        fingerprints = []
        for token in tokens:
            fingerprint = send(token, 428)
            assert fingerprint.startswith("hmac:")
            fingerprints.append(fingerprint)
            approved = instance.cli("credentials", "approve", fingerprint, "--destination", "allowed.invalid")
            assert approved.returncode == 0, approved.stderr
            assert all(value not in approved.stdout + approved.stderr for value in secrets)
            deadline = time.monotonic() + 4
            while True:
                shown = instance.show()
                if shown["saved_matches_active"] and fingerprint in shown["effective"]["hosts"]["allowed.invalid"]["allow"]:
                    break
                assert time.monotonic() < deadline
                time.sleep(0.02)
            assert send(token, 200) == fingerprint
            send(token, 428, destination="forbidden.invalid")
        assert fingerprints[0] != fingerprints[1]
        instance.apply(instance.policy.read_text())
        send(tokens[0], 200)
        send(tokens[1], 200)
        send(arbitrary, 428)
        send(tokens[1], 428, extra={"X-Auth-Token": other})
        pending = instance.cli("services", "approvals")
        assert pending.returncode == 0, pending.stderr
        assert all(value not in pending.stdout + pending.stderr for value in secrets)

        denied = tomlkit.parse(instance.policy.read_text())
        denied["hosts"]["allowed.invalid"]["rules"] = [{
            "action": "credential:use", "resource": "allowed.invalid/*", "effect": "deny",
        }]
        instance.apply(tomlkit.dumps(denied))
        assert send(tokens[1], 403) == fingerprints[1]
        assert instance.process.pid == pid and instance.process.poll() is None
