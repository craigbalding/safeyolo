"""Exercise the documented manual fallback without real Codex credentials."""

from __future__ import annotations

import http.client
import json
import sys
import time

import pytest
import tomlkit

from tests.proxy_contracts.harness import request
from tests.proxy_contracts.test_authority_consistency import _connect, _peers
from tests.proxy_contracts.test_native_policy_cli import native_instance

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Uses the maintained installed Linux fixture")


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
