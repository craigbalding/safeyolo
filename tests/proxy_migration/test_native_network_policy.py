"""Real transport contracts for the explicitly selected native policy path.

Python comparisons retain the actual LocalPolicyClient and NetworkGuard. No
replacement policy evaluator or runtime fallback participates in these cases.
"""

import http.client
import json
import os
import signal
import socket
import socketserver
import ssl
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from mitmproxy.certs import CertStore

from tests.proxy_migration.harness import launch_proxy, read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import FORGED_REQUEST_ID, POLICY, origin_server
from tests.proxy_migration.test_http2_contract import origin_certificate
from tests.proxy_migration.test_http2_contract import origin_server as tls_origin_server
from tests.proxy_migration.test_websocket_contract import read_head

ALLOW = '''budget = 12000
[hosts]
"*" = { egress = "allow" }
'''
DENY = '''[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
'''


class RawParent(socketserver.TCPServer):
    """Retain exact forwarded bytes, including non-ASCII Host values."""

    def __init__(self):
        self.accepts = 0
        self.heads = []
        self.errors = []
        super().__init__(("127.0.0.1", 0), RawParentHandler)

    def get_request(self):
        result = super().get_request()
        self.accepts += 1
        return result


class RawParentHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                piece = self.request.recv(1)
                assert piece, "Parent request ended before headers completed"
                head.extend(piece)
                assert len(head) <= 65536
            self.server.heads.append(bytes(head))
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        except Exception as error:
            self.server.errors.append(error)


@contextmanager
def raw_parent():
    parent = RawParent()
    thread = threading.Thread(target=parent.serve_forever)
    thread.start()
    try:
        yield parent
    finally:
        parent.shutdown()
        parent.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        if parent.errors:
            raise parent.errors[0]


def child_processes(pid):
    """Inspect process parentage; some Linux sandboxes omit task/children."""
    processes = Path("/proc")
    if not (processes / str(pid) / "status").exists():
        return None
    children = set()
    for process in processes.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            status = (process / "status").read_text()
        except FileNotFoundError:
            # A process can exit between enumeration and reading its parent.
            continue
        parent = next(line for line in status.splitlines() if line.startswith("PPid:"))
        if int(parent.split(":", 1)[1]) == pid:
            children.add(int(process.name))
    return children


@contextmanager
def policy_proxy(backend, directory, policy, **options):
    before = child_processes(os.getpid())
    with launch_proxy(backend, directory, policy, native_policy=True, **options) as proxy:
        if backend == "rust":
            assert_no_adapter(proxy, directory, before)
        yield proxy
        if backend == "rust":
            assert_no_adapter(proxy, directory, before)


def assert_no_adapter(proxy, directory, before):
    config = json.loads((directory / "proxy.json").read_text())
    policy_socket = Path(proxy.paths["alice"]).parents[1] / "policy.sock"
    policy_file = Path(config["policy_file"])
    assert policy_file.parent == directory and policy_file.name in {"policy.toml", "policy.yaml", "policy.json"}
    assert "temporary_policy_socket" not in config
    assert proxy.policy_process is None
    assert not (directory / "policy-bridge").exists()
    assert not policy_socket.exists()
    children = child_processes(os.getpid())
    proxy_children = child_processes(proxy.process.pid)
    if before is not None:
        assert children - before == {proxy.process.pid}
        assert proxy_children == set()
    (directory / "native-policy-processes.json").write_text(json.dumps({
        "policy_file": config["policy_file"],
        "temporary_policy_socket_present": False,
        "policy_adapter_process": None,
        "new_fixture_children": sorted(children - before) if before is not None else None,
        "proxy_children": sorted(proxy_children) if proxy_children is not None else None,
    }, indent=2) + "\n")


def replace_policy(proxy, backend, directory, source, *, valid=True):
    """Wait for each real loader to observe the replacement before spending a budget."""
    event = "ops.policy_reload" if valid else "ops.policy_error"
    prior_events = sum(row["event"] == event for row in read_events(directory / "audit.jsonl"))
    before_ready = proxy.readiness_file.stat()
    before_errors = (directory / "process.log").read_text().count("configuration reload failed:")
    policy_file = Path(json.loads((directory / "proxy.json").read_text())["policy_file"])
    replacement = policy_file.with_name(f"{policy_file.stem}.next{policy_file.suffix}")
    replacement.write_text(source)
    replacement.replace(policy_file)
    if backend == "rust":
        proxy.process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 6
    while True:
        assert proxy.process.poll() is None, "Policy reload stopped the proxy"
        if backend == "python":
            observed = sum(row["event"] == event for row in read_events(directory / "audit.jsonl")) > prior_events
        elif valid:
            try:
                current = proxy.readiness_file.stat()
            except FileNotFoundError:
                observed = False  # Readiness is removed while a valid reload commits.
            else:
                observed = (current.st_ino, current.st_mtime_ns) != (before_ready.st_ino, before_ready.st_mtime_ns)
        else:
            observed = (directory / "process.log").read_text().count("configuration reload failed:") > before_errors
        if observed:
            return
        assert time.monotonic() < deadline, "Policy replacement was not observed by the loader"
        time.sleep(0.025)


def assert_rejection(status, headers, body, expected, host):
    assert status == expected, body
    normalized = {name.lower(): value for name, value in headers.items()}
    assert normalized["x-blocked-by"] == "network-guard"
    assert normalized["content-type"] == "application/json"
    assert normalized["x-safeyolo-request-id"] != FORGED_REQUEST_ID
    decoded = json.loads(body)
    assert decoded["domain"] == host
    assert decoded["type"] == ("access_denied" if expected == 403 else "rate_limit_exceeded")
    # The transport must preserve the scanner's ordinary Python JSON wire
    # representation, including spacing, ordering and ASCII escaping.
    assert body == json.dumps(decoded).encode()
    if expected == 429:
        assert normalized["retry-after"] == "60"
        assert normalized["x-ratelimit-remaining"] == "0"


@pytest.mark.parametrize("parent", [False, True], ids=["direct", "parent"])
def test_native_policy_two_agent_http_and_forged_identity(proxy_backend, tmp_path, parent):
    directory = tmp_path / proxy_backend
    with origin_server() as origin:
        host = "target.invalid" if parent else "127.0.0.1"
        port = 8123 if parent else origin.server_address[1]
        url = f"http://{host}:{port}/signed?part=one&part=two%2Fthree"
        parent_url = f"http://127.0.0.1:{origin.server_address[1]}" if parent else None
        identifiers = []
        with policy_proxy(proxy_backend, directory, POLICY, parent_proxy=parent_url) as proxy:
            for agent, expected in (("bob", 403), ("alice", 200), ("bob", 403), ("alice", 200)):
                before = origin.accepts
                egress_before = len(proxy.events("proxy.egress"))
                status, headers, body = send_request(proxy.paths[agent], url, headers={
                    "X-SafeYolo-Agent": "alice" if agent == "bob" else "bob",
                    "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                    "X-SafeYolo-Trace": "1",
                })
                assert status == expected, body
                normalized = {name.lower(): value for name, value in headers.items()}
                identifier = normalized["x-safeyolo-request-id"]
                assert identifier != FORGED_REQUEST_ID and identifier not in identifiers
                identifiers.append(identifier)
                assert origin.accepts - before == int(expected == 200)
                if expected == 403:
                    assert_rejection(status, headers, body, expected, host)
                    assert len(proxy.events("proxy.egress")) == egress_before
                else:
                    assert body == b"hello"
            events = proxy.events("proxy.request")
            assert [event["agent"] for event in events] == ["bob", "alice", "bob", "alice"]
            assert [event["request_id"] for event in events] == identifiers
            assert [event["status"] for event in events] == [403, 200, 403, 200]
            assert all(event["host"] == host and event["port"] == port for event in events)
            expected_target = url if parent else "/signed?part=one&part=two%2Fthree"
            assert origin.requests == [{"method": "GET", "target": expected_target}] * 2


@pytest.mark.parametrize("options,status", [
    ({}, 403), ({"network_guard_block": False}, 200), ({"network_guard_enabled": False}, 200),
], ids=["block-default", "warn", "disabled"])
def test_native_policy_runtime_guard_modes(proxy_backend, tmp_path, options, status):
    with origin_server() as origin:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, DENY, **options) as proxy:
            url = f"http://127.0.0.1:{origin.server_address[1]}/mode"
            for agent in ("alice", "bob"):
                actual, headers, body = send_request(proxy.paths[agent], url)
                assert actual == status
                if status == 403:
                    assert_rejection(actual, headers, body, status, "127.0.0.1")
                else:
                    assert body == b"hello"
            assert origin.accepts == (2 if status == 200 else 0)
            assert len(proxy.events("proxy.egress")) == origin.accepts


@pytest.mark.parametrize("scope", ["domain", "client"])
@pytest.mark.parametrize("required", [False, True])
def test_native_policy_scoped_bypass_and_required_addon(proxy_backend, tmp_path, scope, required):
    policy = ('required = ["network_guard"]\n' if required else "") + DENY
    policy += ('\n[domains."bypass.invalid"]\nbypass = ["network_guard"]\n' if scope == "domain"
               else '\n[clients.alice]\nbypass = ["network_guard"]\n')
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, policy,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            for host in ("bypass.invalid", "other.invalid"):
                for agent in ("alice", "bob"):
                    bypassed = not required and (host == "bypass.invalid" if scope == "domain" else agent == "alice")
                    before = parent.accepts
                    status, headers, body = send_request(proxy.paths[agent], f"http://{host}:8123/scope", headers={
                        "X-SafeYolo-Agent": "alice" if agent == "bob" else "bob",
                    })
                    assert status == (200 if bypassed else 403), body
                    assert parent.accepts - before == int(bypassed)
                    if not bypassed:
                        assert_rejection(status, headers, body, 403, host)
            assert len(proxy.events("proxy.egress")) == parent.accepts


@pytest.mark.parametrize("homoglyph", [True, False])
def test_native_policy_homoglyph_checks_the_source_matching_host(proxy_backend, tmp_path, homoglyph):
    host = "\u0430pi.invalid"  # Cyrillic 'a' followed by Latin letters.
    wire_host = host.encode("idna").decode()
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, ALLOW,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
                          network_guard_homoglyph=homoglyph) as proxy:
            status, headers, body = send_request(proxy.paths["alice"], f"http://{wire_host}:8123/path")
            assert status == (403 if homoglyph else 200), body
            if homoglyph:
                assert json.loads(body)["type"] == "homoglyph_attack"
                assert json.loads(body)["domain"] == host
                assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
                assert parent.accepts == 0
                assert proxy.events("proxy.egress") == []
            else:
                assert body == b"hello"
                assert parent.requests == [{"method": "GET", "target": f"http://{wire_host}:8123/path"}]


@pytest.mark.parametrize("form,mode", [
    ("absolute-upper", "block"), ("origin-lower", "block"),
    ("absolute-upper", "disabled"), ("origin-lower", "disabled"),
    ("absolute-lower", "bypass"), ("absolute-upper", "bypass"), ("origin-lower", "bypass"),
])
def test_native_policy_homoglyph_authority_forms(proxy_backend, tmp_path, form, mode, request):
    """D40: equivalent ACE authorities cannot evade enabled homoglyph inspection."""
    host = "\u0430pi.invalid"
    wire_host = host.encode("idna").decode()
    if form == "absolute-upper":
        wire_host = wire_host.upper()
    target = "/path" if form == "origin-lower" else f"http://{wire_host}:8123/path"
    policy = ALLOW + ('\n[clients.alice]\nbypass = ["network_guard"]\n' if mode == "bypass" else "")
    directory = tmp_path / proxy_backend
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, policy,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
                          network_guard_homoglyph=mode != "disabled") as proxy:
            # Keep the actual wire target form and Host spelling. Passing a
            # Host header also prevents http.client from inventing one.
            status, headers, body = send_request(proxy.paths["alice"], target,
                                                  headers={"Host": f"{wire_host}:8123"})
            (directory / "homoglyph-authority.json").write_text(json.dumps({
                "form": form, "mode": mode, "wire_target": target, "wire_host": wire_host,
                "status": status, "origin_accepts": parent.accepts,
                "origin_requests": parent.requests, "events": proxy.events("proxy.request"),
            }, indent=2) + "\n")
            if mode == "block":
                if proxy_backend == "python":
                    if status != 403:
                        # The same three wire forms were captured before any
                        # xfail was introduced. These two source escapes gave
                        # a normal 200 and contacted the owned parent once.
                        assert status == 200 and body == b"hello"
                        assert parent.accepts == 1 and len(parent.requests) == 1
                    request.node.add_marker(pytest.mark.xfail(
                        strict=True, reason="D40: historical ACE case/origin-form homoglyph bypass"))
                assert status == 403, body
                assert json.loads(body)["type"] == "homoglyph_attack"
                assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
                assert parent.accepts == 0
                assert proxy.events("proxy.egress") == []
            else:
                assert status == 200 and body == b"hello"
                assert parent.accepts == 1 and len(parent.requests) == 1


@pytest.mark.parametrize("mode", ["block", "warn", "homoglyph-disabled", "disabled", "bypass"])
def test_native_policy_malformed_ace_inspection_modes(proxy_backend, tmp_path, mode):
    """D40 repair: malformed ACE obeys the configured inspection mode."""
    if proxy_backend != "rust":
        pytest.skip("Native inspection-error contract; historical source wire behavior is captured separately")
    # Raw Punycode yields a lone surrogate. The source accepts this ASCII
    # origin-form Host; native Unicode inspection must report its failure.
    host = "XN--ib9b.invalid"
    directory = tmp_path / proxy_backend
    policy = ALLOW + ('\n[clients.alice]\nbypass = ["network_guard"]\n' if mode == "bypass" else "")
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, policy,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
                          network_guard_block=mode != "warn",
                          network_guard_homoglyph=mode != "homoglyph-disabled",
                          network_guard_enabled=mode != "disabled") as proxy:
            status, headers, body = send_request(proxy.paths["alice"], "/inspection",
                                                  headers={"Host": f"{host}:8123"})
            events = proxy.events("proxy.network_guard")
            assert len(events) == 1
            guard = events[0]
            (directory / "hostname-inspection.json").write_text(json.dumps({
                "wire_host": host, "mode": mode, "status": status,
                "origin_accepts": parent.accepts, "origin_requests": parent.requests,
                "guard": guard,
            }, indent=2) + "\n")
            if mode == "block":
                assert_rejection(status, headers, body, 403, host)
                assert json.loads(body)["reason"] == "Hostname inspection failed"
                assert parent.accepts == 0
                assert proxy.events("proxy.egress") == []
            else:
                assert status == 200 and body == b"hello"
                assert parent.accepts == 1 and len(parent.requests) == 1
            if mode in ("block", "warn"):
                assert guard["outcome"] == ("blocked" if mode == "block" else "warned")
                assert guard["audit"]["decision"] == ("deny" if mode == "block" else "warn")
                assert guard["audit"]["details"]["reason"] == "Hostname inspection failed"
                assert guard["pdp"] is None
            else:
                assert guard["outcome"] == ("allowed" if mode == "homoglyph-disabled" else "bypassed")
                assert guard["audit"] is None
                assert (guard["pdp"] is not None) == (mode == "homoglyph-disabled")


@pytest.mark.parametrize("host", ["XN--pi-fia905a.invalid", "XN--pi-6kc646z.invalid"])
@pytest.mark.parametrize("homoglyph", [True, False])
def test_native_policy_raw_decodable_mixed_script_ace(proxy_backend, tmp_path, host, homoglyph, request):
    """D40 repair: IDNA round-trip failure does not conceal inspectable scripts."""
    directory = tmp_path / proxy_backend
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, ALLOW,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
                          network_guard_homoglyph=homoglyph) as proxy:
            status, headers, body = send_request(proxy.paths["alice"], "/inspection",
                                                  headers={"Host": f"{host}:8123"})
            (directory / "hostname-inspection.json").write_text(json.dumps({
                "wire_host": host, "homoglyph": homoglyph, "status": status,
                "origin_accepts": parent.accepts, "origin_requests": parent.requests,
                "events": proxy.events("proxy.request"),
            }, indent=2) + "\n")
            if homoglyph:
                if proxy_backend == "python":
                    if status != 403:
                        assert status == 200 and body == b"hello"
                        assert parent.accepts == 1 and len(parent.requests) == 1
                    request.node.add_marker(pytest.mark.xfail(
                        strict=True, reason="D40: historical raw-decodable ACE homoglyph bypass"))
                assert status == 403, body
                assert json.loads(body)["type"] == "homoglyph_attack"
                assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
                assert parent.accepts == 0
                assert proxy.events("proxy.egress") == []
            else:
                assert status == 200 and body == b"hello"
                assert parent.accepts == 1 and len(parent.requests) == 1


@pytest.mark.parametrize("host,homoglyph,expected,uri_host", [
    ("\u0430pi.invalid", True, 403, "xn--pi-6kc.invalid"),
    ("\u0430pi.invalid", False, 200, "xn--pi-6kc.invalid"),
    ("fa\u00df.invalid", True, 200, "fass.invalid"),
    ("example\u3002invalid", True, 200, "example.invalid"),
    (None, True, 400, None),
], ids=["cyrillic-block", "cyrillic-disabled", "sharp-s", "ideographic-stop", "invalid-utf8"])
def test_native_policy_raw_utf8_origin_host(proxy_backend, tmp_path, host, homoglyph, expected, uri_host):
    """Keep policy host and Host bytes while observing each backend's parent form.

    The source forwards this origin-form target unchanged. Native plaintext
    parent forwarding already uses absolute form, with IDNA2003 URI authority.
    This finite transport difference does not change policy inspection outcomes.
    """
    directory = tmp_path / proxy_backend
    wire_host = host.encode() if host is not None else b"\xff.invalid"
    target = b"/utf8?owned=yes&part=two%2Fthree"
    head = b"GET " + target + b" HTTP/1.1\r\nHost: " + wire_host + b":8123\r\nConnection: close\r\n\r\n"
    with raw_parent() as parent:
        with policy_proxy(proxy_backend, directory, ALLOW,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}",
                          network_guard_homoglyph=homoglyph) as proxy:
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(5)
                stream.connect(proxy.paths["alice"])
                stream.sendall(head)
                response = http.client.HTTPResponse(stream)
                response.begin()
                status, headers, body = response.status, dict(response.getheaders()), response.read()
            events = proxy.events("proxy.request")
            (directory / "raw-host-forwarding.json").write_text(json.dumps({
                "wire_head_hex": head.hex(), "policy_host": host, "status": status,
                "origin_accepts": parent.accepts, "parent_head_hex": [item.hex() for item in parent.heads],
                "events": events,
                "parent_request_form": "absolute with IDNA2003 authority" if proxy_backend == "rust" else "origin",
                "scope": "explicit plaintext-parent transport-form difference; Host bytes and inspection preserved",
            }, indent=2) + "\n")
            assert status == expected, body
            if expected == 200:
                assert body == b"hello"
                assert parent.accepts == 1 and len(parent.heads) == 1
                lines = parent.heads[0].split(b"\r\n")
                forwarded = b"http://" + uri_host.encode() + b":8123" + target if proxy_backend == "rust" else target
                assert lines[0] == b"GET " + forwarded + b" HTTP/1.1"
                host_lines = [line.partition(b":")[2] for line in lines if line.lower().startswith(b"host:")]
                assert host_lines == [b" " + wire_host + b":8123"]
            else:
                assert parent.accepts == 0 and parent.heads == []
                assert proxy.events("proxy.egress") == []
                if expected == 403:
                    assert json.loads(body)["type"] == "homoglyph_attack"
                    assert json.loads(body)["domain"] == host
                    assert {name.lower(): value for name, value in headers.items()}["x-blocked-by"] == "network-guard"
            if host is not None:
                assert len(events) == 1
                assert events[0]["host"] == host and events[0]["port"] == 8123


@pytest.mark.parametrize("budget", ["global", "host"])
def test_native_policy_budget_is_shared_and_survives_reload(proxy_backend, tmp_path, budget):
    directory = tmp_path / proxy_backend
    policy = ('budget = 1\n[hosts]\n"*" = { egress = "allow" }\n' if budget == "global"
              else 'budget = 12000\n[hosts]\n"*" = { egress = "allow" }\n"limited.invalid" = { rate = 1 }\n')
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, policy,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            url = "http://limited.invalid:8123/budget"
            started = time.monotonic()
            # GCRA's existing burst allowance admits these first two requests
            # for rate=1. Both trusted agents share the same applicable budget.
            for agent in ("alice", "bob"):
                assert send_request(proxy.paths[agent], url)[0] == 200
            status, headers, body = send_request(proxy.paths["alice"], url)
            assert_rejection(status, headers, body, 429, "limited.invalid")
            assert parent.accepts == 2
            replace_policy(proxy, proxy_backend, directory, policy + "\n# valid reload preserves consumption\n")
            status, headers, body = send_request(proxy.paths["bob"], url)
            assert_rejection(status, headers, body, 429, "limited.invalid")
            replace_policy(proxy, proxy_backend, directory, "[hosts\n", valid=False)
            status, headers, body = send_request(proxy.paths["alice"], url)
            assert_rejection(status, headers, body, 429, "limited.invalid")
            assert parent.accepts == 2
            # An unrelated host is also limited only when the aggregate
            # budget is exhausted. Reload must not replace counters in either case.
            status, headers, body = send_request(proxy.paths["bob"], "http://other.invalid:8123/budget")
            if budget == "global":
                assert_rejection(status, headers, body, 429, "other.invalid")
            else:
                assert status == 200 and body == b"hello"
            assert time.monotonic() - started < 30, "Scenario crossed the intended no-refill window"
            assert len(proxy.events("proxy.egress")) == parent.accepts


def test_native_policy_failed_reload_retains_scoped_decisions(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with origin_server(capture_heads=True) as permitted, origin_server(capture_heads=True) as forbidden:
        permitted_port = permitted.server_address[1]
        forbidden_port = forbidden.server_address[1]
        baseline = (f'budget = 12000\n[hosts]\n"*" = {{ egress = "deny" }}\n'
                    f'"127.0.0.1:{permitted_port}" = {{ egress = "allow" }}\n')
        alice_update = (baseline + f'\n[agents.alice.hosts]\n'
                        f'"127.0.0.1:{forbidden_port}" = {{ egress = "allow" }}\n')
        observations = []
        with policy_proxy(proxy_backend, directory, baseline) as proxy:
            def probe(stage, agent, origin, expected):
                port = origin.server_address[1]
                url = f"http://127.0.0.1:{port}/{stage}/{agent}"
                before = (origin.accepts, list(origin.request_heads), list(origin.requests))
                marker = f"{stage}-{agent}"
                status, headers, body = send_request(proxy.paths[agent], url, headers={
                    "X-Fixture-Canary": marker,
                    "X-SafeYolo-Agent": "bob" if agent == "alice" else "alice",
                    "X-SafeYolo-Request-Id": FORGED_REQUEST_ID,
                })
                assert status == expected, (stage, agent, body)
                identifier = {name.lower(): value for name, value in headers.items()}[
                    "x-safeyolo-request-id"
                ]
                assert identifier != FORGED_REQUEST_ID
                observations.append((identifier, agent, port, expected))
                if expected == 403:
                    assert_rejection(status, headers, body, 403, "127.0.0.1")
                    assert (origin.accepts, origin.request_heads, origin.requests) == before
                else:
                    assert body == b"hello"
                    assert origin.accepts == before[0] + 1
                    assert len(origin.request_heads) == len(before[1]) + 1
                    assert len(origin.requests) == len(before[2]) + 1
                    assert origin.requests[-1] == {"method": "GET", "target": f"/{stage}/{agent}"}
                    assert f"X-Fixture-Canary: {marker}".encode() in origin.request_heads[-1]
                    assert origin.canary_headers[-1] == marker

            def check_decisions(stage, *, alice_forbidden=403):
                for agent, expected in (("alice", alice_forbidden), ("bob", 403)):
                    probe(stage, agent, forbidden, expected)
                for agent in ("alice", "bob"):
                    probe(stage, agent, permitted, 200)

            check_decisions("baseline")
            assert forbidden.accepts == 0 and forbidden.request_heads == []
            for name, bad_source in (("malformed", "[hosts\n"), ("schema", "hosts = 7\n")):
                prior_errors = len([row for row in read_events(directory / "audit.jsonl")
                                    if row["event"] == "ops.policy_error"])
                prior_reloads = len([row for row in read_events(directory / "audit.jsonl")
                                     if row["event"] == "ops.policy_reload"])
                previous_log = (directory / "process.log").read_text()
                replace_policy(proxy, proxy_backend, directory, bad_source, valid=False)
                errors = [row for row in read_events(directory / "audit.jsonl")
                          if row["event"] == "ops.policy_error"]
                assert len(errors) == prior_errors + 1
                assert errors[-1]["summary"] == "Baseline policy file not found or invalid"
                assert errors[-1]["details"] == {
                    "policy_type": "baseline", "error": "File not found or invalid"
                }
                assert errors[-1]["severity"] == "high"
                assert len([row for row in read_events(directory / "audit.jsonl")
                            if row["event"] == "ops.policy_reload"]) == prior_reloads
                if proxy_backend == "rust":
                    failure = (directory / "process.log").read_text()[len(previous_log):]
                    expected_error = "TOML parse error" if name == "malformed" else "hosts must be a table"
                    assert "configuration reload failed:" in failure and expected_error in failure
                check_decisions(name)
                assert forbidden.accepts == 0 and forbidden.request_heads == []

            replace_policy(proxy, proxy_backend, directory, alice_update)
            check_decisions("updated", alice_forbidden=200)
            assert forbidden.accepts == 1
            replace_policy(proxy, proxy_backend, directory, baseline)
            check_decisions("restored")
            assert forbidden.accepts == 1

            deadline = time.monotonic() + 3
            while True:
                requests = {row["request_id"]: row for row in proxy.events("proxy.request")}
                audit = {row["request_id"]: row for row in read_events(directory / "audit.jsonl")
                         if row["event"] == "security.network_guard"}
                denied = [item for item in observations if item[3] == 403]
                if len(requests) >= len(observations) and len(audit) >= len(denied):
                    break
                assert time.monotonic() < deadline, "Request or denial evidence was not written"
                time.sleep(0.025)
            for identifier, agent, port, status in observations:
                row = requests[identifier]
                assert (row["agent"], row["host"], row["port"], row["status"], row["decision"]) == (
                    agent, "127.0.0.1", port, status, "allow" if status == 200 else "deny"
                )
                if status == 403:
                    denial = audit[identifier]
                    assert denial["agent"] == agent and denial["decision"] == "deny"
                    assert denial["details"]["port"] == port
                    assert denial["details"]["attribution"]["trusted_transport_identity"] == agent
            assert len(proxy.events("proxy.egress")) == sum(status == 200 for *_, status in observations)


def test_native_invalid_configuration_reload_keeps_policy(proxy_backend, tmp_path):
    if proxy_backend != "rust":
        pytest.skip("Python source configuration reload requires a process restart")
    directory = tmp_path / proxy_backend
    with origin_server(capture_heads=True) as denied, origin_server(capture_heads=True) as allowed:
        policy = (f'[hosts]\n"*" = {{ egress = "deny" }}\n'
                  f'"127.0.0.1:{allowed.server_address[1]}" = {{ egress = "allow" }}\n')
        with policy_proxy(proxy_backend, directory, policy) as proxy:
            denied_url = f"http://127.0.0.1:{denied.server_address[1]}/config-denied"
            allowed_url = f"http://127.0.0.1:{allowed.server_address[1]}/config-allowed"
            assert send_request(proxy.paths["alice"], denied_url)[0] == 403
            assert send_request(proxy.paths["bob"], denied_url)[0] == 403
            assert denied.accepts == 0 and denied.request_heads == []
            assert send_request(proxy.paths["alice"], allowed_url)[0] == 200
            reloads_before = len([row for row in read_events(directory / "audit.jsonl")
                                  if row["event"] == "ops.policy_reload"])
            config = directory / "proxy.json"
            original_config = config.read_text()
            errors_before = (directory / "process.log").read_text().count("configuration reload failed:")
            try:
                config.write_text('{"listeners":')
                proxy.process.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 3
                while (directory / "process.log").read_text().count("configuration reload failed:") == errors_before:
                    assert proxy.process.poll() is None
                    assert time.monotonic() < deadline, "Invalid configuration reload was not reported"
                    time.sleep(0.025)
                assert "configuration reload failed: EOF while parsing a value" in (
                    directory / "process.log"
                ).read_text()
                assert proxy.readiness_file.exists()
                assert len([row for row in read_events(directory / "audit.jsonl")
                            if row["event"] == "ops.policy_reload"]) == reloads_before
            finally:
                config.write_text(original_config)
            denied_ids = []
            for agent in ("alice", "bob"):
                status, headers, body = send_request(proxy.paths[agent], denied_url)
                assert_rejection(status, headers, body, 403, "127.0.0.1")
                denied_ids.append((agent, {name.lower(): value for name, value in headers.items()}[
                    "x-safeyolo-request-id"
                ]))
            assert denied.accepts == 0 and denied.request_heads == []
            assert send_request(proxy.paths["bob"], allowed_url)[0] == 200
            assert allowed.accepts == 2 and len(allowed.request_heads) == 2
            deadline = time.monotonic() + 3
            while True:
                requests = {row["request_id"]: row for row in proxy.events("proxy.request")}
                audit = {row["request_id"]: row for row in read_events(directory / "audit.jsonl")
                         if row["event"] == "security.network_guard"}
                if all(identifier in requests and identifier in audit for _, identifier in denied_ids):
                    break
                assert time.monotonic() < deadline, "Retained config denial evidence was not written"
                time.sleep(0.025)
            for agent, identifier in denied_ids:
                assert requests[identifier]["agent"] == agent
                assert requests[identifier]["status"] == 403
                assert requests[identifier]["decision"] == "deny"
                assert audit[identifier]["agent"] == agent and audit[identifier]["decision"] == "deny"
            before_ready = proxy.readiness_file.stat()
            proxy.process.send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 3
            while True:
                try:
                    current = proxy.readiness_file.stat()
                except FileNotFoundError:
                    pass  # The native process removes readiness while publishing a valid reload.
                else:
                    if (current.st_ino, current.st_mtime_ns) != (before_ready.st_ino, before_ready.st_mtime_ns):
                        break
                assert proxy.process.poll() is None
                assert time.monotonic() < deadline, "Restored configuration did not reload"
                time.sleep(0.025)
            assert send_request(proxy.paths["alice"], denied_url)[0] == 403
            assert denied.accepts == 0 and denied.request_heads == []


def test_native_policy_connect_and_inner_https_have_separate_decisions(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    pem, public = origin_certificate(directory)
    CertStore.from_store(directory / "ca", "mitmproxy", 2048)
    policy = '''[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { method = "CONNECT" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
condition = { agent = "alice", method = "GET" }
[[permissions]]
action = "network:request"
resource = "*"
effect = "deny"
'''
    with tls_origin_server(pem, ("http/1.1",)) as origin:
        with policy_proxy(proxy_backend, directory, policy, tls=True, upstream_ca=public,
                          eager_connect=True) as proxy:
            for agent, expected in (("bob", 403), ("alice", 200)):
                raw = socket.socket(socket.AF_UNIX)
                raw.settimeout(5)
                try:
                    raw.connect(proxy.paths[agent])
                    raw.sendall((f"CONNECT {origin.authority} HTTP/1.1\r\n"
                                 f"Host: {origin.authority}\r\n\r\n").encode())
                    response, _ = read_head(raw)
                    assert response.split()[1] == "200"
                    context = ssl.create_default_context(cafile=directory / "ca/mitmproxy-ca-cert.pem")
                    stream = context.wrap_socket(raw, server_hostname="127.0.0.1")
                    client = http.client.HTTPConnection("127.0.0.1", origin.server_address[1], timeout=5)
                    client.sock = stream
                    try:
                        client.request("GET", "/inner", headers={"X-SafeYolo-Agent": "alice"})
                        response = client.getresponse()
                        body = response.read()
                        assert response.status == expected, body
                        if expected == 200:
                            assert body == b"hello"
                        else:
                            assert origin.requests == []
                    finally:
                        client.close()
                finally:
                    raw.close()
            assert len(origin.requests) == 1
