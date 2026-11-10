"""Git HTTPS authentication through the production native gateway."""

from __future__ import annotations

import base64
import json
import os
import select
import shlex
import socket
import socketserver
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import tomlkit

from safeyolo.api import AdminAPI
from tests.blackbox.native_credentials import native_cli, store_credential
from tests.proxy_contracts.harness import REPO, request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_gateway_risk_approval import AGENT_TOKEN, _gateway_policy, _gateway_token, _wait_for
from tests.proxy_contracts.test_native_coord_operator import terminal, wait_terminal_exit
from tests.proxy_contracts.test_native_network_policy import policy_proxy, replace_policy

PAT = "fixture-github-pat-312"


def basic(password, username="x-access-token"):
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def padding_alias(authorization):
    encoded = authorization.removeprefix("Basic ")
    unpadded = encoded.rstrip("=")
    assert len(encoded) - len(unpadded) in (1, 2)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet[alphabet.index(unpadded[-1]) | 1]
    alias = unpadded[:-1] + last + encoded[len(unpadded):]
    if alias == encoded or base64.b64decode(alias, validate=True) != base64.b64decode(encoded, validate=True):
        raise AssertionError("padding alias must preserve the decoded credentials")
    return "Basic " + alias


def test_basic_git_password_is_substituted_by_the_native_gateway(tmp_path):
    directory = tmp_path / "basic"
    directory.mkdir()
    services, builtin = directory / "services", directory / "builtin"
    services.mkdir()
    builtin.mkdir()
    (services / "git.yaml").write_text("""schema_version: 1
name: fixture_gateway
default_host: 127.0.0.1
auth:
  type: basic
  allow_http: true
capabilities:
  operator:
    routes:
      - methods: [GET, POST]
        path: /owner/repo.git/*
""")
    proxy_binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", REPO / "proxy/target/release/safeyolo-proxy"))
    binary = native_cli(Path(os.environ.get("SAFEYOLO_NATIVE_CLI", proxy_binary.with_name("safeyolo"))), proxy=proxy_binary)
    store_credential(directory / "data", "git-pat", PAT, binary=binary)
    vault_before = {name: (directory / "data" / name).read_bytes() for name in ("credentials.enc", "credentials.key")}
    operator_token = directory / "operator-token"
    operator_token.write_text("fixture-operator-312")
    with origin_server(capture_heads=True) as origin, policy_proxy(
        "rust", directory, _gateway_policy(origin.server_address[1]), agent_api=True, native_product=True,
        agent_api_token=AGENT_TOKEN.encode(), admin_port=0, admin_api_token_file=operator_token,
        gateway_services_dir=services, gateway_builtin_services_dir=builtin,
    ) as proxy:
        marker = json.loads(proxy.readiness_file.read_text())
        api = AdminAPI(base_url=f"http://127.0.0.1:{marker['admin_port']}", token=operator_token.read_text())
        api.authorize_service("alice", "fixture_gateway", "operator", "git-pat")
        opaque = _gateway_token(proxy)
        url = f"http://127.0.0.1:{origin.server_address[1]}/owner/repo.git/info/refs?service=git-upload-pack"
        status, _, _ = request(proxy.paths["alice"], url, headers={"Authorization": basic(opaque)})
        assert status == 200
        assert {name: (directory / "data" / name).read_bytes() for name in vault_before} == vault_before
        head = origin.request_heads[-1]
        if basic(PAT).encode() not in head:
            raise AssertionError("origin did not receive the host credential in Basic authentication")
        if basic(opaque).encode() in head:
            raise AssertionError("opaque Git password reached the origin")


class GitRequest(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.git()

    def do_POST(self):
        self.git()

    def git(self):
        self.server.requests.append((self.command, self.path))
        if self.headers.get("Authorization") != basic(PAT):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="owned-git-fixture"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.server.authorized.append((self.command, self.path))
        target = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        environment = dict(os.environ, GIT_PROJECT_ROOT=str(self.server.repositories),
                           GIT_HTTP_EXPORT_ALL="1", PATH_INFO=target.path, QUERY_STRING=target.query,
                           REQUEST_METHOD=self.command, CONTENT_TYPE=self.headers.get("Content-Type", ""),
                           CONTENT_LENGTH=str(length), REMOTE_USER="owned", SERVER_PROTOCOL="HTTP/1.1",
                           HTTP_GIT_PROTOCOL=self.headers.get("Git-Protocol", ""))
        environment.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
        backend = subprocess.run(["git", "http-backend"], input=self.rfile.read(length),
                                 capture_output=True, env=environment, timeout=10, check=True)
        headers, body = backend.stdout.split(b"\r\n\r\n", 1)
        fields = [line.decode().split(": ", 1) for line in headers.split(b"\r\n")]
        self.send_response(int(next((value.split()[0] for key, value in fields if key == "Status"), "200")))
        for key, value in fields:
            if key.lower() not in {"status", "content-length"}:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def git_origin(repositories):
    server = ThreadingHTTPServer(("127.0.0.1", 0), GitRequest)
    server.repositories, server.requests, server.authorized = repositories, [], []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class ProxyBridge(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(self.server.proxy_socket)
            peers = {peer: self.request, self.request: peer}
            while peers:
                readable, _, _ = select.select(list(peers), [], [], 15)
                if not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    peers[source].sendall(data)


@contextmanager
def git_proxy(socket_path):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), ProxyBridge) as server:
        server.daemon_threads = True
        server.proxy_socket = socket_path
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            thread.join(timeout=5)


def git(directory, *arguments, environment=None, succeeds=True):
    if environment is None:
        environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    result = subprocess.run(["git", "-c", "user.name=Git fixture", "-c", "user.email=git@example.invalid",
                             *arguments], cwd=directory, env=environment, capture_output=True, timeout=20)
    if (result.returncode == 0) != succeeds:
        diagnostic = result.stderr.decode(errors="replace")
        values = [PAT, basic(PAT), "fixture-host-op-auth-312"]
        if opaque := environment.get("GIT_TEST_OPAQUE"):
            values.extend([opaque, basic(opaque)])
        for value in values:
            diagnostic = diagnostic.replace(value, "[credential]")
        raise AssertionError(f"Git operation exited {result.returncode}; expected success={succeeds}\n{diagnostic}")
    for marker in (PAT.encode(), b"fixture-host-op-auth-312"):
        if marker in result.stdout + result.stderr:
            raise AssertionError("host credential appeared in Git output")
    return result.stdout.strip()


def test_real_git_fetch_push_approval_retry_and_provider_failure(tmp_path, monkeypatch):
    """Use an owned HTTP Git backend; live GitHub/op qualification is separate."""
    directory = tmp_path / "gateway"
    directory.mkdir()
    services, builtin = directory / "services", directory / "builtin"
    services.mkdir()
    builtin.mkdir()
    definition = (REPO / "cli/src/safeyolo/services/github-git.yaml").read_text()
    # All transport stays on loopback. Production keeps HTTPS-only injection.
    definition = definition.replace("type: basic", "type: basic\n  allow_http: true")
    definition = definition.replace("/*/*.git/", "/owner/allowed.git/")
    # A small adopted model exercises the current effect-policy owner too.
    definition += """
effect_model:
  sources:
    fixture: {location: tests/proxy_contracts/test_github_git.py, version: "1"}
  resources:
    repository: {description: Owned Git repository, identity: [name]}
  effects:
    refs_changed:
      description: Push may update repository refs
      persists_after_access: true
      evidence: [fixture]
  operations:
    push:
      method: POST
      path: /owner/allowed.git/git-receive-pack
      coverage: modeled
      arguments: {}
      resources:
        repository: {name: {kind: fixed, value: owner/allowed}}
      effects:
        - {effect: refs_changed, resource: repository, when: {kind: always}, evidence: [fixture]}
      execution_authority: Upstream Git permissions remain required
      evidence: [fixture]
      gaps: []
  enforcement: {}
  rules: {}
  alternatives: {}
  regressions: []
  gaps: []
"""
    (services / "github-git.yaml").write_text(definition)
    provider, calls = tmp_path / "op", tmp_path / "provider-calls"
    provider.write_text(f"#!/bin/sh\nprintf 'read\\n' >> '{calls}'\nprintf '%s' \"$OP_SERVICE_ACCOUNT_TOKEN\" >&2\nprintf '%s' '{PAT}'\n")
    provider.chmod(0o700)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "fixture-host-op-auth-312")
    proxy_binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", REPO / "proxy/target/release/safeyolo-proxy"))
    binary = native_cli(Path(os.environ.get("SAFEYOLO_NATIVE_CLI", proxy_binary.with_name("safeyolo"))), proxy=proxy_binary)
    subprocess.run([str(binary), "--root", str(directory), "init"], capture_output=True, check=True, timeout=15)
    host = tmp_path / "host"
    host.mkdir()
    data = directory / "data"
    data.mkdir(exist_ok=True)
    (host / "config.toml").write_text(f"data_dir={json.dumps(str(data))}\n")
    subprocess.run([str(binary), "--root", str(host), "credentials", "reference", "git-pat", "--storage", "local",
                    "--provider", "onepassword", "--reference", "op://fixture/github/pat"],
                   capture_output=True, check=True, timeout=15)
    operator_token = directory / "operator-token"
    operator_token.write_text("fixture-git-operator-token")
    repositories = tmp_path / "repositories"
    repositories.mkdir()
    bare = repositories / "owner/allowed.git"
    git(tmp_path, "init", "--bare", str(bare))
    git(bare, "config", "http.receivepack", "true")
    source = tmp_path / "source"
    source.mkdir()
    git(source, "init")
    (source / "proof").write_text("initial\n")
    git(source, "add", "proof")
    git(source, "commit", "-m", "Initial fixture")
    git(source, "push", str(bare), "HEAD:refs/heads/main")
    git(bare, "symbolic-ref", "HEAD", "refs/heads/main")
    policy = '''budget=12000
[hosts."github.com"]
egress="allow"
service="github-git"
[hosts."127.0.0.1"]
egress="allow"
[hosts."*"]
egress="deny"
[agents.alice]
agent_id="ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[agents.bob]
agent_id="ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
[controls.credentials]
enabled=true
detection_level="none"
use_default_credential_rules=false
standard_auth_headers=[]
[controls.credentials.entropy]
min_length=1000
[[risk]]
account="agent"
tactics=["impact"]
decision="require_approval"
'''
    with git_origin(repositories) as origin, policy_proxy(
        "rust", directory, policy, agent_api=True, native_product=True,
        agent_api_token=AGENT_TOKEN.encode(), admin_port=0, admin_api_token_file=operator_token,
        gateway_services_dir=services, gateway_builtin_services_dir=builtin,
        onepassword_executable=provider,
        target_ip_mappings=[{"host": "github.com", "ip": "127.0.0.1", "port": origin.server_address[1]}],
        flow_store_enabled=True,
    ) as proxy, git_proxy(proxy.paths["alice"]) as address:
        marker = json.loads(proxy.readiness_file.read_text())
        api = AdminAPI(base_url=f"http://127.0.0.1:{marker['admin_port']}", token=operator_token.read_text())
        api.authorize_service("alice", "github-git", "push", "git-pat")
        opaque = _gateway_token(proxy, "github-git")
        environment = dict(os.environ, http_proxy=address, https_proxy=address, HTTP_PROXY=address, HTTPS_PROXY=address,
                           GIT_TERMINAL_PROMPT="0", GIT_TEST_OPAQUE=opaque,
                           GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        environment.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
        guest = Path(os.environ.get("SAFEYOLO_NATIVE_GUEST", REPO / "guest/command/target/debug/safeyolo-guest"))
        share = tmp_path / "config-share"
        share.mkdir()
        (share / "agent_token").write_text(AGENT_TOKEN)
        native_helper = "!" + shlex.join([str(guest), "--context", str(share / "host-launch-context.json"), "git-credential"])
        filled = subprocess.run(["git", "-c", f"credential.helper={native_helper}", "credential", "fill"],
                                input=b"protocol=https\nhost=github.com\n\n", env=environment,
                                capture_output=True, timeout=15)
        if filled.returncode or f"password={opaque}\n".encode() not in filled.stdout:
            raise AssertionError("Git did not receive its opaque password from the native guest helper")
        if PAT.encode() in filled.stdout + filled.stderr:
            raise AssertionError("Git helper returned the upstream credential")
        ignored = subprocess.run([str(guest), "git-credential", "store"],
                                 input=f"protocol=https\nhost=github.com\npassword={PAT}\n\n".encode(),
                                 env=environment, capture_output=True, timeout=5)
        assert ignored.returncode == 0 and not ignored.stdout
        helper = '!f() { if test "$1" = get; then printf "username=x-access-token\\npassword=%s\\n" "$GIT_TEST_OPAQUE"; fi; }; f'
        remote = f"http://github.com:{origin.server_address[1]}/owner/allowed.git"
        client = tmp_path / "client"
        git(tmp_path, "-c", f"credential.helper={helper}", "clone", remote, str(client), environment=environment)
        (client / "proof").write_text("approved update\n")
        git(client, "commit", "-am", "Approved fixture update", environment=environment)
        before = calls.read_text()
        git(client, "-c", f"credential.helper={helper}", "push", environment=environment, succeeds=False)
        assert calls.read_text() == before, "push discovery must not resolve before approval"
        event = _wait_for(lambda: next((row for row in api.pending_approvals() if row.get("approval_id") and row.get("agent") == "alice"), None), "Git push approval")
        assert "alice wants to push to owner/allowed" in event["summary"]
        canonical = api.approval(event["approval_id"])
        assert canonical["action"]["github_repository"] == "owner/allowed"
        assert canonical["action"]["path"] == "/owner/allowed.git/git-receive-pack"
        instance = SimpleNamespace(root=directory, environment=dict(os.environ, TERM="xterm-256color"))
        with terminal(instance, command=[str(binary), "--root", str(directory), "watch", "--no-color"]) as (watch, master, until):
            output = until(b"alice wants to push to owner/allowed")
            if b"watch>" not in output:
                until(b"watch>")
            os.write(master, b"1\n")
            until(b"later >")
            os.write(master, b"approve once\n")
            until(b"CANONICAL OUTCOME Request #1: approved")
            os.write(master, b"q\n")
            assert wait_terminal_exit(watch, master, bytearray(), timeout=10) == 0
            assert api.approval(event["approval_id"])["status"] == "approved"
        git(client, "-c", f"credential.helper={helper}", "push", environment=environment)
        assert git(client, "rev-parse", "HEAD", environment=environment) == git(bare, "rev-parse", "refs/heads/main")
        assert any(method == "POST" and path.endswith("git-receive-pack") for method, path in origin.authorized)
        assert not api.list_gateway_grants()["grants"], "one push must consume its once grant after discovery"
        (client / "proof").write_text("denied update\n")
        git(client, "commit", "-am", "Denied fixture update", environment=environment)
        before = calls.read_text()
        git(client, "-c", f"credential.helper={helper}", "push", environment=environment, succeeds=False)
        event = _wait_for(lambda: next((row for row in api.pending_approvals() if row.get("approval_id") and row.get("agent") == "alice"), None), "Second Git push approval")
        api.resolve_approval(event["approval_id"], "reject")
        assert calls.read_text() == before, "denial must not resolve the PAT"
        before = calls.read_text()
        upstream_before = len(origin.requests)
        for authorization in [basic(opaque), *(padding_alias(basic(opaque, username)) for username in ("0", "00"))]:
            for agent, target_host, path in [("bob", "github.com", "/owner/allowed.git/git-upload-pack"),
                                             ("alice", "github.com", "/owner/other.git/git-upload-pack"),
                                             ("alice", "127.0.0.1", "/owner/allowed.git/git-upload-pack")]:
                code, _, _ = request(proxy.paths[agent], f"http://{target_host}:{origin.server_address[1]}{path}",
                                     method="POST", body=b"0000", headers={"Authorization": authorization})
                assert code == 403
                assert len(origin.requests) == upstream_before, "rejected opaque passwords must not reach the origin"
        assert calls.read_text() == before
        for username in ("0", "00"):
            code, _, _ = request(proxy.paths["alice"], remote + "/info/refs?service=git-upload-pack",
                                 headers={"Authorization": padding_alias(basic(opaque, username))})
            assert code == 200, "accepted padding aliases must substitute the host credential"
        # Current modeled-effect prohibitions still apply before a grant lookup.
        subprocess.run([str(binary), "--root", str(directory), "services", "approve", "alice", "github-git",
                        "POST", "/owner/allowed.git/git-receive-pack", "--lifetime", "session"],
                       capture_output=True, check=True, timeout=10)
        policy_file = Path(json.loads((directory / "proxy.json").read_text())["policy_file"])
        permitted_policy = policy_file.read_text()
        denied = tomlkit.parse(permitted_policy)
        denied["risk"] = [{"enables": ["refs_changed"], "decision": "deny"}]
        replace_policy(proxy, "rust", directory, tomlkit.dumps(denied))
        opaque = _gateway_token(proxy, "github-git")
        before, upstream_before = calls.read_text(), len(origin.requests)
        for method, path in [("GET", "/info/refs?service=git-receive-pack"), ("POST", "/git-receive-pack")]:
            code, _, body = request(proxy.paths["alice"], remote + path, method=method,
                                    headers={"Authorization": basic(opaque)})
            assert code == 403 and b"GATEWAY_RISKY_ROUTE" in body
        assert calls.read_text() == before and len(origin.requests) == upstream_before
        # Explicit current route denies apply to discovery and pack alike.
        denied = tomlkit.parse(permitted_policy)
        denied["hosts"]["github.com"]["rules"] = [{"action": "gateway:request",
            "resource": "github-git:/owner/allowed.git/git-upload-pack", "effect": "deny",
            "condition": {"agent": "alice"}}]
        replace_policy(proxy, "rust", directory, tomlkit.dumps(denied))
        opaque = _gateway_token(proxy, "github-git")
        for method, path in [("GET", "/info/refs?service=git-upload-pack"), ("POST", "/git-upload-pack")]:
            code, _, _ = request(proxy.paths["alice"], remote + path, method=method,
                                  headers={"Authorization": basic(opaque)})
            assert code == 403
        assert calls.read_text() == before and len(origin.requests) == upstream_before
        replace_policy(proxy, "rust", directory, permitted_policy)
        opaque = _gateway_token(proxy, "github-git")
        provider.write_text(f"#!/bin/sh\nprintf '%s' '{PAT}' >&2\nexit 17\n")
        code, _, body = request(proxy.paths["alice"], remote + "/info/refs?service=git-upload-pack", headers={"Authorization": basic(opaque)})
        assert code == 503 and b"PROVIDER_REJECTED" in body
        for path in directory.rglob("*"):
            if path.is_file():
                try:
                    content = path.read_bytes()
                except FileNotFoundError:
                    continue
                if any(value in content for value in (PAT.encode(), basic(PAT).encode(), b"fixture-host-op-auth-312")):
                    raise AssertionError(f"host credential persisted in {path.name}")
