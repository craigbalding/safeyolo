#!/usr/bin/env python3
"""Check installed native state through restart, replacement and recovery.

Use --native with the current installed CLI and its exact --install-commit.
No agent is booted: this is installed host composition, not guest isolation.
Each return process must read durable state, reset process-local task policy,
and enforce revocations before deliberately restoring access.

The historical cross-backend path remains temporarily for #320's independent
replacement check. It requires independently installed old/current wheels and
SAFEYOLO_PDP_DIR from the pinned old source. It is not the nightly selection.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if __package__:
    from .installed_host_smoke import (
        SmokeError,
        _native_config,
        _pid_alive,
        _process_start_token,
        _runtime_observation,
    )
    from .installed_sections import copy_prepared_nats, owned_processes, surviving_processes
else:
    from installed_host_smoke import (
        SmokeError,
        _native_config,
        _pid_alive,
        _process_start_token,
        _runtime_observation,
    )
    from installed_sections import copy_prepared_nats, owned_processes, surviving_processes

OLD_REVISION = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a"
BODY = b"owned-r638-response-needle\n"
PASS = "synthetic-r638-vault-passphrase"
TASK_ID = "r638-process-local"
TASK_POLICY = {"permissions": [{"action": "network:request", "resource": "127.0.0.2/*",
                                 "effect": "deny", "condition": {"agent": "alice"}}]}


class PreparationError(RuntimeError):
    """An installed command or owned cleanup did not complete."""


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_file(path: Path) -> None:
    check(path.is_file() and path.stat().st_mode & 0o777 == 0o600,
          f"private state file missing or has changed mode: {path}")


def ca_files(root: Path) -> dict[str, tuple[str, int]]:
    certs = root / "certs"
    return {path.name: (sha(path), path.stat().st_mode & 0o777)
            for path in certs.glob("mitmproxy-ca*") if path.is_file()}


def key_fingerprint(path: Path) -> str:
    return hmac.new(path.read_bytes(), b"synthetic-credential", hashlib.sha256).hexdigest()[:16]


def eventually(predicate, message: str, seconds: float = 8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError(message() if callable(message) else message)


def _process_running(pid: int) -> bool:
    return _pid_alive(pid)


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, *, oauth: bool = False):
        super().__init__(address, OriginHandler)
        self.oauth = oauth
        self.seen: list[dict] = []
        self.next_status = 200
        self.oauth_generation = 1


class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.seen.append({
            "method": self.command,
            "path": self.path,
            "body": body,
            "authorization": self.headers.get("Authorization", ""),
        })
        if self.server.oauth:
            generation = self.server.oauth_generation
            self.server.oauth_generation += 1
            payload = json.dumps({
                "access_token": f"synthetic-r638-access-v{generation}",
                "refresh_token": f"synthetic-r638-refresh-v{generation}",
                "expires_in": 3600,
            }).encode()
            content_type = "application/json"
        else:
            payload = BODY
            content_type = "text/plain"
        status = self.server.next_status
        self.server.next_status = 200
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: Path):
        super().__init__("localhost", timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect(str(self.path))


def request(socket_path: Path, method: str, target: str, *, token: str | None = None,
            body: bytes = b"", headers: dict | None = None):
    connection = UnixHTTP(socket_path)
    fields = {"Host": "_safeyolo.proxy.internal" if target in ("/health", "/circuits")
              or target.startswith("/api/") or target.startswith("/gateway/")
              or target.startswith("/plumb/") else "127.0.0.2"}
    if token:
        fields["Authorization"] = f"Bearer {token}"
    if body:
        fields["Content-Type"] = "application/json"
    fields.update(headers or {})
    try:
        connection.request(method, target, body=body, headers=fields)
        response = connection.getresponse()
        data = response.read(4 * 1024 * 1024)
        return response.status, data
    finally:
        connection.close()


def json_request(socket_path: Path, method: str, target: str, token: str,
                 payload: dict | None = None):
    status, raw = request(socket_path, method, target, token=token,
                          body=json.dumps(payload).encode() if payload is not None else b"")
    return status, json.loads(raw) if raw else None


def run(command: list[str], env: dict, *, timeout: float = 25) -> str:
    result = subprocess.run(command, env=env, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if result.returncode:
        raise PreparationError(f"{command[0]} {command[1:3]} exited {result.returncode}: "
                             f"{result.stderr[-1000:]} {result.stdout[-500:]}")
    return result.stdout


def installed_identity(cli: Path, revision: str) -> dict:
    launcher = cli.read_text().splitlines()[0]
    check(launcher.startswith("#!"), f"no interpreter in {cli}")
    python = Path(launcher[2:])
    code = "import json,safeyolo,pathlib,importlib.metadata as m,sys; p=pathlib.Path(safeyolo.__file__).parent; print(json.dumps({'package':str(p),'identity':json.loads((p/'_build_identity.json').read_text()),'version':m.version('safeyolo'),'python_version':sys.version.split()[0]}))"
    result = json.loads(run([str(python), "-I", "-c", code], os.environ.copy()))
    check("site-packages" in result["package"], "CLI is not an installed wheel")
    check(result["identity"]["source_revision"] == revision, "wheel revision mismatch")
    if revision == OLD_REVISION:
        check(result["version"] == "0.1.0", "old package version mismatch")
        check(result["python_version"] == "3.12.14", "old Python version mismatch")
        check(run([str(python), "-I", "-c",
                   "import importlib.metadata as m; print(m.version('mitmproxy'))"],
                  os.environ.copy()).strip() == "12.2.3", "old mitmproxy version mismatch")
    return {"interpreter": str(python), "package": result["package"],
            "version": result["version"], "python_version": result["python_version"],
            "source_revision": revision}


def env_for(root: Path) -> dict:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.pop("SAFEYOLO_RUST_PROXY", None)
    env.pop("SAFEYOLO_PYTHON_SOURCE", None)
    env.pop("SAFEYOLO_PDP_DIR", None)
    env["SAFEYOLO_CONFIG_DIR"] = str(root)
    env["SAFEYOLO_LOGS_DIR"] = str(root / "logs")
    env["SAFEYOLO_COORD_DATA_DIR"] = str(root / "data" / "coord")
    env["SAFEYOLO_NATS_TEST_INSTANCE"] = "installed-continuity-" + root.name
    return env


def unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def socket_for(root: Path, agent: str) -> Path:
    ip = "10.4.0.2" if agent == "alice" else "10.4.0.3"
    return root / "data" / "sockets" / f"{ip}_{agent}" / "proxy.sock"


def start(cli: Path, root: Path, env: dict, backend: str, rust_revision: str) -> dict:
    config = yaml.safe_load((root / "config.yaml").read_text())
    check("backend" not in config["proxy"], "package selection used proxy.backend")
    revision = OLD_REVISION if backend == "python" else rust_revision
    package = installed_identity(cli, revision)
    run([str(cli), "start", "--wait"], env, timeout=45)
    path = socket_for(root, "alice")
    check(path.is_socket(), f"{backend} did not publish Alice's listener")
    token = (root / "data" / "agent_token").read_text().strip()
    status, health = json_request(path, "GET", "/health", token)
    check(status == 200 and isinstance(health, dict), f"{backend} health failed")
    pid = int((root / "data" / "proxy.pid").read_text().strip()) if backend == "python" else \
        json.loads((root / "data" / "proxy-rust.json").read_text())["pid"]
    if backend == "rust":
        expected = Path(package["package"]) / "bin" / "safeyolo-proxy"
        native_path = root / "data/native.json"
        runtime = _runtime_observation(
            root, _native_config(native_path, Path.cwd()), expected,
            config_path=native_path, working_directory=Path.cwd(),
            require_running=True, require_authenticated_identity=True,
        )
        executable = runtime["actual_executable"]
        command = str(expected)
    else:
        executable = os.readlink(f"/proc/{pid}/exe")
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        check(package["interpreter"] in command and "safeyolo.traffic_master" in command,
              "old Python process did not use selected wheel interpreter")
    identity = {"backend": backend, "pid": pid, "executable": executable,
                "command": command[:220], "health_status": status,
                "cli": str(cli), "package": package}
    if backend == "rust":
        identity["runtime"] = runtime
        identity["binary_sha256"] = sha(Path(executable))
        identity["binary_version"] = run([executable, "--version"], env).strip()
    return identity


def stop(cli: Path, root: Path, env: dict) -> None:
    processes = owned_processes(root)
    run([str(cli), "stop"], env)
    check(not surviving_processes(processes), "stop left an owned native/NATS process alive")
    check(not any((root / "data" / marker).exists() for marker in
                  ("proxy.pid", "proxy-rust.json", "proxy-readiness.json")),
          "stop left a process or readiness marker")
    for agent in ("alice", "bob"):
        with socket.socket(socket.AF_UNIX) as probe:
            try:
                probe.settimeout(0.25)
                probe.connect(str(socket_for(root, agent)))
            except OSError:
                # A stopped listener must reject connection attempts.
                continue
        raise AssertionError(f"{agent}'s listener remained accepting after stop")


def admin(root: Path, method: str, target: str, payload: dict | None = None,
          *, backend: str = "rust"):
    port = (yaml.safe_load((root / "config.yaml").read_text())["proxy"]["admin_port"]
            if backend == "python" else
            json.loads((root / "data" / "proxy-readiness.json").read_text())["admin_port"])
    token = (root / "data" / "admin_token").read_text().strip()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(1024 * 1024)
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


def installed_python(cli: Path, env: dict, code: str, *args: str):
    interpreter = cli.read_text().splitlines()[0][2:]
    result = run([interpreter, "-I", "-c", code, *args], env)
    return json.loads(result) if result.strip() else None


def ensure_nats(old_cli: Path, env: dict) -> dict:
    return installed_python(old_cli, env, """
import json
from safeyolo.coord import nats_runtime
pid=nats_runtime.start_server(ready_timeout=8.0)
print(json.dumps({'pid':pid,'version':nats_runtime.NATS_VERSION}))
""")


def summary_value(value: bytes) -> dict:
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def native_flow(root: Path, listener: Path, token: str, flow_id: int, tag: str) -> dict:
    """Read persisted ownership, exact bodies, tag and correlated durable audit."""
    status, flow = json_request(listener, "GET", f"/api/flows/{flow_id}", token)
    check(status == 200 and flow["agent_id"] == flow["evidence_owner"] == "alice",
          "replacement lost exact persisted flow ownership")
    value = "owned" if tag == "native" else "rollback"
    check(any(item.get("tag") == tag and item.get("value") == value
              for item in flow["tags"]), "replacement lost persisted flow tag")
    for side, expected in (("request", b"owned-r638-request-needle"), ("response", BODY)):
        status, body = json_request(listener, "GET", f"/api/flows/{flow_id}/{side}-body", token)
        check(status == 200 and base64.b64decode(body["body_base64"], validate=True) == expected,
              f"replacement changed exact persisted {side} body")
    check(any((event := json.loads(line)).get("event") == "traffic.response" and
              event.get("request_id") == flow["request_id"] and event.get("agent") == "alice"
              for line in (root / "logs/safeyolo.jsonl").read_text().splitlines() if line.strip()),
          "replacement lost durable audit correlation")
    return flow


def https_origin(root: Path) -> tuple[Origin, Path]:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "r638-owned-root")])
    now = datetime.now(UTC)
    root_cert = (x509.CertificateBuilder()
        .subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(root_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "r638-owned-origin")])
    leaf_cert = (x509.CertificateBuilder()
        .subject_name(leaf_name).issuer_name(root_name).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False)
        .add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.2"))]), critical=False)
        .sign(root_key, hashes.SHA256()))
    cert_path = root / "owned-origin-root.pem"
    leaf_path = root / "owned-origin-cert.pem"
    key_path = root / "owned-origin-key.pem"
    cert_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    leaf_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    key_path.chmod(0o600)
    server = Origin(("127.0.0.2", 0))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(leaf_path), str(key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server, cert_path


def trusted_tls_request(socket_path: Path, origin_port: int, root: Path) -> dict:
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(str(socket_path))
        connection.sendall((f"CONNECT 127.0.0.2:{origin_port} HTTP/1.1\r\n"
                            f"Host: 127.0.0.2:{origin_port}\r\n\r\n").encode())
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) < 8192:
            response.extend(connection.recv(4096))
        check(response.startswith(b"HTTP/1.1 200") or response.startswith(b"HTTP/1.0 200"),
              f"proxy CONNECT failed: {response[:100]!r}")
        context = ssl.create_default_context(cafile=str(root / "certs/mitmproxy-ca-cert.pem"))
        with context.wrap_socket(connection, server_hostname="127.0.0.2") as secured:
            peer = secured.getpeercert(binary_form=True)
            secured.sendall((f"GET /tls HTTP/1.1\r\nHost: 127.0.0.2:{origin_port}\r\n"
                             "X-SafeYolo-Test-Context: run=owned;agent=alice;test=R638\r\n"
                             "Connection: close\r\n\r\n").encode())
            reply = http.client.HTTPResponse(secured)
            reply.begin()
            body = reply.read()
            check(reply.status == 200 and body == BODY,
                  f"trusted TLS response changed: {reply.status} {body[:180]!r}")
            return {"status": reply.status, "body": summary_value(body),
                    "peer_certificate_sha256": hashlib.sha256(peer).hexdigest()}


def post_deletion_transition(args, old_id: dict, rust_id: dict, pdp_dir: Path) -> None:
    """Exercise the installed package return without repeating the #638 inventory."""
    root = Path(tempfile.mkdtemp(prefix="r640-package-return-", dir=args.state_parent))
    env = env_for(root)
    old_env = dict(env, SAFEYOLO_PDP_DIR=str(pdp_dir.resolve()))
    active: Path | None = None
    nats_started = False
    stages: list[dict] = []
    origin = Origin(("127.0.0.2", 0))
    oauth = Origin(("127.0.0.1", 0), oauth=True)
    tls_origin, tls_cert_path = https_origin(root)
    servers = (origin, oauth, tls_origin)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        run([str(args.old_cli), "init", "--no-interactive"], old_env)
        (root / ".safeyolo-platform-smoke").touch()
        config_path = root / "config.yaml"
        config = yaml.safe_load(config_path.read_text())
        config["proxy"].update({"port": unused_port(), "admin_port": unused_port(),
                                "web_port": unused_port(),
                                "rust_config": str(root / "data/native.json"),
                                "upstream_ca_cert": str(tls_cert_path)})
        config["proxy"].pop("backend", None)
        config_path.write_text(yaml.safe_dump(config, sort_keys=False))
        (root / "data/agent_map.json").write_text(json.dumps({
            "alice": {"ip": "10.4.0.2"}, "bob": {"ip": "10.4.0.3"}}))
        installed_python(args.old_cli, old_env, """
import json
from safeyolo.agents_store import save_agent
save_agent('alice',{'agent_id':'ag-r640-alice'})
save_agent('bob',{'agent_id':'ag-r640-bob'})
print(json.dumps({'agents':'registered'}))
""")
        service_dir = root / "services"
        service_dir.mkdir(exist_ok=True)
        (service_dir / "contract.yaml").write_text("""schema_version: 1
name: contract
default_host: 127.0.0.2
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
  refresh_on_401: true
risky_routes:
  - path: /v1/write
    methods: [POST]
    tactics: [exfiltration]
capabilities:
  writer:
    routes:
      - methods: [POST]
        path: /v1/write
    contract:
      template: contract.write.v1
      bindings:
        project:
          source: operator
          type: enum
          options: [alpha]
        ticket:
          source: operator
          type: string
      operations:
        - name: write
          request:
            method: POST
            path: /v1/write
            query:
              allow:
                ticket:
                  equals_var: ticket
            body:
              allow:
                project:
                  equals_var: project
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
""")
        installed_python(args.old_cli, old_env, """
import json,sys,tomlkit
from pathlib import Path
from safeyolo.policy.toml_roundtrip import locked_policy_mutate
def update(doc):
    host=tomlkit.inline_table(); host['service']='contract'
    doc['hosts']['127.0.0.2']=host
    doc['agents']=tomlkit.table()
    for name in ('alice','bob'):
        doc['agents'][name]=tomlkit.table()
        doc['agents'][name]['agent_id']='ag-r640-'+name
    doc['agents']['alice']['hosts']=tomlkit.table()
    tls=tomlkit.inline_table(); tls['egress']='allow'; tls['rate']=600
    doc['agents']['alice']['hosts']['127.0.0.2:'+sys.argv[2]]=tls
    doc['addons']=tomlkit.table()
    doc['addons']['credential_guard']=tomlkit.table()
    doc['addons']['credential_guard']['enabled']=True
    doc['addons']['credential_guard']['detection_level']='none'
    doc['addons']['credential_guard']['settings']=tomlkit.table()
    doc['addons']['credential_guard']['settings']['use_default_credential_rules']=False
    doc['addons']['credential_guard']['settings']['entropy']=tomlkit.table()
    doc['addons']['credential_guard']['settings']['entropy']['min_length']=1000
locked_policy_mutate(Path(sys.argv[1]),update)
print(json.dumps({'policy':'created'}))
""", str(root / "policy.toml"), str(tls_origin.server_port))
        run([str(args.old_cli), "policy", "egress", "set", "deny"], old_env)
        installed_python(args.old_cli, old_env, """
import json,sys
from pathlib import Path
from safeyolo.core.vault import Vault,VaultCredential
p=Path(sys.argv[1]); v=Vault(p/'vault.yaml.enc'); v.unlock(sys.argv[2])
v.store(VaultCredential('contract-secret','oauth2','synthetic-r638-expired',
    refresh_token='synthetic-r638-refresh-v0',token_url=sys.argv[3],
    client_id='r640',client_secret='synthetic-client',expires_at='2020-01-01T00:00:00+00:00'))
(p/'vault.key').write_text(sys.argv[2]); (p/'vault.key').chmod(0o600)
print(json.dumps({'names':v.list_names()}))
""", str(root / "data"), PASS,
                   f"http://127.0.0.1:{oauth.server_port}/oauth/token")
        print(json.dumps({"state": str(root), "old": old_id, "rust": rust_id}), flush=True)
        active = args.old_cli
        stages.append(start(active, root, old_env, "python", args.rust_revision))
        alice, bob = socket_for(root, "alice"), socket_for(root, "bob")
        agent_token = (root / "data/agent_token").read_text().strip()
        ca, hmac = root / "certs/mitmproxy-ca.pem", root / "data/hmac_secret"
        ca_snapshot = ca_files(root)
        hmac_hash = sha(hmac)
        old_vault_hash = sha(root / "data/vault.yaml.enc")
        for path in (ca, hmac, root / "data/vault.key", root / "data/vault.yaml.enc"):
            private_file(path)
        old_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        initial_denied, _ = request(alice, "GET", f"http://127.0.0.2:{origin.server_port}/before")
        check(initial_denied in (403, 428) and not origin.seen,
              f"old package did not enforce initial denial: {initial_denied}")
        stop(active, root, old_env)
        active = None
        nats_identity = ensure_nats(args.old_cli, old_env)
        nats_started = True

        active = args.rust_cli
        stages.append(start(active, root, env, "rust", args.rust_revision))
        check(ca_files(root) == ca_snapshot and sha(hmac) == hmac_hash,
              "post-deletion Rust changed old CA/HMAC state")
        rust_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        approval_status, _ = admin(root, "POST", "/admin/policy/host/allow",
                                   {"host": "127.0.0.2", "port": origin.server_port,
                                    "agent": "alice", "rate": 600})
        check(approval_status == 200, "post-deletion Rust could not write scoped approval")
        def allowed():
            status, body = request(alice, "GET", f"http://127.0.0.2:{origin.server_port}/allow")
            return (status, body) if status == 200 else None
        allowed_status, allowed_body = eventually(allowed, "Rust approval did not take effect")
        check(allowed_body == BODY, "Rust approval changed origin body")
        before = len(origin.seen)
        rust_denied, _ = request(bob, "GET", f"http://127.0.0.2:{origin.server_port}/deny")
        check(rust_denied in (403, 428) and len(origin.seen) == before,
              "Rust scoped approval leaked to Bob")
        status, _ = admin(root, "POST", "/admin/agents/alice/services",
                          {"service": "contract", "capability": "writer",
                           "credential": "contract-secret"})
        check(status == 200, "Rust service authorization failed")
        def gateway_token():
            status, catalog = json_request(alice, "GET", "/gateway/services", agent_token)
            return catalog.get("authorized", {}).get("contract", {}).get("token") if status == 200 else None
        before = len(origin.seen)
        status, _ = request(
            alice, "POST", f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
            token=eventually(gateway_token, "Rust service token did not become active"),
            body=b'{"project":"alpha"}')
        check(status in (403, 428) and len(origin.seen) == before,
              "Rust risky route crossed without a binding and grant")
        status, binding = admin(root, "POST", "/admin/gateway/contract-binding", {
            "agent": "alice", "service": "contract", "capability": "writer",
            "template": "contract.write.v1", "bindings": {"project": "alpha", "ticket": "T-1"},
            "grantable_operations": ["write"]})
        check(status == 200 and binding.get("binding_id"), "Rust binding write failed")
        status, grant = admin(root, "POST", "/admin/gateway/grant", {
            "agent": "alice", "service": "contract", "method": "POST",
            "path": "/v1/write", "lifetime": "remembered"})
        check(status == 200 and grant.get("grant_id"), "Rust grant write failed")
        def granted():
            token = gateway_token()
            if token is None:
                return None
            status, body = request(alice, "POST",
                                   f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
                                   token=token, body=b'{"project":"alpha"}')
            return (status, body) if status == 200 else None
        rust_granted, body = eventually(granted, "Rust service/grant did not reach origin")
        check(body == BODY and origin.seen[-1]["authorization"] ==
              "Bearer synthetic-r638-access-v1", "Rust did not use old vault credential")
        native_vault_hash = sha(root / "data/vault.yaml.enc")
        check(native_vault_hash != old_vault_hash,
              "Rust did not durably refresh the old vault credential")
        installed_python(args.old_cli, old_env, """
import json,sys,tomlkit
from pathlib import Path
from safeyolo.policy.toml_roundtrip import locked_policy_mutate
def add(doc):
    context=tomlkit.table()
    context['target_hosts']=['127.0.0.2']
    context['inject_declared']=True
    doc['addons']['test_context']=context
locked_policy_mutate(Path(sys.argv[1]),add)
print(json.dumps({'test_context':'enabled_for_task_check'}))
""", str(root / "policy.toml"))
        task_policy_hash = sha(root / "policy.toml")
        def context_active():
            status, _ = request(
                alice, "GET", f"http://127.0.0.2:{origin.server_port}/context-ready")
            return status == 428
        eventually(context_active, "Rust did not publish the task test context")
        status, registered = admin(root, "PUT", f"/admin/policy/task/{TASK_ID}",
                                   {"policy": TASK_POLICY})
        check(status == 200 and registered.get("permission_count") == 1,
              "Rust task registration failed")
        status, activated = admin(root, "POST", f"/admin/policy/task/{TASK_ID}/activate")
        check(status == 200 and activated.get("permission_count") == 1,
              "Rust task activation failed")
        before = len(origin.seen)
        def task_denied():
            status, _ = request(
                alice, "GET", f"http://127.0.0.2:{origin.server_port}/task",
                headers={"X-SafeYolo-Test-Context":
                         "run=owned;agent=alice;test=R638"})
            return status if status == 403 else None
        native_task_denied = eventually(task_denied, "Rust task overlay did not deny")
        check(native_task_denied == 403 and len(origin.seen) == before,
              "Rust task overlay did not deny before origin contact")
        check(sha(root / "policy.toml") == task_policy_hash,
              "Rust task registration changed durable policy")
        installed_python(args.old_cli, old_env, """
import json,sys
from pathlib import Path
from safeyolo.policy.toml_roundtrip import locked_policy_mutate
def remove(doc): del doc['addons']['test_context']
locked_policy_mutate(Path(sys.argv[1]),remove)
print(json.dumps({'test_context':'removed_after_task_check'}))
""", str(root / "policy.toml"))
        policy_hash = sha(root / "policy.toml")
        stop(active, root, env)
        active = None

        active = args.old_cli
        stages.append(start(active, root, old_env, "python", args.rust_revision))
        check(ca_files(root) == ca_snapshot and sha(hmac) == hmac_hash,
              "old package changed CA/HMAC on rollback")
        rollback_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        task_status, _ = admin(root, "GET", f"/admin/policy/task/{TASK_ID}", backend="python")
        check(task_status == 404, "old process inherited Rust task registration")
        old_allowed, old_body = request(alice, "GET", f"http://127.0.0.2:{origin.server_port}/old")
        check(old_allowed == 200 and old_body == BODY,
              "old package did not use Rust scoped approval")
        before = len(origin.seen)
        old_denied, _ = request(bob, "GET", f"http://127.0.0.2:{origin.server_port}/old-deny")
        check(old_denied in (403, 428) and len(origin.seen) == before,
              "old package allowed Bob through Alice's approval")
        status, old_catalog = json_request(alice, "GET", "/gateway/services", agent_token)
        check(status == 200 and old_catalog.get("authorized", {}).get("contract"),
              "old package did not read Rust service authorization")
        old_grant_status, old_grant_body = request(
            alice, "POST", f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
            token=old_catalog["authorized"]["contract"]["token"],
            body=b'{"project":"alpha"}')
        check(old_grant_status == 200 and old_grant_body == BODY and
              origin.seen[-1]["authorization"] == "Bearer synthetic-r638-access-v1",
              "old package did not use Rust grant and vault credential")
        installed_python(args.old_cli, old_env, """
import json,sys
from pathlib import Path
from safeyolo.mitm_addons.service_gateway import ServiceGateway
gateway=ServiceGateway(); gateway._get_policy_path=lambda:Path(sys.argv[1])
gateway._load_grants_from_policy(); gateway._load_contract_bindings_from_policy()
assert gateway._check_grant('alice','contract','POST','/v1/write').grant_id==sys.argv[2]
assert gateway.get_contract_binding('alice','contract','writer').binding_id==sys.argv[3]
print(json.dumps({'old_grant_and_binding_read':True}))
""", str(root / "policy.toml"), grant["grant_id"], binding["binding_id"])
        check(sha(root / "data/vault.yaml.enc") == native_vault_hash,
              "old package changed the native-refreshed vault")
        status, registered = admin(root, "PUT", f"/admin/policy/task/{TASK_ID}",
                                   {"policy": TASK_POLICY}, backend="python")
        check(status == 200 and registered.get("permission_count") == 1,
              "old task registration failed")
        status, saved_task = admin(root, "GET", f"/admin/policy/task/{TASK_ID}",
                                   backend="python")
        check(status == 200 and saved_task.get("policy") == TASK_POLICY,
              "old process did not retain its task registration")
        check(sha(root / "policy.toml") == policy_hash,
              "old task registration changed durable policy")
        stop(active, root, old_env)
        active = None

        active = args.rust_cli
        stages.append(start(active, root, env, "rust", args.rust_revision))
        check(stages[-1]["pid"] != stages[1]["pid"], "Rust return reused prior process")
        check(ca_files(root) == ca_snapshot and sha(hmac) == hmac_hash,
              "return Rust changed CA/HMAC identity")
        returned_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        returned_task_get, _ = admin(root, "GET", f"/admin/policy/task/{TASK_ID}")
        check(returned_task_get == 404, "fresh Rust inherited prior task registration")
        returned_task_activate, _ = admin(root, "POST", f"/admin/policy/task/{TASK_ID}/activate")
        check(returned_task_activate == 404, "fresh Rust activated a prior task")
        return_allowed, return_body = request(
            alice, "GET", f"http://127.0.0.2:{origin.server_port}/returned")
        check(return_allowed == 200 and return_body == BODY,
              "return Rust did not use retained scoped approval")
        before = len(origin.seen)
        return_denied, _ = request(
            bob, "GET", f"http://127.0.0.2:{origin.server_port}/returned-deny")
        check(return_denied in (403, 428) and len(origin.seen) == before,
              "return Rust allowed Bob through Alice's approval")
        return_granted, return_grant_body = eventually(
            granted, "return Rust did not use retained service/grant")
        check(return_grant_body == BODY and origin.seen[-1]["authorization"] ==
              "Bearer synthetic-r638-access-v1", "return Rust lost vault credential")
        check(sha(root / "data/vault.yaml.enc") == native_vault_hash,
              "return Rust changed the retained credential")
        check(sha(root / "policy.toml") == policy_hash,
              "package rollback changed durable policy")
        for path in (ca, hmac, root / "data/vault.key", root / "data/vault.yaml.enc"):
            private_file(path)
        stop(active, root, env)
        active = None
        installed_python(args.old_cli, old_env, """
import json
from safeyolo.coord import nats_runtime
nats_runtime.stop_server()
print(json.dumps({'nats':'stopped'}))
""")
        nats_started = False
        eventually(lambda: not _process_running(nats_identity["pid"]),
                   "transition left its NATS server running")
        run(["tmux", "-S", str(root / "data/traffic-tmux.sock"), "kill-server"], env)
        eventually(lambda: all(not _process_running(stage["pid"]) for stage in stages),
                   "transition left an old or new proxy process running")
        print(json.dumps({"result": "linux_post_deletion_package_return_passed",
                          "state": str(root), "stages": stages,
                          "statuses": {"initial_denied": initial_denied,
                                       "rust_allowed": allowed_status, "rust_denied": rust_denied,
                                       "old_allowed": old_allowed, "old_denied": old_denied,
                                       "return_allowed": return_allowed,
                                       "return_denied": return_denied,
                                       "grants": [rust_granted, old_grant_status, return_granted],
                                       "task_active": native_task_denied,
                                       "task_reset": [returned_task_get, returned_task_activate]},
                          "ca_hmac_unchanged": True,
                          "trusted_tls_statuses": [old_tls["status"], rust_tls["status"],
                                                   rollback_tls["status"], returned_tls["status"]],
                          "durable_policy_service_grant": "used across all package switches",
                          "task_policy": "registrations reset on process replacement",
                          "processes_stopped": True, "agents_started": 0}), flush=True)
    finally:
        if active is not None:
            try:
                stop(active, root, old_env if active == args.old_cli else env)
            except Exception as exc:
                print(f"cleanup failed: {type(exc).__name__}: {exc}", flush=True)
        if nats_started:
            try:
                installed_python(args.old_cli, old_env, """
import json
from safeyolo.coord import nats_runtime
nats_runtime.stop_server()
print(json.dumps({'nats':'stopped'}))
""")
            except Exception as exc:
                print(f"NATS cleanup failed: {type(exc).__name__}: {exc}", flush=True)
        for server in servers:
            server.shutdown()
            server.server_close()
        # A failed start may not have created the private tmux server.
        subprocess.run(["tmux", "-S", str(root / "data/traffic-tmux.sock"), "kill-server"],
                       capture_output=True, check=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", action="store_true", help="Current installed native replacement/recovery")
    parser.add_argument("--old-cli", type=Path, help="Historical cross-backend fixture only")
    parser.add_argument("--cli", "--rust-cli", dest="rust_cli", required=True, type=Path)
    parser.add_argument("--install-commit", "--rust-revision", dest="rust_revision", required=True)
    parser.add_argument("--state-parent", required=True, type=Path)
    parser.add_argument("--config-dir", type=Path, help="New isolated directory for the native procedure")
    parser.add_argument("--output", type=Path, help="Bounded native result report")
    parser.add_argument("--prepared-config", type=Path, help="Prepared product's verified NATS executable")
    parser.add_argument("--post-deletion", action="store_true",
                        help="Run the focused package return without the full #638 inventory")
    args = parser.parse_args()
    rust_id = installed_identity(args.rust_cli, args.rust_revision)
    if args.native:
        if args.old_cli or args.post_deletion:
            parser.error("--native cannot select historical cross-backend fixtures")
        args.old_cli = args.rust_cli
        old_id = rust_id
        pdp_dir = None
    else:
        if args.old_cli is None or args.config_dir is not None or args.output is not None:
            parser.error("historical execution requires --old-cli; native result options require --native")
        old_id = installed_identity(args.old_cli, OLD_REVISION)
        pdp_dir = Path(os.environ.get("SAFEYOLO_PDP_DIR", ""))
        check(pdp_dir.is_dir() and (pdp_dir / "__init__.py").is_file(),
              "SAFEYOLO_PDP_DIR must name the selected old source's pdp directory")
        source_revision = run(["git", "-C", str(pdp_dir.parent), "rev-parse", "HEAD"],
                              os.environ.copy()).strip()
        check(source_revision == OLD_REVISION, "old pdp source revision mismatch")
    args.state_parent.mkdir(parents=True, exist_ok=True)
    if args.post_deletion:
        post_deletion_transition(args, old_id, rust_id, pdp_dir)
        return
    if args.config_dir is not None:
        root = args.config_dir.resolve()
        root.mkdir(parents=True, exist_ok=False)
    else:
        root = Path(tempfile.mkdtemp(prefix="installed-continuity-", dir=args.state_parent))
    env = env_for(root)
    if args.prepared_config is not None:
        copy_prepared_nats(args.prepared_config, root)
    old_env = env if args.native else dict(env, SAFEYOLO_PDP_DIR=str(pdp_dir.resolve()))
    prior_backend = "rust" if args.native else "python"
    stages: list[dict] = []
    active: Path | None = None
    nats_started = False
    origin = Origin(("127.0.0.2", 0))
    oauth = Origin(("127.0.0.1", 0), oauth=True)
    tls_origin, tls_cert_path = https_origin(root)
    threads = [threading.Thread(target=server.serve_forever, daemon=True)
               for server in (origin, oauth, tls_origin)]
    for thread in threads:
        thread.start()
    try:
        run([str(args.old_cli), "init", "--no-interactive"], old_env)
        (root / ".safeyolo-platform-smoke").touch()
        config = yaml.safe_load((root / "config.yaml").read_text())
        config["proxy"].update({"port": 0 if args.native else unused_port(),
                                "admin_port": 0 if args.native else unused_port(),
                                "web_port": 0 if args.native else unused_port(),
                                "upstream_ca_cert": str(tls_cert_path)})
        if args.native:
            config["proxy"]["upstream_proxy"] = ""
        else:
            config["proxy"]["rust_config"] = str(root / "data/native.json")
        config["proxy"].pop("backend", None)
        (root / "config.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
        (root / "data/agent_map.json").write_text(json.dumps({
            "alice": {"ip": "10.4.0.2"}, "bob": {"ip": "10.4.0.3"}}))
        installed_python(args.old_cli, old_env, """
import json
from safeyolo.agents_store import save_agent
save_agent('alice',{'agent_id':'ag-r638-alice'})
save_agent('bob',{'agent_id':'ag-r638-bob'})
print(json.dumps({'agents':'registered'}))
""")
        # The old writer creates the canonical encrypted file and its key.
        installed_python(args.old_cli, old_env, """
import json,sys
from pathlib import Path
from safeyolo.core.vault import Vault,VaultCredential
p=Path(sys.argv[1]); v=Vault(p/'vault.yaml.enc'); v.unlock(sys.argv[2]);
v.store(VaultCredential('contract-secret','oauth2','synthetic-r638-expired',
    refresh_token='synthetic-r638-refresh-v0',token_url=sys.argv[3],
    client_id='r638',client_secret='synthetic-client',expires_at='2020-01-01T00:00:00+00:00'))
(p/'vault.key').write_text(sys.argv[2]); (p/'vault.key').chmod(0o600)
print(json.dumps({'names':v.list_names()}))
""", str(root / "data"), PASS,
                   f"http://127.0.0.1:{oauth.server_port}/oauth/token")
        # A service file is an operator-authored input, shared by both releases.
        service_dir = root / "services"
        service_dir.mkdir(exist_ok=True)
        (service_dir / "contract.yaml").write_text("""schema_version: 1
name: contract
default_host: 127.0.0.2
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
  refresh_on_401: true
risky_routes:
  - path: /v1/write
    methods: [POST]
    tactics: [exfiltration]
capabilities:
  writer:
    routes:
      - methods: [POST, GET]
        path: /v1/write
    contract:
      template: contract.write.v1
      bindings:
        project:
          source: operator
          type: enum
          options: [alpha]
        ticket:
          source: operator
          type: string
      operations:
        - name: write
          request:
            method: POST
            path: /v1/write
            query:
              allow:
                ticket:
                  equals_var: ticket
            body:
              allow:
                project:
                  equals_var: project
        - name: read
          request:
            method: GET
            path: /v1/write
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
""")
        catalog_override = service_dir / "gmail.yaml"
        catalog_override.write_text("""schema_version: 1
name: gmail
description: r638 disposable user override
default_host: 127.0.0.2
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /v1/catalog
""")
        installed_python(args.old_cli, old_env, """
import json,sys,tomlkit
from pathlib import Path
from safeyolo.policy.toml_roundtrip import locked_policy_mutate
def update(doc):
    host=tomlkit.inline_table(); host['service']='contract'
    doc['hosts']['127.0.0.2']=host
    doc['agents']=tomlkit.table()
    doc['agents']['alice']=tomlkit.table()
    doc['agents']['alice']['agent_id']='ag-r638-alice'
    doc['agents']['alice']['hosts']=tomlkit.table()
    tls_host=tomlkit.inline_table(); tls_host['egress']='allow'; tls_host['rate']=600
    doc['agents']['alice']['hosts']['127.0.0.2:'+sys.argv[2]]=tls_host
    doc['agents']['bob']=tomlkit.table()
    doc['agents']['bob']['agent_id']='ag-r638-bob'
    doc['addons']=tomlkit.table()
    doc['addons']['test_context']=tomlkit.table()
    doc['addons']['test_context']['target_hosts']=['127.0.0.2']
    doc['addons']['test_context']['inject_declared']=True
    doc['addons']['credential_guard']=tomlkit.table()
    doc['addons']['credential_guard']['enabled']=True
    doc['addons']['credential_guard']['detection_level']='none'
    doc['addons']['credential_guard']['settings']=tomlkit.table()
    doc['addons']['credential_guard']['settings']['use_default_credential_rules']=False
    doc['addons']['credential_guard']['settings']['entropy']=tomlkit.table()
    doc['addons']['credential_guard']['settings']['entropy']['min_length']=1000
    doc['addons']['circuit_breaker']=tomlkit.table()
    doc['addons']['circuit_breaker']['failure_threshold']=2
    doc['addons']['circuit_breaker']['success_threshold']=1
    doc['addons']['circuit_breaker']['timeout_seconds']=120
    doc['addons']['circuit_breaker']['use_exponential_backoff']=False
    doc['addons']['circuit_breaker']['jitter_factor']=0
locked_policy_mutate(Path(sys.argv[1]),update)
print(json.dumps({'policy':'created'}))
""", str(root / "policy.toml"), str(tls_origin.server_port))
        run([str(args.old_cli), "policy", "egress", "set", "deny"], old_env)
        check(tomllib.loads((root / "policy.toml").read_text())["hosts"]["*"]["egress"] == "deny",
              "old policy writer did not set wildcard egress deny")
        provider_dir = root / "coord-providers"
        provider_dir.mkdir()
        provider_snapshot = provider_dir / "fixture.json"
        observed_at = int(time.time() * 1000)
        provider_snapshot.write_text(json.dumps({"leases": [{
            "resource": "slot", "state": "held", "holder_agent_id": "ag-r638-bob",
            "observed_at": observed_at, "valid_until": observed_at + 300_000,
        }]}))
        provider_hash = sha(provider_snapshot)
        print(json.dumps({"state": str(root), "old": old_id, "rust": rust_id}), flush=True)
        active = args.old_cli
        stages.append(start(active, root, old_env, prior_backend, args.rust_revision))
        agent_token = (root / "data/agent_token").read_text().strip()
        alice = socket_for(root, "alice")
        old_coord = installed_python(args.old_cli, old_env, """
import asyncio,json
from safeyolo.coord import api
api.bootstrap()
async def exercise():
    room_id=await api.create_room('r638-rollback')
    api.grant('r638-rollback','agent','ag-r638-alice',operation_id='r638-grant-alice')
    api.grant('r638-rollback','agent','ag-r638-bob',operation_id='r638-grant-bob')
    api.advertise_resource('r638-rollback','fixture','slot',advertised=True,
                           operation_id='r638-resource-advertisement')
    sent=await api.send('r638-rollback','agent','ag-r638-alice','python-created-r638',
        declared_content_type='text/plain',sender_agent_name='alice',notify=['bob'])
    page=await api.read_room('r638-rollback','agent','ag-r638-bob')
    assert len(page['messages'])==1
    state=await api.get_room_state('r638-rollback','agent','ag-r638-bob')
    assert state['resource_leases'][0]['state']=='held'
    assert state['resource_leases'][0]['holder_agent_id']=='ag-r638-bob'
    return {'room_id':room_id,'message_id':sent['envelope']['msg_id'],
            'sequence':page['messages'][0]['sequence'],'attention_status':sent['attention_status'],
            'provider_owned_lease':state['resource_leases'][0]['state']}
print(json.dumps(asyncio.run(exercise())))
""")
        plumb_status, pending = json_request(alice, "POST", "/plumb/request-chat", agent_token,
                                              {"participants": ["bob"], "topic": "r638",
                                               "reason": "installed transition"})
        check(plumb_status == 202 and pending.get("request_id"),
              f"old Python plumb pending writer failed: {plumb_status} {pending}")
        plumb_request_id = pending["request_id"]
        status, denied = request(alice, "GET",
                                 f"http://127.0.0.2:{origin.server_port}/initial")
        check(status in (403, 428, 429) and not origin.seen,
              f"Python baseline did not deny unapproved origin: {status}")
        ca = root / "certs/mitmproxy-ca.pem"
        hmac = root / "data/hmac_secret"
        check(ca.is_file() and hmac.is_file(), "old Python did not create CA/HMAC state")
        ca_snapshot = ca_files(root)
        check(len(ca_snapshot) >= (2 if args.native else 4), "installed launcher did not create CA and key files")
        for path in (ca, hmac, root / "data/vault.key", root / "data/vault.yaml.enc"):
            private_file(path)
        old_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        initial_state = {"ca_sha256": sha(ca), "hmac_sha256": sha(hmac),
                         "hmac_fingerprint": key_fingerprint(hmac),
                         "vault_sha256": sha(root / "data/vault.yaml.enc"),
                         "policy_sha256": sha(root / "policy.toml")}
        stop(active, root, old_env)
        active = None
        print(json.dumps({"old_initial": stages[-1], "state": initial_state,
                          "denied_status": status, "coord": old_coord,
                          "plumb_request_id": plumb_request_id, "trusted_tls": old_tls}),
              flush=True)
        nats_identity = ensure_nats(args.old_cli, old_env)
        nats_started = True
        print(json.dumps({"nats": nats_identity}), flush=True)
        active = args.rust_cli
        stages.append(start(active, root, env, "rust", args.rust_revision))
        native = json.loads((root / "data/native.json").read_text())
        check(Path(native["circuit_state_file"]) == root / "data/circuit_breaker_state.json",
              "Rust generated a different circuit path")
        check(Path(native["flow_store_db_path"]) == root / "logs/flows.sqlite3",
              "Rust generated a different flow path")
        check(Path(native["gateway_services_dir"]) == root / "services",
              "Rust generated a different service directory")
        check(ca_files(root) == ca_snapshot and sha(hmac) == initial_state["hmac_sha256"]
              and key_fingerprint(hmac) == initial_state["hmac_fingerprint"],
              "Rust changed the Python CA files, HMAC key, or synthetic fingerprint")
        private_file(root / "data/vault.yaml.enc")
        private_file(hmac)
        native_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        bob = socket_for(root, "bob")
        coord_status, coord_page = json_request(
            bob, "GET", "/api/coord/rooms/r638-rollback/messages?since=0&limit=5", agent_token)
        check(coord_status == 200 and any(m.get("body") == "python-created-r638"
                                          for m in coord_page.get("messages", [])),
              f"native Coord did not read old retained message: {coord_status} {coord_page}")
        attention_status, attention_page = json_request(
            bob, "GET", "/api/coord/attention/wait?since=0&limit=5&timeout=0.1", agent_token)
        check(attention_status == 200 and attention_page.get("edges"),
              f"native Coord did not read old attention: {attention_status} {attention_page}")
        state_status, native_room_state = json_request(
            bob, "GET", "/api/coord/rooms/r638-rollback/state", agent_token)
        lease = native_room_state.get("resource_leases", [{}])[0] if state_status == 200 else {}
        check(state_status == 200 and lease.get("provider") == "fixture" and
              lease.get("resource") == "slot" and lease.get("state") == "unknown" and
              lease.get("provenance") == "provider_owned_lease" and
              sha(provider_snapshot) == provider_hash,
              "native did not preserve external provider ownership and retained advertisement")
        coord_send_status, coord_sent = json_request(
            alice, "POST", "/api/coord/rooms/r638-rollback/send", agent_token,
            {"body": "native-written-r638", "declared_content_type": "text/plain",
             "notify": ["bob"]})
        check(coord_send_status == 200 and coord_sent.get("envelope", {}).get("msg_id"),
              f"native Coord send failed: {coord_send_status} {coord_sent}")
        pending_status, pending_native = admin(root, "GET", "/admin/plumb/pending")
        check(pending_status == 200 and any(p.get("request_id") == plumb_request_id
                                            for p in pending_native.get("pending", [])),
              "native plumb did not read old pending request")
        approved_status, plumb_approved = admin(
            root, "POST", "/admin/plumb/approve",
            {"request_id": plumb_request_id, "ttl_seconds": 180})
        check(approved_status == 200 and plumb_approved.get("conversation_id"),
              f"native plumb approval failed: {approved_status} {plumb_approved}")
        conversation_id = plumb_approved["conversation_id"]
        plumb_send_status, plumb_sent = json_request(
            alice, "POST", f"/plumb/conversations/{conversation_id}/messages", agent_token,
            {"body": "native-written-plumb"})
        check(plumb_send_status == 200 and plumb_sent.get("id"),
              f"native plumb send failed: {plumb_send_status} {plumb_sent}")
        print(json.dumps({"native_coord": {"old_message_read": True,
                          "old_attention_read": True, "new_message_id":
                          coord_sent["envelope"]["msg_id"], "plumb_pending_read": True,
                          "plumb_conversation_id": conversation_id,
                          "plumb_message_id": plumb_sent["id"]}}), flush=True)
        status, services = json_request(alice, "GET", "/gateway/services", agent_token)
        check(status == 200 and any(item.get("name") == "contract"
                                    for item in services.get("available", [])),
              f"Rust did not load old service catalog: {status} {services}")
        check(any(item.get("name") == "gmail" and
                  item.get("description") == "r638 disposable user override"
                  for item in services["available"]),
              "Rust did not select old user catalog override")
        status, denied = request(alice, "GET",
                                 f"http://127.0.0.2:{origin.server_port}/initial-rust")
        check(status in (403, 428) and not origin.seen,
              f"Rust did not keep Python baseline denial: {status}")
        status, approved = admin(root, "POST", "/admin/policy/host/allow",
                                 {"host": "127.0.0.2", "port": origin.server_port,
                                  "agent": "alice", "rate": 600})
        check(status == 200, f"Rust host approval failed: {status} {approved}")
        check(tomllib.loads((root / "policy.toml").read_text())["hosts"]["*"]["egress"] == "deny",
              "Rust host approval changed wildcard egress")
        def approved_request():
            value, data = request(alice, "POST",
                                  f"http://127.0.0.2:{origin.server_port}/flow",
                                  body=b"owned-r638-request-needle",
                                  headers={"X-SafeYolo-Test-Context":
                                           "run=owned;agent=alice;test=R638"})
            return (value, data) if value == 200 else None
        allowed_status, allowed_bytes = eventually(approved_request,
                                                   "Rust did not activate scoped host approval")
        check(allowed_bytes == BODY and origin.seen[-1]["body"] == b"owned-r638-request-needle",
              "approved request bytes changed")
        before = len(origin.seen)
        bob_status, _ = request(bob, "GET", f"http://127.0.0.2:{origin.server_port}/bob")
        check(bob_status in (403, 428) and len(origin.seen) == before,
              "Alice's scoped approval leaked to Bob")
        wrong_port_status, _ = request(alice, "GET",
                                       f"http://127.0.0.2:{origin.server_port + 1}/wrong-port")
        check(wrong_port_status in (403, 428), "scoped approval leaked to another port")
        task_target = f"http://127.0.0.2:{origin.server_port}/task-lifetime"
        task_headers = {"X-SafeYolo-Test-Context": "run=owned;agent=alice;test=R638"}
        policy_before_task = sha(root / "policy.toml")
        task_status, _ = admin(root, "GET", f"/admin/policy/task/{TASK_ID}")
        check(task_status == 404, "native task registry was not initially empty")
        task_status, registered = admin(root, "PUT", f"/admin/policy/task/{TASK_ID}",
                                        {"policy": TASK_POLICY})
        check(task_status == 200 and registered.get("permission_count") == 1,
              f"native task registration failed: {task_status} {registered}")
        task_status, saved_task = admin(root, "GET", f"/admin/policy/task/{TASK_ID}")
        check(task_status == 200 and saved_task.get("policy") == TASK_POLICY,
              "native task registry did not retain the registered document")
        registered_status, registered_body = request(alice, "GET", task_target,
                                                     headers=task_headers)
        check(registered_status == 200 and registered_body == BODY,
              f"native task registration changed enforcement before activation: "
              f"{registered_status} {registered_body[:180]!r}")
        task_status, activated = admin(root, "POST", f"/admin/policy/task/{TASK_ID}/activate")
        check(task_status == 200 and activated.get("permission_count") == 1,
              f"native task activation failed: {task_status} {activated}")
        before = len(origin.seen)
        active_task_status, active_task_body = request(alice, "GET", task_target,
                                                       headers=task_headers)
        check(active_task_status == 403 and len(origin.seen) == before,
              f"native active task overlay did not deny before origin contact: "
              f"{active_task_status} {active_task_body[:180]!r}, "
              f"origin_delta={len(origin.seen) - before}")
        task_status, cleared = admin(root, "DELETE", f"/admin/policy/task/{TASK_ID}")
        check(task_status == 200 and cleared.get("status") == "cleared",
              f"native task clear failed: {task_status} {cleared}")
        task_status, _ = admin(root, "GET", f"/admin/policy/task/{TASK_ID}")
        check(task_status == 404, "native task clear retained its registration")
        cleared_task_status, cleared_task_body = request(alice, "GET", task_target,
                                                         headers=task_headers)
        check(cleared_task_status == 200 and cleared_task_body == BODY,
              "native task clear did not restore scoped host approval")
        check(sha(root / "policy.toml") == policy_before_task,
              "native task registration, activation, or clear changed durable policy")
        installed_python(args.old_cli, old_env, """
import json,sys
from pathlib import Path
from safeyolo.policy.toml_roundtrip import locked_policy_mutate
def update(doc): del doc['addons']['test_context']
locked_policy_mutate(Path(sys.argv[1]),update)
print(json.dumps({'test_context':'removed_after_flow'}))
""", str(root / "policy.toml"))
        time.sleep(0.8)
        print(json.dumps({"rust_read": stages[-1], "catalog_status": status,
                          "approval": approved, "allowed_status": allowed_status,
                          "allowed_body": summary_value(allowed_bytes),
                          "bob_status": bob_status, "wrong_port_status": wrong_port_status,
                          "origin_count": len(origin.seen),
                          "task_registered_status": registered_status,
                          "task_active_status": active_task_status,
                          "task_cleared_status": cleared_task_status}), flush=True)
        status, authorization = admin(root, "POST", "/admin/agents/alice/services",
                                      {"service": "contract", "capability": "writer",
                                       "credential": "contract-secret"})
        check(status == 200, f"native service authorization failed: {status} {authorization}")
        def current_gateway_token():
            value, catalog = json_request(alice, "GET", "/gateway/services", agent_token)
            if value != 200:
                return None
            return catalog.get("authorized", {}).get("contract", {}).get("token")
        gateway_token = eventually(current_gateway_token, "native service authorization not active")
        before = len(origin.seen)
        status, _ = request(alice, "POST",
                            f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
                            token=gateway_token, body=b'{"project":"alpha"}')
        check(status in (403, 428) and len(origin.seen) == before,
              f"risky route crossed without binding/grant: {status}")
        status, binding = admin(root, "POST", "/admin/gateway/contract-binding", {
            "agent": "alice", "service": "contract", "capability": "writer",
            "template": "contract.write.v1", "bindings": {"project": "alpha", "ticket": "T-1"},
            "grantable_operations": ["write"]})
        check(status == 200 and binding.get("binding_id"),
              f"native contract binding failed: {status} {binding}")
        binding_id = binding["binding_id"]
        status, grant = admin(root, "POST", "/admin/gateway/grant", {
            "agent": "alice", "service": "contract", "method": "POST",
            "path": "/v1/write", "lifetime": "remembered"})
        check(status == 200 and grant.get("grant_id"),
              f"native grant failed: {status} {grant}")
        grant_id = grant["grant_id"]
        gateway_token = eventually(current_gateway_token, "native token disappeared")
        last_gateway_response = []
        first_gateway_responses = []
        def granted_request():
            token = current_gateway_token()
            if token is None:
                return None
            value, body = request(alice, "POST",
                                  f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
                                  token=token, body=b'{"project":"alpha"}')
            last_gateway_response[:] = [value, body[:300].decode(errors="replace")]
            if len(first_gateway_responses) < 8:
                first_gateway_responses.append(last_gateway_response.copy())
            return (value, body) if value == 200 else None
        gateway_status, gateway_body = eventually(granted_request,
                                                  lambda: "native binding/grant did not pass live "
                                                  f"request; first={first_gateway_responses}; "
                                                  f"last={last_gateway_response}")
        check(gateway_body == BODY and origin.seen[-1]["body"] == b'{"project":"alpha"}',
              "granted service changed exact request/response bytes")
        check(origin.seen[-1]["authorization"] == "Bearer synthetic-r638-access-v1",
              "native OAuth refresh did not inject refreshed credential: "
              f"{origin.seen[-1]['authorization'][-24:]!r}; provider calls={len(oauth.seen)}")
        check(len(oauth.seen) == 1, "native OAuth did not call provider exactly once")
        native_vault_hash = sha(root / "data/vault.yaml.enc")
        check(native_vault_hash != initial_state["vault_sha256"],
              "native OAuth refresh did not durably change vault")
        private_file(root / "data/vault.yaml.enc")
        print(json.dumps({"native_write": {"authorization": authorization,
                          "binding_id": binding_id, "grant_id": grant_id,
                          "request_status": gateway_status,
                          "response": summary_value(gateway_body),
                          "oauth_provider_calls": len(oauth.seen),
                          "vault_changed": True,
                          "policy_changed": sha(root / "policy.toml") != initial_state["policy_sha256"]}}),
              flush=True)
        flow_db = root / "logs/flows.sqlite3"
        with sqlite3.connect(flow_db) as connection:
            row = connection.execute("SELECT id, request_id FROM flows WHERE path='/flow' AND agent_id='alice' "
                                     "AND status_code=200 ORDER BY id DESC LIMIT 1").fetchone()
        check(row is not None, "native did not retain the exact flow in old SQLite path")
        flow_id, flow_request_id = row
        status, native_flow = json_request(alice, "GET", f"/api/flows/{flow_id}", agent_token)
        check(status == 200 and native_flow is not None, "native flow consumer failed")
        status, native_tag = json_request(alice, "POST", f"/api/flows/{flow_id}/tag",
                                          agent_token, {"tag": "native", "value": "owned"})
        check(status == 200, f"native flow tag writer failed: {status} {native_tag}")
        audit = root / "logs/safeyolo.jsonl"
        check(any((event := json.loads(line)).get("event") == "traffic.response" and
                  event.get("request_id") == flow_request_id and event.get("agent") == "alice" and
                  event.get("details", {}).get("status") == 200
                  for line in audit.read_text().splitlines() if line.strip()),
              "native durable audit response is not correlated with owned flow")
        for _ in range(2):
            origin.next_status = 500
            failure_status, _ = request(
                alice, "GET", f"http://127.0.0.2:{origin.server_port}/circuit-failure")
            check(failure_status == 500, f"native failure did not reach origin: {failure_status}")
        circuit_status, native_circuit = json_request(alice, "GET", "/circuits", agent_token)
        check(circuit_status == 200 and
              native_circuit.get("domains", {}).get("127.0.0.2", {}).get("state") == "open",
              f"native circuit did not open: {circuit_status} {native_circuit}")
        before = len(origin.seen)
        blocked_status, _ = request(
            alice, "GET", f"http://127.0.0.2:{origin.server_port}/circuit-blocked")
        check(blocked_status == 503 and len(origin.seen) == before,
              "native open circuit reached origin")
        # Leave an active registration in the native process at replacement.
        policy_before_task = sha(root / "policy.toml")
        task_status, registered = admin(root, "PUT", f"/admin/policy/task/{TASK_ID}",
                                        {"policy": TASK_POLICY})
        check(task_status == 200 and registered.get("permission_count") == 1,
              f"native task re-registration failed: {task_status} {registered}")
        task_status, activated = admin(root, "POST", f"/admin/policy/task/{TASK_ID}/activate")
        check(task_status == 200 and activated.get("permission_count") == 1,
              f"native task reactivation failed: {task_status} {activated}")
        check(sha(root / "policy.toml") == policy_before_task,
              "native task reactivation changed durable policy")
        stop(active, root, env)
        check((root / "data/circuit_breaker_state.json").is_file(),
              "native open circuit was not persisted on close")
        active = args.old_cli
        stages.append(start(active, root, old_env, prior_backend, args.rust_revision))
        check(ca_files(root) == ca_snapshot and sha(hmac) == initial_state["hmac_sha256"]
              and key_fingerprint(hmac) == initial_state["hmac_fingerprint"],
              "Python rollback changed CA/HMAC identity")
        private_file(root / "data/vault.yaml.enc")
        private_file(hmac)
        old_circuit_status, old_circuit = json_request(alice, "GET", "/circuits", agent_token)
        check(old_circuit_status == 200 and
              old_circuit.get("domains", {}).get("127.0.0.2", {}).get("state") == "open",
              f"old Python did not load native open circuit: {old_circuit_status} {old_circuit}")
        before = len(origin.seen)
        old_blocked_status, _ = request(
            alice, "GET", f"http://127.0.0.2:{origin.server_port}/old-circuit-blocked")
        check(old_blocked_status == 503 and len(origin.seen) == before,
              "old Python open circuit reached origin")
        reset_status, reset = admin(root, "POST", "/admin/circuit-breaker/reset",
                                    {"host": "127.0.0.2"}, backend=prior_backend)
        check(reset_status == 200, f"old Python circuit reset failed: {reset_status} {reset}")
        old_recovered_status, old_recovered = request(
            alice, "GET", f"http://127.0.0.2:{origin.server_port}/old-after-reset")
        check(old_recovered_status == 200 and old_recovered == BODY,
              "old Python circuit reset did not restore origin use")
        task_status, _ = admin(root, "GET", f"/admin/policy/task/{TASK_ID}",
                               backend=prior_backend)
        check(task_status == 404, "old Python inherited the native task registration")
        old_task_status, old_task_body = request(alice, "GET", task_target)
        check(old_task_status == 200 and old_task_body == BODY,
              "old Python inherited the native active task overlay")
        policy_before_old_task = sha(root / "policy.toml")
        task_status, old_registered = admin(root, "PUT", f"/admin/policy/task/{TASK_ID}",
                                            {"policy": TASK_POLICY}, backend=prior_backend)
        check(task_status == 200 and old_registered.get("permission_count") == 1,
              f"old Python task registration failed: {task_status} {old_registered}")
        task_status, old_saved_task = admin(root, "GET", f"/admin/policy/task/{TASK_ID}",
                                            backend=prior_backend)
        check(task_status == 200 and old_saved_task.get("policy") == TASK_POLICY,
              "old Python did not retain its own task registration")
        task_status, _ = admin(root, "POST", f"/admin/policy/task/{TASK_ID}/activate",
                               backend=prior_backend)
        check(task_status == (200 if args.native else 404),
              "replacement task activation returned an unexpected result")
        old_task_status, old_task_body = request(alice, "GET", task_target)
        check(old_task_status == 200 and old_task_body == BODY,
              "old Python registration changed a request without task context")
        check(sha(root / "policy.toml") == policy_before_old_task,
              "old Python task registration changed durable policy")
        rollback_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        old_catalog_status, old_catalog = json_request(alice, "GET", "/gateway/services", agent_token)
        check(old_catalog_status == 200 and old_catalog.get("authorized", {}).get("contract"),
              f"old Python did not read native service authorization: {old_catalog_status}")
        check(any(item.get("name") == "gmail" and
                  item.get("description") == "r638 disposable user override"
                  for item in old_catalog["available"]),
              "old Python did not read user catalog override")
        old_gateway_token = old_catalog["authorized"]["contract"]["token"]
        old_gateway_status, old_gateway_bytes = request(
            alice, "POST", f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
            token=old_gateway_token, body=b'{"project":"alpha"}')
        check(old_gateway_status == 200 and old_gateway_bytes == BODY,
              f"old Python did not use native grant/binding: {old_gateway_status}")
        check(origin.seen[-1]["authorization"] == "Bearer synthetic-r638-access-v1",
              "old Python did not inject native-refreshed vault credential")
        old_coord_read = installed_python(args.old_cli, old_env, """
import asyncio,json
from safeyolo.coord import api
api.bootstrap()
async def exercise():
    page=await api.read_room('r638-rollback','agent','ag-r638-bob',since_sequence=0,limit=5)
    assert [m['body'] for m in page['messages']]==['python-created-r638','native-written-r638']
    attention=await api.wait_for_attention('ag-r638-bob',since_sequence=0,timeout_seconds=0.1,limit=5)
    assert attention['edges']
    state=await api.get_room_state('r638-rollback','agent','ag-r638-bob')
    assert state['resource_leases'][0]['state']=='held'
    sent=await api.send('r638-rollback','agent','ag-r638-bob','python-rollback-r638',
        declared_content_type='text/plain',sender_agent_name='bob',notify=['alice'])
    return {'messages_read':len(page['messages']),'attention_edges':len(attention['edges']),
            'new_message_id':sent['envelope']['msg_id'],
            'provider_owned_lease':state['resource_leases'][0]['state']}
print(json.dumps(asyncio.run(exercise())))
""")
        plumb_old_status, plumb_old = json_request(
            bob, "GET", f"/plumb/conversations/{conversation_id}/messages", agent_token)
        check(plumb_old_status == 200 and any(
            m.get("body") == "native-written-plumb" for m in plumb_old.get("messages", [])),
            f"old Python did not read native plumb message: {plumb_old_status} {plumb_old}")
        plumb_reply_status, plumb_reply = json_request(
            bob, "POST", f"/plumb/conversations/{conversation_id}/messages", agent_token,
            {"body": "python-rollback-plumb"})
        check(plumb_reply_status == 200 and plumb_reply.get("id"),
              f"old Python plumb write failed: {plumb_reply_status} {plumb_reply}")
        if args.native:
            native_flow(root, alice, agent_token, flow_id, "native")
            status, _ = json_request(alice, "POST", f"/api/flows/{flow_id}/tag", agent_token,
                                     {"tag": "replacement", "value": "rollback"})
            check(status == 200, "replacement could not write its durable flow tag")
            old_read = installed_python(args.rust_cli, env, """
import json,sys
from pathlib import Path
from safeyolo.core.vault import Vault
from safeyolo.policy.toml_roundtrip import load_agents,load_roundtrip,locked_policy_mutate,upsert_agent
root=Path(sys.argv[1]); binding_id=sys.argv[2]; grant_id=sys.argv[3]
vault=Vault(root/'data/vault.yaml.enc'); vault.unlock((root/'data/vault.key').read_text())
cred=vault.get('contract-secret'); assert cred and cred.value=='synthetic-r638-access-v1'
cred.expires_at='2020-01-01T00:00:00+00:00'; vault.store(cred)
assert vault.refresh_oauth2('contract-secret')
assert vault.get('contract-secret').value=='synthetic-r638-access-v2'
policy=root/'policy.toml'; alice=load_agents(load_roundtrip(policy))['alice']
assert any(g['grant_id']==grant_id for g in alice['grants'])
assert any(b['binding_id']==binding_id for b in alice['contract_bindings'])
def revoke(doc):
    alice=load_agents(doc)['alice']; assert alice['services']['contract']['capability']=='writer'
    del alice['services']['contract']
    if not alice['services']: alice.pop('services')
    alice['grants']=[g for g in alice['grants'] if g['grant_id']!=grant_id]
    alice['contract_bindings']=[b for b in alice['contract_bindings'] if b['binding_id']!=binding_id]
    if not alice['grants']: alice.pop('grants')
    if not alice['contract_bindings']: alice.pop('contract_bindings')
    upsert_agent(doc,'alice',alice)
locked_policy_mutate(policy,revoke,save_if_unchanged=False)
alice=load_agents(load_roundtrip(policy))['alice']
assert not alice.get('services') and not alice.get('grants') and not alice.get('contract_bindings')
print(json.dumps({'vault_refreshed':True,'native_grant_read':True,
              'native_binding_read':True,'service_revoked':True}))
""", str(root), binding_id, grant_id)
        else:
            old_read = installed_python(args.old_cli, old_env, """
import json,sys
from pathlib import Path
from safeyolo.core.vault import Vault
from safeyolo.storage.flow_store import FlowStore
from safeyolo.core.audit_stream import AuditLineParser
from safeyolo.mitm_addons.service_gateway import ServiceGateway
from safeyolo.policy.toml_roundtrip import load_agents,load_roundtrip,locked_policy_mutate,upsert_agent
root=Path(sys.argv[1]); flow_id=int(sys.argv[2]); binding_id=sys.argv[3]; grant_id=sys.argv[4]
store=FlowStore(str(root/'logs/flows.sqlite3')); store.init_db()
flow=store.get_flow(flow_id)
assert flow['agent_id']=='alice' and flow['status_code']==200
assert store.get_request_body(flow_id)['body']==b'owned-r638-request-needle'
assert store.get_response_body(flow_id)['body']==b'owned-r638-response-needle\\n'
assert any(t['tag']=='native' and t['value']=='owned' for t in store.get_flow_tags(flow_id))
store.tag_flow(flow_id,'python','rollback'); store.close()
events=[e for line in (root/'logs/safeyolo.jsonl').read_text().splitlines()
        if (e:=AuditLineParser().parse(line))]
assert any(e['event']=='traffic.response' and e.get('agent')=='alice'
           and e.get('request_id')==flow['request_id'] for e in events)
vault=Vault(root/'data/vault.yaml.enc'); vault.unlock((root/'data/vault.key').read_text())
cred=vault.get('contract-secret'); assert cred and cred.value=='synthetic-r638-access-v1'
cred.expires_at='2020-01-01T00:00:00+00:00'; vault.store(cred)
assert vault.refresh_oauth2('contract-secret')
assert vault.get('contract-secret').value=='synthetic-r638-access-v2'
policy=root/'policy.toml'; gateway=ServiceGateway(); gateway._get_policy_path=lambda:policy
gateway._load_grants_from_policy(); gateway._load_contract_bindings_from_policy()
assert gateway._check_grant('alice','contract','POST','/v1/write').grant_id==grant_id
assert gateway.get_contract_binding('alice','contract','writer').binding_id==binding_id
assert gateway.revoke_grant(grant_id) and gateway.revoke_contract_binding(binding_id)
def remove_service(doc):
    alice=load_agents(doc)['alice']; assert alice['services']['contract']['capability']=='writer'
    del alice['services']['contract']; alice.pop('services',None)
    upsert_agent(doc,'alice',alice)
locked_policy_mutate(policy,remove_service,save_if_unchanged=False)
alice=load_agents(load_roundtrip(policy))['alice']
assert not alice.get('services') and not alice.get('grants') and not alice.get('contract_bindings')
print(json.dumps({'flow_id':flow_id,'flow_agent':flow['agent_id'],
    'flow_request_bytes':len(b'owned-r638-request-needle'),
    'flow_response_bytes':len(b'owned-r638-response-needle\\n'),
    'audit_events':len(events),'native_tag_read':True,'python_tag_written':True,
    'native_grant_read':True,'native_binding_read':True,'service_revoked':True,
    'vault_refreshed':True}))
    """, str(root), str(flow_id), binding_id, grant_id)
        check(len(oauth.seen) == 2, "old Python OAuth writer did not call provider")
        check(sha(root / "data/vault.yaml.enc") != native_vault_hash,
              "old Python OAuth did not durably update native vault")
        private_file(root / "data/vault.yaml.enc")
        check(sha(provider_snapshot) == provider_hash,
              "Python rollback changed the provider-owned snapshot")
        catalog_override.unlink()
        run([str(args.old_cli), "policy", "host", "remove", "127.0.0.2",
             "--port", str(origin.server_port), "--agent", "alice"], env)
        host_policy = tomllib.loads((root / "policy.toml").read_text())
        check(f"127.0.0.2:{origin.server_port}" not in host_policy["agents"]["alice"].get("hosts", {}),
              "old Python writer did not revoke scoped host approval")
        print(json.dumps({"python_rollback": stages[-1], "gateway_status": old_gateway_status,
                          "task_reset_status": old_task_status,
                          "task_registered_without_activation": True,
                          "gateway_response": summary_value(old_gateway_bytes),
                          "old_consumer": old_read, "oauth_provider_calls": len(oauth.seen),
                          "coord": old_coord_read, "plumb_read_count": len(plumb_old["messages"]),
                          "plumb_reply_id": plumb_reply["id"],
                          "circuit_reset_status": old_recovered_status,
                          "host_approval_revoked": True}),
              flush=True)
        stop(active, root, old_env)
        active = None
        ensure_nats(args.old_cli, old_env)
        active = args.rust_cli
        stages.append(start(active, root, env, "rust", args.rust_revision))
        check(stages[-1]["pid"] != stages[1]["pid"], "return reused the first Rust process")
        task_status, _ = admin(root, "GET", f"/admin/policy/task/{TASK_ID}")
        check(task_status == 404, "fresh Rust inherited the old process task registration")
        task_status, _ = admin(root, "POST", f"/admin/policy/task/{TASK_ID}/activate")
        check(task_status == 404, "fresh Rust activated a task from a prior process")
        check(ca_files(root) == ca_snapshot and sha(hmac) == initial_state["hmac_sha256"]
              and key_fingerprint(hmac) == initial_state["hmac_fingerprint"],
              "return Rust changed CA/HMAC identity")
        for path in (ca, hmac, root / "data/vault.key", root / "data/vault.yaml.enc"):
            private_file(path)
        returned_tls = trusted_tls_request(alice, tls_origin.server_port, root)
        status, returned_circuit = json_request(alice, "GET", "/circuits", agent_token)
        check(status == 200 and returned_circuit.get("domains", {}).get("127.0.0.2", {})
              .get("state", "closed") != "open", "return Rust resurrected open circuit")
        before = len(origin.seen)
        host_revoked_status, _ = request(
            alice, "GET", f"http://127.0.0.2:{origin.server_port}/after-host-revocation")
        check(host_revoked_status in (403, 428) and len(origin.seen) == before,
              "return Rust resurrected Python-revoked scoped host approval")
        status, returned_catalog = json_request(alice, "GET", "/gateway/services", agent_token)
        check(status == 200 and not returned_catalog.get("authorized", {}).get("contract"),
              "return Rust resurrected Python-revoked service authorization")
        check(any(item.get("name") == "gmail" and
                  item.get("description") != "r638 disposable user override"
                  for item in returned_catalog["available"]),
              "return Rust retained removed user catalog override")
        before = len(origin.seen)
        revoked_status, _ = request(
            alice, "POST", f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
            token=gateway_token, body=b'{"project":"alpha"}')
        check(revoked_status in (403, 428) and len(origin.seen) == before,
              "return Rust crossed Python-revoked grant/binding")
        status, returned_flow = json_request(alice, "GET", f"/api/flows/{flow_id}", agent_token)
        check(status == 200 and any(t.get("tag") == ("replacement" if args.native else "python") and t.get("value") == "rollback"
                                    for t in returned_flow.get("tags", [])),
              f"return Rust did not read replacement flow tag: {status} {returned_flow}")
        if args.native:
            native_flow(root, alice, agent_token, flow_id, "replacement")
        status, returned_coord = json_request(
            alice, "GET", "/api/coord/rooms/r638-rollback/messages?since=0&limit=5", agent_token)
        check(status == 200 and [m.get("body") for m in returned_coord.get("messages", [])] == [
            "python-created-r638", "native-written-r638", "python-rollback-r638"],
              f"return Rust lost Coord history: {status} {returned_coord}")
        state_status, returned_room_state = json_request(
            bob, "GET", "/api/coord/rooms/r638-rollback/state", agent_token)
        lease = returned_room_state.get("resource_leases", [{}])[0] if state_status == 200 else {}
        check(state_status == 200 and lease.get("resource") == "slot" and
              lease.get("state") == "unknown" and sha(provider_snapshot) == provider_hash,
              "return Rust changed provider-owned lease or lost advertisement")
        status, returned_plumb = json_request(
            alice, "GET", f"/plumb/conversations/{conversation_id}/messages", agent_token)
        check(status == 200 and [m.get("body") for m in returned_plumb.get("messages", [])] == [
            "native-written-plumb", "python-rollback-plumb"],
              f"return Rust lost plumb history: {status} {returned_plumb}")
        approval_status, _ = admin(root, "POST", "/admin/policy/host/allow",
                                   {"host": "127.0.0.2", "port": origin.server_port,
                                    "agent": "alice", "rate": 600})
        check(approval_status == 200, "return Rust could not reapprove scoped host")
        def returned_circuit_request():
            value, body = request(alice, "GET",
                                  f"http://127.0.0.2:{origin.server_port}/after-circuit-reset")
            return (value, body) if value == 200 else None
        return_circuit_status, return_circuit_body = eventually(
            returned_circuit_request, "return Rust did not use Python reset circuit")
        check(return_circuit_body == BODY, "return Rust changed recovered response body")
        return_task_status, return_task_body = request(alice, "GET", task_target)
        check(return_task_status == 200 and return_task_body == BODY,
              "fresh Rust retained a previous process task overlay")
        status, _ = admin(root, "POST", "/admin/agents/alice/services",
                          {"service": "contract", "capability": "writer",
                           "credential": "contract-secret"})
        check(status == 200, "return Rust could not reauthorize service")
        status, rebound = admin(root, "POST", "/admin/gateway/contract-binding", {
            "agent": "alice", "service": "contract", "capability": "writer",
            "template": "contract.write.v1", "bindings": {"project": "alpha", "ticket": "T-1"},
            "grantable_operations": ["write"]})
        check(status == 200 and rebound.get("binding_id") != binding_id,
              "return Rust did not create a distinct binding")
        status, regrant = admin(root, "POST", "/admin/gateway/grant", {
            "agent": "alice", "service": "contract", "method": "POST",
            "path": "/v1/write", "lifetime": "remembered"})
        check(status == 200 and regrant.get("grant_id") != grant_id,
              "return Rust did not create a distinct grant")
        def returned_granted_request():
            token = current_gateway_token()
            if token is None:
                return None
            value, body = request(
                alice, "POST", f"http://127.0.0.2:{origin.server_port}/v1/write?ticket=T-1",
                token=token, body=b'{"project":"alpha"}')
            return (value, body) if value == 200 else None
        final_status, final_bytes = eventually(
            returned_granted_request, "return Rust did not activate deliberate regrant")
        check(final_bytes == BODY and origin.seen[-1]["authorization"] ==
              "Bearer synthetic-r638-access-v2", "return Rust did not use Python-refreshed vault")
        check(len(oauth.seen) == 2, "return Rust unexpectedly refreshed unexpired OAuth token")
        close_status, _ = admin(root, "POST", "/admin/plumb/close",
                                {"conversation_id": conversation_id})
        check(close_status == 200, "return Rust could not close retained collaboration")
        closed_status, _ = json_request(
            alice, "GET", f"/plumb/conversations/{conversation_id}/messages", agent_token)
        check(closed_status == 403, "closed collaboration remained usable")
        print(json.dumps({"rust_return": stages[-1], "revoked_status": revoked_status,
                          "host_revoked_status": host_revoked_status,
                          "regranted_status": final_status, "response": summary_value(final_bytes),
                          "python_flow_tag_read": True, "coord_messages": len(returned_coord["messages"]),
                          "plumb_messages": len(returned_plumb["messages"]),
                          "plumb_closed_status": closed_status,
                          "circuit_reset_status": return_circuit_status,
                          "task_reset_status": return_task_status,
                          "oauth_provider_calls": len(oauth.seen),
                          "ca_hmac_unchanged": True,
                          "provider_owned_lease": lease["state"],
                          "trusted_tls_statuses": [old_tls["status"], native_tls["status"],
                                                   rollback_tls["status"], returned_tls["status"]]}),
              flush=True)
        stop(active, root, env)
        active = None
        installed_python(args.old_cli, old_env, """
import json
from safeyolo.coord import nats_runtime
nats_runtime.stop_server()
print(json.dumps({'nats':'stopped'}))
""")
        nats_started = False
        if args.native:
            check(len({stage["runtime"]["receipt"]["start_token"] for stage in stages}) == 4,
                  "native replacement reused a prior process identity")
        else:
            print(json.dumps({"result": "linux_installed_transition_passed",
                              "stages": [stage["backend"] for stage in stages],
                              "state": str(root), "task_policy": "process-local reset observed",
                              "macos": "blocked by #637 host prerequisite"}), flush=True)
    finally:
        cleanup_errors = []
        if active is not None:
            try:
                stop(active, root, old_env if active == args.old_cli else env)
            except Exception as exc:
                print(f"cleanup failed: {type(exc).__name__}: {exc}", flush=True)
                cleanup_errors.append(str(exc))
        if nats_started:
            try:
                installed_python(args.old_cli, old_env, """
import json
from safeyolo.coord import nats_runtime
nats_runtime.stop_server()
print(json.dumps({'nats':'stopped'}))
""")
            except Exception as exc:
                print(f"NATS cleanup failed: {type(exc).__name__}: {exc}", flush=True)
                cleanup_errors.append(str(exc))
        for server, thread in zip((origin, oauth, tls_origin), threads, strict=True):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            if thread.is_alive():
                cleanup_errors.append("owned origin is still live")
        if args.native:
            # Marker removal cannot substitute for observing a process exit.
            for stage in stages:
                if (_pid_alive(stage["pid"]) and _process_start_token(stage["pid"]) ==
                        stage["runtime"]["receipt"]["start_token"]):
                    cleanup_errors.append(f"owned native process {stage['pid']} is still live")
            if any((root / "data" / marker).exists() for marker in (
                    "proxy-rust.json", "proxy-readiness.json", "coord/nats/nats.pid.json")):
                cleanup_errors.append("owned runtime marker remains")
            if cleanup_errors:
                raise PreparationError("owned cleanup failed: " + "; ".join(cleanup_errors))
    if args.native:
        report = {
            "result": "installed_native_continuity_passed", "source_revision": args.rust_revision,
            "state": str(root), "runtimes": stages, "agents_started": 0,
            "flow": {"id": flow_id, "request_body_bytes": len(b"owned-r638-request-needle"),
                     "response_body_bytes": len(BODY), "audit_correlated": True,
                     "replacement_tag_read": True},
            "circuit": {"replacement_blocked_status": old_blocked_status,
                        "reset_status": old_recovered_status, "fresh_return_status": return_circuit_status},
            "revocation": {"host_status": host_revoked_status, "service_status": revoked_status,
                           "regranted_status": final_status, "catalog_override_removed": True},
            "coord": {"messages": len(returned_coord["messages"]),
                      "retained_attention_edges": old_coord_read["attention_edges"],
                      "provider_owned_lease": lease["state"], "provider_snapshot_unchanged": True},
            "plumb": {"pending_retained": True, "messages": len(returned_plumb["messages"]),
                      "closed_status": closed_status},
            "task_policy": "process-local registration and activation reset",
            "oauth": {"provider_calls": len(oauth.seen), "stored_credential_reused": True},
            "tls_statuses": [old_tls["status"], native_tls["status"], rollback_tls["status"], returned_tls["status"]],
            "private_file_mode": "0600", "ca_hmac_unchanged": True, "cleanup": "stopped",
            "limitations": ["Host composition only; no guest or hardware isolation observed."],
        }
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (PreparationError, SmokeError, OSError, subprocess.SubprocessError) as exc:
        print(f"Preparation or cleanup failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
