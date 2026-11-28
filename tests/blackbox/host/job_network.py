"""Exercise scoped jobs, revocation and teardown through an owned proxy.

Requires host Python 3.10+, tomlkit, OpenSSL, candidate CLI/proxy binaries and
an installed shared Trixie guest. Supply a fresh --root with traversable parents
and a disk-backed --scratch directory. --admin-port and --upstream-port must be
free ports authorized for this run. On macOS use the approved physical VZ wrapper
and a short, owned TMPDIR. This creates a separate instance and retains its saved
grant, sanitized upstream observations and job results for inspection.
Two ordinary runs check stable saved authority. Three further runs check live
revocation, expiry and caller cancellation, including retained connections.
"""

import argparse
import base64
import hashlib
import http.client
import json
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomlkit

if __package__:
    from .job_sandbox import interrupt_request, job_directories, observe_backend
else:
    from job_sandbox import interrupt_request, job_directories, observe_backend

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from execution_receipt import ProcedureReceipt


def stage_runtime(cli: Path, proxy: Path, base: Path, root: Path):
    """Link prepared platform inputs into an initialized disposable instance."""
    root.chmod(0o755)
    selected = base / "current"
    host = selected / "host" if (selected / "share").is_dir() else base
    share = selected / "share" if (selected / "share").is_dir() else base / "share"
    for name in ("libexec", "lib", "assets", "package-info", "SHA256SUMS"):
        source = host / name
        if source.exists():
            (root / name).symlink_to(source.resolve())
    (root / "share").symlink_to(share.resolve(strict=True))
    if (base / "host").exists():
        (root / "host").symlink_to((base / "host").resolve())
    (root / "bin").mkdir()
    for source in (host / "bin").iterdir():
        if source.name not in {"safeyolo", "safeyolo-proxy"}:
            (root / "bin" / source.name).symlink_to(source.resolve())
    (root / "bin/safeyolo").symlink_to(cli)
    (root / "bin/safeyolo-proxy").symlink_to(proxy)
    # Mapped gVisor processes must traverse the installation's runtime parent.
    # Secret files written by init and the vault retain their private modes.
    (root / "data").chmod(0o755)


def prepare(cli: Path, proxy: Path, base: Path, root: Path, port: int, upstream: int):
    """Reuse installed runtime inputs without changing the original instance."""
    root.mkdir(mode=0o755)
    subprocess.run([str(cli), "--dangerously-allow-root", "--instance-dir", str(root), "--json", "init"], check=True)
    stage_runtime(cli, proxy, base, root)
    config = {
        "admin_port": port,
        "listeners": [],
        "flow_store_enabled": False,
        "tls_ca_file": "certs/mitmproxy-ca.pem",
        "upstream_ca_file": "certs/mitmproxy-ca-cert.pem",
    }
    original = tomlkit.parse((base / "config.toml").read_text())
    if "linux" in original:
        config["linux"] = original["linux"]
    (root / "config.toml").write_text(tomlkit.dumps(config))
    (root / "services/simple.yaml").write_text(
        "schema_version: 1\nname: simple\ndefault_host: 127.0.0.1\n"
        "auth: {type: bearer}\ncapabilities:\n  reader:\n    routes:\n"
        "      - methods: [GET]\n        path: /value\n"
    )
    (root / "policy.toml").write_text(f'''
[hosts."127.0.0.1"]
service = "simple"
[hosts."127.0.0.1:{upstream}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents."gate:proof".services.simple]
capability = "reader"
token = "job-secret"
[controls.credentials]
enabled = false
[controls.patterns]
enabled = false
[controls.test_context]
action = "warn"
''')
    subprocess.run(
        [str(cli), "--dangerously-allow-root", "--instance-dir", str(root), "--json", "credentials", "add", "job-secret", "--stdin", "--storage", "local"],
        input=b"synthetic-job-provider-secret\n", check=True,
    )
    create_upstream_certificate(root)


def create_upstream_certificate(root: Path):
    """Sign an owned loopback origin with the instance's disposable CA."""
    # Use a portable OpenSSL config rather than version-specific -addext flags.
    request = root / "certs/upstream.cnf"
    request.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
        "[dn]\nCN=127.0.0.1\n[extensions]\nsubjectAltName=IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    )
    subprocess.run(
        ["openssl", "req", "-sha256", "-new", "-newkey", "rsa:2048", "-nodes",
         "-config", str(request), "-keyout", str(root / "certs/upstream.key"),
         "-out", str(root / "certs/upstream.csr")],
        check=True,
    )
    subprocess.run(
        ["openssl", "x509", "-sha256", "-req", "-in", str(root / "certs/upstream.csr"), "-days", "1",
         "-CA", str(root / "certs/mitmproxy-ca.pem"), "-CAkey", str(root / "certs/mitmproxy-ca.pem"),
         "-CAcreateserial", "-extfile", str(request), "-extensions", "extensions",
         "-out", str(root / "certs/upstream.pem")],
        check=True,
    )


def program(port: int) -> str:
    """Use only the shared guest's Bash, curl and sha256sum; never print tokens."""
    return r'''
trap 'printf "job assertion failed at line %s\n" "$LINENO" >&2' ERR
test ! -e /app/agent_token
test ! -e /safeyolo/agent_token
test "$SSL_CERT_FILE" = /safeyolo/network/mitmproxy-ca-cert.pem
test -s "$SSL_CERT_FILE"
pattern='^\{[[:space:]]*"simple"[[:space:]]*:[[:space:]]*"(sgw_[A-Za-z0-9_-]+)"[[:space:]]*\}$'
[[ ${SAFEYOLO_GATEWAY_TOKENS:?} =~ $pattern ]]
token=${BASH_REMATCH[1]}
request() {
    printf 'Authorization: Bearer %s\n' "$token" |
        curl --silent --show-error --max-time 12 --proxy "$HTTPS_PROXY" \
        --cacert "$SSL_CERT_FILE" --header @- --output /work/response \
        --write-out '%{http_code}' "$1"
}
test "$(request https://127.0.0.1:PORT/value)" = 200
test "$(cat /work/response)" = ok
test "$(request https://127.0.0.1:PORT/write)" = 403
test "$(request http://_safeyolo.proxy.internal/health)" = 503
test "$(request http://job-denied.invalid/value)" = 403
printf '%s' "$token" | sha256sum | cut -d ' ' -f 1
printf 'HTTPS gateway, route/Agent API/egress refusal\n'
'''.replace("PORT", str(port))


def job(cli: Path, root: Path, scratch: Path, port: int, index: int):
    before = job_directories(root)
    spec = scratch / f"job-{index}.spec.json"
    spec.write_text(json.dumps({
        "gate_id": "proof", "argv": ["/bin/bash", "-euo", "pipefail", "-c", program(port)],
        "network": True, "timeout_seconds": 70, "memory_mb": 512,
        "max_input_bytes": 0, "max_input_entries": 1, "retain_bytes": 4096,
    }))
    # Write streams before waiting or asserting, including on caller timeout.
    output_path = scratch / f"job-{index}.stdout"
    try:
        completed, _records, observed = interrupt_request(
            [str(cli), "--dangerously-allow-root", "--instance-dir", str(root), "--json", "job", "run", str(spec)], root, None, umask=0o022)
    except subprocess.TimeoutExpired as error:
        output_path.write_bytes(error.stdout or b"")
        (scratch / f"job-{index}.stderr").write_bytes(error.stderr or b"")
        raise
    output_path.write_bytes(completed.stdout)
    (scratch / f"job-{index}.stderr").write_bytes(completed.stderr)
    (scratch / f"job-{index}.exit").write_text(str(completed.returncode))
    (scratch / f"job-{index}.backend.json").write_text(json.dumps(observed))
    assert observed and all("error" not in item for item in observed), "job did not retain a verified live backend"
    result = json.loads(output_path.read_bytes())
    assert completed.returncode == 0, result
    assert result["outcome"] == {"kind": "exit", "code": 0}, result
    assert result["observation_error"] is None, result
    assert result["gate_principal"] == result["authorization_principal"] == "gate:proof", result
    output = base64.b64decode(result["stdout"]["retained_base64"], validate=True)
    assert result["stdout"]["bytes"] == len(output), result
    assert result["stdout"]["sha256"] == hashlib.sha256(output).hexdigest(), result
    fingerprint, message = output.decode().splitlines()
    assert len(fingerprint) == 64 and all(c in "0123456789abcdef" for c in fingerprint), output
    assert message == "HTTPS gateway, route/Agent API/egress refusal", output
    assert job_directories(root) == before, "job runtime or delegated socket remains"
    return {**result, "observed_backends": observed}, fingerprint


def wait_ready(child: subprocess.Popen, root: Path, port: int):
    marker = root / "data/ready.json"
    deadline = time.monotonic() + 60
    while child.poll() is None:
        if marker.exists():
            ready = json.loads(marker.read_text())
            assert ready["pid"] == child.pid and ready["admin_port"] == port, ready
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("owned proxy did not publish readiness")
        time.sleep(0.025)
    raise RuntimeError(f"owned proxy exited before readiness: {child.returncode}")


class DelegatedHTTPSConnection(http.client.HTTPSConnection):
    """Reconnect only through the selected job socket, including after EOF."""

    def __init__(self, path, port, certificate):
        super().__init__("127.0.0.1", port, timeout=5,
                         context=ssl.create_default_context(cafile=str(certificate)))
        self.path = path
        self.set_tunnel("127.0.0.1", port)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(str(self.path))
            self._tunnel()
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        except (OSError, http.client.HTTPException):
            self.close()
            raise


def delegated_connection(path, port, certificate):
    """Keep a real delegated CONNECT open across job teardown."""
    connection = DelegatedHTTPSConnection(path, port, certificate)
    connection.connect()
    return connection


def scoped_request(connection, token):
    connection.request("GET", "/value", headers={"Authorization": "Bearer " + token})
    response = connection.getresponse()
    body = response.read()
    return response.status, body


def ended_delegation(path, connection, token, observations, expected):
    """Old connections and new dials must both fail without an origin effect."""
    assert not path.exists(), "terminated job retained its delegated socket"
    try:
        scoped_request(connection, token)
    except (OSError, http.client.HTTPException):
        pass  # A closed transport is the required result after teardown.
    else:
        raise AssertionError("terminated job retained an active delegated connection")
    with socket.socket(socket.AF_UNIX) as fresh:
        fresh.settimeout(3)
        try:
            fresh.connect(str(path))
        except OSError:
            pass  # The delegated endpoint must be unavailable after teardown.
        else:
            raise AssertionError("terminated job accepted a new delegated connection")
    assert len(observations) == expected, "old authority produced an origin effect"


def lifecycle_job(args, mode, observations):
    """Exercise live revocation, expiry or cancellation on one owned job."""
    before = job_directories(args.root)
    count = len(observations)
    spec = args.scratch / f"{mode}.spec.json"
    spec.write_text(json.dumps({"gate_id": "proof", "argv": ["/bin/bash", "-euo", "pipefail", "-c",
                                                           program(args.upstream_port) + "\nexec sleep 300"],
                                "network": True, "timeout_seconds": 25 if mode == "expiry" else 90,
                                "memory_mb": 512, "max_input_bytes": 0, "max_input_entries": 1, "retain_bytes": 4096}))
    command = [str(args.cli), "--dangerously-allow-root", "--instance-dir", str(args.root), "--json", "job", "run", str(spec)]
    connection = None
    with (args.scratch / f"{mode}.stdout").open("wb") as stdout, (args.scratch / f"{mode}.stderr").open("wb") as stderr:
        with subprocess.Popen(command, stdout=stdout, stderr=stderr, umask=0o022) as child:
            try:
                deadline = time.monotonic() + 180
                paths = []
                while child.poll() is None:
                    paths = [path for directory in job_directories(args.root) - before
                             for path in directory.glob("agents/job-*/proxy/proxy.sock") if path.is_socket()]
                    if len(paths) == 1 and len(observations) == count + 1:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("job did not reach the owned origin and delegate")
                    time.sleep(0.025)
                assert child.poll() is None and len(paths) == 1, "job exited before the live authority probe"
                backend = observe_backend(paths[0].parents[1] / "runtime.json")
                # Only this fixture's scoped token enters memory. Never retain
                # the services response or put the token in a command argument.
                authorized = json.loads(subprocess.check_output(
                    [str(args.cli), "--dangerously-allow-root", "--instance-dir", str(args.root), "--json", "services", "authorized", "gate:proof"], timeout=10))
                token = authorized["services"]["simple"]["token"]
                connection = delegated_connection(paths[0], args.upstream_port, args.root / "certs/mitmproxy-ca-cert.pem")
                assert scoped_request(connection, token) == (200, b"ok")
                assert len(observations) == count + 2
                if mode == "revocation":
                    subprocess.run([str(args.cli), "--dangerously-allow-root", "--instance-dir", str(args.root), "services", "revoke", "gate:proof", "simple"],
                                   check=True, capture_output=True, timeout=10)
                    try:
                        status, _ = scoped_request(connection, token)
                    except (OSError, http.client.HTTPException):
                        pass  # Policy replacement can close the entire delegated transport.
                    else:
                        assert status == 403
                    assert len(observations) == count + 2, "revoked authority reached the origin"
                if mode != "expiry":
                    child.send_signal(signal.SIGTERM)
                child.wait(timeout=180)
                result = json.loads((args.scratch / f"{mode}.stdout").read_text())
                expected = {"kind": "timeout"} if mode == "expiry" else {"kind": "interrupted", "signal": signal.SIGTERM}
                assert result["outcome"] == expected and result["observation_error"] is None, result
                assert child.returncode == (124 if mode == "expiry" else 1)
                assert job_directories(args.root) == before
                ended_delegation(paths[0], connection, token, observations, count + 2)
                return {**result, "observed_backend": backend}
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=180)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                        raise
                if connection is not None:
                    connection.close()
                if mode == "revocation":
                    subprocess.run([str(args.cli), "--dangerously-allow-root", "--instance-dir", str(args.root), "services", "authorize", "gate:proof", "simple",
                                    "--capability", "reader", "--credential", "job-secret"],
                                   check=True, capture_output=True, timeout=10)


def assert_restored_gate_grant(root: Path) -> None:
    """Check the fixture's saved authority after live revoke/authorize."""
    settings = tomlkit.parse((root / "policy.toml").read_text())
    grant = dict(settings["agents"]["gate:proof"]["services"]["simple"])
    # Native authorization and authority compilation both default to agent.
    grant.setdefault("account", "agent")
    assert grant == {"capability": "reader", "token": "job-secret", "account": "agent"}, "saved gate authority changed"


def run(args, receipt=None):
    observations = []
    original = {args.base_root / name: (args.base_root / name).read_bytes()
                for name in ("config.toml", "policy.toml") if (args.base_root / name).is_file()}

    class Upstream(BaseHTTPRequestHandler):
        # Keep the origin side live beyond the owned job deadline, so an idle
        # server close cannot substitute for delegated-connection teardown.
        timeout = 180
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            credential = self.headers.get("Authorization", "")
            accepted = self.path == "/value" and credential == "Bearer synthetic-job-provider-secret"
            observations.append({"path": self.path, "credential_replaced": accepted, "gateway_token_leaked": "sgw_" in credential})
            (args.scratch / "upstream.json").write_text(json.dumps(observations))
            self.send_response(200 if accepted else 400)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *unused):
            # HTTP request logs are replaced by the sanitized observations above.
            pass

    prepare(args.cli, args.proxy, args.base_root, args.root, args.admin_port, args.upstream_port)
    receipt = receipt or ProcedureReceipt("job-network", args.scratch / "result.json")
    receipt.checkpoint("identity", cli=subprocess.check_output([str(args.cli), "--version"], text=True).strip(),
                       proxy=subprocess.check_output([str(args.proxy), "--version"], text=True).strip())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.root / "certs/upstream.pem", args.root / "certs/upstream.key")
    with ThreadingHTTPServer(("127.0.0.1", args.upstream_port), Upstream) as sink:
        sink.socket = context.wrap_socket(sink.socket, server_side=True)
        thread = threading.Thread(target=sink.serve_forever)
        thread.start()
        try:
            with (args.scratch / "proxy.log").open("wb") as log:
                with subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml"), "--dangerously-allow-root"], stdout=log, stderr=log) as child:
                    try:
                        wait_ready(child, args.root, args.admin_port)
                        first, fingerprint = job(args.cli, args.root, args.scratch, args.upstream_port, 1)
                        second, again = job(args.cli, args.root, args.scratch, args.upstream_port, 2)
                        assert first["run_id"] != second["run_id"], (first, second)
                        assert fingerprint == again, "saved gate capability changed between transient runs"
                        assert len(observations) == 2 and all(row["credential_replaced"] and not row["gateway_token_leaked"] for row in observations), observations
                        receipt.checkpoint("scoped-requests", jobs=[first, second], origin=list(observations))
                        revoked = lifecycle_job(args, "revocation", observations)
                        receipt.checkpoint("revocation", job=revoked)
                        expired = lifecycle_job(args, "expiry", observations)
                        receipt.checkpoint("expiry", job=expired)
                        cancelled = lifecycle_job(args, "cancellation", observations)
                        receipt.checkpoint("cancellation", job=cancelled)
                        assert len(observations) == 8 and all(row["credential_replaced"] and not row["gateway_token_leaked"] for row in observations)
                    finally:
                        if child.poll() is None:
                            child.terminate()
                        try:
                            child.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                            raise
                    assert child.returncode == 0, f"proxy shutdown returned {child.returncode}"
        finally:
            sink.shutdown()
            thread.join(timeout=15)
            assert not thread.is_alive(), "upstream thread did not stop"
    # Live service revoke/authorize restores the grant semantically; serialization
    # and reload metadata can change. The donor instance stays byte-identical.
    for path, content in original.items():
        assert path.read_bytes() == content, path
    assert_restored_gate_grant(args.root)
    assert len(observations) == 8 and all(row["credential_replaced"] and not row["gateway_token_leaked"] for row in observations)
    assert not (args.root / "data/ready.json").exists(), "proxy readiness remains after shutdown"
    rows = [json.loads(line) for line in (args.root / "logs/audit.jsonl").read_text().splitlines()]
    for result in (first, second, revoked, expired, cancelled):
        assert any(row["details"].get("attribution", {}).get("trusted_transport_identity") == result["run_id"]
                   and row["details"]["attribution"].get("attribution_provenance", {}).get("authorization_principal") == "gate:proof"
                   for row in rows), f"missing trusted audit attribution for {result['run_id']}"
    receipt.checkpoint("audit")
    # A live foreign listener after teardown must not be mistaken for cleanup.
    for port in (args.admin_port, args.upstream_port):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
    receipt.checkpoint("cleanup", origin=observations)
    receipt.checkpoint("finished")
    print("PASS scoped runs, credential replacement, revocation, expiry, cancellation, audit and delegated teardown")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "proxy", "base-root", "root", "scratch"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("admin-port", "upstream-port"):
        parser.add_argument(f"--{name}", type=int, required=True)
    args = parser.parse_args()
    for name in ("cli", "proxy", "base_root", "scratch"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.root = args.root.absolute()
    if args.admin_port == args.upstream_port or not all(1 <= port <= 65535 for port in (args.admin_port, args.upstream_port)):
        parser.error("supply two distinct, nonzero authorized ports")
    if args.root.exists() or any(args.scratch.iterdir()):
        parser.error("--root must be fresh and --scratch must be empty")
    args.scratch.chmod(0o700)
    run(args)


if __name__ == "__main__":
    main()
