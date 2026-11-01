"""Run two credentialed jobs through an owned native proxy on a prepared host.

Requires host Python 3.10+, tomlkit, OpenSSL, candidate CLI/proxy binaries and
an installed shared Trixie guest. Supply a fresh --root with traversable parents
and a disk-backed --scratch directory. --admin-port and --upstream-port must be
free ports authorized for this run. On macOS use the approved physical VZ wrapper
and a short, owned TMPDIR. This creates a separate instance and retains its saved
grant, sanitized upstream observations and job results for inspection.
"""

import argparse
import base64
import hashlib
import json
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import tomlkit
from job_sandbox import job_directories


def prepare(cli: Path, proxy: Path, base: Path, root: Path, port: int, upstream: int):
    """Reuse installed runtime inputs without changing the original instance."""
    root.mkdir(mode=0o755)
    subprocess.run([str(cli), "--root", str(root), "init"], check=True)
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
        [str(cli), "--root", str(root), "credentials", "add", "job-secret", "--stdin", "--storage", "local"],
        input=b"synthetic-job-provider-secret\n", check=True,
    )
    # Use a portable OpenSSL config rather than version-specific -addext flags.
    request = root / "certs/upstream.cnf"
    request.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
        "[dn]\nCN=127.0.0.1\n[extensions]\nsubjectAltName=IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
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
    with output_path.open("wb") as stdout, (scratch / f"job-{index}.stderr").open("wb") as stderr:
        with subprocess.Popen(
            [str(cli), "--root", str(root), "job", "run", str(spec)],
            stdout=stdout, stderr=stderr, umask=0o022,
        ) as child:
            try:
                child.wait(timeout=180)
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=180)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                        raise
                (scratch / f"job-{index}.exit").write_text(str(child.returncode))
    result = json.loads(output_path.read_bytes())
    assert child.returncode == 0, result
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
    return result, fingerprint


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


def run(args):
    observations = []
    original = {args.base_root / name: (args.base_root / name).read_bytes()
                for name in ("config.toml", "policy.toml") if (args.base_root / name).is_file()}

    class Upstream(BaseHTTPRequestHandler):
        timeout = 10

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
    protected = {args.root / name: (args.root / name).read_bytes() for name in ("config.toml", "policy.toml")}
    protected.update(original)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.root / "certs/upstream.pem", args.root / "certs/upstream.key")
    with HTTPServer(("127.0.0.1", args.upstream_port), Upstream) as sink:
        sink.socket = context.wrap_socket(sink.socket, server_side=True)
        thread = threading.Thread(target=sink.serve_forever)
        thread.start()
        try:
            with (args.scratch / "proxy.log").open("wb") as log:
                with subprocess.Popen([str(args.proxy), "--config", str(args.root / "config.toml")], stdout=log, stderr=log) as child:
                    try:
                        wait_ready(child, args.root, args.admin_port)
                        first, fingerprint = job(args.cli, args.root, args.scratch, args.upstream_port, 1)
                        second, again = job(args.cli, args.root, args.scratch, args.upstream_port, 2)
                        assert first["run_id"] != second["run_id"], (first, second)
                        assert fingerprint == again, "saved gate capability changed between transient runs"
                        assert len(observations) == 2 and all(row["credential_replaced"] and not row["gateway_token_leaked"] for row in observations), observations
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
    for path, content in protected.items():
        assert path.read_bytes() == content, path
    assert not (args.root / "data/ready.json").exists(), "proxy readiness remains after shutdown"
    rows = [json.loads(line) for line in (args.root / "logs/audit.jsonl").read_text().splitlines()]
    for result in (first, second):
        assert any(row["details"].get("attribution", {}).get("trusted_transport_identity") == result["run_id"]
                   and row["details"]["attribution"].get("attribution_provenance", {}).get("authorization_principal") == "gate:proof"
                   for row in rows), f"missing trusted audit attribution for {result['run_id']}"
    # A live foreign listener after teardown must not be mistaken for cleanup.
    for port in (args.admin_port, args.upstream_port):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
    print("PASS two transient runs, stable saved grant, HTTPS credential replacement, refusals, audit and owned teardown")


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
