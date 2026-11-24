"""Exercise release retries and credentials through urllib's real redirects.

HTTPS transport is substituted and retry delays are recorded. urllib builds
and follows requests, copies headers, processes redirects and raises HTTP errors.
"""
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import traceback
import urllib.request
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPHandler
from urllib.response import addinfourl

import pytest
import yaml

from guest import resolve_inputs as inputs

API = "https://api.github.com/repos/cli/cli/releases/latest"
TOKEN = "controlled-release-token"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def upstream(monkeypatch):
    routes, requests = {}, []
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_ACTIONS", "GH_VERSION", "MISE_VERSION", "GH_SHA256_AMD64", "GH_SHA256_ARM64"):
        monkeypatch.delenv(name, raising=False)

    def receive(self, request):
        requests.append((request.full_url, {key.lower(): value for key, value in request.header_items()}))
        route = routes[request.full_url]
        reply = route.pop(0) if isinstance(route, list) else route
        if isinstance(reply, Exception):
            raise reply
        status, headers, body = reply
        message = Message()
        for key, value in headers.items():
            message[key] = value
        response = addinfourl(body if isinstance(body, io.BytesIO) else io.BytesIO(body),
                             message, request.full_url, status)
        response.msg = HTTPStatus(status).phrase
        return response

    def insecure(self, request):
        pytest.fail(f"followed an insecure redirect to {request.full_url}")

    monkeypatch.setattr(inputs.DownloadHTTPSHandler, "https_open", receive)
    monkeypatch.setattr(HTTPHandler, "http_open", insecure)
    return routes, requests


@pytest.fixture
def retry_sleeps(monkeypatch):
    delays = []
    monkeypatch.setattr(inputs.time, "sleep", delays.append)
    return delays


@pytest.fixture
def gh_release(upstream):
    routes, requests = upstream
    version = "9.8.7"
    base = f"https://github.com/cli/cli/releases/download/v{version}/"
    assets, checksums = [], []
    for arch in inputs.ARCHITECTURES:
        name = inputs.asset_name("gh", version, arch)
        digest = inputs.sha256(arch.encode())
        assets.append({"name": name, "browser_download_url": base + name, "digest": "sha256:" + digest})
        checksums.append(f"{digest}  {name}")
        routes[base + name] = (200, {}, arch.encode())
    name = f"gh_{version}_checksums.txt"
    assets.append({"name": name, "browser_download_url": base + name})
    routes[base + name] = (200, {}, "\n".join(checksums).encode())
    data = {"tag_name": "v" + version, "draft": False, "prerelease": False,
            "html_url": f"https://github.com/cli/cli/releases/tag/v{version}", "assets": assets}
    routes[API] = (200, {}, json.dumps(data).encode())
    return routes, requests, version


@pytest.mark.parametrize("credentials", ["none", "GH_TOKEN", "GITHUB_TOKEN", "both", "empty-gh"])
@pytest.mark.parametrize("explicit", [False, True])
def test_release_token_is_optional_and_never_frozen(tmp_path, monkeypatch, capsys, gh_release, credentials, explicit):
    routes, requests, version = gh_release
    if credentials in {"GH_TOKEN", "both"}:
        monkeypatch.setenv("GH_TOKEN", TOKEN)
    if credentials in {"GITHUB_TOKEN", "both", "empty-gh"}:
        monkeypatch.setenv("GITHUB_TOKEN", TOKEN if credentials != "both" else "lower-priority-token")
    if credentials == "empty-gh":
        monkeypatch.setenv("GH_TOKEN", "")
    api = API
    if explicit:
        monkeypatch.setenv("GH_VERSION", version)
        api = API.removesuffix("latest") + "tags/v" + version
        routes[api] = routes[API]
    output = tmp_path / "inputs.json"
    monkeypatch.setattr(sys, "argv", ["resolve_inputs.py", "resolve", "--tools", "gh", "--output", str(output)])
    inputs.main()
    record = json.loads(output.read_bytes())
    assert record["tools"]["gh"]["version"] == version
    for arch in inputs.ARCHITECTURES:
        inputs.download(record["tools"]["gh"]["assets"][arch], tmp_path / arch)
        assert (tmp_path / arch).read_bytes() == arch.encode()
        assert inputs.environment(record, arch)["GH_VERSION"] == version
    assert requests[0][0] == api
    assert requests[0][1].get("authorization") == (None if credentials == "none" else f"Bearer {TOKEN}")
    assert all("authorization" not in headers for _, headers in requests[1:])
    assert all(headers["user-agent"] == "safeyolo-guest-builder" for _, headers in requests)
    captured = capsys.readouterr()
    assert TOKEN not in output.read_text() + captured.out + captured.err
    assert "lower-priority-token" not in output.read_text() + captured.out + captured.err


@pytest.mark.parametrize("fault", ["draft", "prerelease", "unstable-version", "explicit-mismatch"])
def test_authenticated_lookup_preserves_release_selection_failures(monkeypatch, gh_release, fault):
    routes, requests, _ = gh_release
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    data = json.loads(routes[API][2])
    api = API
    if fault in {"draft", "prerelease"}:
        data[fault] = True
    elif fault == "unstable-version":
        data["tag_name"] = "v9.8.7-rc1"
    else:
        monkeypatch.setenv("GH_VERSION", "1.2.3")
        api = API.removesuffix("latest") + "tags/v1.2.3"
    routes[api] = (200, {}, json.dumps(data).encode())
    with pytest.raises(ValueError, match="stable release|explicit tool version"):
        inputs.release("gh")
    assert len(requests) == 1
    assert requests[0][1]["authorization"] == f"Bearer {TOKEN}"


@pytest.mark.skipif(not shutil.which("gpg"), reason="signature control requires GPG")
def test_signed_release_fetches_checksums_signature_and_key_without_credentials(monkeypatch, upstream):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    version = "2026.10.12"
    fixtures = ROOT / "tests/fixtures/guest-signatures"
    api = "https://api.github.com/repos/jdx/mise/releases/latest"
    # Even a checksum/signature URL on the API origin receives no token.
    sums = "https://api.github.com/checksums"
    signature = "https://api.github.com/signature"
    key = "https://mise.jdx.dev/gpg-key.pub"
    assets = [{"name": inputs.asset_name("mise", version, arch),
               "browser_download_url": f"https://github.com/jdx/mise/{arch}"} for arch in inputs.ARCHITECTURES]
    assets += [{"name": "SHASUMS256.txt", "browser_download_url": sums},
               {"name": "SHASUMS256.asc", "browser_download_url": signature}]
    data = {"tag_name": "v" + version, "draft": False, "prerelease": False,
            "html_url": "https://github.com/jdx/mise/releases/tag/v" + version, "assets": assets}
    routes.update({api: (200, {}, json.dumps(data).encode()),
                   sums: (200, {}, (fixtures / "mise-2026.10.12-SHASUMS256.txt").read_bytes()),
                   signature: (200, {}, (fixtures / "mise-2026.10.12-SHASUMS256.asc").read_bytes()),
                   key: (200, {}, (fixtures / "mise-key.pub").read_bytes())})
    record = inputs.release("mise")
    assert record["assets"]["amd64"]["verification"]["signer"] == "24853EC9F655CE80B48E6C3A8B81C9D17413A06D"
    assert [url for url, _ in requests] == [api, sums, signature, key]
    assert requests[0][1]["authorization"] == f"Bearer {TOKEN}"
    assert all("authorization" not in headers for _, headers in requests[1:])


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("destination", ["https://release-assets.githubusercontent.com/asset",
                                        "https://github.com/cli/cli/release.asc",
                                        "https://mise.jdx.dev/gpg-key.pub",
                                        "https://api.github.com.other.invalid/metadata"])
def test_authorization_is_removed_from_every_redirect(monkeypatch, upstream, status, destination):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    same_origin = API + "?redirect=1"
    returned = API + "?redirect=2"
    routes.update({API: (status, {"Location": "/repos/cli/cli/releases/latest?redirect=1"}, b""),
                   same_origin: (status, {"Location": destination}, b""),
                   destination: (status, {"Location": returned}, b""),
                   returned: (200, {}, b"metadata")})
    assert inputs.fetch(API, github_api=True) == b"metadata"
    assert [url for url, _ in requests] == [API, same_origin, destination, returned]
    assert requests[0][1]["authorization"] == f"Bearer {TOKEN}"
    assert all("authorization" not in headers for _, headers in requests[1:])


def test_api_url_does_not_automatically_receive_credentials(monkeypatch, upstream):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    routes[API] = (200, {}, b"download")
    assert inputs.fetch(API) == b"download"
    assert "authorization" not in requests[0][1]


@pytest.mark.parametrize("destination", ["http://publisher.invalid/file", "ftp://publisher.invalid/file", "file:///etc/passwd"])
def test_insecure_redirect_is_refused_before_request(monkeypatch, upstream, destination):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    intermediate = "https://publisher.invalid/redirect"
    routes.update({API: (302, {"Location": intermediate}, b""),
                   intermediate: (302, {"Location": destination}, b"")})
    with pytest.raises((ValueError, HTTPError), match="HTTPS|Redirection"):
        inputs.fetch(API, github_api=True)
    assert [url for url, _ in requests] == [API, intermediate]
    assert "authorization" not in requests[1][1]


@pytest.mark.parametrize("status", [401, 403, 404, 503])
def test_release_api_failure_is_visible_without_fallback_or_token(
    tmp_path, monkeypatch, capsys, upstream, retry_sleeps, status,
):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    routes[API] = (status, {}, b"release lookup failed")
    output = tmp_path / "inputs.json"
    monkeypatch.setattr(sys, "argv", ["resolve_inputs.py", "resolve", "--tools", "gh", "--output", str(output)])
    with pytest.raises(HTTPError) as error:
        inputs.main()
    assert error.value.code == status
    assert not output.exists()
    assert len(requests) == (3 if status == 503 else 1)
    assert retry_sleeps == ([1, 2] if status == 503 else [])
    captured = capsys.readouterr()
    assert TOKEN not in "".join(traceback.format_exception(error.value)) + captured.out + captured.err


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
@pytest.mark.parametrize("redirected", [False, True])
def test_fetch_retries_transient_http_with_fresh_redirect_history(
    monkeypatch, upstream, retry_sleeps, status, redirected,
):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    errors = [io.BytesIO(b"temporary release failure") for _ in range(2)]
    if redirected:
        intermediate = API + "?redirect=1"
        returned = API + "?redirect=2"
        asset = "https://release-assets.githubusercontent.com/release"
        routes.update({API: (302, {"Location": intermediate}, b""),
                       asset: (302, {"Location": returned}, b""),
                       returned: (302, {"Location": intermediate}, b"")})
        # Revisit one hop within each attempt. Reusing its old Request would
        # exhaust urllib's redirect allowance before the third attempt.
        routes[intermediate] = [
            (302, {"Location": asset}, b""), (status, {}, errors[0]),
            (302, {"Location": asset}, b""), (status, {}, errors[1]),
            (302, {"Location": asset}, b""), (200, {}, b"verified metadata"),
        ]
        path = [API, intermediate, asset, returned, intermediate]
    else:
        routes[API] = [(status, {}, errors[0]), (status, {}, errors[1]),
                       (200, {}, b"verified metadata")]
        path = [API]
    assert inputs.fetch(API, github_api=True) == b"verified metadata"
    assert [url for url, _ in requests] == path * 3
    assert retry_sleeps == [1, 2] and all(error.closed for error in errors)
    for index, (_, headers) in enumerate(requests):
        assert headers.get("authorization") == (f"Bearer {TOKEN}" if index % len(path) == 0 else None)
        assert headers["user-agent"] == "safeyolo-guest-builder"


@pytest.mark.parametrize("failure", [URLError("transport failed"), ssl.SSLError("TLS failed"),
                                     TimeoutError("transport timed out")])
def test_fetch_preserves_transport_failures_without_retry(upstream, retry_sleeps, failure):
    routes, requests = upstream
    routes[API] = failure
    with pytest.raises(type(failure)) as error:
        inputs.fetch(API)
    assert error.value is failure
    assert len(requests) == 1 and retry_sleeps == []


def test_signature_http_exhaustion_preserves_failure_without_output_or_key_fetch(
    tmp_path, monkeypatch, capsys, upstream, retry_sleeps,
):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    api = "https://api.github.com/repos/oras-project/oras/releases/latest"
    base = "https://github.com/oras-project/oras/releases/download/v9.8.7/"
    sums = base + "oras_9.8.7_checksums.txt"
    signature = base + "oras_9.8.7_checksums.txt.asc"
    assets = [{"name": inputs.asset_name("oras", "9.8.7", arch),
               "browser_download_url": base + inputs.asset_name("oras", "9.8.7", arch)}
              for arch in inputs.ARCHITECTURES]
    assets += [{"name": "oras_9.8.7_checksums.txt", "browser_download_url": sums},
               {"name": "oras_9.8.7_checksums.txt.asc", "browser_download_url": signature}]
    metadata = {"tag_name": "v9.8.7", "draft": False, "prerelease": False,
                "html_url": "https://github.com/oras-project/oras/releases/tag/v9.8.7", "assets": assets}
    errors = [io.BytesIO(f"signature failure {index}".encode()) for index in range(3)]
    routes.update({api: (200, {}, json.dumps(metadata).encode()), sums: (200, {}, b"checksums"),
                   signature: [(504, {}, error) for error in errors]})
    output = tmp_path / "inputs.json"
    monkeypatch.setattr(sys, "argv", ["resolve_inputs.py", "resolve", "--tools", "oras",
                                     "--output", str(output)])
    with pytest.raises(HTTPError) as error:
        inputs.main()
    assert error.value.code == 504 and error.value.url == signature
    assert all(body.closed for body in errors[:2])
    assert error.value.read() == b"signature failure 2"
    error.value.close()
    assert retry_sleeps == [1, 2] and not output.exists()
    # The official-key fetch precedes every GPG operation in signed_checksums.
    assert [url for url, _ in requests] == [api, sums, signature, signature, signature]
    assert requests[0][1]["authorization"] == f"Bearer {TOKEN}"
    assert all("authorization" not in headers for _, headers in requests[1:])
    captured = capsys.readouterr()
    assert TOKEN not in "".join(traceback.format_exception(error.value)) + captured.out + captured.err


@pytest.mark.parametrize("variable", ["GH_TOKEN", "GITHUB_TOKEN"])
@pytest.mark.parametrize("line_break", ["\n", "\r", "\r\n"])
def test_cli_rejects_token_line_breaks_without_disclosing_credentials(tmp_path, variable, line_break):
    output = tmp_path / "inputs.json"
    environment = {**os.environ, "GH_TOKEN": "", "GITHUB_TOKEN": "unused-fallback-token"}
    environment[variable] = TOKEN + line_break
    result = subprocess.run([sys.executable, str(ROOT / "guest/resolve_inputs.py"), "resolve", "--tools", "gh",
                             "--output", str(output)], env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert TOKEN not in result.stdout + result.stderr
    assert "GitHub API token must not contain line breaks" in result.stderr
    assert not output.exists()


def test_resolve_workflow_supplies_its_scoped_token_to_the_resolver_step():
    workflow = yaml.safe_load((ROOT / ".github/workflows/guest-oci.yml").read_text())
    job = workflow["jobs"]["resolve"]
    assert job.get("permissions", workflow["permissions"]) == {"contents": "read"}
    step = next(step for step in job["steps"] if step.get("id") == "inputs")
    assert step["env"]["GH_TOKEN"] == "${{ secrets.GITHUB_TOKEN }}"
    assert 'python3 guest/resolve_inputs.py resolve --base --output "$RUNNER_TEMP/inputs.json"' in step["run"]


@pytest.mark.parametrize("workflow_name", ["ci.yml", "guest-oci.yml", "blackbox.yml", "installed-arm64.yml"])
def test_publisher_workflow_supplies_token_for_fresh_release_lookup(workflow_name):
    workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text())
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            if "scripts/install_oras.sh" not in step.get("run", ""):
                continue
            environment = {**workflow.get("env", {}), **job.get("env", {}), **step.get("env", {})}
            if environment.get("GUEST_INPUTS"):
                continue
            assert job.get("permissions", workflow["permissions"])["contents"] == "read"
            assert step.get("env", {}).get("GH_TOKEN") == "${{ secrets.GITHUB_TOKEN }}", (job_name, step)


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
@pytest.mark.parametrize("outcome", ["cached", "http-error", "checksum"])
def test_download_cli_identifies_tool_and_architecture_without_url_secrets(
    tmp_path, monkeypatch, capsys, upstream, retry_sleeps, architecture, outcome,
):
    routes, requests = upstream
    url = (f"https://fixture-user:private-password@upstream.invalid/gh-9.8.7-linux-{architecture}.tar.gz"
           "?signature=private-query#private-fragment")
    output = tmp_path / "gh.tar.gz"
    payload = b"verified archive"
    frozen = tmp_path / "inputs.json"
    frozen.write_text(json.dumps({"tools": {"gh": {"version": "9.8.7", "assets": {
        architecture: {"url": url, "sha256": inputs.sha256(payload)},
    }}}}))
    monkeypatch.setattr(sys, "argv", ["resolve_inputs.py", "download", "--inputs", str(frozen),
                                    "--architecture", architecture, "--tool", "gh", "--output", str(output)])
    if outcome == "cached":
        output.write_bytes(payload)
        inputs.main()
        assert not requests and not retry_sleeps
    else:
        routes[url] = (504, {}, b"unavailable") if outcome == "http-error" else (200, {}, b"wrong bytes")
        with pytest.raises(HTTPError if outcome == "http-error" else ValueError) as error:
            inputs.main()
        if outcome == "http-error":
            assert error.value.code == 504
            assert retry_sleeps == [1, 2] and len(requests) == 3
        else:
            assert "frozen official checksum" in str(error.value)
            assert not retry_sleeps and len(requests) == 1
        assert not output.exists()
    captured = capsys.readouterr()
    assert not captured.out
    assert (f"Preparing gh 9.8.7 for linux/{architecture}: "
            f"'https://upstream.invalid/gh-9.8.7-linux-{architecture}.tar.gz'") in captured.err
    for secret in ("fixture-user", "private-password", "private-query", "private-fragment"):
        assert secret not in captured.err


def download_diagnostics(capsys):
    return [json.loads(line.removeprefix("guest HTTPS: "))
            for line in capsys.readouterr().err.splitlines()]


@pytest.mark.parametrize("route", ["direct", "http-proxy", "https-proxy", "bypass"])
@pytest.mark.parametrize("userinfo", [False, True])
def test_failed_fetch_reports_actual_peer_and_all_address_errors(monkeypatch, capsys, route, userinfo):
    proxy = "https://proxy-user:proxy-secret@proxy.invalid:8443/secret-proxy-path?private-query"
    if route == "http-proxy":
        proxy = proxy.replace("https:", "http:", 1)
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {} if route == "direct" else {"https": proxy})
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: route == "bypass")
    monkeypatch.setenv("GH_TOKEN", "private-api-token")
    rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::20", 443, 0, 0))]
    failures = [TimeoutError("private-first-error"), OSError(101, "private-last-error")]
    resolutions, sockets, attempts, delays = [], [], [], []

    def resolve(*args):
        resolutions.append(args)
        port = args[1]
        return [(family, kind, protocol, name, (address[0], port, *address[2:]))
                for family, kind, protocol, name, address in rows]

    class FailedSocket:
        def __init__(self, *args):
            self.args, self.closed, self.timeout = args, False, None
            sockets.append(self)

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, address):
            attempts.append(address)
            raise failures[len(attempts) - 1]

        def close(self):
            self.closed = True

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", FailedSocket)
    monkeypatch.setattr(inputs.time, "sleep", delays.append)
    clock = iter([0, 1, 1.75, 2, 3.25])
    monkeypatch.setattr(inputs.time, "monotonic", lambda: next(clock))

    origin = "private-user:private-password@origin.invalid:443" if userinfo else "origin.invalid"
    with pytest.raises(URLError) as error:
        inputs.fetch(f"https://{origin}/private-url-path?private-url-query#private-fragment", github_api=True)
    assert error.value.reason is failures[-1]
    proxied = route in {"http-proxy", "https-proxy"}
    peer, port = ("proxy.invalid", 8443) if proxied else ("origin.invalid", 443)
    raw_host = origin.removesuffix(":443")
    assert resolutions == [(peer if proxied else raw_host, port, 0, socket.SOCK_STREAM)]
    assert attempts == [("192.0.2.20", port), ("2001:db8::20", port, 0, 0)]
    assert all(sock.closed and sock.timeout == 120 for sock in sockets)
    assert [sock.args for sock in sockets] == [row[:3] for row in rows]
    assert delays == []
    events = download_diagnostics(capsys)
    assert events == [
        {"event": "connection", "host": peer, "port": port, "proxy": proxied,
         "origin_host": "origin.invalid", "origin_port": 443},
        {"event": "address_error", "family": socket.AF_INET, "address": ["192.0.2.20", port],
         "elapsed": 0.75, "error": "TimeoutError", "errno": None},
        {"event": "address_error", "family": socket.AF_INET6, "address": ["2001:db8::20", port, 0, 0],
         "elapsed": 1.25, "error": "OSError", "errno": 101},
    ]


@pytest.mark.parametrize("dns_failure", [False, True])
def test_resolution_failure_is_observed_without_replacement(monkeypatch, capsys, dns_failure):
    connection = inputs.DownloadHTTPSConnection("origin.invalid", timeout=120)
    failure = socket.gaierror(-2, "private resolver text")

    def resolve(*args):
        if dns_failure:
            raise failure
        return []

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(OSError) as error:
        connection.connect()
    events = download_diagnostics(capsys)
    if dns_failure:
        assert error.value is failure
        assert events[-1]["event"] == "resolution_error" and events[-1]["errno"] == -2
        assert "private resolver text" not in json.dumps(events)
    else:
        assert str(error.value) == "getaddrinfo returns an empty list"
        assert len(events) == 1


def test_success_after_failed_address_retains_timeout_bind_and_tls(monkeypatch, capsys):
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443)),
                 (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 443, 0, 0))]
    sockets, wrapped = [], []

    class ControlledSocket:
        def __init__(self, *args):
            self.closed, self.bound, self.timeout = False, None, None
            sockets.append(self)

        def settimeout(self, timeout):
            self.timeout = timeout

        def bind(self, source):
            self.bound = source

        def connect(self, address):
            if len(sockets) == 1:
                raise TimeoutError("first address timed out")

        def close(self):
            self.closed = True

        def setsockopt(self, *args):
            pass

    def wrap(context, sock, *, server_hostname):
        wrapped.append((context.verify_mode, context.check_hostname, server_hostname, sock))
        return sock

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: addresses)
    monkeypatch.setattr(socket, "socket", ControlledSocket)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    connection = inputs.DownloadHTTPSConnection("origin.invalid", timeout=120, source_address=("127.0.0.1", 0))
    connection.connect()
    assert connection.sock is sockets[1]
    assert sockets[0].closed and not sockets[1].closed
    assert all(sock.timeout == 120 and sock.bound == ("127.0.0.1", 0) for sock in sockets)
    assert wrapped == [(ssl.CERT_REQUIRED, True, "origin.invalid", sockets[1])]
    assert [event["event"] for event in download_diagnostics(capsys)] == ["connection", "address_error", "address_connected"]
    connection.close()
    assert sockets[1].closed


@pytest.mark.parametrize("proxied", [False, True])
def test_successful_fetch_retains_proxy_auth_origin_auth_tls_and_bytes(monkeypatch, capsys, proxied):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"https": "http://private-user:private-password@proxy.invalid:8443"} if proxied else {})
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: False)
    monkeypatch.setenv("GH_TOKEN", "private-api-token")
    sent, wrapped, peers = [], [], []
    replies = [b"HTTP/1.1 200 Connection established\r\n\r\n"] if proxied else []
    replies.append(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nverified")

    class ProxySocket:
        def sendall(self, data):
            sent.append(data)

        def makefile(self, mode):
            return io.BytesIO(replies.pop(0))

        def settimeout(self, timeout):
            assert timeout == 120

        def connect(self, address):
            peers.append(address)

        def setsockopt(self, *args):
            pass

        def close(self):
            pass

    peer = ProxySocket()
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", port))])
    monkeypatch.setattr(socket, "socket", lambda *args: peer)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda context, sock, *, server_hostname:
                        wrapped.append((context.verify_mode, context.check_hostname, server_hostname)) or sock)
    assert inputs.fetch("https://origin.invalid/private-path?private-query", github_api=True) == b"verified"
    assert wrapped == [(ssl.CERT_REQUIRED, True, "origin.invalid")]
    assert peers == [("192.0.2.20", 8443 if proxied else 443)]
    if proxied:
        assert b"CONNECT origin.invalid:443" in sent[0]
        assert b"Proxy-Authorization: Basic " in sent[0]
        assert b"private-api-token" not in sent[0]
    assert b"Authorization: Bearer private-api-token" in sent[-1]
    assert b"Proxy-Authorization" not in sent[-1]
    assert download_diagnostics(capsys)[0] == {"event": "connection", "host": "proxy.invalid" if proxied else "origin.invalid",
                                    "port": 8443 if proxied else 443, "proxy": proxied,
                                    "origin_host": "origin.invalid", "origin_port": 443}


def test_redirect_diagnostic_omits_all_url_secrets(capsys):
    handler = inputs.HTTPSRedirectHandler()
    request = urllib.request.Request("https://origin.invalid/private-source")
    destination = "https://private-user:private-password@[2001:db8::1]:8443/private-path?private-query#private-fragment"
    redirected = handler.redirect_request(request, None, 302, "Found", {}, destination)
    assert redirected.full_url == destination
    assert download_diagnostics(capsys) == [{"event": "redirect", "destination":
                                    {"scheme": "https", "host": "2001:db8::1", "port": 8443}}]


def test_redirected_socket_failure_reports_the_new_actual_peer(monkeypatch, capsys):
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {})
    resolved, sent, wrapped = [], [], []
    failure = OSError(101, "private socket error")
    destination = "https://redirect.invalid/private-path?private-query#private-fragment"

    def resolve(host, port, *args):
        resolved.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", port))]

    class RedirectSocket:
        def settimeout(self, timeout):
            assert timeout == 120

        def connect(self, address):
            if len(resolved) == 2:
                raise failure

        def sendall(self, data):
            sent.append(data)

        def makefile(self, mode):
            return io.BytesIO(f"HTTP/1.1 302 Found\r\nLocation: {destination}\r\nContent-Length: 0\r\n\r\n".encode())

        def setsockopt(self, *args):
            pass

        def close(self):
            pass

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", lambda *args: RedirectSocket())
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda context, sock, *, server_hostname:
                        wrapped.append(server_hostname) or sock)
    with pytest.raises(URLError) as error:
        inputs.fetch("https://origin.invalid/private-source")
    assert error.value.reason is failure
    assert resolved == [("origin.invalid", 443), ("redirect.invalid", 443)]
    assert wrapped == ["origin.invalid"] and len(sent) == 1
    events = download_diagnostics(capsys)
    assert [event["event"] for event in events] == ["connection", "address_connected", "redirect", "connection", "address_error"]
    assert events[2]["destination"] == {"scheme": "https", "host": "redirect.invalid", "port": None}
    assert events[3]["host"] == "redirect.invalid" and events[4]["errno"] == 101
    assert "private" not in json.dumps(events)


def test_diagnostic_stream_failure_does_not_replace_connection_result(monkeypatch):
    def closed_stream(*args, **kwargs):
        raise BrokenPipeError("closed stderr")

    monkeypatch.setattr("builtins.print", closed_stream)
    inputs.download_diagnostic("address_error", errno=101)
