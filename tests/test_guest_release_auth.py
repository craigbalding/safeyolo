"""Exercise release credentials through urllib's real redirect machinery.

Only the HTTPS transport is replaced. urllib builds and follows requests,
copies headers, processes redirect statuses and raises HTTP errors normally.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import traceback
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPHandler, HTTPSHandler
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
        status, headers, body = routes[request.full_url]
        message = Message()
        for key, value in headers.items():
            message[key] = value
        response = addinfourl(io.BytesIO(body), message, request.full_url, status)
        response.msg = HTTPStatus(status).phrase
        return response

    def insecure(self, request):
        pytest.fail(f"followed an insecure redirect to {request.full_url}")

    monkeypatch.setattr(HTTPSHandler, "https_open", receive)
    monkeypatch.setattr(HTTPHandler, "http_open", insecure)
    return routes, requests


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
def test_release_api_failure_is_visible_without_fallback_or_token(tmp_path, monkeypatch, capsys, upstream, status):
    routes, requests = upstream
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    routes[API] = (status, {}, b"release lookup failed")
    output = tmp_path / "inputs.json"
    monkeypatch.setattr(sys, "argv", ["resolve_inputs.py", "resolve", "--tools", "gh", "--output", str(output)])
    with pytest.raises(HTTPError) as error:
        inputs.main()
    assert error.value.code == status
    assert not output.exists()
    assert len(requests) == 1
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
