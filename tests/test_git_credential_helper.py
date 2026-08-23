"""git-credential-safeyolo helper contract tests.

Runs the helper as a subprocess with a mocked /gateway/services endpoint and
asserts the git-credential-format output.
"""

from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest


HELPER_PATH = Path(__file__).resolve().parent.parent / "guest" / "rootfs" / "git-credential-safeyolo"


# --- Fake Agent API --------------------------------------------------------


class _FakeAgentApiHandler(http.server.BaseHTTPRequestHandler):
    payload: dict = {}  # class-level override per test
    required_auth: str = "test-agent-token"
    hits: list[dict] = []  # request log

    def log_message(self, *_args, **_kwargs):  # silence stderr noise in tests
        pass

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        _FakeAgentApiHandler.hits.append({"path": self.path, "auth": auth})
        if self.path != "/gateway/services":
            self.send_error(404)
            return
        if auth != f"Bearer {self.required_auth}":
            self.send_error(401)
            return
        body = json.dumps(self.payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_agent_api():
    server = http.server.HTTPServer(("127.0.0.1", 0), _FakeAgentApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _FakeAgentApiHandler.hits = []
    yield server
    server.shutdown()
    thread.join(timeout=2.0)


def _run_helper(tmp_path, stdin_text: str, api_server, verb: str = "get") -> subprocess.CompletedProcess:
    """Run the helper with a temporary agent token + rewritten API URL.

    We rewrite AGENT_API_URL + AGENT_TOKEN_PATH at run time via a small shim
    that imports the helper as a module and calls main(), so tests don't have
    to touch DNS / write to /app/agent_token.
    """
    token_file = tmp_path / "agent_token"
    token_file.write_text("test-agent-token")

    api_url = f"http://127.0.0.1:{api_server.server_port}/gateway/services"

    shim = tmp_path / "run_helper.py"
    shim.write_text(f"""
import importlib.util, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("helper", {str(HELPER_PATH)!r})
spec = importlib.util.spec_from_loader("helper", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
mod.AGENT_API_URL = {api_url!r}
mod.AGENT_TOKEN_PATH = {str(token_file)!r}
sys.exit(mod.main(["helper", {verb!r}]))
""")

    return subprocess.run(
        [sys.executable, str(shim)],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=10,
    )


# --- Tests -----------------------------------------------------------------


class TestGitCredentialHelperGet:
    def test_returns_sgw_token_for_configured_github_host(self, tmp_path, fake_agent_api):
        _FakeAgentApiHandler.payload = {
            "agent": "test-agent",
            "authorized": {
                "github": {
                    "host": "github.com",
                    "token": "sgw_" + "a" * 64,
                    "capability": "git_push",
                    "account": "agent",
                }
            },
            "available": [],
        }

        stdin = "protocol=https\nhost=github.com\n\n"
        result = _run_helper(tmp_path, stdin, fake_agent_api)

        assert result.returncode == 0, result.stderr
        assert "username=safeyolo" in result.stdout
        assert f"password=sgw_{'a' * 64}" in result.stdout
        # Sanity: helper called the fake API with the bearer token.
        assert any(h["auth"] == "Bearer test-agent-token" for h in _FakeAgentApiHandler.hits)

    def test_silent_when_host_not_in_authorized_services(self, tmp_path, fake_agent_api):
        _FakeAgentApiHandler.payload = {
            "agent": "test-agent",
            "authorized": {
                "github": {
                    "host": "github.com",
                    "token": "sgw_" + "b" * 64,
                    "capability": "git_push",
                    "account": "agent",
                }
            },
            "available": [],
        }

        stdin = "protocol=https\nhost=example.com\n\n"
        result = _run_helper(tmp_path, stdin, fake_agent_api)

        assert result.returncode == 0, result.stderr
        # No credentials → helper prints nothing so git falls through to the
        # next helper / prompt.
        assert result.stdout.strip() == ""

    def test_silent_when_username_is_someone_else(self, tmp_path, fake_agent_api):
        """If the operator already configured a specific username, don't override."""
        _FakeAgentApiHandler.payload = {
            "agent": "test-agent",
            "authorized": {
                "github": {
                    "host": "github.com",
                    "token": "sgw_" + "c" * 64,
                    "capability": "git_push",
                    "account": "agent",
                }
            },
            "available": [],
        }
        stdin = "protocol=https\nhost=github.com\nusername=alice\n\n"
        result = _run_helper(tmp_path, stdin, fake_agent_api)
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_silent_for_non_https(self, tmp_path, fake_agent_api):
        _FakeAgentApiHandler.payload = {"agent": "a", "authorized": {}, "available": []}
        stdin = "protocol=ssh\nhost=github.com\n\n"
        result = _run_helper(tmp_path, stdin, fake_agent_api)
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_store_and_erase_are_noops(self, tmp_path, fake_agent_api):
        # Both verbs must consume stdin and exit 0 without emitting anything.
        for verb in ("store", "erase"):
            stdin = "protocol=https\nhost=github.com\nusername=safeyolo\npassword=sgw_x\n\n"
            result = _run_helper(tmp_path, stdin, fake_agent_api, verb=verb)
            assert result.returncode == 0
            assert result.stdout == ""

    def test_missing_agent_token_returns_silent(self, tmp_path, fake_agent_api):
        _FakeAgentApiHandler.payload = {"agent": "a", "authorized": {}, "available": []}
        # Point token path at a nonexistent file by not writing it (shim writes it,
        # so we override differently: use a URL to a path that doesn't exist).
        shim = tmp_path / "run_helper_no_token.py"
        shim.write_text(f"""
import importlib.util, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("helper", {str(HELPER_PATH)!r})
spec = importlib.util.spec_from_loader("helper", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
mod.AGENT_API_URL = 'http://127.0.0.1:{fake_agent_api.server_port}/gateway/services'
mod.AGENT_TOKEN_PATH = {str(tmp_path / 'does-not-exist')!r}
sys.exit(mod.main(["helper", "get"]))
""")
        result = subprocess.run(
            [sys.executable, str(shim)],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""
