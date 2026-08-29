"""Tests for the Agent API token-to-curl-argv drift check."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_agent_token_argv.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_agent_token_argv", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


def test_rejects_direct_agent_token_command_substitution():
    text = """```sh
curl -sS http://_safeyolo.proxy.internal/health \\
  -H "Authorization: Bearer $(cat /app/agent_token)"
```
"""
    assert mod.find_unsafe_token_argv(text)


def test_rejects_spacing_quoting_and_host_token_file_variants():
    text = """```sh
curl --header 'Authorization :  Bearer $(  cat -- "$TOKEN_FILE"  )' \\
  http://_safeyolo.proxy.internal/health
```
"""
    assert mod.find_unsafe_token_argv(text)


def test_rejects_token_read_then_direct_header_interpolation():
    text = """```sh
agent_token = ignored
AGENT_TOKEN="$(cat "/app/agent_token")"
curl -sS \\
  --header="Authorization: Bearer ${AGENT_TOKEN}" \\
  http://_safeyolo.proxy.internal/health
```
"""
    findings = mod.find_unsafe_token_argv(text)
    assert len(findings) == 1
    assert findings[0][0] == 4


def test_rejects_legacy_backtick_token_expansion():
    text = """curl -H 'Authorization: Bearer `cat /app/agent_token`' \\
  http://_safeyolo.proxy.internal/health
"""
    assert mod.find_unsafe_token_argv(text)


def test_rejects_python_curl_argv_construction():
    text = """cmd = ["curl", "-s"]
cmd.extend(["-H", f"Authorization: Bearer {token}"])
subprocess.run(cmd)
"""
    assert mod.find_unsafe_token_argv(text)


def test_accepts_stdin_header_pattern_on_one_or_many_lines():
    multiline = """(
  agent_token=$(cat /app/agent_token) || exit
  printf 'Authorization: Bearer %s\\n' "$agent_token" |
    curl -sS --header @- http://_safeyolo.proxy.internal/health
)
"""
    graph_label = (
        "Read /app/agent_token fresh; pipe the Authorization header to "
        "curl -sS --header @- http://_safeyolo.proxy.internal/health"
    )
    assert mod.find_unsafe_token_argv(multiline) == []
    assert mod.find_unsafe_token_argv(graph_label) == []


def test_ignores_placeholders_admin_credentials_and_in_process_headers():
    text = """curl -H "Authorization: Bearer <token>" http://example.test
ADMIN_TOKEN=$(cat /run/admin_token)
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:9090/stats
flow.request.headers["authorization"] = f"Bearer {agent_token}"
"""
    assert mod.find_unsafe_token_argv(text) == []
