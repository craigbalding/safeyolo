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
TOKEN_FILE="$HOME/.safeyolo/data/agent_token"
curl --header 'Authorization :  Bearer $(  cat -- "$TOKEN_FILE"  )' \\
  http://_safeyolo.proxy.internal/health
```
"""
    assert mod.find_unsafe_token_argv(text)


def test_rejects_token_read_then_direct_header_interpolation():
    text = """```sh
agent_token = ignored
TOKEN_PATH=/app/agent_token
AGENT_TOKEN="$(cat "$TOKEN_PATH")"
curl -sS \\
  --header="Authorization: Bearer ${AGENT_TOKEN}" \\
  http://_safeyolo.proxy.internal/health
```
"""
    findings = mod.find_unsafe_token_argv(text)
    assert len(findings) == 1
    assert findings[0][0] == 5


def test_rejects_legacy_backtick_token_expansion():
    text = """curl -H 'Authorization: Bearer `cat /app/agent_token`' \\
  http://_safeyolo.proxy.internal/health
"""
    assert mod.find_unsafe_token_argv(text)


def test_rejects_python_list_curl_argv_construction_with_source_flow():
    text = '''import subprocess

def _agent_token():
    path = "/app/agent_token"
    with open(path) as f:
        return f.read().strip()

def request(token):
    cmd = ["curl", "-s"]
    cmd.extend(["-H", f"Authorization: Bearer {token}"])
    cmd.append("http://_safeyolo.proxy.internal/health")
    subprocess.run(cmd)

request(_agent_token())
'''
    assert mod.find_unsafe_token_argv(text)


def test_rejects_python_tuple_curl_argv_construction():
    text = '''import subprocess
from pathlib import Path

agent_token = Path("/app/agent_token").read_text().strip()
subprocess.run((
    "curl", "-H", f"Authorization: Bearer {agent_token}",
    "http://_safeyolo.proxy.internal/health",
))
'''
    assert mod.find_unsafe_token_argv(text)


def test_accepts_unrelated_admin_and_service_curl_argv():
    text = '''import subprocess

admin_token = "admin-value"
subprocess.run([
    "curl", "-H", f"Authorization: Bearer {admin_token}",
    "http://localhost:9090/stats",
])
service_token = "service-value"
subprocess.run((
    "curl", "--header", f"Authorization: Bearer {service_token}",
    "https://service.example/v1",
))
'''
    assert mod.find_unsafe_token_argv(text) == []


def test_accepts_non_curl_in_process_header_from_agent_token():
    text = '''from pathlib import Path

agent_token = Path("/app/agent_token").read_text()
headers = {"Authorization": f"Bearer {agent_token}"}
literal_fixture = "Authorization: Bearer $(cat /app/agent_token)"
'''
    assert mod.find_unsafe_token_argv(text) == []


def test_rejects_shell_agent_api_url_alias():
    text = '''```sh
AGENT_API=http://_safeyolo.proxy.internal/health
token=$(cat /app/agent_token)
curl -H "Authorization: Bearer $token" "$AGENT_API"
```
'''
    assert mod.find_unsafe_token_argv(text)


def test_rejects_python_agent_api_url_alias():
    text = '''import subprocess
from pathlib import Path

token = Path("/app/agent_token").read_text().strip()
url = "http://_safeyolo.proxy.internal/health"
subprocess.run(["curl", "-H", f"Authorization: Bearer {token}", url])
'''
    assert mod.find_unsafe_token_argv(text)


def test_rejects_python_list_add_and_augmented_add_assembly():
    text = '''import subprocess
from pathlib import Path

AGENT_API_URL = "http://_safeyolo.proxy.internal/health"
token = Path("/app/agent_token").read_text().strip()
cmd = ["curl"] + ["-H", f"Authorization: Bearer {token}", AGENT_API_URL]
subprocess.run(cmd)

literal_agent_url = "http://_safeyolo.proxy.internal/health"
cmd = ["curl"]
cmd += ["-H", f"Authorization: Bearer {token}", literal_agent_url]
subprocess.run(cmd)
'''
    assert len(mod.find_unsafe_token_argv(text)) == 2


def test_shell_reassignment_in_separate_block_kills_token_path_provenance():
    text = '''```sh
TOKEN_FILE=/app/agent_token
```

```sh
TOKEN_FILE=/run/admin_token
admin_token=$(cat "$TOKEN_FILE")
curl -H "Authorization: Bearer $admin_token" \\
  http://_safeyolo.proxy.internal/health
```
'''
    assert mod.find_unsafe_token_argv(text) == []


def test_python_function_returning_token_path_is_not_token_value():
    text = '''import subprocess
from pathlib import Path

def token_path():
    return Path("/app/agent_token")

path_text = token_path()
subprocess.run([
    "curl", "-H", f"Authorization: Bearer {path_text}",
    "http://_safeyolo.proxy.internal/health",
])
'''
    assert mod.find_unsafe_token_argv(text) == []


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
