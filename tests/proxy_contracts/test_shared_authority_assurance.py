"""Run the deterministic controller against real native approval/HTTP owners.

Backend births and guest transport are controlled process-test inputs. Actual
installed guest enforcement and cleanup remain separate installed evidence.
"""

from __future__ import annotations

import http.client
import json
import subprocess
import sys
import threading
import uuid
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.blackbox import installed_shared_approvals as approvals
from tests.blackbox.installed_host_smoke import _process_start_token
from tests.proxy_contracts.harness import launch_proxy, request


@pytest.mark.skipif(sys.platform != "linux", reason="controlled backend birth uses Linux runsc argv")
def test_deterministic_controller_observes_native_decisions_and_origin_effects(tmp_path, monkeypatch):
    """Exercise wrong scope, original receipts, expiry, revocation and turnover."""
    ids = {name: "ag-" + uuid.uuid4().hex for name in ("worker", "helper")}
    marker = "authority-" + uuid.uuid4().hex
    hits = []

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.server.server_port, self.path))
            self.send_response(200)
            self.send_header("Content-Length", str(len(marker)))
            self.end_headers()
            self.wfile.write(marker.encode())

        do_POST = do_GET

        def log_message(self, *_arguments):
            pass  # The independent origin counter records only port and path.

    with ExitStack() as stack:
        origins = []
        for address in ("127.0.0.2", "127.0.0.2", "127.0.0.3"):
            server = HTTPServer((address, 0), Origin)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
            thread.start()
            def close(server=server, thread=thread):
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                assert not thread.is_alive()
            stack.callback(close)
            origins.append(server)
        ports = [server.server_port for server in origins]
        services, builtin = tmp_path / "services", tmp_path / "builtin"
        services.mkdir()
        builtin.mkdir()
        source = Path(__file__).parents[1] / "blackbox/fixtures/delegated-approval-service.yaml"
        (services / "fixture.yaml").write_bytes(source.read_bytes())
        token = tmp_path / "operator-token"
        token.write_text("synthetic-authority-operator")
        (tmp_path / "data").mkdir()
        (tmp_path / "data/instance_id").write_text("sy-" + uuid.uuid4().hex)
        policy = '''[controls.credentials]
enabled=false
[hosts."*"]
egress="deny"
'''
        for name, identity in ids.items():
            policy += f'''[agents.{name}]
agent_id="{identity}"
[agents.{name}.hosts."127.0.0.2"]
egress="deny"
[agents.{name}.hosts."127.0.0.2:{ports[0]}"]
egress="prompt"
'''

        restart_preparation = []

        def start(_cli, root, name, *, python_tests=True):
            restart_preparation.append(python_tests)
            generation = uuid.uuid4().hex
            child = subprocess.Popen(["runsc-sandbox", "-c", "import time; time.sleep(300)",
                "boot", "safeyolo-" + generation, "--root", str(root / "run")], executable=sys.executable)
            def reap():
                child.terminate()
                child.wait(timeout=5)
            stack.callback(reap)
            directory = root / "agents" / name
            (directory / "config-share").mkdir(parents=True, exist_ok=True)
            (directory / "runtime.json").write_text(json.dumps({"name": name, "agent_id": ids[name],
                "run_id": generation, "state": "running", "backend_pid": child.pid,
                "backend_token": _process_start_token(child.pid)}))
            (directory / "config-share/host-launch-context.json").write_text(json.dumps({"agent_id": ids[name], "generation": generation}))

        for name in ids:
            start(None, tmp_path, name)
        restart_preparation.clear()
        monkeypatch.setattr(approvals, "start_guest", start)
        monkeypatch.setattr(approvals, "stop_guest", lambda *_arguments: None)
        monkeypatch.setattr(approvals, "checked", lambda _arguments: (tmp_path / "agents/worker/runtime.json").read_text())
        with launch_proxy("rust", tmp_path, policy, native_product=True, agent_api=True,
                          agents=tuple(ids), admin_port=0, admin_api_token_file=token,
                          gateway_services_dir=services, gateway_builtin_services_dir=builtin) as proxy:
            port = json.loads(proxy.readiness_file.read_text())["admin_port"]

            def operator(method, path, body=None):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    connection.request(method, path, json.dumps(body) if body is not None else None,
                                       {"Authorization": "Bearer synthetic-authority-operator", "Content-Type": "application/json"})
                    reply = connection.getresponse()
                    return {"status": reply.status, "body": json.loads(reply.read())}
                finally:
                    connection.close()

            def guest(name, method, url, body=None, headers=None):
                selected = dict(headers or {})
                if "_safeyolo.proxy.internal" in url:
                    selected["Authorization"] = "Bearer fixture-agent-api-token-one"
                status, received, raw = request(proxy.paths[name], url, method=method, headers=selected,
                    body=json.dumps(body).encode() if body is not None else None)
                return {"status": status, "body": raw.decode(), "approval_id": received.get("x-safeyolo-approval-id")}

            args = SimpleNamespace(config_dir=tmp_path, worker="worker", helper="helper", transport_cli="controlled",
                                   native_cli=Path("controlled"), output=tmp_path / "effects.json")
            result, _receipt = approvals.deterministic_exchange(args, ids, guest, operator,
                lambda _operation, _show, identifier: operator("GET", "/admin/approvals/" + identifier)["body"],
                ports, marker, hits)
            assert result["no_model_or_human_decision"] and len(hits) == 3
            assert result["original_run_id"] != result["current_run_id"]
            assert restart_preparation == [False]
