"""P1/P4/P6 use installed native commands, two trusted listeners and owned origins.

Only this test driver uses Python. Commands execute from outside the checkout,
with a PATH containing only the installed native binaries. Existing fixture
deadlines are 15 seconds for readiness, 5 for HTTP and 4 for watcher publication.
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.proxy_contracts.harness import child_process, request, wait_ready
from tests.proxy_contracts.scenarios import origin_server

REPO = Path(__file__).resolve().parents[2]
DENY = 'budget = 12000\n[hosts]\n"*" = {egress="deny", unknown_creds="prompt"}\n'
AGENT_TOKEN = "synthetic-native-policy-fixture-agent-token"
pytestmark = pytest.mark.skipif(
    os.uname().sysname != "Linux", reason="#816 P1/P4/P6 selects Ubuntu; host/platform suites have separate owners",
)


class NativeInstance:
    def __init__(self, root, process, paths, environment):
        self.root = root
        self.process = process
        self.paths = paths
        self.environment = environment
        self.policy = root / "policy.toml"
        marker = json.loads((root / "data/ready.json").read_text())
        self.port = marker["admin_port"]
        self.token = (root / "data/admin_token").read_text().strip()

    def cli(self, *arguments):
        return subprocess.run(
            [str(self.root / "bin/safeyolo"), "--root", str(self.root), *arguments],
            cwd=self.root.parent, env=self.environment, capture_output=True, text=True, timeout=15,
        )

    def show(self):
        result = self.cli("policy", "show")
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def admin(self, method, path, body=None, *, expected_status=200):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            client.request(method, path, body=json.dumps(body) if body is not None else None,
                           headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
            response = client.getresponse()
            content = response.read()
            assert response.status == expected_status, (response.status, content)
            return json.loads(content)
        finally:
            client.close()

    def apply(self, source, *, valid=True):
        candidate = self.root.parent / "candidate"
        candidate.write_text(source)
        result = self.cli("policy", "apply", str(candidate))
        assert (result.returncode == 0) == valid, (result.stdout, result.stderr)
        if valid:
            assert json.loads(result.stdout)["status"] == "active"
        return result


@contextmanager
def native_instance(directory, source=DENY, *, services=False, parent_proxy=None):
    artifacts = Path(os.environ.get("SAFEYOLO_NATIVE_ARTIFACTS", str(REPO / "proxy/target/debug")))
    root = directory / "installed"
    installation = subprocess.run(
        [str(REPO / "scripts/install_native.sh"), "--root", str(root), "--artifacts", str(artifacts),
         "--profile", "debug"], capture_output=True, text=True, timeout=15,
    )
    assert installation.returncode == 0, installation.stderr
    assert "commit=" in installation.stdout and "profile=" in installation.stdout
    assert sorted(path.name for path in (root / "bin").iterdir()) == ["safeyolo", "safeyolo-proxy"]
    assert not list(root.rglob("*.py")) and not (root / ".venv").exists()
    assert (root / "data/admin_token").stat().st_mode & 0o777 == 0o600
    if source is not None:
        (root / "policy.toml").write_text(source)
    socket_parent = os.environ.get("SAFEYOLO_TEST_SOCKET_DIR")
    with tempfile.TemporaryDirectory(prefix="sy-native-", dir=socket_parent) as sockets:
        paths = {name: str(Path(sockets) / f"{name}.sock") for name in ("alice", "bob")}
        configuration = f'admin_port = 0\nflow_store_enabled = false\nagent_api_enabled = {str(services).lower()}\n'
        if parent_proxy:
            configuration += f'parent_proxy = {json.dumps(parent_proxy)}\n'
        if services:
            (root / "builtin-services").mkdir()
            (root / "services").mkdir()
            agent_token = root / "data/agent_token"
            agent_token.touch(mode=0o600)
            agent_token.write_text(AGENT_TOKEN)
            configuration += 'gateway_builtin_services_dir = "builtin-services"\ngateway_services_dir = "services"\n'
        for name, path in paths.items():
            configuration += f'[[listeners]]\nagent_id = "{name}"\nsocket_path = {json.dumps(path)}\n'
        (root / "config.toml").write_text(configuration)
        environment = dict(os.environ, PATH=str(root / "bin"), SAFEYOLO_HOME=str(root),
                           SAFEYOLO_DATA_DIR=str(root / "data"))
        # Retain proxy and CA variables. This fixture needs no installed host
        # identity, extra events listener, Python launcher or external parent.
        for key in ("PYTHONPATH", "SAFEYOLO_CLI_PYTHON", "SAFEYOLO_OPERATOR_INSTANCE_ID_FILE",
                    "SAFEYOLO_COMMAND_CENTRE_EVENTS_PORT", "SAFEYOLO_COMMAND_CENTRE_TAILNET_ADMIN_PORT",
                    "SAFEYOLO_COMMAND_CENTRE_TAILNET_EVENTS_PORT", "SAFEYOLO_UPSTREAM_PROXY"):
            environment.pop(key, None)
        try:
            with child_process(
                [str(root / "bin/safeyolo-proxy"), "--config", str(root / "config.toml")], root, environment,
            ) as process:
                readiness = root / "data/ready.json"
                wait_ready(process, [readiness, *map(Path, paths.values())], root / "process.log",
                           readiness_file=readiness, expected_backend="rust-m2")
                yield NativeInstance(root, process, paths, environment)
        finally:
            # The existing process fixture has stopped the proxy. Retain small
            # diagnostics, but do not accumulate copied debug binaries per case.
            for binary in ("safeyolo", "safeyolo-proxy"):
                (root / "bin" / binary).unlink(missing_ok=True)


def scoped_policy(port):
    return DENY + f'\n[agents.alice.hosts]\n"127.0.0.1:{port}" = {{egress="allow"}}\n'


def controls(instance, origin, other):
    before = origin.accepts
    target = f"http://127.0.0.1:{origin.server_address[1]}/native-policy-control"
    status, _, body = request(instance.paths["alice"], target)
    assert (status, body) == (200, b"hello")
    status, _, body = request(instance.paths["bob"], target)
    assert status == 403, body
    status, _, body = request(instance.paths["alice"], f"http://127.0.0.1:{other.server_address[1]}/denied-port")
    assert status == 403, body
    assert origin.accepts == before + 1
    assert other.accepts == 0


def test_installed_check_show_apply_and_scoped_enforcement(tmp_path):
    with origin_server() as origin, origin_server() as other, native_instance(tmp_path, source=None) as instance:
        source = scoped_policy(origin.server_address[1])
        candidate = tmp_path / "candidate"
        candidate.write_text(source)
        saved = instance.policy.read_bytes()
        quotas = instance.admin("GET", "/admin/budgets")
        checked = instance.cli("policy", "check", str(candidate))
        assert checked.returncode == 0, checked.stderr
        assert instance.cli("policy", "check", str(instance.policy)).returncode == 0
        before = instance.show()
        assert before["status"] == "active"
        assert before["effective"]["hosts"]["*"]["egress"] == "allow"
        assert before["effective"]["hosts"]["*"]["unknown_creds"] == "prompt"
        assert before["sources"]["controls.network.action"] == "default"
        assert instance.policy.read_bytes() == saved
        assert instance.admin("GET", "/admin/budgets") == quotas
        instance.apply(source)
        shown = instance.show()
        assert shown["status"] == "active" and shown["saved_matches_active"]
        assert shown["effective"]["agents"]["alice"]["hosts"][f"127.0.0.1:{origin.server_address[1]}"]["egress"] == "allow"
        # Replaced mode APIs cannot become a second owner or disable the
        # active denied control behind the new policy show response.
        for path in ("/modes", "/plugins/network-guard/mode"):
            instance.admin("PUT", path, {"mode": "warn"}, expected_status=404)
        assert instance.show()["effective"] == shown["effective"]
        controls(instance, origin, other)
        # Reads after real requests also preserve the spent counters and file.
        quotas = instance.admin("GET", "/admin/budgets")
        engine = instance.admin("GET", "/stats")["policy-engine"]["engine_stats"]
        saved = instance.policy.read_bytes()
        assert instance.cli("policy", "check", str(instance.policy)).returncode == 0
        instance.show()
        assert instance.policy.read_bytes() == saved
        assert instance.admin("GET", "/stats")["policy-engine"]["engine_stats"] == engine
        after = instance.admin("GET", "/admin/budgets")
        assert after["tracked_keys"] == quotas["tracked_keys"]
        assert after["budgets"].keys() == quotas["budgets"].keys()
        for key, before in quotas["budgets"].items():
            assert after["budgets"][key]["budget_per_minute"] == before["budget_per_minute"]
            # Availability can refill with the real clock; reads must not
            # charge another evaluation or reduce the available quota.
            assert after["budgets"][key]["remaining"] >= before["remaining"]


def test_installed_credential_approval_keeps_destination_scope(tmp_path):
    policy = '''budget = 12000
[hosts]
"*" = {egress="allow", unknown_creds="prompt"}
[credential.synthetic]
match = ["key-native"]
headers = ["authorization"]
'''
    with origin_server(capture_heads=True) as origin, origin_server() as other, native_instance(tmp_path) as instance:
        instance.apply(policy)
        port = origin.server_address[1]
        target = f"http://127.0.0.1:{port}/native-credential"
        status, _, body = request(instance.paths["alice"], target)
        assert (status, body) == (200, b"hello")
        headers = {"Authorization": "Bearer key-native"}
        status, response_headers, body = request(instance.paths["alice"], target, headers=headers)
        assert status == 428, body
        assert origin.accepts == 1
        request_id = next(value for name, value in response_headers.items() if name.lower() == "x-safeyolo-request-id")
        pending = instance.admin("GET", "/admin/approvals")
        events = pending["approvals"]
        event = next(row for row in events if row.get("request_id") == request_id)
        fingerprint = event["approval"]["key"]
        assert fingerprint.startswith("hmac:")
        assert "key-native" not in json.dumps(event)
        instance.admin("POST", "/admin/policy/baseline/approve", {"destination": "127.0.0.1", "cred_id": fingerprint})
        deadline = time.monotonic() + 4
        while True:
            shown = instance.show()
            if shown["saved_matches_active"] and fingerprint in shown["effective"].get("hosts", {}).get("127.0.0.1", {}).get("allow", []):
                break
            assert time.monotonic() < deadline, shown
            time.sleep(0.02)
        assert shown["effective"]["hosts"]["127.0.0.1"]["allow"] == [fingerprint]
        status, _, body = request(instance.paths["alice"], target, headers=headers)
        assert (status, body) == (200, b"hello")
        assert origin.accepts == 2
        status, _, body = request(instance.paths["alice"], f"http://localhost:{other.server_address[1]}/other-destination", headers=headers)
        assert status == 428, body
        assert other.accepts == 0
        status, _, body = request(instance.paths["alice"], f"http://localhost:{other.server_address[1]}/nonsecret")
        assert (status, body) == (200, b"hello")


def test_rejected_apply_preserves_allowed_denied_saved_live_and_recovers(tmp_path):
    with origin_server() as origin, origin_server() as other, native_instance(tmp_path) as instance:
        source = scoped_policy(origin.server_address[1])
        instance.apply(source)
        active = instance.show()["effective"]
        saved = instance.policy.read_bytes()
        pid = instance.process.pid
        for rejected in ('[hosts\n', source.replace('egress="allow"', 'egress="invalid"')):
            instance.apply(rejected, valid=False)
            controls(instance, origin, other)
            assert instance.policy.read_bytes() == saved
            shown = instance.show()
            assert shown["effective"] == active and shown["saved_matches_active"]
        instance.root.chmod(0o500)
        try:
            failed = instance.apply(DENY, valid=False)
            assert "Permission denied" in failed.stderr
            controls(instance, origin, other)
            assert instance.policy.read_bytes() == saved
            assert instance.show()["effective"] == active
        finally:
            instance.root.chmod(0o700)
        # The policy compiler accepts the string model. The reached native
        # detector cannot compile a surrogate regex, selecting real activation
        # failure after the durable write, without a production fault switch.
        failed = instance.apply(DENY + "\n[credential.activation_failure]\nmatch = ['\\uD800']\n", valid=False)
        assert "activation failed" in failed.stderr
        controls(instance, origin, other)
        assert instance.policy.read_bytes() == saved
        shown = instance.show()
        assert shown["effective"] == active and shown["saved_matches_active"]
        instance.policy.write_text('[hosts\n')
        shown = instance.show()
        assert shown["status"] == "saved_differs" and not shown["saved_matches_active"]
        assert shown["effective"] == active and "policy apply" in shown["repair"]
        controls(instance, origin, other)
        # Whole replacement repairs the invalid saved candidate in the same
        # process; it does not depend on parsing that rejected document.
        instance.apply(source + '\n[controls.network]\naction = "block"\n')
        shown = instance.show()
        assert shown["status"] == "active"
        assert shown["sources"]["controls.network.action"] == str(instance.policy)
        assert instance.process.pid == pid and instance.process.poll() is None
        controls(instance, origin, other)


def test_apply_with_service_store_uses_existing_transaction_without_deadlock(tmp_path):
    with origin_server() as origin, origin_server() as other, native_instance(tmp_path, services=True) as instance:
        instance.apply(scoped_policy(origin.server_address[1]))
        controls(instance, origin, other)
        assert instance.show()["saved_matches_active"]
        (instance.root / "services/extra.yaml").write_text(json.dumps({
            "schema_version": 1, "name": "extra", "description": "Owned catalogue update",
            "capabilities": {"inspect": {"description": "Metadata only", "routes": []}},
        }))
        deadline = time.monotonic() + 4
        while True:
            # Observe the maintained catalogue check, then verify its policy
            # publication retains the fresh authoring and installed commands.
            status, _, body = request(
                instance.paths["alice"], "http://_safeyolo.proxy.internal/gateway/services?agent=alice",
                headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
            )
            assert status == 200, body
            catalogue = json.loads(body)
            if any(service["name"] == "extra" for service in catalogue["available"]):
                break
            assert time.monotonic() < deadline, catalogue
            time.sleep(0.02)
        instance.apply(scoped_policy(origin.server_address[1]))
        controls(instance, origin, other)
        assert instance.show()["saved_matches_active"]


def test_apply_keeps_checked_list_file_scope_when_saved_under_another_root(tmp_path):
    with origin_server() as origin, native_instance(
        tmp_path, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        (tmp_path / "targets.txt").write_text("chosen.example\n")
        # A shadowed list at the saved policy's directory must not change the
        # scope of FILE that the operator checked and applied.
        (instance.root / "targets.txt").write_text("shadowed.example\n")
        source = DENY + '\n[lists]\nselected="targets.txt"\n[hosts."$selected"]\negress="allow"\n'
        instance.apply(source)
        shown = instance.show()
        assert shown["effective"]["lists"]["selected"] == str(tmp_path / "targets.txt")
        # The owned parent answers allowed requests; no external DNS or origin
        # is needed to observe the distinct authored host scopes.
        assert request(instance.paths["alice"], "http://chosen.example/chosen")[0] == 200
        assert request(instance.paths["alice"], "http://shadowed.example/shadowed")[0] == 403
        assert origin.accepts == 1


@pytest.mark.parametrize("old_field", ['[addons.network_guard]\nenabled = false', 'required = ["network_guard"]'])
def test_native_check_rejects_replaced_policy_fields(tmp_path, old_field):
    with native_instance(tmp_path) as instance:
        candidate = tmp_path / "old.toml"
        candidate.write_text(old_field)
        result = instance.cli("policy", "check", str(candidate))
        assert result.returncode != 0
        assert "unsupported field" in result.stderr
