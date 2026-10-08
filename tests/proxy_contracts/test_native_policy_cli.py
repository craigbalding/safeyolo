"""#816 uses installed native commands, two trusted listeners and owned origins.

Only this test driver uses Python. Commands execute from outside the checkout,
with a PATH containing only the installed native binaries. Existing fixture
deadlines are 15 seconds for readiness, 5 for HTTP and 4 for watcher publication.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
import tomlkit

from tests.proxy_contracts.harness import ReadinessError, child_process, read_events, request, wait_ready
from tests.proxy_contracts.scenarios import origin_server

REPO = Path(__file__).resolve().parents[2]
DENY = 'budget = 12000\n[hosts]\n"*" = {egress="deny", unknown_creds="prompt"}\n'
AGENT_TOKEN = "synthetic-native-policy-fixture-agent-token"
HOST_BINARIES = ("safeyolo", "safeyolo-coord", "safeyolo-proxy")
GUEST_BINARIES = ("safeyolo-guest", "safeyolo-coord")
pytestmark = pytest.mark.skipif(
    os.uname().sysname != "Linux", reason="#816 selects Ubuntu; host/platform suites have separate owners",
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

    def agent_api(self, agent, path, *, method="GET", body=None, status=200):
        result, _, raw = request(self.paths[agent], "http://_safeyolo.proxy.internal" + path,
                                method=method, body=json.dumps(body).encode() if body else b"",
                                headers={"Authorization": f"Bearer {AGENT_TOKEN}"})
        assert result == status, (result, raw)
        return json.loads(raw)

    def context(self, operation, agent="alice", *arguments):
        result = self.cli("test-context", operation, "--socket", self.paths[agent],
                          "--token-file", str(self.root / "data/agent_token"), *arguments)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)


@contextmanager
def native_instance(directory, source=DENY, *, services=False, parent_proxy=None, agent_api=False,
                    capture=False, extra_config=""):
    artifacts = Path(os.environ.get("SAFEYOLO_NATIVE_ARTIFACTS", str(REPO / "proxy/target/debug")))
    root = directory / "installed"
    try:
        bundle = os.environ.get("SAFEYOLO_NATIVE_BUNDLE")
        inputs = ["--bundle", bundle] if bundle else [
            "--artifacts", str(artifacts),
            "--guest-artifacts", os.environ.get("SAFEYOLO_GUEST_ARTIFACTS", str(REPO / "guest/command/target/debug")),
            "--runtime-artifacts", str(Path(shutil.which("tmux")).parent), "--profile", "debug",
        ]
        installation = subprocess.run(
            [str(REPO / "scripts/install_native.sh"), "--root", str(root), *inputs],
            capture_output=True, text=True, timeout=15,
        )
        assert installation.returncode == 0, installation.stderr
        assert "commit=" in installation.stdout and "profile=" in installation.stdout
        assert set(HOST_BINARIES).issubset(path.name for path in (root / "bin").iterdir())
        assert (root / "bin/tmux").is_file() and not (root / ".venv").exists()
        assert (root / "bin/watch-backlog-factory").stat().st_mode & 0o111
        assert (root / "data/admin_token").stat().st_mode & 0o777 == 0o600
        assert (root / "data/agent_token").stat().st_mode & 0o777 == 0o600
        if source is not None:
            (root / "policy.toml").write_text(source)
        socket_parent = os.environ.get("SAFEYOLO_TEST_SOCKET_DIR")
        with tempfile.TemporaryDirectory(prefix="sy-native-", dir=socket_parent) as sockets:
            paths = {name: str(Path(sockets) / f"{name}.sock") for name in ("alice", "bob")}
            configuration = (f'admin_port = 0\nflow_store_enabled = {str(capture).lower()}\n'
                             f'agent_api_enabled = {str(services or agent_api).lower()}\n')
            if parent_proxy:
                configuration += f'parent_proxy = {json.dumps(parent_proxy)}\n'
            if services:
                (root / "builtin-services").mkdir(exist_ok=True)
                (root / "services").mkdir(exist_ok=True)
                configuration += 'gateway_builtin_services_dir = "builtin-services"\ngateway_services_dir = "services"\n'
            if services or agent_api:
                agent_token = root / "data/agent_token"
                agent_token.touch(mode=0o600)
                agent_token.write_text(AGENT_TOKEN)
            configuration += extra_config
            for index, (name, path) in enumerate(paths.items(), 2):
                configuration += (f'[[listeners]]\nagent_id = "{name}"\nsocket_path = {json.dumps(path)}\n'
                                  f'source_id = "10.0.0.{index}"\n')
            (root / "config.toml").write_text(configuration)
            environment = dict(os.environ, PATH=str(root / "bin"), SAFEYOLO_HOME=str(root),
                               SAFEYOLO_CONFIG_DIR=str(root),
                               SAFEYOLO_NATIVE_CONFIG_PATH=str(root / "config.toml"),
                               SAFEYOLO_NATIVE_WORKING_DIRECTORY=str(root),
                               SAFEYOLO_DATA_DIR=str(root / "unused-legacy-data"))
            # Retain proxy and CA variables. This fixture needs no installed host
            # identity, extra events listener, Python launcher or external parent.
            for key in ("PYTHONPATH", "SAFEYOLO_CLI_PYTHON", "SAFEYOLO_OPERATOR_INSTANCE_ID_FILE",
                        "SAFEYOLO_COMMAND_CENTRE_EVENTS_PORT", "SAFEYOLO_COMMAND_CENTRE_TAILNET_ADMIN_PORT",
                        "SAFEYOLO_COMMAND_CENTRE_TAILNET_EVENTS_PORT", "SAFEYOLO_UPSTREAM_PROXY"):
                environment.pop(key, None)
            with child_process(
                [str(root / "bin/safeyolo-proxy"), "--config", str(root / "config.toml")], root, environment,
            ) as process:
                readiness = root / "data/ready.json"
                wait_ready(process, [readiness, *map(Path, paths.values())], root / "process.log",
                           readiness_file=readiness, expected_backend="rust-m2")
                yield NativeInstance(root, process, paths, environment)
    finally:
        # The process fixture stops the proxy before these owned copies are
        # removed. Cover installation/startup failures too; retain diagnostics
        # and artifact identity sidecars, not repeated executable copies.
        for binary in (*HOST_BINARIES, "tmux", "watch-backlog-factory"):
            (root / "bin" / binary).unlink(missing_ok=True)
        (root / "libexec/tmux").unlink(missing_ok=True)
        for binary in GUEST_BINARIES:
            (root / "assets/guest" / binary).unlink(missing_ok=True)


def scoped_policy(port):
    return DENY + f'\n[agents.alice.hosts]\n"127.0.0.1:{port}" = {{egress="allow"}}\n'


def test_installed_stop_cleanup_accepts_inactive_native_process_record(tmp_path):
    from tests.blackbox.installed_sections import cleanup_instance

    with native_instance(tmp_path) as instance:
        record = instance.root / "data/proxy-process.json"
        # Proxy readiness precedes the host identity receipt. Reuse the
        # fixture's fifteen-second readiness deadline for that publication.
        deadline = time.monotonic() + 15
        while not record.is_file():
            assert instance.process.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert json.loads(record.read_text())["pid"] == instance.process.pid
        failures = cleanup_instance(instance.root / "bin/safeyolo", instance.root)
        assert instance.process.wait(timeout=10) == 0
        assert failures == []
        assert record.is_file()


@contextmanager
def restarted_proxy(instance):
    original_pid = instance.process.pid
    stopped = instance.cli("stop")
    assert stopped.returncode == 0, stopped.stderr
    instance.process.wait(timeout=10)
    started = instance.cli("start")
    assert started.returncode == 0, started.stderr
    try:
        ready = json.loads((instance.root / "data/ready.json").read_text())
        assert ready["ready"] and ready["pid"] != original_pid
        instance.port = ready["admin_port"]
        yield instance
    finally:
        stopped = instance.cli("stop")
        assert stopped.returncode == 0, stopped.stderr


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
        engine = instance.admin("GET", "/stats")["policy"]["engine_stats"]
        saved = instance.policy.read_bytes()
        assert instance.cli("policy", "check", str(instance.policy)).returncode == 0
        instance.show()
        assert instance.policy.read_bytes() == saved
        assert instance.admin("GET", "/stats")["policy"]["engine_stats"] == engine
        after = instance.admin("GET", "/admin/budgets")
        assert after["tracked_keys"] == quotas["tracked_keys"]
        assert after["budgets"].keys() == quotas["budgets"].keys()
        for key, before in quotas["budgets"].items():
            assert after["budgets"][key]["budget_per_minute"] == before["budget_per_minute"]
            # Availability can refill with the real clock; reads must not
            # charge another evaluation or reduce the available quota.
            assert after["budgets"][key]["remaining"] >= before["remaining"]

    assert instance.process.poll() is not None
    assert not list((instance.root / "bin").iterdir())
    for binary in GUEST_BINARIES:
        assert not (instance.root / "assets/guest" / binary).exists()


def test_installed_lab_stages_skills_without_the_optional_python_checker(tmp_path):
    artifacts = Path(os.environ.get("SAFEYOLO_NATIVE_ARTIFACTS", str(REPO / "proxy/target/debug")))
    guest_artifacts = Path(os.environ.get("SAFEYOLO_GUEST_ARTIFACTS", str(REPO / "guest/command/target/debug")))
    with native_instance(tmp_path) as instance:
        skill = instance.root / "assets/skills/safeyolo"
        instructions = (skill / "SKILL.md").read_bytes()
        assert b"github-checks.md" not in instructions
        assert not (skill / "references/github-checks.md").exists()
        assert (skill / "references/coord.md").is_file()
        assert (skill / "references/guest-tools.md").is_file()

    # The fixture has stopped the proxy and removed its binary copies. Reuse
    # its installed skills with the real CLI and checked Coord input. Missing
    # host binaries stop startup after Lab staging, without allocating a guest
    # or copying the two large inner inputs merely to check skill propagation.
    coord = instance.root / "assets/guest/safeyolo-coord"
    home = instance.root / "agents/lab-staging/home"
    os.link(guest_artifacts / "safeyolo-coord", coord)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        result = subprocess.run(
            [str(artifacts / "safeyolo"), "--root", str(instance.root), "lab", "--agent", "lab-staging",
             "--workspace", str(workspace), "--objective", "inspect installed Lab assets", "--yes"],
            cwd=tmp_path, env=instance.environment, capture_output=True, text=True, timeout=15,
        )
        assert result.returncode != 0
        staged = instance.root / "agents/lab-staging/config-share/skills"
        assert (staged / "safeyolo/SKILL.md").read_bytes() == instructions
        assert not list(staged.rglob("*.py"))
        assert not (staged / "safeyolo/references/github-checks.md").exists()
        assert (staged / "safeyolo-lab-controller/scripts/safeyolo-lab").is_file()
        assert (home / ".agents/skills/safeyolo").readlink() == Path("/safeyolo/skills/safeyolo")
    finally:
        coord.unlink()
        (home / ".safeyolo/safeyolo-coord").unlink(missing_ok=True)


def test_installed_fixture_removes_executables_after_startup_failure(tmp_path):
    with pytest.raises(ReadinessError, match="Proxy process exited"):
        with native_instance(tmp_path, extra_config="\n[invalid\n"):
            pytest.fail("Invalid configuration must not start a proxy")
    root = tmp_path / "installed"
    assert not list((root / "bin").iterdir())
    for binary in GUEST_BINARIES:
        assert not (root / "assets/guest" / binary).exists()
        assert (root / "assets/guest" / f"{binary}.version").is_file()
    assert (root / "process.log").is_file()
    assert (root / "data/admin_token").stat().st_mode & 0o777 == 0o600
    assert (root / "data/agent_token").stat().st_mode & 0o777 == 0o600


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


@pytest.mark.parametrize("services", [False, True])
@pytest.mark.parametrize("saved_egress", ["allow", "deny"])
def test_failed_activation_retains_live_generation_when_saved_policy_differs(tmp_path, services, saved_egress):
    with origin_server() as origin, origin_server() as other, native_instance(tmp_path, services=services) as instance:
        source = scoped_policy(origin.server_address[1])
        instance.apply(source)
        active = instance.show()["effective"]
        pid = instance.process.pid
        # Select a saved/live mismatch without asking the existing mtime
        # watcher to activate the external candidate before the failed apply.
        saved_list = tmp_path / "saved-targets.txt"
        saved_list.write_text("saved.example\n")
        saved = (
            DENY.replace('egress="deny"', f'egress="{saved_egress}"')
            + f'\n[lists]\nsaved = {json.dumps(str(saved_list))}\n'
            + '[hosts."$saved"]\negress = "allow"\n'
        )
        metadata = instance.policy.stat()
        instance.policy.write_text(saved)
        os.utime(instance.policy, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        assert instance.show()["status"] == "saved_differs"
        checked = instance.cli("policy", "check", str(instance.policy))
        assert checked.returncode == 0, checked.stderr
        controls(instance, origin, other)
        failed = instance.apply(DENY + "\n[credential.activation_failure]\nmatch = ['\\uD800']\n", valid=False)
        assert "activation failed" in failed.stderr
        assert instance.policy.read_text() == saved
        controls(instance, origin, other)
        # The maintained watcher checks every two seconds. Observe through
        # the existing four-second publication deadline so its next check
        # cannot silently activate the restored, previously inactive bytes.
        deadline = time.monotonic() + 4
        while True:
            shown = instance.show()
            assert shown["status"] == "saved_differs" and not shown["saved_matches_active"]
            assert shown["effective"] == active and "policy apply" in shown["repair"]
            if time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        controls(instance, origin, other)
        instance.apply(source)
        assert instance.show()["status"] == "active"
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
        assert shown["effective"]["lists"]["selected"] == ["chosen.example"]
        assert shown["sources"]["lists.selected"] == str(tmp_path / "targets.txt")
        # The owned parent answers allowed requests; no external DNS or origin
        # is needed to observe the distinct authored host scopes.
        assert request(instance.paths["alice"], "http://chosen.example/chosen")[0] == 200
        assert request(instance.paths["alice"], "http://shadowed.example/shadowed")[0] == 403
        assert origin.accepts == 1


def test_show_distinguishes_saved_list_inputs_from_active_compiled_scope(tmp_path):
    with origin_server() as origin, native_instance(
        tmp_path, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        targets = tmp_path / "targets.txt"
        targets.write_text("chosen.example\n")
        source = DENY + '\n[lists]\nselected="targets.txt"\n[hosts."$selected"]\negress="allow"\n'
        instance.apply(source)
        saved_policy = instance.policy.read_bytes()
        pid = instance.process.pid
        assert request(instance.paths["alice"], "http://chosen.example/chosen")[0] == 200
        assert request(instance.paths["alice"], "http://replacement.example/denied")[0] == 403
        metadata = targets.stat()
        for content, expected_status in (("replacement.example\n", "saved_differs"),
                                         ("replacement.example:70000\n", "saved_differs"),
                                         (None, "saved_unreadable")):
            if content is None:
                targets.unlink()
            else:
                targets.write_text(content)
                os.utime(targets, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
            checked = instance.cli("policy", "check", str(instance.policy))
            assert (checked.returncode == 0) == (content == "replacement.example\n"), checked.stderr
            shown = instance.show()
            assert shown["status"] == expected_status and not shown["saved_matches_active"]
            assert shown["effective"]["lists"]["selected"] == ["chosen.example"]
            assert shown["sources"]["lists.selected"] == str(targets)
            assert shown["list_files"]["selected"]["status"] == expected_status
            assert "policy apply" in shown["repair"]
            assert instance.policy.read_bytes() == saved_policy
            accepted = origin.accepts
            assert request(instance.paths["alice"], "http://chosen.example/still-active")[0] == 200
            assert request(instance.paths["alice"], "http://replacement.example/still-denied")[0] == 403
            assert origin.accepts == accepted + 1
        targets.write_text("replacement.example\n")
        instance.apply(source)
        shown = instance.show()
        assert shown["status"] == "active" and shown["saved_matches_active"]
        assert shown["effective"]["lists"]["selected"] == ["replacement.example"]
        assert request(instance.paths["alice"], "http://chosen.example/now-denied")[0] == 403
        assert request(instance.paths["alice"], "http://replacement.example/now-active")[0] == 200
        assert instance.process.pid == pid and instance.process.poll() is None


@pytest.mark.parametrize("old_field", ['[addons.network_guard]\nenabled = false', 'required = ["network_guard"]'])
def test_native_check_rejects_replaced_policy_fields(tmp_path, old_field):
    with native_instance(tmp_path) as instance:
        candidate = tmp_path / "old.toml"
        candidate.write_text(old_field)
        result = instance.cli("policy", "check", str(candidate))
        assert result.returncode != 0
        assert "unsupported field" in result.stderr


def test_installed_config_help_and_named_diagnostics(tmp_path):
    with native_instance(tmp_path, agent_api=True) as instance:
        for arguments in (("--help",), ("test-context", "--help")):
            result = instance.cli(*arguments)
            assert result.returncode == 0 and "trusted listener" in result.stdout
            assert "addon" not in result.stdout.lower()
        checked = instance.cli("config", "check", str(instance.root / "config.toml"))
        assert checked.returncode == 0 and "Configuration is valid" in checked.stdout
        candidate = tmp_path / "invalid-config.toml"
        candidate.write_text("[addons.network_guard]\nenabled=false\n")
        rejected = instance.cli("config", "check", str(candidate))
        assert rejected.returncode != 0 and "unsupported field 'addons'" in rejected.stderr
        # Broken old inputs cannot become native policy/configuration sources.
        (instance.root / "addons.yaml").mkdir()
        (instance.root / "config.yaml").write_text("broken: [")
        instance.apply(DENY + '\n[agents.bob]\nfolder="private-operator-path"\n')
        assert instance.show()["saved_matches_active"]
        stats = instance.admin("GET", "/stats")
        assert {"network", "credentials", "circuits", "test_context", "capture", "audit", "policy"} <= stats.keys()
        assert "network-guard" not in stats and "credential-guard" not in stats
        sensor = instance.agent_api("alice", "/config")
        assert set(sensor) == {"credential_rules", "scan_patterns", "policy_hash", "controls", "logging"}
        assert "private-operator-path" not in json.dumps(sensor)
        assert instance.show()["effective"]["agents"]["bob"]["folder"] == "private-operator-path"


def test_native_listener_update_preserves_other_toml_settings():
    # Exercise the changed writer through its real Admin/reload call path. The
    # fake runsc only reports/stops fixture state; this is no guest lifecycle proof.
    with socket.socket() as port:
        port.bind(("127.0.0.1", 0))
        events_port = port.getsockname()[1]
    source = DENY + '\n[agents.alice]\nagent_id="ag-11111111111111111111111111111111"\n'
    extra = (f'\n[command_centre]\nenabled=true\nevents_port={events_port}\n'
             '[capture]\nmax_request_body_bytes=9\nqueue_max=7\n[trace]\nttl_s=12\n')
    with tempfile.TemporaryDirectory(prefix="sy-listeners-", dir=Path.home()) as directory, native_instance(
        Path(directory), source, extra_config=extra,
    ) as instance:
        runner = instance.root / "bin/runsc"
        runner.write_text('''#!/bin/sh
case "$3" in
state) [ ! -e "$SAFEYOLO_CONFIG_DIR/stopped" ] || exit 1
       printf '{"status":"running"}\\n' ;;
kill) : > "$SAFEYOLO_CONFIG_DIR/stopped" ;;
delete) ;;
*) exit 2 ;;
esac
''')
        runner.chmod(0o755)
        (instance.root / "data/agent_map.json").write_text(json.dumps({
            "alice": {"ip": "10.0.0.2"}, "bob": {"ip": "10.0.0.3"},
        }))
        (instance.root / "data/sockets/10.0.0.3_bob").mkdir(parents=True)
        stopped = instance.admin("POST", "/admin/agents/ag-11111111111111111111111111111111/stop")
        assert stopped["sandbox_state"] == "stopped"
        saved = tomllib.loads((instance.root / "config.toml").read_text())
        assert saved["capture"] == {"max_request_body_bytes": 9, "queue_max": 7}
        assert saved["trace"] == {"ttl_s": 12}
        assert saved["command_centre"]["events_port"] == events_port
        assert json.loads((instance.root / "data/ready.json").read_text())["reload_id"] == saved["reload_id"]
        # Custom ingress remains intact; the other host-owned slot is added.
        assert {entry["socket_path"] for entry in saved["listeners"]} == {
            *instance.paths.values(), str(instance.root / "data/sockets/10.0.0.3_bob/proxy.sock"),
        }
        assert instance.cli("config", "check", str(instance.root / "config.toml")).returncode == 0


def delivered(instance, origin, host, *, status=200, agent="alice", path="/native-table", method="GET", headers=None,
              pending=False):
    before = origin.accepts
    result, reply_headers, body = request(instance.paths[agent], f"http://{host}{path}", method=method,
                                          headers=headers)
    assert result == status, (host, result, body)
    if status == 200:
        assert body == b"hello"
    assert origin.accepts == before + int(status == 200)
    if pending:
        identifier = next(value for name, value in reply_headers.items()
                          if name.lower() == "x-safeyolo-request-id")
        pending = instance.admin("GET", "/admin/approvals")["approvals"]
        assert any(row.get("request_id") == identifier and row["agent"] == agent for row in pending), pending
    return reply_headers


@pytest.mark.parametrize("effect,status", [("allow", 200), ("prompt", 428), ("deny", 403)])
def test_installed_unlisted_destination_effects(tmp_path, effect, status):
    with origin_server() as origin, native_instance(
        tmp_path, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        instance.apply(f'[hosts]\n"*" = {{egress="{effect}"}}\n')
        delivered(instance, origin, "unlisted.invalid:8123", status=status, pending=effect == "prompt")


@pytest.mark.parametrize("global_effect,agent_effect,status", [("deny", "allow", 200), ("allow", "deny", 403)])
def test_installed_agent_override_precedence(tmp_path, global_effect, agent_effect, status):
    source = f'[hosts]\n"*" = {{egress="{global_effect}"}}\n[agents.alice]\negress="{agent_effect}"\n'
    with origin_server() as origin, native_instance(
        tmp_path, source, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        saved = instance.policy.read_bytes()
        checked = instance.cli("policy", "check", str(instance.policy))
        assert checked.returncode == 0, checked.stderr
        assert instance.policy.read_bytes() == saved
        instance.apply(source)
        saved = instance.policy.read_bytes()
        assert tomllib.loads(saved.decode())["agents"]["alice"] == {"egress": agent_effect}
        delivered(instance, origin, "override.invalid:8123", status=status)
        delivered(instance, origin, "override.invalid:8123", agent="bob", status=403 if status == 200 else 200)
        with restarted_proxy(instance):
            assert instance.policy.read_bytes() == saved
            assert instance.show()["saved_matches_active"]
            assert json.loads(instance.cli("doctor").stdout)["agents"] == []
            delivered(instance, origin, "override.invalid:8123", status=status)
            delivered(instance, origin, "override.invalid:8123", agent="bob", status=403 if status == 200 else 200)
            assert instance.policy.read_bytes() == saved
        assert not any(Path(path).exists() for path in instance.paths.values())


def test_installed_policy_overrides_coexist_with_degraded_host_identity_and_attachment():
    with tempfile.TemporaryDirectory(prefix="sy-host-", dir=Path.home()) as directory, origin_server() as origin, native_instance(
        Path(directory), parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        created = instance.cli("agent", "create", "marker", "--workspace", directory)
        assert created.returncode == 0, created.stderr
        agent_id = json.loads(created.stdout)["configuration"]["id"]
        policy = tomlkit.parse(instance.policy.read_text())
        policy["agents"]["alice"] = {"egress": "allow"}
        source = tomlkit.dumps(policy)
        candidate = Path(directory) / "coexisting-policy.toml"
        candidate.write_text(source)
        checked = instance.cli("policy", "check", str(candidate))
        assert checked.returncode == 0, checked.stderr
        instance.apply(source)
        saved = instance.policy.read_bytes()
        assert tomllib.loads(saved.decode())["agents"]["alice"] == {"egress": "allow"}
        run_id = "0123456789abcdef0123456789abcdef"
        # Reuse the sentry-shaped host-process control. Birth/run/argv identify
        # the retained record; host namespaces must still deny stop authority.
        backend = subprocess.Popen(
            ["runsc-sandbox", "-c", "read line", f"--root={instance.root / 'run'}", "boot", f"safeyolo-{run_id}"],
            executable="/bin/sh", stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            birth = Path(f"/proc/{backend.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            agent = instance.root / "agents/marker"
            (agent / "config-share").mkdir(parents=True, exist_ok=True)
            runtime = json.dumps({"agent_id": agent_id, "run_id": run_id, "state": "running", "ip": "10.200.0.8",
                                  "backend_pid": backend.pid, "backend_token": f"linux:{boot}:{backend.pid}:{birth}"}).encode()
            context = json.dumps({"agent_id": agent_id, "generation": run_id, "ip": "10.200.0.8"}).encode()
            (agent / "runtime.json").write_bytes(runtime)
            (agent / "config-share/host-launch-context.json").write_bytes(context)
            # Startup must rebuild a corrupt derived map through the same host
            # enumeration, while keeping Alice/Bob's explicit listeners.
            (instance.root / "data/agent_map.json").write_text("corrupt")
            explicit = tomllib.loads((instance.root / "config.toml").read_text())["listeners"]
            delivered(instance, origin, "override.invalid:8123", status=200)
            delivered(instance, origin, "override.invalid:8123", agent="bob", status=403)
            with restarted_proxy(instance):
                status = instance.cli("agent", "status", "marker")
                assert status.returncode == 0, status.stderr
                observed = json.loads(status.stdout)
                assert (observed["agent_id"], observed["run_id"], observed["runtime_state"]) == (agent_id, run_id, "degraded")
                assert observed["proxy_attachment"]["state"] == "ready"
                socket_path = instance.root / "data/sockets/10.200.0.8_marker/proxy.sock"
                assert socket_path.is_socket()
                instance.paths["marker"] = str(socket_path)
                listeners = tomllib.loads((instance.root / "config.toml").read_text())["listeners"]
                assert all(entry in listeners for entry in explicit)
                assert {"agent_id": "marker", "source_id": "10.200.0.8", "socket_path": str(socket_path)} in listeners
                assert json.loads((instance.root / "data/agent_map.json").read_text())["marker"]["ip"] == "10.200.0.8"
                delivered(instance, origin, "override.invalid:8123", status=200)
                delivered(instance, origin, "override.invalid:8123", agent="bob", status=403)
                delivered(instance, origin, "override.invalid:8123", agent="marker", status=403)
                refused = instance.cli("agent", "stop", "marker")
                assert refused.returncode != 0
                assert backend.poll() is None
                assert (agent / "runtime.json").read_bytes() == runtime
                assert (agent / "config-share/host-launch-context.json").read_bytes() == context
                assert instance.policy.read_bytes() == saved
            assert not socket_path.exists()
        finally:
            backend.terminate()
            backend.communicate(timeout=5)


@pytest.mark.parametrize("broad,narrow,status", [("deny", "allow", 200), ("allow", "deny", 403)])
def test_installed_exact_host_precedes_wildcard(tmp_path, broad, narrow, status):
    source = f'[hosts]\n"*.invalid"={{egress="{broad}"}}\n"exact.invalid"={{egress="{narrow}"}}\n'
    with origin_server() as origin, native_instance(
        tmp_path, source, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        delivered(instance, origin, "exact.invalid:8123", status=status)
        delivered(instance, origin, "neighbor.invalid:8123", status=403 if status == 200 else 200)


@pytest.mark.parametrize("bare,port_effect,status", [("deny", "allow", 200), ("allow", "deny", 403)])
def test_installed_port_precedence_and_other_port_fallthrough(tmp_path, bare, port_effect, status):
    source = f'[hosts]\n"ports.invalid"={{egress="{bare}"}}\n"ports.invalid:8123"={{egress="{port_effect}"}}\n'
    with origin_server() as origin, native_instance(
        tmp_path, source, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        delivered(instance, origin, "ports.invalid:8123", status=status)
        delivered(instance, origin, "ports.invalid:8124", status=403 if status == 200 else 200)


def test_installed_named_list_and_advanced_method_path(tmp_path):
    with origin_server() as origin, native_instance(
        tmp_path, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        (tmp_path / "named-hosts.txt").write_text("one.invalid\ntwo.invalid\n")
        instance.apply(DENY + '\n[lists]\nowned="named-hosts.txt"\n'
                       '[hosts."$owned"]\negress="allow"\n')
        for host, status in (("one.invalid", 200), ("two.invalid", 200), ("unlisted.invalid", 403)):
            delivered(instance, origin, f"{host}:8123", status=status)
        instance.apply('''[[permissions]]
action="network:request"
resource="advanced.invalid/*"
effect="allow"
condition={method="GET", path_prefix="/allowed/"}
[[permissions]]
action="network:request"
resource="*"
effect="deny"
''')
        delivered(instance, origin, "advanced.invalid:8123", path="/allowed/marker")
        delivered(instance, origin, "advanced.invalid:8123", method="POST", path="/allowed/marker", status=403)
        delivered(instance, origin, "advanced.invalid:8123", path="/wrong/marker", status=403)


@pytest.mark.parametrize("scope", ["host", "global"])
def test_installed_small_request_budget_scope(tmp_path, scope):
    source = ('budget=1\n[hosts]\n"*"={egress="allow"}\n' if scope == "global"
              else 'budget=12000\n[hosts]\n"*"={egress="allow"}\n"limited.invalid"={rate=1}\n')
    with origin_server() as origin, native_instance(
        tmp_path, source, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        started = time.monotonic()
        # The existing rate-one GCRA fixture admits exactly two initial hits.
        delivered(instance, origin, "limited.invalid:8123")
        delivered(instance, origin, "limited.invalid:8123", agent="bob")
        delivered(instance, origin, "limited.invalid:8123", status=429)
        delivered(instance, origin, "neighbor.invalid:8123", status=429 if scope == "global" else 200)
        assert time.monotonic() - started < 30, "rate-one fixture crossed its no-refill bound"


def test_installed_connect_budget_leaves_inner_request_budget_unspent(tmp_path):
    source = 'budget=1\n[hosts]\n"*"={egress="allow"}\n'
    with origin_server() as origin, native_instance(tmp_path, source) as instance:
        started = time.monotonic()
        # Use the maintained CONNECT fixture's exact two-admission rate-one burst.
        # An HTTP inner request uses the existing transport-owned tunnel path.
        authority = f"127.0.0.1:{origin.server_address[1]}"
        for index, expected in enumerate((200, 200, 429)):
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(5)
                stream.connect(instance.paths["alice"])
                stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                reply = http.client.HTTPResponse(stream)
                reply.begin()
                assert reply.status == expected
                reply.close()
                if index == 0:
                    quotas = instance.admin("GET", "/admin/budgets")["budgets"]
                    assert "network:connect:__global__" in quotas
                    assert "network:request:__global__" not in quotas
                    stream.sendall(f"GET /inner-accounting HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode())
                    inner = http.client.HTTPResponse(stream)
                    inner.begin()
                    assert inner.status == 200 and inner.read() == b"hello"
                    inner.close()
        quotas = instance.admin("GET", "/admin/budgets")["budgets"]
        assert {"network:connect:__global__", "network:request:__global__"} <= quotas.keys()
        assert origin.requests == [{"method": "GET", "target": "/inner-accounting"}]
        # CONNECT exhaustion does not spend the remaining ordinary HTTP admission.
        delivered(instance, origin, authority)
        delivered(instance, origin, authority, agent="bob", status=429)
        quotas = instance.admin("GET", "/admin/budgets")["budgets"]
        assert {"network:connect:__global__", "network:request:__global__"} <= quotas.keys()
        assert time.monotonic() - started < 30


def test_installed_scanner_block_warn_and_host_exception(tmp_path):
    source = '''[hosts]
"*"={egress="allow"}
[[scan_patterns]]
name="native-canary"
pattern="native-canary"
target="request"
scope=["url"]
action="block"
[controls.patterns]
request="block"
'''
    with origin_server() as origin, native_instance(
        tmp_path, source, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        delivered(instance, origin, "scanner.invalid:8123", path="/native-canary", status=403)
        instance.apply(source.replace('request="block"', 'request="warn"'))
        delivered(instance, origin, "scanner.invalid:8123", path="/native-canary")
        instance.apply(source + '\n[hosts."exempt.invalid"]\nexceptions=["patterns"]\n')
        delivered(instance, origin, "exempt.invalid:8123", path="/native-canary")
        delivered(instance, origin, "neighbor.invalid:8123", path="/native-canary", status=403)
        audits = read_events(instance.root / "logs/audit.jsonl")
        scanner = [row for row in audits if row["event"] == "security.pattern_scanner"]
        assert {row["decision"] for row in scanner} >= {"deny", "log"}
        assert all(row["control"] == "patterns" and "addon" not in row for row in scanner)


def test_installed_expiring_host_entry_observes_reload_boundary(tmp_path):
    from datetime import UTC, datetime, timedelta

    with origin_server() as origin, native_instance(
        tmp_path, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        expires = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()
        source = DENY + f'\n[hosts."expiry.invalid"]\negress="allow"\nexpires="{expires}"\n'
        instance.apply(source)
        delivered(instance, origin, "expiry.invalid:8123")
        time.sleep(2.1)
        # Expiry is compiled at reload. A successful apply selects that boundary.
        instance.apply(source)
        delivered(instance, origin, "expiry.invalid:8123", status=403)
        assert "expiry.invalid" not in instance.show()["effective"]["hosts"]


def test_installed_configured_circuit_threshold_reset_recovery(tmp_path):
    source = '''[hosts]
"*"={egress="allow"}
[controls.circuits]
failure_threshold=2
success_threshold=1
timeout_seconds=60
use_exponential_backoff=false
jitter_factor=0.0
'''
    with origin_server() as origin, native_instance(
        tmp_path, source, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
    ) as instance:
        for _ in range(2):
            result = request(instance.paths["alice"], "http://circuit.invalid:8123/fail", method="POST")
            assert result[0] == 501, result
        before = origin.accepts
        assert request(instance.paths["bob"], "http://circuit.invalid:8123/marker")[0] == 503
        assert origin.accepts == before
        instance.admin("POST", "/admin/circuit-breaker/reset", {"host": "circuit.invalid"})
        delivered(instance, origin, "circuit.invalid:8123")
        assert instance.show()["effective"]["controls"]["circuits"]["failure_threshold"] == 2


def test_installed_context_formatter_atomic_watched_file(tmp_path):
    with native_instance(tmp_path) as instance:
        destination = tmp_path / "watched/context"
        fields = ["--run", "native", "--agent", "alice", "--role", "tester", "--suite", "policy",
                  "--subject", "context", "--step", "one", "--test", "atomic", "--intent", "observe",
                  "--expect", "complete", "--field", "zeta=last", "--field", "alpha=first"]
        initial = instance.cli("test-context", *fields, "--write", str(destination))
        assert initial.returncode == 0, initial.stderr
        old = initial.stdout.strip()
        assert old == "run=native;agent=alice;role=tester;suite=policy;subject=context;step=one;test=atomic;intent=observe;expect=complete;alpha=first;zeta=last"
        seen = set()
        new_fields = ["two" if value == "one" else value for value in fields]
        new = old.replace("step=one", "step=two")
        with ThreadPoolExecutor(max_workers=1) as executor:
            updating = executor.submit(instance.cli, "test-context", *new_fields, "--write", str(destination))
            while not updating.done():
                seen.add(destination.read_text())
            result = updating.result()
        assert result.returncode == 0, result.stderr
        seen.add(destination.read_text())
        assert seen <= {old, new} and destination.read_text() == new
        # The formatter round-trip and header form preserve every supported pair.
        header = instance.cli("test-context", *new_fields, "--header")
        assert header.returncode == 0 and header.stdout.strip() == "X-SafeYolo-Test-Context: " + new
        destination.parent.chmod(0o500)
        try:
            rejected = instance.cli("test-context", *fields, "--write", str(destination))
            assert rejected.returncode != 0 and "Permission denied" in rejected.stderr
            assert destination.read_text() == new
        finally:
            destination.parent.chmod(0o700)
        rejected = instance.cli("test-context", *fields, "--run", "duplicate", "--write", str(destination))
        assert rejected.returncode != 0 and "duplicate" in rejected.stderr and destination.read_text() == new


@pytest.mark.parametrize("fields,message", [
    (["--run", "native"], "missing required context field(s): agent"),
    (["--run", "native", "--agent", "alice", "--intent", "two words"], "outside [A-Za-z0-9_.:-]"),
    (["--run", "one", "--run", "two", "--agent", "alice"], "duplicate context key: run"),
    (["--run", "native", "--agent", "alice", "--field", "extra=one", "--field", "extra=two"], "duplicate context key: extra"),
    (["--run", "native", "--agent", "alice", "--field", "role=reader"], "use --role"),
])
def test_installed_context_invalid_input_keeps_previous_file(tmp_path, fields, message):
    with native_instance(tmp_path) as instance:
        destination = tmp_path / "watched-context"
        destination.write_text("run=previous;agent=alice")
        result = instance.cli("test-context", *fields, "--write", str(destination))
        assert result.returncode != 0 and message in result.stderr
        assert destination.read_text() == "run=previous;agent=alice"


def test_installed_context_declare_injection_expiry_clear_and_evidence(tmp_path):
    source = '''[hosts]
"*"={egress="allow"}
[controls.test_context]
target_hosts=["context.invalid"]
inject_declared=false
declared_ttl=2
'''
    with origin_server() as origin, native_instance(
        tmp_path, source, parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}", agent_api=True,
        capture=True, extra_config='\n[capture]\nmax_response_body_bytes=3\ncompress_bodies=false\n',
    ) as instance:
        url = "context.invalid:8123"
        delivered(instance, origin, url, status=428)
        delivered(instance, origin, "unrelated.invalid:8123")
        delivered(instance, origin, url, headers={"X-SafeYolo-Test-Context": "run=explicit;agent=alice"})
        declared = instance.context("declare", "alice", "--run", "native-context", "--agent", "bob", "--ttl", "2")
        assert declared["agent"] == "alice" and declared["context"]["agent"] == "bob"
        assert instance.context("current")["context"] == declared["context"]
        delivered(instance, origin, url, status=428)  # Declaration alone does not enable injection.
        instance.apply(source.replace("inject_declared=false", "inject_declared=true"))
        headers = delivered(instance, origin, url, headers={"X-SafeYolo-Agent": "bob", "X-Agent-Id": "bob",
                                                           "X-SafeYolo-Trace": "true"})
        identifier = next(value for name, value in headers.items() if name.lower() == "x-safeyolo-request-id")
        delivered(instance, origin, url, agent="bob", status=428)
        trace = instance.agent_api("alice", f"/trace?request_id={identifier}")
        assert trace["agent_id"] == "alice" and trace["steps"]
        assert all("control" in step and "addon" not in step for step in trace["steps"])
        instance.agent_api("bob", f"/trace?request_id={identifier}", status=404)
        evidence = instance.agent_api("alice", f"/explain?request_id={identifier}")
        context_events = [row for row in evidence["events"] if row["event"] == "security.test_context"]
        assert {row["details"]["phase"] for row in context_events} == {"request", "response"}, evidence
        assert all(row["agent"] == "alice" and row["details"]["trusted_agent"] == "alice"
                   and row["details"]["test_agent_match"] is False for row in context_events)
        assert instance.agent_api("bob", f"/explain?request_id={identifier}")["events"] == []
        deadline = time.monotonic() + 4
        while True:
            flows = instance.agent_api("alice", "/api/flows/search?run=native-context")["flows"]
            if flows:
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)
        flow = next(row for row in flows if row["request_id"] == identifier)
        assert flow["agent_id"] == flow["evidence_owner"] == "alice"
        assert flow["response_body_truncated"] == 1
        body = instance.agent_api("alice", f"/api/flows/{flow['id']}/response-body")
        assert base64.b64decode(body["body_base64"]) == b"hel"
        instance.agent_api("bob", f"/api/flows/{flow['id']}/response-body", status=404)
        assert instance.agent_api("bob", "/api/flows/search?run=native-context")["flows"] == []
        time.sleep(2.1)
        delivered(instance, origin, url, status=428)
        assert instance.context("current")["context"] is None
        instance.context("declare", "alice", "--run", "clear-control", "--agent", "alice")
        delivered(instance, origin, url)
        instance.context("clear")
        delivered(instance, origin, url, status=428)
        sensor = instance.agent_api("alice", "/config")
        assert "addons" not in sensor and sensor["controls"]["test_context"]["target_hosts"] == ["context.invalid"]
