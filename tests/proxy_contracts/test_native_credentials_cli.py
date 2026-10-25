"""#819 installed host CLI and proxy boundaries with synthetic credentials.

Reuse #816's installation, owned origin, readiness (15s), HTTP (5s) and
catalogue (4s) deadlines. C4 uses the resolver's ten-second provider deadline.
These host listeners do not establish guest filesystem isolation or real op.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.proxy_contracts.harness import child_process, connection, read_events, request, wait_ready
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_policy_cli import NativeInstance, native_instance

LOCAL = "synthetic-native-local-credential-819"
EXTERNAL = "synthetic-native-external-credential-819"
AUTH = "synthetic-host-provider-authentication-819"
DETECTED = "ghp_synthetic819000000000000000000000000000000"
SERVICE = {
    "schema_version": 1, "name": "notes", "default_host": "127.0.0.1",
    "auth": {"type": "bearer", "allow_http": True},
    "capabilities": {"reader": {"routes": [{"methods": ["GET"], "path": "/notes/*"}]}},
    "risky_routes": [{"methods": ["GET"], "path": "/notes/risky", "tactics": ["impact"]}],
}
POLICY = '''budget=12000
[hosts]
"*"={egress="deny", unknown_creds="deny"}
[agents.alice]
[agents.bob]
[[risk]]
account="owned"
tactics=["impact"]
decision="require_approval"
'''


def cli(instance, *arguments, valid=True):
    result = instance.cli(*arguments)
    if (result.returncode == 0) != valid:
        raise AssertionError("native command exit did not match the expected result")
    for value in (LOCAL, EXTERNAL, AUTH, DETECTED):
        if value in result.stdout + result.stderr:
            raise AssertionError("credential marker appeared in command output")
    return json.loads(result.stdout) if result.stdout.startswith(('[', '{')) else result.stdout


def catalogue(instance, path, definition):
    path.write_text(json.dumps(definition))
    deadline = time.monotonic() + 4
    while True:
        selected = cli(instance, "services", "show", definition["name"])
        if selected["definition"] == definition:
            return selected
        assert time.monotonic() < deadline, selected
        time.sleep(0.02)


def token(instance, service="notes"):
    return cli(instance, "services", "authorized", "alice")["services"][service]["token"]


def authorize(instance, name="local", service="notes", *extra):
    arguments = ["services", "authorize", "alice", service, "--capability", "reader",
                 "--account", "owned", "--host", "127.0.0.1", "--allow-host-network"]
    if name:
        arguments.extend(["--credential", name])
    return cli(instance, *arguments, *extra)


def deliver(instance, origin, credential, *, agent="alice", path="/notes/one",
            method="GET", host="127.0.0.1", status=200, headers=None, value=LOCAL, timeout=5):
    before = origin.accepts
    client = connection(instance.paths[agent])
    try:
        client.sock.settimeout(timeout)
        client.request(method, f"http://{host}:{origin.server_address[1]}{path}",
                       headers={"Authorization": "Bearer " + credential, **(headers or {})})
        response = client.getresponse()
        code, body = response.status, response.read()
    finally:
        client.close()
    if code != status:
        raise AssertionError(f"expected HTTP {status}, received {code}")
    for secret in (LOCAL, EXTERNAL, AUTH, DETECTED):
        if secret.encode() in body:
            raise AssertionError("credential marker appeared in response")
    if status == 200:
        assert origin.accepts == before + 1
        head = origin.request_heads[-1]
        if AUTH.encode() in head:
            raise AssertionError("provider authentication marker reached the origin")
        if value is not None:
            if ("Bearer " + value).encode() not in head:
                raise AssertionError("origin did not receive the exact selected synthetic credential")
        else:
            assert b"Authorization:" not in head
        if credential.encode() in head:
            raise AssertionError("gateway token reached the origin")
    else:
        assert origin.accepts == before
    return body


def surfaces(instance, values=(LOCAL, EXTERNAL, AUTH, DETECTED)):
    # Fixture inputs and deliberate origin observations live outside the
    # installed root. Scan generated files, routine logs and the encrypted file.
    for path in instance.root.rglob("*"):
        if path.is_file() and path.parent.name != "bin":
            try:
                content = path.read_bytes()
            except FileNotFoundError:
                # The proxy can atomically rename a circuit snapshot after is_file().
                continue
            for value in values:
                if value.encode() in content:
                    raise AssertionError(f"credential marker in generated {path.relative_to(instance.root)}")


def test_surfaces_tolerates_atomic_snapshot_rename(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    temporary = data / ".circuit-fixture.tmp"
    temporary.write_bytes(b"snapshot")
    final = data / "circuits.json"
    read_bytes = Path.read_bytes

    def rename_then_read(path):
        if path == temporary:
            path.rename(final)
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", rename_then_read)
    surfaces(SimpleNamespace(root=tmp_path))
    assert final.read_bytes() == b"snapshot"


@pytest.mark.parametrize("relative", [
    "data/circuits.json", "generated.json", "process.log", "credentials.enc",
    "data/.circuit-retained.tmp",
])
@pytest.mark.parametrize("value", [LOCAL, EXTERNAL, AUTH, DETECTED])
def test_surfaces_detects_credentials_in_present_files(tmp_path, relative, value):
    path = tmp_path / relative
    path.parent.mkdir(exist_ok=True)
    path.write_text(value)
    with pytest.raises(AssertionError, match="credential marker in generated"):
        surfaces(SimpleNamespace(root=tmp_path))


@pytest.mark.parametrize("error", [PermissionError, OSError])
def test_surfaces_propagates_other_read_errors(tmp_path, monkeypatch, error):
    (tmp_path / "process.log").touch()

    def unreadable(_path):
        raise error("fixture read failure")

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    with pytest.raises(error, match="fixture read failure"):
        surfaces(SimpleNamespace(root=tmp_path))


@contextmanager
def restart(instance):
    instance.process.terminate()
    assert instance.process.wait(timeout=10) == 0
    with child_process([str(instance.root / "bin/safeyolo-proxy"), "--config",
                        str(instance.root / "config.toml")], instance.root, instance.environment) as process:
        readiness = instance.root / "data/ready.json"
        wait_ready(process, [readiness, *map(Path, instance.paths.values())], instance.root / "process.log",
                   readiness_file=readiness, expected_backend="rust-m2")
        yield NativeInstance(instance.root, process, instance.paths, instance.environment)


def setup(instance, directory):
    value_file = directory / "value"
    value_file.write_text(LOCAL)
    cli(instance, "credentials", "add", "local", "--storage", "local", "--value-file", str(value_file))
    cli(instance, "credentials", "list")
    # Loading a new definition follows the existing watcher; no second CLI loader.
    path = instance.root / "builtin-services/notes.yaml"
    path.write_text(json.dumps(SERVICE))
    deadline = time.monotonic() + 4
    while True:
        available = cli(instance, "services", "list")["services"]
        if any(row["definition"]["name"] == "notes" for row in available):
            break
        assert time.monotonic() < deadline
        time.sleep(0.02)
    authorize(instance)
    selected = cli(instance, "services", "authorized", "alice")["services"]["notes"]
    assert (selected["capability"], selected["account"], selected["credential"]) == ("reader", "owned", "local")
    assert selected["routes"] == SERVICE["capabilities"]["reader"]["routes"]


def test_installed_local_first_restart_scope_revocation_removal(tmp_path):
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY, services=True, capture=True,
    ) as instance:
        assert shutil.which("op", path=instance.environment["PATH"]) is None
        setup(instance, tmp_path)
        credential = token(instance)
        assert credential.startswith("sgw_")
        deliver(instance, origin, credential)
        deliver(instance, origin, credential, agent="bob", status=403)
        deliver(instance, origin, credential, host="localhost", status=403)
        deliver(instance, origin, credential, method="DELETE", status=403)
        deliver(instance, origin, credential, path="/outside", status=403)
        surfaces(instance)
        with restart(instance) as resumed:
            assert cli(resumed, "credentials", "list")[0]["name"] == "local"
            credential = token(resumed)
            deliver(resumed, origin, credential)
            cli(resumed, "services", "revoke", "alice", "notes")
            deliver(resumed, origin, credential, status=403)
            authorize(resumed)
            credential = token(resumed)
            cli(resumed, "credentials", "remove", "local")
            deliver(resumed, origin, credential, status=503)
            code, _, body = request(resumed.paths["alice"],
                                    f"http://127.0.0.1:{origin.server_address[1]}/ordinary")
            assert (code, body) == (200, b"hello")
            surfaces(resumed)


def test_passphrase_cli_unlock_write_lock_and_ordinary_restart(tmp_path):
    protected = "synthetic-explicit-unlock-passphrase"
    pass_file = tmp_path / "passphrase"
    pass_file.write_text(protected)
    pass_file.chmod(0o600)
    value_file = tmp_path / "value"
    value_file.write_text(LOCAL)
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY, services=True, capture=True,
    ) as instance:
        cli(instance, "credentials", "add", "local", "--storage", "passphrase",
            "--passphrase-file", str(pass_file), "--value-file", str(value_file))
        catalogue(instance, instance.root / "builtin-services/notes.yaml", SERVICE)
        authorize(instance)
        deliver(instance, origin, token(instance))
        cli(instance, "credentials", "lock")
        deliver(instance, origin, token(instance), status=503)
        missing = instance.cli("credentials", "unlock")
        assert missing.returncode != 0 and "--passphrase-file" in missing.stderr
        pass_file.write_text("wrong")
        wrong = instance.cli("credentials", "unlock", "--passphrase-file", str(pass_file))
        assert wrong.returncode != 0 and protected not in wrong.stdout + wrong.stderr
        deliver(instance, origin, token(instance), status=503)
        pass_file.write_text(protected)
        cli(instance, "credentials", "unlock", "--passphrase-file", str(pass_file))
        deliver(instance, origin, token(instance))
        with restart(instance) as resumed:
            deliver(resumed, origin, token(resumed), status=503)
            cli(resumed, "credentials", "unlock", "--passphrase-file", str(pass_file))
            deliver(resumed, origin, token(resumed))
            surfaces(resumed, (LOCAL, protected))


def provider(path, calls, mode):
    commands = {"ok": f"printf '%s' '{EXTERNAL}'", "locked": "exit 17", "missing": "exit 1",
                "timeout": "exec /bin/sleep 20"}
    path.write_text(f"#!/bin/sh\nprintf 'call\\n' >> '{calls}'\n"
                    f'printf "%s" "$OP_SERVICE_ACCOUNT_TOKEN" >&2\n{commands[mode]}\n')
    path.chmod(0o700)


def test_installed_provider_order_failures_local_control_and_no_persistence(tmp_path, monkeypatch):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", AUTH)
    executable, calls = tmp_path / "controlled-op", tmp_path / "calls"
    provider(executable, calls, "ok")
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY, services=True, capture=True,
        extra_config=f'onepassword_executable={json.dumps(str(executable))}\n',
    ) as instance:
        setup(instance, tmp_path)
        cli(instance, "credentials", "reference", "external", "--storage", "local", "--provider", "onepassword",
            "--reference", "op://synthetic-vault/synthetic-item/credential")
        authorize(instance, "external")
        credential = token(instance)
        deliver(instance, origin, credential, agent="bob", status=403)
        deliver(instance, origin, credential, path="/notes/risky", status=428)
        assert not calls.exists()
        assert cli(instance, "services", "approvals")["approvals"]
        cli(instance, "services", "approve", "alice", "notes", "GET", "/notes/risky")
        # A risk grant does not authorize Bob or a path outside the capability.
        deliver(instance, origin, credential, path="/outside", status=403)
        deliver(instance, origin, credential, path="/notes/risky", value=EXTERNAL)
        assert calls.read_text().splitlines() == ["call"]
        for mode in ("unavailable", "locked", "missing", "timeout"):
            if mode == "unavailable":
                executable.unlink()
            else:
                provider(executable, calls, mode)
            before = time.monotonic()
            # The provider has a 10s product deadline. This client's 15s test
            # deadline observes that terminal rather than timing out first.
            body = deliver(instance, origin, credential, status=503, timeout=15)
            if mode == "timeout":
                assert 9 <= time.monotonic() - before < 12
                assert b"PROVIDER_TIMEOUT" in body
            else:
                assert b"PROVIDER_" in body
            authorize(instance)
            deliver(instance, origin, token(instance))
            authorize(instance, "external")
            credential = token(instance)
        provider(executable, calls, "ok")
        deliver(instance, origin, credential, value=EXTERNAL)
        surfaces(instance)


def test_installed_catalogue_override_activation_and_malformed_preservation(tmp_path):
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY, services=True,
    ) as instance:
        setup(instance, tmp_path)
        credential = token(instance)
        deliver(instance, origin, credential)
        override = json.loads(json.dumps(SERVICE))
        override["capabilities"]["reader"]["routes"] = [{"methods": ["GET"], "path": "/selected"}]
        path = instance.root / "services/notes.yaml"
        selected = catalogue(instance, path, override)
        assert Path(selected["source"]) == path
        metadata = cli(instance, "services", "authorized", "alice")["services"]["notes"]
        assert metadata["routes"] == override["capabilities"]["reader"]["routes"]
        assert (metadata["credential"], metadata["account"]) == ("local", "owned")
        credential = token(instance)
        deliver(instance, origin, credential, path="/selected")
        deliver(instance, origin, credential, status=403)
        saved = instance.policy.read_bytes()
        path.write_text("capabilities: [invalid]\n")
        # Two watcher checks must leave the accepted definition and policy live.
        deadline = time.monotonic() + 4
        while True:
            assert cli(instance, "services", "show", "notes")["definition"] == override
            assert instance.policy.read_bytes() == saved
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        deliver(instance, origin, credential, path="/selected")
        path.unlink()
        deadline = time.monotonic() + 4
        while cli(instance, "services", "show", "notes")["definition"] != SERVICE:
            assert time.monotonic() < deadline
            time.sleep(0.02)
        credential = token(instance)
        deliver(instance, origin, credential)
        surfaces(instance)


def test_installed_credential_free_service_requires_no_store_or_provider(tmp_path):
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY, services=True,
    ) as instance:
        definition = json.loads(json.dumps(SERVICE))
        definition.pop("auth")
        path = instance.root / "services/notes.yaml"
        path.write_text(json.dumps(definition))
        deadline = time.monotonic() + 4
        while not any(row["definition"]["name"] == "notes" for row in cli(instance, "services", "list")["services"]):
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert not (instance.root / "data/credentials.enc").exists()
        assert not (instance.root / "data/credentials.key").exists()
        authorize(instance, None)
        credential = token(instance)
        deliver(instance, origin, credential, value=None)
        deliver(instance, origin, credential, agent="bob", status=403, value=None)


def test_installed_binding_does_not_replace_service_or_risk_approval(tmp_path):
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY, services=True,
    ) as instance:
        setup(instance, tmp_path)
        definition = json.loads(json.dumps(SERVICE))
        definition["capabilities"]["reader"]["contract"] = {
            "template": "notes.reader.v1",
            "enforcement": {"request_shape": "enforced", "transport_hygiene": "enforced"},
            "bindings": {"approved_id": {"source": "operator", "type": "integer"}},
            "operations": [{"name": "read", "request": {"method": "GET", "path": "/notes/{id}",
                "path_params": {"id": {"equals_var": "approved_id"}},
                "transport": {"require_no_body": True}}}],
        }
        definition["risky_routes"][0]["path"] = "/notes/*"
        catalogue(instance, instance.root / "services/notes.yaml", definition)
        credential = token(instance)
        cli(instance, "services", "approve", "alice", "notes", "GET", "/notes/7")
        deliver(instance, origin, credential, path="/notes/7", status=403)
        bindings = tmp_path / "bindings.json"
        bindings.write_text(json.dumps({"approved_id": 7}))
        cli(instance, "services", "bind", "alice", "notes", "reader", "--bindings", str(bindings))
        # The existing file watcher activates contract-derived routes and
        # remints service tokens. Observe that publication before using them.
        deadline = time.monotonic() + 4
        while not instance.show()["saved_matches_active"]:
            assert time.monotonic() < deadline
            time.sleep(0.02)
        credential = token(instance)
        deliver(instance, origin, credential, path="/notes/8", status=403)
        deliver(instance, origin, credential, agent="bob", path="/notes/7", status=403)
        deliver(instance, origin, credential, path="/notes/7")
        deliver(instance, origin, credential, path="/notes/7", status=428)
        cli(instance, "services", "approve", "alice", "notes", "GET", "/notes/7", "--lifetime", "remembered")
        with restart(instance) as resumed:
            deliver(resumed, origin, token(resumed), path="/notes/7")
            grants = cli(resumed, "services", "grants")["grants"]
            cli(resumed, "services", "revoke-grant", grants[0]["grant_id"])
            deliver(resumed, origin, token(resumed), path="/notes/7", status=428)
            cli(resumed, "services", "revoke", "alice", "notes")
            deliver(resumed, origin, credential, path="/notes/7", status=403)
        surfaces(instance)


def test_installed_credential_policy_approval_uses_existing_native_operation(tmp_path):
    # The outer gateway token must pass before injection can reach the separate
    # credential check. Limit this fixture permission to its owned destination.
    source = POLICY.replace('unknown_creds="deny"', 'unknown_creds="prompt"') + r'''
[credential.fixture-gateway]
match = ['\Asgw_[0-9a-f]{64}\Z']
headers = ["authorization"]
allowed_hosts = ["127.0.0.1"]
[hosts."127.0.0.1"]
allow = ["fixture-gateway:*"]
'''
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, source, services=True, capture=True,
    ) as instance:
        setup(instance, tmp_path)
        input_file = tmp_path / "recognized-value"
        input_file.write_text(DETECTED)
        cli(instance, "credentials", "add", "recognized", "--storage", "local", "--value-file", str(input_file))
        authorize(instance, "recognized")
        deliver(instance, origin, token(instance), status=428)
        pending = cli(instance, "services", "approvals")["approvals"]
        credential_prompt = next(row for row in pending if row["approval"]["approval_type"] == "credential")
        assert credential_prompt["approval"]["scope_hint"]["rule"] == "github"
        fingerprint = credential_prompt["approval"]["key"]
        cli(instance, "credentials", "approve", fingerprint, "--destination", "127.0.0.1")
        deliver(instance, origin, token(instance), value=DETECTED)
        surfaces(instance)


@pytest.mark.parametrize("caller", ["credentials", "admin", "approvals"])
def test_installed_direct_credential_approval_activates_next_connection(tmp_path, caller):
    _direct_credential_approval(tmp_path, caller, activation_failure=False)


@pytest.mark.parametrize("caller", ["credentials", "admin", "approvals"])
def test_installed_direct_credential_activation_failure_is_visible(tmp_path, caller):
    _direct_credential_approval(tmp_path, caller, activation_failure=True)


def _direct_credential_approval(directory, caller, *, activation_failure):
    source = ('budget=12000\n[hosts]\n"*"={egress="allow",unknown_creds="prompt"}\n'
              '[agents.alice]\nagent_id="ag-11111111111111111111111111111111"\n')
    replacement = DETECTED[:-1] + "1"
    with origin_server(capture_heads=True) as origin, native_instance(directory, source) as instance:
        def send(current, value=DETECTED, *, status, host="127.0.0.1"):
            before = origin.accepts
            code, headers, body = request(
                current.paths["alice"], f"http://{host}:{origin.server_address[1]}/held",
                headers={"Authorization": "Bearer " + value},
            )
            assert code == status, (code, status)
            assert all(secret.encode() not in body for secret in (DETECTED, replacement))
            assert origin.accepts == before + (status == 200)
            if status == 200 and value.encode() not in origin.request_heads[-1]:
                raise AssertionError("held credential did not reach origin")
            return next(value for name, value in headers.items() if name.lower() == "x-safeyolo-request-id")

        request_id = send(instance, status=428)
        deadline = time.monotonic() + 4
        while True:
            events = read_events(instance.root / "logs/audit.jsonl")
            detections = [event for event in events if event["event"] == "security.credential_guard"
                          and event.get("request_id") == request_id]
            if detections:
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)
        fingerprint = detections[0]["details"]["fingerprint"]
        assert fingerprint.startswith("hmac:")
        active = instance.show()["effective"]
        if activation_failure:
            # Valid policy syntax can still fail when the detector compiles.
            # Preserve mtime to keep the independent file watcher out of setup.
            metadata = instance.policy.stat()
            saved = source + "\n[credential.activation_failure]\nmatch=['\\uD800']\n"
            instance.policy.write_text(saved)
            os.utime(instance.policy, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))

        if caller == "admin":
            result = instance.admin("POST", "/admin/policy/baseline/approve", {
                "destination": "127.0.0.1", "cred_id": [fingerprint, fingerprint], "tier": "inferred",
            }, expected_status=503 if activation_failure else 200)
            if activation_failure:
                assert result["status"] == "rejected"
                assert result["error"] == "credential approval activation failed"
            else:
                assert result["status"] == "added" and result["permission_count"] == 1
                assert result["cred_id"] == [fingerprint, fingerprint] and result["tier"] == "inferred"
        else:
            arguments = ("credentials", "approve", fingerprint, "--destination", "127.0.0.1") if caller == "credentials" else (
                "approvals", "approve", request_id, "--json",
            )
            result = instance.cli(*arguments)
            assert (result.returncode == 0) != activation_failure, "approval command exit did not match activation"
            assert all(secret not in result.stdout + result.stderr for secret in (DETECTED, replacement))
            if activation_failure:
                assert "credential approval activation failed" in result.stderr
            else:
                assert json.loads(result.stdout)["status"] == ("added" if caller == "credentials" else "approved")

        if activation_failure:
            assert instance.policy.read_text() == saved
            assert instance.show()["effective"] == active
            send(instance, status=428)
            events = read_events(instance.root / "logs/audit.jsonl")
            assert not any(event["event"] == "admin.approval_added" for event in events)
            instance.apply(source)
            cli(instance, "credentials", "approve", fingerprint, "--destination", "127.0.0.1")

        # request() opens and closes a distinct connection on every call. No
        # policy view, watcher wait, policy apply or restart precedes this retry.
        send(instance, status=200)
        assert instance.process.poll() is None
        assert instance.show()["saved_matches_active"]
        send(instance, replacement, status=428)
        send(instance, status=428, host="localhost")
        with restart(instance) as resumed:
            send(resumed, status=200)
            send(resumed, replacement, status=428)
            denied = tomlkit.parse(resumed.policy.read_text())
            denied["hosts"]["127.0.0.1"]["rules"] = [{
                "action": "credential:use", "resource": "127.0.0.1/*", "effect": "deny",
            }]
            resumed.apply(tomlkit.dumps(denied))
            cli(resumed, "credentials", "approve", fingerprint, "--destination", "127.0.0.1")
            send(resumed, status=403)
        surfaces(instance, (DETECTED, replacement))


def test_init_and_read_only_commands_defer_storage_until_a_valid_secret_write(tmp_path):
    from tests.proxy_contracts.test_native_policy_cli import native_inputs

    artifacts, _, _ = native_inputs()
    binary = artifacts / "safeyolo"
    root = tmp_path / "instance"

    def command(*arguments, valid=True, value=None):
        result = subprocess.run([str(binary), "--root", str(root), *arguments],
                                input=value, capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == valid, result.stderr
        assert LOCAL not in result.stdout + result.stderr
        return result

    command("init")
    for arguments, valid in [
        (("credentials", "list"), True),
        (("credentials", "remove", "missing"), False),
        (("credentials", "invalid"), False),
        (("credentials", "add", "invalid", "--storage", "local", "--type", "unsupported"), False),
        (("credentials", "import-codex", "invalid"), False),
        (("credentials", "provider", "--executable", "/bin/true"), True),
        (("credentials", "unlock"), False),
    ]:
        command(*arguments, valid=valid)
        assert not (root / "data/credentials.key").exists()
        assert not (root / "data/credentials.enc").exists()
    refused = command("credentials", "add", "local", "--stdin", value=LOCAL, valid=False)
    assert "--storage local or --storage passphrase" in refused.stderr
    assert not (root / "data/credentials.key").exists()
    assert not (root / "data/credentials.enc").exists()
    command("credentials", "add", "local", "--storage", "local", "--stdin", value=LOCAL)
    assert (root / "data/credentials.key").read_text().startswith("safeyolo-native-key-v1:")
    assert json.loads(command("credentials", "list").stdout)[0]["name"] == "local"
    assert LOCAL.encode() not in (root / "data/credentials.enc").read_bytes()
    encrypted = (root / "data/credentials.enc").read_bytes()
    key = (root / "data/credentials.key").read_bytes()
    command("credentials", "add", "local", "--storage", "passphrase", "--stdin", value=LOCAL, valid=False)
    assert (root / "data/credentials.enc").read_bytes() == encrypted
    (root / "data/credentials.enc").unlink()
    for arguments in [("credentials", "list"), ("credentials", "add", "local", "--stdin")]:
        command(*arguments, value=LOCAL, valid=False)
        assert not (root / "data/credentials.enc").exists()
        assert (root / "data/credentials.key").read_bytes() == key


@pytest.mark.parametrize("selection", ["local", "passphrase", "cancel", "mismatch"])
def test_first_storage_choice_and_hidden_passphrase_input(tmp_path, selection):
    from tests.proxy_contracts.test_native_coord_operator import terminal, wait_terminal_exit
    from tests.proxy_contracts.test_native_policy_cli import native_inputs

    artifacts, _, _ = native_inputs()
    root = tmp_path / "instance"
    binary = (artifacts / "safeyolo").resolve()
    subprocess.run([str(binary), "--root", str(root), "init"], check=True, capture_output=True)
    (root / "bin").mkdir()
    (root / "bin/safeyolo").symlink_to(binary)
    value_file = tmp_path / "value"
    value_file.write_text(LOCAL)
    instance = SimpleNamespace(root=root, environment=os.environ.copy())
    protected = "synthetic-manual-storage-passphrase"
    with terminal(instance, ["credentials", "add", "local", "--value-file", str(value_file)]) as (process, master, until):
        output = until(b"Choose credential storage")
        assert not (root / "data/credentials.key").exists()
        os.write(master, ("q" if selection == "cancel" else "local" if selection == "local" else "passphrase").encode() + b"\n")
        if selection in ("passphrase", "mismatch"):
            output += until(b"Storage passphrase:")
            os.write(master, protected.encode() + b"\n")
            output += until(b"Confirm storage passphrase:")
            os.write(master, (protected if selection == "passphrase" else "different").encode() + b"\n")
        output = bytearray(output)
        code = wait_terminal_exit(process, master, output, timeout=5)
        assert (b"Credential stored:" if selection in ("local", "passphrase") else b"cancelled" if selection == "cancel" else b"do not match") in output
        assert (code == 0) == (selection in ("local", "passphrase"))
        assert protected.encode() not in output and LOCAL.encode() not in output
    if selection in ("cancel", "mismatch"):
        assert not (root / "data/credentials.key").exists()
        assert not (root / "data/credentials.enc").exists()
        return
    key = (root / "data/credentials.key").read_text()
    assert (key == "safeyolo-passphrase-v1") == (selection == "passphrase")
    if selection == "local":
        return
    encrypted = (root / "data/credentials.enc").read_bytes()
    for value in (None, "wrong", protected):
        arguments = []
        if value is not None:
            pass_file = tmp_path / "passphrase"
            pass_file.write_text(value)
            arguments = ["--passphrase-file", str(pass_file)]
        result = subprocess.run([str(binary), "--root", str(root), "credentials", "list", *arguments],
                                capture_output=True, text=True, timeout=15)
        assert (result.returncode == 0) == (value == protected)
        assert protected not in result.stdout + result.stderr
        assert (root / "data/credentials.enc").read_bytes() == encrypted
    assert json.loads(result.stdout)[0]["name"] == "local"
