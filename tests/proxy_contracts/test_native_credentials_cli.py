"""#819 installed host CLI and proxy boundaries with synthetic credentials.

Reuse #816's installation, owned origin, readiness (15s), HTTP (5s) and
catalogue (4s) deadlines. C4 uses the resolver's ten-second provider deadline.
These host listeners do not establish guest filesystem isolation or real op.
"""

from __future__ import annotations

import json
import shutil
import time
from contextlib import contextmanager
from pathlib import Path

from tests.proxy_contracts.harness import child_process, connection, request, wait_ready
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


def surfaces(instance):
    # Fixture inputs and deliberate origin observations live outside the
    # installed root. Scan generated files, routine logs and the encrypted file.
    for path in instance.root.rglob("*"):
        if path.is_file() and path.parent.name != "bin":
            content = path.read_bytes()
            for value in (LOCAL, EXTERNAL, AUTH, DETECTED):
                if value.encode() in content:
                    raise AssertionError(f"credential marker in generated {path.relative_to(instance.root)}")


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
    cli(instance, "credentials", "add", "local", "--value-file", str(value_file))
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
        cli(instance, "credentials", "reference", "external", "--provider", "onepassword",
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
        (instance.root / "data/credentials.enc").unlink()
        (instance.root / "data/credentials.key").unlink()
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
    with origin_server(capture_heads=True) as origin, native_instance(
        tmp_path, POLICY.replace('unknown_creds="deny"', 'unknown_creds="prompt"'), services=True, capture=True,
    ) as instance:
        setup(instance, tmp_path)
        input_file = tmp_path / "recognized-value"
        input_file.write_text(DETECTED)
        cli(instance, "credentials", "add", "recognized", "--value-file", str(input_file))
        authorize(instance, "recognized")
        deliver(instance, origin, token(instance), status=428)
        pending = cli(instance, "services", "approvals")["approvals"]
        credential_prompt = next(row for row in pending if row["approval"]["approval_type"] == "credential")
        fingerprint = credential_prompt["approval"]["key"]
        cli(instance, "credentials", "approve", fingerprint, "--destination", "127.0.0.1")
        deadline = time.monotonic() + 4
        while not instance.show()["saved_matches_active"]:
            assert time.monotonic() < deadline
            time.sleep(0.02)
        deliver(instance, origin, token(instance), value=DETECTED)
        surfaces(instance)
