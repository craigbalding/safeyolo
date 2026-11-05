"""Connect per-attempt private input to the accepted event/caller/provisioner."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from scripts import claude_blackbox_events as events
from tests import test_claude_blackbox_events as event_tests

ROOT = Path(__file__).resolve().parents[1]
HELPER_SHA256 = "7f282180e8b4b413f07ab208785c82bb835370021e9f51d99935bb11123806eb"
invocation = event_tests.invocation
transport = event_tests.transport


def access_input(tmp_path):
    source = tmp_path / "private sealed source"
    source.mkdir(mode=0o700)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keyfile = source / "transport-private.pem"
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    keyfile.chmod(0o600)
    access = {"value": "SYNTHETIC-ACCESS-ONE", "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()}
    access["source_expires_at"] = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    replace_access(source, access)
    return source, access


def replace_access(source, access):
    # Model the existing private sender: only ciphertext is persisted/delivered.
    key = serialization.load_pem_private_key((source / "transport-private.pem").read_bytes(), password=None)
    transport_key = Fernet.generate_key()
    wrapped = key.public_key().encrypt(transport_key,
                                      padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    envelope = {"wrapped_key": base64.b64encode(wrapped).decode(),
                "ciphertext": Fernet(transport_key).encrypt(json.dumps(access).encode()).decode()}
    pending = source / "sealed-access.pending"
    pending.write_text(json.dumps(envelope))
    pending.chmod(0o600)
    pending.replace(source / "sealed-access.json")


def binding_environment(source, output):
    return dict(os.environ, CLAUDE_ACCESS_SOURCE=str(source), CLAUDE_ACCESS_PYTHON=sys.executable,
                CLAUDE_EVENT_RUN="42", CLAUDE_EVENT_OUTPUT=str(output),
                CLAUDE_PROVISION="/unused/helper", CLAUDE_CREDENTIAL="host-access-only")


def source_binding(source, output):
    return subprocess.run(["bash", "-euc", "source " + shlex.quote(str(ROOT / "scripts/claude_access_binding.sh"))],
                          env=binding_environment(source, output), capture_output=True, check=False)


def unseal(directory):
    envelope = json.loads((directory / "sealed-access.json").read_bytes())
    key = serialization.load_pem_private_key((directory / "transport-private.pem").read_bytes(), password=None)
    transport_key = key.decrypt(base64.b64decode(envelope["wrapped_key"]),
                                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return json.loads(Fernet(transport_key).decrypt(envelope["ciphertext"].encode()))


def test_each_attempt_rereads_access_without_extending_expiry(tmp_path):
    source, access = access_input(tmp_path)
    envelopes = []
    for attempt in (1, 2, 3):
        if attempt == 3:
            access.update(value="SYNTHETIC-ACCESS-TWO", expires_at=(datetime.now(UTC) + timedelta(minutes=45)).isoformat())
            replace_access(source, access)
        before = {path.name: path.read_bytes() for path in source.iterdir()}
        output = tmp_path / f"42-{attempt}"
        result = source_binding(source, output)
        assert result.returncode == 0 and not result.stdout and not result.stderr
        directory = output.with_name(output.name + ".provision")
        assert unseal(directory) == access
        assert directory.stat().st_mode & 0o777 == 0o700
        for path in directory.iterdir():
            assert path.stat().st_mode & 0o777 == 0o600
            assert access["value"].encode() not in path.read_bytes()
        envelopes.append((directory / "sealed-access.json").read_bytes())
        assert not output.exists()  # The unchanged caller must create its own output.
        assert {path.name: path.read_bytes() for path in source.iterdir()} == before
        for path in tmp_path.rglob("*"):
            if path.is_file():
                assert b"SYNTHETIC" not in path.read_bytes()
    assert len(set(envelopes)) == 3
    assert unseal(source) == access


@pytest.mark.parametrize("fault", ["missing", "expired", "short", "naive", "source-expiry", "empty", "refresh", "malformed", "tampered", "wrong-key", "plaintext", "public-file", "public-key", "public-source"])
def test_unavailable_or_unusable_source_cannot_prepare_input(tmp_path, fault):
    source, access = access_input(tmp_path)
    envelope = source / "sealed-access.json"
    if fault == "missing":
        envelope.unlink()
    elif fault in {"expired", "short"}:
        access["expires_at"] = (datetime.now(UTC) + timedelta(minutes=-1 if fault == "expired" else 10)).isoformat()
    elif fault == "naive":
        access["expires_at"] = "2099-01-01T00:00:00"
    elif fault == "source-expiry":
        access["source_expires_at"] = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
    elif fault == "empty":
        access["value"] = ""
    elif fault == "refresh":
        access["refresh_token"] = "SYNTHETIC-RENEWAL-MUST-STAY-ON-ORIGINAL-HOST"
    if fault != "missing":
        replace_access(source, access)
    if fault == "malformed":
        envelope.write_text("invalid SYNTHETIC-ACCESS-ONE")
    if fault == "tampered":
        sealed = json.loads(envelope.read_bytes())
        sealed["ciphertext"] = Fernet(Fernet.generate_key()).encrypt(b"SYNTHETIC-TAMPERING").decode()
        envelope.write_text(json.dumps(sealed))
    if fault == "wrong-key":
        (source / "transport-private.pem").write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    if fault == "plaintext":
        envelope.write_text(json.dumps(access))
    if fault == "public-file":
        envelope.chmod(0o644)
    if fault == "public-key":
        (source / "transport-private.pem").chmod(0o644)
    if fault == "public-source":
        source.chmod(0o644)
    result = source_binding(source, tmp_path / "42-1")
    assert result.returncode == 2 and not result.stdout
    assert b"SYNTHETIC" not in result.stderr
    assert not list((tmp_path / "42-1.provision").iterdir())


def test_existing_attempt_cannot_be_reprepared(tmp_path):
    source, _ = access_input(tmp_path)
    output = tmp_path / "42-1"
    assert source_binding(source, output).returncode == 0
    directory = tmp_path / "42-1.provision"
    before = {path.name: path.read_bytes() for path in directory.iterdir()}
    result = source_binding(source, output)
    assert result.returncode == 2 and b"FileExistsError" in result.stderr
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == before


@pytest.fixture
def accepted_helper():
    selected = os.environ.get("SAFEYOLO_TEST_CLAUDE_PROVISION_HELPER")
    if not selected:
        pytest.skip("operator helper not supplied; set SAFEYOLO_TEST_CLAUDE_PROVISION_HELPER for the connection proof")
    helper = Path(selected)
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == HELPER_SHA256
    return helper


@pytest.fixture
def connected(transport, tmp_path, monkeypatch, accepted_helper):
    config, request, controller = transport
    Path(config["remote_attempts"]).mkdir(mode=0o700)
    source, access = access_input(tmp_path)
    imports = tmp_path / "synthetic-imports.jsonl"
    native = controller / "prepared/bin/safeyolo"
    native.parent.mkdir(parents=True, mode=0o700)
    native.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
        import json, os, pathlib, sys
        with pathlib.Path(os.environ['SYNTHETIC_IMPORTS']).open('a') as stream:
            stream.write(json.dumps({'args':sys.argv[1:], 'value':sys.stdin.read(), 'mask':os.umask(0o077)})+'\\n')
        print('SYNTHETIC-NATIVE-PRIVATE-OUTPUT')
        print('SYNTHETIC-NATIVE-PRIVATE-ERROR', file=sys.stderr)
    '''))
    native.chmod(0o700)
    helper = tmp_path / "accepted helper wrapper"
    helper.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(accepted_helper))} \"$@\"\n")
    helper.chmod(0o700)
    binding = Path(config["binding"])
    binding.write_text("set +x\n" + "\n".join(f"{key}={shlex.quote(value)}" for key, value in {
        "CLAUDE_ACCESS_SOURCE": str(source), "CLAUDE_ACCESS_PYTHON": sys.executable,
        "CLAUDE_PROVISION": str(helper), "CLAUDE_CREDENTIAL": "host-access-only",
    }.items()) + "\nsource " + shlex.quote(str(ROOT / "scripts/claude_access_binding.sh")) + "\n")
    monkeypatch.setenv("SYNTHETIC_IMPORTS", str(imports))
    return config, request, controller, source, access, imports, native


def admit(config, request):
    run = event_tests.trusted_run()
    run.update(event="schedule", run_attempt=request["event_attempt"])
    github = event_tests.FakeGitHub(request)
    github.artifact["name"] = f"claude-event-{request['event_attempt']}"
    return events.consume(config, github, run, "master")


def test_admitted_attempts_connect_new_input_to_exact_helper_and_caller(connected):
    config, request, controller, source, access, imports, _ = connected
    for attempt in (1, 2):
        if attempt == 2:
            access["value"] = "SYNTHETIC-ACCESS-TWO"
            replace_access(source, access)
        request["event_attempt"] = attempt
        result = admit(config, request)
        assert result["exit"] == result["guest_exit"] == 0, result
        directory = Path(result["remote_output"] + ".provision")
        assert [path.name for path in directory.iterdir()] == ["provision-result.json"]
        receipt = json.loads((directory / "provision-result.json").read_bytes())
        assert receipt["expires_at"] == access["expires_at"] and not receipt["refresh_token_transferred"]
        assert receipt["credential_add_exit"] == 0
        assert (directory / "provision-result.json").stat().st_mode & 0o777 == 0o600
        rows = [json.loads(line) for line in imports.read_text().splitlines()]
        assert len(rows) == attempt and rows[-1]["value"] == access["value"]
        assert rows[-1]["mask"] == 0o077
        assert rows[-1]["args"][-3:] == [access["expires_at"], "--storage", "local"]
        assert "--stdin" in rows[-1]["args"] and "--refresh-token-file" not in rows[-1]["args"]
        for path in (Path(result["remote_output"]) / "private.log",
                     Path(result["remote_output"]) / "result.json",
                     Path(config["attempts"]) / f"42-{attempt}/result.json",
                     Path(config["attempts"]) / f"42-{attempt}/transport.json"):
            assert b"SYNTHETIC" not in path.read_bytes()
        assert admit(config, request) is None
    stages = [json.loads(line)["stage"] for line in (controller / "events").read_text().splitlines()]
    assert stages == ["selection", "readiness", "smoke"] * 2


@pytest.mark.parametrize("fault", ["missing", "expired"])
def test_unavailable_input_stops_the_actual_event_payload_before_caller(connected, fault):
    config, request, controller, source, access, imports, _ = connected
    if fault == "missing":
        (source / "sealed-access.json").unlink()
    else:
        access["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        replace_access(source, access)
    result = admit(config, request)
    assert result["exit"] == result["guest_exit"] == 2
    assert not (controller / "events").exists() and not imports.exists()
    assert not Path(result["remote_output"]).exists()
    assert admit(config, request) is None


def test_uncertain_import_cannot_reprepare_or_reenter_smoke(connected):
    config, request, controller, source, _, imports, native = connected
    native.unlink()  # Launch failure leaves the exact helper's unfinished receipt.
    result = admit(config, request)
    assert result["exit"] != 0 and result["guest_exit"] != 0
    report = json.loads((Path(result["remote_output"]) / "result.json").read_bytes())
    assert report["stage"] == "host-service-binding" and not imports.exists()
    directory = Path(result["remote_output"] + ".provision")
    receipt = (directory / "provision-result.json").read_bytes()
    assert json.loads(receipt)["credential_add_exit"] is None and "finished_at" not in json.loads(receipt)
    assert (directory / "transport-private.pem").is_file() and (directory / "sealed-access.json").is_file()
    assert admit(config, request) is None
    assert source_binding(source, Path(result["remote_output"])).returncode == 2
    assert (directory / "provision-result.json").read_bytes() == receipt
    assert [json.loads(line)["stage"] for line in (controller / "events").read_text().splitlines()] == ["selection", "readiness"]
