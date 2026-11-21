#!/usr/bin/env python3
"""Send from real systrap guests to a separate TLS/NATS instance owner.

On a prepared disposable Linux host, supply the same installation and runtime
prerequisites as installed_authority, plus OpenSSL for a private test certificate.
The new root owns two credential-free guests. A second root owns the destination
room, broker, TLS key and peer credential. No peer credential enters a guest.
Both roots must be new; output must be empty and disk-backed. The driver checks
destination-owned message effects, wrong principal/instance and revocation,
then stops both instances. This is a same-host TLS journey, not a live tailnet.
Wrong-instance selection is refused by the source before forwarding. Native
federation tests cover the destination's payload-mismatch handler separately.
"""

from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path
from urllib.parse import urlencode

import tomlkit

from tests.blackbox.execution_receipt import ProcedureReceipt, save
from tests.blackbox.guest_exec import guest_http_request
from tests.blackbox.installed_authority import NAMES, prepare_authority_guests
from tests.blackbox.installed_host_smoke import _sha256
from tests.blackbox.installed_lifecycle import running_guest
from tests.blackbox.installed_provider import checked, inputs
from tests.blackbox.installed_sections import cleanup_instance, copy_prepared_nats, prepare_native_instance


def run(args):
    base, root, output = args.prepared_config.resolve(), args.root.resolve(), args.output.resolve()
    destination = root.with_name(root.name + "-destination")
    assert not root.exists() and not destination.exists(), "both instance roots must be new"
    output.mkdir(parents=True, exist_ok=True)
    assert not any(output.iterdir()), "--output must be empty"
    output.chmod(0o700)
    cli = base / "bin/safeyolo"
    report = {"status": "incomplete", "inputs": inputs(base, args.revision),
              "source_root": str(root), "destination_root": str(destination), "cleanup": "unverified"}
    save(output / "result.json", report)

    def native(selected, *words):
        env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(selected),
                            "SAFEYOLO_NATIVE_CONFIG_PATH": str(selected / "config.toml"),
                            "SAFEYOLO_COORD_DATA_DIR": str(selected / "data/coord"),
                            "SAFEYOLO_NATS_TEST_INSTANCE": str(selected), "SAFEYOLO_RUNSC_PLATFORM": "systrap"}
        return checked([str(cli), "--root", str(selected), *words], env=env, diagnostics=output / "native.log")

    def observe():
        raw = native(destination, "coord", "watch", "shared", "--history", "100", "--once", "--json")
        rows = [json.loads(line) for line in raw.splitlines()]
        report["destination_messages"] = rows
        save(output / "result.json", report)
        return rows

    def send(actor, body, instance_id=None):
        env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_NATIVE_CONFIG_PATH": str(root / "config.toml")}
        query = {"home": "destination"}
        if instance_id is not None:
            query["instance_id"] = instance_id
        return guest_http_request(str(cli), actor, "POST",
                                  "http://_safeyolo.proxy.internal/api/coord/rooms/shared/send?" + urlencode(query),
                                  {"body": body, "notify": "none"}, env=env)

    try:
        prepare_authority_guests(base, root, lambda *words: native(root, *words))
        native(root, "start")
        prepare_native_instance(base, destination)
        config = tomlkit.parse((destination / "config.toml").read_text())
        config.update(admin_port=0, flow_store_enabled=False)
        (destination / "config.toml").write_text(tomlkit.dumps(config))
        (destination / ".safeyolo-platform-smoke").touch()
        copy_prepared_nats(base, destination)
        native(destination, "coord", "start")
        source_id = (root / "data/instance_id").read_text().strip()
        destination_id = (destination / "data/instance_id").read_text().strip()
        assert source_id != destination_id
        report.update(source_instance_id=source_id, destination_instance_id=destination_id)
        native(destination, "coord", "room", "create", "shared")
        credential = destination / "source-credential"
        native(destination, "coord", "federation", "credential", str(credential))
        native(destination, "coord", "federation", "trust", source_id, str(credential))
        policy = json.loads(native(root, "agent", "status", "bbtest"))
        source_agent = policy["agent_id"]
        native(destination, "coord", "federation", "member", "shared", source_id, source_agent, "remote-bbtest")
        certificate, key = destination / "server.pem", destination / "server.key"
        checked(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                 "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                 "-addext", "basicConstraints=critical,CA:FALSE",
                 "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                 "-addext", "extendedKeyUsage=serverAuth",
                 "-keyout", str(key), "-out", str(certificate)], diagnostics=output / "native.log")
        key.chmod(0o600)
        report["tls_certificate_sha256"] = _sha256(certificate)
        native(destination, "coord", "stop")
        save(destination / "coord-federation.json", {
            "mode": "tls", "listen": "127.0.0.1", "cert_file": str(certificate), "key_file": str(key),
            "ca_file": str(certificate), "local_server_name": "127.0.0.1",
            "peers": [{"instance_id": source_id, "credential_file": str(credential)}]})
        broker = json.loads(native(destination, "coord", "start"))
        endpoint = f"tls://127.0.0.1:{broker['client_port']}"
        native(destination, "start")
        native(root, "coord", "federation", "home", "destination", destination_id, "tls", endpoint,
               str(certificate), str(credential))
        report["participants"] = {}
        for name in NAMES:
            native(root, "agent", "start", name, "--sandbox-only")
            report["participants"][name] = running_guest(root, name, json.loads(native(root, "agent", "status", name)))
            actual = _sha256(root / "agents" / name / "config-share/safeyolo-guest")
            assert actual == report["inputs"]["guest"]["sha256"]
            report["participants"][name]["guest_sha256"] = actual
        observed = report["participants"]["bbtest"]
        context = {"platform": "systrap", "agent": "bbtest", "pid": observed["backend_pid"],
                   "start_token": observed["backend_token"]}
        save(output / "platform.json", context)
        receipt = ProcedureReceipt("federation", output / "result.json")
        receipt.document["guest"] = context
        receipt.checkpoint('identity')
        marker = "federation-" + uuid.uuid4().hex
        native(destination, "coord", "send", "shared", marker + "-observer")
        baseline = observe()
        assert any(row.get("body") == marker + "-observer" and row["sender_kind"] == "operator" for row in baseline)
        report["refusals"] = {}
        for label, actor, instance_id, status in (("wrong-principal", "bbpeer", None, 403),
                                                 ("wrong-instance", "bbtest", source_id, 409)):
            refusal = {"home": "destination", "instance_id": instance_id, "expected_status": status,
                       "enforcement": "source-instance-selection" if instance_id else "destination-principal",
                       "status": None, "destination_unchanged": None}
            report["refusals"][label] = refusal
            save(output / "result.json", report)
            try:
                reply = send(actor, marker + "-" + label, instance_id)
                refusal["status"] = reply["status"]
            finally:
                # Save the response before the observer can fail, and observe
                # even when the guest transport raises instead of returning it.
                save(output / "result.json", report)
                refusal["destination_unchanged"] = observe() == baseline
                save(output / "result.json", report)
            assert refusal["status"] == status, f"{label}: expected HTTP {status}"
            assert refusal["destination_unchanged"], "refused federation request changed destination"
        receipt.checkpoint('scope', refusals=report["refusals"], destination_count=len(baseline))
        try:
            allowed = send("bbtest", marker + "-allowed")
            report["allowed_status"] = allowed["status"]
        finally:
            save(output / "result.json", report)
            rows = observe()
        assert allowed["status"] == 200
        delivered = [row for row in rows if row.get("body") == marker + "-allowed"]
        assert len(rows) == len(baseline) + 1 and len(delivered) == 1
        assert delivered[0]["sender_kind"] == "agent" and delivered[0]["sender_agent_name"] == "remote-bbtest"
        assert delivered[0]["origin_instance_id"] == source_id and delivered[0]["origin_agent_id"] == source_agent
        assert delivered[0]["sender_agent_id"] != source_agent
        receipt.checkpoint('destination-effect', status=allowed["status"], before=len(baseline), after=len(rows),
                           sender_agent_id=delivered[0]["sender_agent_id"],
                           origin_instance_id=delivered[0]["origin_instance_id"],
                           origin_agent_id=delivered[0]["origin_agent_id"])
        native(destination, "coord", "federation", "revoke", source_id)
        try:
            revoked = send("bbtest", marker + "-revoked")
            report["revocation_status"] = revoked["status"]
        finally:
            save(output / "result.json", report)
            report["revocation_destination_unchanged"] = observe() == rows
            save(output / "result.json", report)
        assert revoked["status"] == 403 and report["revocation_destination_unchanged"]
        receipt.checkpoint('revocation', status=revoked["status"],
                           destination_unchanged=report["revocation_destination_unchanged"])
        report["status"] = "passed"
    finally:
        failures = []
        for selected in (root, destination):
            if (selected / ".safeyolo-platform-smoke").is_file():
                failures.extend(cleanup_instance(cli, selected))
        report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures)
        save(output / "result.json", report)
        if report["status"] == "passed":
            assert not failures, failures
    receipt.checkpoint('finished')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-config", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
