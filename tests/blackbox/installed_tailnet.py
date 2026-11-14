#!/usr/bin/env python3
"""Observe real tailnet refusals without changing a host route or service.

Run observe on the destination's assigned address. Its fresh port and nonsecret
nonce go to the source operator. Run probe before and after each check to prove
that the independent observer stayed reachable. Check uses a new native root
and real host Tailscale status; it never substitutes status JSON. Run the
missing-interface check only in an already authorized isolated namespace.

These are wrong-node and missing-local-interface witnesses. They do not prove
wrong-route, active interface loss/reconnect, or protected federation delivery.
No command changes Tailscale, network interfaces, routes or existing instances.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from tests.blackbox.execution_receipt import save
from tests.blackbox.installed_host_smoke import _cli_identity, _sha256
from tests.blackbox.installed_provider import checked
from tests.blackbox.installed_sections import cleanup_instance, copy_prepared_nats, prepare_native_instance

REASONS = {
    "wrong-node": "not an address assigned to the selected Tailscale node",
    "missing-interface": "has no assigned local network interface",
}
INFO = b'INFO {"server_id":"BB26","server_name":"observer","version":"2.14.5","proto":1,"max_payload":1048576}\r\n'


def observe(bind: str, source: str, duration: float, output: Path) -> None:
    """Count connections independently; never retain incoming credential bytes."""
    nonce = uuid.uuid4().hex
    report = {"boundary": "independent TCP observer", "nonce": nonce, "connections": [],
              "status": "incomplete", "closed": False, "driver_sha256": _sha256(Path(__file__)),
              "host": socket.gethostname(), "uid": os.getuid(), "pid": os.getpid()}
    with socket.socket() as listener:
        listener.bind((bind, 0))
        listener.listen()
        listener.settimeout(.2)
        report.update(address=bind, port=listener.getsockname()[1])
        save(output / "ready.json", {key: report[key] for key in ("address", "port", "nonce")})
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                continue
            row = {"source": peer[0], "control": False, "received_bytes": 0,
                   "observed_at": datetime.now(UTC).isoformat()}
            report["connections"].append(row)
            save(output / "result.json", report)
            with connection:
                connection.settimeout(2)
                try:
                    # A client that reached this listener would have a NATS INFO
                    # frame permitting authentication. Count even silent clients.
                    connection.sendall(INFO)
                    data = b""
                    while b"\n" not in data and len(data) < 4096:
                        chunk = connection.recv(4096 - len(data))
                        if not chunk:
                            break
                        data += chunk
                    row.update(control=data == f"BB26 {nonce}\r\n".encode() and peer[0] == source,
                               received_bytes=len(data))
                    if row["control"]:
                        connection.sendall(f"BB26-OK {nonce}\r\n".encode())
                except OSError as error:
                    row["error"] = type(error).__name__
            save(output / "result.json", report)
    report.update(closed=True, status="passed" if len(report["connections"]) >= 2 and
                  all(row["control"] for row in report["connections"]) else "failed")
    save(output / "result.json", report)
    assert report["status"] == "passed", "observer lacked paired probes or saw an unexpected connection"


def probe(address: str, port: int, source: str, nonce: str) -> None:
    with socket.create_connection((address, port), timeout=5, source_address=(source, 0)) as connection:
        reader = connection.makefile("rb")
        assert reader.readline(4096).startswith(b"INFO ")
        connection.sendall(f"BB26 {nonce}\r\n".encode())
        assert reader.readline(4096) == f"BB26-OK {nonce}\r\n".encode()


def check(args, output: Path) -> None:
    cli = Path(args.cli).resolve(strict=True)
    identity = _cli_identity(cli)
    coord = cli.with_name("safeyolo-coord")
    version = checked([str(coord), "--version"]).strip()
    assert f"commit={identity['source_revision']}" in version, "CLI and Coord sources differ"
    root = args.root.resolve()
    assert not root.exists(), "--root must be new"
    env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_NATIVE_CONFIG_PATH": str(root / "config.toml"),
                        "SAFEYOLO_COORD_DATA_DIR": str(root / "data/coord"), "SAFEYOLO_NATS_TEST_INSTANCE": str(root)}

    def native(*words):
        return checked([str(cli), "--root", str(root), *words], env=env, diagnostics=output / "native.log")

    status = json.loads(checked(["tailscale", "status", "--json"]))
    assert status["Self"]["ID"] == args.source_node and args.source in status["Self"]["TailscaleIPs"]
    assert status["BackendState"] == "Running" and status["TUN"] is True
    assert any(peer.get("ID") == args.destination_node and args.address in peer.get("TailscaleIPs", [])
               for peer in status.get("Peer", {}).values()), "destination does not match live peer status"
    report = {"case": args.expect, "status": "incomplete", "cli": identity,
              "coord": {"path": str(coord), "sha256": _sha256(coord), "version": version},
              "driver_sha256": _sha256(Path(__file__)), "source_node": args.source_node,
              "source_address": args.source, "destination_node": args.destination_node,
              "destination_address": args.address, "port": args.port, "nonce": args.nonce,
              "started_at": datetime.now(UTC).isoformat(), "cleanup": "unverified",
              "limit": "Requires matching independent observer; whole BB-26 remains incomplete"}
    save(output / "result.json", report)
    try:
        prepare_native_instance(cli.parent.parent, root)
        (root / ".safeyolo-platform-smoke").touch()
        copy_prepared_nats(cli.parent.parent, root)
        credential = root / "observer-credential"
        native("coord", "federation", "credential", str(credential))
        # An owned, otherwise valid credential detects an erroneous connect;
        # it grants no authority in any live destination instance.
        node = args.source_node if args.expect == "wrong-node" else args.destination_node
        command = [str(cli), "--root", str(root), "coord", "federation", "home", "observer",
                   "sy-bb26-observer", "tailscale", f"nats://{args.address}:{args.port}", node, str(credential)]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        report["refusal"] = {"stage": "native home selection", "exit": result.returncode,
                             "reason": result.stderr.strip()}
        save(output / "result.json", report)
        assert result.returncode != 0, "invalid protected home was selected"
        assert REASONS[args.expect] in result.stderr, "wrong refusal cause"
        report["status"] = "passed"
    finally:
        failures = cleanup_instance(cli, root) if (root / ".safeyolo-platform-smoke").is_file() else []
        report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures)
        report["finished_at"] = datetime.now(UTC).isoformat()
        save(output / "result.json", report)
        assert not failures, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("observe", "probe", "check"):
        selected = commands.add_parser(name)
        selected.add_argument("--address", required=True)
        selected.add_argument("--source", required=True)
        if name != "observe":
            selected.add_argument("--port", required=True, type=int)
            selected.add_argument("--nonce", required=True)
        if name != "probe":
            selected.add_argument("--output", required=True, type=Path)
    commands.choices["observe"].add_argument("--duration", type=float, default=60)
    selected = commands.choices["check"]
    selected.add_argument("--cli", required=True)
    selected.add_argument("--root", required=True, type=Path)
    selected.add_argument("--source-node", required=True)
    selected.add_argument("--destination-node", required=True)
    selected.add_argument("--expect", choices=REASONS, required=True)
    args = parser.parse_args()
    if args.command != "probe":
        args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    if args.command == "observe":
        assert args.duration > 0
        observe(args.address, args.source, args.duration, args.output)
    elif args.command == "probe":
        probe(args.address, args.port, args.source, args.nonce)
    else:
        assert args.source != args.address and args.source_node != args.destination_node
        check(args, args.output)


if __name__ == "__main__":
    main()
