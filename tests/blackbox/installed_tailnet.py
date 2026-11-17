#!/usr/bin/env python3
"""Observe real tailnet refusals without changing a host route or service.

Run observe on the destination's assigned address. Its fresh port and nonsecret
nonce go to the source operator. Run probe before and after each check to prove
that the independent observer stayed reachable. Check uses a new native root
and real host Tailscale status; it never substitutes status JSON. Run the
missing-interface check only in an already authorized isolated namespace.

For the full journey, forward the observer to an owned real NATS listener.
Keep one prepared source proxy and guest live across phase commands. An
authorized executor supplies isolated route/interface faults between phases;
the driver never changes host networking. Verify destination-owned messages
and both hosts' stopped cleanup with the retained phase/observer receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import socket
import subprocess
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlencode

from tests.blackbox.execution_receipt import read_json, save
from tests.blackbox.guest_exec import guest_http_request
from tests.blackbox.installed_host_smoke import _cli_identity, _native_config, _runtime_observation, _sha256
from tests.blackbox.installed_lifecycle import running_guest
from tests.blackbox.installed_provider import checked
from tests.blackbox.installed_sections import cleanup_instance, copy_prepared_nats, prepare_native_instance

REASONS = {
    "wrong-node": "not an address assigned to the selected Tailscale node",
    "wrong-route": "does not route through the host's Tailscale interface",
    "missing-interface": "has no assigned local network interface",
}
PHASES = ("initial", "wrong-node", "wrong-route", "missing-interface", "lost-interface", "restored", "finished")
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


def probe(address: str, port: int, source: str, nonce: str, phase: str = "") -> None:
    with socket.create_connection((address, port), timeout=5, source_address=(source, 0)) as connection:
        reader = connection.makefile("rb")
        assert reader.readline(4096).startswith(b"INFO ")
        suffix = f" {phase} {time.monotonic_ns()}" if phase else ""
        connection.sendall(f"BB26 {nonce}{suffix}\r\n".encode())
        acknowledgement = f" {phase}" if phase else ""
        assert reader.readline(4096) == f"BB26-OK {nonce}{acknowledgement}\r\n".encode()
        if phase:
            connection.sendall(f"BB26-END {nonce} {phase} {time.monotonic_ns()}\r\n".encode())
            assert reader.readline(4096) == f"BB26-DONE {nonce} {phase}\r\n".encode()


def protocol_line(connection: socket.socket) -> bytes:
    """Read one bounded frame without consuming subsequent protocol bytes."""
    line = bytearray()
    while len(line) < 65536:
        chunk = connection.recv(1)
        if not chunk:
            break
        line += chunk
        if chunk == b"\n":
            return bytes(line)
    assert not line, "incomplete or oversized initial NATS frame"
    return b""


def observe_federation(bind: str, source: str, forward_port: int, duration: float, output: Path) -> None:
    """Forward to owned NATS; retain counts and phase boundaries, never payloads."""
    report = {"boundary": "independent TCP forwarding observer", "nonce": uuid.uuid4().hex,
              "address": bind, "source": source, "forward_port": forward_port, "phase_marks": [],
              "connections": [], "status": "incomplete", "closed": False,
              "driver_sha256": _sha256(Path(__file__)), "host": socket.gethostname(), "uid": os.getuid()}
    lock, stopping = threading.Lock(), threading.Event()
    active, threads = [], []

    def retain():
        save(output / "result.json", report)

    def disconnect(pair):
        for connection in pair:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # A peer can close before an owned forced disconnect.

    def forward(connection, peer):
        row = {"source": peer[0], "control": False, "received_bytes": 0,
               "observed_at": datetime.now(UTC).isoformat(), "markers": []}
        pair = None
        tail = b""
        markers = {name: f"bb26-{report['nonce']}-{name}".encode()
                   for name in ("initial", "lost-interface", "restored")}
        with connection:
            try:
                connection.settimeout(2)
                with socket.create_connection((bind, forward_port), timeout=2) as upstream:
                    greeting = protocol_line(upstream)
                    assert greeting.startswith(b"INFO "), "owned upstream supplied no NATS greeting"
                    connection.sendall(greeting)
                    try:
                        first = protocol_line(connection)
                    except TimeoutError:
                        first = b""  # Reconnect protection may withhold all authentication bytes.
                    with lock:
                        expected = len(report["phase_marks"])
                        phase = PHASES[expected] if expected < len(PHASES) else None
                        parts = first.split()
                        control = [b"BB26", report["nonce"].encode(), str(phase).encode()]
                        if (peer[0] == source and phase is not None and len(parts) == 4 and
                                parts[:3] == control and parts[3].isdigit()):
                            row.update(control=True, phase=phase)
                            count = 0
                            if phase == "lost-interface":
                                # Only the live initial-delivery connection proves cached-connection loss.
                                count = sum(current[2].get("connect") and current[2].get("phase") == "initial" and
                                    "initial" in current[2]["markers"] for current in active)
                                for current in active:
                                    current[2]["forced_disconnect"] = phase
                                    disconnect(current[:2])
                            mark = {"phase": phase, "source_sent_ns": int(parts[3]),
                                "observed_at": datetime.now(UTC).isoformat(), "disconnected": count}
                            report["phase_marks"].append(mark)
                        else:
                            row.update(phase=report["phase_marks"][-1]["phase"] if expected else None,
                                       received_bytes=len(first), connect=first.startswith(b"CONNECT "))
                            if first:
                                pair = (connection, upstream, row)
                                active.append(pair)
                        report["connections"].append(row)
                        retain()
                    if row["control"]:
                        connection.sendall(f"BB26-OK {report['nonce']} {row['phase']}\r\n".encode())
                        end = protocol_line(connection).split()
                        assert len(end) == 4 and end[:3] == [b"BB26-END", report["nonce"].encode(), row["phase"].encode()]
                        assert end[3].isdigit()
                        with lock:
                            mark["source_received_ns"] = int(end[3])
                            retain()
                        connection.sendall(f"BB26-DONE {report['nonce']} {row['phase']}\r\n".encode())
                        return
                    if not first:
                        return
                    upstream.sendall(first)
                    while not stopping.is_set() and not row.get("forced_disconnect"):
                        ready, _, _ = select.select((connection, upstream), (), (), .1)
                        for incoming in ready:
                            data = incoming.recv(65536)
                            if not data:
                                return
                            if incoming is connection:
                                with lock:
                                    row["received_bytes"] += len(data)
                                    window = tail + data
                                    row["markers"] = sorted(set(row["markers"]) |
                                        {name for name, marker in markers.items() if marker in window})
                                    tail = window[-max(map(len, markers.values())):]
                                    retain()
                            (upstream if incoming is connection else connection).sendall(data)
            except (OSError, AssertionError) as error:
                with lock:
                    if not stopping.is_set() and not row.get("forced_disconnect"):
                        row["error"] = type(error).__name__
                        if row not in report["connections"]:
                            report["connections"].append(row)
                        retain()
            finally:
                with lock:
                    if pair in active:
                        active.remove(pair)
                    row["closed"] = True
                    retain()

    with socket.socket() as listener:
        listener.bind((bind, 0))
        listener.listen()
        listener.settimeout(.1)
        report["port"] = listener.getsockname()[1]
        save(output / "ready.json", {key: report[key] for key in ("address", "port", "nonce")})
        retain()
        deadline = time.monotonic() + duration
        try:
            while time.monotonic() < deadline:
                with lock:
                    if len(report["phase_marks"]) == len(PHASES):
                        break
                try:
                    connection, peer = listener.accept()
                except TimeoutError:
                    continue
                thread = threading.Thread(target=forward, args=(connection, peer), daemon=True)
                threads.append(thread)
                thread.start()
        finally:
            stopping.set()
            with lock:
                for pair in active:
                    disconnect(pair[:2])
            for thread in threads:
                thread.join(timeout=3)
    assert not any(thread.is_alive() for thread in threads), "observer worker cleanup is unverified"
    report.update(closed=True, status="passed" if not observer_problems(report) else "failed")
    retain()
    assert report["status"] == "passed", "incomplete phases, withheld-byte violation or observer failure"


def observer_problems(report: dict) -> list[str]:
    problems = []
    if [row["phase"] for row in report["phase_marks"]] != list(PHASES):
        problems.append("missing ordered phase probes")
    previous = 0
    for row in report["phase_marks"]:
        sent, received = row.get("source_sent_ns"), row.get("source_received_ns")
        if type(sent) is not int or type(received) is not int or not previous < sent <= received:
            problems.append("incomplete or unordered source-clock probe bounds")
            break
        previous = received
    product = [row for row in report["connections"] if not row["control"]]
    disconnected = [row for row in product if row.get("phase") == "initial" and row.get("connect") and
        "initial" in row.get("markers", []) and row.get("forced_disconnect") == "lost-interface" and row.get("closed")]
    if not disconnected or not any(row["phase"] == "lost-interface" and row["disconnected"] == len(disconnected)
                                   for row in report["phase_marks"]):
        problems.append("initial authenticated delivery connection was not disconnected for interface loss")
    if any(row.get("error") or row["source"] != report["source"] for row in report["connections"]):
        problems.append("observer error or unexpected source")
    if any(row.get("received_bytes", 0) and row.get("phase") not in {"initial", "restored"} for row in product):
        problems.append("application bytes arrived during a refused phase")
    if any("lost-interface" in row.get("markers", []) for row in product):
        problems.append("refused operation was submitted, including after recovery")
    for phase in ("initial", "restored"):
        if not any(row.get("phase") == phase and row.get("connect") and phase in row.get("markers", []) for row in product):
            problems.append(f"no observed protected delivery for {phase}")
    return problems


def verify_live_pair(args) -> None:
    status = json.loads(checked(["tailscale", "status", "--json"]))
    assert status["Self"]["ID"] == args.source_node and args.source in status["Self"]["TailscaleIPs"]
    assert status["BackendState"] == "Running" and status["TUN"] is True
    assert any(peer.get("ID") == args.destination_node and args.address in peer.get("TailscaleIPs", [])
               for peer in status.get("Peer", {}).values()), "destination does not match live peer status"


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

    verify_live_pair(args)
    report = {"case": args.expect, "status": "incomplete", "cli": identity,
              "coord": {"path": str(coord), "sha256": _sha256(coord), "version": version},
              "driver_sha256": _sha256(Path(__file__)), "source_node": args.source_node,
              "source_address": args.source, "destination_node": args.destination_node,
              "destination_address": args.address, "port": args.port, "nonce": args.nonce,
              "started_at": datetime.now(UTC).isoformat(), "cleanup": "unverified",
              "started_ns": time.monotonic_ns(),
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
        report["finished_ns"] = time.monotonic_ns()
        save(output / "result.json", report)
        assert not failures, failures


def phase(args, output: Path) -> None:
    """Use the same owned proxy, guest and selected home before/after real loss."""
    cli, root = Path(args.cli).resolve(strict=True), args.root.resolve(strict=True)
    assert (root / ".safeyolo-platform-smoke").is_file(), "select an owned disposable source instance"
    env = os.environ | {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_NATIVE_CONFIG_PATH": str(root / "config.toml"),
                        "SAFEYOLO_COORD_DATA_DIR": str(root / "data/coord")}
    identity = _cli_identity(cli)
    report = {"phase": args.phase, "status": "incomplete", "root": str(root), "cli": identity,
              "driver_sha256": _sha256(Path(__file__)), "nonce": args.nonce,
              "address": args.address, "port": args.port, "source_address": args.source,
              "source_node": args.source_node, "destination_node": args.destination_node,
              "home_name": args.home, "room": args.room, "started_at": datetime.now(UTC).isoformat(),
              "started_ns": time.monotonic_ns(),
              "cleanup": "retained for next phase or explicit stop"}
    save(output / "result.json", report)
    try:
        verify_live_pair(args)
        proxy, coord = cli.with_name("safeyolo-proxy"), cli.with_name("safeyolo-coord")
        version = checked([str(coord), "--version"]).strip()
        assert f"commit={identity['source_revision']}" in version, "CLI and Coord sources differ"
        report["binaries"] = {path.name: _sha256(path) for path in (cli, proxy, coord)}
        runtime = _runtime_observation(root, _native_config(root / "config.toml", root), proxy,
            config_path=root / "config.toml", working_directory=root, require_running=True)
        report["proxy"] = {"pid": runtime["pid"], "start_token": runtime["receipt"]["token"]}
        status = json.loads(checked([str(cli), "--root", str(root), "agent", "status", args.agent], env=env))
        report["guest"] = running_guest(root, args.agent, status)
        report["guest"]["sha256"] = _sha256(root / "agents" / args.agent / "config-share/safeyolo-guest")
        report["source_instance"] = (root / "data/instance_id").read_text().strip()
        diagnosis = json.loads(checked([str(cli), "--root", str(root), "coord", "federation", "check", args.home],
                                      env=env, diagnostics=output / "native.log"))
        report["home"] = diagnosis
        save(output / "result.json", report)
        endpoint = diagnosis["configured"]
        assert endpoint["mode"] == "tailscale" and endpoint["tailscale_node"] == args.destination_node
        assert endpoint["url"] == f"nats://{args.address}:{args.port}", "selected home bypasses the independent observer"
        assert diagnosis["instance_id"] == report["source_instance"]
        if args.phase == "initial":
            assert args.initial is None, "initial phase must not reuse an earlier attempt"
        else:
            assert args.initial is not None, "--initial must identify this journey's initial result.json"
            initial = read_json(args.initial)
            assert initial["status"] == "passed" and initial["phase"] == "initial"
            fields = ("root", "cli", "binaries", "proxy", "guest", "source_instance", "nonce", "address", "port",
                      "source_address", "source_node", "destination_node", "home_name", "room", "driver_sha256")
            assert all(report[key] == initial[key] for key in fields), "source identity changed across interface loss"
            assert diagnosis["configured"] == initial["home"]["configured"]
            assert diagnosis["expected_owner"] == initial["home"]["expected_owner"]
        if args.phase == "lost-interface":
            assert diagnosis["protection"]["verified"] is False
            assert REASONS["missing-interface"] in diagnosis["protection"]["reason"]
            assert diagnosis["broker_authentication"] == "not_checked"
        else:
            assert diagnosis["protection"]["verified"] is True
            assert diagnosis["broker_authentication"] == "authenticated"
            assert diagnosis["owner"]["reachable"] is True and diagnosis["owner"]["identity_verified"] is True
        marker = f"bb26-{args.nonce}-{args.phase}"
        report["marker"] = marker
        save(output / "result.json", report)
        # Exactly one submission. A lost reply needs destination inspection,
        # never an automatic replay of this phase or its marker.
        reply = guest_http_request(str(cli), args.agent, "POST",
            "http://_safeyolo.proxy.internal/api/coord/rooms/" + quote(args.room, safe="") + "/send?" +
            urlencode({"home": args.home}), {"body": marker, "notify": "none"}, env=env)
        report["response_status"] = reply["status"]
        assert reply["status"] >= 400 if args.phase == "lost-interface" else reply["status"] == 200
        report["status"] = "passed"
    finally:
        report["finished_at"] = datetime.now(UTC).isoformat()
        report["finished_ns"] = time.monotonic_ns()
        save(output / "result.json", report)


def stop(args, output: Path) -> None:
    """Stop only the selected disposable source, retaining failed cleanup."""
    root, cli = args.root.resolve(strict=True), Path(args.cli).resolve(strict=True)
    assert (root / ".safeyolo-platform-smoke").is_file(), "select an owned disposable instance"
    report = {"root": str(root), "cli": _cli_identity(cli), "cleanup": "unverified"}
    save(output / "result.json", report)
    failures = cleanup_instance(cli, root)
    report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures)
    save(output / "result.json", report)
    assert not failures, failures


def verify(args, output: Path) -> None:
    """Read destination effects independently and require the full paired journey."""
    root, cli = args.root.resolve(strict=True), Path(args.cli).resolve(strict=True)
    assert (root / ".safeyolo-platform-smoke").is_file(), "select an owned disposable destination"
    report = {"status": "incomplete", "destination_root": str(root), "cli": _cli_identity(cli),
              "driver_sha256": _sha256(Path(__file__)), "cleanup": "unverified"}
    save(output / "result.json", report)
    try:
        phases = {value["phase"]: value for path in args.phase_report if (value := read_json(path))}
        checks = {value["case"]: value for path in args.check_report if (value := read_json(path))}
        assert len(args.phase_report) == 3 and set(phases) == {"initial", "lost-interface", "restored"}
        assert len(args.check_report) == 3 and set(checks) == set(REASONS)
        observer, cleanup = read_json(args.observer), read_json(args.source_cleanup)
        assert observer["closed"] is True and observer["status"] == "passed" and not observer_problems(observer)
        initial = phases["initial"]
        assert report["cli"]["source_revision"] == initial["cli"]["source_revision"], "different destination source"
        paired = ("nonce", "source_node", "destination_node", "port")
        for value in (*phases.values(), *checks.values()):
            assert value["status"] == "passed"
            assert value["cli"] == initial["cli"], "different source CLI identity"
            assert all(value[key] == initial[key] for key in paired), "unrelated tailnet receipt"
            assert value["driver_sha256"] == initial["driver_sha256"] == report["driver_sha256"]
            assert value.get("destination_address", value.get("address")) == initial["address"]
            assert value["source_address"] == initial["source_address"]
        assert all(value["cleanup"] == "stopped" and not value["cleanup_failures"] for value in checks.values())
        for case, value in checks.items():
            assert value["refusal"]["exit"] != 0 and REASONS[case] in value["refusal"]["reason"]
            assert value["coord"]["sha256"] == initial["binaries"]["safeyolo-coord"], "different native Coord bytes"
        fields = ("root", "cli", "binaries", "proxy", "guest", "source_instance", "home_name", "room")
        for name, value in phases.items():
            assert all(value[key] == initial[key] for key in fields), "source restarted or changed selection"
            assert value["marker"] == f"bb26-{initial['nonce']}-{name}"
            assert value["home"]["configured"] == initial["home"]["configured"]
            assert value["home"]["expected_owner"] == initial["home"]["expected_owner"]
            if name == "lost-interface":
                assert value["response_status"] >= 400 and value["home"]["protection"]["verified"] is False
                assert REASONS["missing-interface"] in value["home"]["protection"]["reason"]
                assert value["home"]["broker_authentication"] == "not_checked"
            else:
                assert value["response_status"] == 200 and value["home"]["protection"]["verified"] is True
                assert value["home"]["broker_authentication"] == "authenticated"
                assert value["home"]["owner"]["reachable"] is True and value["home"]["owner"]["identity_verified"] is True
        assert observer["nonce"] == initial["nonce"] and observer["port"] == initial["port"]
        assert observer["address"] == initial["address"] and observer["source"] == initial["source_address"]
        marks = observer["phase_marks"]
        windows = {row["phase"]: (row["source_received_ns"], marks[index + 1]["source_sent_ns"])
                   for index, row in enumerate(marks[:-1])}
        for name, value in (*phases.items(), *checks.items()):
            beginning, end = windows[name]
            assert beginning <= value["started_ns"] <= value["finished_ns"] <= end, "attempt was outside its observed phase"
        assert cleanup["root"] == initial["root"] and cleanup["cli"] == initial["cli"]
        assert cleanup["cleanup"] == "stopped" and not cleanup["cleanup_failures"]
        destination = (root / "data/instance_id").read_text().strip()
        assert destination == initial["home"]["expected_owner"] != initial["source_instance"]
        rows = [json.loads(line) for line in checked([str(cli), "--root", str(root), "coord", "watch", initial["room"],
                "--history", "100", "--once", "--json"], diagnostics=output / "native.log").splitlines()]
        report["destination_messages"] = rows
        save(output / "result.json", report)
        source, agent = initial["source_instance"], initial["guest"]["agent_id"]
        principal = "ag-fed-" + hashlib.sha256(f"{len(source)}:{source}{agent}".encode()).hexdigest()
        delivered = [row for row in rows if row.get("body", "").startswith(f"bb26-{initial['nonce']}-")]
        assert sorted(row["body"] for row in delivered) == sorted(phases[key]["marker"] for key in ("initial", "restored"))
        assert all(row["sender_kind"] == "agent" and row["sender_agent_id"] == principal and
                   row["origin_instance_id"] == source and row["origin_agent_id"] == agent
                   for row in delivered), "wrong federated sender or source"
        report.update(status="passed", nonce=initial["nonce"], source_instance=source,
                      destination_instance=destination, observer=observer, phases=phases, checks=checks,
                      source_cleanup=cleanup)
    finally:
        failures = cleanup_instance(cli, root)
        report.update(cleanup="failed" if failures else "stopped", cleanup_failures=failures)
        if failures:
            report["status"] = "failed"
        save(output / "result.json", report)
        assert not failures, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("observe", "probe", "check", "phase"):
        selected = commands.add_parser(name)
        selected.add_argument("--address", required=True)
        selected.add_argument("--source", required=True)
        if name != "observe":
            selected.add_argument("--port", required=True, type=int)
            selected.add_argument("--nonce", required=True)
        if name != "probe":
            selected.add_argument("--output", required=True, type=Path)
    commands.choices["observe"].add_argument("--duration", type=float, default=60)
    commands.choices["observe"].add_argument("--forward-port", type=int)
    commands.choices["probe"].add_argument("--phase", choices=PHASES, default="")
    for name in ("check", "phase"):
        selected = commands.choices[name]
        selected.add_argument("--cli", required=True)
        selected.add_argument("--root", required=True, type=Path)
        selected.add_argument("--source-node", required=True)
        selected.add_argument("--destination-node", required=True)
    commands.choices["check"].add_argument("--expect", choices=REASONS, required=True)
    selected = commands.choices["phase"]
    selected.add_argument("--phase", choices=("initial", "lost-interface", "restored"), required=True)
    selected.add_argument("--initial", type=Path)
    selected.add_argument("--agent", required=True)
    selected.add_argument("--home", required=True)
    selected.add_argument("--room", required=True)
    for name in ("stop", "verify"):
        selected = commands.add_parser(name)
        selected.add_argument("--cli", required=True)
        selected.add_argument("--root", required=True, type=Path)
        selected.add_argument("--output", required=True, type=Path)
    selected = commands.choices["verify"]
    selected.add_argument("--phase-report", type=Path, action="append", required=True)
    selected.add_argument("--check-report", type=Path, action="append", required=True)
    selected.add_argument("--observer", type=Path, required=True)
    selected.add_argument("--source-cleanup", type=Path, required=True)
    args = parser.parse_args()
    if args.command != "probe":
        args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    if args.command == "observe":
        assert args.duration > 0
        if args.forward_port is not None:
            assert 1 <= args.forward_port <= 65535, "--forward-port must name the actual owned NATS listener"
            observe_federation(args.address, args.source, args.forward_port, args.duration, args.output)
        else:
            observe(args.address, args.source, args.duration, args.output)
    elif args.command == "probe":
        probe(args.address, args.port, args.source, args.nonce, args.phase)
    elif args.command in {"check", "phase"}:
        assert args.source != args.address and args.source_node != args.destination_node
        if args.command == "check":
            check(args, args.output)
        else:
            phase(args, args.output)
    elif args.command == "stop":
        stop(args, args.output)
    else:
        verify(args, args.output)


if __name__ == "__main__":
    main()
