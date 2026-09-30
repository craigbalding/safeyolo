"""Real retained-consumer controls for the native Rust proxy.

These tests use the same Python AdminAPI and listener reconciliation helper
used by the operator workflow.  They observe a request reaching an owned
origin and real Unix socket inodes changing; a successful control response or
reload marker alone is not sufficient.
"""

import json
import time
from dataclasses import asdict
from pathlib import Path

from safeyolo import rust_proxy
from safeyolo.api import AdminAPI
from safeyolo.proxy import sync_proxy_ignore_hosts
from safeyolo.runtime_identity import process_start_token
from safeyolo.sockets import path_for
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import DENY, policy_proxy

OPERATOR_TOKEN = "synthetic-retained-controls-token"
ALLOW = """
budget = 12000
[hosts]
"*" = { egress = "allow" }
"""


def _admin_client(proxy, token_file: Path) -> AdminAPI:
    marker = json.loads(proxy.readiness_file.read_text())
    return AdminAPI(
        base_url=f"http://127.0.0.1:{marker['admin_port']}",
        token=token_file.read_text().strip(),
        timeout=5,
    )


def test_retained_admin_client_mode_change_reaches_live_enforcement(tmp_path, monkeypatch):
    """AdminAPI mode changes alter the next real request decision."""
    token_file = tmp_path / "admin-token"
    token_file.write_text(OPERATOR_TOKEN + "\n")
    directory = tmp_path / "mode"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "cli"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "cli-logs"))

    with origin_server() as origin:
        with policy_proxy(
            "rust",
            directory,
            DENY,
            admin_port=0,
            admin_api_token_file=token_file,
            network_guard_block=True,
        ) as proxy:
            client = _admin_client(proxy, token_file)
            target = f"http://127.0.0.1:{origin.server_address[1]}/mode-consumer"

            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 403, body
            assert origin.accepts == 0

            changed = client.set_mode("network-guard", "warn")
            assert changed["status"] == "updated"
            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 200, body
            assert body == b"hello"
            assert origin.accepts == 1

            changed = client.set_mode("network-guard", "block")
            assert changed["status"] == "updated"
            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 403, body
            assert origin.accepts == 1

            changed = client.set_all_modes("warn")
            assert changed["status"] == "updated"
            modes = client.get_modes()["modes"]
            assert modes and all(mode == "warn" for mode in modes.values())
            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 200, body
            assert body == b"hello"
            assert origin.accepts == 2

            changed = client.set_all_modes("block")
            assert changed["status"] == "updated"
            modes = client.get_modes()["modes"]
            assert modes and all(mode == "block" for mode in modes.values())
            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 403, body
            assert origin.accepts == 2


def test_retained_ignore_host_consumer_publishes_and_clears_native_entries(tmp_path, monkeypatch):
    """The existing CLI publisher reaches the native ignore-host route."""
    cli_root = tmp_path / "cli"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(cli_root))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "cli-logs"))
    cli_token = cli_root / "data" / "admin_token"
    cli_token.parent.mkdir(parents=True)
    cli_token.write_text("synthetic-ignore-consumer-token\n")
    token_file = tmp_path / "operator-token"
    token_file.write_text("synthetic-ignore-consumer-token\n")

    directory = tmp_path / "ignore-hosts"
    with policy_proxy(
        "rust",
        directory,
        ALLOW,
        admin_port=0,
        admin_api_token_file=token_file,
    ) as proxy:
        marker = json.loads(proxy.readiness_file.read_text())
        port = marker["admin_port"]
        assert sync_proxy_ignore_hosts(["example.test:443"], admin_port=port, timeout=5)
        assert sync_proxy_ignore_hosts([], admin_port=port, timeout=5)

        audit = directory / "audit.jsonl"
        deadline = time.monotonic() + 3
        updates = []
        while time.monotonic() < deadline:
            if audit.exists():
                updates = [
                    json.loads(line)
                    for line in audit.read_text().splitlines()
                    if line and json.loads(line).get("event") == "admin.proxy_ignore_hosts_update"
                ]
                if len(updates) >= 2:
                    break
            time.sleep(0.02)

        assert len(updates) >= 2
        assert updates[-2]["details"]["hosts"] == ["example.test:443"]
        assert updates[-2]["details"]["operator_entry_count"] == 1
        assert updates[-1]["details"]["hosts"] == []
        assert updates[-1]["details"]["operator_entry_count"] == 0


def test_retained_listener_consumer_adds_and_removes_real_native_sockets(tmp_path, monkeypatch):
    """sync_proxy_modes changes the live native listener set via SIGHUP."""
    cli_root = tmp_path / "cli"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(cli_root))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "cli-logs"))
    directory = tmp_path / "listeners"
    mapping = {"alice": "10.0.0.2"}

    with origin_server() as origin:
        with policy_proxy(
            "rust",
            directory,
            ALLOW,
            agent_map=mapping,
        ) as proxy:
            process = rust_proxy.RustProcess(
                pid=proxy.process.pid,
                start_token=process_start_token(proxy.process.pid),
                readiness_file=str(proxy.readiness_file),
                admin_port=None,
                admin_token_file=None,
                config_file=str(directory / "proxy.json"),
                working_directory=str(directory),
            )
            assert process.start_token
            state_path = rust_proxy.state_file()
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps(asdict(process)))

            alice = Path(proxy.paths["alice"])
            target = f"http://127.0.0.1:{origin.server_address[1]}/listener-consumer"
            status, _, body = send_request(str(alice), target)
            assert status == 200 and body == b"hello"
            assert alice.exists()

            mapping["bob"] = "10.0.0.3"
            (cli_root / "data" / "agent_map.json").write_text(
                json.dumps({name: {"ip": ip} for name, ip in mapping.items()})
            )
            assert rust_proxy.sync_listeners(timeout=5)
            bob = path_for("bob", "10.0.0.3")
            assert bob.exists()
            status, _, body = send_request(str(bob), target)
            assert status == 200 and body == b"hello"

            del mapping["alice"]
            (cli_root / "data" / "agent_map.json").write_text(
                json.dumps({name: {"ip": ip} for name, ip in mapping.items()})
            )
            assert rust_proxy.sync_listeners(timeout=5)
            assert not alice.exists()
            assert bob.exists()
            status, _, body = send_request(str(bob), target)
            assert status == 200 and body == b"hello"
            assert origin.accepts == 3
