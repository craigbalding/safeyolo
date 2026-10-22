"""Real retained-consumer controls for the native Rust proxy.

These tests use the same Python AdminAPI and listener reconciliation helper
used by the operator workflow.  They observe a request reaching an owned
origin and real Unix socket inodes changing; a successful control response or
reload marker alone is not sufficient.
"""

import json
import time
from pathlib import Path

from safeyolo.api import AdminAPI
from safeyolo.proxy import sync_proxy_ignore_hosts
from tests.proxy_contracts.harness import request as send_request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_network_policy import DENY, policy_proxy

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
